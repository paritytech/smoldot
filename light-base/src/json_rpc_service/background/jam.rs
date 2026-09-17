// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! The JSON-RPC service of a JAM chain.
//!
//! A JAM chain answers the `jamHead_unstable_*` group over the header-only
//! sync, under a bound on the bytes and finalized headers each follow pins,
//! and the encoding-neutral methods of [`METHODS`]. Every other method,
//! `chainHead_v1_*` included, is answered with method-not-found: its header
//! bytes and hashes would be JAM ones under a name whose clients expect SCALE.
//!
//! From the chain specification, `chainSpec_v1_chainName` returns the `id`,
//! `chainSpec_v1_genesisHash` the hash of the genesis header, and
//! `chainSpec_v1_properties` an empty object, since a JAM chain specification
//! has no properties.
//!
//! Errors use the codes of the matching `chainHead_v1` cases: `-32800` for one
//! follow too many, `-32801` for an unknown or unpinned block, `-32804` for a
//! hash repeated in one unpin.

use crate::{platform::PlatformRef, sync_service};
use alloc::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString as _},
    vec,
    vec::Vec,
};
use futures_lite::stream::StreamExt as _;
use futures_util::stream;
use smoldot::{
    jam::codec,
    json_rpc::{methods, parse},
};

const JAM_PIN_BYTES: usize = 4 * 1024 * 1024;
const JAM_PIN_COUNT: usize = 512;

/// The methods a JAM chain answers, as `rpc_methods` lists them.
const METHODS: [&str; 8] = [
    "chainSpec_v1_chainName",
    "chainSpec_v1_genesisHash",
    "chainSpec_v1_properties",
    "jamHead_unstable_follow",
    "jamHead_unstable_header",
    "jamHead_unstable_unfollow",
    "jamHead_unstable_unpin",
    "rpc_methods",
];

struct JamFollow {
    headers: hashbrown::HashMap<[u8; 32], Vec<u8>, fnv::FnvBuildHasher>,
    counted_headers: BTreeSet<[u8; 32]>,
    finalized_pinned_remaining: usize,
    notifications: async_channel::Receiver<sync_service::Notification>,
}

impl JamFollow {
    fn new(
        finalized_header: Vec<u8>,
        notifications: async_channel::Receiver<sync_service::Notification>,
    ) -> (Self, [u8; 32]) {
        let mut follow = Self {
            headers: Default::default(),
            counted_headers: BTreeSet::new(),
            finalized_pinned_remaining: JAM_PIN_COUNT - 1,
            notifications,
        };
        let root = follow.pin(finalized_header);
        follow.counted_headers.insert(root);
        (follow, root)
    }

    /// Pins a header by its canonical JAM encoding and returns its hash.
    fn pin(&mut self, encoded: Vec<u8>) -> [u8; 32] {
        let hash = codec::header_hash(&encoded);
        self.headers.insert(hash, encoded);
        hash
    }

    fn unpin(&mut self, hash: &[u8; 32]) {
        self.headers.remove(hash);
        if self.counted_headers.remove(hash) {
            self.finalized_pinned_remaining += 1;
        }
    }
}

fn follow_event(subscription: &str, result: methods::JamHeadFollowEvent) -> String {
    methods::ServerToClient::jamHead_unstable_followEvent {
        subscription: Cow::Borrowed(subscription),
        result,
    }
    .to_json_request_object_parameters(None)
}

/// Pins what `notification` reports and sends its events. An error ends the
/// subscription with `stop`; the budget and slot checks fail before anything
/// is pinned, charged or sent.
async fn jam_notification(
    id: &str,
    follow: &mut JamFollow,
    notification: sync_service::Notification,
    responses: &async_channel::Sender<String>,
) -> Result<(), ()> {
    let events = match notification {
        // `scale_encoded_header` holds the canonical JAM encoding here.
        sync_service::Notification::Block(block) => {
            let retained: usize = follow.headers.values().map(Vec::len).sum();
            if retained.saturating_add(block.scale_encoded_header.len()) > JAM_PIN_BYTES {
                return Err(());
            }
            // The sync service reports verified headers, which always have a slot.
            let slot = codec::header_slot(&block.scale_encoded_header).ok_or(())?;
            let hash = follow.pin(block.scale_encoded_header);
            let new_block = methods::JamHeadFollowEvent::NewBlock {
                block_hash: methods::HashHexString(hash),
                parent_block_hash: methods::HashHexString(block.parent_hash),
                slot,
            };
            if block.is_new_best {
                vec![
                    new_block,
                    methods::JamHeadFollowEvent::BestBlockChanged {
                        best_block_hash: methods::HashHexString(hash),
                    },
                ]
            } else {
                vec![new_block]
            }
        }
        // The sync service verifies finality; this adapter only accounts for pins.
        // Headers are pinned here independently and survive tree pruning.
        sync_service::Notification::Finalized {
            finalized_blocks_hashes,
            best_block_hash_if_changed,
            pruned_blocks,
        } => {
            let newly_counted: BTreeSet<_> = finalized_blocks_hashes
                .iter()
                .chain(&pruned_blocks)
                .filter(|hash| {
                    follow.headers.contains_key(*hash) && !follow.counted_headers.contains(*hash)
                })
                .copied()
                .collect();
            // A finality jump exceeding the budget intentionally stops clients that
            // kept too many pins. Check before changing accounting or emitting events.
            if newly_counted.len() > follow.finalized_pinned_remaining {
                return Err(());
            }
            follow.finalized_pinned_remaining -= newly_counted.len();
            follow.counted_headers.extend(newly_counted);
            let finalized = methods::JamHeadFollowEvent::Finalized {
                finalized_block_hashes: finalized_blocks_hashes
                    .into_iter()
                    .map(methods::HashHexString)
                    .collect(),
                pruned_block_hashes: pruned_blocks
                    .into_iter()
                    .map(methods::HashHexString)
                    .collect(),
            };
            match best_block_hash_if_changed {
                Some(hash) => vec![
                    methods::JamHeadFollowEvent::BestBlockChanged {
                        best_block_hash: methods::HashHexString(hash),
                    },
                    finalized,
                ],
                None => vec![finalized],
            }
        }
        sync_service::Notification::BestBlockChanged { hash } => {
            vec![methods::JamHeadFollowEvent::BestBlockChanged {
                best_block_hash: methods::HashHexString(hash),
            }]
        }
    };
    for event in events {
        responses
            .send(follow_event(id, event))
            .await
            .map_err(|_| ())?;
    }
    Ok(())
}

pub(crate) async fn run_jam<P: PlatformRef>(
    config: super::super::JamConfig<P>,
    requests: async_channel::Receiver<String>,
    responses: async_channel::Sender<String>,
) {
    let max_follows = usize::try_from(config.max_subscriptions).unwrap_or(usize::MAX);
    let mut follows: BTreeMap<String, JamFollow> = BTreeMap::new();
    let mut sequence = 0u64;
    loop {
        enum Wake {
            Request(Result<String, async_channel::RecvError>),
            Block(String, Option<sync_service::Notification>),
        }
        let wake =
            futures_lite::future::or(async { Wake::Request(requests.recv().await) }, async {
                let mut waits = stream::FuturesUnordered::new();
                for (id, follow) in &follows {
                    waits.push(async move {
                        Wake::Block(id.clone(), follow.notifications.recv().await.ok())
                    });
                }
                match waits.next().await {
                    Some(wake) => wake,
                    None => futures_lite::future::pending().await,
                }
            })
            .await;
        match wake {
            Wake::Request(Err(_)) => return,
            Wake::Block(id, notification) => {
                let Some(follow) = follows.get_mut(&id) else {
                    continue;
                };
                let ok = if let Some(notification) = notification {
                    jam_notification(&id, follow, notification, &responses)
                        .await
                        .is_ok()
                } else {
                    false
                };
                if !ok {
                    follows.remove(&id);
                    let _ = responses
                        .send(follow_event(&id, methods::JamHeadFollowEvent::Stop))
                        .await;
                }
            }
            Wake::Request(Ok(request)) => {
                let (request_id, method) = match methods::parse_jsonrpc_client_to_server(&request) {
                    Ok(parsed) => parsed,
                    Err(methods::ParseClientToServerError::JsonRpcParse(_)) => {
                        let _ = responses.send(parse::build_parse_error_response()).await;
                        continue;
                    }
                    Err(methods::ParseClientToServerError::Method { request_id, error }) => {
                        let _ = responses.send(error.to_json_error(request_id)).await;
                        continue;
                    }
                    Err(methods::ParseClientToServerError::UnknownNotification { .. }) => continue,
                };
                let response = match method {
                    methods::MethodCall::jamHead_unstable_follow {} => {
                        if follows.len() >= max_follows || sequence == u64::MAX {
                            parse::build_error_response(
                                request_id,
                                parse::ErrorResponse::ApplicationDefined(
                                    -32800,
                                    "too many active follow subscriptions",
                                ),
                                None,
                            )
                        } else {
                            sequence += 1;
                            let id = sequence.to_string();
                            let snapshot = config.sync_service.subscribe_all(16, false).await;
                            let _ = responses
                                .send(
                                    methods::Response::jamHead_unstable_follow(Cow::Borrowed(&id))
                                        .to_json_response(request_id),
                                )
                                .await;
                            // `scale_encoded_header` fields hold canonical JAM encodings.
                            let (mut follow, root) = JamFollow::new(
                                snapshot.finalized_block_scale_encoded_header,
                                snapshot.new_blocks,
                            );
                            let _ = responses
                                .send(follow_event(
                                    &id,
                                    methods::JamHeadFollowEvent::Initialized {
                                        finalized_block_hashes: vec![methods::HashHexString(root)],
                                    },
                                ))
                                .await;
                            let mut valid = true;
                            let mut best_hash = root;
                            for mut block in snapshot.non_finalized_blocks_ancestry_order {
                                if block.is_new_best {
                                    best_hash = codec::header_hash(&block.scale_encoded_header);
                                }
                                // Snapshot best is reported only after all forks have been
                                // announced. Live block notifications retain their usual order.
                                block.is_new_best = false;
                                if jam_notification(
                                    &id,
                                    &mut follow,
                                    sync_service::Notification::Block(block),
                                    &responses,
                                )
                                .await
                                .is_err()
                                {
                                    valid = false;
                                    break;
                                }
                            }
                            if valid {
                                let _ = responses
                                    .send(follow_event(
                                        &id,
                                        methods::JamHeadFollowEvent::BestBlockChanged {
                                            best_block_hash: methods::HashHexString(best_hash),
                                        },
                                    ))
                                    .await;
                                follows.insert(id, follow);
                            } else {
                                let _ = responses
                                    .send(follow_event(&id, methods::JamHeadFollowEvent::Stop))
                                    .await;
                            }
                            continue;
                        }
                    }
                    methods::MethodCall::jamHead_unstable_header {
                        follow_subscription,
                        hash,
                    } => match follows.get(&*follow_subscription) {
                        None => methods::Response::jamHead_unstable_header(None)
                            .to_json_response(request_id),
                        Some(follow) => match follow.headers.get(&hash.0) {
                            Some(bytes) => methods::Response::jamHead_unstable_header(Some(
                                methods::HexString(bytes.clone()),
                            ))
                            .to_json_response(request_id),
                            None => parse::build_error_response(
                                request_id,
                                parse::ErrorResponse::ApplicationDefined(
                                    -32801,
                                    "unknown or unpinned block",
                                ),
                                None,
                            ),
                        },
                    },
                    methods::MethodCall::jamHead_unstable_unpin {
                        follow_subscription,
                        hash_or_hashes,
                    } => {
                        let mut error = None;
                        if let Some(follow) = follows.get_mut(&*follow_subscription) {
                            let hashes = match hash_or_hashes {
                                methods::HashHexStringSingleOrArray::Single(hash) => vec![hash],
                                methods::HashHexStringSingleOrArray::Array(hashes) => hashes,
                            };
                            let mut seen = BTreeSet::new();
                            for hash in &hashes {
                                if !seen.insert(hash.0) {
                                    error = Some(parse::ErrorResponse::ApplicationDefined(
                                        -32804,
                                        "duplicate block hash",
                                    ));
                                    break;
                                }
                                if !follow.headers.contains_key(&hash.0) {
                                    error = Some(parse::ErrorResponse::ApplicationDefined(
                                        -32801,
                                        "unknown or unpinned block",
                                    ));
                                    break;
                                }
                            }
                            if error.is_none() {
                                for hash in hashes {
                                    follow.unpin(&hash.0);
                                }
                            }
                        }
                        match error {
                            Some(error) => parse::build_error_response(request_id, error, None),
                            None => methods::Response::jamHead_unstable_unpin(())
                                .to_json_response(request_id),
                        }
                    }
                    methods::MethodCall::jamHead_unstable_unfollow {
                        follow_subscription,
                    } => {
                        follows.remove(&*follow_subscription);
                        methods::Response::jamHead_unstable_unfollow(())
                            .to_json_response(request_id)
                    }
                    methods::MethodCall::rpc_methods {} => {
                        methods::Response::rpc_methods(methods::RpcMethods {
                            methods: METHODS.iter().map(|name| (*name).into()).collect(),
                        })
                        .to_json_response(request_id)
                    }
                    methods::MethodCall::chainSpec_v1_chainName {} => {
                        methods::Response::chainSpec_v1_chainName(Cow::Borrowed(&config.chain_name))
                            .to_json_response(request_id)
                    }
                    methods::MethodCall::chainSpec_v1_genesisHash {} => {
                        methods::Response::chainSpec_v1_genesisHash(methods::HashHexString(
                            config.genesis_block_hash,
                        ))
                        .to_json_response(request_id)
                    }
                    methods::MethodCall::chainSpec_v1_properties {} => {
                        methods::Response::chainSpec_v1_properties(
                            serde_json::from_str("{}").unwrap(),
                        )
                        .to_json_response(request_id)
                    }
                    _ => parse::build_error_response(
                        request_id,
                        parse::ErrorResponse::MethodNotFound,
                        None,
                    ),
                };
                let _ = responses.send(response).await;
            }
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests;
