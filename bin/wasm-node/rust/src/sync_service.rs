// Smoldot
// Copyright (C) 2019-2021  Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Background syncing service.
//!
//! The role of the [`SyncService`] is to do whatever necessary to obtain and stay up-to-date
//! with the best and the finalized blocks of a chain.
//!
//! The configuration of the chain to synchronize must be passed when creating a [`SyncService`],
//! after which it will spawn background tasks and use the networking service to stay
//! synchronized.
//!
//! Use [`SyncService::subscribe_best`] and [`SyncService::subscribe_finalized`] to get notified
//! about updates of the best and finalized blocks.

use crate::{ffi, lossy_channel, network_service, runtime_service};

use futures::{
    channel::{mpsc, oneshot},
    lock::Mutex,
    prelude::*,
};
use smoldot::{
    chain::{self, async_tree},
    executor::{host, read_only_runtime_host},
    header,
    informant::HashDisplay,
    libp2p::{self, PeerId},
    network::{self, protocol, service},
    sync::{all, all_forks::sources, para},
    trie::{self, prefix_proof, proof_verify},
};
use std::{
    collections::HashMap,
    convert::TryFrom as _,
    fmt, iter,
    num::{NonZeroU32, NonZeroU64},
    pin::Pin,
    sync::Arc,
};

pub use crate::lossy_channel::Receiver as NotificationsReceiver;

/// Configuration for a [`SyncService`].
pub struct Config {
    /// Name of the chain, for logging purposes.
    ///
    /// > **Note**: This name will be directly printed out. Any special character should already
    /// >           have been filtered out from this name.
    pub log_name: String,

    /// State of the finalized chain.
    pub chain_information: chain::chain_information::ValidChainInformation,

    /// Closure that spawns background tasks.
    pub tasks_executor: Box<dyn FnMut(String, Pin<Box<dyn Future<Output = ()> + Send>>) + Send>,

    /// Access to the network, and index of the chain to sync from the point of view of the
    /// network service.
    pub network_service: (Arc<network_service::NetworkService>, usize),

    /// Receiver for events coming from the network, as returned by
    /// [`network_service::NetworkService::new`].
    pub network_events_receiver: mpsc::Receiver<network_service::Event>,

    /// Extra fields used when the chain is a parachain.
    /// If `None`, this chain is a standalone chain or a relay chain.
    pub parachain: Option<ConfigParachain>,
}

/// See [`Config::parachain`].
pub struct ConfigParachain {
    /// Runtime service that synchronizes the relay chain of this parachain.
    pub relay_chain_sync: Arc<runtime_service::RuntimeService>,

    /// Id of the parachain within the relay chain.
    ///
    /// This is an arbitrary number used to identify the parachain within the storage of the
    /// relay chain.
    ///
    /// > **Note**: This information is normally found in the chain specification of the
    /// >           parachain.
    pub parachain_id: u32,
}

/// Identifier for a blocks request to be performed.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct BlocksRequestId(usize);

pub struct SyncService {
    /// Sender of messages towards the background task.
    to_background: Mutex<mpsc::Sender<ToBackground>>,

    /// See [`Config::network_service`].
    network_service: Arc<network_service::NetworkService>,
    /// See [`Config::network_service`].
    network_chain_index: usize,
}

impl SyncService {
    pub async fn new(mut config: Config) -> Self {
        let (to_background, from_foreground) = mpsc::channel(16);

        if let Some(config_parachain) = config.parachain {
            (config.tasks_executor)(
                "sync-para".into(),
                Box::pin(start_parachain(
                    config.log_name.clone(),
                    config.chain_information,
                    config_parachain.relay_chain_sync.clone(),
                    config_parachain.parachain_id,
                    from_foreground,
                    config.network_service.1,
                    config.network_events_receiver,
                )),
            );
        } else {
            (config.tasks_executor)(
                "sync-relay".into(),
                Box::pin(
                    start_relay_chain(
                        config.log_name,
                        config.chain_information,
                        from_foreground,
                        config.network_service.0.clone(),
                        config.network_service.1,
                        config.network_events_receiver,
                    )
                    .await,
                ),
            );
        }

        SyncService {
            to_background: Mutex::new(to_background),
            network_service: config.network_service.0,
            network_chain_index: config.network_service.1,
        }
    }

    /// Returns the SCALE-encoded header of the current finalized block, alongside with a stream
    /// producing updates of the finalized block.
    ///
    /// Not all updates are necessarily reported. In particular, updates that weren't pulled from
    /// the `Stream` yet might get overwritten by newest updates.
    ///
    /// If you have subscribed to new blocks, the finalized blocks reported in this channel are
    /// guaranteed to have earlier been reported as new blocks.
    ///
    /// If you have subscribed to best blocks, the finalized blocks reported in this channel are
    /// guaranteed to be ancestors of the latest reported best block.
    // TODO: is this last paragraph true for parachains?
    pub async fn subscribe_finalized(&self) -> (Vec<u8>, NotificationsReceiver<Vec<u8>>) {
        let (send_back, rx) = oneshot::channel();

        self.to_background
            .lock()
            .await
            .send(ToBackground::SubscribeFinalized { send_back })
            .await
            .unwrap();

        rx.await.unwrap()
    }

    /// Returns the SCALE-encoded header of the current best block, alongside with a stream
    /// producing updates of the best block.
    ///
    /// Not all updates are necessarily reported. In particular, updates that weren't pulled from
    /// the `Stream` yet might get overwritten by newest updates.
    pub async fn subscribe_best(&self) -> (Vec<u8>, NotificationsReceiver<Vec<u8>>) {
        let (send_back, rx) = oneshot::channel();

        self.to_background
            .lock()
            .await
            .send(ToBackground::SubscribeBest { send_back })
            .await
            .unwrap();

        rx.await.unwrap()
    }

    /// Subscribes to the state of the chain: the current state and the new blocks.
    ///
    /// Contrary to [`SyncService::subscribe_best`], *all* new blocks are reported. Only up to
    /// `buffer_size` block notifications are buffered in the channel. If the channel is full
    /// when a new notification is attempted to be pushed, the channel gets closed.
    ///
    /// The channel also gets closed if a gap in the finality happens, such as after a Grandpa
    /// warp syncing.
    ///
    /// See [`SubscribeAll`] for information about the return value.
    pub async fn subscribe_all(&self, buffer_size: usize) -> SubscribeAll {
        let (send_back, rx) = oneshot::channel();

        self.to_background
            .lock()
            .await
            .send(ToBackground::SubscribeAll {
                send_back,
                buffer_size,
            })
            .await
            .unwrap();

        rx.await.unwrap()
    }

    /// Returns true if it is believed that we are near the head of the chain.
    ///
    /// The way this method is implemented is opaque and cannot be relied on. The return value
    /// should only ever be shown to the user and not used for any meaningful logic.
    pub async fn is_near_head_of_chain_heuristic(&self) -> bool {
        let (send_back, rx) = oneshot::channel();

        self.to_background
            .lock()
            .await
            .send(ToBackground::IsNearHeadOfChainHeuristic { send_back })
            .await
            .unwrap();

        rx.await.unwrap()
    }

    /// Returns the list of peers from the [`network_service::NetworkService`] that are used to
    /// synchronize blocks.
    ///
    /// Returns, for each peer, their identity and best block number and hash.
    ///
    /// This function is subject to race condition. The list returned by this function can change
    /// at any moment. The return value should only ever be shown to the user and not used for any
    /// meaningful logic
    pub async fn syncing_peers(
        &self,
    ) -> impl ExactSizeIterator<Item = (PeerId, protocol::Role, u64, [u8; 32])> {
        let (send_back, rx) = oneshot::channel();

        self.to_background
            .lock()
            .await
            .send(ToBackground::SyncingPeers { send_back })
            .await
            .unwrap();

        rx.await.unwrap().into_iter()
    }

    /// Returns the list of peers from the [`network_service::NetworkService`] that are expected to
    /// be aware of the given block.
    ///
    /// A peer is returned by this method either if it has directly sent a block announce in the
    /// past, or if the requested block height is below the finalized block height and the best
    /// block of the peer is above the requested block. In other words, it is assumed that all
    /// peers are always on the same finalized chain as the local node.
    ///
    /// This function is subject to race condition. The list returned by this function is not
    /// necessarily exact, as a peer might have known about a block in the past but no longer
    /// does.
    pub async fn peers_assumed_know_blocks(
        &self,
        block_number: u64,
        block_hash: &[u8; 32],
    ) -> impl Iterator<Item = PeerId> {
        let (send_back, rx) = oneshot::channel();

        self.to_background
            .lock()
            .await
            .send(ToBackground::PeersAssumedKnowBlock {
                send_back,
                block_number,
                block_hash: *block_hash,
            })
            .await
            .unwrap();

        rx.await.unwrap().into_iter()
    }

    // TODO: doc; explain the guarantees
    pub async fn block_query(
        self: Arc<Self>,
        hash: [u8; 32],
        fields: protocol::BlocksRequestFields,
    ) -> Result<protocol::BlockData, ()> {
        // TODO: better error?
        const NUM_ATTEMPTS: usize = 3;

        let request_config = protocol::BlocksRequestConfig {
            start: protocol::BlocksRequestConfigStart::Hash(hash),
            desired_count: NonZeroU32::new(1).unwrap(),
            direction: protocol::BlocksRequestDirection::Ascending,
            fields: fields.clone(),
        };

        // TODO: better peers selection ; don't just take the first 3
        // TODO: must only ask the peers that know about this block
        for target in self.network_service.peers_list().await.take(NUM_ATTEMPTS) {
            let mut result = match self
                .network_service
                .clone()
                .blocks_request(target, self.network_chain_index, request_config.clone())
                .await
            {
                Ok(b) => b,
                Err(_) => continue,
            };

            if result.len() != 1 {
                continue;
            }

            let result = result.remove(0);

            if result.header.is_none() && fields.header {
                continue;
            }
            if result
                .header
                .as_ref()
                .map_or(false, |h| header::decode(h).is_err())
            {
                continue;
            }
            if result.body.is_none() && fields.body {
                continue;
            }
            // Note: the presence of a justification isn't checked and can't be checked, as not
            // all blocks have a justification in the first place.
            if result.hash != hash {
                continue;
            }
            if result.header.as_ref().map_or(false, |h| {
                header::hash_from_scale_encoded_header(&h) != result.hash
            }) {
                continue;
            }
            match (&result.header, &result.body) {
                (Some(_), Some(_)) => {
                    // TODO: verify correctness of body
                }
                _ => {}
            }

            return Ok(result);
        }

        Err(())
    }

    /// Performs one or more storage proof requests in order to find the value of the given
    /// `requested_keys`.
    ///
    /// Must be passed a block hash and the Merkle value of the root node of the storage trie of
    /// this same block. The value of `storage_trie_root` corresponds to the value in the
    /// [`smoldot::header::HeaderRef::state_root`] field.
    ///
    /// Returns the storage values of `requested_keys` in the storage of the block, or an error if
    /// it couldn't be determined. If `Ok`, the `Vec` is guaranteed to have the same number of
    /// elements as `requested_keys`.
    ///
    /// This function is equivalent to calling
    /// [`network_service::NetworkService::storage_proof_request`] and verifying the proof,
    /// potentially multiple times until it succeeds. The number of attempts and the selection of
    /// peers is done through reasonable heuristics.
    pub async fn storage_query(
        self: Arc<Self>,
        block_hash: &[u8; 32],
        storage_trie_root: &[u8; 32],
        requested_keys: impl Iterator<Item = impl AsRef<[u8]>> + Clone,
    ) -> Result<Vec<Option<Vec<u8>>>, StorageQueryError> {
        const NUM_ATTEMPTS: usize = 3;

        let mut outcome_errors = Vec::with_capacity(NUM_ATTEMPTS);

        // TODO: better peers selection ; don't just take the first 3
        // TODO: must only ask the peers that know about this block
        for target in self.network_service.peers_list().await.take(NUM_ATTEMPTS) {
            let result = self
                .network_service
                .clone()
                .storage_proof_request(
                    self.network_chain_index,
                    target,
                    protocol::StorageProofRequestConfig {
                        block_hash: *block_hash,
                        keys: requested_keys.clone(),
                    },
                )
                .await
                .map_err(StorageQueryErrorDetail::Network)
                .and_then(|outcome| {
                    let mut result = Vec::with_capacity(requested_keys.clone().count());
                    for key in requested_keys.clone() {
                        result.push(
                            proof_verify::verify_proof(proof_verify::VerifyProofConfig {
                                proof: outcome.iter().map(|nv| &nv[..]),
                                requested_key: key.as_ref(),
                                trie_root_hash: &storage_trie_root,
                            })
                            .map_err(StorageQueryErrorDetail::ProofVerification)?
                            .map(|v| v.to_owned()),
                        );
                    }
                    debug_assert_eq!(result.len(), result.capacity());
                    Ok(result)
                });

            match result {
                Ok(values) => return Ok(values),
                Err(err) => {
                    outcome_errors.push(err);
                }
            }
        }

        Err(StorageQueryError {
            errors: outcome_errors,
        })
    }

    pub async fn storage_prefix_keys_query(
        self: Arc<Self>,
        block_number: u64,
        block_hash: &[u8; 32],
        prefix: &[u8],
        storage_trie_root: &[u8; 32],
    ) -> Result<Vec<Vec<u8>>, StorageQueryError> {
        let mut prefix_scan = prefix_proof::prefix_scan(prefix_proof::Config {
            prefix,
            trie_root_hash: *storage_trie_root,
        });

        'main_scan: loop {
            const NUM_ATTEMPTS: usize = 3;

            let mut outcome_errors = Vec::with_capacity(NUM_ATTEMPTS);

            // TODO: better peers selection ; don't just take the first 3
            for target in self
                .peers_assumed_know_blocks(block_number, block_hash)
                .await
                .take(NUM_ATTEMPTS)
            {
                let result = self
                    .network_service
                    .clone()
                    .storage_proof_request(
                        self.network_chain_index,
                        target,
                        protocol::StorageProofRequestConfig {
                            block_hash: *block_hash,
                            keys: prefix_scan.requested_keys().map(|nibbles| {
                                trie::nibbles_to_bytes_extend(nibbles).collect::<Vec<_>>()
                            }),
                        },
                    )
                    .await
                    .map_err(StorageQueryErrorDetail::Network);

                match result {
                    Ok(proof) => {
                        match prefix_scan.resume(proof.iter().map(|v| &v[..])) {
                            Ok(prefix_proof::ResumeOutcome::InProgress(scan)) => {
                                // Continue next step of the proof.
                                prefix_scan = scan;
                                continue 'main_scan;
                            }
                            Ok(prefix_proof::ResumeOutcome::Success { keys }) => {
                                return Ok(keys);
                            }
                            Err((scan, err)) => {
                                prefix_scan = scan;
                                outcome_errors
                                    .push(StorageQueryErrorDetail::ProofVerification(err));
                            }
                        }
                    }
                    Err(err) => {
                        outcome_errors.push(err);
                    }
                }
            }

            return Err(StorageQueryError {
                errors: outcome_errors,
            });
        }
    }

    // TODO: documentation
    // TODO: there's no proof that the call proof is actually correct
    pub async fn call_proof_query<'a>(
        self: Arc<Self>,
        block_number: u64,
        config: protocol::CallProofRequestConfig<
            'a,
            impl Iterator<Item = impl AsRef<[u8]>> + Clone,
        >,
    ) -> Result<Vec<Vec<u8>>, CallProofQueryError> {
        const NUM_ATTEMPTS: usize = 3;

        let mut outcome_errors = Vec::with_capacity(NUM_ATTEMPTS);

        // TODO: better peers selection ; don't just take the first 3
        for target in self
            .peers_assumed_know_blocks(block_number, &config.block_hash)
            .await
            .take(NUM_ATTEMPTS)
        {
            let result = self
                .network_service
                .clone()
                .call_proof_request(self.network_chain_index, target, config.clone())
                .await;

            match result {
                Ok(value) if !value.is_empty() => return Ok(value),
                // TODO: this check of emptiness is a bit of a hack; it is necessary because Substrate responds to requests about blocks it doesn't know with an empty proof
                Ok(_) => outcome_errors.push(service::CallProofRequestError::Request(
                    smoldot::libp2p::peers::RequestError::Connection(
                        smoldot::libp2p::connection::established::RequestError::SubstreamClosed,
                    ),
                )),
                Err(err) => {
                    outcome_errors.push(err);
                }
            }
        }

        Err(CallProofQueryError {
            errors: outcome_errors,
        })
    }
}

/// Error that can happen when calling [`SyncService::storage_query`].
#[derive(Debug)]
pub struct StorageQueryError {
    /// Contains one error per peer that has been contacted. If this list is empty, then we
    /// aren't connected to any node.
    pub errors: Vec<StorageQueryErrorDetail>,
}

impl StorageQueryError {
    /// Returns `true` if this is caused by networking issues, as opposed to a consensus-related
    /// issue.
    pub fn is_network_problem(&self) -> bool {
        self.errors.iter().all(|err| match err {
            StorageQueryErrorDetail::Network(service::StorageProofRequestError::Request(_)) => true,
            StorageQueryErrorDetail::Network(service::StorageProofRequestError::Decode(_)) => false,
            // TODO: as a temporary hack, we consider `TrieRootNotFound` as the remote not knowing about the requested block; see https://github.com/paritytech/substrate/pull/8046
            StorageQueryErrorDetail::ProofVerification(proof_verify::Error::TrieRootNotFound) => {
                true
            }
            StorageQueryErrorDetail::ProofVerification(_) => false,
        })
    }
}

impl fmt::Display for StorageQueryError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.errors.is_empty() {
            write!(f, "No node available for storage query")
        } else {
            write!(f, "Storage query errors:")?;
            for err in &self.errors {
                write!(f, "\n- {}", err)?;
            }
            Ok(())
        }
    }
}

/// See [`StorageQueryError`].
#[derive(Debug, derive_more::Display)]
pub enum StorageQueryErrorDetail {
    /// Error during the network request.
    #[display(fmt = "{}", _0)]
    Network(service::StorageProofRequestError),
    /// Error verifying the proof.
    #[display(fmt = "{}", _0)]
    ProofVerification(proof_verify::Error),
}

/// Error that can happen when calling [`SyncService::call_proof_query`].
#[derive(Debug, Clone)]
pub struct CallProofQueryError {
    /// Contains one error per peer that has been contacted. If this list is empty, then we
    /// aren't connected to any node.
    pub errors: Vec<service::CallProofRequestError>,
}

impl CallProofQueryError {
    /// Returns `true` if this is caused by networking issues, as opposed to a consensus-related
    /// issue.
    pub fn is_network_problem(&self) -> bool {
        self.errors.iter().all(|err| err.is_network_problem())
    }
}

impl fmt::Display for CallProofQueryError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.errors.is_empty() {
            write!(f, "No node available for call proof query")
        } else {
            write!(f, "Call proof query errors:")?;
            for err in &self.errors {
                write!(f, "\n- {}", err)?;
            }
            Ok(())
        }
    }
}

/// Return value of [`SyncService::subscribe_all`].
pub struct SubscribeAll {
    /// SCALE-encoded header of the finalized block at the time of the subscription.
    pub finalized_block_scale_encoded_header: Vec<u8>,

    /// List of all known non-finalized blocks at the time of subscription.
    ///
    /// Only one element in this list has [`BlockNotification::is_new_best`] equal to true.
    ///
    /// The blocks are guaranteed to be ordered so that parents are always found before their
    /// children.
    pub non_finalized_blocks_ancestry_order: Vec<BlockNotification>,

    /// Channel onto which new blocks are sent. The channel gets closed if it is full when a new
    /// block needs to be reported.
    pub new_blocks: mpsc::Receiver<Notification>,
}

/// Notification about a new block or a new finalized block.
///
/// See [`SyncService::subscribe_all`].
#[derive(Debug, Clone)]
pub enum Notification {
    /// A non-finalized block has been finalized.
    Finalized {
        /// Blake2 hash of the block that has been finalized.
        ///
        /// A block with this hash is guaranteed to have earlier been reported in a
        /// [`BlockNotification`], either in [`SubscribeAll::non_finalized_blocks`] or in a
        /// [`Notification::Block`].
        ///
        /// It is, however, not guaranteed that this block is a child of the previously-finalized
        /// block. In other words, if multiple blocks are finalized at the same time, only one
        /// [`Notification::Finalized`] is generated and contains the highest finalized block.
        hash: [u8; 32],

        /// Hash of the best block after the finalization.
        ///
        /// If the newly-finalized block is an ancestor of the current best block, then this field
        /// contains the hash of this current best block. Otherwise, the best block is now
        /// the non-finalized block with the given hash.
        ///
        /// A block with this hash is guaranteed to have earlier been reported in a
        /// [`BlockNotification`], either in [`SubscribeAll::non_finalized_blocks`] or in a
        /// [`Notification::Block`].
        best_block_hash: [u8; 32],
    },

    /// A new block has been added to the list of unfinalized blocks.
    Block(BlockNotification),
}

/// Notification about a new block.
///
/// See [`SyncService::subscribe_all`].
#[derive(Debug, Clone)]
pub struct BlockNotification {
    /// True if this block is considered as the best block of the chain.
    pub is_new_best: bool,

    /// SCALE-encoded header of the block.
    pub scale_encoded_header: Vec<u8>,

    /// Blake2 hash of the header of the parent of this block.
    ///
    ///
    /// A block with this hash is guaranteed to have earlier been reported in a
    /// [`BlockNotification`], either in [`SubscribeAll::non_finalized_blocks`] or in a
    /// [`Notification::Block`].
    ///
    /// > **Note**: The header of a block contains the hash of its parent. When it comes to
    /// >           consensus algorithms such as Babe or Aura, the syncing code verifies that this
    /// >           hash, stored in the header, actually corresponds to a valid block. However,
    /// >           when it comes to parachain consensus, no such verification is performed.
    /// >           Contrary to the hash stored in the header, the value of this field is
    /// >           guaranteed to refer to a block that is known by the syncing service. This
    /// >           allows a subscriber of the state of the chain to precisely track the hierarchy
    /// >           of blocks, without risking to run into a problem in case of a block with an
    /// >           invalid header.
    pub parent_hash: [u8; 32],
}

async fn start_relay_chain(
    log_name: String,
    chain_information: chain::chain_information::ValidChainInformation,
    mut from_foreground: mpsc::Receiver<ToBackground>,
    network_service: Arc<network_service::NetworkService>,
    network_chain_index: usize,
    mut from_network_service: mpsc::Receiver<network_service::Event>,
) -> impl Future<Output = ()> {
    let log_target = format!("sync-service-{}", log_name);

    // TODO: implicit generics
    let mut sync = all::AllSync::<_, (libp2p::PeerId, protocol::Role), ()>::new(all::Config {
        chain_information,
        sources_capacity: 32,
        blocks_capacity: {
            // This is the maximum number of blocks between two consecutive justifications.
            1024
        },
        max_disjoint_headers: 1024,
        max_requests_per_block: NonZeroU32::new(3).unwrap(),
        download_ahead_blocks: {
            // Verifying a block mostly consists in:
            //
            // - Verifying a sr25519 signature for each block, plus a VRF output when the
            // block is claiming a primary BABE slot.
            // - Verifying one ed25519 signature per authority for every justification.
            //
            // At the time of writing, the speed of these operations hasn't been benchmarked.
            // It is likely that it varies quite a bit between the various environments (the
            // different browser engines, and NodeJS).
            //
            // Assuming a maximum verification speed of 5k blocks/sec and a 95% latency of one
            // second, the number of blocks to download ahead of time in order to not block
            // is 5k.
            NonZeroU32::new(5000).unwrap()
        },
        full: None,
    });

    async move {
        // TODO: remove
        let mut peers_source_id_map = HashMap::new();

        // List of block requests currently in progress.
        let mut pending_block_requests = stream::FuturesUnordered::new();
        // List of grandpa warp sync requests currently in progress.
        let mut pending_grandpa_requests = stream::FuturesUnordered::new();
        // List of storage requests currently in progress.
        let mut pending_storage_requests = stream::FuturesUnordered::new();
        let mut finalized_notifications = Vec::<lossy_channel::Sender<Vec<u8>>>::new();
        let mut best_notifications = Vec::<lossy_channel::Sender<Vec<u8>>>::new();
        let mut all_notifications = Vec::<mpsc::Sender<Notification>>::new();

        let mut has_new_best = false;
        let mut has_new_finalized = false;

        // Main loop of the syncing logic.
        loop {
            loop {
                // `desired_requests()` returns, in decreasing order of priority, the requests
                // that should be started in order for the syncing to proceed. We simply pick the
                // first request, but enforce one ongoing request per source.
                let (source_id, _, mut request_detail) = match sync
                    .desired_requests()
                    .find(|(source_id, _, _)| sync.source_num_ongoing_requests(*source_id) == 0)
                {
                    Some(v) => v,
                    None => break,
                };

                // Before notifying the syncing of the request, clamp the number of blocks to the
                // number of blocks we expect to receive.
                request_detail.num_blocks_clamp(NonZeroU64::new(64).unwrap());

                match request_detail {
                    all::RequestDetail::BlocksRequest {
                        first_block_hash,
                        first_block_height,
                        ascending,
                        num_blocks,
                        request_headers,
                        request_bodies,
                        request_justification,
                    } => {
                        let peer_id = sync.source_user_data_mut(source_id).0.clone(); // TODO: why does this require cloning? weird borrow chk issue

                        let block_request = network_service.clone().blocks_request(
                            peer_id,
                            network_chain_index,
                            network::protocol::BlocksRequestConfig {
                                start: if let Some(first_block_hash) = first_block_hash {
                                    network::protocol::BlocksRequestConfigStart::Hash(
                                        first_block_hash,
                                    )
                                } else {
                                    network::protocol::BlocksRequestConfigStart::Number(
                                        NonZeroU64::new(first_block_height).unwrap(), // TODO: unwrap?
                                    )
                                },
                                desired_count: NonZeroU32::new(
                                    u32::try_from(num_blocks.get()).unwrap_or(u32::max_value()),
                                )
                                .unwrap(),
                                direction: if ascending {
                                    network::protocol::BlocksRequestDirection::Ascending
                                } else {
                                    network::protocol::BlocksRequestDirection::Descending
                                },
                                fields: network::protocol::BlocksRequestFields {
                                    header: request_headers,
                                    body: request_bodies,
                                    justification: request_justification,
                                },
                            },
                        );

                        let (block_request, abort) = future::abortable(block_request);
                        let request_id = sync.add_request(source_id, request_detail, abort);

                        pending_block_requests
                            .push(async move { (request_id, block_request.await) });
                    }
                    all::RequestDetail::GrandpaWarpSync {
                        sync_start_block_hash,
                    } => {
                        let peer_id = sync.source_user_data_mut(source_id).0.clone(); // TODO: why does this require cloning? weird borrow chk issue

                        let grandpa_request = network_service.clone().grandpa_warp_sync_request(
                            peer_id,
                            network_chain_index,
                            sync_start_block_hash,
                        );

                        let (grandpa_request, abort) = future::abortable(grandpa_request);
                        let request_id = sync.add_request(source_id, request_detail, abort);

                        pending_grandpa_requests
                            .push(async move { (request_id, grandpa_request.await) });
                    }
                    all::RequestDetail::StorageGet {
                        block_hash,
                        state_trie_root,
                        ref keys,
                    } => {
                        let peer_id = sync.source_user_data_mut(source_id).0.clone(); // TODO: why does this require cloning? weird borrow chk issue

                        let storage_request = network_service.clone().storage_proof_request(
                            network_chain_index,
                            peer_id,
                            network::protocol::StorageProofRequestConfig {
                                block_hash,
                                keys: keys.clone().into_iter(),
                            },
                        );

                        let keys = keys.clone();
                        let storage_request = async move {
                            if let Ok(outcome) = storage_request.await {
                                // TODO: lots of copying around
                                // TODO: log what happens
                                keys.iter()
                                    .map(|key| {
                                        proof_verify::verify_proof(
                                            proof_verify::VerifyProofConfig {
                                                proof: outcome.iter().map(|nv| &nv[..]),
                                                requested_key: key.as_ref(),
                                                trie_root_hash: &state_trie_root,
                                            },
                                        )
                                        .map_err(|_| ())
                                        .map(|v| v.map(|v| v.to_vec()))
                                    })
                                    .collect::<Result<Vec<_>, ()>>()
                            } else {
                                Err(())
                            }
                        };

                        let (storage_request, abort) = future::abortable(storage_request);
                        let request_id = sync.add_request(source_id, request_detail, abort);

                        pending_storage_requests
                            .push(async move { (request_id, storage_request.await) });
                    }
                }
            }

            // TODO: handle obsolete requests

            // The sync state machine can be in a few various states. At the time of writing:
            // idle, verifying header, verifying block, verifying grandpa warp sync proof,
            // verifying storage proof.
            // If the state is one of the "verifying" states, perform the actual verification and
            // loop again until the sync is in an idle state.
            loop {
                match sync.process_one() {
                    all::ProcessOne::AllSync(idle) => {
                        sync = idle;
                        break;
                    }
                    all::ProcessOne::VerifyWarpSyncFragment(verify) => {
                        let sender_peer_id = verify.proof_sender().1 .0.clone(); // TODO: unnecessary cloning most of the time

                        let (sync_out, result) = verify.perform();
                        sync = sync_out;

                        if let Err(err) = result {
                            log::warn!(
                                target: &log_target,
                                "Failed to verify warp sync fragment from {}: {}",
                                sender_peer_id,
                                err
                            );
                        }

                        // Verifying a fragment is rather expensive. We yield in order to not
                        // block the entire node.
                        super::yield_once().await;
                    }
                    all::ProcessOne::VerifyHeader(verify) => {
                        let verified_hash = verify.hash();

                        // Verifying a block is rather expensive. We yield in order to not
                        // block the entire node.
                        super::yield_once().await;

                        match verify.perform(ffi::unix_time(), ()) {
                            all::HeaderVerifyOutcome::Success {
                                sync: sync_out,
                                is_new_best,
                                is_new_finalized,
                                ..
                            } => {
                                log::debug!(
                                    target: &log_target,
                                    "Successfully verified header {} (new best: {})",
                                    HashDisplay(&verified_hash),
                                    if is_new_best { "yes" } else { "no" }
                                );

                                if is_new_best {
                                    has_new_best = true;
                                }
                                if is_new_finalized {
                                    // It is possible that finalizing this new block has modified
                                    // the best block as well.
                                    // TODO: ^ this is really a footgun; make it clearer in the syncing API
                                    has_new_best = true;
                                    has_new_finalized = true;
                                }

                                // Elements in `all_notifications` are removed one by one and
                                // inserted back if the channel is still open.
                                for index in (0..all_notifications.len()).rev() {
                                    let mut subscription = all_notifications.swap_remove(index);
                                    // TODO: the code below is `O(n)` complexity
                                    let header = sync_out
                                        .non_finalized_blocks_ancestry_order()
                                        .find(|h| h.hash() == verified_hash)
                                        .unwrap();
                                    let notification = Notification::Block(BlockNotification {
                                        is_new_best,
                                        scale_encoded_header: header.scale_encoding_vec(),
                                        parent_hash: *header.parent_hash,
                                    });

                                    if subscription.try_send(notification).is_err() {
                                        continue;
                                    }
                                    if is_new_finalized {
                                        if subscription
                                            .try_send(Notification::Finalized {
                                                hash: verified_hash,
                                                best_block_hash: sync_out.best_block_hash(),
                                            })
                                            .is_err()
                                        {
                                            continue;
                                        }
                                    }
                                    all_notifications.push(subscription);
                                }

                                sync = sync_out;
                                continue;
                            }
                            all::HeaderVerifyOutcome::Error {
                                sync: sync_out,
                                error,
                                ..
                            } => {
                                log::warn!(
                                    target: &log_target,
                                    "Error while verifying header {}: {}",
                                    HashDisplay(&verified_hash),
                                    error
                                );

                                sync = sync_out;
                                continue;
                            }
                        }
                    }

                    // Can't verify header and body in non-full mode.
                    all::ProcessOne::VerifyBodyHeader(_) => unreachable!(),
                }
            }

            // TODO: handle this differently
            if has_new_best {
                has_new_best = false;

                let scale_encoded_header = sync.best_block_header().scale_encoding_vec();
                for index in (0..best_notifications.len()).rev() {
                    let mut notif = best_notifications.swap_remove(index);
                    if notif.send(scale_encoded_header.clone()).is_ok() {
                        best_notifications.push(notif);
                    }
                }

                let fut = network_service.set_local_best_block(
                    network_chain_index,
                    sync.best_block_hash(),
                    sync.best_block_number(),
                );
                fut.await;

                // Since this task is verifying blocks, a heavy CPU-only operation, it is very
                // much possible for it to take a long time before having to wait for some event.
                // Since JavaScript/Wasm is single-threaded, this would prevent all the other
                // tasks in the background from running.
                // In order to provide a better granularity, we force a yield after each new serie
                // of verifications.
                crate::yield_once().await;
            }

            // TODO: handle this differently
            if has_new_finalized {
                has_new_finalized = false;

                // If the chain uses GrandPa, the networking has to be kept up-to-date with the
                // state of finalization for other peers to send back relevant gossip messages.
                // (code style) `grandpa_set_id` is extracted first in order to avoid borrowing
                // checker issues.
                let grandpa_set_id =
                    if let chain::chain_information::ChainInformationFinalityRef::Grandpa {
                        after_finalized_block_authorities_set_id,
                        ..
                    } = sync.as_chain_information().as_ref().finality
                    {
                        Some(after_finalized_block_authorities_set_id)
                    } else {
                        None
                    };
                if let Some(set_id) = grandpa_set_id {
                    let commit_finalized_height =
                        u32::try_from(sync.finalized_block_header().number).unwrap(); // TODO: unwrap :-/
                    network_service
                        .set_local_grandpa_state(
                            network_chain_index,
                            network::service::GrandpaState {
                                set_id,
                                round_number: 1, // TODO:
                                commit_finalized_height,
                            },
                        )
                        .await;
                }

                let scale_encoded_header = sync.finalized_block_header().scale_encoding_vec();
                for index in (0..finalized_notifications.len()).rev() {
                    let mut notif = finalized_notifications.swap_remove(index);
                    if notif.send(scale_encoded_header.clone()).is_ok() {
                        finalized_notifications.push(notif);
                    }
                }

                // Since this task is verifying blocks, a heavy CPU-only operation, it is very
                // much possible for it to take a long time before having to wait for some event.
                // Since JavaScript/Wasm is single-threaded, this would prevent all the other
                // tasks in the background from running.
                // In order to provide a better granularity, we force a yield after each new serie
                // of verifications.
                crate::yield_once().await;
            }

            // All requests have been started.
            // Now waiting for some event to happen: a network event, a request from the frontend
            // of the sync service, or a request being finished.
            let response_outcome = futures::select! {
                network_event = from_network_service.next() => {
                    // Something happened on the network.

                    let network_event = match network_event {
                        Some(m) => m,
                        None => {
                            // The channel from the network service has been closed. Closing the
                            // sync background task as well.
                            return
                        },
                    };

                    match network_event {
                        network_service::Event::Connected { peer_id, role, chain_index, best_block_number, best_block_hash }
                            if chain_index == network_chain_index =>
                        {
                            let id = sync.add_source((peer_id.clone(), role), best_block_number, best_block_hash);
                            peers_source_id_map.insert(peer_id, id);
                        },
                        network_service::Event::Disconnected { peer_id, chain_index }
                            if chain_index == network_chain_index =>
                        {
                            let id = peers_source_id_map.remove(&peer_id).unwrap();
                            let (_, requests) = sync.remove_source(id);
                            for (_, abort) in requests {
                                abort.abort();
                            }
                        },
                        network_service::Event::BlockAnnounce { chain_index, peer_id, announce }
                            if chain_index == network_chain_index =>
                        {
                            let id = *peers_source_id_map.get(&peer_id).unwrap();
                            let decoded = announce.decode();
                            // TODO: stupid to re-encode header
                            match sync.block_announce(id, decoded.header.scale_encoding_vec(), decoded.is_best) {
                                all::BlockAnnounceOutcome::HeaderVerify |
                                all::BlockAnnounceOutcome::AlreadyInChain => {
                                    log::debug!(
                                        target: &log_target,
                                        "Processed block announce from {}", peer_id
                                    );
                                },
                                all::BlockAnnounceOutcome::Discarded => {
                                    log::debug!(
                                        target: &log_target,
                                        "Processed block announce from {} (discarded)", peer_id
                                    );
                                },
                                all::BlockAnnounceOutcome::Disjoint {} => {
                                    log::debug!(
                                        target: &log_target,
                                        "Processed block announce from {} (disjoint)", peer_id
                                    );
                                },
                                all::BlockAnnounceOutcome::TooOld { announce_block_height, .. } => {
                                    log::warn!(
                                        target: &log_target,
                                        "Block announce header height (#{}) from {} is below finalized block",
                                        announce_block_height, peer_id
                                    );
                                },
                                all::BlockAnnounceOutcome::NotFinalizedChain => {
                                    log::warn!(
                                        target: &log_target,
                                        "Block announce from {} isn't part of finalized chain",
                                        peer_id
                                    );
                                },
                                all::BlockAnnounceOutcome::InvalidHeader(err) => {
                                    log::warn!(
                                        target: &log_target,
                                        "Failed to decode block announce header from {}: {}",
                                        peer_id, err
                                    );
                                },
                            }
                        },
                        network_service::Event::GrandpaCommitMessage { chain_index, message }
                            if chain_index == network_chain_index =>
                        {
                            match sync.grandpa_commit_message(&message.as_encoded()) {
                                Ok(()) => {
                                    has_new_finalized = true;
                                    has_new_best = true;  // TODO: done in case finality changes the best block; make this clearer in the sync layer

                                    // Elements in `all_notifications` are removed one by one and
                                    // inserted back if the channel is still open.
                                    for index in (0..all_notifications.len()).rev() {
                                        let mut subscription = all_notifications.swap_remove(index);
                                        if subscription
                                            .try_send(Notification::Finalized {
                                                hash: sync.finalized_block_header().hash(),
                                                best_block_hash: sync.best_block_hash(),
                                            })
                                            .is_err()
                                        {
                                            continue;
                                        }
                                        all_notifications.push(subscription);
                                    }
                                },
                                Err(err) => {
                                    log::warn!(
                                        target: &log_target,
                                        "Error when verifying GrandPa commit message: {}", err
                                    );
                                }
                            }
                        },
                        _ => {
                            // Different chain index.
                        }
                    }

                    continue;
                }

                message = from_foreground.next() => {
                    // Received message from the front `SyncService`.
                    let message = match message {
                        Some(m) => m,
                        None => {
                            // The channel with the frontend sync service has been closed.
                            // Closing the sync background task as a result.
                            return
                        },
                    };

                    match message {
                        ToBackground::IsNearHeadOfChainHeuristic { send_back } => {
                            let _ = send_back.send(sync.is_near_head_of_chain_heuristic());
                        }
                        ToBackground::SubscribeFinalized { send_back } => {
                            let (tx, rx) = lossy_channel::channel();
                            finalized_notifications.push(tx);
                            let current = sync.finalized_block_header().scale_encoding_vec();
                            let _ = send_back.send((current, rx));
                        }
                        ToBackground::SubscribeBest { send_back } => {
                            let (tx, rx) = lossy_channel::channel();
                            best_notifications.push(tx);
                            let current = sync.best_block_header().scale_encoding_vec();
                            let _ = send_back.send((current, rx));
                        }
                        ToBackground::SubscribeAll { send_back, buffer_size } => {
                            let (tx, new_blocks) = mpsc::channel(buffer_size.saturating_sub(1));
                            all_notifications.push(tx);
                            let _ = send_back.send(SubscribeAll {
                                finalized_block_scale_encoded_header: sync.finalized_block_header().scale_encoding_vec(),
                                non_finalized_blocks_ancestry_order: {
                                    let best_hash = sync.best_block_hash();
                                    sync.non_finalized_blocks_ancestry_order().map(|h| {
                                        let scale_encoding = h.scale_encoding_vec();
                                        BlockNotification {
                                            is_new_best: header::hash_from_scale_encoded_header(&scale_encoding) == best_hash,
                                            scale_encoded_header: scale_encoding,
                                            parent_hash: *h.parent_hash,
                                        }
                                    }).collect()
                                },
                                new_blocks,
                            });
                        }
                        ToBackground::PeersAssumedKnowBlock { send_back, block_number, block_hash } => {
                            let finalized_num = sync.finalized_block_header().number;
                            let outcome = if block_number <= finalized_num {
                                sync.sources()
                                    .filter(|source_id| {
                                        let source_best = sync.source_best_block(*source_id);
                                        source_best.0 > block_number ||
                                            (source_best.0 == block_number && *source_best.1 == block_hash)
                                    })
                                    .map(|id| sync.source_user_data(id).0.clone())
                                    .collect()
                            } else {
                                // As documented, `knows_non_finalized_block` would panic if the
                                // block height was below the one of the known finalized block.
                                sync.knows_non_finalized_block(block_number, &block_hash)
                                    .map(|id| sync.source_user_data(id).0.clone())
                                    .collect()
                            };
                            let _ = send_back.send(outcome);
                        }
                        ToBackground::SyncingPeers { send_back } => {
                            let out = sync.sources()
                                .map(|src| {
                                    let (peer_id, role) = sync.source_user_data(src).clone();
                                    let (height, hash) = sync.source_best_block(src);
                                    (peer_id, role, height, *hash)
                                })
                                .collect::<Vec<_>>();
                            let _ = send_back.send(out);
                        }
                    };

                    continue;
                },

                (request_id, result) = pending_block_requests.select_next_some() => {
                    // A block(s) request has been finished.
                    // `result` is an error if the block request got cancelled by the sync state
                    // machine.
                    if let Ok(result) = result {
                        // Inject the result of the request into the sync state machine.
                        sync.blocks_request_response(
                            request_id,
                            result.map_err(|_| ()).map(|v| {
                                v.into_iter().filter_map(|block| {
                                    Some(all::BlockRequestSuccessBlock {
                                        scale_encoded_header: block.header?,
                                        scale_encoded_justification: block.justification,
                                        scale_encoded_extrinsics: Vec::new(),
                                        user_data: (),
                                    })
                                })
                            })
                        ).1

                    } else {
                        // The sync state machine has emitted a `Action::Cancel` earlier, and is
                        // thus no longer interested in the response.
                        continue;
                    }
                },

                (request_id, result) = pending_grandpa_requests.select_next_some() => {
                    // A GrandPa warp sync request has been finished.
                    // `result` is an error if the block request got cancelled by the sync state
                    // machine.
                    if let Ok(result) = result {
                        // Inject the result of the request into the sync state machine.
                        sync.grandpa_warp_sync_response(
                            request_id,
                            result.ok(),
                        ).1

                    } else {
                        // The sync state machine has emitted a `Action::Cancel` earlier, and is
                        // thus no longer interested in the response.
                        continue;
                    }
                },

                (request_id, result) = pending_storage_requests.select_next_some() => {
                    // A storage request has been finished.
                    // `result` is an error if the block request got cancelled by the sync state
                    // machine.
                    if let Ok(result) = result {
                        // Inject the result of the request into the sync state machine.
                        sync.storage_get_response(
                            request_id,
                            result.map(|list| list.into_iter()),
                        ).1

                    } else {
                        // The sync state machine has emitted a `Action::Cancel` earlier, and is
                        // thus no longer interested in the response.
                        continue;
                    }
                },
            };

            // `response_outcome` represents the way the state machine has changed as a
            // consequence of the response to a request.
            match response_outcome {
                all::ResponseOutcome::Outdated
                | all::ResponseOutcome::Queued
                | all::ResponseOutcome::NotFinalizedChain { .. }
                | all::ResponseOutcome::AllAlreadyInChain { .. } => {}
                all::ResponseOutcome::WarpSyncFinished => {
                    let finalized_num = sync.finalized_block_header().number;
                    log::info!(
                        target: &log_target,
                        "GrandPa warp sync finished to #{}",
                        finalized_num
                    );
                    has_new_finalized = true;
                    has_new_best = true;
                    // Since there is a gap in the blocks, all active notifications to all blocks
                    // must be cleared.
                    all_notifications.clear();
                }
            }
        }
    }
}

async fn start_parachain(
    log_target: String,
    chain_information: chain::chain_information::ValidChainInformation,
    relay_chain_sync: Arc<runtime_service::RuntimeService>,
    parachain_id: u32,
    mut from_foreground: mpsc::Receiver<ToBackground>,
    network_chain_index: usize,
    mut from_network_service: mpsc::Receiver<network_service::Event>,
) {
    // Latest finalized parahead.
    let mut finalized_parahead = chain_information
        .as_ref()
        .finalized_block_header
        .scale_encoding_vec();

    // List of senders that get notified when the best block is modified.
    let mut best_subscriptions = Vec::<lossy_channel::Sender<_>>::new();
    // List of senders that get notified when the finalized block is modified.
    let mut finalized_subscriptions = Vec::<lossy_channel::Sender<_>>::new();

    // State machine that tracks the list of parachain network sources and their known blocks.
    let mut sync_sources = sources::AllForksSources::<(PeerId, protocol::Role)>::new(
        40,
        header::decode(&finalized_parahead).unwrap().number,
    );
    // Maps `PeerId`s to their indices within `sync_sources`.
    let mut sync_sources_map = HashMap::new();

    // `true` after a parachain block has been fetched from the parachain.
    // TODO: logic not really correct, as need to check whether relay chain is near head of chain too
    let mut is_near_head_of_chain = false;

    loop {
        // Stream of blocks of the relay chain this parachain is registered on.
        let mut relay_chain_subscribe_all = relay_chain_sync.subscribe_all(32).await;

        // Block the rest of the syncing before we could determine the parahead of the relay
        // chain finalized block.
        if let Ok(finalized) = parahead(
            &relay_chain_sync,
            parachain_id,
            &header::hash_from_scale_encoded_header(
                &relay_chain_subscribe_all.finalized_block_scale_encoded_header,
            ),
        )
        .await
        {
            // Elements in `finalized_subscriptions` are removed one by one
            // and inserted back if the channel is still open.
            for index in (0..finalized_subscriptions.len()).rev() {
                let mut sender = finalized_subscriptions.swap_remove(index);
                if sender.send(finalized.clone()).is_ok() {
                    finalized_subscriptions.push(sender);
                }
            }

            finalized_parahead = finalized;
        }

        // Tree of relay chain blocks. Blocks are inserted when received from the relay chain
        // sync service. Once inside, their corresponding parahead is fetched. Once the parahead
        // is fetched, this parahead is reported to our subscriptions.
        let mut async_tree = async_tree::AsyncTree::<ffi::Instant, [u8; 32], Vec<u8>>::new();
        for block in relay_chain_subscribe_all.non_finalized_blocks_ancestry_order {
            let hash = header::hash_from_scale_encoded_header(&block.scale_encoded_header);
            let parent = async_tree
                .input_iter_unordered()
                .find(|(_, b, _, _)| **b == block.parent_hash)
                .map(|b| b.0); // TODO: check if finalized
            async_tree.input_insert_block(hash, parent, false, block.is_new_best);
        }

        // List of senders that get notified when the tree of blocks is modified.
        // Note that this list is created in the inner loop, as to be cleared if the relay chain
        // blocks stream has a gap.
        let mut all_subscriptions = Vec::<mpsc::Sender<_>>::new();

        // List of in-progress parahead fetching operations.
        let mut in_progress_paraheads = stream::FuturesUnordered::new();

        loop {
            // Start fetching paraheads of new blocks whose parahead needs to be fetched.
            loop {
                match async_tree.next_necessary_async_op(&ffi::Instant::now()) {
                    async_tree::NextNecessaryAsyncOp::NotReady { when } => {
                        // TODO: register when
                        break;
                    }
                    async_tree::NextNecessaryAsyncOp::Ready(op) => {
                        let relay_chain_sync = relay_chain_sync.clone();
                        let block_hash = *op.block_user_data;
                        let async_op_id = op.id;
                        in_progress_paraheads.push(Box::pin(async move {
                            (
                                async_op_id,
                                parahead(&relay_chain_sync, parachain_id, &block_hash).await,
                            )
                        }));
                    }
                }
            }

            futures::select! {
                relay_chain_notif = relay_chain_subscribe_all.new_blocks.next() => {
                    let relay_chain_notif = match relay_chain_notif {
                        Some(n) => n,
                        None => break, // Jumps to the outer loop to recreate the channel.
                    };

                    match relay_chain_notif {
                        Notification::Finalized { hash, best_block_hash } => {
                            let finalized = async_tree.input_iter_unordered().find(|(_, b, _, _)| **b == hash).unwrap().0;
                            let best = async_tree.input_iter_unordered().find(|(_, b, _, _)| **b == best_block_hash).unwrap().0;
                            async_tree.input_finalize(finalized, best);
                        }
                        Notification::Block(block) => {
                            let hash = header::hash_from_scale_encoded_header(&block.scale_encoded_header);
                            let parent = async_tree.input_iter_unordered().find(|(_, b, _, _)| **b == block.parent_hash).map(|b| b.0); // TODO: check if finalized
                            async_tree.input_insert_block(hash, parent, false, block.is_new_best);
                        }
                    };

                    while let Some(update) = async_tree.try_advance_output() {
                        match update {
                            async_tree::OutputUpdate::Finalized { async_op_user_data: parahead, .. }
                                if parahead != finalized_parahead =>
                            {
                                finalized_parahead = parahead;

                                // Elements in `finalized_subscriptions` are removed one by one
                                // and inserted back if the channel is still open.
                                for index in (0..finalized_subscriptions.len()).rev() {
                                    let mut sender = finalized_subscriptions.swap_remove(index);
                                    if sender.send(finalized_parahead.clone()).is_ok() {
                                        finalized_subscriptions.push(sender);
                                    }
                                }

                                // Elements in `all_subscriptions` are removed one by one and
                                // inserted back if the channel is still open.
                                let hash = header::hash_from_scale_encoded_header(&finalized_parahead);
                                let best_block_hash = async_tree.best_block_index()
                                    .map(|(_, parahead)| header::hash_from_scale_encoded_header(parahead))
                                    .unwrap_or(hash);
                                for index in (0..all_subscriptions.len()).rev() {
                                    let mut sender = all_subscriptions.swap_remove(index);
                                    let notif = Notification::Finalized {
                                        hash,
                                        best_block_hash,
                                    };
                                    if sender.try_send(notif).is_ok() {
                                        all_subscriptions.push(sender);
                                    }
                                }
                            }
                            async_tree::OutputUpdate::Finalized { .. } => {
                                // Finalized parahead is same as was already finalized. Don't
                                // report it again.
                            }
                            async_tree::OutputUpdate::Block(block) => {
                                // We need to access `async_tree` below, so deconstruct `block`.
                                let is_new_best = block.is_new_best;
                                let scale_encoded_header = block.async_op_user_data.clone();
                                let block_index = block.index;

                                let parent_header = async_tree.parent(block_index)
                                    .map(|idx| async_tree.block_async_user_data(idx).unwrap())
                                    .unwrap_or_else(|| &finalized_parahead);

                                // Do not report the new block if it is the same as its parent.
                                if *parent_header == scale_encoded_header {
                                    continue;
                                }

                                // TODO: if parent wasn't best block but child is best block, and parent is equal to child, then we don't report the fact that the block is best to the subscribers, causing a state mismatch with potential new subscribers that are grabbed later

                                if is_new_best {
                                    // Elements in `best_subscriptions` are removed one by one
                                    // and inserted back if the channel is still open.
                                    for index in (0..best_subscriptions.len()).rev() {
                                        let mut sender = best_subscriptions.swap_remove(index);
                                        if sender.send(scale_encoded_header.clone()).is_ok() {
                                            best_subscriptions.push(sender);
                                        }
                                    }
                                }

                                // Elements in `all_subscriptions` are removed one by one and
                                // inserted back if the channel is still open.
                                let parent_hash = header::hash_from_scale_encoded_header(&parent_header);
                                for index in (0..all_subscriptions.len()).rev() {
                                    let mut sender = all_subscriptions.swap_remove(index);
                                    let notif = Notification::Block(BlockNotification {
                                        is_new_best,
                                        parent_hash,
                                        scale_encoded_header: scale_encoded_header.clone(),
                                    });
                                    if sender.try_send(notif).is_ok() {
                                        all_subscriptions.push(sender);
                                    }
                                }
                            }
                        }
                    }
                },

                (async_op_id, parahead_result) = in_progress_paraheads.select_next_some() => {
                    match parahead_result {
                        Ok(parahead) => {
                            async_tree.async_op_finished(async_op_id, parahead);
                        },
                        Err(_error) => {
                            // TODO: log here?
                            async_tree.async_op_failure(async_op_id, &ffi::Instant::now());
                        }
                    }
                }

                foreground_message = from_foreground.next().fuse() => {
                    // Terminating the parachain sync task if the foreground has closed.
                    let foreground_message = match foreground_message {
                        Some(m) => m,
                        None => return,
                    };

                    // Note that the rest of this `select!` statement can block for a long time,
                    // which means that there might be a big delay for processing the messages here.
                    // At the time of writing, the nature of the messages makes this a non-issue,
                    // but care should be taken about this.

                    match foreground_message {
                        ToBackground::IsNearHeadOfChainHeuristic { send_back } => {
                            let _ = send_back.send(is_near_head_of_chain);
                        },
                        ToBackground::SubscribeFinalized { send_back } => {
                            let (tx, rx) = lossy_channel::channel();
                            finalized_subscriptions.push(tx);
                            let _ = send_back.send((finalized_parahead.clone(), rx));
                        }
                        ToBackground::SubscribeBest { send_back } => {
                            let (tx, rx) = lossy_channel::channel();
                            best_subscriptions.push(tx);
                            let best_parahead = async_tree.best_block_index().map(|(_, h)| h.clone()).unwrap_or_else(|| finalized_parahead.clone());
                            let _ = send_back.send((best_parahead, rx));
                        }
                        ToBackground::SubscribeAll { send_back, buffer_size } => {
                            let (tx, new_blocks) = mpsc::channel(buffer_size.saturating_sub(1));
                            let _ = send_back.send(SubscribeAll {
                                finalized_block_scale_encoded_header: finalized_parahead.clone(),
                                non_finalized_blocks_ancestry_order: async_tree.input_iter_unordered().filter_map(|(node_index, _, parahead, is_best)| {
                                    let parahead = parahead?;
                                    let parent_hash = async_tree.parent(node_index)
                                        .map(|idx| header::hash_from_scale_encoded_header(&async_tree.block_async_user_data(idx).unwrap()))
                                        .unwrap_or_else(|| header::hash_from_scale_encoded_header(&finalized_parahead));

                                    Some(BlockNotification {
                                        is_new_best: is_best,
                                        scale_encoded_header: parahead.clone(),
                                        parent_hash,
                                    })
                                }).collect(),
                                new_blocks,
                            });

                            all_subscriptions.push(tx);
                        }
                        ToBackground::PeersAssumedKnowBlock { send_back, block_number, block_hash } => {
                            // If `block_number` is over the finalized block, then which source
                            // knows which block is precisely tracked. Otherwise, it is assumed
                            // that all sources are on the finalized chain and thus that all
                            // sources whose best block is superior to `block_number` have it.
                            let list = if block_number > sync_sources.finalized_block_height() {
                                sync_sources.knows_non_finalized_block(block_number, &block_hash)
                                    .map(|local_id| sync_sources.user_data(local_id).0.clone())
                                    .collect()
                            } else {
                                sync_sources
                                    .keys()
                                    .filter(|local_id| {
                                        sync_sources.best_block(*local_id).0 >= block_number
                                    })
                                    .map(|local_id| sync_sources.user_data(local_id).0.clone())
                                    .collect()
                            };

                            let _ = send_back.send(list);
                        }
                        ToBackground::SyncingPeers { send_back } => {
                            let _ = send_back.send(sync_sources.keys().map(|local_id| {
                                let (height, hash) = sync_sources.best_block(local_id);
                                let (peer_id, role) = sync_sources.user_data(local_id).clone();
                                (peer_id, role, height, *hash)
                            }).collect());
                        }
                    }
                },

                network_event = from_network_service.next() => {
                    // Something happened on the network.

                    let network_event = match network_event {
                        Some(m) => m,
                        None => {
                            // The channel from the network service has been closed. Closing the
                            // sync background task as well.
                            return
                        },
                    };

                    match network_event {
                        network_service::Event::Connected { peer_id, role, chain_index, best_block_number, best_block_hash }
                            if chain_index == network_chain_index =>
                        {
                            let local_id = sync_sources.add_source(best_block_number, best_block_hash, (peer_id.clone(), role));
                            sync_sources_map.insert(peer_id, local_id);
                        },
                        network_service::Event::Disconnected { peer_id, chain_index }
                            if chain_index == network_chain_index =>
                        {
                            let local_id = sync_sources_map.remove(&peer_id).unwrap();
                            let (_peer_id, _role) = sync_sources.remove(local_id);
                            debug_assert_eq!(peer_id, _peer_id);
                        },
                        network_service::Event::BlockAnnounce { chain_index, peer_id, announce }
                            if chain_index == network_chain_index =>
                        {
                            let local_id = *sync_sources_map.get(&peer_id).unwrap();
                            let decoded = announce.decode();
                            let decoded_header_hash = decoded.header.hash();
                            sync_sources.add_known_block(local_id, decoded.header.number, decoded_header_hash);
                            if decoded.is_best {
                                sync_sources.set_best_block(local_id, decoded.header.number, decoded_header_hash);
                            }
                        },
                        _ => {
                            // Uninteresting message or irrelevant chain index.
                        }
                    }
                }
            }
        }
    }
}

async fn parahead(
    relay_chain_sync: &Arc<runtime_service::RuntimeService>,
    parachain_id: u32,
    block_hash: &[u8; 32],
) -> Result<Vec<u8>, ParaheadError> {
    // For each relay chain block, call `ParachainHost_persisted_validation_data` in
    // order to know where the parachains are.
    let (runtime_call_lock, virtual_machine) = relay_chain_sync
        .runtime_lock(block_hash)
        .await
        .unwrap() // TODO: /!\ wrong, racy, because finalized blocks are pruned from the relay chain sync
        .start(
            para::PERSISTED_VALIDATION_FUNCTION_NAME,
            para::persisted_validation_data_parameters(
                parachain_id,
                para::OccupiedCoreAssumption::TimedOut,
            ),
        )
        .await
        .map_err(ParaheadError::Call)?;

    // TODO: move the logic below in the `para` module

    let mut runtime_call = match read_only_runtime_host::run(read_only_runtime_host::Config {
        virtual_machine,
        function_to_call: para::PERSISTED_VALIDATION_FUNCTION_NAME,
        parameter: para::persisted_validation_data_parameters(
            parachain_id,
            para::OccupiedCoreAssumption::TimedOut,
        ),
    }) {
        Ok(vm) => vm,
        Err((err, prototype)) => {
            runtime_call_lock.unlock(prototype);
            return Err(ParaheadError::StartError(err));
        }
    };

    let output = loop {
        match runtime_call {
            read_only_runtime_host::RuntimeHostVm::Finished(Ok(success)) => {
                let output = success.virtual_machine.value().as_ref().to_owned();
                runtime_call_lock.unlock(success.virtual_machine.into_prototype());
                break output;
            }
            read_only_runtime_host::RuntimeHostVm::Finished(Err(error)) => {
                runtime_call_lock.unlock(error.prototype);
                return Err(ParaheadError::ReadOnlyRuntime(error.detail));
            }
            read_only_runtime_host::RuntimeHostVm::StorageGet(get) => {
                let storage_value = match runtime_call_lock.storage_entry(&get.key_as_vec()) {
                    Ok(v) => v,
                    Err(err) => {
                        runtime_call_lock.unlock(
                            read_only_runtime_host::RuntimeHostVm::StorageGet(get).into_prototype(),
                        );
                        return Err(ParaheadError::Call(err));
                    }
                };
                runtime_call = get.inject_value(storage_value.map(iter::once));
            }
            read_only_runtime_host::RuntimeHostVm::NextKey(_) => {
                todo!() // TODO:
            }
            read_only_runtime_host::RuntimeHostVm::StorageRoot(storage_root) => {
                runtime_call = storage_root.resume(runtime_call_lock.block_storage_root());
            }
        }
    };

    // Try decode the result of the runtime call.
    // If this fails, it indicates an incompatibility between smoldot and the relay
    // chain.
    match para::decode_persisted_validation_data_return_value(&output) {
        Ok(Some(pvd)) => Ok(pvd.parent_head.to_vec()),
        Ok(None) => {
            // TODO:
            /*// `Ok(None)` indicates that the parachain doesn't occupy any core
            // on the relay chain at the latest block that the relay chain syncing
            // has synced. It might have occupied a core before, or might occupy
            // a core in the future, and as such this is not a fatal error.
            log::log!(
                target: &log_target,
                if relay_sync_near_head_of_chain {
                    log::Level::Warn
                } else {
                    log::Level::Debug
                },
                "Couldn't find the parachain head from relay chain. \
                    The parachain likely doesn't occupy a core."
            );*/
            Err(ParaheadError::NoCore)
        }
        Err(error) => {
            // TODO:
            /*// Only a debug line is printed if not near the head of the chain,
            // to handle chains that have been upgraded later on to support
            // parachains later.
            log::log!(
                target: &log_target,
                if relay_sync_near_head_of_chain {
                    log::Level::Error
                } else {
                    log::Level::Debug
                },
                "Failed to fetch the parachain head from relay chain: {}",
                error
            );*/
            Err(ParaheadError::InvalidRuntimeOutput(error))
        }
    }
}

#[derive(derive_more::Display)]
enum ParaheadError {
    Call(runtime_service::RuntimeCallError),
    StartError(host::StartErr),
    ReadOnlyRuntime(read_only_runtime_host::ErrorDetail),
    NoCore,
    InvalidRuntimeOutput(para::Error),
}

impl ParaheadError {
    /// Returns `true` if this is caused by networking issues, as opposed to a consensus-related
    /// issue.
    fn is_network_problem(&self) -> bool {
        match self {
            ParaheadError::Call(err) => err.is_network_problem(),
            ParaheadError::StartError(_) => false,
            ParaheadError::ReadOnlyRuntime(_) => false,
            ParaheadError::NoCore => false,
            ParaheadError::InvalidRuntimeOutput(_) => false,
        }
    }
}

enum ToBackground {
    /// See [`SyncService::is_near_head_of_chain_heuristic`].
    IsNearHeadOfChainHeuristic { send_back: oneshot::Sender<bool> },
    /// See [`SyncService::subscribe_finalized`].
    SubscribeFinalized {
        send_back: oneshot::Sender<(Vec<u8>, lossy_channel::Receiver<Vec<u8>>)>,
    },
    /// See [`SyncService::subscribe_best`].
    SubscribeBest {
        send_back: oneshot::Sender<(Vec<u8>, lossy_channel::Receiver<Vec<u8>>)>,
    },
    /// See [`SyncService::subscribe_all`].
    SubscribeAll {
        send_back: oneshot::Sender<SubscribeAll>,
        buffer_size: usize,
    },
    /// See [`SyncService::peers_assumed_know_blocks`].
    PeersAssumedKnowBlock {
        send_back: oneshot::Sender<Vec<PeerId>>,
        block_number: u64,
        block_hash: [u8; 32],
    },
    /// See [`SyncService::syncing_peers`].
    SyncingPeers {
        send_back: oneshot::Sender<Vec<(PeerId, protocol::Role, u64, [u8; 32])>>,
    },
}
