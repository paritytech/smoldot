// Smoldot
// Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.
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

// TODO: document

use futures_channel::oneshot;
use futures_lite::FutureExt as _;
use smol::stream::StreamExt as _;
use smoldot::{
    executor,
    json_rpc::{methods, service},
};
use std::{
    num::NonZero,
    pin::{self, Pin},
    sync::Arc,
};

use crate::{consensus_service, database_thread};

pub struct Config {
    /// Function that can be used to spawn background tasks.
    ///
    /// The tasks passed as parameter must be executed until they shut down.
    pub tasks_executor: Arc<dyn Fn(Pin<Box<dyn Future<Output = ()> + Send>>) + Send + Sync>,

    /// Receiver for actions that the JSON-RPC client wants to perform.
    pub receiver: async_channel::Receiver<Message>,

    /// `chainHead_v1_follow` subscription start handle.
    pub chain_head_follow_subscription: service::SubscriptionStartProcess,

    /// Parameter that was passed by the user when requesting `chainHead_v1_follow`.
    pub with_runtime: bool,

    /// Consensus service of the chain.
    pub consensus_service: Arc<consensus_service::ConsensusService>,

    /// Database to access blocks.
    pub database: Arc<database_thread::DatabaseThread>,
}

pub enum Message {
    Header {
        request: service::RequestProcess,
    },
    Unpin {
        block_hashes: Vec<[u8; 32]>,
        outcome: oneshot::Sender<Result<(), ()>>,
    },
}

/// Spawns a new tasks dedicated to handling a `chainHead_v1_follow` subscription.
///
/// Returns the identifier of the subscription.
pub async fn spawn_chain_head_subscription_task(config: Config) -> String {
    let mut json_rpc_subscription = config.chain_head_follow_subscription.accept();
    let json_rpc_subscription_id = json_rpc_subscription.subscription_id().to_owned();
    let return_value = json_rpc_subscription_id.clone();

    let tasks_executor = config.tasks_executor.clone();
    tasks_executor(Box::pin(async move {
        let consensus_service_subscription = config
            .consensus_service
            .subscribe_all(32, NonZero::<usize>::new(32).unwrap())
            .await;
        let mut consensus_service_subscription_new_blocks =
            pin::pin!(consensus_service_subscription.new_blocks);

        let mut foreground_receiver = pin::pin!(config.receiver);

        let mut pinned_blocks =
            hashbrown::HashSet::with_capacity_and_hasher(32, fnv::FnvBuildHasher::default());
        let mut current_best_block = consensus_service_subscription.finalized_block_hash;

        pinned_blocks.insert(consensus_service_subscription.finalized_block_hash);
        json_rpc_subscription
            .send_notification(methods::ServerToClient::chainHead_v1_followEvent {
                subscription: (&json_rpc_subscription_id).into(),
                result: methods::FollowEvent::Initialized {
                    finalized_block_hashes: vec![methods::HashHexString(
                        consensus_service_subscription.finalized_block_hash,
                    )],
                    finalized_block_runtime: if config.with_runtime {
                        Some(convert_runtime_spec(
                            consensus_service_subscription
                                .finalized_block_runtime
                                .runtime_version(),
                        ))
                    } else {
                        None
                    },
                },
            })
            .await;

        for block in consensus_service_subscription.non_finalized_blocks_ancestry_order {
            pinned_blocks.insert(block.block_hash);
            json_rpc_subscription
                .send_notification(methods::ServerToClient::chainHead_v1_followEvent {
                    subscription: (&json_rpc_subscription_id).into(),
                    result: methods::FollowEvent::NewBlock {
                        block_hash: methods::HashHexString(block.block_hash),
                        new_runtime: if let (Some(new_runtime), true) =
                            (&block.runtime_update, config.with_runtime)
                        {
                            Some(convert_runtime_spec(new_runtime.runtime_version()))
                        } else {
                            None
                        },
                        parent_block_hash: methods::HashHexString(block.parent_hash),
                    },
                })
                .await;

            if block.is_new_best {
                current_best_block = block.block_hash;
                json_rpc_subscription
                    .send_notification(methods::ServerToClient::chainHead_v1_followEvent {
                        subscription: (&json_rpc_subscription_id).into(),
                        result: methods::FollowEvent::BestBlockChanged {
                            best_block_hash: methods::HashHexString(block.block_hash),
                        },
                    })
                    .await;
            }
        }

        loop {
            enum WakeUpReason {
                ConsensusNotification(consensus_service::Notification),
                ConsensusSubscriptionStop,
                Foreground(Message),
                ForegroundClosed,
            }

            let wake_up_reason = async {
                consensus_service_subscription_new_blocks
                    .next()
                    .await
                    .map_or(
                        WakeUpReason::ConsensusSubscriptionStop,
                        WakeUpReason::ConsensusNotification,
                    )
            }
            .or(async {
                foreground_receiver
                    .next()
                    .await
                    .map_or(WakeUpReason::ForegroundClosed, WakeUpReason::Foreground)
            })
            .await;

            match wake_up_reason {
                WakeUpReason::ForegroundClosed => return,
                WakeUpReason::Foreground(Message::Header { request }) => {
                    let methods::MethodCall::chainHead_v1_header { hash, .. } = request.request()
                    else {
                        unreachable!()
                    };

                    if !pinned_blocks.contains(&hash.0) {
                        request.fail(service::ErrorResponse::InvalidParams(None));
                        continue;
                    }

                    let database_outcome = config
                        .database
                        .with_database(move |database| database.block_scale_encoded_header(&hash.0))
                        .await;

                    match database_outcome {
                        Ok(Some(header)) => {
                            request.respond(methods::Response::chainHead_v1_header(Some(
                                methods::HexString(header),
                            )))
                        }
                        Ok(None) => {
                            // Should never happen given that blocks are pinned.
                            // TODO: log the problem
                            request.fail(service::ErrorResponse::InternalError);
                        }
                        Err(_) => {
                            // TODO: log the problem
                            request.fail(service::ErrorResponse::InternalError);
                        }
                    }
                }
                WakeUpReason::Foreground(Message::Unpin {
                    block_hashes,
                    outcome,
                }) => {
                    if block_hashes.iter().any(|h| !pinned_blocks.contains(h)) {
                        let _ = outcome.send(Err(()));
                    } else {
                        for block_hash in block_hashes {
                            pinned_blocks.remove(&block_hash);
                            config
                                .consensus_service
                                .unpin_block(consensus_service_subscription.id, block_hash)
                                .await;
                        }
                        let _ = outcome.send(Ok(()));
                    }
                }
                WakeUpReason::ConsensusNotification(consensus_service::Notification::Block {
                    block,
                    ..
                }) => {
                    pinned_blocks.insert(block.block_hash);
                    json_rpc_subscription
                        .send_notification(methods::ServerToClient::chainHead_v1_followEvent {
                            subscription: (&json_rpc_subscription_id).into(),
                            result: methods::FollowEvent::NewBlock {
                                block_hash: methods::HashHexString(block.block_hash),
                                new_runtime: if let (Some(new_runtime), true) =
                                    (&block.runtime_update, config.with_runtime)
                                {
                                    Some(convert_runtime_spec(new_runtime.runtime_version()))
                                } else {
                                    None
                                },
                                parent_block_hash: methods::HashHexString(block.parent_hash),
                            },
                        })
                        .await;

                    if block.is_new_best {
                        current_best_block = block.block_hash;
                        json_rpc_subscription
                            .send_notification(methods::ServerToClient::chainHead_v1_followEvent {
                                subscription: (&json_rpc_subscription_id).into(),
                                result: methods::FollowEvent::BestBlockChanged {
                                    best_block_hash: methods::HashHexString(block.block_hash),
                                },
                            })
                            .await;
                    }
                }
                WakeUpReason::ConsensusNotification(
                    consensus_service::Notification::Finalized {
                        finalized_blocks_newest_to_oldest,
                        pruned_blocks_hashes,
                        best_block_hash,
                    },
                ) => {
                    json_rpc_subscription
                        .send_notification(methods::ServerToClient::chainHead_v1_followEvent {
                            subscription: (&json_rpc_subscription_id).into(),
                            result: methods::FollowEvent::Finalized {
                                // As specified in the JSON-RPC spec, the list must be ordered
                                // in increasing block number. Consequently we have to reverse
                                // the list.
                                finalized_blocks_hashes: finalized_blocks_newest_to_oldest
                                    .into_iter()
                                    .map(methods::HashHexString)
                                    .rev()
                                    .collect(),
                                pruned_blocks_hashes: pruned_blocks_hashes
                                    .into_iter()
                                    .map(methods::HashHexString)
                                    .collect(),
                            },
                        })
                        .await;

                    if best_block_hash != current_best_block {
                        current_best_block = best_block_hash;
                        json_rpc_subscription
                            .send_notification(methods::ServerToClient::chainHead_v1_followEvent {
                                subscription: (&json_rpc_subscription_id).into(),
                                result: methods::FollowEvent::BestBlockChanged {
                                    best_block_hash: methods::HashHexString(best_block_hash),
                                },
                            })
                            .await;
                    }
                }
                WakeUpReason::ConsensusSubscriptionStop => {
                    json_rpc_subscription
                        .send_notification(methods::ServerToClient::chainHead_v1_followEvent {
                            subscription: (&json_rpc_subscription_id).into(),
                            result: methods::FollowEvent::Stop {},
                        })
                        .await;
                }
            }
        }
    }));

    return_value
}

fn convert_runtime_spec(runtime: &'_ executor::CoreVersion) -> methods::MaybeRuntimeSpec<'_> {
    let runtime = runtime.decode();
    methods::MaybeRuntimeSpec::Valid {
        spec: methods::RuntimeSpec {
            impl_name: runtime.impl_name.into(),
            spec_name: runtime.spec_name.into(),
            impl_version: runtime.impl_version,
            spec_version: runtime.spec_version,
            transaction_version: runtime.transaction_version,
            apis: runtime
                .apis
                .map(|api| (methods::HexString(api.name_hash.to_vec()), api.version))
                .collect(),
        },
    }
}
