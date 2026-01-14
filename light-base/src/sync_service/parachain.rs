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

use super::{ToBackground, paraheads};
use crate::{log, network_service, platform::PlatformRef, runtime_service, util};

use alloc::{boxed::Box, format, string::String, sync::Arc, vec::Vec};
use core::{iter, pin::Pin};
use futures_channel::oneshot;
use futures_lite::FutureExt as _;
use futures_util::{StreamExt as _, future};
use hashbrown::HashMap;
use smoldot::{header, informant::HashDisplay, libp2p::PeerId, network::codec};

/// Starts a sync service background task to synchronize a parachain.
pub(super) async fn start_parachain<TPlat: PlatformRef>(
    log_target: String,
    platform: TPlat,
    finalized_block_header: Vec<u8>,
    block_number_bytes: usize,
    relay_chain_sync: Arc<runtime_service::RuntimeService<TPlat>>,
    parachain_id: u32,
    from_foreground: Pin<Box<async_channel::Receiver<ToBackground>>>,
    network_service: Arc<network_service::NetworkServiceChain<TPlat>>,
) {
    let (to_paraheads, from_paraheads) = async_channel::bounded(16);
    let from_paraheads = Box::pin(from_paraheads);

    let paraheads_log_target = format!("{log_target}-paraheads");
    platform.spawn_task(paraheads_log_target.clone().into(), {
        let platform = platform.clone();
        let task = paraheads::start_paraheads(
            paraheads_log_target.clone(),
            platform.clone(),
            finalized_block_header,
            relay_chain_sync,
            parachain_id,
            from_paraheads,
        );

        async move {
            task.await;
            log!(&platform, Debug, &paraheads_log_target, "paraheads-hutdown");
        }
    });

    ParachainBackgroundTask {
        log_target,
        from_foreground,
        block_number_bytes,
        paraheads: to_paraheads.clone(),
        from_network_service: None,
        network_service,
        sync_sources: HashMap::with_capacity_and_hasher(
            0,
            util::SipHasherBuild::new({
                let mut seed = [0; 16];
                platform.fill_random_bytes(&mut seed);
                seed
            }),
        ),
        subscription_state: ParachainBackgroundState::NotSubscribed {
            subscribe_future: {
                Box::pin(async move {
                    let (send_back, sub_rx) = oneshot::channel();
                    let _ = to_paraheads
                        .send(super::ToBackground::SubscribeAll {
                            send_back,
                            buffer_size: 32,
                            runtime_interest: false,
                        })
                        .await;
                    // TODO: don't panic if the paraheads service dies here
                    sub_rx.await.unwrap()
                })
            },
        },
        platform,
    }
    .run()
    .await;
}

/// Task that is running in the background.
struct ParachainBackgroundTask<TPlat: PlatformRef> {
    /// Target to use for all logs.
    log_target: String,

    /// Access to the platform's capabilities.
    platform: TPlat,

    /// Channel receiving message from the sync service frontend.
    from_foreground: Pin<Box<async_channel::Receiver<ToBackground>>>,

    /// Number of bytes to use to encode the parachain block numbers in headers.
    block_number_bytes: usize,

    /// Channel to the paraheads background service.
    paraheads: async_channel::Sender<super::ToBackground>,

    /// Networking service connected to the peer-to-peer network of the parachain.
    network_service: Arc<network_service::NetworkServiceChain<TPlat>>,

    /// Events coming from the networking service. `None` if not subscribed yet.
    from_network_service: Option<Pin<Box<async_channel::Receiver<network_service::Event>>>>,

    /// List of parachain network sources.
    ///
    /// Values are their role, and self-reported best block when we connected to them. This best
    /// block is never updated.
    ///
    /// > **Note**: In the past, smoldot used to track exactly which peer knows which block
    /// >           based on block announces. This, however, caused issues due to the fact that
    /// >           there's a disconnect between the parachain best block on the relay chain
    /// >           and the parachain best block on the network. We currently simply assume that
    /// >           all parachain nodes know about all parachain blocks from the relay chain.
    sync_sources: HashMap<PeerId, (codec::Role, u64, [u8; 32]), util::SipHasherBuild>,

    /// Extra fields that are set after the subscription to the paraheads service events has
    /// succeeded.
    subscription_state: ParachainBackgroundState,
}

enum ParachainBackgroundState {
    /// Currently subscribing to the paraheads service.
    NotSubscribed {
        /// Future when the subscription has finished.
        subscribe_future: future::BoxFuture<'static, super::SubscribeAll>,
    },

    /// Subscribed to the paraheads service.
    Subscribed(ParachainBackgroundTaskAfterSubscription),
}

struct ParachainBackgroundTaskAfterSubscription {
    /// Stream of blocks of the relay chain this parachain is registered on.
    /// The buffer size should be large enough so that, if the CPU is busy, it doesn't become full
    /// before the execution of the sync service resumes.
    /// The maximum number of pinned block is ignored, as this maximum is a way to avoid malicious
    /// behaviors. This code is by definition not considered malicious.
    paraheads_subscribe_all: async_channel::Receiver<super::Notification>,

    /// List of block numbers indexed by the block hash for all non-finalized blocks. Filled
    /// when we receive a notification from the paraheads task.
    /// Blocks whose header isn't decodable are ignored.
    known_block_numbers: HashMap<[u8; 32], u64, fnv::FnvBuildHasher>,
}

impl<TPlat: PlatformRef> ParachainBackgroundTask<TPlat> {
    async fn run(mut self) {
        loop {
            // Yield at every loop in order to provide better tasks granularity.
            futures_lite::future::yield_now().await;

            // Wait until something interesting happens.
            enum WakeUpReason {
                ForegroundClosed,
                ForegroundMessage(ToBackground),
                NewSubscription(super::SubscribeAll),
                ParaheadNotification(super::Notification),
                SubscriptionDead,
                MustSubscribeNetworkEvents,
                NetworkEvent(network_service::Event),
            }

            let wake_up_reason: WakeUpReason = {
                let (subscribe_future, paraheads_subscribe_all, is_paraheads_subscribed) =
                    match &mut self.subscription_state {
                        ParachainBackgroundState::NotSubscribed {
                            subscribe_future, ..
                        } => (Some(subscribe_future), None, false),
                        ParachainBackgroundState::Subscribed(paraheads_subscription) => (
                            None,
                            Some(&mut paraheads_subscription.paraheads_subscribe_all),
                            true,
                        ),
                    };

                async {
                    if let Some(subscribe_future) = subscribe_future {
                        WakeUpReason::NewSubscription(subscribe_future.await)
                    } else {
                        future::pending().await
                    }
                }
                .or(async {
                    match self.from_foreground.next().await {
                        Some(msg) => WakeUpReason::ForegroundMessage(msg),
                        None => WakeUpReason::ForegroundClosed,
                    }
                })
                .or(async {
                    if let Some(paraheads_subscribe_all) = paraheads_subscribe_all {
                        match paraheads_subscribe_all.recv().await {
                            Ok(notif) => WakeUpReason::ParaheadNotification(notif),
                            Err(_) => WakeUpReason::SubscriptionDead,
                        }
                    } else {
                        future::pending().await
                    }
                })
                .or(async {
                    if is_paraheads_subscribed {
                        if let Some(from_network_service) = self.from_network_service.as_mut() {
                            match from_network_service.next().await {
                                Some(ev) => WakeUpReason::NetworkEvent(ev),
                                None => {
                                    self.from_network_service = None;
                                    WakeUpReason::MustSubscribeNetworkEvents
                                }
                            }
                        } else {
                            WakeUpReason::MustSubscribeNetworkEvents
                        }
                    } else {
                        future::pending().await
                    }
                })
                .await
            };

            match (wake_up_reason, &mut self.subscription_state) {
                (WakeUpReason::ForegroundClosed, _) => {
                    // Terminate the background task.
                    return;
                }

                (WakeUpReason::NewSubscription(paraheads_subscribe_all), _) => {
                    // Subscription to the paraheads has finished.
                    log!(
                        &self.platform,
                        Debug,
                        &self.log_target,
                        "paraheads-new-subscription",
                        finalized_hash = HashDisplay(&header::hash_from_scale_encoded_header(
                            &paraheads_subscribe_all.finalized_block_scale_encoded_header
                        )),
                    );

                    // The networking service needs to be kept up to date with what the
                    // local node considers as the best block.
                    if let Ok(header) = header::decode(
                        &paraheads_subscribe_all.finalized_block_scale_encoded_header,
                        self.block_number_bytes,
                    ) {
                        let parahash = header::hash_from_scale_encoded_header(
                            &paraheads_subscribe_all.finalized_block_scale_encoded_header,
                        );
                        self.network_service
                            .set_local_best_block(parahash, header.number)
                            .await;
                    }

                    let known_block_numbers = paraheads_subscribe_all
                        .non_finalized_blocks_ancestry_order
                        .iter()
                        .filter_map(|block| {
                            Some((
                                header::hash_from_scale_encoded_header(&block.scale_encoded_header),
                                header::decode(
                                    &block.scale_encoded_header,
                                    self.block_number_bytes,
                                )
                                .ok()?
                                .number,
                            ))
                        })
                        .collect();

                    self.subscription_state = ParachainBackgroundState::Subscribed(
                        ParachainBackgroundTaskAfterSubscription {
                            known_block_numbers,
                            paraheads_subscribe_all: paraheads_subscribe_all.new_blocks,
                        },
                    );
                }

                (WakeUpReason::SubscriptionDead, _) => {
                    // Recreate the channel.
                    log!(
                        &self.platform,
                        Debug,
                        &self.log_target,
                        "paraheads-subscription-reset"
                    );
                    self.subscription_state = ParachainBackgroundState::NotSubscribed {
                        subscribe_future: {
                            let to_paraheads = self.paraheads.clone();
                            Box::pin(async move {
                                let (send_back, sub_rx) = oneshot::channel();
                                let _ = to_paraheads
                                    .send(super::ToBackground::SubscribeAll {
                                        send_back,
                                        buffer_size: 32,
                                        runtime_interest: false,
                                    })
                                    .await;
                                // TODO: don't panic if the paraheads service dies here
                                sub_rx.await.unwrap()
                            })
                        },
                    };
                }

                (
                    WakeUpReason::ParaheadNotification(super::Notification::Block(
                        super::BlockNotification {
                            scale_encoded_header,
                            ..
                        },
                    )),
                    ParachainBackgroundState::Subscribed(paraheads_subscription),
                ) => {
                    if let Ok(header) =
                        header::decode(&scale_encoded_header, self.block_number_bytes)
                    {
                        paraheads_subscription.known_block_numbers.insert(
                            header::hash_from_scale_encoded_header(&scale_encoded_header),
                            header.number,
                        );
                    }
                }

                (
                    WakeUpReason::ParaheadNotification(super::Notification::Finalized {
                        hash,
                        pruned_blocks,
                        ..
                    }),
                    ParachainBackgroundState::Subscribed(paraheads_subscription),
                ) => {
                    // The networking service needs to be kept up to date with what the
                    // local node considers as the best block.
                    if let Some(block_number) =
                        paraheads_subscription.known_block_numbers.get(&hash)
                    {
                        self.network_service
                            .set_local_best_block(hash, *block_number)
                            .await;
                    }

                    for pruned in iter::chain([hash], pruned_blocks) {
                        paraheads_subscription.known_block_numbers.remove(&pruned);
                    }
                }

                (
                    WakeUpReason::ParaheadNotification(super::Notification::BestBlockChanged {
                        ..
                    }),
                    ParachainBackgroundState::Subscribed(_),
                ) => {
                    // Ignored.
                }

                (
                    WakeUpReason::ForegroundMessage(ToBackground::IsNearHeadOfChainHeuristic {
                        send_back,
                    }),
                    _,
                ) => {
                    let _ = self
                        .paraheads
                        .send(ToBackground::IsNearHeadOfChainHeuristic { send_back })
                        .await;
                }

                (
                    WakeUpReason::ForegroundMessage(ToBackground::SubscribeAll {
                        send_back,
                        buffer_size,
                        runtime_interest,
                    }),
                    _,
                ) => {
                    let _ = self
                        .paraheads
                        .send(ToBackground::SubscribeAll {
                            send_back,
                            buffer_size,
                            runtime_interest,
                        })
                        .await;
                }

                (
                    WakeUpReason::ForegroundMessage(ToBackground::PeersAssumedKnowBlock {
                        send_back,
                        ..
                    }),
                    _,
                ) => {
                    // Simply assume that all peers know about all blocks.
                    //
                    // We could in principle check whether the block is higher than the current
                    // finalized block, and if not if it is in the list of paraheads found in the
                    // relay chain. But because parachain blocks might not be decodable, we can't
                    // know their number, and thus we can't know if the requested block is a
                    // descendant of the finalized block.
                    // Assuming that all peers know all blocks is the only sane way of
                    // implementing this.
                    let _ = send_back.send(self.sync_sources.keys().cloned().collect());
                }

                (WakeUpReason::ForegroundMessage(ToBackground::SyncingPeers { send_back }), _) => {
                    let _ = send_back.send(
                        self.sync_sources
                            .iter()
                            .map(|(peer_id, (role, best_height, best_hash))| {
                                //let (height, hash) = self.sync_sources.best_block(local_id);
                                (peer_id.clone(), *role, *best_height, *best_hash)
                            })
                            .collect(),
                    );
                }

                (
                    WakeUpReason::ForegroundMessage(ToBackground::SerializeChainInformation {
                        send_back,
                    }),
                    _,
                ) => {
                    let _ = self
                        .paraheads
                        .send(ToBackground::SerializeChainInformation { send_back })
                        .await;
                }

                (WakeUpReason::MustSubscribeNetworkEvents, _) => {
                    debug_assert!(self.from_network_service.is_none());
                    self.sync_sources.clear();
                    self.from_network_service = Some(Box::pin(
                        // As documented, `subscribe().await` is expected to return quickly.
                        self.network_service.subscribe().await,
                    ));
                }

                (
                    WakeUpReason::NetworkEvent(network_service::Event::Connected {
                        peer_id,
                        role,
                        best_block_number,
                        best_block_hash,
                    }),
                    _,
                ) => {
                    let _former_value = self
                        .sync_sources
                        .insert(peer_id, (role, best_block_number, best_block_hash));
                    debug_assert!(_former_value.is_none());
                }

                (
                    WakeUpReason::NetworkEvent(network_service::Event::Disconnected { peer_id }),
                    _,
                ) => {
                    let _role = self.sync_sources.remove(&peer_id);
                    debug_assert!(_role.is_some());
                }

                (
                    WakeUpReason::NetworkEvent(network_service::Event::BlockAnnounce {
                        peer_id: _peer_id,
                        ..
                    }),
                    _,
                ) => {
                    debug_assert!(self.sync_sources.contains_key(&_peer_id));
                }

                (WakeUpReason::NetworkEvent(_), _) => {
                    // Uninteresting message.
                }

                (
                    WakeUpReason::ParaheadNotification(_),
                    ParachainBackgroundState::NotSubscribed { .. },
                ) => {
                    // These paths are unreachable.
                    debug_assert!(false);
                }
            }
        }
    }
}
