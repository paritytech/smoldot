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

use super::ToBackground;
use crate::{log, platform::PlatformRef, runtime_service};

use alloc::{borrow::ToOwned as _, boxed::Box, format, string::String, sync::Arc, vec::Vec};
use core::{mem, num::NonZero, pin::Pin, time::Duration};
use futures_lite::FutureExt as _;
use futures_util::{StreamExt as _, future, stream};
use itertools::Itertools as _;
use smoldot::{chain::async_tree, header, informant::HashDisplay, sync::para};

/// Starts a sync service background task to synchronize a parachain.
pub(super) async fn start_paraheads<TPlat: PlatformRef>(
    log_target: String,
    platform: TPlat,
    finalized_block_header: Vec<u8>,
    relay_chain_sync: Arc<runtime_service::RuntimeService<TPlat>>,
    parachain_id: u32,
    from_foreground: Pin<Box<async_channel::Receiver<ToBackground>>>,
) {
    ParachainBackgroundTask {
        log_target,
        from_foreground,
        parachain_id,
        obsolete_finalized_parahead: finalized_block_header,
        subscription_state: ParachainBackgroundState::NotSubscribed {
            all_subscriptions: Vec::new(),
            subscribe_future: {
                let relay_chain_sync = relay_chain_sync.clone();
                Box::pin(async move {
                    relay_chain_sync
                        .subscribe_all(32, NonZero::<usize>::new(usize::MAX).unwrap())
                        .await
                })
            },
        },
        relay_chain_sync,
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

    /// Id of the parachain registered within the relay chain. Chosen by the user.
    parachain_id: u32,

    /// Runtime service of the relay chain.
    relay_chain_sync: Arc<runtime_service::RuntimeService<TPlat>>,

    /// Last-known finalized parachain header. Can be very old and obsolete.
    /// Updated after we successfully fetch the parachain head of a relay chain finalized block,
    /// and left untouched if the fetch fails.
    /// Initialized to the parachain genesis block header.
    obsolete_finalized_parahead: Vec<u8>,

    /// Extra fields that are set after the subscription to the runtime service events has
    /// succeeded.
    subscription_state: ParachainBackgroundState<TPlat>,
}

enum ParachainBackgroundState<TPlat: PlatformRef> {
    /// Currently subscribing to the relay chain runtime service.
    NotSubscribed {
        /// List of senders that will get notified when the tree of blocks is modified.
        ///
        /// These subscriptions are pending and no notification should be sent to them until the
        /// subscription to the relay chain runtime service is finished.
        all_subscriptions: Vec<async_channel::Sender<super::Notification>>,

        /// Future when the subscription has finished.
        subscribe_future: future::BoxFuture<'static, runtime_service::SubscribeAll<TPlat>>,
    },

    /// Subscribed to the relay chain runtime service.
    Subscribed(ParachainBackgroundTaskAfterSubscription<TPlat>),
}

struct ParachainBackgroundTaskAfterSubscription<TPlat: PlatformRef> {
    /// List of senders that get notified when the tree of blocks is modified.
    all_subscriptions: Vec<async_channel::Sender<super::Notification>>,

    /// Stream of blocks of the relay chain this parachain is registered on.
    /// The buffer size should be large enough so that, if the CPU is busy, it doesn't become full
    /// before the execution of the sync service resumes.
    /// The maximum number of pinned block is ignored, as this maximum is a way to avoid malicious
    /// behaviors. This code is by definition not considered malicious.
    relay_chain_subscribe_all: runtime_service::Subscription<TPlat>,

    /// Hash of the best parachain that has been reported to the subscriptions.
    /// `None` if and only if no finalized parachain head is known yet.
    reported_best_parahead_hash: Option<[u8; 32]>,

    /// Tree of relay chain blocks. Blocks are inserted when received from the relay chain
    /// sync service. Once inside, their corresponding parachain head is fetched. Once the
    /// parachain head is fetched, this parachain head is reported to our subscriptions.
    ///
    /// The root of the tree is a "virtual" block. It can be thought as the parent of the relay
    /// chain finalized block, but is there even if the relay chain finalized block is block 0.
    ///
    /// All block in the tree has an associated parachain head behind an `Option`. This `Option`
    /// always contains `Some`, except for the "virtual" root block for which it is `None`.
    ///
    /// If the output finalized block has a parachain head equal to `None`, it therefore means
    /// that no finalized parachain head is known yet.
    /// Note that, when it is the case, `SubscribeAll` messages from the frontend are still
    /// answered with a single finalized block set to `obsolete_finalized_parahead`. Once a
    /// finalized parachain head is known, it is important to reset all subscriptions.
    ///
    /// The set of blocks in this tree whose parachain block hasn't been fetched yet is the same
    /// as the set of blocks that is maintained pinned on the runtime service. Blocks are unpinned
    /// when their parachain head fetching succeeds or when they are removed from the tree.
    async_tree: async_tree::AsyncTree<TPlat::Instant, [u8; 32], Option<Vec<u8>>>,

    /// If `true`, [`ParachainBackgroundTaskAfterSubscription::async_tree`] might need to
    /// be advanced.
    must_process_sync_tree: bool,

    /// List of in-progress parachain head fetching operations.
    ///
    /// The operations require some blocks to be pinned within the relay chain runtime service,
    /// which is guaranteed by the fact that `relay_chain_subscribe_all.new_blocks` stays
    /// alive for longer than this container, and by the fact that we unpin block after a
    /// fetching operation has finished and that we never fetch twice for the same block.
    in_progress_paraheads: stream::FuturesUnordered<
        future::BoxFuture<'static, (async_tree::AsyncOpId, Result<Vec<u8>, ParaheadError>)>,
    >,

    /// Future that is ready when we need to start a new parachain head fetch operation.
    next_start_parahead_fetch: Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl<TPlat: PlatformRef> ParachainBackgroundTask<TPlat> {
    async fn run(mut self) {
        loop {
            // Yield at every loop in order to provide better tasks granularity.
            futures_lite::future::yield_now().await;

            // Wait until something interesting happens.
            enum WakeUpReason<TPlat: PlatformRef> {
                ForegroundClosed,
                ForegroundMessage(ToBackground),
                NewSubscription(runtime_service::SubscribeAll<TPlat>),
                StartParaheadFetch,
                ParaheadFetchFinished {
                    async_op_id: async_tree::AsyncOpId,
                    parahead_result: Result<Vec<u8>, ParaheadError>,
                },
                Notification(runtime_service::Notification),
                SubscriptionDead,
                AdvanceSyncTree,
            }

            let wake_up_reason: WakeUpReason<_> = {
                let (
                    subscribe_future,
                    next_start_parahead_fetch,
                    relay_chain_subscribe_all,
                    in_progress_paraheads,
                    must_process_sync_tree,
                ) = match &mut self.subscription_state {
                    ParachainBackgroundState::NotSubscribed {
                        subscribe_future, ..
                    } => (Some(subscribe_future), None, None, None, None),
                    ParachainBackgroundState::Subscribed(runtime_subscription) => (
                        None,
                        Some(&mut runtime_subscription.next_start_parahead_fetch),
                        Some(&mut runtime_subscription.relay_chain_subscribe_all),
                        Some(&mut runtime_subscription.in_progress_paraheads),
                        Some(&mut runtime_subscription.must_process_sync_tree),
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
                    if let Some(relay_chain_subscribe_all) = relay_chain_subscribe_all {
                        match relay_chain_subscribe_all.next().await {
                            Some(notif) => WakeUpReason::Notification(notif),
                            None => WakeUpReason::SubscriptionDead,
                        }
                    } else {
                        future::pending().await
                    }
                })
                .or(async {
                    if let Some(next_start_parahead_fetch) = next_start_parahead_fetch {
                        next_start_parahead_fetch.as_mut().await;
                        *next_start_parahead_fetch = Box::pin(future::pending());
                        WakeUpReason::StartParaheadFetch
                    } else {
                        future::pending().await
                    }
                })
                .or(async {
                    if let Some(in_progress_paraheads) = in_progress_paraheads {
                        if !in_progress_paraheads.is_empty() {
                            let (async_op_id, parahead_result) =
                                in_progress_paraheads.next().await.unwrap();
                            WakeUpReason::ParaheadFetchFinished {
                                async_op_id,
                                parahead_result,
                            }
                        } else {
                            future::pending().await
                        }
                    } else {
                        future::pending().await
                    }
                })
                .or(async {
                    if let Some(must_process_sync_tree) = must_process_sync_tree {
                        if *must_process_sync_tree {
                            *must_process_sync_tree = false;
                            WakeUpReason::AdvanceSyncTree
                        } else {
                            future::pending().await
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

                (WakeUpReason::NewSubscription(relay_chain_subscribe_all), _) => {
                    // Subscription to the relay chain has finished.
                    log!(
                        &self.platform,
                        Debug,
                        &self.log_target,
                        "relay-chain-new-subscription",
                        finalized_hash = HashDisplay(&header::hash_from_scale_encoded_header(
                            &relay_chain_subscribe_all.finalized_block_scale_encoded_header
                        )),
                        subscription_id = ?relay_chain_subscribe_all.new_blocks.id(),
                    );
                    log!(
                        &self.platform,
                        Debug,
                        &self.log_target,
                        "parahead-fetch-operations-cleared"
                    );

                    let async_tree = {
                        let mut async_tree =
                            async_tree::AsyncTree::<TPlat::Instant, [u8; 32], _>::new(
                                async_tree::Config {
                                    finalized_async_user_data: None,
                                    retry_after_failed: Duration::from_secs(5),
                                    blocks_capacity: 32,
                                },
                            );
                        let finalized_hash = header::hash_from_scale_encoded_header(
                            &relay_chain_subscribe_all.finalized_block_scale_encoded_header,
                        );
                        let finalized_index =
                            async_tree.input_insert_block(finalized_hash, None, false, true);
                        async_tree.input_finalize(finalized_index);
                        for block in relay_chain_subscribe_all.non_finalized_blocks_ancestry_order {
                            let hash =
                                header::hash_from_scale_encoded_header(&block.scale_encoded_header);
                            let parent = async_tree
                                .input_output_iter_unordered()
                                .find(|b| *b.user_data == block.parent_hash)
                                .map(|b| b.id)
                                .unwrap_or(finalized_index);
                            async_tree.input_insert_block(
                                hash,
                                Some(parent),
                                false,
                                block.is_new_best,
                            );
                        }
                        async_tree
                    };

                    self.subscription_state = ParachainBackgroundState::Subscribed(
                        ParachainBackgroundTaskAfterSubscription {
                            all_subscriptions: match &mut self.subscription_state {
                                ParachainBackgroundState::NotSubscribed {
                                    all_subscriptions,
                                    ..
                                } => mem::take(all_subscriptions),
                                _ => unreachable!(),
                            },
                            relay_chain_subscribe_all: relay_chain_subscribe_all.new_blocks,
                            reported_best_parahead_hash: None,
                            async_tree,
                            must_process_sync_tree: false,
                            in_progress_paraheads: stream::FuturesUnordered::new(),
                            next_start_parahead_fetch: Box::pin(future::ready(())),
                        },
                    );
                }

                (
                    WakeUpReason::AdvanceSyncTree,
                    ParachainBackgroundState::Subscribed(runtime_subscription),
                ) => {
                    if let Some(update) = runtime_subscription.async_tree.try_advance_output() {
                        // Make sure to process any notification that comes after.
                        runtime_subscription.must_process_sync_tree = true;

                        match update {
                            async_tree::OutputUpdate::Finalized {
                                former_finalized_async_op_user_data: former_finalized_parahead,
                                pruned_blocks,
                                best_output_block_updated,
                                ..
                            } if *runtime_subscription
                                .async_tree
                                .output_finalized_async_user_data()
                                != former_finalized_parahead =>
                            {
                                let new_finalized_parahead = runtime_subscription
                                    .async_tree
                                    .output_finalized_async_user_data();
                                debug_assert!(new_finalized_parahead.is_some());

                                // If this is the first time a finalized parahead is known, any
                                // `SubscribeAll` message that has been answered beforehand was
                                // answered in a dummy way with a potentially obsolete finalized
                                // header.
                                // For this reason, we reset all subscriptions to force all
                                // subscribers to re-subscribe.
                                if former_finalized_parahead.is_none() {
                                    runtime_subscription.all_subscriptions.clear();
                                }

                                let hash = header::hash_from_scale_encoded_header(
                                    new_finalized_parahead.as_ref().unwrap(),
                                );

                                // Must unpin the pruned blocks if they haven't already been unpinned.
                                let mut pruned_blocks_hashes =
                                    Vec::with_capacity(pruned_blocks.len());
                                for (_, hash, pruned_block_parahead) in pruned_blocks {
                                    if pruned_block_parahead.is_none() {
                                        runtime_subscription
                                            .relay_chain_subscribe_all
                                            .unpin_block(hash)
                                            .await;
                                    }
                                    pruned_blocks_hashes.push(hash);
                                }

                                log!(
                                    &self.platform,
                                    Debug,
                                    &self.log_target,
                                    "subscriptions-notify-parablock-finalized",
                                    hash = HashDisplay(&hash)
                                );

                                let best_block_hash = runtime_subscription
                                    .async_tree
                                    .output_best_block_index()
                                    .map(|(_, parahead)| {
                                        header::hash_from_scale_encoded_header(
                                            parahead.as_ref().unwrap(),
                                        )
                                    })
                                    .unwrap_or(hash);
                                runtime_subscription.reported_best_parahead_hash =
                                    Some(best_block_hash);

                                // Elements in `all_subscriptions` are removed one by one and
                                // inserted back if the channel is still open.
                                for index in (0..runtime_subscription.all_subscriptions.len()).rev()
                                {
                                    let sender =
                                        runtime_subscription.all_subscriptions.swap_remove(index);
                                    let notif = super::Notification::Finalized {
                                        hash,
                                        best_block_hash_if_changed: if best_output_block_updated {
                                            Some(best_block_hash)
                                        } else {
                                            None
                                        },
                                        pruned_blocks: pruned_blocks_hashes.clone(),
                                    };
                                    if sender.try_send(notif).is_ok() {
                                        runtime_subscription.all_subscriptions.push(sender);
                                    }
                                }
                            }

                            async_tree::OutputUpdate::Finalized { .. }
                            | async_tree::OutputUpdate::BestBlockChanged { .. } => {
                                // Do not report anything to subscriptions if no finalized parahead is
                                // known yet.
                                let finalized_parahead = match runtime_subscription
                                    .async_tree
                                    .output_finalized_async_user_data()
                                {
                                    Some(p) => p,
                                    None => continue,
                                };

                                // Calculate hash of the parablock corresponding to the new best relay
                                // chain block.
                                let parahash = header::hash_from_scale_encoded_header(
                                    runtime_subscription
                                        .async_tree
                                        .output_best_block_index()
                                        .map(|(_, b)| b.as_ref().unwrap())
                                        .unwrap_or(finalized_parahead),
                                );

                                if runtime_subscription.reported_best_parahead_hash.as_ref()
                                    != Some(&parahash)
                                {
                                    runtime_subscription.reported_best_parahead_hash =
                                        Some(parahash);

                                    log!(
                                        &self.platform,
                                        Debug,
                                        &self.log_target,
                                        "subscriptions-notify-best-block-changed",
                                        hash = HashDisplay(&parahash)
                                    );

                                    // Elements in `all_subscriptions` are removed one by one and
                                    // inserted back if the channel is still open.
                                    for index in
                                        (0..runtime_subscription.all_subscriptions.len()).rev()
                                    {
                                        let sender = runtime_subscription
                                            .all_subscriptions
                                            .swap_remove(index);
                                        let notif = super::Notification::BestBlockChanged {
                                            hash: parahash,
                                        };
                                        if sender.try_send(notif).is_ok() {
                                            runtime_subscription.all_subscriptions.push(sender);
                                        }
                                    }
                                }
                            }

                            async_tree::OutputUpdate::Block(block) => {
                                // `block` borrows `async_tree`. We need to mutably access `async_tree`
                                // below, so deconstruct `block` beforehand.
                                let is_new_best = block.is_new_best;
                                let block_index = block.index;
                                let scale_encoded_header: Vec<u8> = runtime_subscription
                                    .async_tree
                                    .block_async_user_data(block.index)
                                    .unwrap()
                                    .clone()
                                    .unwrap();
                                let parahash =
                                    header::hash_from_scale_encoded_header(&scale_encoded_header);

                                // Do not report anything to subscriptions if no finalized parahead is
                                // known yet.
                                let finalized_parahead = match runtime_subscription
                                    .async_tree
                                    .output_finalized_async_user_data()
                                {
                                    Some(p) => p,
                                    None => continue,
                                };

                                // Do not report the new block if it has already been reported in the
                                // past. This covers situations where the parahead is identical to the
                                // relay chain's parent's parahead, but also situations where multiple
                                // sibling relay chain blocks have the same parahead.
                                if *finalized_parahead == scale_encoded_header
                                    || runtime_subscription
                                        .async_tree
                                        .input_output_iter_unordered()
                                        .filter(|item| item.id != block_index)
                                        .filter_map(|item| item.async_op_user_data)
                                        .any(|item| item.as_ref() == Some(&scale_encoded_header))
                                {
                                    // While the parablock has already been reported, it is possible that
                                    // it becomes the new best block while it wasn't before, in which
                                    // case we should send a notification.
                                    if is_new_best
                                        && runtime_subscription.reported_best_parahead_hash.as_ref()
                                            != Some(&parahash)
                                    {
                                        runtime_subscription.reported_best_parahead_hash =
                                            Some(parahash);

                                        log!(
                                            &self.platform,
                                            Debug,
                                            &self.log_target,
                                            "subscriptions-notify-best-block-changed",
                                            hash = HashDisplay(&parahash)
                                        );

                                        // Elements in `all_subscriptions` are removed one by one and
                                        // inserted back if the channel is still open.
                                        for index in
                                            (0..runtime_subscription.all_subscriptions.len()).rev()
                                        {
                                            let sender = runtime_subscription
                                                .all_subscriptions
                                                .swap_remove(index);
                                            let notif = super::Notification::BestBlockChanged {
                                                hash: parahash,
                                            };
                                            if sender.try_send(notif).is_ok() {
                                                runtime_subscription.all_subscriptions.push(sender);
                                            }
                                        }
                                    }

                                    continue;
                                }

                                if is_new_best {
                                    runtime_subscription.reported_best_parahead_hash =
                                        Some(parahash);
                                }

                                let parent_hash = header::hash_from_scale_encoded_header(
                                    runtime_subscription
                                        .async_tree
                                        .parent(block_index)
                                        .map(|idx| {
                                            runtime_subscription
                                                .async_tree
                                                .block_async_user_data(idx)
                                                .unwrap()
                                                .as_ref()
                                                .unwrap()
                                        })
                                        .unwrap_or(finalized_parahead),
                                );

                                log!(
                                    &self.platform,
                                    Debug,
                                    &self.log_target,
                                    "subscriptions-notify-new-parablock",
                                    hash = HashDisplay(&parahash),
                                    parent_hash = HashDisplay(&parent_hash),
                                    ?is_new_best
                                );

                                // Elements in `all_subscriptions` are removed one by one and
                                // inserted back if the channel is still open.
                                for index in (0..runtime_subscription.all_subscriptions.len()).rev()
                                {
                                    let sender =
                                        runtime_subscription.all_subscriptions.swap_remove(index);
                                    let notif =
                                        super::Notification::Block(super::BlockNotification {
                                            is_new_best,
                                            parent_hash,
                                            scale_encoded_header: scale_encoded_header.clone(),
                                        });
                                    if sender.try_send(notif).is_ok() {
                                        runtime_subscription.all_subscriptions.push(sender);
                                    }
                                }
                            }
                        }
                    }
                }

                (
                    WakeUpReason::StartParaheadFetch,
                    ParachainBackgroundState::Subscribed(runtime_subscription),
                ) => {
                    // Must start downloading a parahead.

                    // Internal state check.
                    debug_assert_eq!(
                        runtime_subscription.reported_best_parahead_hash.is_some(),
                        runtime_subscription
                            .async_tree
                            .output_finalized_async_user_data()
                            .is_some()
                    );

                    // Limit the maximum number of simultaneous downloads.
                    if runtime_subscription.in_progress_paraheads.len() >= 4 {
                        continue;
                    }

                    match runtime_subscription
                        .async_tree
                        .next_necessary_async_op(&self.platform.now())
                    {
                        async_tree::NextNecessaryAsyncOp::NotReady { when: Some(when) } => {
                            runtime_subscription.next_start_parahead_fetch =
                                Box::pin(self.platform.sleep_until(when));
                        }
                        async_tree::NextNecessaryAsyncOp::NotReady { when: None } => {
                            runtime_subscription.next_start_parahead_fetch =
                                Box::pin(future::pending());
                        }
                        async_tree::NextNecessaryAsyncOp::Ready(op) => {
                            log!(
                                &self.platform,
                                Debug,
                                &self.log_target,
                                "parahead-fetch-operation-started",
                                relay_block_hash =
                                    HashDisplay(&runtime_subscription.async_tree[op.block_index]),
                            );

                            runtime_subscription.in_progress_paraheads.push({
                                let relay_chain_sync = self.relay_chain_sync.clone();
                                let subscription_id =
                                    runtime_subscription.relay_chain_subscribe_all.id();
                                let block_hash = runtime_subscription.async_tree[op.block_index];
                                let async_op_id = op.id;
                                let parachain_id = self.parachain_id;
                                Box::pin(async move {
                                    (
                                        async_op_id,
                                        fetch_parahead(
                                            &relay_chain_sync,
                                            subscription_id,
                                            parachain_id,
                                            &block_hash,
                                        )
                                        .await,
                                    )
                                })
                            });

                            // There might be more downloads to start.
                            runtime_subscription.next_start_parahead_fetch =
                                Box::pin(future::ready(()));
                        }
                    }
                }

                (
                    WakeUpReason::Notification(runtime_service::Notification::Finalized {
                        hash,
                        best_block_hash_if_changed,
                        ..
                    }),
                    ParachainBackgroundState::Subscribed(runtime_subscription),
                ) => {
                    // Relay chain has a new finalized block.
                    log!(
                        &self.platform,
                        Debug,
                        &self.log_target,
                        "relay-chain-block-finalized",
                        hash = HashDisplay(&hash)
                    );

                    if let Some(best_block_hash_if_changed) = best_block_hash_if_changed {
                        let best = runtime_subscription
                            .async_tree
                            .input_output_iter_unordered()
                            .find(|b| *b.user_data == best_block_hash_if_changed)
                            .unwrap()
                            .id;
                        runtime_subscription
                            .async_tree
                            .input_set_best_block(Some(best));
                    }

                    let finalized = runtime_subscription
                        .async_tree
                        .input_output_iter_unordered()
                        .find(|b| *b.user_data == hash)
                        .unwrap()
                        .id;
                    runtime_subscription.async_tree.input_finalize(finalized);
                    runtime_subscription.must_process_sync_tree = true;
                }

                (
                    WakeUpReason::Notification(runtime_service::Notification::Block(block)),
                    ParachainBackgroundState::Subscribed(runtime_subscription),
                ) => {
                    // Relay chain has a new block.
                    let hash = header::hash_from_scale_encoded_header(&block.scale_encoded_header);

                    log!(
                        &self.platform,
                        Debug,
                        &self.log_target,
                        "relay-chain-new-block",
                        hash = HashDisplay(&hash),
                        parent_hash = HashDisplay(&block.parent_hash)
                    );

                    let parent = runtime_subscription
                        .async_tree
                        .input_output_iter_unordered()
                        .find(|b| *b.user_data == block.parent_hash)
                        .map(|b| b.id); // TODO: check if finalized
                    runtime_subscription.async_tree.input_insert_block(
                        hash,
                        parent,
                        false,
                        block.is_new_best,
                    );
                    runtime_subscription.must_process_sync_tree = true;

                    runtime_subscription.next_start_parahead_fetch = Box::pin(future::ready(()));
                }

                (
                    WakeUpReason::Notification(runtime_service::Notification::BestBlockChanged {
                        hash,
                    }),
                    ParachainBackgroundState::Subscribed(runtime_subscription),
                ) => {
                    // Relay chain has a new best block.
                    log!(
                        &self.platform,
                        Debug,
                        &self.log_target,
                        "relay-chain-best-block-changed",
                        hash = HashDisplay(&hash)
                    );

                    // If the block isn't found in `async_tree`, assume that it is equal to the
                    // finalized block (that has left the tree already).
                    let node_idx = runtime_subscription
                        .async_tree
                        .input_output_iter_unordered()
                        .find(|b| *b.user_data == hash)
                        .map(|b| b.id);
                    runtime_subscription
                        .async_tree
                        .input_set_best_block(node_idx);

                    runtime_subscription.must_process_sync_tree = true;
                }

                (WakeUpReason::SubscriptionDead, _) => {
                    // Recreate the channel.
                    log!(
                        &self.platform,
                        Debug,
                        &self.log_target,
                        "relay-chain-subscription-reset"
                    );
                    self.subscription_state = ParachainBackgroundState::NotSubscribed {
                        all_subscriptions: Vec::new(),
                        subscribe_future: {
                            let relay_chain_sync = self.relay_chain_sync.clone();
                            Box::pin(async move {
                                relay_chain_sync
                                    .subscribe_all(32, NonZero::<usize>::new(usize::MAX).unwrap())
                                    .await
                            })
                        },
                    };
                }

                (
                    WakeUpReason::ParaheadFetchFinished {
                        async_op_id,
                        parahead_result: Ok(parahead),
                    },
                    ParachainBackgroundState::Subscribed(runtime_subscription),
                ) => {
                    // A parahead fetching operation is successful.
                    log!(
                        &self.platform,
                        Debug,
                        &self.log_target,
                        "parahead-fetch-operation-success",
                        parahead_hash = HashDisplay(
                            blake2_rfc::blake2b::blake2b(32, b"", &parahead).as_bytes()
                        ),
                        relay_blocks = runtime_subscription
                            .async_tree
                            .async_op_blocks(async_op_id)
                            .map(|b| HashDisplay(b))
                            .join(",")
                    );

                    // Unpin the relay blocks whose parahead is now known.
                    for block in runtime_subscription
                        .async_tree
                        .async_op_finished(async_op_id, Some(parahead))
                    {
                        let hash = &runtime_subscription.async_tree[block];
                        runtime_subscription
                            .relay_chain_subscribe_all
                            .unpin_block(*hash)
                            .await;
                    }

                    runtime_subscription.must_process_sync_tree = true;

                    runtime_subscription.next_start_parahead_fetch = Box::pin(future::ready(()));
                }

                (
                    WakeUpReason::ParaheadFetchFinished {
                        parahead_result:
                            Err(ParaheadError::PinRuntimeError(
                                runtime_service::PinPinnedBlockRuntimeError::ObsoleteSubscription,
                            )),
                        ..
                    },
                    _,
                ) => {
                    // The relay chain runtime service has some kind of gap or issue and has
                    // discarded the runtime.
                    // Destroy the subscription and recreate the channels.
                    log!(
                        &self.platform,
                        Debug,
                        &self.log_target,
                        "relay-chain-subscription-reset"
                    );
                    self.subscription_state = ParachainBackgroundState::NotSubscribed {
                        all_subscriptions: Vec::new(),
                        subscribe_future: {
                            let relay_chain_sync = self.relay_chain_sync.clone();
                            Box::pin(async move {
                                relay_chain_sync
                                    .subscribe_all(32, NonZero::<usize>::new(usize::MAX).unwrap())
                                    .await
                            })
                        },
                    };
                }

                (
                    WakeUpReason::ParaheadFetchFinished {
                        async_op_id,
                        parahead_result: Err(error),
                    },
                    ParachainBackgroundState::Subscribed(runtime_subscription),
                ) => {
                    // Failed fetching a parahead.

                    // Several relay chains initially didn't support parachains, and have later
                    // been upgraded to support them. Similarly, the parachain might not have had a
                    // core on the relay chain until recently. For these reasons, errors when the
                    // relay chain is not near head of the chain are most likely normal and do
                    // not warrant logging an error.
                    // Note that `is_near_head_of_chain_heuristic` is normally not acceptable to
                    // use due to being too vague, but since this is just about whether to print a
                    // log message, it's completely fine.
                    if self
                        .relay_chain_sync
                        .is_near_head_of_chain_heuristic()
                        .await
                        && !error.is_network_problem()
                    {
                        log!(
                            &self.platform,
                            Error,
                            &self.log_target,
                            format!(
                                "Failed to fetch the parachain head from relay chain blocks {}: {}",
                                runtime_subscription
                                    .async_tree
                                    .async_op_blocks(async_op_id)
                                    .map(|b| HashDisplay(b))
                                    .join(", "),
                                error
                            )
                        );
                    }

                    log!(
                        &self.platform,
                        Debug,
                        &self.log_target,
                        "parahead-fetch-operation-error",
                        relay_blocks = runtime_subscription
                            .async_tree
                            .async_op_blocks(async_op_id)
                            .map(|b| HashDisplay(b))
                            .join(","),
                        ?error
                    );

                    runtime_subscription
                        .async_tree
                        .async_op_failure(async_op_id, &self.platform.now());

                    runtime_subscription.next_start_parahead_fetch = Box::pin(future::ready(()));
                }

                (
                    WakeUpReason::ForegroundMessage(ToBackground::IsNearHeadOfChainHeuristic {
                        send_back,
                    }),
                    ParachainBackgroundState::Subscribed(sub),
                ) if sub.async_tree.output_finalized_async_user_data().is_some() => {
                    // Since there is a mapping between relay chain blocks and parachain blocks,
                    // whether a parachain is at the head of the chain is the same thing as whether
                    // its relay chain is at the head of the chain.
                    // Note that there is no ordering guarantee of any kind w.r.t. block
                    // subscriptions notifications.
                    let val = self
                        .relay_chain_sync
                        .is_near_head_of_chain_heuristic()
                        .await;
                    let _ = send_back.send(val);
                }

                (
                    WakeUpReason::ForegroundMessage(ToBackground::IsNearHeadOfChainHeuristic {
                        send_back,
                    }),
                    _,
                ) => {
                    // If no finalized parahead is known yet, we might be very close to the head
                    // but also maybe very very far away. We lean on the cautious side and always
                    // return `false`.
                    let _ = send_back.send(false);
                }

                (
                    WakeUpReason::ForegroundMessage(ToBackground::SubscribeAll {
                        send_back,
                        buffer_size,
                        ..
                    }),
                    ParachainBackgroundState::NotSubscribed {
                        all_subscriptions, ..
                    },
                ) => {
                    let (tx, new_blocks) = async_channel::bounded(buffer_size.saturating_sub(1));

                    // No known finalized parahead.
                    let _ = send_back.send(super::SubscribeAll {
                        finalized_block_scale_encoded_header: self
                            .obsolete_finalized_parahead
                            .clone(),
                        finalized_block_runtime: None,
                        non_finalized_blocks_ancestry_order: Vec::new(),
                        new_blocks,
                    });

                    all_subscriptions.push(tx);
                }

                (
                    WakeUpReason::ForegroundMessage(ToBackground::SubscribeAll {
                        send_back,
                        buffer_size,
                        ..
                    }),
                    ParachainBackgroundState::Subscribed(runtime_subscription),
                ) => {
                    let (tx, new_blocks) = async_channel::bounded(buffer_size.saturating_sub(1));

                    // There are two possibilities here: either we know of any recent finalized
                    // parahead, or we don't. In case where we don't know of any finalized parahead
                    // yet, we report a single obsolete finalized parahead, which is
                    // `obsolete_finalized_parahead`. The rest of this module makes sure that no
                    // other block is reported to subscriptions as long as this is the case, and
                    // that subscriptions are reset once the first known finalized parahead
                    // is known.
                    if let Some(finalized_parahead) = runtime_subscription
                        .async_tree
                        .output_finalized_async_user_data()
                    {
                        // Finalized parahead is known.
                        let finalized_parahash =
                            header::hash_from_scale_encoded_header(finalized_parahead);
                        let _ = send_back.send(super::SubscribeAll {
                            finalized_block_scale_encoded_header: finalized_parahead.clone(),
                            finalized_block_runtime: None,
                            non_finalized_blocks_ancestry_order: {
                                let mut list =
                                    Vec::<([u8; 32], super::BlockNotification)>::with_capacity(
                                        runtime_subscription
                                            .async_tree
                                            .num_input_non_finalized_blocks(),
                                    );

                                for relay_block in runtime_subscription
                                    .async_tree
                                    .input_output_iter_ancestry_order()
                                {
                                    let parablock = match relay_block.async_op_user_data {
                                        Some(b) => b.as_ref().unwrap(),
                                        None => continue,
                                    };

                                    let parablock_hash =
                                        header::hash_from_scale_encoded_header(parablock);

                                    // TODO: O(n)
                                    if let Some((_, entry)) =
                                        list.iter_mut().find(|(h, _)| *h == parablock_hash)
                                    {
                                        // Block is already in the list. Don't add it a second time.
                                        if relay_block.is_output_best {
                                            entry.is_new_best = true;
                                        }
                                        continue;
                                    }

                                    // Find the parent of the parablock. This is done by going through
                                    // the ancestors of the corresponding relay chain block (until and
                                    // including the finalized relay chain block) until we find one
                                    // whose parablock is different from the parablock in question.
                                    // If none is found, the parablock is the same as the finalized
                                    // parablock.
                                    let parent_hash = runtime_subscription
                                        .async_tree
                                        .ancestors(relay_block.id)
                                        .find_map(|idx| {
                                            let hash = header::hash_from_scale_encoded_header(
                                                runtime_subscription
                                                    .async_tree
                                                    .block_async_user_data(idx)
                                                    .unwrap()
                                                    .as_ref()
                                                    .unwrap(),
                                            );
                                            if hash != parablock_hash {
                                                Some(hash)
                                            } else {
                                                None
                                            }
                                        })
                                        .or_else(|| {
                                            if finalized_parahash != parablock_hash {
                                                Some(finalized_parahash)
                                            } else {
                                                None
                                            }
                                        });

                                    // `parent_hash` is `None` if the parablock is
                                    // the same as the finalized parablock, in which case we
                                    // don't add it to the list.
                                    if let Some(parent_hash) = parent_hash {
                                        debug_assert!(
                                            list.iter().filter(|(h, _)| *h == parent_hash).count()
                                                == 1
                                                || parent_hash == finalized_parahash
                                        );
                                        list.push((
                                            parablock_hash,
                                            super::BlockNotification {
                                                is_new_best: relay_block.is_output_best,
                                                scale_encoded_header: parablock.clone(),
                                                parent_hash,
                                            },
                                        ));
                                    }
                                }

                                list.into_iter().map(|(_, v)| v).collect()
                            },
                            new_blocks,
                        });
                    } else {
                        // No known finalized parahead.
                        let _ = send_back.send(super::SubscribeAll {
                            finalized_block_scale_encoded_header: self
                                .obsolete_finalized_parahead
                                .clone(),
                            finalized_block_runtime: None,
                            non_finalized_blocks_ancestry_order: Vec::new(),
                            new_blocks,
                        });
                    }

                    runtime_subscription.all_subscriptions.push(tx);
                }

                (
                    WakeUpReason::ForegroundMessage(ToBackground::PeersAssumedKnowBlock {
                        send_back,
                        ..
                    }),
                    _,
                ) => {
                    let _ = send_back.send(Vec::new());
                }

                (WakeUpReason::ForegroundMessage(ToBackground::SyncingPeers { send_back }), _) => {
                    let _ = send_back.send(Vec::new());
                }

                (
                    WakeUpReason::ForegroundMessage(ToBackground::SerializeChainInformation {
                        send_back,
                    }),
                    _,
                ) => {
                    let _ = send_back.send(None);
                }

                (
                    WakeUpReason::ParaheadFetchFinished { .. }
                    | WakeUpReason::AdvanceSyncTree
                    | WakeUpReason::Notification(_)
                    | WakeUpReason::StartParaheadFetch,
                    ParachainBackgroundState::NotSubscribed { .. },
                ) => {
                    // These paths are unreachable.
                    debug_assert!(false);
                }
            }
        }
    }
}

async fn fetch_parahead<TPlat: PlatformRef>(
    relay_chain_sync: &Arc<runtime_service::RuntimeService<TPlat>>,
    subscription_id: runtime_service::SubscriptionId,
    parachain_id: u32,
    block_hash: &[u8; 32],
) -> Result<Vec<u8>, ParaheadError> {
    // Call `ParachainHost_persisted_validation_data` in order to know where the parachain is.
    let (pinned_runtime, block_state_trie_root, block_number) = relay_chain_sync
        .pin_pinned_block_runtime(subscription_id, *block_hash)
        .await
        .map_err(ParaheadError::PinRuntimeError)?;
    let success = relay_chain_sync
        .runtime_call(
            pinned_runtime,
            *block_hash,
            block_number,
            block_state_trie_root,
            para::PERSISTED_VALIDATION_FUNCTION_NAME.to_owned(),
            None, // TODO: /!\
            para::persisted_validation_data_parameters(
                parachain_id,
                para::OccupiedCoreAssumption::TimedOut,
            )
            .fold(Vec::new(), |mut a, b| {
                a.extend_from_slice(b.as_ref());
                a
            }),
            6,
            Duration::from_secs(10),
            NonZero::<u32>::new(2).unwrap(),
        )
        .await
        .map_err(ParaheadError::RuntimeCall)?;

    // Try decode the result of the runtime call.
    // If this fails, it indicates an incompatibility between smoldot and the relay chain.
    match para::decode_persisted_validation_data_return_value(
        &success.output,
        relay_chain_sync.block_number_bytes(),
    ) {
        Ok(Some(pvd)) => Ok(pvd.parent_head.to_vec()),
        Ok(None) => Err(ParaheadError::NoCore),
        Err(error) => Err(ParaheadError::InvalidRuntimeOutput(error)),
    }
}

/// Error that can happen when fetching the parachain head corresponding to a relay chain block.
#[derive(Debug, derive_more::Display, derive_more::Error)]
enum ParaheadError {
    /// Error while performing call request over the network.
    #[display("Error while performing call request over the network: {_0}")]
    RuntimeCall(runtime_service::RuntimeCallError),
    /// Error pinning the runtime of the block.
    PinRuntimeError(runtime_service::PinPinnedBlockRuntimeError),
    /// Parachain doesn't have a core in the relay chain.
    NoCore,
    /// Error while decoding the output of the call.
    ///
    /// This indicates some kind of incompatibility between smoldot and the relay chain.
    #[display("Error while decoding the output of the call: {_0}")]
    InvalidRuntimeOutput(para::Error),
}

impl ParaheadError {
    /// Returns `true` if this is caused by networking issues, as opposed to a consensus-related
    /// issue.
    fn is_network_problem(&self) -> bool {
        match self {
            ParaheadError::RuntimeCall(runtime_service::RuntimeCallError::Inaccessible(_)) => true,
            ParaheadError::RuntimeCall(
                runtime_service::RuntimeCallError::Execution(_)
                | runtime_service::RuntimeCallError::Crash
                | runtime_service::RuntimeCallError::InvalidRuntime(_)
                | runtime_service::RuntimeCallError::ApiVersionRequirementUnfulfilled,
            ) => false,
            ParaheadError::PinRuntimeError(_) => false,
            ParaheadError::NoCore => false,
            ParaheadError::InvalidRuntimeOutput(_) => false,
        }
    }
}
