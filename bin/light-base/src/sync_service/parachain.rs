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
use crate::{network_service, runtime_service, Platform};

use futures::{channel::mpsc, prelude::*};
use itertools::Itertools as _;
use smoldot::{
    chain::{self, async_tree},
    executor::{host, read_only_runtime_host},
    header,
    informant::HashDisplay,
    libp2p::PeerId,
    network::protocol,
    sync::{all_forks::sources, para},
};
use std::{
    collections::HashMap,
    iter,
    num::{NonZeroU32, NonZeroUsize},
    sync::Arc,
    time::Duration,
};

/// Starts a sync service background task to synchronize a parachain.
pub(super) async fn start_parachain<TPlat: Platform>(
    log_target: String,
    chain_information: chain::chain_information::ValidChainInformation,
    block_number_bytes: usize,
    relay_chain_sync: Arc<runtime_service::RuntimeService<TPlat>>,
    relay_chain_block_number_bytes: usize,
    parachain_id: u32,
    mut from_foreground: mpsc::Receiver<ToBackground>,
    network_chain_index: usize,
    from_network_service: stream::BoxStream<'static, network_service::Event>,
) {
    // Necessary for the `select!` loop below.
    let mut from_network_service = from_network_service.fuse();

    // Last good known parachain header of a relay chain finalized block.
    // Updated after we successfully fetch the parahead of a relay chain finalized block, and left
    // untouched if the fetch fails.
    // Initialized to the parachain genesis block header.
    let mut finalized_parahead = chain_information
        .as_ref()
        .finalized_block_header
        .scale_encoding_vec(block_number_bytes);

    // Hash of the best parachain that has been reported to the output.
    let mut best_parahead_hash = header::hash_from_scale_encoded_header(&finalized_parahead);

    // State machine that tracks the list of parachain network sources and their known blocks.
    let mut sync_sources = sources::AllForksSources::<(PeerId, protocol::Role)>::new(
        40,
        header::decode(&finalized_parahead, block_number_bytes)
            .unwrap()
            .number,
    );
    // Maps `PeerId`s to their indices within `sync_sources`.
    let mut sync_sources_map = HashMap::new();

    // This function contains two loops within each other. If the relay chain syncing service has
    // a gap in its blocks, or if the node is overloaded and can't process blocks in time, then
    // we break out of the inner loop in order to reset everything.
    loop {
        // Stream of blocks of the relay chain this parachain is registered on.
        // The buffer size should be large enough so that, if the CPU is busy, it doesn't
        // become full before the execution of the sync service resumes.
        // The maximum number of pinned block is ignored, as this maximum is a way to avoid
        // malicious behaviors. This code is by definition not considered malicious.
        let mut relay_chain_subscribe_all = relay_chain_sync
            .subscribe_all(32, NonZeroUsize::new(usize::max_value()).unwrap())
            .await;
        log::debug!(
            target: &log_target,
            "RelayChain => NewSubscription(finalized_hash={})",
            HashDisplay(&header::hash_from_scale_encoded_header(
                &relay_chain_subscribe_all.finalized_block_scale_encoded_header
            ))
        );

        // Tree of relay chain blocks. Blocks are inserted when received from the relay chain
        // sync service. Once inside, their corresponding parahead is fetched. Once the parahead
        // is fetched, this parahead is reported to our subscriptions.
        //
        // The root of the tree is a "virtual" block. It can be thought as the parent of the relay
        // chain finalized block, but is there even if the relay chain finalized block is block 0.
        //
        // All block in the tree has an associated parahead behind an `Option`. This `Option`
        // always contains `Some`, except for the "virtual" root block for which it is `None`.
        //
        // If the output finalized block has a parahead equal to `None`, it therefore means that
        // no finalized parahead is known yet.
        //
        // The set of blocks in this tree whose parahead hasn't been fetched yet is the same as
        // the set of blocks that is maintained pinned on the runtime service. Blocks are unpinned
        // when their parahead fetching succeeds or when they are removed from the tree.
        let mut async_tree = {
            let mut async_tree =
                async_tree::AsyncTree::<TPlat::Instant, [u8; 32], _>::new(async_tree::Config {
                    finalized_async_user_data: None,
                    retry_after_failed: Duration::from_secs(5),
                    blocks_capacity: 32,
                });
            let finalized_hash = header::hash_from_scale_encoded_header(
                &relay_chain_subscribe_all.finalized_block_scale_encoded_header,
            );
            let finalized_index = async_tree.input_insert_block(finalized_hash, None, false, true);
            async_tree.input_finalize(finalized_index, finalized_index);
            for block in relay_chain_subscribe_all.non_finalized_blocks_ancestry_order {
                let hash = header::hash_from_scale_encoded_header(&block.scale_encoded_header);
                let parent = async_tree
                    .input_iter_unordered()
                    .find(|b| *b.user_data == block.parent_hash)
                    .map(|b| b.id)
                    .unwrap_or(finalized_index);
                async_tree.input_insert_block(hash, Some(parent), false, block.is_new_best);
            }
            async_tree
        };

        // List of senders that get notified when the tree of blocks is modified.
        // Note that this list is created in the inner loop, as to be cleared if the relay chain
        // blocks stream has a gap.
        let mut all_subscriptions = Vec::<mpsc::Sender<_>>::new();
        log::debug!(target: &log_target, "Subscriptions <= Reset");

        // List of in-progress parahead fetching operations.
        //
        // The operations require some blocks to be pinned within the relay chain runtime service,
        // which is guaranteed by the fact that `relay_chain_subscribe_all.new_blocks` stays
        // alive for longer than this container, and by the fact that we unpin block after a
        // fetching operation has finished and that we never fetch twice for the same block.
        let mut in_progress_paraheads = stream::FuturesUnordered::new();
        log::debug!(target: &log_target, "ParaheadFetchOperations <= Clear");

        // Future that is ready when we need to wake up the `select!` below.
        let mut wakeup_deadline = future::Either::Right(future::pending());

        loop {
            // Start fetching paraheads of new blocks whose parahead needs to be fetched.
            while in_progress_paraheads.len() < 4 {
                match async_tree.next_necessary_async_op(&TPlat::now()) {
                    async_tree::NextNecessaryAsyncOp::NotReady { when: Some(when) } => {
                        wakeup_deadline = future::Either::Left(TPlat::sleep_until(when).fuse());
                        break;
                    }
                    async_tree::NextNecessaryAsyncOp::NotReady { when: None } => {
                        wakeup_deadline = future::Either::Right(future::pending());
                        break;
                    }
                    async_tree::NextNecessaryAsyncOp::Ready(op) => {
                        log::debug!(
                            target: &log_target,
                            "ParaheadFetchOperations <= StartFetch(relay_block_hash={})",
                            HashDisplay(op.block_user_data),
                        );

                        in_progress_paraheads.push({
                            let relay_chain_sync = relay_chain_sync.clone();
                            let subscription_id = relay_chain_subscribe_all.new_blocks.id();
                            let block_hash = *op.block_user_data;
                            let async_op_id = op.id;
                            async move {
                                (
                                    async_op_id,
                                    parahead(
                                        &relay_chain_sync,
                                        relay_chain_block_number_bytes,
                                        subscription_id,
                                        parachain_id,
                                        &block_hash,
                                    )
                                    .await,
                                )
                            }
                            .boxed()
                        });
                    }
                }
            }

            // Report to the outside any block in the `async_tree` that is now ready.
            while let Some(update) = async_tree.try_advance_output() {
                match update {
                    async_tree::OutputUpdate::Finalized {
                        async_op_user_data: new_parahead,
                        former_finalized_async_op_user_data: former_parahead,
                        pruned_blocks,
                        ..
                    } if *new_parahead != former_parahead => {
                        debug_assert!(new_parahead.is_some());
                        let hash =
                            header::hash_from_scale_encoded_header(new_parahead.as_ref().unwrap());

                        finalized_parahead = new_parahead.clone().unwrap();

                        if let Ok(header) = header::decode(&finalized_parahead, block_number_bytes)
                        {
                            sync_sources.set_finalized_block_height(header.number);
                            // TODO: what about an `else`? does sync_sources leak if the block can't be decoded?
                        }

                        // Must unpin the pruned blocks if they haven't already been unpinned.
                        for (_, hash, pruned_block_parahead) in pruned_blocks {
                            if pruned_block_parahead.is_none() {
                                relay_chain_subscribe_all
                                    .new_blocks
                                    .unpin_block(&hash)
                                    .await;
                            }
                        }

                        log::debug!(
                            target: &log_target,
                            "Subscriptions <= ParablockFinalized(hash={})",
                            HashDisplay(&hash)
                        );

                        let best_block_hash = async_tree
                            .best_block_index()
                            .map(|(_, parahead)| {
                                header::hash_from_scale_encoded_header(parahead.as_ref().unwrap())
                            })
                            .unwrap_or(hash);
                        best_parahead_hash = best_block_hash;

                        // Elements in `all_subscriptions` are removed one by one and
                        // inserted back if the channel is still open.
                        for index in (0..all_subscriptions.len()).rev() {
                            let mut sender = all_subscriptions.swap_remove(index);
                            let notif = super::Notification::Finalized {
                                hash,
                                best_block_hash,
                            };
                            if sender.try_send(notif).is_ok() {
                                all_subscriptions.push(sender);
                            }
                        }
                    }
                    async_tree::OutputUpdate::Finalized { .. }
                    | async_tree::OutputUpdate::BestBlockChanged { .. } => {
                        // Calculate hash of the parablock corresponding to the new best relay
                        // chain block.
                        let parahash = header::hash_from_scale_encoded_header(
                            async_tree
                                .best_block_index()
                                .map(|(_, b)| b.as_ref().unwrap())
                                .unwrap_or(&finalized_parahead),
                        );

                        if parahash != best_parahead_hash {
                            best_parahead_hash = parahash;

                            log::debug!(
                                target: &log_target,
                                "Subscriptions <= BestBlockChanged(hash={})",
                                HashDisplay(&parahash)
                            );

                            // Elements in `all_subscriptions` are removed one by one and
                            // inserted back if the channel is still open.
                            for index in (0..all_subscriptions.len()).rev() {
                                let mut sender = all_subscriptions.swap_remove(index);
                                let notif =
                                    super::Notification::BestBlockChanged { hash: parahash };
                                if sender.try_send(notif).is_ok() {
                                    all_subscriptions.push(sender);
                                }
                            }
                        }
                    }
                    async_tree::OutputUpdate::Block(block) => {
                        // `block` borrows `async_tree`. We need to mutably access `async_tree`
                        // below, so deconstruct `block` beforehand.
                        let is_new_best = block.is_new_best;
                        let scale_encoded_header: Vec<u8> =
                            block.async_op_user_data.clone().unwrap();
                        let parahash =
                            header::hash_from_scale_encoded_header(&scale_encoded_header);
                        let block_index = block.index;

                        // Do not report the new block if it has already been reported in the
                        // past. This covers situations where the parahead is identical to the
                        // relay chain's parent's parahead, but also situations where multiple
                        // sibling relay chain blocks have the same parahead.
                        if finalized_parahead == scale_encoded_header
                            || async_tree
                                .input_iter_unordered()
                                .filter(|item| item.id != block_index)
                                .filter_map(|item| item.async_op_user_data)
                                .any(|item| item.as_ref() == Some(&scale_encoded_header))
                        {
                            // While the parablock has already been reported, it is possible that
                            // it becomes the new best block while it wasn't before, in which
                            // case we should send a notification.
                            if is_new_best && parahash != best_parahead_hash {
                                best_parahead_hash = parahash;

                                log::debug!(
                                    target: &log_target,
                                    "Subscriptions <= BestBlockChanged(hash={})",
                                    HashDisplay(&parahash)
                                );

                                // Elements in `all_subscriptions` are removed one by one and
                                // inserted back if the channel is still open.
                                for index in (0..all_subscriptions.len()).rev() {
                                    let mut sender = all_subscriptions.swap_remove(index);
                                    let notif =
                                        super::Notification::BestBlockChanged { hash: parahash };
                                    if sender.try_send(notif).is_ok() {
                                        all_subscriptions.push(sender);
                                    }
                                }
                            }

                            continue;
                        }

                        log::debug!(
                            target: &log_target,
                            "Subscriptions <= NewParablock(hash={})",
                            HashDisplay(&parahash)
                        );

                        if is_new_best {
                            best_parahead_hash = parahash;
                        }

                        let parent_hash = header::hash_from_scale_encoded_header(
                            &async_tree
                                .parent(block_index)
                                .map(|idx| {
                                    async_tree
                                        .block_async_user_data(idx)
                                        .unwrap()
                                        .as_ref()
                                        .unwrap()
                                })
                                .or_else(|| async_tree.finalized_async_user_data().as_ref())
                                .unwrap_or(&finalized_parahead),
                        );

                        // Elements in `all_subscriptions` are removed one by one and
                        // inserted back if the channel is still open.
                        for index in (0..all_subscriptions.len()).rev() {
                            let mut sender = all_subscriptions.swap_remove(index);
                            let notif = super::Notification::Block(super::BlockNotification {
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

            futures::select! {
                () = wakeup_deadline => {
                    // Do nothing. This is simply to wake up and loop again.
                },

                relay_chain_notif = relay_chain_subscribe_all.new_blocks.next().fuse() => { // TODO: remove fuse()?
                    let relay_chain_notif = match relay_chain_notif {
                        Some(n) => n,
                        None => break, // Jumps to the outer loop to recreate the channel.
                    };

                    // Update the local tree of blocks to match the update sent by the relay chain
                    // syncing service.
                    match relay_chain_notif {
                        runtime_service::Notification::Finalized { hash, best_block_hash, .. } => {
                            log::debug!(
                                target: &log_target,
                                "RelayChain => Finalized(hash={})",
                                HashDisplay(&hash)
                            );

                            let finalized = async_tree.input_iter_unordered().find(|b| *b.user_data == hash).unwrap().id;
                            let best = async_tree.input_iter_unordered().find(|b| *b.user_data == best_block_hash).unwrap().id;
                            async_tree.input_finalize(finalized, best);
                        }
                        runtime_service::Notification::Block(block) => {
                            let hash = header::hash_from_scale_encoded_header(&block.scale_encoded_header);

                            log::debug!(
                                target: &log_target,
                                "RelayChain => Block(hash={}, parent_hash={})",
                                HashDisplay(&hash),
                                HashDisplay(&block.parent_hash)
                            );

                            let parent = async_tree.input_iter_unordered().find(|b| *b.user_data == block.parent_hash).map(|b| b.id); // TODO: check if finalized
                            async_tree.input_insert_block(hash, parent, false, block.is_new_best);
                        }
                        runtime_service::Notification::BestBlockChanged { hash } => {
                            log::debug!(
                                target: &log_target,
                                "RelayChain => BestBlockChanged(hash={})",
                                HashDisplay(&hash)
                            );

                            let node_idx = async_tree.input_iter_unordered().find(|b| *b.user_data == hash).unwrap().id;
                            async_tree.input_set_best_block(node_idx);
                        }
                    };
                },

                (async_op_id, parahead_result) = in_progress_paraheads.select_next_some() => {
                    // A parahead fetching operation is finished.

                    // Log and update the `async_tree` accordingly.
                    match parahead_result {
                        Ok(parahead) => {
                            log::debug!(
                                target: &log_target,
                                "ParaheadFetchOperations => Parahead(hash={}, relay_blocks={})",
                                HashDisplay(blake2_rfc::blake2b::blake2b(32, b"", &parahead).as_bytes()),
                                async_tree.async_op_blocks(async_op_id).map(|b| HashDisplay(b)).join(",")
                            );

                            // Unpin the relay blocks whose parahead is now known.
                            for block in async_tree.async_op_finished(async_op_id, Some(parahead)) {
                                let hash = async_tree.block_user_data(block);
                                relay_chain_subscribe_all.new_blocks.unpin_block(hash).await;
                            }
                        },
                        Err(error) => {
                            // Several chains initially didn't support parachains, and have later
                            // been upgraded to support them. Similarly, the parachain might not
                            // have had a core on the relay chain until recently. For these
                            // reasons, errors when the relay chain is not near head of the chain
                            // are most likely normal and do not warrant logging an error.
                            if relay_chain_sync.is_near_head_of_chain_heuristic().await
                                && !error.is_network_problem()
                            {
                                log::error!(
                                    target: &log_target,
                                    "Failed to fetch the parachain head from relay chain blocks {}: {}",
                                    async_tree.async_op_blocks(async_op_id).map(|b| HashDisplay(b)).join(", "),
                                    error
                                );
                            }

                            log::debug!(
                                target: &log_target,
                                "ParaheadFetchOperations => Error(relay_blocks={}, error={:?})",
                                async_tree.async_op_blocks(async_op_id).map(|b| HashDisplay(b)).join(","),
                                error
                            );

                            async_tree.async_op_failure(async_op_id, &TPlat::now());
                        }
                    }
                }

                foreground_message = from_foreground.next().fuse() => {
                    // Message from the public API of the syncing service.

                    // Terminating the parachain sync task if the foreground has closed.
                    let foreground_message = match foreground_message {
                        Some(m) => m,
                        None => return,
                    };

                    match foreground_message {
                        ToBackground::IsNearHeadOfChainHeuristic { send_back } => {
                            // Since there is a mapping between relay chain blocks and parachain
                            // blocks, whether a parachain is at the head of the chain is the
                            // same thing as whether its relay chain is at the head of the chain.
                            // Note that there is no ordering guarantee of any kind w.r.t.
                            // block subscriptions notifications.
                            let val = relay_chain_sync.is_near_head_of_chain_heuristic().await;
                            let _ = send_back.send(val);
                        },
                        ToBackground::SubscribeAll { send_back, buffer_size, .. } => {
                            let (tx, new_blocks) = mpsc::channel(buffer_size.saturating_sub(1));
                            let _ = send_back.send(super::SubscribeAll {
                                finalized_block_scale_encoded_header: finalized_parahead.clone(),
                                finalized_block_runtime: None,
                                non_finalized_blocks_ancestry_order: async_tree.input_iter_unordered().filter_map(|block| {
                                    // `async_op_user_data` is `Some` only if this block has
                                    // already been reported on the output. In order to maintain
                                    // consistency, only these blocks should be reported.
                                    let parahead = block.async_op_user_data?.as_ref().unwrap();
                                    let parent_hash = async_tree.parent(block.id)
                                        .map(|idx| header::hash_from_scale_encoded_header(&async_tree.block_async_user_data(idx).unwrap().as_ref().unwrap()))
                                        .or_else(|| async_tree.finalized_async_user_data().as_ref().map(header::hash_from_scale_encoded_header))
                                        .unwrap_or(header::hash_from_scale_encoded_header(&finalized_parahead));

                                    Some(super::BlockNotification {
                                        is_new_best: block.is_output_best,
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
                                    .map(|local_id| sync_sources[local_id].0.clone())
                                    .collect()
                            } else {
                                sync_sources
                                    .keys()
                                    .filter(|local_id| {
                                        sync_sources.best_block(*local_id).0 >= block_number
                                    })
                                    .map(|local_id| sync_sources[local_id].0.clone())
                                    .collect()
                            };

                            let _ = send_back.send(list);
                        }
                        ToBackground::SyncingPeers { send_back } => {
                            let _ = send_back.send(sync_sources.keys().map(|local_id| {
                                let (height, hash) = sync_sources.best_block(local_id);
                                let (peer_id, role) = sync_sources[local_id].clone();
                                (peer_id, role, height, *hash)
                            }).collect());
                        }
                        ToBackground::SerializeChainInformation { send_back } => {
                            let _ = send_back.send(None);
                        }
                    }
                },

                network_event = from_network_service.next() => {
                    // Something happened on the network.
                    // We expect the networking channel to never close, so the event is unwrapped.
                    match network_event.unwrap() {
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
                            if let Ok(decoded_header) = header::decode(&decoded.scale_encoded_header, block_number_bytes) {
                                let decoded_header_hash = header::hash_from_scale_encoded_header(
                                    &decoded.scale_encoded_header
                                );
                                sync_sources.add_known_block(
                                    local_id,
                                    decoded_header.number,
                                    decoded_header_hash
                                );
                                if decoded.is_best {
                                    sync_sources.add_known_block_and_set_best(
                                        local_id,
                                        decoded_header.number,
                                        decoded_header_hash
                                    );
                                }
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

async fn parahead<TPlat: Platform>(
    relay_chain_sync: &Arc<runtime_service::RuntimeService<TPlat>>,
    relay_chain_block_number_bytes: usize,
    subscription_id: runtime_service::SubscriptionId,
    parachain_id: u32,
    block_hash: &[u8; 32],
) -> Result<Vec<u8>, ParaheadError> {
    // For each relay chain block, call `ParachainHost_persisted_validation_data` in
    // order to know where the parachains are.
    let precall = relay_chain_sync
        .pinned_block_runtime_lock(subscription_id, block_hash)
        .await;
    let (runtime_call_lock, virtual_machine) = precall
        .start(
            para::PERSISTED_VALIDATION_FUNCTION_NAME,
            para::persisted_validation_data_parameters(
                parachain_id,
                para::OccupiedCoreAssumption::TimedOut,
            ),
            6,
            Duration::from_secs(10),
            NonZeroU32::new(2).unwrap(),
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
            read_only_runtime_host::RuntimeHostVm::NextKey(nk) => {
                // TODO:
                runtime_call_lock
                    .unlock(read_only_runtime_host::RuntimeHostVm::NextKey(nk).into_prototype());
                return Err(ParaheadError::NextKeyForbidden);
            }
            read_only_runtime_host::RuntimeHostVm::StorageRoot(storage_root) => {
                runtime_call = storage_root.resume(runtime_call_lock.block_storage_root());
            }
        }
    };

    // Try decode the result of the runtime call.
    // If this fails, it indicates an incompatibility between smoldot and the relay
    // chain.
    match para::decode_persisted_validation_data_return_value(
        &output,
        relay_chain_block_number_bytes,
    ) {
        Ok(Some(pvd)) => Ok(pvd.parent_head.to_vec()),
        Ok(None) => Err(ParaheadError::NoCore),
        Err(error) => Err(ParaheadError::InvalidRuntimeOutput(error)),
    }
}

/// Error that can happen when fetching the parachain head corresponding to a relay chain block.
#[derive(Debug, derive_more::Display)]
enum ParaheadError {
    /// Error while performing call request over the network.
    #[display(fmt = "Error while performing call request over the network: {}", _0)]
    Call(runtime_service::RuntimeCallError),
    /// Error while starting virtual machine to verify call proof.
    #[display(
        fmt = "Error while starting virtual machine to verify call proof: {}",
        _0
    )]
    StartError(host::StartErr),
    /// Error during the execution of the virtual machine to verify call proof.
    #[display(fmt = "Error during the call proof verification: {}", _0)]
    ReadOnlyRuntime(read_only_runtime_host::ErrorDetail),
    /// Parachain doesn't have a core in the relay chain.
    NoCore,
    /// Error while decoding the output of the call.
    ///
    /// This indicates some kind of incompatibility between smoldot and the relay chain.
    #[display(fmt = "Error while decoding the output of the call: {}", _0)]
    InvalidRuntimeOutput(para::Error),
    /// Fetching following keys is not supported by call proofs.
    NextKeyForbidden,
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
            ParaheadError::NextKeyForbidden => false,
        }
    }
}
