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

use super::{BlockNotification, Notification, SubscribeAll, ToBackground};
use crate::{ffi, network_service, runtime_service};

use futures::{channel::mpsc, prelude::*};
use smoldot::{
    chain::{self, async_tree},
    executor::{host, read_only_runtime_host},
    header,
    informant::HashDisplay,
    libp2p::PeerId,
    network::protocol,
    sync::{all_forks::sources, para},
};
use std::{collections::HashMap, iter, sync::Arc};

pub(super) async fn start_parachain(
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
    // Whether `finalized_parahead` corresponds to the parahead of the finalized relay chain
    // block. `false` if it is older.
    let mut finalized_parahead_up_to_date;

    // State machine that tracks the list of parachain network sources and their known blocks.
    let mut sync_sources = sources::AllForksSources::<(PeerId, protocol::Role)>::new(
        40,
        header::decode(&finalized_parahead).unwrap().number,
    );
    // Maps `PeerId`s to their indices within `sync_sources`.
    let mut sync_sources_map = HashMap::new();

    // `true` after a parachain block has been fetched from the parachain.
    // TODO: handled in a hacky way; unclear how to handle properly
    let mut is_near_head_of_chain;

    loop {
        // Stream of blocks of the relay chain this parachain is registered on.
        let mut relay_chain_subscribe_all = relay_chain_sync.subscribe_all(32).await;
        log::debug!(
            target: &log_target,
            "Resetting parachain syncing to relay chain block 0x{}",
            HashDisplay(&header::hash_from_scale_encoded_header(
                &relay_chain_subscribe_all.finalized_block_scale_encoded_header
            ))
        );

        is_near_head_of_chain = relay_chain_sync.is_near_head_of_chain_heuristic().await;

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
            finalized_parahead = finalized;
            finalized_parahead_up_to_date = true;
        } else {
            finalized_parahead_up_to_date = false;
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
                .map(|b| b.0);
            debug_assert!(
                parent.is_some()
                    || block.parent_hash
                        == header::hash_from_scale_encoded_header(
                            &relay_chain_subscribe_all.finalized_block_scale_encoded_header
                        )
            );
            async_tree.input_insert_block(hash, parent, false, block.is_new_best);
        }

        // List of senders that get notified when the tree of blocks is modified.
        // Note that this list is created in the inner loop, as to be cleared if the relay chain
        // blocks stream has a gap.
        let mut all_subscriptions = Vec::<mpsc::Sender<_>>::new();

        // List of in-progress parahead fetching operations.
        let mut in_progress_paraheads = stream::FuturesUnordered::new();

        // Future that is ready when we need to wake up the `select!` below.
        let mut wakeup_deadline = future::Either::Right(future::pending());

        loop {
            // Start fetching paraheads of new blocks whose parahead needs to be fetched.
            if finalized_parahead_up_to_date {
                loop {
                    match async_tree.next_necessary_async_op(&ffi::Instant::now()) {
                        async_tree::NextNecessaryAsyncOp::NotReady { when: Some(when) } => {
                            wakeup_deadline = future::Either::Left(ffi::Delay::new_at(when));
                            break;
                        }
                        async_tree::NextNecessaryAsyncOp::NotReady { when: None } => {
                            wakeup_deadline = future::Either::Right(future::pending());
                            break;
                        }
                        async_tree::NextNecessaryAsyncOp::Ready(op) => {
                            log::debug!(
                                target: &log_target,
                                "Fetching parahead for relay chain block 0x{} (operation id: {:?})",
                                HashDisplay(op.block_user_data),
                                op.id
                            );

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
            }

            futures::select! {
                () = wakeup_deadline => {
                    // Do nothing. This is simply to wake up and loop again.
                },

                relay_chain_notif = relay_chain_subscribe_all.new_blocks.next() => {
                    let relay_chain_notif = match relay_chain_notif {
                        Some(n) => n,
                        None => break, // Jumps to the outer loop to recreate the channel.
                    };

                    is_near_head_of_chain = relay_chain_sync.is_near_head_of_chain_heuristic().await;

                    match relay_chain_notif {
                        Notification::Finalized { hash, best_block_hash } => {
                            log::debug!(
                                target: &log_target,
                                "Relay chain has finalized block 0x{}",
                                HashDisplay(&hash)
                            );

                            // If finalized parahead is outdated, it would be a logic error to
                            // notify any new block. Instead, reset the syncing in order to try
                            // fetching the parahead of the relay finalized block again.
                            if !finalized_parahead_up_to_date {
                                break;
                            }

                            let finalized = async_tree.input_iter_unordered().find(|(_, b, _, _)| **b == hash).unwrap().0;
                            let best = async_tree.input_iter_unordered().find(|(_, b, _, _)| **b == best_block_hash).unwrap().0;
                            async_tree.input_finalize(finalized, best);
                        }
                        Notification::Block(block) => {
                            let hash = header::hash_from_scale_encoded_header(&block.scale_encoded_header);

                            log::debug!(
                                target: &log_target,
                                "New relay chain block 0x{}",
                                HashDisplay(&hash)
                            );

                            let parent = async_tree.input_iter_unordered().find(|(_, b, _, _)| **b == block.parent_hash).map(|b| b.0); // TODO: check if finalized
                            async_tree.input_insert_block(hash, parent, false, block.is_new_best);
                        }
                    };

                    while let Some(update) = async_tree.try_advance_output() {
                        match update {
                            async_tree::OutputUpdate::Finalized { async_op_user_data: parahead, .. }
                                if parahead != finalized_parahead =>
                            {
                                debug_assert!(finalized_parahead_up_to_date);

                                finalized_parahead = parahead;
                                let hash = header::hash_from_scale_encoded_header(&finalized_parahead);

                                log::debug!(
                                    target: &log_target,
                                    "Reporting finalized parablock 0x{}",
                                    HashDisplay(&hash)
                                );

                                // Elements in `all_subscriptions` are removed one by one and
                                // inserted back if the channel is still open.
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

                                log::debug!(
                                    target: &log_target,
                                    "Reporting new parablock 0x{}",
                                    HashDisplay(&header::hash_from_scale_encoded_header(&scale_encoded_header))
                                );

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
                    debug_assert!(finalized_parahead_up_to_date);

                    match parahead_result {
                        Ok(parahead) => {
                            // TODO: print more info
                            log::debug!(
                                target: &log_target,
                                "Successfully fetched parahead",
                            );

                            async_tree.async_op_finished(async_op_id, parahead);
                        },
                        Err(error) => {
                            // Only a debug line is printed if not near the head of the chain,
                            // to handle chains that have been upgraded later on to support
                            // parachains later.
                            log::log!(
                                target: &log_target,
                                if is_near_head_of_chain && !error.is_network_problem() { // TODO: is is_near_head_of_chain the correct flag?
                                    log::Level::Error
                                } else {
                                    log::Level::Debug
                                },
                                "Failed to fetch the parachain head from relay chain: {}",
                                error
                            );

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
                            let _ = send_back.send(is_near_head_of_chain && finalized_parahead_up_to_date);
                        },
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
        .ok_or(ParaheadError::BlockPruned)?
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
        Ok(None) => Err(ParaheadError::NoCore),
        Err(error) => Err(ParaheadError::InvalidRuntimeOutput(error)),
    }
}

#[derive(derive_more::Display)]
enum ParaheadError {
    Call(runtime_service::RuntimeCallError),
    StartError(host::StartErr),
    ReadOnlyRuntime(read_only_runtime_host::ErrorDetail),
    NoCore,
    InvalidRuntimeOutput(para::Error),
    BlockPruned,
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
            ParaheadError::BlockPruned => false,
        }
    }
}
