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

//! This module contains useful features built on top of the [`RuntimeService`] that are only used
//! by the JSON-RPC service.

use crate::{
    platform::Platform,
    runtime_service::{Notification, RuntimeError, RuntimeService},
};

use futures::prelude::*;
use smoldot::{executor, header};
use std::{num::NonZeroUsize, sync::Arc};

/// Returns the current runtime version, plus an unlimited stream that produces one item every
/// time the specs of the runtime of the best block are changed.
///
/// The future returned by this function waits until the runtime is available. This can take
/// a long time.
///
/// The stream can generate an `Err` if the runtime in the best block is invalid.
///
/// The stream is infinite. In other words it is guaranteed to never return `None`.
pub async fn subscribe_runtime_version<TPlat: Platform>(
    runtime_service: &Arc<RuntimeService<TPlat>>,
) -> (
    Result<executor::CoreVersion, RuntimeError>,
    stream::BoxStream<'static, Result<executor::CoreVersion, RuntimeError>>,
) {
    let mut master_stream = stream::unfold(runtime_service.clone(), |runtime_service| async move {
        let subscribe_all = runtime_service
            .subscribe_all("subscribe-runtime-version", 16, NonZeroUsize::new(24).unwrap())
            .await;

        // Map of runtimes by hash. Contains all non-finalized blocks, plus the current finalized
        // block.
        let mut headers = hashbrown::HashMap::<
            [u8; 32],
            Arc<Result<executor::CoreVersion, RuntimeError>>,
            fnv::FnvBuildHasher,
        >::with_capacity_and_hasher(16, Default::default());

        let current_finalized_hash = header::hash_from_scale_encoded_header(
            &subscribe_all.finalized_block_scale_encoded_header,
        );
        subscribe_all
            .new_blocks
            .unpin_block(&current_finalized_hash)
            .await;

        headers.insert(
            current_finalized_hash,
            Arc::new(subscribe_all.finalized_block_runtime),
        );

        let mut current_best = None;
        for block in subscribe_all.non_finalized_blocks_ancestry_order {
            let hash = header::hash_from_scale_encoded_header(&block.scale_encoded_header);
            subscribe_all.new_blocks.unpin_block(&hash).await;

            if let Some(new_runtime) = block.new_runtime {
                headers.insert(hash, Arc::new(new_runtime));
            } else {
                let parent_runtime = headers
                    .get(&block.parent_hash)
                    .unwrap()
                    .clone();
                headers.insert(hash, parent_runtime);
            }

            if block.is_new_best {
                debug_assert!(current_best.is_none());
                current_best = Some(hash);
            }
        }
        let current_best = current_best.unwrap_or(current_finalized_hash);
        let current_best_runtime = (**headers.get(&current_best).unwrap()).clone();

        // Turns `subscribe_all.new_blocks` into a stream of headers.
        let substream = stream::unfold(
            (
                subscribe_all.new_blocks,
                headers,
                current_finalized_hash,
                current_best,
            ),
            |(
                mut new_blocks,
                mut headers,
                mut current_finalized_hash,
                mut current_best,
            )| async move {
                loop {
                    match new_blocks.next().await? {
                        Notification::Block(block) => {
                            let hash =
                                header::hash_from_scale_encoded_header(&block.scale_encoded_header);
                            new_blocks.unpin_block(&hash).await;

                            if let Some(new_runtime) = block.new_runtime {
                                headers.insert(hash, Arc::new(new_runtime));
                            } else {
                                let parent_runtime = headers
                                    .get(&block.parent_hash)
                                    .unwrap()
                                    .clone();
                                headers.insert(hash, parent_runtime);
                            }

                            if block.is_new_best {
                                let current_best_runtime =
                                    headers.get(&current_best).unwrap();
                                let new_best_runtime = headers.get(&hash).unwrap();
                                current_best = hash;

                                if !Arc::ptr_eq(current_best_runtime, new_best_runtime) {
                                    let runtime = (**new_best_runtime).clone();
                                    break Some((
                                        runtime,
                                        (
                                            new_blocks,
                                            headers,
                                            current_finalized_hash,
                                            current_best,
                                        ),
                                    ));
                                }
                            }
                        }
                        Notification::Finalized {
                            hash,
                            pruned_blocks,
                            best_block_hash,
                        } => {
                            let current_best_runtime =
                                headers.get(&current_best).unwrap().clone();
                            let new_best_runtime =
                                headers.get(&best_block_hash).unwrap().clone();

                            // Clean up the headers we won't need anymore.
                            for pruned_block in pruned_blocks {
                                let _was_in = headers.remove(&pruned_block);
                                debug_assert!(_was_in.is_some());
                            }

                            let _ = headers
                                .remove(&current_finalized_hash)
                                .unwrap();
                            current_finalized_hash = hash;
                            current_best = best_block_hash;

                            if !Arc::ptr_eq(&current_best_runtime, &new_best_runtime) {
                                let runtime = (*new_best_runtime).clone();
                                break Some((
                                    runtime,
                                    (
                                        new_blocks,
                                        headers,
                                        current_finalized_hash,
                                        current_best,
                                    ),
                                ));
                            }
                        }
                        Notification::BestBlockChanged { hash } => {
                            let current_best_runtime =
                                headers.get(&current_best).unwrap().clone();
                            let new_best_runtime =
                                headers.get(&hash).unwrap().clone();

                            current_best = hash;

                            if !Arc::ptr_eq(&current_best_runtime, &new_best_runtime) {
                                let runtime = (*new_best_runtime).clone();
                                break Some((
                                    runtime,
                                    (
                                        new_blocks,
                                        headers,
                                        current_finalized_hash,
                                        current_best,
                                    ),
                                ));
                            }
                        }
                    }
                }
            },
        );

        // Prepend the current best block to the stream.
        let substream = stream::once(future::ready(current_best_runtime)).chain(substream);
        Some((substream, runtime_service))
    })
    .flatten()
    .boxed();

    // TODO: we don't dedup blocks; in other words the stream can produce the same block twice if the inner subscription drops

    // Now that we have a stream, extract the first element to be the first value.
    let first_value = master_stream.next().await.unwrap();
    (first_value, master_stream)
}

/// Returns the SCALE-encoded header of the current finalized block, plus an unlimited stream
/// that produces one item every time the finalized block is changed.
///
/// This function only returns once the runtime of the current finalized block is known. This
/// might take a long time.
pub async fn subscribe_finalized<TPlat: Platform>(
    runtime_service: &Arc<RuntimeService<TPlat>>,
) -> (Vec<u8>, stream::BoxStream<'static, Vec<u8>>) {
    let mut master_stream = stream::unfold(runtime_service.clone(), |runtime_service| async move {
        let subscribe_all = runtime_service
            .subscribe_all("subscribe-finalized", 16, NonZeroUsize::new(32).unwrap())
            .await;

        // Map of block headers by hash. Contains all non-finalized blocks headers.
        let mut non_finalized_headers =
            hashbrown::HashMap::<[u8; 32], Vec<u8>, fnv::FnvBuildHasher>::with_capacity_and_hasher(
                16,
                Default::default(),
            );

        subscribe_all
            .new_blocks
            .unpin_block(&header::hash_from_scale_encoded_header(
                &subscribe_all.finalized_block_scale_encoded_header,
            ))
            .await;

        for block in subscribe_all.non_finalized_blocks_ancestry_order {
            let hash = header::hash_from_scale_encoded_header(&block.scale_encoded_header);
            subscribe_all.new_blocks.unpin_block(&hash).await;
            non_finalized_headers.insert(hash, block.scale_encoded_header);
        }

        // Turns `subscribe_all.new_blocks` into a stream of headers.
        let substream = stream::unfold(
            (subscribe_all.new_blocks, non_finalized_headers),
            |(mut new_blocks, mut non_finalized_headers)| async {
                loop {
                    match new_blocks.next().await? {
                        Notification::Block(block) => {
                            let hash =
                                header::hash_from_scale_encoded_header(&block.scale_encoded_header);
                            new_blocks.unpin_block(&hash).await;
                            non_finalized_headers.insert(hash, block.scale_encoded_header);
                        }
                        Notification::Finalized {
                            hash,
                            pruned_blocks,
                            ..
                        } => {
                            // Clean up the headers we won't need anymore.
                            for pruned_block in pruned_blocks {
                                let _was_in = non_finalized_headers.remove(&pruned_block);
                                debug_assert!(_was_in.is_some());
                            }

                            let header = non_finalized_headers.remove(&hash).unwrap();
                            break Some((header, (new_blocks, non_finalized_headers)));
                        }
                        Notification::BestBlockChanged { .. } => {}
                    }
                }
            },
        );

        // Prepend the current finalized block to the stream.
        let substream = stream::once(future::ready(
            subscribe_all.finalized_block_scale_encoded_header,
        ))
        .chain(substream);

        Some((substream, runtime_service))
    })
    .flatten()
    .boxed();

    // TODO: we don't dedup blocks; in other words the stream can produce the same block twice if the inner subscription drops

    // Now that we have a stream, extract the first element to be the first value.
    let first_value = master_stream.next().await.unwrap();
    (first_value, master_stream)
}

/// Returns the SCALE-encoded header of the current best block, plus an unlimited stream that
/// produces one item every time the best block is changed.
///
/// This function only returns once the runtime of the current best block is known. This might
/// take a long time.
pub async fn subscribe_best<TPlat: Platform>(
    runtime_service: &Arc<RuntimeService<TPlat>>,
) -> (Vec<u8>, stream::BoxStream<'static, Vec<u8>>) {
    let mut master_stream = stream::unfold(runtime_service.clone(), |runtime_service| async move {
        let subscribe_all = runtime_service
            .subscribe_all("subscribe-best", 16, NonZeroUsize::new(32).unwrap())
            .await;

        // Map of block headers by hash. Contains all non-finalized blocks headers, plus the
        // current finalized block header.
        let mut headers =
            hashbrown::HashMap::<[u8; 32], Vec<u8>, fnv::FnvBuildHasher>::with_capacity_and_hasher(
                16,
                Default::default(),
            );

        let current_finalized_hash = header::hash_from_scale_encoded_header(
            &subscribe_all.finalized_block_scale_encoded_header,
        );

        subscribe_all
            .new_blocks
            .unpin_block(&current_finalized_hash)
            .await;

        headers.insert(
            current_finalized_hash,
            subscribe_all.finalized_block_scale_encoded_header,
        );

        let mut current_best = None;
        for block in subscribe_all.non_finalized_blocks_ancestry_order {
            let hash = header::hash_from_scale_encoded_header(&block.scale_encoded_header);
            subscribe_all.new_blocks.unpin_block(&hash).await;
            headers.insert(hash, block.scale_encoded_header);

            if block.is_new_best {
                debug_assert!(current_best.is_none());
                current_best = Some(hash);
            }
        }
        let current_best = current_best.unwrap_or(current_finalized_hash);
        let current_best_header = headers.get(&current_best).unwrap().clone();

        // Turns `subscribe_all.new_blocks` into a stream of headers.
        let substream = stream::unfold(
            (
                subscribe_all.new_blocks,
                headers,
                current_finalized_hash,
                current_best,
            ),
            |(
                mut new_blocks,
                mut headers,
                mut current_finalized_hash,
                mut current_best,
            )| async move {
                loop {
                    match new_blocks.next().await? {
                        Notification::Block(block) => {
                            let hash =
                                header::hash_from_scale_encoded_header(&block.scale_encoded_header);
                            new_blocks.unpin_block(&hash).await;
                            headers.insert(hash, block.scale_encoded_header);

                            if block.is_new_best {
                                current_best = hash;
                                let header =
                                    headers.get(&current_best).unwrap().clone();
                                break Some((
                                    header,
                                    (
                                        new_blocks,
                                        headers,
                                        current_finalized_hash,
                                        current_best,
                                    ),
                                ));
                            }
                        }
                        Notification::Finalized {
                            hash,
                            pruned_blocks,
                            best_block_hash,
                        } => {
                            // Clean up the headers we won't need anymore.
                            for pruned_block in pruned_blocks {
                                let _was_in = headers.remove(&pruned_block);
                                debug_assert!(_was_in.is_some());
                            }

                            let _ = headers
                                .remove(&current_finalized_hash)
                                .unwrap();
                            current_finalized_hash = hash;

                            if best_block_hash != current_best {
                                current_best = best_block_hash;
                                let header =
                                    headers.get(&current_best).unwrap().clone();
                                break Some((
                                    header,
                                    (
                                        new_blocks,
                                        headers,
                                        current_finalized_hash,
                                        current_best,
                                    ),
                                ));
                            }
                        }
                        Notification::BestBlockChanged { hash } => {
                            if hash != current_best {
                                current_best = hash;
                                let header =
                                    headers.get(&current_best).unwrap().clone();
                                break Some((
                                    header,
                                    (
                                        new_blocks,
                                        headers,
                                        current_finalized_hash,
                                        current_best,
                                    ),
                                ));
                            }
                        }
                    }
                }
            },
        );

        // Prepend the current best block to the stream.
        let substream = stream::once(future::ready(current_best_header)).chain(substream);
        Some((substream, runtime_service))
    })
    .flatten()
    .boxed();

    // TODO: we don't dedup blocks; in other words the stream can produce the same block twice if the inner subscription drops

    // Now that we have a stream, extract the first element to be the first value.
    let first_value = master_stream.next().await.unwrap();
    (first_value, master_stream)
}
