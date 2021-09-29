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

//! Data structure. Inputs blocks, tries to fetch their runtime, and outputs blocks whose runtime
//! is known.
//!
//! # Usage
//!
//! This data structure holds a tree of blocks whose runtime is either known, or not. This tree
//! can be updated by using [`DownloadTree::insert_block`] and [`DownloadTree::finalize`].
//!
//! The data structure also holds a list of on-going runtime parameter downloads. Use
//! [`DownloadTree::next_necessary_download`] to insert an ongoing download in the data structure.
//! It is the responsibility of the API user to actually perform the download and use
//! [`DownloadTree::runtime_download_finished`] or [`DownloadTree::runtime_download_failure`] when
//! this download is finished.
//!
//! Whenever it is updated, the [`DownloadTree`] can also update the block that it considers as
//! the "output best block" and the block that it considers as the "output finalized block". These
//! blocks are guaranteed to have their runtime known.
//! At initialization, the data structure is initially in a "not ready" state, in which case
//! it doesn't have any output best or finalized block. Use [`DownloadTree::has_output`] to
//! determine whether the data structure is ready.
//!

use crate::{chain::fork_tree, executor, header, metadata};
use alloc::vec::Vec;
use core::{cmp, iter, mem, num::NonZeroUsize, time::Duration};

mod tests;

/// Error when analyzing the runtime.
#[derive(Debug, derive_more::Display, Clone)]
pub enum RuntimeError {
    /// The `:code` key of the storage is empty.
    CodeNotFound,
    /// Error while parsing the `:heappages` storage value.
    InvalidHeapPages(executor::InvalidHeapPagesError),
    /// Error while compiling the runtime.
    Build(executor::host::NewErr),
    /// Error when determining the runtime specification.
    CoreVersion(executor::CoreVersionError),
}

/// Identifier for a download in the [`DownloadTree`].
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct DownloadId(u64);

#[derive(Debug)]
pub enum NextNecessaryDownload<TNow> {
    Ready(DownloadParams),
    NotReady { when: Option<TNow> },
}

/// Information about a download that must be performed.
#[derive(Debug)]
pub struct DownloadParams {
    /// Identifier to later provide when calling [`DownloadTree::runtime_download_finished`] or
    /// [`DownloadTree::runtime_download_failure`].
    pub id: DownloadId,

    /// Hash of the block whose runtime to download.
    pub block_hash: [u8; 32],

    /// State trie root of the block whose runtime to download.
    pub block_state_root: [u8; 32],
}

pub struct DownloadTree<TNow> {
    /// List of all compiled runtime. Referenced by the various blocks below.
    runtimes: slab::Slab<Runtime>,

    /// State of the finalized block reported through the public API of the output.
    /// This doesn't necessarily match the one of the input.
    ///
    /// When `DownloadTree` has output, The value of [`Block::runtime`] for this block is
    /// guaranteed to be [`RuntimeDownloadState::Finished`].
    finalized_block: Block<TNow>,

    /// State of all the non-finalized blocks.
    non_finalized_blocks: fork_tree::ForkTree<Block<TNow>>,

    /// Index within [`DownloadTree::non_finalized_blocks`] of the current "output" best block.
    /// `None` if the best block is the finalized block.
    ///
    /// When `DownloadTree` has output, the value of [`Block::runtime`] for this block is
    /// guaranteed to be [`RuntimeDownloadState::Finished`].
    best_block_index: Option<fork_tree::NodeIndex>,

    /// Index within [`DownloadTree::non_finalized_blocks`] of the finalized block according to
    /// the input. `None` if the input finalized block is the same as the output finalized block.
    ///
    /// If `Some` and when `DownloadTree` has output, the value of [`Block::runtime`] for this
    /// block is guaranteed to **not** be [`RuntimeDownloadState::Finished`].
    input_finalized_index: Option<fork_tree::NodeIndex>,

    /// Incremented by one and stored within [`Block::input_best_block_weight`].
    input_best_block_next_weight: u32,

    /// Identifier to assign to the next download.
    next_download_id: DownloadId,
}

impl<TNow> DownloadTree<TNow>
where
    TNow: Clone + core::ops::Add<Duration, Output = TNow> + Ord,
{
    /// Returns a new [`DownloadTree`] containing one "input" finalized block.
    ///
    /// This [`DownloadTree`] is in a non-ready state.
    pub fn from_finalized_block(finalized_block_scale_encoded_header: Vec<u8>) -> Self {
        DownloadTree::new_inner(finalized_block_scale_encoded_header, None)
    }

    /// Returns a new [`DownloadTree`] containing one "input" finalized block. The runtime of this
    /// finalized block will be compiled from the given storage, meaning that this block also
    /// becomes the "output" finalized block and the "output" best block.
    ///
    /// This [`DownloadTree`] is immediately in a ready state.
    pub fn from_finalized_block_and_storage<'a>(
        finalized_block_scale_encoded_header: Vec<u8>,
        genesis_storage: impl ExactSizeIterator<Item = (&'a [u8], &'a [u8])> + Clone,
    ) -> Self {
        // Build the runtime of the genesis block.
        let genesis_runtime = {
            let code = genesis_storage
                .clone()
                .find(|(k, _)| k == b":code")
                .map(|(_, v)| v.to_vec());
            let heap_pages = genesis_storage
                .clone()
                .find(|(k, _)| k == b":heappages")
                .map(|(_, v)| v.to_vec());

            // Note that in the absolute we don't need to panic in case of a problem, and could
            // simply store an `Err` and continue running.
            // However, in practice, it seems more sane to detect problems in the genesis block.
            let mut runtime = SuccessfulRuntime::from_params(&code, &heap_pages);

            // As documented in the `metadata` field, we must fill it using the genesis storage.
            if let Ok(runtime) = runtime.as_mut() {
                let mut query = metadata::query_metadata(runtime.virtual_machine.take().unwrap());
                loop {
                    match query {
                        metadata::Query::Finished(Ok(metadata), vm) => {
                            runtime.virtual_machine = Some(vm);
                            runtime.metadata = Some(metadata);
                            break;
                        }
                        metadata::Query::StorageGet(get) => {
                            let key = get.key_as_vec();
                            let value = genesis_storage
                                .clone()
                                .find(|(k, _)| &**k == key)
                                .map(|(_, v)| v);
                            query = get.inject_value(value.map(iter::once));
                        }
                        metadata::Query::Finished(Err(err), _) => {
                            panic!("Unable to generate genesis metadata: {}", err)
                        }
                    }
                }
            }

            Runtime {
                runtime,
                runtime_code: code,
                heap_pages,
                num_blocks: NonZeroUsize::new(1).unwrap(),
            }
        };

        DownloadTree::new_inner(finalized_block_scale_encoded_header, Some(genesis_runtime))
    }

    fn new_inner(
        finalized_block_scale_encoded_header: Vec<u8>,
        finalized_runtime: Option<Runtime>,
    ) -> Self {
        let mut runtimes = slab::Slab::with_capacity(4); // Usual len is `1`, rarely `2`.

        // Note that `finalized_runtime` is intentionally silently discarded if the finalized
        // block fails to parse.
        let finalized_block_runtime = match header::decode(&finalized_block_scale_encoded_header) {
            Err(_) => Err(BlockRuntimeErr::InvalidHeader),
            Ok(header) => {
                if let Some(finalized_runtime) = finalized_runtime {
                    Ok(RuntimeDownloadState::Finished(
                        runtimes.insert(finalized_runtime),
                    ))
                } else {
                    Ok(RuntimeDownloadState::Unknown {
                        same_as_parent: false,
                        state_root: *header.state_root,
                        timeout: None,
                    })
                }
            }
        };

        DownloadTree {
            runtimes,
            best_block_index: None,
            non_finalized_blocks: fork_tree::ForkTree::with_capacity(32),
            finalized_block: Block {
                runtime: finalized_block_runtime,
                hash: header::hash_from_scale_encoded_header(&finalized_block_scale_encoded_header),
                header: finalized_block_scale_encoded_header,
                input_best_block_weight: 1,
            },
            input_finalized_index: None,
            input_best_block_next_weight: 2,
            next_download_id: DownloadId(0),
        }
    }

    /// Returns `true` if the state machine is in a ready state, meaning that it has an "output"
    /// finalized block and an "output" best block.
    ///
    /// Several methods panic if the state machine isn't in a ready state.
    pub fn has_output(&self) -> bool {
        if matches!(
            self.finalized_block.runtime,
            Ok(RuntimeDownloadState::Finished(_))
        ) {
            debug_assert!(!self.runtimes.is_empty());
            debug_assert!(self.best_block_index.map_or(true, |idx| matches!(
                self.non_finalized_blocks.get(idx).unwrap().runtime,
                Ok(RuntimeDownloadState::Finished(_))
            )));
            true
        } else {
            false
        }
    }

    /// Returns the hash of the current "output" finalized block.
    ///
    /// # Panic
    ///
    /// Panics if [`DownloadTree::has_output`] isn't `true`.
    ///
    pub fn finalized_block_hash(&self) -> &[u8; 32] {
        &self.finalized_block.hash
    }

    /// Returns the hash of the current "output" best block.
    ///
    /// # Panic
    ///
    /// Panics if [`DownloadTree::has_output`] isn't `true`.
    ///
    pub fn best_block_hash(&self) -> &[u8; 32] {
        if let Some(best_block_index) = self.best_block_index {
            &self
                .non_finalized_blocks
                .get(best_block_index)
                .unwrap()
                .hash
        } else {
            &self.finalized_block.hash
        }
    }

    /// Returns the SCALE-encoded header of the current "output" finalized block.
    ///
    /// # Panic
    ///
    /// Panics if [`DownloadTree::has_output`] isn't `true`.
    ///
    pub fn finalized_block_header(&self) -> &[u8] {
        &self.finalized_block.header
    }

    /// Returns the SCALE-encoded header of the current "output" best block.
    ///
    /// # Panic
    ///
    /// Panics if [`DownloadTree::has_output`] isn't `true`.
    ///
    pub fn best_block_header(&self) -> &[u8] {
        if let Some(best_block_index) = self.best_block_index {
            &self
                .non_finalized_blocks
                .get(best_block_index)
                .unwrap()
                .header
        } else {
            &self.finalized_block.header
        }
    }

    /// Returns the specification of the current "output" best block. Returns an error if the
    /// runtime had failed to compile.
    ///
    /// # Panic
    ///
    /// Panics if [`DownloadTree::has_output`] isn't `true`.
    ///
    pub fn best_block_runtime_spec(&self) -> Result<&executor::CoreVersion, &RuntimeError> {
        let index = self.best_block_runtime_index();
        self.runtimes[index]
            .runtime
            .as_ref()
            .map(|r| &r.runtime_spec)
    }

    /// Returns the runtime of the current "output" finalized block. Returns an error if the
    /// runtime had failed to compile.
    ///
    /// # Panic
    ///
    /// Panics if [`DownloadTree::has_output`] isn't `true`.
    ///
    // TODO: is this method really useful?
    pub fn finalized_block_runtime(
        &self,
    ) -> Result<&executor::host::HostVmPrototype, &RuntimeError> {
        let index = self.finalized_block_runtime_index();
        self.runtimes[index]
            .runtime
            .as_ref()
            .map(|r| r.virtual_machine.as_ref().unwrap())
    }

    /// Returns the runtime of the current "output" best block. Returns an error if the runtime
    /// had failed to compile.
    ///
    /// # Panic
    ///
    /// Panics if [`DownloadTree::has_output`] isn't `true`.
    ///
    // TODO: is this method really useful?
    pub fn best_block_runtime(&self) -> Result<&executor::host::HostVmPrototype, &RuntimeError> {
        let index = self.best_block_runtime_index();
        self.runtimes[index]
            .runtime
            .as_ref()
            .map(|r| r.virtual_machine.as_ref().unwrap())
    }

    /// Extracts the runtime of the current "output" finalized block.
    ///
    /// # Panic
    ///
    /// Panics if [`DownloadTree::has_output`] isn't `true`.
    ///
    pub fn finalized_block_runtime_extract(
        self,
    ) -> Result<ExtractedRuntime<TNow>, (Self, RuntimeError)> {
        let runtime_index = self.finalized_block_runtime_index();
        self.runtime_extract_inner(runtime_index)
    }

    /// Extracts the runtime of the current "output" best block.
    ///
    /// # Panic
    ///
    /// Panics if [`DownloadTree::has_output`] isn't `true`.
    ///
    pub fn best_block_runtime_extract(
        self,
    ) -> Result<ExtractedRuntime<TNow>, (Self, RuntimeError)> {
        let runtime_index = self.best_block_runtime_index();
        self.runtime_extract_inner(runtime_index)
    }

    fn runtime_extract_inner(
        mut self,
        runtime_index: usize,
    ) -> Result<ExtractedRuntime<TNow>, (Self, RuntimeError)> {
        match self.runtimes[runtime_index].runtime.as_mut() {
            Err(err) => {
                let err = err.clone();
                Err((self, err))
            }
            Ok(runtime) => {
                let runtime = runtime.virtual_machine.take().unwrap();

                Ok(ExtractedRuntime {
                    runtime,
                    tree: ExtractedDownloadTree {
                        inner: self,
                        extracted_runtime_index: runtime_index,
                    },
                })
            }
        }
    }

    /// Injects into the state of the data structure a completed runtime download.
    pub fn runtime_download_finished(
        &mut self,
        download_id: DownloadId,
        storage_code: Option<Vec<u8>>,
        storage_heap_pages: Option<Vec<u8>>,
    ) -> OutputUpdate {
        // Find the number of blocks that are bound to this download.
        let num_concerned_blocks = iter::once(&self.finalized_block)
            .chain(self.non_finalized_blocks.iter_unordered().map(|(_, b)| b))
            .filter(|b| match b.runtime {
                Ok(RuntimeDownloadState::Downloading {
                    download_id: id, ..
                }) if id == download_id => true,
                _ => false,
            })
            .count();

        // The download might concern only blocks that have now been pruned.
        if num_concerned_blocks == 0 {
            debug_assert!(self.try_advance_output().is_noop());
            return OutputUpdate {
                best_block_updated: false,
                best_block_runtime_changed: false,
                finalized_block_updated: false,
            };
        }

        // Try find the identifier of an existing runtime that has this code and heap pages. If
        // none is found, compile the runtime.
        // This search is `O(n)`, but considering the very low number of runtimes (most of the
        // time one, occasionally two), this shouldn't be a problem.
        // The runtime's `num_blocks` is also increased by `num_concerned_blocks` here.
        let runtime_index = if let Some((runtime_index, runtime)) = self
            .runtimes
            .iter_mut()
            .find(|(_, r)| r.runtime_code == storage_code && r.heap_pages == storage_heap_pages)
        {
            runtime.num_blocks =
                NonZeroUsize::new(runtime.num_blocks.get() + num_concerned_blocks).unwrap();
            runtime_index
        } else {
            let runtime = SuccessfulRuntime::from_params(&storage_code, &storage_heap_pages);
            self.runtimes.insert(Runtime {
                num_blocks: NonZeroUsize::new(num_concerned_blocks).unwrap(),
                runtime,
                runtime_code: storage_code,
                heap_pages: storage_heap_pages,
            })
        };

        // Update the blocks that were downloading this runtime to become `Finished`.
        match self.finalized_block.runtime {
            Ok(RuntimeDownloadState::Downloading {
                download_id: id, ..
            }) if id == download_id => {
                self.finalized_block.runtime = Ok(RuntimeDownloadState::Finished(runtime_index));
            }
            _ => {}
        }
        for index in self
            .non_finalized_blocks
            .iter_unordered()
            .map(|(index, _)| index)
            .collect::<Vec<_>>()
        {
            let block = self.non_finalized_blocks.get_mut(index).unwrap();
            match block.runtime {
                Ok(RuntimeDownloadState::Downloading {
                    download_id: id, ..
                }) if id == download_id => {
                    block.runtime = Ok(RuntimeDownloadState::Finished(runtime_index));
                }
                _ => {}
            }
        }

        // Sanity check.
        debug_assert_eq!(
            self.runtimes
                .iter()
                .map(|(_, r)| r.num_blocks.get())
                .sum::<usize>(),
            iter::once(&self.finalized_block)
                .chain(self.non_finalized_blocks.iter_unordered().map(|(_, b)| b))
                .filter(|b| matches!(b.runtime, Ok(RuntimeDownloadState::Finished(_))))
                .count()
        );

        self.try_advance_output()
    }

    /// Injects into the state of the state machine a failed runtime download.
    ///
    /// This same download will not be repeated for the next few seconds. Thanks to this, it is
    /// possible to immediately call this function in response to a new necessary download.
    pub fn runtime_download_failure(&mut self, download_id: DownloadId, now: &TNow) {
        let new_timeout = now.clone() + Duration::from_secs(10); // TODO: hardcoded value

        // Update the blocks that were downloading this runtime.
        match self.finalized_block.runtime {
            Ok(RuntimeDownloadState::Downloading {
                download_id: id,
                state_root,
                ref timeout,
            }) if id == download_id => {
                let timeout = match timeout {
                    Some(a) => Some(cmp::min(a.clone(), new_timeout.clone())),
                    None => Some(new_timeout.clone()),
                };

                // Note: the value of `same_as_parent` is irrelevant for the finalized block.
                self.finalized_block.runtime = Ok(RuntimeDownloadState::Unknown {
                    state_root,
                    same_as_parent: false,
                    timeout,
                });
            }
            _ => {}
        }

        for index in self
            .non_finalized_blocks
            .iter_unordered()
            .map(|(index, _)| index)
            .collect::<Vec<_>>()
        {
            let block = self.non_finalized_blocks.get_mut(index).unwrap();
            match block.runtime {
                Ok(RuntimeDownloadState::Downloading {
                    state_root,
                    download_id: id,
                    ref timeout,
                }) if id == download_id => {
                    let timeout = match timeout {
                        Some(a) => Some(cmp::min(a.clone(), new_timeout.clone())),
                        None => Some(new_timeout.clone()),
                    };

                    block.runtime = Ok(RuntimeDownloadState::Unknown {
                        same_as_parent: false, // TODO: not implemented properly; should check if parent had same download id
                        state_root,
                        timeout,
                    });
                }
                _ => {}
            }
        }

        debug_assert!(self.try_advance_output().is_noop());
    }

    /// Examines the state of `self` and, if a block's runtime should be downloaded, changes the
    /// state of the block to "downloading" and returns the parameters of the download.
    pub fn next_necessary_download(&mut self, now: &TNow) -> NextNecessaryDownload<TNow> {
        let mut when_not_ready = None;

        // Local finalized block, in case the state machine isn't in a ready state.
        match self.start_necessary_download(None, now) {
            NextNecessaryDownload::Ready(params) => return NextNecessaryDownload::Ready(params),
            NextNecessaryDownload::NotReady { when } => {
                when_not_ready = match (when, when_not_ready.take()) {
                    (None, None) => None,
                    (Some(a), None) => Some(a),
                    (None, Some(b)) => Some(b),
                    (Some(a), Some(b)) => Some(cmp::min(a, b)),
                };
            }
        }

        // Finalized block according to the blocks input.
        if let Some(idx) = self.input_finalized_index {
            match self.start_necessary_download(Some(idx), now) {
                NextNecessaryDownload::Ready(params) => {
                    return NextNecessaryDownload::Ready(params)
                }
                NextNecessaryDownload::NotReady { when } => {
                    when_not_ready = match (when, when_not_ready.take()) {
                        (None, None) => None,
                        (Some(a), None) => Some(a),
                        (None, Some(b)) => Some(b),
                        (Some(a), Some(b)) => Some(cmp::min(a, b)),
                    };
                }
            }
        }

        // Best block according to the blocks input.
        if let Some((idx, _)) = self
            .non_finalized_blocks
            .iter_unordered()
            .max_by_key(|(_, b)| b.input_best_block_weight)
        {
            match self.start_necessary_download(Some(idx), now) {
                NextNecessaryDownload::Ready(params) => {
                    return NextNecessaryDownload::Ready(params)
                }
                NextNecessaryDownload::NotReady { when } => {
                    when_not_ready = match (when, when_not_ready.take()) {
                        (None, None) => None,
                        (Some(a), None) => Some(a),
                        (None, Some(b)) => Some(b),
                        (Some(a), Some(b)) => Some(cmp::min(a, b)),
                    };
                }
            }
        }

        // TODO: consider also downloading the forks' runtimes, but only once the `RuntimeEnvironmentUpdated` digest item is deployed everywhere, otherwise too much bandwidth is used

        NextNecessaryDownload::NotReady {
            when: when_not_ready,
        }
    }

    /// Starts downloading the runtime of the block with the given index, if necessary.
    fn start_necessary_download(
        &mut self,
        block_index: Option<fork_tree::NodeIndex>,
        now: &TNow,
    ) -> NextNecessaryDownload<TNow> {
        let block = match block_index {
            None => &mut self.finalized_block,
            Some(idx) => self.non_finalized_blocks.get_mut(idx).unwrap(),
        };

        if let Ok(runtime) = &mut block.runtime {
            if let RuntimeDownloadState::Unknown {
                state_root,
                ref timeout,
                ..
            } = *runtime
            {
                if timeout.as_ref().map_or(true, |t| t <= now) {
                    let download_id = self.next_download_id;
                    self.next_download_id.0 += 1;
                    *runtime = RuntimeDownloadState::Downloading {
                        download_id,
                        state_root,
                        timeout: None,
                    };

                    // TODO: update all children that have same as parent to point to the same download

                    return NextNecessaryDownload::Ready(DownloadParams {
                        id: download_id,
                        block_hash: block.hash,
                        block_state_root: state_root,
                    });
                } else {
                    return NextNecessaryDownload::NotReady {
                        when: timeout.clone(),
                    };
                }
            }
        }

        NextNecessaryDownload::NotReady { when: None }
    }

    /// Updates the state machine with a new block.
    ///
    /// # Panic
    ///
    /// Panics if `parent_hash` wasn't inserted before.
    ///
    pub fn insert_block(
        &mut self,
        scale_encoded_header: Vec<u8>,
        parent_hash: &[u8; 32],
        is_new_best: bool,
    ) -> OutputUpdate {
        // Find the parent of the new block in the list of blocks that we know.
        let parent_index = if *parent_hash == self.finalized_block.hash {
            None
        } else {
            Some(
                self.non_finalized_blocks
                    .find(|b| b.hash == *parent_hash)
                    .unwrap(),
            )
        };

        // When this block is later inserted, value to use for `input_best_block_weight`.
        let input_best_block_weight = if is_new_best {
            let id = self.input_best_block_next_weight;
            debug_assert!(self
                .non_finalized_blocks
                .iter_unordered()
                .all(|(_, b)| b.input_best_block_weight < id));
            self.input_best_block_next_weight += 1;
            id
        } else {
            0
        };

        // In order to fetch the runtime code (below), we need to know the state trie
        // root of the block, which is found in the block's header.
        // Try to decode the new block's header. Failures are handled gracefully by
        // inserting the block but not retrieving its runtime.
        let decoded_header = match header::decode(&scale_encoded_header) {
            Ok(h) => h,
            Err(_) => {
                self.non_finalized_blocks.insert(
                    parent_index,
                    Block {
                        runtime: Err(BlockRuntimeErr::InvalidHeader),
                        hash: header::hash_from_scale_encoded_header(&scale_encoded_header),
                        header: scale_encoded_header,
                        input_best_block_weight,
                    },
                );

                debug_assert!(self.try_advance_output().is_noop());
                return OutputUpdate {
                    best_block_updated: false,
                    best_block_runtime_changed: false,
                    finalized_block_updated: false,
                };
            }
        };

        // Since https://github.com/paritytech/substrate/pull/9580 (Sept. 15th 2021),
        // the header contains a digest item indicating that the runtime environment
        // has changed since the parent.
        // However, as this is a recent addition, the absence of this digest item does
        // not necessarily mean that the runtime environment has not changed.
        // For this reason, we add `|| true`. This `|| true` can be removed in the
        // future.
        // TODO: remove `|| true`
        let runtime_environment_update =
            decoded_header.digest.has_runtime_environment_updated() || true;
        if !runtime_environment_update {
            // Runtime of the new block is the same as the parent.
            let parent_runtime = match parent_index {
                None => &self.finalized_block.runtime,
                Some(parent_index) => &self.non_finalized_blocks.get(parent_index).unwrap().runtime,
            };

            // It is possible, however, that the parent's runtime is unknown, in
            // which case we proceed with the rest of the function as if
            // `runtime_environment_update` was `true`.
            match *parent_runtime {
                Ok(RuntimeDownloadState::Unknown { .. }) | Err(_) => {}

                Ok(RuntimeDownloadState::Downloading { download_id, .. }) => {
                    self.non_finalized_blocks.insert(
                        parent_index,
                        Block {
                            runtime: Ok(RuntimeDownloadState::Downloading {
                                download_id,
                                state_root: *decoded_header.state_root,
                                timeout: None,
                            }),
                            hash: header::hash_from_scale_encoded_header(&scale_encoded_header),
                            header: scale_encoded_header,
                            input_best_block_weight,
                        },
                    );

                    debug_assert!(self.try_advance_output().is_noop());
                    return OutputUpdate {
                        best_block_updated: false,
                        best_block_runtime_changed: false,
                        finalized_block_updated: false,
                    };
                }

                Ok(RuntimeDownloadState::Finished(runtime_index)) => {
                    self.runtimes[runtime_index].num_blocks =
                        NonZeroUsize::new(self.runtimes[runtime_index].num_blocks.get() + 1)
                            .unwrap();
                    self.non_finalized_blocks.insert(
                        parent_index,
                        Block {
                            runtime: Ok(RuntimeDownloadState::Finished(runtime_index)),
                            hash: header::hash_from_scale_encoded_header(&scale_encoded_header),
                            header: scale_encoded_header,
                            input_best_block_weight,
                        },
                    );

                    // Since the block is immediately ready to be output, it is possible that
                    // we can advance the best and finalized output.
                    return self.try_advance_output();
                }
            }
        }

        // Insert the new runtime.
        self.non_finalized_blocks.insert(
            parent_index,
            Block {
                runtime: Ok(RuntimeDownloadState::Unknown {
                    same_as_parent: !runtime_environment_update,
                    state_root: *decoded_header.state_root,
                    timeout: None,
                }),
                hash: header::hash_from_scale_encoded_header(&scale_encoded_header),
                header: scale_encoded_header,
                input_best_block_weight,
            },
        );

        debug_assert!(self.try_advance_output().is_noop());
        OutputUpdate {
            best_block_updated: false,
            best_block_runtime_changed: false,
            finalized_block_updated: false,
        }
    }

    /// Updates the state machine to take into account that the input of blocks has finalized the
    /// given block.
    ///
    /// `new_best_block_hash` is the hash of the best block after the finalization.
    ///
    /// > **Note**: Finalizing a block might have to modify the current best block if the block
    /// >           being finalized isn't an ancestor of the current best block.
    ///
    /// # Panic
    ///
    /// Panics if `hash_to_finalize` or `new_best_block_hash` weren't inserted before.
    /// Panics if trying to finalize the parent of a block that is already finalized.
    /// Panics if `new_best_block_hash` is not a descendant of `hash_to_finalize`.
    ///
    pub fn finalize(
        &mut self,
        hash_to_finalize: [u8; 32],
        new_best_block_hash: [u8; 32],
    ) -> OutputUpdate {
        if hash_to_finalize != self.finalized_block.hash {
            // Find the finalized block in the list of blocks that we know.
            let finalized_node_index = self
                .non_finalized_blocks
                .find(|b| b.hash == hash_to_finalize)
                .unwrap();
            self.input_finalized_index = Some(finalized_node_index);
        } else {
            debug_assert_eq!(self.input_finalized_index, None);
        }

        // Find the new best block in the list of blocks that we know and make sure that its
        // weight is the maximum.
        if new_best_block_hash == self.finalized_block.hash {
            if self.finalized_block.input_best_block_weight != self.input_best_block_next_weight {
                self.finalized_block.input_best_block_weight = self.input_best_block_next_weight;
                self.input_best_block_next_weight += 1;
            }
        } else {
            let new_best_block_index = self
                .non_finalized_blocks
                .find(|b| b.hash == new_best_block_hash)
                .unwrap();

            // Make sure that `new_best_block_hash` is a descendant of `hash_to_finalize`,
            // otherwise the state of the tree will be corrupted.
            // This is checked with an `assert!` rather than a `debug_assert!`, as this constraint
            // is part of the public API of this method.
            assert!(self
                .input_finalized_index
                .map_or(true, |finalized_index| self
                    .non_finalized_blocks
                    .is_ancestor(finalized_index, new_best_block_index)));

            // If necessary, update the weight of the block.
            match &mut self
                .non_finalized_blocks
                .get_mut(new_best_block_index)
                .unwrap()
                .input_best_block_weight
            {
                w if *w == self.input_best_block_next_weight => {}
                w => {
                    *w = self.input_best_block_next_weight;
                    self.input_best_block_next_weight += 1;
                }
            }
        }

        // Minor sanity checks.
        debug_assert!(
            self.finalized_block.input_best_block_weight < self.input_best_block_next_weight
        );
        debug_assert!(self
            .non_finalized_blocks
            .iter_unordered()
            .all(|(_, b)| b.input_best_block_weight < self.input_best_block_next_weight));

        // Try see if we can update the output blocks.
        self.try_advance_output()
    }

    /// Returns the index of the runtime of the "output" best block, as an index within
    /// [`DownloadTree::runtimes`].
    ///
    /// # Panic
    ///
    /// Panics if [`DownloadTree::has_output`] isn't `true`.
    ///
    fn best_block_runtime_index(&self) -> usize {
        let best_block = if let Some(best_block_index) = self.best_block_index {
            self.non_finalized_blocks.get(best_block_index).unwrap()
        } else {
            &self.finalized_block
        };

        match best_block.runtime {
            Ok(RuntimeDownloadState::Finished(index)) => index,
            // It is guaranteed that the best block's runtime is always in the `Finished` state.
            _ => unreachable!(),
        }
    }

    /// Returns the index of the runtime of the "output" finalized block, as an index within
    /// [`DownloadTree::runtimes`].
    ///
    /// # Panic
    ///
    /// Panics if [`DownloadTree::has_output`] isn't `true`.
    ///
    fn finalized_block_runtime_index(&self) -> usize {
        match self.finalized_block.runtime {
            Ok(RuntimeDownloadState::Finished(index)) => index,
            // It is guaranteed that the finalized block's runtime is always in the `Finished`
            // state.
            _ => unreachable!(),
        }
    }

    /// Tries to update the output finalized and best blocks to follow the input.
    fn try_advance_output(&mut self) -> OutputUpdate {
        let output = self.try_advance_output_inner();

        // Sanity checks.
        debug_assert!(!output.best_block_runtime_changed || output.best_block_updated);
        debug_assert!(
            !matches!(
                self.finalized_block.runtime,
                Ok(RuntimeDownloadState::Finished(_))
            ) || self.best_block_index.map_or(true, |idx| matches!(
                self.non_finalized_blocks.get(idx).unwrap().runtime,
                Ok(RuntimeDownloadState::Finished(_))
            ))
        );
        debug_assert_eq!(
            self.runtimes
                .iter()
                .map(|(_, r)| r.num_blocks.get())
                .sum::<usize>(),
            iter::once(&self.finalized_block)
                .chain(self.non_finalized_blocks.iter_unordered().map(|(_, b)| b))
                .filter(|b| matches!(b.runtime, Ok(RuntimeDownloadState::Finished(_))))
                .count()
        );

        // Make sure that advancing the output has advanced to the best possible best/finalized.
        debug_assert!(self.try_advance_output_inner().is_noop());

        output
    }

    fn try_advance_output_inner(&mut self) -> OutputUpdate {
        let mut output = OutputUpdate {
            best_block_updated: false,
            best_block_runtime_changed: false,
            finalized_block_updated: false,
        };

        // Runtime index of the best block at the start. `None` if not available, meaning no
        // output yet.
        let best_block_runtime_index_start = {
            let best_block = if let Some(best_block_index) = self.best_block_index {
                self.non_finalized_blocks.get(best_block_index).unwrap()
            } else {
                &self.finalized_block
            };

            match best_block.runtime {
                Ok(RuntimeDownloadState::Finished(index)) => Some(index),
                _ => None,
            }
        };

        // Try to advance the output finalized block.
        // `input_finalized_index` is `Some` if the input finalized is not already equal to the
        // output finalized.
        if let Some(input_finalized_index) = self.input_finalized_index {
            // Finding a new finalized block.
            let new_finalized = {
                let mut new_finalized = self
                    .non_finalized_blocks
                    .node_to_root_path(input_finalized_index)
                    .find(|node_index| {
                        matches!(
                            self.non_finalized_blocks.get(*node_index).unwrap().runtime,
                            Ok(RuntimeDownloadState::Finished(_))
                        )
                    });

                // If there's no finalized block that is ready, jump to the lowest block that is
                // downloading.
                // If we can't find any block that is downloading, simply jump to the input
                // finalized block.
                if !self.has_output() && new_finalized.is_none() {
                    new_finalized = Some(
                        self.non_finalized_blocks
                            .root_to_node_path(input_finalized_index)
                            .find(|node_index| {
                                matches!(
                                    self.non_finalized_blocks.get(*node_index).unwrap().runtime,
                                    Ok(RuntimeDownloadState::Downloading { .. })
                                )
                            })
                            .unwrap_or(input_finalized_index),
                    );
                }

                new_finalized
            };

            if let Some(new_finalized) = new_finalized {
                output.finalized_block_updated = true;

                // Make sure that the output best block will still be in the tree after the
                // pruning below, or setting its to the new finalized block if not. Its actual
                // value is updated later down this function.
                // This is only done conditionally in order to avoid setting
                // `output.best_block_updated` to `true` if not necessary.
                if !self.best_block_index.map_or(false, |b| {
                    self.non_finalized_blocks.is_ancestor(new_finalized, b)
                        && self.best_block_index != Some(new_finalized)
                }) {
                    // If `best_block_index == new_finalized`, then the best block actually stays
                    // the same, but `self.best_block_index` still has to be updated because we
                    // prune `new_finalized` below.
                    if self.best_block_index != Some(new_finalized) {
                        output.best_block_updated = true;
                    }
                    self.best_block_index = None;
                }

                if self.input_finalized_index == Some(new_finalized) {
                    self.input_finalized_index = None;
                }

                for pruned in self.non_finalized_blocks.prune_ancestors(new_finalized) {
                    debug_assert_ne!(Some(pruned.index), self.input_finalized_index);
                    debug_assert!(self.best_block_index.map_or(true, |b| b != pruned.index));

                    // If this is the new finalized block, replace `self.finalized_block`.
                    let thrown_away_block = if pruned.index == new_finalized {
                        mem::replace(&mut self.finalized_block, pruned.user_data)
                    } else {
                        pruned.user_data
                    };

                    // Update `self.runtimes` to account for the block that was just removed.
                    // This block just removed can be either a non-finalized block, or the
                    // previously-finalized block.
                    if let Ok(RuntimeDownloadState::Finished(runtime_index)) =
                        thrown_away_block.runtime
                    {
                        match NonZeroUsize::new(self.runtimes[runtime_index].num_blocks.get() - 1) {
                            Some(nv) => self.runtimes[runtime_index].num_blocks = nv,
                            None => {
                                self.runtimes.remove(runtime_index);
                            }
                        }
                    }
                }
            }
        }

        // Try to advance the output best block to the `Finished` block with the highest weight.
        // This is done at the end in order to not accidentally pick a blocked that is pruned
        // when advancing finality.
        {
            // Weight of the current output best block.
            let mut current_runtime_service_best_block_weight = match self.best_block_index {
                None => self.finalized_block.input_best_block_weight,
                Some(idx) => {
                    self.non_finalized_blocks
                        .get(idx)
                        .unwrap()
                        .input_best_block_weight
                }
            };

            for (node_index, block) in self.non_finalized_blocks.iter_unordered() {
                // Check uniqueness of weights.
                debug_assert!(
                    block.input_best_block_weight != current_runtime_service_best_block_weight
                        || self.best_block_index == Some(node_index)
                );

                if block.input_best_block_weight <= current_runtime_service_best_block_weight {
                    continue;
                }

                if !matches!(block.runtime, Ok(RuntimeDownloadState::Finished(_))) {
                    continue;
                }

                // Runtime service best can be updated to the block being iterated.
                current_runtime_service_best_block_weight = block.input_best_block_weight;
                self.best_block_index = Some(node_index);
                output.best_block_updated = true;

                // Continue looping, as there might be another block with an even higher weight.
            }
        }

        // Now check if the runtime index of the best block has changed since the start.
        let best_block_runtime_index_end = {
            let best_block = if let Some(best_block_index) = self.best_block_index {
                self.non_finalized_blocks.get(best_block_index).unwrap()
            } else {
                &self.finalized_block
            };

            match best_block.runtime {
                Ok(RuntimeDownloadState::Finished(index)) => Some(index),
                _ => None,
            }
        };
        if best_block_runtime_index_end != best_block_runtime_index_start {
            output.best_block_runtime_changed = true;
        }

        // The best and finalized blocks might have changed, but for API purposes we don't report
        // any change before the first output.
        if !self.has_output() {
            output = OutputUpdate {
                best_block_updated: false,
                best_block_runtime_changed: false,
                finalized_block_updated: false,
            };
        }

        output
    }
}

/// Informs about whether the call to the method that returned this [`OutputUpdate`] resulted in
/// a change in the output best or finalized block.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[must_use]
pub struct OutputUpdate {
    /// If `true`, the call to the method that returned this [`OutputUpdate`] resulted in a change
    /// in the output finalized block of the [`DownloadTree`].
    pub finalized_block_updated: bool,
    /// If `true`, the change in new block has already resulted in a change in the version of the
    /// runtime.
    pub best_block_runtime_changed: bool,
    /// If `true`, the call to the method that returned this [`OutputUpdate`] resulted in a change
    /// in the output best block of the [`DownloadTree`].
    pub best_block_updated: bool,
}

impl OutputUpdate {
    fn is_noop(&self) -> bool {
        !self.finalized_block_updated && !self.best_block_updated
    }
}

pub struct ExtractedRuntime<TNow> {
    /// Equivalent to [`DownloadTree`] but with a runtime extracted.
    pub tree: ExtractedDownloadTree<TNow>,

    /// Runtime extracted from the [`DownloadTree`].
    pub runtime: executor::host::HostVmPrototype,
}

pub struct ExtractedDownloadTree<TNow> {
    inner: DownloadTree<TNow>,
    extracted_runtime_index: usize,
}

impl<TNow> ExtractedDownloadTree<TNow> {
    /// Puts back the runtime that was extracted.
    ///
    /// Note that no effort is made to ensure that the runtime being put back is the one that was
    /// extracted. It is a serious logic error to put back a different runtime.
    pub fn unlock(mut self, vm: executor::host::HostVmPrototype) -> DownloadTree<TNow> {
        let vm_slot = &mut self.inner.runtimes[self.extracted_runtime_index]
            .runtime
            .as_mut()
            .unwrap()
            .virtual_machine;
        debug_assert!(vm_slot.is_none());
        *vm_slot = Some(vm);
        self.inner
    }
}

struct Block<TNow> {
    /// Hash of the block in question. Redundant with `header`, but the hash is so often needed
    /// that it makes sense to cache it.
    hash: [u8; 32],

    /// Header of the block in question.
    /// Guaranteed to always be valid for the output best and finalized blocks. Otherwise,
    /// not guaranteed to be valid.
    header: Vec<u8>,

    /// Runtime information of that block. Shared amongst multiple different blocks.
    runtime: Result<RuntimeDownloadState<TNow>, BlockRuntimeErr>,

    /// A block with a higher value here has been reported by the input as the best block
    /// more recently than a block with a lower value. `0` means never reported as best block.
    input_best_block_weight: u32,
}

#[derive(Debug)]
enum BlockRuntimeErr {
    /// The header of the block isn't valid, and as such its runtime couldn't be downloaded.
    ///
    /// > **Note**: It is possible for parachains to include blocks with invalid headers, as
    /// >           nothing actually enforces that a parachain's blocks must conform to a certain
    /// >           format.
    InvalidHeader,
}

enum RuntimeDownloadState<TNow> {
    /// Index within [`DownloadTree::runtimes`] of this block's runtime.
    Finished(usize),

    /// Runtime is currently being downloaded. The future can be found in
    // [`Background::runtime_downloads`].
    Downloading {
        /// Identifier for this download in the public API.
        /// Attributed from [`Background::next_download_id`]. Multiple different blocks can point
        /// to the same `download_id` when it is known that they point to the same runtime.
        download_id: DownloadId,

        /// State trie root of the block. Necessary in case the download fails and gets restarted.
        // TODO: redundant with header
        state_root: [u8; 32],

        /// Do not start any download before `TNow`. Used to avoid repeatedly trying to download
        /// the same block over and over again when it's constantly failing.
        timeout: Option<TNow>,
    },

    /// Runtime hasn't started being downloaded from the network.
    Unknown {
        /// `true` if it is known that this runtime is the same as its parent's.
        /// If `true`, it is illegal for the parent to be in the state
        /// [`RuntimeDownloadState::Finished`] or [`RuntimeDownloadState::Downloading`].
        ///
        /// When in doubt, `false`.
        ///
        /// Value is irrelevant for the finalized block.
        same_as_parent: bool,

        /// State trie root of the block. Necessary in order to download the runtime.
        // TODO: redundant with header
        state_root: [u8; 32],

        /// Do not start any download before `TNow`. Used to avoid repeatedly trying to download
        /// the same block over and over again when it's constantly failing.
        timeout: Option<TNow>,
    },
}

struct Runtime {
    /// Number of blocks in [`DownloadTree`] that use this runtime (includes both finalized and
    /// non-finalized blocks).
    num_blocks: NonZeroUsize,

    /// Successfully-compiled runtime and all its information. Can contain an error if an error
    /// happened, including a problem when obtaining the runtime specs or the metadata. It is
    /// better to report to the user an error about for example the metadata not being extractable
    /// compared to returning an obsolete version.
    runtime: Result<SuccessfulRuntime, RuntimeError>,

    /// Undecoded storage value of `:code` corresponding to the [`Runtime::runtime`]
    /// field.
    ///
    /// Can be `None` if the storage is empty, in which case the runtime will have failed to
    /// build.
    // TODO: consider storing hash instead
    runtime_code: Option<Vec<u8>>,

    /// Undecoded storage value of `:heappages` corresponding to the
    /// [`Runtime::runtime`] field.
    ///
    /// Can be `None` if the storage is empty, in which case the runtime will have failed to
    /// build.
    // TODO: consider storing hash instead
    heap_pages: Option<Vec<u8>>,
}

struct SuccessfulRuntime {
    /// Cache of the metadata extracted from the runtime. `None` if unknown.
    ///
    /// This cache is filled lazily whenever it is requested through the public API.
    ///
    /// Note that building the metadata might require access to the storage, just like obtaining
    /// the runtime code. if the runtime code gets an update, we can reasonably assume that the
    /// network is able to serve us the storage of recent blocks, and thus the changes of being
    /// able to build the metadata are very high.
    ///
    /// If the runtime is the one found in the genesis storage, the metadata must have been been
    /// filled using the genesis storage as well. If we build the metadata of the genesis runtime
    /// lazily, chances are that the network wouldn't be able to serve the storage of blocks near
    /// the genesis.
    ///
    /// As documented in the smoldot metadata module, the metadata might access the storage, but
    /// we intentionally don't watch for changes in these storage keys to refresh the metadata.
    metadata: Option<Vec<u8>>,

    /// Runtime specs extracted from the runtime.
    runtime_spec: executor::CoreVersion,

    /// Virtual machine itself, to perform additional calls.
    ///
    /// Always `Some`, except for temporary extractions necessary to execute the VM.
    virtual_machine: Option<executor::host::HostVmPrototype>,
}

impl SuccessfulRuntime {
    fn from_params(
        code: &Option<Vec<u8>>,
        heap_pages: &Option<Vec<u8>>,
    ) -> Result<Self, RuntimeError> {
        let vm = match executor::host::HostVmPrototype::new(
            code.as_ref().ok_or(RuntimeError::CodeNotFound)?,
            executor::storage_heap_pages_to_value(heap_pages.as_deref())
                .map_err(RuntimeError::InvalidHeapPages)?,
            executor::vm::ExecHint::CompileAheadOfTime,
        ) {
            Ok(vm) => vm,
            Err(error) => {
                return Err(RuntimeError::Build(error));
            }
        };

        let (runtime_spec, vm) = match executor::core_version(vm) {
            (Ok(spec), vm) => (spec, vm),
            (Err(error), _) => {
                return Err(RuntimeError::CoreVersion(error));
            }
        };

        Ok(SuccessfulRuntime {
            metadata: None,
            runtime_spec,
            virtual_machine: Some(vm),
        })
    }
}
