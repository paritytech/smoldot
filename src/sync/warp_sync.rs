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

//! Warp syncing.
//!
//! # Overview
//!
//! The warp syncing algorithm works only if the chain uses Grandpa for its finality.
//! It consists in the following steps:
//!
//! - Downloading a warp sync proof from a source. This proof contains a list of *fragments*. Each
//! fragment represents a change in the list of Grandpa authorities, and a list of signatures of
//! the previous authorities that certify that this change is correct.
//! - Verifying the fragments. Each fragment that is successfully verified progresses towards
//! towards the head of the chain. Even if one fragment is invalid, all the previously-verified
//! fragments can still be kept, and the warp syncing can resume from there.
//! - Downloading from a source the runtime code of the final block of the proof.
//! - Performing some runtime calls in order to obtain the current consensus-related parameters
//! of the chain. This might require obtaining some storage items, in which case they must also
//! be downloaded from a source.
//!
//! At the end of the syncing, a [`ValidChainInformation`] corresponding to the head of the chain
//! is yielded.
//!
//! # Usage
//!
//! Use the [`warp_sync()`] function to start a Grandpa warp syncing state machine.
//!
//! At any given moment, this state machine holds a list of *sources* that it might use to
//! download the warp sync proof or the runtime code. Sources must be added and removed by the API
//! user by calling one of the various `add_source` and `remove_source` functions.
//!
//! Sources are identified through a [`SourceId`]. Each source has an opaque so-called "user data"
//! of type `TSrc` associated to it. The content of this "user data" is at the discretion of the
//! API user.
//!
//! The [`InProgressWarpSync`] enum must be examined in order to determine how to make the warp
//! syncing process.
//!
//! At the end of the process, a [`Success`] is returned and can be used to kick-off another
//! syncing phase.

use crate::{
    chain::chain_information::{
        self, babe_fetch_epoch, BabeEpochInformation, ChainInformation, ChainInformationConsensus,
        ChainInformationConsensusRef, ChainInformationFinality, ChainInformationFinalityRef,
        ValidChainInformation, ValidChainInformationRef,
    },
    executor::{
        self,
        host::{self, HostVmPrototype, NewErr},
        vm::ExecHint,
    },
    finality::grandpa::warp_sync,
    header::{self, Header, HeaderRef},
};

use alloc::vec::Vec;
use core::ops;

pub use warp_sync::{Error as FragmentError, WarpSyncFragment};

/// Problem encountered during a call to [`warp_sync()`].
#[derive(Debug, derive_more::Display)]
pub enum Error {
    #[display(fmt = "Missing :code")]
    MissingCode,
    #[display(fmt = "Invalid heap pages value: {}", _0)]
    InvalidHeapPages(executor::InvalidHeapPagesError),
    #[display(fmt = "Error during Babe epoch information: {}", _0)]
    BabeFetchEpoch(babe_fetch_epoch::Error),
    #[display(fmt = "Error initializing downloaded runtime: {}", _0)]
    NewRuntime(NewErr),
    /// Parameters produced by the runtime are incoherent.
    #[display(fmt = "Parameters produced by the runtime are incoherent: {}", _0)]
    InvalidChain(chain_information::ValidityError),
}

/// The configuration for [`warp_sync()`].
pub struct Config {
    /// The chain information of the starting point of the warp syncing.
    pub start_chain_information: ValidChainInformation,

    /// Number of bytes used when encoding/decoding the block number. Influences how various data
    /// structures should be parsed.
    pub block_number_bytes: usize,

    /// The initial capacity of the list of sources.
    pub sources_capacity: usize,
}

/// Initializes the warp sync state machine.
///
/// On error, returns the [`ValidChainInformation`] that was provided in the configuration.
pub fn warp_sync<TSrc>(
    config: Config,
) -> Result<InProgressWarpSync<TSrc>, (ValidChainInformation, WarpSyncInitError)> {
    match config.start_chain_information.as_ref().finality {
        ChainInformationFinalityRef::Grandpa { .. } => {}
        _ => {
            return Err((
                config.start_chain_information,
                WarpSyncInitError::NotGrandpa,
            ))
        }
    }

    Ok(InProgressWarpSync::WaitingForSources(WaitingForSources {
        state: PreVerificationState {
            start_chain_information: config.start_chain_information,
            block_number_bytes: config.block_number_bytes,
        },
        sources: slab::Slab::with_capacity(config.sources_capacity),
        previous_verifier_values: None,
    }))
}

/// Error potentially returned by [`warp_sync()`].
#[derive(Debug, derive_more::Display, Clone)]
pub enum WarpSyncInitError {
    /// Chain doesn't use the Grandpa finality algorithm.
    NotGrandpa,
}

/// Identifier for a source in the [`WarpSync`].
//
// Implementation note: this represents the index within the `Slab` used for the list of sources.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct SourceId(usize);

/// The result of a successful warp sync.
pub struct Success<TSrc> {
    /// The synced chain information.
    pub chain_information: ValidChainInformation,

    /// The runtime constructed in `VirtualMachineParamsGet`. Corresponds to the runtime of the
    /// finalized block of [`Success::chain_information`].
    pub finalized_runtime: HostVmPrototype,

    /// Storage value at the `:code` key of the finalized block.
    pub finalized_storage_code: Option<Vec<u8>>,

    /// Storage value at the `:heappages` key of the finalized block.
    pub finalized_storage_heap_pages: Option<Vec<u8>>,

    /// The list of sources that were added to the state machine.
    pub sources: Vec<TSrc>,
}

/// The warp sync state machine.
#[derive(derive_more::From)]
pub enum WarpSync<TSrc> {
    /// Warp syncing is over.
    Finished(Success<TSrc>),
    /// Warp syncing is in progress,
    InProgress(InProgressWarpSync<TSrc>),
}

#[derive(derive_more::From)]
pub enum InProgressWarpSync<TSrc> {
    /// Loading a storage value is required in order to continue.
    #[from]
    StorageGet(StorageGet<TSrc>),
    /// Fetching the key that follows a given one is required in order to continue.
    #[from]
    NextKey(NextKey<TSrc>),
    /// Verifying the warp sync response is required to continue.
    #[from]
    Verifier(Verifier<TSrc>),
    /// Requesting GrandPa warp sync data from a source is required to continue.
    #[from]
    WarpSyncRequest(GrandpaWarpSyncRequest<TSrc>),
    /// Fetching the parameters for the virtual machine is required to continue.
    #[from]
    VirtualMachineParamsGet(VirtualMachineParamsGet<TSrc>),
    /// Adding more sources of warp sync data to is required to continue.
    #[from]
    WaitingForSources(WaitingForSources<TSrc>),
}

impl<TSrc> WarpSync<TSrc> {
    fn from_babe_fetch_epoch_query(
        mut query: babe_fetch_epoch::Query,
        mut fetched_current_epoch: Option<BabeEpochInformation>,
        mut state: PostVerificationState<TSrc>,
        post_download: PostRuntimeDownloadState,
    ) -> (Self, Option<Error>) {
        loop {
            match (query, fetched_current_epoch) {
                (
                    babe_fetch_epoch::Query::Finished {
                        result: Ok(next_epoch),
                        virtual_machine,
                    },
                    Some(current_epoch),
                ) => {
                    // The number of slots per epoch is never modified once the chain is running,
                    // and as such is copied from the original chain information.
                    let slots_per_epoch = match state.start_chain_information.as_ref().consensus {
                        ChainInformationConsensusRef::Babe {
                            slots_per_epoch, ..
                        } => slots_per_epoch,
                        _ => unreachable!(),
                    };

                    // Build a `ChainInformation` using the parameters found in the runtime.
                    // It is possible, however, that the runtime produces parameters that aren't
                    // coherent. For example the runtime could give "current" and "next" Babe
                    // epochs that don't follow each other.
                    let chain_information =
                        match ValidChainInformation::try_from(ChainInformation {
                            finalized_block_header: state.header,
                            finality: state.chain_information_finality,
                            consensus: ChainInformationConsensus::Babe {
                                finalized_block_epoch_information: Some(current_epoch),
                                finalized_next_epoch_transition: next_epoch,
                                slots_per_epoch,
                            },
                        }) {
                            Ok(ci) => ci,
                            Err(err) => {
                                return (
                                    Self::InProgress(
                                        InProgressWarpSync::warp_sync_request_from_next_source(
                                            state.sources,
                                            PreVerificationState {
                                                start_chain_information: state
                                                    .start_chain_information,
                                                block_number_bytes: state.block_number_bytes,
                                            },
                                            None,
                                        ),
                                    ),
                                    Some(Error::InvalidChain(err)),
                                )
                            }
                        };

                    return (
                        Self::Finished(Success {
                            chain_information,
                            finalized_runtime: virtual_machine,
                            finalized_storage_code: post_download.finalized_storage_code,
                            finalized_storage_heap_pages: post_download
                                .finalized_storage_heap_pages,
                            sources: state
                                .sources
                                .drain()
                                .map(|source| source.user_data)
                                .collect(),
                        }),
                        None,
                    );
                }
                (
                    babe_fetch_epoch::Query::Finished {
                        result: Ok(current_epoch),
                        virtual_machine,
                    },
                    None,
                ) => {
                    fetched_current_epoch = Some(current_epoch);
                    query = babe_fetch_epoch::babe_fetch_epoch(babe_fetch_epoch::Config {
                        runtime: virtual_machine,
                        epoch_to_fetch: babe_fetch_epoch::BabeEpochToFetch::NextEpoch,
                    });
                }
                (
                    babe_fetch_epoch::Query::Finished {
                        result: Err(error),
                        virtual_machine: _,
                    },
                    _,
                ) => {
                    return (
                        Self::InProgress(InProgressWarpSync::warp_sync_request_from_next_source(
                            state.sources,
                            PreVerificationState {
                                start_chain_information: state.start_chain_information,
                                block_number_bytes: state.block_number_bytes,
                            },
                            None,
                        )),
                        Some(Error::BabeFetchEpoch(error)),
                    )
                }
                (babe_fetch_epoch::Query::StorageGet(storage_get), fetched_current_epoch) => {
                    return (
                        Self::InProgress(InProgressWarpSync::StorageGet(StorageGet {
                            inner: storage_get,
                            fetched_current_epoch,
                            state,
                            post_download,
                        })),
                        None,
                    )
                }
                (babe_fetch_epoch::Query::StorageRoot(storage_root), e) => {
                    fetched_current_epoch = e;
                    query = storage_root.resume(&state.header.state_root);
                }
                (babe_fetch_epoch::Query::NextKey(next_key), fetched_current_epoch) => {
                    return (
                        Self::InProgress(InProgressWarpSync::NextKey(NextKey {
                            inner: next_key,
                            fetched_current_epoch,
                            state,
                            post_download,
                        })),
                        None,
                    )
                }
            }
        }
    }
}

impl<TSrc> InProgressWarpSync<TSrc> {
    /// Returns the chain information that is considered verified.
    pub fn as_chain_information(&self) -> ValidChainInformationRef {
        match self {
            Self::StorageGet(storage_get) => &storage_get.state.start_chain_information,
            Self::NextKey(next_key) => &next_key.state.start_chain_information,
            Self::Verifier(verifier) => &verifier.state.start_chain_information,
            Self::WarpSyncRequest(warp_sync_request) => {
                &warp_sync_request.state.start_chain_information
            }
            Self::VirtualMachineParamsGet(virtual_machine_params_get) => {
                &virtual_machine_params_get.state.start_chain_information
            }
            Self::WaitingForSources(waiting_for_sources) => {
                &waiting_for_sources.state.start_chain_information
            }
        }
        .into()
    }

    /// Returns a list of all known sources stored in the state machine.
    pub fn sources(&'_ self) -> impl Iterator<Item = SourceId> + '_ {
        let sources = match self {
            Self::StorageGet(storage_get) => &storage_get.state.sources,
            Self::NextKey(next_key) => &next_key.state.sources,
            Self::Verifier(verifier) => &verifier.sources,
            Self::WarpSyncRequest(warp_sync_request) => &warp_sync_request.sources,
            Self::VirtualMachineParamsGet(virtual_machine_params_get) => {
                &virtual_machine_params_get.state.sources
            }
            Self::WaitingForSources(waiting_for_sources) => &waiting_for_sources.sources,
        };

        sources.iter().map(|(id, _)| SourceId(id))
    }

    fn warp_sync_request_from_next_source(
        mut sources: slab::Slab<Source<TSrc>>,
        state: PreVerificationState,
        previous_verifier_values: Option<(Header, ChainInformationFinality)>,
    ) -> Self {
        // It is possible for a source to be banned because of, say, networking errors.
        // If all sources are "banned", unban them in order to try make progress again with the
        // hopes that this time it will work.
        if sources.iter().all(|(_, s)| s.already_tried) {
            for (_, s) in &mut sources {
                s.already_tried = false;
            }
        }

        let next_id = sources
            .iter()
            .find(|(_, s)| !s.already_tried)
            .map(|(id, _)| SourceId(id));

        if let Some(next_id) = next_id {
            Self::WarpSyncRequest(GrandpaWarpSyncRequest {
                source_id: next_id,
                sources,
                state,
                previous_verifier_values,
            })
        } else {
            debug_assert!(sources.is_empty());
            Self::WaitingForSources(WaitingForSources {
                sources,
                state,
                previous_verifier_values,
            })
        }
    }

    /// Remove a source from the list of sources.
    ///
    /// # Panic
    ///
    /// Panics if the source wasn't added to the list earlier.
    ///
    pub fn remove_source(self, to_remove: SourceId) -> (TSrc, InProgressWarpSync<TSrc>) {
        match self {
            Self::WaitingForSources(waiting_for_sources) => {
                waiting_for_sources.remove_source(to_remove)
            }
            Self::WarpSyncRequest(warp_sync_request) => warp_sync_request.remove_source(to_remove),
            Self::Verifier(verifier) => verifier.remove_source(to_remove),
            Self::VirtualMachineParamsGet(mut virtual_machine_params_get) => {
                let (removed, result) = virtual_machine_params_get.state.remove_source(to_remove);
                match result {
                    StateRemoveSourceResult::RemovedOther(state) => {
                        virtual_machine_params_get.state = state;
                        (
                            removed,
                            Self::VirtualMachineParamsGet(virtual_machine_params_get),
                        )
                    }
                    StateRemoveSourceResult::RemovedCurrent(warp_sync) => (removed, warp_sync),
                }
            }
            Self::StorageGet(mut storage_get) => {
                let (removed, result) = storage_get.state.remove_source(to_remove);
                match result {
                    StateRemoveSourceResult::RemovedOther(state) => {
                        storage_get.state = state;
                        (removed, Self::StorageGet(storage_get))
                    }
                    StateRemoveSourceResult::RemovedCurrent(warp_sync) => (removed, warp_sync),
                }
            }
            Self::NextKey(mut next_key) => {
                let (removed, result) = next_key.state.remove_source(to_remove);
                match result {
                    StateRemoveSourceResult::RemovedOther(state) => {
                        next_key.state = state;
                        (removed, Self::NextKey(next_key))
                    }
                    StateRemoveSourceResult::RemovedCurrent(warp_sync) => (removed, warp_sync),
                }
            }
        }
    }
}

impl<TSrc> ops::Index<SourceId> for InProgressWarpSync<TSrc> {
    type Output = TSrc;

    #[track_caller]
    fn index(&self, source_id: SourceId) -> &TSrc {
        let sources = match self {
            Self::StorageGet(storage_get) => &storage_get.state.sources,
            Self::NextKey(next_key) => &next_key.state.sources,
            Self::Verifier(verifier) => &verifier.sources,
            Self::WarpSyncRequest(warp_sync_request) => &warp_sync_request.sources,
            Self::VirtualMachineParamsGet(virtual_machine_params_get) => {
                &virtual_machine_params_get.state.sources
            }
            Self::WaitingForSources(waiting_for_sources) => &waiting_for_sources.sources,
        };

        debug_assert!(sources.contains(source_id.0));
        &sources[source_id.0].user_data
    }
}

impl<TSrc> ops::IndexMut<SourceId> for InProgressWarpSync<TSrc> {
    #[track_caller]
    fn index_mut(&mut self, source_id: SourceId) -> &mut TSrc {
        let sources = match self {
            Self::StorageGet(storage_get) => &mut storage_get.state.sources,
            Self::NextKey(next_key) => &mut next_key.state.sources,
            Self::Verifier(verifier) => &mut verifier.sources,
            Self::WarpSyncRequest(warp_sync_request) => &mut warp_sync_request.sources,
            Self::VirtualMachineParamsGet(virtual_machine_params_get) => {
                &mut virtual_machine_params_get.state.sources
            }
            Self::WaitingForSources(waiting_for_sources) => &mut waiting_for_sources.sources,
        };

        debug_assert!(sources.contains(source_id.0));
        &mut sources[source_id.0].user_data
    }
}

/// Loading a storage value is required in order to continue.
#[must_use]
pub struct StorageGet<TSrc> {
    inner: babe_fetch_epoch::StorageGet,
    fetched_current_epoch: Option<BabeEpochInformation>,
    state: PostVerificationState<TSrc>,
    post_download: PostRuntimeDownloadState,
}

impl<TSrc> StorageGet<TSrc> {
    /// Returns the key whose value must be passed to [`StorageGet::inject_value`].
    pub fn key(&'_ self) -> impl Iterator<Item = impl AsRef<[u8]> + '_> + '_ {
        self.inner.key()
    }

    /// Returns the source that we received the warp sync data from.
    pub fn warp_sync_source(&self) -> (SourceId, &TSrc) {
        debug_assert!(self
            .state
            .sources
            .contains(self.state.warp_sync_source_id.0));

        (
            self.state.warp_sync_source_id,
            &self.state.sources[self.state.warp_sync_source_id.0].user_data,
        )
    }

    /// Returns the header that we're warp syncing up to.
    pub fn warp_sync_header(&self) -> HeaderRef {
        (&self.state.header).into()
    }

    /// Add a source to the list of sources.
    pub fn add_source(&mut self, user_data: TSrc) -> SourceId {
        SourceId(self.state.sources.insert(Source {
            user_data,
            already_tried: false,
        }))
    }

    /// Returns the key whose value must be passed to [`StorageGet::inject_value`].
    ///
    /// This method is a shortcut for calling `key` and concatenating the returned slices.
    pub fn key_as_vec(&self) -> Vec<u8> {
        self.inner.key_as_vec()
    }

    /// Injects the corresponding storage value.
    pub fn inject_value(
        self,
        value: Option<impl Iterator<Item = impl AsRef<[u8]>>>,
    ) -> (WarpSync<TSrc>, Option<Error>) {
        WarpSync::from_babe_fetch_epoch_query(
            self.inner.inject_value(value),
            self.fetched_current_epoch,
            self.state,
            self.post_download,
        )
    }

    /// Injects a failure to retrieve the storage value.
    pub fn inject_error(self) -> InProgressWarpSync<TSrc> {
        InProgressWarpSync::warp_sync_request_from_next_source(
            self.state.sources,
            PreVerificationState {
                start_chain_information: self.state.start_chain_information,
                block_number_bytes: self.state.block_number_bytes,
            },
            None,
        )
    }
}

/// Fetching the key that follows a given one is required in order to continue.
#[must_use]
pub struct NextKey<TSrc> {
    inner: babe_fetch_epoch::NextKey,
    fetched_current_epoch: Option<BabeEpochInformation>,
    state: PostVerificationState<TSrc>,
    post_download: PostRuntimeDownloadState,
}

impl<TSrc> NextKey<TSrc> {
    /// Returns the key whose next key must be passed back.
    pub fn key(&'_ self) -> impl AsRef<[u8]> + '_ {
        self.inner.key()
    }

    /// Returns the source that we received the warp sync data from.
    pub fn warp_sync_source(&self) -> (SourceId, &TSrc) {
        debug_assert!(self
            .state
            .sources
            .contains(self.state.warp_sync_source_id.0));
        (
            self.state.warp_sync_source_id,
            &self.state.sources[self.state.warp_sync_source_id.0].user_data,
        )
    }

    /// Returns the header that we're warp syncing up to.
    pub fn warp_sync_header(&self) -> HeaderRef {
        (&self.state.header).into()
    }

    /// Add a source to the list of sources.
    pub fn add_source(&mut self, user_data: TSrc) -> SourceId {
        SourceId(self.state.sources.insert(Source {
            user_data,
            already_tried: false,
        }))
    }

    /// Injects the key.
    ///
    /// # Panic
    ///
    /// Panics if the key passed as parameter isn't strictly superior to the requested key.
    ///
    pub fn inject_key(self, key: Option<impl AsRef<[u8]>>) -> (WarpSync<TSrc>, Option<Error>) {
        WarpSync::from_babe_fetch_epoch_query(
            self.inner.inject_key(key),
            self.fetched_current_epoch,
            self.state,
            self.post_download,
        )
    }
}

/// Verifying the warp sync response is required to continue.
pub struct Verifier<TSrc> {
    verifier: warp_sync::Verifier,
    state: PreVerificationState,
    warp_sync_source_id: SourceId,
    sources: slab::Slab<Source<TSrc>>,
    final_set_of_fragments: bool,
    previous_verifier_values: Option<(Header, ChainInformationFinality)>,
}

impl<TSrc> Verifier<TSrc> {
    /// Add a source to the list of sources.
    pub fn add_source(&mut self, user_data: TSrc) -> SourceId {
        SourceId(self.sources.insert(Source {
            user_data,
            already_tried: false,
        }))
    }

    /// Remove a source from the list of sources.
    ///
    /// # Panic
    ///
    /// Panics if the source wasn't added to the list earlier.
    ///
    pub fn remove_source(mut self, to_remove: SourceId) -> (TSrc, InProgressWarpSync<TSrc>) {
        debug_assert!(self.sources.contains(to_remove.0));
        let removed = self.sources.remove(to_remove.0).user_data;

        if to_remove == self.warp_sync_source_id {
            let next_state = InProgressWarpSync::warp_sync_request_from_next_source(
                self.sources,
                self.state,
                self.previous_verifier_values,
            );

            (removed, next_state)
        } else {
            (removed, InProgressWarpSync::Verifier(self))
        }
    }

    /// Returns the identifier and user data of the source that has sent the fragment that is to
    /// be verified.
    pub fn proof_sender(&self) -> (SourceId, &TSrc) {
        (
            self.warp_sync_source_id,
            &self.sources[self.warp_sync_source_id.0].user_data,
        )
    }

    /// Verifies the next warp sync fragment in queue.
    pub fn next(self) -> (InProgressWarpSync<TSrc>, Result<(), FragmentError>) {
        match self.verifier.next() {
            Ok(warp_sync::Next::NotFinished(next_verifier)) => (
                InProgressWarpSync::Verifier(Self {
                    verifier: next_verifier,
                    state: self.state,
                    sources: self.sources,
                    warp_sync_source_id: self.warp_sync_source_id,
                    final_set_of_fragments: self.final_set_of_fragments,
                    previous_verifier_values: self.previous_verifier_values,
                }),
                Ok(()),
            ),
            Ok(warp_sync::Next::EmptyProof) => (
                // TODO: should return success immediately; unfortunately the AllSync is quite complicated to update if we do this
                InProgressWarpSync::VirtualMachineParamsGet(VirtualMachineParamsGet {
                    state: PostVerificationState {
                        header: self
                            .state
                            .start_chain_information
                            .as_ref()
                            .finalized_block_header
                            .into(),
                        chain_information_finality: self
                            .state
                            .start_chain_information
                            .as_ref()
                            .finality
                            .into(),
                        block_number_bytes: self.state.block_number_bytes,
                        start_chain_information: self.state.start_chain_information,
                        sources: self.sources,
                        warp_sync_source_id: self.warp_sync_source_id,
                    },
                }),
                Ok(()),
            ),
            Ok(warp_sync::Next::Success {
                scale_encoded_header,
                chain_information_finality,
            }) => {
                // As the verification of the fragment has succeeded, we are sure that the header
                // is valid and can decode it.
                let header: Header = header::decode(&scale_encoded_header).unwrap().into();

                if self.final_set_of_fragments {
                    (
                        InProgressWarpSync::VirtualMachineParamsGet(VirtualMachineParamsGet {
                            state: PostVerificationState {
                                header,
                                chain_information_finality,
                                start_chain_information: self.state.start_chain_information,
                                block_number_bytes: self.state.block_number_bytes,
                                sources: self.sources,
                                warp_sync_source_id: self.warp_sync_source_id,
                            },
                        }),
                        Ok(()),
                    )
                } else {
                    (
                        InProgressWarpSync::WarpSyncRequest(GrandpaWarpSyncRequest {
                            source_id: self.warp_sync_source_id,
                            sources: self.sources,
                            state: self.state,
                            previous_verifier_values: Some((header, chain_information_finality)),
                        }),
                        Ok(()),
                    )
                }
            }
            Err(error) => (
                InProgressWarpSync::warp_sync_request_from_next_source(
                    self.sources,
                    self.state,
                    self.previous_verifier_values,
                ),
                Err(error),
            ),
        }
    }
}

struct PreVerificationState {
    start_chain_information: ValidChainInformation,
    block_number_bytes: usize,
}

struct PostVerificationState<TSrc> {
    header: Header,
    chain_information_finality: ChainInformationFinality,
    start_chain_information: ValidChainInformation,
    block_number_bytes: usize,
    sources: slab::Slab<Source<TSrc>>,
    warp_sync_source_id: SourceId,
}

impl<TSrc> PostVerificationState<TSrc> {
    fn remove_source(mut self, to_remove: SourceId) -> (TSrc, StateRemoveSourceResult<TSrc>) {
        debug_assert!(self.sources.contains(to_remove.0));
        let removed = self.sources.remove(to_remove.0).user_data;

        if to_remove == self.warp_sync_source_id {
            (
                removed,
                StateRemoveSourceResult::RemovedCurrent(
                    InProgressWarpSync::warp_sync_request_from_next_source(
                        self.sources,
                        PreVerificationState {
                            start_chain_information: self.start_chain_information,
                            block_number_bytes: self.block_number_bytes,
                        },
                        None,
                    ),
                ),
            )
        } else {
            (removed, StateRemoveSourceResult::RemovedOther(self))
        }
    }
}

enum StateRemoveSourceResult<TSrc> {
    RemovedCurrent(InProgressWarpSync<TSrc>),
    RemovedOther(PostVerificationState<TSrc>),
}

struct PostRuntimeDownloadState {
    finalized_storage_code: Option<Vec<u8>>,
    finalized_storage_heap_pages: Option<Vec<u8>>,
}

/// Requesting GrandPa warp sync data from a source is required to continue.
pub struct GrandpaWarpSyncRequest<TSrc> {
    source_id: SourceId,
    sources: slab::Slab<Source<TSrc>>,
    state: PreVerificationState,
    previous_verifier_values: Option<(Header, ChainInformationFinality)>,
}

impl<TSrc> GrandpaWarpSyncRequest<TSrc> {
    /// The source to make a GrandPa warp sync request to.
    pub fn current_source(&self) -> (SourceId, &TSrc) {
        debug_assert!(self.sources.contains(self.source_id.0));
        (self.source_id, &self.sources[self.source_id.0].user_data)
    }

    /// The hash of the header to warp sync from.
    pub fn start_block_hash(&self) -> [u8; 32] {
        match self.previous_verifier_values.as_ref() {
            Some((header, _)) => header.hash(),
            None => self
                .state
                .start_chain_information
                .as_ref()
                .finalized_block_header
                .hash(),
        }
    }

    /// Add a source to the list of sources.
    pub fn add_source(&mut self, user_data: TSrc) -> SourceId {
        SourceId(self.sources.insert(Source {
            user_data,
            already_tried: false,
        }))
    }

    /// Remove a source from the list of sources.
    ///
    /// # Panic
    ///
    /// Panics if the source wasn't added to the list earlier.
    ///
    pub fn remove_source(mut self, to_remove: SourceId) -> (TSrc, InProgressWarpSync<TSrc>) {
        debug_assert!(self.sources.contains(to_remove.0));
        let removed = self.sources.remove(to_remove.0).user_data;

        if to_remove == self.source_id {
            let next_state = InProgressWarpSync::warp_sync_request_from_next_source(
                self.sources,
                self.state,
                self.previous_verifier_values,
            );

            (removed, next_state)
        } else {
            (removed, InProgressWarpSync::WarpSyncRequest(self))
        }
    }

    /// Submit a GrandPa warp sync successful response.
    pub fn handle_response_ok(
        mut self,
        fragments: Vec<WarpSyncFragment>,
        final_set_of_fragments: bool,
    ) -> InProgressWarpSync<TSrc> {
        debug_assert!(self.sources.contains(self.source_id.0));
        self.sources[self.source_id.0].already_tried = true;

        let verifier = match &self.previous_verifier_values {
            Some((_, chain_information_finality)) => warp_sync::Verifier::new(
                chain_information_finality.into(),
                self.state.block_number_bytes,
                fragments,
                final_set_of_fragments,
            ),
            None => warp_sync::Verifier::new(
                self.state.start_chain_information.as_ref().finality,
                self.state.block_number_bytes,
                fragments,
                final_set_of_fragments,
            ),
        };

        InProgressWarpSync::Verifier(Verifier {
            final_set_of_fragments,
            verifier,
            state: self.state,
            sources: self.sources,
            warp_sync_source_id: self.source_id,
            previous_verifier_values: self.previous_verifier_values,
        })
    }

    /// Submit a GrandPa warp sync request failure.
    pub fn handle_response_err(mut self) -> InProgressWarpSync<TSrc> {
        debug_assert!(self.sources.contains(self.source_id.0));
        self.sources[self.source_id.0].already_tried = true;

        InProgressWarpSync::warp_sync_request_from_next_source(
            self.sources,
            self.state,
            self.previous_verifier_values,
        )
    }
}

/// Fetching the parameters for the virtual machine is required to continue.
pub struct VirtualMachineParamsGet<TSrc> {
    state: PostVerificationState<TSrc>,
}

impl<TSrc> VirtualMachineParamsGet<TSrc> {
    /// Returns the source that we received the warp sync data from.
    pub fn warp_sync_source(&self) -> (SourceId, &TSrc) {
        debug_assert!(self
            .state
            .sources
            .contains(self.state.warp_sync_source_id.0));

        (
            self.state.warp_sync_source_id,
            &self.state.sources[self.state.warp_sync_source_id.0].user_data,
        )
    }

    /// Returns the header that we're warp syncing up to.
    pub fn warp_sync_header(&self) -> HeaderRef {
        (&self.state.header).into()
    }

    /// Add a source to the list of sources.
    pub fn add_source(&mut self, user_data: TSrc) -> SourceId {
        SourceId(self.state.sources.insert(Source {
            user_data,
            already_tried: false,
        }))
    }

    /// Injects a failure to retrieve the parameters.
    pub fn inject_error(self) -> InProgressWarpSync<TSrc> {
        InProgressWarpSync::warp_sync_request_from_next_source(
            self.state.sources,
            PreVerificationState {
                start_chain_information: self.state.start_chain_information,
                block_number_bytes: self.state.block_number_bytes,
            },
            None,
        )
    }

    /// Set the code and heap pages from storage using the keys `:code` and `:heappages`
    /// respectively. Also allows setting an execution hint for the virtual machine.
    pub fn set_virtual_machine_params(
        self,
        code: Option<impl AsRef<[u8]>>,
        heap_pages: Option<impl AsRef<[u8]>>,
        exec_hint: ExecHint,
        allow_unresolved_imports: bool,
    ) -> (WarpSync<TSrc>, Option<Error>) {
        let code = match code {
            Some(code) => code.as_ref().to_vec(),
            None => {
                return (
                    WarpSync::InProgress(InProgressWarpSync::warp_sync_request_from_next_source(
                        self.state.sources,
                        PreVerificationState {
                            start_chain_information: self.state.start_chain_information,
                            block_number_bytes: self.state.block_number_bytes,
                        },
                        None,
                    )),
                    Some(Error::MissingCode),
                )
            }
        };

        let decoded_heap_pages =
            match executor::storage_heap_pages_to_value(heap_pages.as_ref().map(|p| p.as_ref())) {
                Ok(hp) => hp,
                Err(err) => {
                    return (
                        WarpSync::InProgress(
                            InProgressWarpSync::warp_sync_request_from_next_source(
                                self.state.sources,
                                PreVerificationState {
                                    start_chain_information: self.state.start_chain_information,
                                    block_number_bytes: self.state.block_number_bytes,
                                },
                                None,
                            ),
                        ),
                        Some(Error::InvalidHeapPages(err)),
                    )
                }
            };

        let runtime = match HostVmPrototype::new(host::Config {
            module: &code,
            heap_pages: decoded_heap_pages,
            exec_hint,
            allow_unresolved_imports,
        }) {
            Ok(runtime) => runtime,
            Err(error) => {
                return (
                    WarpSync::InProgress(InProgressWarpSync::warp_sync_request_from_next_source(
                        self.state.sources,
                        PreVerificationState {
                            start_chain_information: self.state.start_chain_information,
                            block_number_bytes: self.state.block_number_bytes,
                        },
                        None,
                    )),
                    Some(Error::NewRuntime(error)),
                )
            }
        };

        let babe_current_epoch_query =
            babe_fetch_epoch::babe_fetch_epoch(babe_fetch_epoch::Config {
                runtime,
                epoch_to_fetch: babe_fetch_epoch::BabeEpochToFetch::CurrentEpoch,
            });

        let (warp_sync, error) = WarpSync::from_babe_fetch_epoch_query(
            babe_current_epoch_query,
            None,
            self.state,
            PostRuntimeDownloadState {
                finalized_storage_code: Some(code),
                finalized_storage_heap_pages: heap_pages.map(|hp| hp.as_ref().to_vec()),
            },
        );

        (warp_sync, error)
    }
}

/// Adding more sources of warp sync data to is required to continue.
pub struct WaitingForSources<TSrc> {
    /// List of sources. It is guaranteed that they all have `already_tried` equal to `true`.
    sources: slab::Slab<Source<TSrc>>,
    state: PreVerificationState,
    previous_verifier_values: Option<(Header, ChainInformationFinality)>,
}

impl<TSrc> WaitingForSources<TSrc> {
    /// Add a source to the list of sources.
    pub fn add_source(mut self, user_data: TSrc) -> GrandpaWarpSyncRequest<TSrc> {
        let source_id = SourceId(self.sources.insert(Source {
            user_data,
            already_tried: false,
        }));

        GrandpaWarpSyncRequest {
            source_id,
            sources: self.sources,
            state: self.state,
            previous_verifier_values: self.previous_verifier_values,
        }
    }

    /// Remove a source from the list of sources.
    ///
    /// # Panic
    ///
    /// Panics if the source wasn't added to the list earlier.
    ///
    pub fn remove_source(mut self, to_remove: SourceId) -> (TSrc, InProgressWarpSync<TSrc>) {
        debug_assert!(self.sources.contains(to_remove.0));
        let removed = self.sources.remove(to_remove.0).user_data;
        (removed, InProgressWarpSync::WaitingForSources(self))
    }
}

#[derive(Debug, Copy, Clone)]
struct Source<TSrc> {
    user_data: TSrc,
    /// `true` if this source has been in a past `WarpSyncRequest`. `false` if the source is
    /// currently in a `WarpSyncRequest`.
    already_tried: bool,
}
