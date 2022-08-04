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
    trie::proof_verify,
};

use alloc::{string::String, vec::Vec};
use core::{iter, ops};

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
    /// Chain uses an unrecognized consensus mechanism.
    UnknownConsensus,
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

    Ok(InProgressWarpSync {
        start_chain_information: config.start_chain_information,
        block_number_bytes: config.block_number_bytes,
        sources: slab::Slab::with_capacity(config.sources_capacity),
        in_progress_requests: slab::Slab::with_capacity(config.sources_capacity), // TODO: requests_capacity?
        phase: Phase::PreVerification {
            previous_verifier_values: None,
        },
    })
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

    /// The list of requests that were added to the state machine.
    pub in_progress_requests: Vec<(SourceId, RequestId, RequestDetail)>,
}

/// The warp sync state machine.
#[derive(derive_more::From)]
pub enum WarpSync<TSrc> {
    /// Warp syncing is over.
    Finished(Success<TSrc>),
    /// Warp syncing is in progress,
    InProgress(InProgressWarpSync<TSrc>),
}

impl<TSrc> ops::Index<SourceId> for InProgressWarpSync<TSrc> {
    type Output = TSrc;

    #[track_caller]
    fn index(&self, source_id: SourceId) -> &TSrc {
        debug_assert!(self.sources.contains(source_id.0));
        &self.sources[source_id.0].user_data
    }
}

impl<TSrc> ops::IndexMut<SourceId> for InProgressWarpSync<TSrc> {
    #[track_caller]
    fn index_mut(&mut self, source_id: SourceId) -> &mut TSrc {
        debug_assert!(self.sources.contains(source_id.0));
        &mut self.sources[source_id.0].user_data
    }
}

/// Warp syncing process now obtaining the chain information.
pub struct InProgressWarpSync<TSrc> {
    phase: Phase,
    start_chain_information: ValidChainInformation,
    block_number_bytes: usize,
    sources: slab::Slab<Source<TSrc>>,
    in_progress_requests: slab::Slab<(SourceId, RequestDetail)>,
}

enum Phase {
    PreVerification {
        previous_verifier_values: Option<(Header, ChainInformationFinality)>,
    },
    PostVerification {
        header: Header,
        chain_information_finality: ChainInformationFinality,
        warp_sync_source_id: SourceId,
        // TODO: use struct instead
        runtime: Option<(HostVmPrototype, Option<Vec<u8>>, Option<Vec<u8>>)>,
        babeapi_current_epoch_response: Option<Vec<Vec<u8>>>,
        babeapi_next_epoch_response: Option<Vec<Vec<u8>>>,
    },
}

impl<TSrc> InProgressWarpSync<TSrc> {
    /// Returns the value that was initially passed in [`Config::block_number_bytes`].
    pub fn block_number_bytes(&self) -> usize {
        self.block_number_bytes
    }

    /// Returns the chain information that is considered verified.
    pub fn as_chain_information(&self) -> ValidChainInformationRef {
        // TODO: not correct
        (&self.start_chain_information).into()
    }

    /// Returns a list of all known sources stored in the state machine.
    pub fn sources(&'_ self) -> impl Iterator<Item = SourceId> + '_ {
        self.sources.iter().map(|(id, _)| SourceId(id))
    }

    /// Add a source to the list of sources.
    pub fn add_source(&mut self, user_data: TSrc) -> SourceId {
        SourceId(self.sources.insert(Source {
            user_data,
            already_tried: false,
        }))
    }

    pub fn remove_source(mut self, to_remove: SourceId) -> (TSrc, InProgressWarpSync<TSrc>) {
        debug_assert!(self.sources.contains(to_remove.0));
        let removed = self.sources.remove(to_remove.0).user_data;

        if let Phase::PostVerification {
            warp_sync_source_id,
            ..
        } = &self.phase
        {
            if to_remove == *warp_sync_source_id {
                (
                    removed,
                    todo!(), // TODO:
                )
            } else {
                (removed, self)
            }
        } else {
            (removed, self)
        }
    }

    pub fn desired_requests(
        &'_ self,
    ) -> impl Iterator<Item = (SourceId, &'_ TSrc, DesiredRequest)> + '_ {
        let warp_sync_request = if let Phase::PreVerification {
            previous_verifier_values,
        } = &self.phase
        {
            let start_block_hash = match previous_verifier_values.as_ref() {
                Some((header, _)) => header.hash(self.block_number_bytes),
                None => self
                    .start_chain_information
                    .as_ref()
                    .finalized_block_header
                    .hash(self.block_number_bytes),
            };

            if !self
                .in_progress_requests
                .iter()
                .any(|(_, (_, rq))| match rq {
                    RequestDetail::WarpSyncRequest { block_hash }
                        if *block_hash == start_block_hash =>
                    {
                        true
                    }
                    _ => false,
                })
            {
                either::Left(self.sources.iter().filter_map(move |(src_id, src)| {
                    // TODO: also filter by source finalized block? so that we don't request from sources below us
                    if !src.already_tried {
                        Some((
                            SourceId(src_id),
                            &src.user_data,
                            DesiredRequest::WarpSyncRequest {
                                block_hash: start_block_hash,
                            },
                        ))
                    } else {
                        None
                    }
                }))
            } else {
                either::Right(iter::empty())
            }
        } else {
            either::Right(iter::empty())
        };

        let runtime_parameters_get = if let Phase::PostVerification {
            header,
            chain_information_finality,
            warp_sync_source_id,
            runtime,
            babeapi_current_epoch_response,
            babeapi_next_epoch_response,
        } = &self.phase
        {
            if !self.in_progress_requests.iter().any(|(_, rq)| {
            rq.0 == *warp_sync_source_id && matches!(rq.1, RequestDetail::RuntimeParametersGet { block_hash: b } if b == header.hash(self.block_number_bytes))
        }) {
            Some((
                *warp_sync_source_id,
                &self.sources[warp_sync_source_id.0].user_data,
                DesiredRequest::RuntimeParametersGet {
                    block_hash: header.hash(self.block_number_bytes),
                    state_trie_root: header.state_root,
                },
            ))
        } else {
            None
        }
        } else {
            None
        };

        let babe_current_epoch = if let Phase::PostVerification {
            header,
            chain_information_finality,
            warp_sync_source_id,
            runtime,
            babeapi_current_epoch_response,
            babeapi_next_epoch_response,
        } = &self.phase
        {
            if babeapi_current_epoch_response.is_none() && !self.in_progress_requests.iter().any(|(_, rq)| {
            rq.0 == *warp_sync_source_id && matches!(rq.1, RequestDetail::RuntimeCallMerkleProof { block_hash: b, function_name: ref f,  parameter_vectored: ref p } if b == header.hash(self.block_number_bytes) && f == "BabeApi_current_epoch" && p.is_empty())
        }) {Some((
            *warp_sync_source_id,
            &self.sources[warp_sync_source_id.0].user_data,
            DesiredRequest::RuntimeCallMerkleProof {
                block_hash: header.hash(self.block_number_bytes),
                function_name: "BabeApi_current_epoch".into(), // TODO: consider Cow<'static, str> instead of String
                parameter_vectored: Vec::new(),
            },
        )) } else { None }
        } else {
            None
        };

        let babe_next_epoch = if let Phase::PostVerification {
            header,
            chain_information_finality,
            warp_sync_source_id,
            runtime,
            babeapi_current_epoch_response,
            babeapi_next_epoch_response,
        } = &self.phase
        {
            if babeapi_next_epoch_response.is_none() && !self.in_progress_requests.iter().any(|(_, rq)| {
                rq.0 == *warp_sync_source_id && matches!(rq.1, RequestDetail::RuntimeCallMerkleProof { block_hash: b, function_name: ref f,  parameter_vectored: ref p } if b == header.hash(self.block_number_bytes) && f == "BabeApi_next_epoch" && p.is_empty())
            }) {Some((
                *warp_sync_source_id,
                &self.sources[warp_sync_source_id.0].user_data,
                DesiredRequest::RuntimeCallMerkleProof {
                    block_hash: header.hash(self.block_number_bytes),
                    function_name: "BabeApi_next_epoch".into(), // TODO: consider Cow<'static, str> instead of String
                    parameter_vectored: Vec::new(),
                },
            )) } else { None }
        } else {
            None
        };

        warp_sync_request
            .chain(runtime_parameters_get.into_iter())
            .chain(babe_current_epoch.into_iter())
            .chain(babe_next_epoch.into_iter())
    }

    /// Inserts a new request in the data structure.
    ///
    /// > **Note**: The request doesn't necessarily have to match a request returned by
    /// >           [`ChainInfoQuery::desired_requests`].
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is out of range.
    ///
    pub fn add_request(&mut self, source_id: SourceId, detail: RequestDetail) -> RequestId {
        assert!(self.sources.contains(source_id.0));
        RequestId(self.in_progress_requests.insert((source_id, detail)))
    }

    /// Injects a failure to retrieve the parameters.
    pub fn inject_error(&mut self, id: RequestId) {
        match (self.in_progress_requests.remove(id.0), &mut self.phase) {
            ((source_id, RequestDetail::WarpSyncRequest { .. }), _) => {
                // TODO: check that block hash matches starting point? ^
                self.sources[source_id.0].already_tried = true;
            }
            (
                (
                    source_id,
                    RequestDetail::RuntimeCallMerkleProof { .. }
                    | RequestDetail::RuntimeParametersGet { .. },
                ),
                Phase::PostVerification {
                    header,
                    chain_information_finality,
                    warp_sync_source_id,
                    ..
                },
            ) if source_id == *warp_sync_source_id => {
                self.phase = Phase::PreVerification {
                    previous_verifier_values: Some((
                        header.clone(),
                        chain_information_finality.clone(),
                    )),
                }
            }
            (
                (
                    _,
                    RequestDetail::RuntimeCallMerkleProof { .. }
                    | RequestDetail::RuntimeParametersGet { .. },
                ),
                _,
            ) => {}
        }
    }

    /// Set the code and heap pages from storage using the keys `:code` and `:heappages`
    /// respectively. Also allows setting an execution hint for the virtual machine.
    pub fn set_virtual_machine_params(
        &mut self,
        id: RequestId,
        code: Option<impl AsRef<[u8]>>,
        heap_pages: Option<impl AsRef<[u8]>>,
        exec_hint: ExecHint,
        allow_unresolved_imports: bool,
    ) {
        match (self.in_progress_requests.remove(id.0), &self.phase) {
            (
                (_, RequestDetail::RuntimeParametersGet { block_hash }),
                Phase::PostVerification { header, .. },
            ) if block_hash == header.hash(self.block_number_bytes) => {}
            ((_, RequestDetail::RuntimeParametersGet { .. }), _) => return,
            (
                (
                    _,
                    RequestDetail::RuntimeCallMerkleProof { .. }
                    | RequestDetail::WarpSyncRequest { .. },
                ),
                _,
            ) => panic!(),
        }

        let code = match code {
            Some(code) => code.as_ref().to_vec(),
            None => {
                todo!()
                /*return (
                    todo!(), // TODO:
                    Some(Error::MissingCode),
                );*/
            }
        };

        let decoded_heap_pages =
            match executor::storage_heap_pages_to_value(heap_pages.as_ref().map(|p| p.as_ref())) {
                Ok(hp) => hp,
                Err(err) => {
                    todo!()
                    /*return (
                        todo!(), // TODO:
                        Some(Error::InvalidHeapPages(err)),
                    );*/
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
                todo!()
                /*return (
                    todo!(), // TODO:
                    Some(Error::NewRuntime(error)),
                );*/
            }
        };

        if let Phase::PostVerification {
            runtime: ref mut runtime_store,
            ..
        } = self.phase
        {
            *runtime_store = Some((
                runtime,
                Some(code),
                heap_pages.map(|hp| hp.as_ref().to_vec()),
            ));
        } else {
            // This is checked at the beginning of this function.
            unreachable!()
        }
    }

    pub fn run(mut self) -> (WarpSync<TSrc>, Option<Error>) {
        if let Phase::PostVerification {
            header,
            chain_information_finality,
            warp_sync_source_id,
            runtime,
            babeapi_current_epoch_response,
            babeapi_next_epoch_response,
        } = &mut self.phase
        {
            if runtime.is_none()
                || babeapi_current_epoch_response.is_none()
                || babeapi_next_epoch_response.is_none()
            {
                return (WarpSync::InProgress(self), None);
            }

            let (runtime, finalized_storage_code, finalized_storage_heap_pages) =
                runtime.take().unwrap();
            let babeapi_current_epoch_response = babeapi_current_epoch_response.take().unwrap();
            let babeapi_next_epoch_response = babeapi_next_epoch_response.take().unwrap();

            match self.start_chain_information.as_ref().consensus {
                ChainInformationConsensusRef::Babe { .. } => {
                    let mut babe_current_epoch_query =
                        babe_fetch_epoch::babe_fetch_epoch(babe_fetch_epoch::Config {
                            runtime,
                            epoch_to_fetch: babe_fetch_epoch::BabeEpochToFetch::CurrentEpoch,
                        });

                    let (current_epoch, runtime) = loop {
                        match babe_current_epoch_query {
                            babe_fetch_epoch::Query::StorageGet(get) => {
                                let value = match proof_verify::verify_proof(proof_verify::VerifyProofConfig {
                                    requested_key: &get.key_as_vec(), // TODO: allocating vec
                                    trie_root_hash: &header.state_root,
                                    proof: babeapi_current_epoch_response.iter().map(|v| &v[..]),
                                }) {
                                    Ok(v) => v,
                                    Err(err) => todo!(), // TODO:
                                };

                                babe_current_epoch_query = get.inject_value(value.map(iter::once));
                            },
                            babe_fetch_epoch::Query::NextKey(nk) => todo!(), // TODO:
                            babe_fetch_epoch::Query::StorageRoot(root) => {
                                babe_current_epoch_query = root.resume(&header.state_root);
                            },
                            babe_fetch_epoch::Query::Finished { result: Ok(result), virtual_machine } => break (result, virtual_machine),
                            babe_fetch_epoch::Query::Finished { result: Err(_), virtual_machine } => todo!(), // TODO:
                        }
                    };

                    let mut babe_next_epoch_query =
                        babe_fetch_epoch::babe_fetch_epoch(babe_fetch_epoch::Config {
                            runtime,
                            epoch_to_fetch: babe_fetch_epoch::BabeEpochToFetch::NextEpoch,
                        });

                    let (next_epoch, runtime) = loop {
                        match babe_next_epoch_query {
                            babe_fetch_epoch::Query::StorageGet(get) => {
                                let value = match proof_verify::verify_proof(proof_verify::VerifyProofConfig {
                                    requested_key: &get.key_as_vec(), // TODO: allocating vec
                                    trie_root_hash: &header.state_root,
                                    proof: babeapi_next_epoch_response.iter().map(|v| &v[..]),
                                }) {
                                    Ok(v) => v,
                                    Err(err) => todo!(), // TODO:
                                };

                                babe_next_epoch_query = get.inject_value(value.map(iter::once));
                            },
                            babe_fetch_epoch::Query::NextKey(nk) => todo!(), // TODO:
                            babe_fetch_epoch::Query::StorageRoot(root) => {
                                babe_next_epoch_query = root.resume(&header.state_root);
                            },
                            babe_fetch_epoch::Query::Finished { result: Ok(result), virtual_machine } => break (result, virtual_machine),
                            babe_fetch_epoch::Query::Finished { result: Err(_), virtual_machine } => todo!(), // TODO:
                        }
                    };

                    // The number of slots per epoch is never modified once the chain is running,
                    // and as such is copied from the original chain information.
                    let slots_per_epoch = match self.start_chain_information.as_ref().consensus {
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
                            finalized_block_header: header.clone(),
                            finality: chain_information_finality.clone(),
                            consensus: ChainInformationConsensus::Babe {
                                finalized_block_epoch_information: Some(current_epoch),
                                finalized_next_epoch_transition: next_epoch,
                                slots_per_epoch,
                            },
                        }) {
                            Ok(ci) => ci,
                            Err(err) => {
                                todo!() // TODO:
                            }
                        };

                    return (
                        WarpSync::Finished(Success {
                            chain_information,
                            finalized_runtime: runtime,
                            finalized_storage_code,
                            finalized_storage_heap_pages,
                            sources: self
                                .sources
                                .drain()
                                .map(|source| source.user_data)
                                .collect(),
                            in_progress_requests: self
                                .in_progress_requests
                                .iter()
                                .map(|(id, (src_id, detail))| (*src_id, RequestId(id), detail.clone()))
                                .collect(),
                        }),
                        None,
                    );
                }
                ChainInformationConsensusRef::Aura { .. } |  // TODO: https://github.com/paritytech/smoldot/issues/933
                ChainInformationConsensusRef::Unknown => {
                    (
                        todo!(), // TODO:
                        Some(Error::UnknownConsensus),
                    )
                }
            }
        } else {
            (WarpSync::InProgress(self), None)
        }
    }

    pub fn runtime_call_merkle_proof_success(
        &mut self,
        request_id: RequestId,
        response: impl Iterator<Item = impl AsRef<[u8]>>,
    ) {
        match (
            self.in_progress_requests.remove(request_id.0),
            &mut self.phase,
        ) {
            (
                (
                    _,
                    RequestDetail::RuntimeCallMerkleProof {
                        block_hash,
                        function_name,
                        parameter_vectored,
                    },
                ),
                Phase::PostVerification {
                    ref header,
                    ref mut babeapi_current_epoch_response,
                    ..
                },
            ) if block_hash == header.hash(self.block_number_bytes)
                && function_name == "BabeApi_current_epoch"
                && parameter_vectored.is_empty() =>
            {
                *babeapi_current_epoch_response =
                    Some(response.map(|e| e.as_ref().to_vec()).collect());
            }
            (
                (
                    _,
                    RequestDetail::RuntimeCallMerkleProof {
                        block_hash,
                        function_name,
                        parameter_vectored,
                    },
                ),
                Phase::PostVerification {
                    ref header,
                    ref mut babeapi_next_epoch_response,
                    ..
                },
            ) if block_hash == header.hash(self.block_number_bytes)
                && function_name == "BabeApi_next_epoch"
                && parameter_vectored.is_empty() =>
            {
                *babeapi_next_epoch_response =
                    Some(response.map(|e| e.as_ref().to_vec()).collect());
            }
            ((_, RequestDetail::RuntimeCallMerkleProof { .. }), _) => return,
            (
                (_, RequestDetail::RuntimeParametersGet { .. })
                | (_, RequestDetail::WarpSyncRequest { .. }),
                _,
            ) => panic!(),
        }
    }

    /// Submit a GrandPa warp sync successful response.
    pub fn handle_response_ok(
        mut self,
        request_id: RequestId,
        fragments: Vec<WarpSyncFragment>,
        final_set_of_fragments: bool,
    ) -> InProgressWarpSync<TSrc> {
        match (
            self.in_progress_requests.remove(request_id.0),
            &mut self.phase,
        ) {
            (
                (rq_source_id, RequestDetail::WarpSyncRequest { block_hash }),
                Phase::PreVerification {
                    previous_verifier_values,
                },
            ) => {
                // TODO: check block_hash ^
                self.sources[rq_source_id.0].already_tried = true;

                let mut verifier = match &previous_verifier_values {
                    Some((_, chain_information_finality)) => warp_sync::Verifier::new(
                        chain_information_finality.into(),
                        self.block_number_bytes,
                        fragments,
                        final_set_of_fragments,
                    ),
                    None => warp_sync::Verifier::new(
                        self.start_chain_information.as_ref().finality,
                        self.block_number_bytes,
                        fragments,
                        final_set_of_fragments,
                    ),
                };

                // TODO: restore feature where fragments are verified one by one through public API
                loop {
                    match verifier.next() {
                        Ok(warp_sync::Next::NotFinished(next_verifier)) => {
                            verifier = next_verifier;
                        }
                        Ok(warp_sync::Next::EmptyProof) => {
                            self.phase = Phase::PostVerification {
                                babeapi_current_epoch_response: None,
                                babeapi_next_epoch_response: None,
                                runtime: None,
                                header: self
                                    .start_chain_information
                                    .as_ref()
                                    .finalized_block_header
                                    .into(),
                                chain_information_finality: self
                                    .start_chain_information
                                    .as_ref()
                                    .finality
                                    .into(),
                                warp_sync_source_id: rq_source_id,
                            };
                            break;
                        }
                        Ok(warp_sync::Next::Success {
                            scale_encoded_header,
                            chain_information_finality,
                        }) => {
                            // As the verification of the fragment has succeeded, we are sure that the header
                            // is valid and can decode it.
                            let header: Header =
                                header::decode(&scale_encoded_header, self.block_number_bytes)
                                    .unwrap()
                                    .into();

                            if final_set_of_fragments {
                                self.phase = Phase::PostVerification {
                                    babeapi_current_epoch_response: None,
                                    babeapi_next_epoch_response: None,
                                    runtime: None,
                                    header,
                                    chain_information_finality,
                                    warp_sync_source_id: rq_source_id,
                                };
                            } else {
                                *previous_verifier_values =
                                    Some((header, chain_information_finality));
                            }

                            break;
                        }
                        Err(error) => {
                            todo!() // TODO:
                        }
                    }
                }

                self
            }
            ((_, RequestDetail::WarpSyncRequest { .. }), _) => self,
            ((_, _), _) => panic!(),
        }
    }
}

#[derive(Debug, Copy, Clone)]
struct Source<TSrc> {
    user_data: TSrc,
    /// `true` if this source has been in a past `WarpSyncRequest`. `false` if the source is
    /// currently in a `WarpSyncRequest`.
    already_tried: bool,
}

#[derive(Debug, Clone)]
pub enum DesiredRequest {
    WarpSyncRequest {
        block_hash: [u8; 32],
    },
    RuntimeParametersGet {
        block_hash: [u8; 32],
        state_trie_root: [u8; 32],
    },
    RuntimeCallMerkleProof {
        block_hash: [u8; 32],
        function_name: String,
        parameter_vectored: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
pub enum RequestDetail {
    WarpSyncRequest {
        block_hash: [u8; 32],
    },
    RuntimeParametersGet {
        block_hash: [u8; 32],
    },
    RuntimeCallMerkleProof {
        block_hash: [u8; 32],
        function_name: String,
        parameter_vectored: Vec<u8>,
    },
}

/// Identifier for a request in the warp sync state machine.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct RequestId(usize);
