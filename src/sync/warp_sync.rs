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
//! Similarly, at any given moment, this state machine holds a list of requests that concern these
//! sources. Use [`InProgressWarpSync::desired_requires`] to determine which requests will be
//! useful to the progress of the warp syncing.
//!
//! Use [`InProgressWarpSync::process_one`] in order to run verifications of the payloads that have
//! previously been downloaded.
//!

use crate::{
    chain::chain_information::{
        self, babe_fetch_epoch, ChainInformation, ChainInformationConsensus,
        ChainInformationConsensusRef, ChainInformationFinality, ChainInformationFinalityRef,
        ValidChainInformation, ValidChainInformationRef,
    },
    executor::{
        self,
        host::{self, HostVmPrototype, NewErr},
        vm::ExecHint,
    },
    finality::grandpa::warp_sync,
    header::{self, Header},
    trie::proof_verify,
};

use alloc::{borrow::Cow, vec::Vec};
use core::{iter, mem, ops};

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
    /// Failed to verify call proof.
    InvalidCallProof(proof_verify::Error),
    /// Warp sync requires fetching the key that follows another one. This isn't implemented in
    /// smoldot.
    NextKeyUnimplemented,
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

    /// The initial capacity of the list of requests.
    pub requests_capacity: usize,
}

/// Initializes the warp sync state machine.
///
/// On error, returns the [`ValidChainInformation`] that was provided in the configuration.
pub fn warp_sync<TSrc, TRq>(
    config: Config,
) -> Result<InProgressWarpSync<TSrc, TRq>, (ValidChainInformation, WarpSyncInitError)> {
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
        in_progress_requests: slab::Slab::with_capacity(config.requests_capacity),
        phase: Phase::DownloadFragments {
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
pub struct Success<TSrc, TRq> {
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
    pub in_progress_requests: Vec<(SourceId, RequestId, TRq, RequestDetail)>,
}

/// The warp sync state machine.
#[derive(derive_more::From)]
pub enum WarpSync<TSrc, TRq> {
    /// Warp syncing is over.
    Finished(Success<TSrc, TRq>),
    /// Warp syncing is in progress,
    InProgress(InProgressWarpSync<TSrc, TRq>),
}

impl<TSrc, TRq> ops::Index<SourceId> for InProgressWarpSync<TSrc, TRq> {
    type Output = TSrc;

    #[track_caller]
    fn index(&self, source_id: SourceId) -> &TSrc {
        debug_assert!(self.sources.contains(source_id.0));
        &self.sources[source_id.0].user_data
    }
}

impl<TSrc, TRq> ops::IndexMut<SourceId> for InProgressWarpSync<TSrc, TRq> {
    #[track_caller]
    fn index_mut(&mut self, source_id: SourceId) -> &mut TSrc {
        debug_assert!(self.sources.contains(source_id.0));
        &mut self.sources[source_id.0].user_data
    }
}

/// Warp syncing process now obtaining the chain information.
pub struct InProgressWarpSync<TSrc, TRq> {
    phase: Phase,
    start_chain_information: ValidChainInformation,
    block_number_bytes: usize,
    sources: slab::Slab<Source<TSrc>>,
    in_progress_requests: slab::Slab<(SourceId, TRq, RequestDetail)>,
}

enum Phase {
    DownloadFragments {
        previous_verifier_values: Option<(Header, ChainInformationFinality)>,
    },
    PendingVerify {
        previous_verifier_values: Option<(Header, ChainInformationFinality)>,
        downloaded_source: SourceId,
        final_set_of_fragments: bool,
        /// Always `Some`.
        verifier: Option<warp_sync::Verifier>,
    },
    PostVerification {
        header: Header,
        chain_information_finality: ChainInformationFinality,
        warp_sync_source_id: SourceId,
        // TODO: use struct instead?
        runtime: Option<(Option<Vec<u8>>, Option<Vec<u8>>)>,
        babeapi_current_epoch_response: Option<Vec<Vec<u8>>>,
        babeapi_next_epoch_response: Option<Vec<Vec<u8>>>,
    },
}

impl<TSrc, TRq> InProgressWarpSync<TSrc, TRq> {
    /// Returns the value that was initially passed in [`Config::block_number_bytes`].
    pub fn block_number_bytes(&self) -> usize {
        self.block_number_bytes
    }

    /// Returns the chain information that is considered verified.
    pub fn as_chain_information(&self) -> ValidChainInformationRef {
        // Note: after verifying a warp sync fragment, we are certain that the header targeted by
        // this fragment is indeed part of the chain. However, this is not enough in order to
        // produce a full chain information struct. Such struct can only be produced after the
        // entire warp syncing has succeeded. If if it still in progress, all we can return is
        // the starting point.
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

    /// Removes a source from the list of sources. In addition to the user data associated to this
    /// source, also returns a list of requests that were in progress concerning this source. These
    /// requests are now considered obsolete.
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is invalid.
    ///
    pub fn remove_source(
        &'_ mut self,
        to_remove: SourceId,
    ) -> (TSrc, impl Iterator<Item = (RequestId, TRq)> + '_) {
        debug_assert!(self.sources.contains(to_remove.0));
        let removed = self.sources.remove(to_remove.0).user_data;

        if let Phase::PostVerification {
            warp_sync_source_id,
            header,
            chain_information_finality,
            ..
        } = &self.phase
        {
            if to_remove == *warp_sync_source_id {
                self.phase = Phase::DownloadFragments {
                    previous_verifier_values: Some((
                        header.clone(),
                        chain_information_finality.clone(),
                    )),
                }
            }
        } else if let Phase::PendingVerify {
            previous_verifier_values,
            downloaded_source,
            ..
        } = &mut self.phase
        {
            // We make sure to not leave invalid source IDs in the state of `self`.
            // While it is a waste of bandwidth to completely remove a proof that has already
            // been downloaded if the source disconnects, it is in practice not something that is
            // supposed to happen.
            if *downloaded_source == to_remove {
                self.phase = Phase::DownloadFragments {
                    previous_verifier_values: previous_verifier_values.take(),
                }
            }
        }

        let obsolete_requests_indices = self
            .in_progress_requests
            .iter()
            .filter_map(|(id, (src, _, _))| if *src == to_remove { Some(id) } else { None })
            .collect::<Vec<_>>();
        let mut obsolete_requests = Vec::with_capacity(obsolete_requests_indices.len());
        for index in obsolete_requests_indices {
            let (_, user_data, _) = self.in_progress_requests.remove(index);
            obsolete_requests.push((RequestId(index), user_data));
        }

        (removed, obsolete_requests.into_iter())
    }

    /// Returns a list of requests that should be started in order to drive the warp syncing
    /// process to completion.
    ///
    /// Once a request that matches a desired request is added through
    /// [`InProgressWarpSync::add_request`], it is no longer returned by this function.
    pub fn desired_requests(
        &'_ self,
    ) -> impl Iterator<Item = (SourceId, &'_ TSrc, DesiredRequest)> + '_ {
        let warp_sync_request = if let Phase::DownloadFragments {
            previous_verifier_values,
        } = &self.phase
        {
            // TODO: it feels like a hack to try again sources that have failed in the past
            let all_sources_already_tried = self.sources.iter().all(|(_, s)| s.already_tried);

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
                .any(|(_, (_, _, rq))| match rq {
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
                    if all_sources_already_tried || !src.already_tried {
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
            warp_sync_source_id,
            ..
        } = &self.phase
        {
            if !self.in_progress_requests.iter().any(|(_, rq)| {
                rq.0 == *warp_sync_source_id
                    && match rq.2 {
                        RequestDetail::RuntimeParametersGet { block_hash: b }
                            if b == header.hash(self.block_number_bytes) =>
                        {
                            true
                        }
                        _ => false,
                    }
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
            warp_sync_source_id,
            babeapi_current_epoch_response: None,
            ..
        } = &self.phase
        {
            if !self.in_progress_requests.iter().any(|(_, rq)| {
                rq.0 == *warp_sync_source_id
                    && match rq.2 {
                        RequestDetail::RuntimeCallMerkleProof {
                            block_hash: b,
                            function_name: ref f,
                            parameter_vectored: ref p,
                        } if b == header.hash(self.block_number_bytes)
                            && f == "BabeApi_current_epoch"
                            && p.is_empty() =>
                        {
                            true
                        }
                        _ => false,
                    }
            }) {
                Some((
                    *warp_sync_source_id,
                    &self.sources[warp_sync_source_id.0].user_data,
                    DesiredRequest::RuntimeCallMerkleProof {
                        block_hash: header.hash(self.block_number_bytes),
                        function_name: "BabeApi_current_epoch".into(),
                        parameter_vectored: Cow::Borrowed(&[]),
                    },
                ))
            } else {
                None
            }
        } else {
            None
        };

        let babe_next_epoch = if let Phase::PostVerification {
            header,
            warp_sync_source_id,
            babeapi_next_epoch_response: None,
            ..
        } = &self.phase
        {
            if !self.in_progress_requests.iter().any(|(_, rq)| {
                rq.0 == *warp_sync_source_id
                    && match rq.2 {
                        RequestDetail::RuntimeCallMerkleProof {
                            block_hash: b,
                            function_name: ref f,
                            parameter_vectored: ref p,
                        } if b == header.hash(self.block_number_bytes)
                            && f == "BabeApi_next_epoch"
                            && p.is_empty() =>
                        {
                            true
                        }
                        _ => false,
                    }
            }) {
                Some((
                    *warp_sync_source_id,
                    &self.sources[warp_sync_source_id.0].user_data,
                    DesiredRequest::RuntimeCallMerkleProof {
                        block_hash: header.hash(self.block_number_bytes),
                        function_name: "BabeApi_next_epoch".into(),
                        parameter_vectored: Cow::Borrowed(&[]),
                    },
                ))
            } else {
                None
            }
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
    /// >           [`InProgressWarpSync::desired_requests`].
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is out of range.
    ///
    pub fn add_request(
        &mut self,
        source_id: SourceId,
        user_data: TRq,
        detail: RequestDetail,
    ) -> RequestId {
        assert!(self.sources.contains(source_id.0));
        RequestId(
            self.in_progress_requests
                .insert((source_id, user_data, detail)),
        )
    }

    /// Removes the given request from the state machine. Returns the user data that was associated
    /// to it.
    ///
    /// # Panic
    ///
    /// Panics if the [`RequestId`] is invalid.
    ///
    pub fn fail_request(&mut self, id: RequestId) -> TRq {
        match (self.in_progress_requests.remove(id.0), &mut self.phase) {
            ((source_id, user_data, RequestDetail::WarpSyncRequest { .. }), _) => {
                // TODO: check that block hash matches starting point? ^
                self.sources[source_id.0].already_tried = true;
                user_data
            }
            (
                (
                    source_id,
                    user_data,
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
                self.phase = Phase::DownloadFragments {
                    previous_verifier_values: Some((
                        header.clone(),
                        chain_information_finality.clone(),
                    )),
                };
                user_data
            }
            (
                (
                    _,
                    user_data,
                    RequestDetail::RuntimeCallMerkleProof { .. }
                    | RequestDetail::RuntimeParametersGet { .. },
                ),
                _,
            ) => user_data,
        }
    }

    /// Injects a successful response and removes the given request from the state machine. Returns
    /// the user data that was associated to it.
    ///
    /// # Panic
    ///
    /// Panics if the [`RequestId`] is invalid.
    /// Panics if the [`RequestId`] doesn't correspond to a runtime parameters get request.
    ///
    pub fn runtime_parameters_get_success(
        &mut self,
        id: RequestId,
        code: Option<impl AsRef<[u8]>>,
        heap_pages: Option<impl AsRef<[u8]>>,
    ) -> TRq {
        let user_data = match (self.in_progress_requests.remove(id.0), &self.phase) {
            (
                (_, user_data, RequestDetail::RuntimeParametersGet { block_hash }),
                Phase::PostVerification { header, .. },
            ) if block_hash == header.hash(self.block_number_bytes) => user_data,
            ((_, user_data, RequestDetail::RuntimeParametersGet { .. }), _) => return user_data,
            (
                (
                    _,
                    _,
                    RequestDetail::RuntimeCallMerkleProof { .. }
                    | RequestDetail::WarpSyncRequest { .. },
                ),
                _,
            ) => panic!(),
        };

        if let Phase::PostVerification {
            runtime: ref mut runtime_store,
            ..
        } = self.phase
        {
            *runtime_store = Some((
                code.map(|c| c.as_ref().to_vec()),
                heap_pages.map(|hp| hp.as_ref().to_vec()),
            ));
        } else {
            // This is checked at the beginning of this function.
            unreachable!()
        }

        user_data
    }

    /// Injects a successful response and removes the given request from the state machine. Returns
    /// the user data that was associated to it.
    ///
    /// # Panic
    ///
    /// Panics if the [`RequestId`] is invalid.
    /// Panics if the [`RequestId`] doesn't correspond to a runtime merkle call proof request.
    ///
    pub fn runtime_call_merkle_proof_success(
        &mut self,
        request_id: RequestId,
        response: impl Iterator<Item = impl AsRef<[u8]>>,
    ) -> TRq {
        match (
            self.in_progress_requests.remove(request_id.0),
            &mut self.phase,
        ) {
            (
                (
                    _,
                    user_data,
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
                user_data
            }
            (
                (
                    _,
                    user_data,
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
                user_data
            }
            ((_, user_data, RequestDetail::RuntimeCallMerkleProof { .. }), _) => return user_data,
            (
                (_, _, RequestDetail::RuntimeParametersGet { .. })
                | (_, _, RequestDetail::WarpSyncRequest { .. }),
                _,
            ) => panic!(),
        }
    }

    /// Injects a successful response and removes the given request from the state machine. Returns
    /// the user data that was associated to it.
    ///
    /// # Panic
    ///
    /// Panics if the [`RequestId`] is invalid.
    /// Panics if the [`RequestId`] doesn't correspond to a warp sync request.
    ///
    pub fn warp_sync_request_success(
        &mut self,
        request_id: RequestId,
        fragments: Vec<WarpSyncFragment>,
        final_set_of_fragments: bool,
    ) -> TRq {
        match (
            self.in_progress_requests.remove(request_id.0),
            &mut self.phase,
        ) {
            (
                (rq_source_id, user_data, RequestDetail::WarpSyncRequest { block_hash }),
                Phase::DownloadFragments {
                    previous_verifier_values,
                },
            ) => {
                let desired_block_hash = match previous_verifier_values.as_ref() {
                    Some((header, _)) => header.hash(self.block_number_bytes),
                    None => self
                        .start_chain_information
                        .as_ref()
                        .finalized_block_header
                        .hash(self.block_number_bytes),
                };
                if desired_block_hash != block_hash {
                    return user_data;
                }

                // Ignore downloads from sources that are "banned".
                if self.sources[rq_source_id.0].already_tried {
                    return user_data;
                }

                self.sources[rq_source_id.0].already_tried = true;

                let verifier = match &previous_verifier_values {
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

                self.phase = Phase::PendingVerify {
                    previous_verifier_values: previous_verifier_values.take(),
                    final_set_of_fragments,
                    downloaded_source: rq_source_id,
                    verifier: Some(verifier),
                };

                user_data
            }
            ((_, user_data, RequestDetail::WarpSyncRequest { .. }), _) => {
                // Uninteresting download. We simply ignore the response.
                user_data
            }
            ((_, _, _), _) => panic!(),
        }
    }

    /// Start processing one CPU operation.
    ///
    /// This function takes ownership of `self` and yields it back after the operation is finished.
    pub fn process_one(self) -> ProcessOne<TSrc, TRq> {
        if let Phase::PostVerification {
            runtime: Some(_),
            babeapi_current_epoch_response: Some(_),
            babeapi_next_epoch_response: Some(_),
            ..
        } = &self.phase
        {
            return ProcessOne::BuildChainInformation(BuildChainInformation { inner: self });
        }

        if let Phase::PendingVerify { .. } = &self.phase {
            return ProcessOne::VerifyWarpSyncFragment(VerifyWarpSyncFragment { inner: self });
        }

        ProcessOne::Idle(self)
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
        function_name: Cow<'static, str>,
        parameter_vectored: Cow<'static, [u8]>,
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
        function_name: Cow<'static, str>,
        parameter_vectored: Cow<'static, [u8]>,
    },
}

/// Identifier for a request in the warp sync state machine.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct RequestId(usize);

pub enum ProcessOne<TSrc, TRq> {
    Idle(InProgressWarpSync<TSrc, TRq>),
    VerifyWarpSyncFragment(VerifyWarpSyncFragment<TSrc, TRq>),
    BuildChainInformation(BuildChainInformation<TSrc, TRq>),
}

pub struct VerifyWarpSyncFragment<TSrc, TRq> {
    inner: InProgressWarpSync<TSrc, TRq>,
}

impl<TSrc, TRq> VerifyWarpSyncFragment<TSrc, TRq> {
    pub fn proof_sender(&self) -> (SourceId, &TSrc) {
        if let Phase::PendingVerify {
            downloaded_source, ..
        } = &self.inner.phase
        {
            (
                *downloaded_source,
                &self.inner.sources[downloaded_source.0].user_data,
            )
        } else {
            unreachable!()
        }
    }

    // TODO: does this API make sense?
    pub fn verify(mut self) -> (InProgressWarpSync<TSrc, TRq>, Option<FragmentError>) {
        if let Phase::PendingVerify {
            previous_verifier_values,
            verifier,
            final_set_of_fragments,
            downloaded_source,
        } = &mut self.inner.phase
        {
            match verifier.take().unwrap().next() {
                Ok(warp_sync::Next::NotFinished(next_verifier)) => {
                    *verifier = Some(next_verifier);
                }
                Ok(warp_sync::Next::EmptyProof) => {
                    self.inner.phase = Phase::PostVerification {
                        babeapi_current_epoch_response: None,
                        babeapi_next_epoch_response: None,
                        runtime: None,
                        header: self
                            .inner
                            .start_chain_information
                            .as_ref()
                            .finalized_block_header
                            .into(),
                        chain_information_finality: self
                            .inner
                            .start_chain_information
                            .as_ref()
                            .finality
                            .into(),
                        warp_sync_source_id: *downloaded_source,
                    };
                }
                Ok(warp_sync::Next::Success {
                    scale_encoded_header,
                    chain_information_finality,
                }) => {
                    // As the verification of the fragment has succeeded, we are sure that the header
                    // is valid and can decode it.
                    let header: Header =
                        header::decode(&scale_encoded_header, self.inner.block_number_bytes)
                            .unwrap()
                            .into();

                    if *final_set_of_fragments {
                        self.inner.phase = Phase::PostVerification {
                            babeapi_current_epoch_response: None,
                            babeapi_next_epoch_response: None,
                            runtime: None,
                            header,
                            chain_information_finality,
                            warp_sync_source_id: *downloaded_source,
                        };
                    } else {
                        *previous_verifier_values = Some((header, chain_information_finality));
                    }
                }
                Err(error) => {
                    self.inner.phase = Phase::DownloadFragments {
                        previous_verifier_values: previous_verifier_values.take(),
                    };
                    return (self.inner, Some(error));
                }
            }

            (self.inner, None)
        } else {
            unreachable!()
        }
    }
}

pub struct BuildChainInformation<TSrc, TRq> {
    inner: InProgressWarpSync<TSrc, TRq>,
}

impl<TSrc, TRq> BuildChainInformation<TSrc, TRq> {
    pub fn build(mut self) -> (WarpSync<TSrc, TRq>, Option<Error>) {
        if let Phase::PostVerification {
            header,
            chain_information_finality,
            runtime: runtime @ Some(_),
            babeapi_current_epoch_response: babeapi_current_epoch_response @ Some(_),
            babeapi_next_epoch_response: babeapi_next_epoch_response @ Some(_),
            ..
        } = &mut self.inner.phase
        {
            let (finalized_storage_code, finalized_storage_heap_pages) = runtime.take().unwrap();
            let babeapi_current_epoch_response = babeapi_current_epoch_response.take().unwrap();
            let babeapi_next_epoch_response = babeapi_next_epoch_response.take().unwrap();

            let finalized_storage_code = match finalized_storage_code {
                Some(code) => code,
                None => {
                    self.inner.phase = Phase::DownloadFragments {
                        previous_verifier_values: Some((
                            header.clone(),
                            chain_information_finality.clone(),
                        )),
                    };
                    return (WarpSync::InProgress(self.inner), Some(Error::MissingCode));
                }
            };

            let decoded_heap_pages = match executor::storage_heap_pages_to_value(
                finalized_storage_heap_pages.as_ref().map(|p| p.as_ref()),
            ) {
                Ok(hp) => hp,
                Err(err) => {
                    self.inner.phase = Phase::DownloadFragments {
                        previous_verifier_values: Some((
                            header.clone(),
                            chain_information_finality.clone(),
                        )),
                    };
                    return (
                        WarpSync::InProgress(self.inner),
                        Some(Error::InvalidHeapPages(err)),
                    );
                }
            };

            let runtime = match HostVmPrototype::new(host::Config {
                module: &finalized_storage_code,
                heap_pages: decoded_heap_pages,
                exec_hint: ExecHint::CompileAheadOfTime, // TODO: make configurable
                allow_unresolved_imports: false,         // TODO: make configurable
            }) {
                Ok(runtime) => runtime,
                Err(error) => {
                    self.inner.phase = Phase::DownloadFragments {
                        previous_verifier_values: Some((
                            header.clone(),
                            chain_information_finality.clone(),
                        )),
                    };
                    return (
                        WarpSync::InProgress(self.inner),
                        Some(Error::NewRuntime(error)),
                    );
                }
            };

            match self.inner.start_chain_information.as_ref().consensus {
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
                                    Err(err) => {
                                        self.inner.phase = Phase::DownloadFragments {
                                            previous_verifier_values: Some((
                                                header.clone(),
                                                chain_information_finality.clone(),
                                            )),
                                        };
                                        return (
                                            WarpSync::InProgress(self.inner),
                                            Some(Error::InvalidCallProof(err)),
                                        );
                                    }
                                };

                                babe_current_epoch_query = get.inject_value(value.map(iter::once));
                            },
                            babe_fetch_epoch::Query::NextKey(_) => {
                                // TODO: implement
                                self.inner.phase = Phase::DownloadFragments {
                                    previous_verifier_values: Some((
                                        header.clone(),
                                        chain_information_finality.clone(),
                                    )),
                                };
                                return (
                                    WarpSync::InProgress(self.inner),
                                    Some(Error::NextKeyUnimplemented),
                                );}
                            babe_fetch_epoch::Query::StorageRoot(root) => {
                                babe_current_epoch_query = root.resume(&header.state_root);
                            },
                            babe_fetch_epoch::Query::Finished { result: Ok(result), virtual_machine } => break (result, virtual_machine),
                            babe_fetch_epoch::Query::Finished { result: Err(err), .. } => {
                                self.inner.phase = Phase::DownloadFragments {
                                    previous_verifier_values: Some((
                                        header.clone(),
                                        chain_information_finality.clone(),
                                    )),
                                };
                                return (
                                    WarpSync::InProgress(self.inner),
                                    Some(Error::BabeFetchEpoch(err)),
                                );
                            }
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
                                    Err(err) => {
                                        self.inner.phase = Phase::DownloadFragments {
                                            previous_verifier_values: Some((
                                                header.clone(),
                                                chain_information_finality.clone(),
                                            )),
                                        };
                                        return (
                                            WarpSync::InProgress(self.inner),
                                            Some(Error::InvalidCallProof(err)),
                                        );
                                    }
                                };

                                babe_next_epoch_query = get.inject_value(value.map(iter::once));
                            },
                            babe_fetch_epoch::Query::NextKey(_) => {
                                // TODO: implement
                                self.inner.phase = Phase::DownloadFragments {
                                    previous_verifier_values: Some((
                                        header.clone(),
                                        chain_information_finality.clone(),
                                    )),
                                };
                                return (
                                    WarpSync::InProgress(self.inner),
                                    Some(Error::NextKeyUnimplemented),
                                );
                            }
                            babe_fetch_epoch::Query::StorageRoot(root) => {
                                babe_next_epoch_query = root.resume(&header.state_root);
                            },
                            babe_fetch_epoch::Query::Finished { result: Ok(result), virtual_machine } => break (result, virtual_machine),
                            babe_fetch_epoch::Query::Finished { result: Err(err), .. } => {
                                self.inner.phase = Phase::DownloadFragments {
                                    previous_verifier_values: Some((
                                        header.clone(),
                                        chain_information_finality.clone(),
                                    )),
                                };
                                return (
                                    WarpSync::InProgress(self.inner),
                                    Some(Error::BabeFetchEpoch(err)),
                                );
                            }
                        }
                    };

                    // The number of slots per epoch is never modified once the chain is running,
                    // and as such is copied from the original chain information.
                    let slots_per_epoch = match self.inner.start_chain_information.as_ref().consensus {
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
                                self.inner.phase = Phase::DownloadFragments {
                                    previous_verifier_values: Some((
                                        header.clone(),
                                        chain_information_finality.clone(),
                                    )),
                                };
                                return (
                                    WarpSync::InProgress(self.inner),
                                    Some(Error::InvalidChain(err)),
                                );
                            }
                        };

                    return (
                        WarpSync::Finished(Success {
                            chain_information,
                            finalized_runtime: runtime,
                            finalized_storage_code: Some(finalized_storage_code),
                            finalized_storage_heap_pages,
                            sources: self.inner
                                .sources
                                .drain()
                                .map(|source| source.user_data)
                                .collect(),
                            in_progress_requests: mem::take(&mut self.inner
                                .in_progress_requests)
                                .into_iter()
                                .map(|(id, (src_id, user_data, detail))| (src_id, RequestId(id), user_data, detail))
                                .collect(),
                        }),
                        None,
                    );
                }
                ChainInformationConsensusRef::Aura { .. } |  // TODO: https://github.com/paritytech/smoldot/issues/933
                ChainInformationConsensusRef::Unknown => {
                    // TODO: detect this at warp sync initialization
                    self.inner.phase = Phase::DownloadFragments {
                        previous_verifier_values: Some((
                            header.clone(),
                            chain_information_finality.clone(),
                        )),
                    };
                    return (
                        WarpSync::InProgress(self.inner),
                        Some(Error::UnknownConsensus),
                    );
                }
            }
        } else {
            unreachable!()
        }
    }
}
