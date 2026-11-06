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

//! Build the chain information of a chain given its runtime.
//!
//! This module contains the [`ChainInformationBuild`] struct, a state machine that drives the
//! process of building the chain information of a certain finalized point of a chain.

use alloc::{boxed::Box, vec::Vec};
use core::{fmt, iter, num::NonZero};

use crate::{
    chain::chain_information,
    executor::{host, runtime_call},
    header, trie,
};

pub use runtime_call::{Nibble, TrieEntryVersion};

/// Configuration to provide to [`ChainInformationBuild::new`].
pub struct Config {
    /// Header of the finalized block, whose chain information is to retrieve.
    ///
    /// Stored within the chain information at the end.
    pub finalized_block_header: ConfigFinalizedBlockHeader,

    /// Runtime of the finalized block. Must be built using the Wasm code found at the `:code` key
    /// of the block storage.
    pub runtime: host::HostVmPrototype,

    /// Number of bytes of the block number encoded in the block header.
    pub block_number_bytes: usize,
}

/// See [`Config::finalized_block_header`].
pub enum ConfigFinalizedBlockHeader {
    /// The block is the genesis block of the chain.
    Genesis {
        /// Hash of the root of the state trie of the genesis.
        state_trie_root_hash: [u8; 32],
    },
    /// The block can any block, genesis block of the chain or not.
    Any {
        /// Header of the block.
        scale_encoded_header: Vec<u8>,
        /// Can be used to pass information about the finality of the chain, if already known.
        known_finality: Option<chain_information::ChainInformationFinality>,
    },
}

/// Current state of the operation.
#[must_use]
pub enum ChainInformationBuild {
    /// Fetching the chain information is over.
    Finished {
        /// The result of the computation.
        ///
        /// If successful, the chain information is guaranteed to be valid.
        result: Result<chain_information::ValidChainInformation, Error>,
        /// Value of [`Config::runtime`] passed back.
        virtual_machine: host::HostVmPrototype,
    },

    /// Still in progress.
    InProgress(InProgress),
}

/// Chain information building is still in progress.
#[must_use]
pub enum InProgress {
    /// Loading a storage value is required in order to continue.
    StorageGet(StorageGet),
    /// Obtaining the Merkle value of the closest descendant of a trie node is required in order
    /// to continue.
    ClosestDescendantMerkleValue(ClosestDescendantMerkleValue),
    /// Fetching the key that follows a given one is required in order to continue.
    NextKey(NextKey),
}

/// Problem encountered during the chain building process.
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum Error {
    /// Error while starting the Wasm virtual machine.
    #[display("While calling {call:?}: {error}")]
    WasmStart {
        call: RuntimeCall,
        #[error(source)]
        error: host::StartErr,
    },
    /// Error while running the Wasm virtual machine.
    #[display("While calling {call:?}: {error}")]
    WasmVm {
        call: RuntimeCall,
        #[error(source)]
        error: runtime_call::ErrorDetail,
    },
    /// Runtime has called an offchain worker host function.
    OffchainWorkerHostFunction,
    /// Failed to decode the output of the `AuraApi_slot_duration` runtime call.
    AuraSlotDurationOutputDecode,
    /// Failed to decode the output of the `AuraApi_authorities` runtime call.
    AuraAuthoritiesOutputDecode,
    /// Failed to decode the output of the `BabeApi_current_epoch` runtime call.
    BabeCurrentEpochOutputDecode,
    /// Failed to decode the output of the `BabeApi_next_epoch` runtime call.
    BabeNextEpochOutputDecode,
    /// Failed to decode the output of the `BabeApi_configuration` runtime call.
    BabeConfigurationOutputDecode,
    /// The version of `GrandaApi` is too old to be able to build the chain information.
    GrandpaApiTooOld,
    /// Failed to decode the output of the `GrandpaApi_authorities` runtime call.
    GrandpaAuthoritiesOutputDecode,
    /// Failed to decode the output of the `GrandpaApi_current_set_id` runtime call.
    GrandpaCurrentSetIdOutputDecode,
    /// The combination of the information retrieved from the runtime doesn't make sense together.
    #[display("{_0}")]
    InvalidChainInformation(chain_information::ValidityError),
    /// Multiple consensus algorithms have been detected.
    MultipleConsensusAlgorithms,
}

/// Function call to perform or being performed.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub enum RuntimeCall {
    AuraApiSlotDuration,
    AuraApiAuthorities,
    BabeApiCurrentEpoch,
    BabeApiNextEpoch,
    BabeApiConfiguration,
    GrandpaApiAuthorities,
    GrandpaApiCurrentSetId,
}

impl RuntimeCall {
    /// Name of the runtime function corresponding to this call.
    pub fn function_name(&self) -> &'static str {
        match self {
            RuntimeCall::AuraApiSlotDuration => "AuraApi_slot_duration",
            RuntimeCall::AuraApiAuthorities => "AuraApi_authorities",
            RuntimeCall::BabeApiCurrentEpoch => "BabeApi_current_epoch",
            RuntimeCall::BabeApiNextEpoch => "BabeApi_next_epoch",
            RuntimeCall::BabeApiConfiguration => "BabeApi_configuration",
            RuntimeCall::GrandpaApiAuthorities => "GrandpaApi_grandpa_authorities",
            RuntimeCall::GrandpaApiCurrentSetId => "GrandpaApi_current_set_id",
        }
    }

    /// Returns the list of parameters to pass when making the call.
    ///
    /// The actual parameters are obtained by putting together all the returned buffers together.
    pub fn parameter_vectored(&self) -> impl Iterator<Item = impl AsRef<[u8]> + Clone> + Clone {
        iter::empty::<Vec<u8>>()
    }

    /// Returns the list of parameters to pass when making the call.
    ///
    /// This function is a convenience around [`RuntimeCall::parameter_vectored`].
    pub fn parameter_vectored_vec(&self) -> Vec<u8> {
        Vec::new()
    }
}

impl fmt::Debug for RuntimeCall {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.function_name(), f)
    }
}

impl ChainInformationBuild {
    /// Starts a new chain information build process.
    ///
    /// # Panic
    ///
    /// Panics if a [`ConfigFinalizedBlockHeader::Any`] is provided, and the header can't be
    /// decoded.
    ///
    pub fn new(config: Config) -> Self {
        let [aura_version, babe_version, grandpa_version] = config
            .runtime
            .runtime_version()
            .decode()
            .apis
            .find_versions(["AuraApi", "BabeApi", "GrandpaApi"]);
        let runtime_has_aura = aura_version.map_or(false, |version_number| version_number == 1);
        let runtime_babeapi_is_v1 = babe_version.and_then(|version_number| match version_number {
            1 => Some(true),
            2 => Some(false),
            _ => None,
        });
        let runtime_grandpa_supports_currentsetid =
            grandpa_version.and_then(|version_number| match version_number {
                // Version 1 is from 2019 and isn't used by any chain in production, so we don't
                // care about it.
                2 => Some(false),
                3 => Some(true),
                _ => None,
            });

        let inner = ChainInformationBuildInner {
            finalized_block_header: config.finalized_block_header,
            block_number_bytes: config.block_number_bytes,
            call_in_progress: None,
            virtual_machine: Some(config.runtime),
            runtime_has_aura,
            runtime_babeapi_is_v1,
            runtime_grandpa_supports_currentsetid,
            aura_autorities_call_output: None,
            aura_slot_duration_call_output: None,
            babe_current_epoch_call_output: None,
            babe_next_epoch_call_output: None,
            babe_configuration_call_output: None,
            grandpa_autorities_call_output: None,
            grandpa_current_set_id_call_output: None,
        };

        ChainInformationBuild::start_next_call(inner)
    }
}

impl InProgress {
    /// Returns the list of runtime calls that will be performed. Always includes the value
    /// returned by [`InProgress::call_in_progress`].
    ///
    /// This list never changes, except for the fact that it gets shorter over time.
    pub fn remaining_calls(&self) -> impl Iterator<Item = RuntimeCall> {
        let inner = match self {
            InProgress::StorageGet(StorageGet(_, shared)) => shared,
            InProgress::ClosestDescendantMerkleValue(ClosestDescendantMerkleValue(_, shared)) => {
                shared
            }
            InProgress::NextKey(NextKey(_, shared)) => shared,
        };

        ChainInformationBuild::necessary_calls(inner)
    }

    /// Returns the runtime call currently being made.
    pub fn call_in_progress(&self) -> RuntimeCall {
        let inner = match self {
            InProgress::StorageGet(StorageGet(_, shared)) => shared,
            InProgress::ClosestDescendantMerkleValue(ClosestDescendantMerkleValue(_, shared)) => {
                shared
            }
            InProgress::NextKey(NextKey(_, shared)) => shared,
        };

        inner.call_in_progress.unwrap()
    }
}

/// Loading a storage value is required in order to continue.
#[must_use]
pub struct StorageGet(runtime_call::StorageGet, ChainInformationBuildInner);

impl StorageGet {
    /// Returns the key whose value must be passed to [`StorageGet::inject_value`].
    pub fn key(&self) -> impl AsRef<[u8]> {
        self.0.key()
    }

    /// If `Some`, read from the given child trie. If `None`, read from the main trie.
    pub fn child_trie(&self) -> Option<impl AsRef<[u8]>> {
        self.0.child_trie()
    }

    /// Injects the corresponding storage value.
    pub fn inject_value(
        self,
        value: Option<(impl Iterator<Item = impl AsRef<[u8]>>, TrieEntryVersion)>,
    ) -> ChainInformationBuild {
        ChainInformationBuild::from_call_in_progress(self.0.inject_value(value), self.1)
    }

    /// Returns the runtime call currently being made.
    pub fn call_in_progress(&self) -> RuntimeCall {
        self.1.call_in_progress.unwrap()
    }
}

/// Obtaining the Merkle value of the closest descendant of a trie node is required in order
/// to continue.
#[must_use]
pub struct ClosestDescendantMerkleValue(
    runtime_call::ClosestDescendantMerkleValue,
    ChainInformationBuildInner,
);

impl ClosestDescendantMerkleValue {
    /// Returns the key whose closest descendant Merkle value must be passed to
    /// [`ClosestDescendantMerkleValue::inject_merkle_value`].
    pub fn key(&self) -> impl Iterator<Item = Nibble> {
        self.0.key()
    }

    /// If `Some`, read from the given child trie. If `None`, read from the main trie.
    pub fn child_trie(&self) -> Option<impl AsRef<[u8]>> {
        self.0.child_trie()
    }

    /// Indicate that the value is unknown and resume the calculation.
    ///
    /// This function be used if you are unaware of the Merkle value. The algorithm will perform
    /// the calculation of this Merkle value manually, which takes more time.
    pub fn resume_unknown(self) -> ChainInformationBuild {
        ChainInformationBuild::from_call_in_progress(self.0.resume_unknown(), self.1)
    }

    /// Injects the corresponding Merkle value.
    ///
    /// `None` can be passed if there is no descendant or, in the case of a child trie read, in
    /// order to indicate that the child trie does not exist.
    pub fn inject_merkle_value(self, merkle_value: Option<&[u8]>) -> ChainInformationBuild {
        ChainInformationBuild::from_call_in_progress(
            self.0.inject_merkle_value(merkle_value),
            self.1,
        )
    }

    /// Returns the runtime call currently being made.
    pub fn call_in_progress(&self) -> RuntimeCall {
        self.1.call_in_progress.unwrap()
    }
}

/// Fetching the key that follows a given one is required in order to continue.
#[must_use]
pub struct NextKey(runtime_call::NextKey, ChainInformationBuildInner);

impl NextKey {
    /// Returns the key whose next key must be passed back.
    pub fn key(&self) -> impl Iterator<Item = Nibble> {
        self.0.key()
    }

    /// If `Some`, read from the given child trie. If `None`, read from the main trie.
    pub fn child_trie(&self) -> Option<impl AsRef<[u8]>> {
        self.0.child_trie()
    }

    /// If `true`, then the provided value must the one superior or equal to the requested key.
    /// If `false`, then the provided value must be strictly superior to the requested key.
    pub fn or_equal(&self) -> bool {
        self.0.or_equal()
    }

    /// If `true`, then the search must include both branch nodes and storage nodes. If `false`,
    /// the search only covers storage nodes.
    pub fn branch_nodes(&self) -> bool {
        self.0.branch_nodes()
    }

    /// Returns the prefix the next key must start with. If the next key doesn't start with the
    /// given prefix, then `None` should be provided.
    pub fn prefix(&self) -> impl Iterator<Item = Nibble> {
        self.0.prefix()
    }

    /// Injects the key.
    ///
    /// # Panic
    ///
    /// Panics if the key passed as parameter isn't strictly superior to the requested key.
    /// Panics if the key passed as parameter doesn't start with the requested prefix.
    ///
    pub fn inject_key(self, key: Option<impl Iterator<Item = Nibble>>) -> ChainInformationBuild {
        ChainInformationBuild::from_call_in_progress(self.0.inject_key(key), self.1)
    }

    /// Returns the runtime call currently being made.
    pub fn call_in_progress(&self) -> RuntimeCall {
        self.1.call_in_progress.unwrap()
    }
}

impl ChainInformationBuild {
    fn necessary_calls(
        inner: &ChainInformationBuildInner,
    ) -> impl Iterator<Item = RuntimeCall> + use<> {
        let aura_api_authorities =
            if inner.runtime_has_aura && inner.aura_autorities_call_output.is_none() {
                Some(RuntimeCall::AuraApiAuthorities)
            } else {
                None
            };

        let aura_slot_duration =
            if inner.runtime_has_aura && inner.aura_slot_duration_call_output.is_none() {
                Some(RuntimeCall::AuraApiSlotDuration)
            } else {
                None
            };

        let babe_current_epoch = if matches!(
            inner.finalized_block_header,
            ConfigFinalizedBlockHeader::Any {
                ref scale_encoded_header,
                ..
            } if header::decode(scale_encoded_header, inner.block_number_bytes).unwrap().number != 0
        ) && inner.runtime_babeapi_is_v1.is_some()
            && inner.babe_current_epoch_call_output.is_none()
        {
            Some(RuntimeCall::BabeApiCurrentEpoch)
        } else {
            None
        };

        let babe_next_epoch = if matches!(
            inner.finalized_block_header,
            ConfigFinalizedBlockHeader::Any {
                ref scale_encoded_header,
                ..
            } if header::decode(scale_encoded_header, inner.block_number_bytes).unwrap().number != 0
        ) && inner.runtime_babeapi_is_v1.is_some()
            && inner.babe_next_epoch_call_output.is_none()
        {
            Some(RuntimeCall::BabeApiNextEpoch)
        } else {
            None
        };

        let babe_configuration = if inner.runtime_babeapi_is_v1.is_some()
            && inner.babe_configuration_call_output.is_none()
        {
            Some(RuntimeCall::BabeApiConfiguration)
        } else {
            None
        };

        let grandpa_authorities = if !matches!(
            inner.finalized_block_header,
            ConfigFinalizedBlockHeader::Any {
                known_finality: Some(chain_information::ChainInformationFinality::Grandpa { .. }),
                ..
            },
        ) && inner.runtime_grandpa_supports_currentsetid.is_some()
            && inner.grandpa_autorities_call_output.is_none()
        {
            Some(RuntimeCall::GrandpaApiAuthorities)
        } else {
            None
        };

        // The grandpa set ID doesn't need to be retrieved if finality was provided by the user,
        // but also doesn't need to be retrieved for the genesis block because we know it's
        // always 0.
        let grandpa_current_set_id = if matches!(
            inner.finalized_block_header,
            ConfigFinalizedBlockHeader::Any {
                ref scale_encoded_header,
                known_finality: None,
                ..
            } if header::decode(scale_encoded_header, inner.block_number_bytes).unwrap().number != 0,
        ) && inner.runtime_grandpa_supports_currentsetid
            == Some(true)
            && inner.grandpa_current_set_id_call_output.is_none()
        {
            Some(RuntimeCall::GrandpaApiCurrentSetId)
        } else {
            None
        };

        [
            aura_api_authorities,
            aura_slot_duration,
            babe_current_epoch,
            babe_next_epoch,
            babe_configuration,
            grandpa_authorities,
            grandpa_current_set_id,
        ]
        .into_iter()
        .flatten()
    }

    fn start_next_call(mut inner: ChainInformationBuildInner) -> Self {
        debug_assert!(inner.call_in_progress.is_none());
        debug_assert!(inner.virtual_machine.is_some());

        if let Some(call) = ChainInformationBuild::necessary_calls(&inner).next() {
            let vm_start_result = runtime_call::run(runtime_call::Config {
                function_to_call: call.function_name(),
                parameter: call.parameter_vectored(),
                virtual_machine: inner.virtual_machine.take().unwrap(),
                max_log_level: 0,
                storage_proof_size_behavior:
                    runtime_call::StorageProofSizeBehavior::proof_recording_disabled(),
                storage_main_trie_changes: Default::default(),
                calculate_trie_changes: false,
                calculate_child_tries_roots_on_finish: false,
            });

            let vm = match vm_start_result {
                Ok(vm) => vm,
                Err((error, virtual_machine)) => {
                    return ChainInformationBuild::Finished {
                        result: Err(Error::WasmStart { call, error }),
                        virtual_machine,
                    };
                }
            };

            inner.call_in_progress = Some(call);
            ChainInformationBuild::from_call_in_progress(vm, inner)
        } else {
            // If the logic of this module is correct, all the information that we need has been
            // retrieved at this point.

            let consensus = match (
                inner.runtime_has_aura,
                inner.runtime_babeapi_is_v1,
                &inner.finalized_block_header,
            ) {
                (true, Some(_), _) => {
                    return ChainInformationBuild::Finished {
                        result: Err(Error::MultipleConsensusAlgorithms),
                        virtual_machine: inner.virtual_machine.take().unwrap(),
                    };
                }
                (false, None, _) => chain_information::ChainInformationConsensus::Unknown,
                (
                    false,
                    Some(_),
                    ConfigFinalizedBlockHeader::Any {
                        scale_encoded_header,
                        ..
                    },
                ) if header::decode(scale_encoded_header, inner.block_number_bytes)
                    .unwrap()
                    .number
                    != 0 =>
                {
                    chain_information::ChainInformationConsensus::Babe {
                        finalized_block_epoch_information: Some(Box::new(
                            inner.babe_current_epoch_call_output.take().unwrap(),
                        )),
                        finalized_next_epoch_transition: Box::new(
                            inner.babe_next_epoch_call_output.take().unwrap(),
                        ),
                        slots_per_epoch: inner
                            .babe_configuration_call_output
                            .take()
                            .unwrap()
                            .slots_per_epoch,
                    }
                }
                (false, Some(_), _) => {
                    let config = inner.babe_configuration_call_output.take().unwrap();
                    chain_information::ChainInformationConsensus::Babe {
                        slots_per_epoch: config.slots_per_epoch,
                        finalized_block_epoch_information: None,
                        finalized_next_epoch_transition: Box::new(
                            chain_information::BabeEpochInformation {
                                epoch_index: 0,
                                start_slot_number: None,
                                authorities: config.epoch0_information.authorities,
                                randomness: config.epoch0_information.randomness,
                                c: config.epoch0_configuration.c,
                                allowed_slots: config.epoch0_configuration.allowed_slots,
                            },
                        ),
                    }
                }
                (true, None, _) => chain_information::ChainInformationConsensus::Aura {
                    finalized_authorities_list: inner.aura_autorities_call_output.take().unwrap(),
                    slot_duration: inner.aura_slot_duration_call_output.take().unwrap(),
                },
            };

            // Build the finalized block header, and extract the information about finality if it
            // was already provided by the API user.
            let (finalized_block_header, known_finality) = match inner.finalized_block_header {
                ConfigFinalizedBlockHeader::Genesis {
                    state_trie_root_hash,
                } => {
                    let header = header::HeaderRef {
                        parent_hash: &[0; 32],
                        number: 0,
                        state_root: &state_trie_root_hash,
                        extrinsics_root: &trie::EMPTY_BLAKE2_TRIE_MERKLE_VALUE,
                        digest: header::DigestRef::empty(),
                    }
                    .scale_encoding_vec(inner.block_number_bytes);

                    (header, None)
                }
                ConfigFinalizedBlockHeader::Any {
                    scale_encoded_header: header,
                    known_finality,
                } => (header, known_finality),
            };

            // Build the finality information if not known yet.
            let finality = if let Some(known_finality) = known_finality {
                known_finality
            } else if inner.runtime_grandpa_supports_currentsetid.is_some() {
                chain_information::ChainInformationFinality::Grandpa {
                    after_finalized_block_authorities_set_id: if header::decode(
                        &finalized_block_header,
                        inner.block_number_bytes,
                    )
                    .unwrap()
                    .number
                        == 0
                    {
                        0
                    } else {
                        // If the GrandPa runtime API version is too old, it is not possible to
                        // determine the current set ID.
                        let Some(grandpa_current_set_id_call_output) =
                            inner.grandpa_current_set_id_call_output.take()
                        else {
                            debug_assert_eq!(
                                inner.runtime_grandpa_supports_currentsetid,
                                Some(false)
                            );
                            return ChainInformationBuild::Finished {
                                result: Err(Error::GrandpaApiTooOld),
                                virtual_machine: inner.virtual_machine.take().unwrap(),
                            };
                        };

                        grandpa_current_set_id_call_output
                    },
                    // TODO: The runtime doesn't give us a way to know the current scheduled change. At the moment the runtime it never schedules changes with a delay of more than 0. So in practice this `None` is correct, but it relies on implementation details
                    finalized_scheduled_change: None,
                    finalized_triggered_authorities: inner
                        .grandpa_autorities_call_output
                        .take()
                        .unwrap(),
                }
            } else {
                chain_information::ChainInformationFinality::Outsourced
            };

            // Build a `ChainInformation` using the parameters found in the runtime.
            // It is possible, however, that the runtime produces parameters that aren't
            // coherent. For example the runtime could give "current" and "next" Babe
            // epochs that don't follow each other.
            let chain_information = match chain_information::ValidChainInformation::try_from(
                chain_information::ChainInformation {
                    finalized_block_header: Box::new(
                        header::decode(&finalized_block_header, inner.block_number_bytes)
                            .unwrap()
                            .into(),
                    ),
                    finality,
                    consensus,
                },
            ) {
                Ok(ci) => ci,
                Err(err) => {
                    return ChainInformationBuild::Finished {
                        result: Err(Error::InvalidChainInformation(err)),
                        virtual_machine: inner.virtual_machine.take().unwrap(),
                    };
                }
            };

            ChainInformationBuild::Finished {
                result: Ok(chain_information),
                virtual_machine: inner.virtual_machine.take().unwrap(),
            }
        }
    }

    fn from_call_in_progress(
        mut call: runtime_call::RuntimeCall,
        mut inner: ChainInformationBuildInner,
    ) -> Self {
        loop {
            debug_assert!(inner.call_in_progress.is_some());

            match call {
                runtime_call::RuntimeCall::Finished(Ok(success)) => {
                    inner.virtual_machine = Some(match inner.call_in_progress.take() {
                        None => unreachable!(),
                        Some(RuntimeCall::AuraApiSlotDuration) => {
                            let result = decode_aura_slot_duration_output(
                                success.virtual_machine.value().as_ref(),
                            );
                            let virtual_machine = success.virtual_machine.into_prototype();
                            match result {
                                Ok(output) => inner.aura_slot_duration_call_output = Some(output),
                                Err(err) => {
                                    return ChainInformationBuild::Finished {
                                        result: Err(err),
                                        virtual_machine,
                                    };
                                }
                            }
                            virtual_machine
                        }
                        Some(RuntimeCall::AuraApiAuthorities) => {
                            let result = decode_aura_authorities_output(
                                success.virtual_machine.value().as_ref(),
                            );
                            let virtual_machine = success.virtual_machine.into_prototype();
                            match result {
                                Ok(output) => inner.aura_autorities_call_output = Some(output),
                                Err(err) => {
                                    return ChainInformationBuild::Finished {
                                        result: Err(err),
                                        virtual_machine,
                                    };
                                }
                            }
                            virtual_machine
                        }
                        Some(RuntimeCall::BabeApiCurrentEpoch) => {
                            let result = decode_babe_epoch_output(
                                success.virtual_machine.value().as_ref(),
                                false,
                            );
                            let virtual_machine = success.virtual_machine.into_prototype();
                            match result {
                                Ok(output) => inner.babe_current_epoch_call_output = Some(output),
                                Err(err) => {
                                    return ChainInformationBuild::Finished {
                                        result: Err(err),
                                        virtual_machine,
                                    };
                                }
                            }
                            virtual_machine
                        }
                        Some(RuntimeCall::BabeApiNextEpoch) => {
                            let result = decode_babe_epoch_output(
                                success.virtual_machine.value().as_ref(),
                                true,
                            );
                            let virtual_machine = success.virtual_machine.into_prototype();
                            match result {
                                Ok(output) => inner.babe_next_epoch_call_output = Some(output),
                                Err(err) => {
                                    return ChainInformationBuild::Finished {
                                        result: Err(err),
                                        virtual_machine,
                                    };
                                }
                            }
                            virtual_machine
                        }
                        Some(RuntimeCall::BabeApiConfiguration) => {
                            let result = decode_babe_configuration_output(
                                success.virtual_machine.value().as_ref(),
                                inner.runtime_babeapi_is_v1.unwrap(),
                            );
                            let virtual_machine = success.virtual_machine.into_prototype();
                            match result {
                                Ok(output) => inner.babe_configuration_call_output = Some(output),
                                Err(err) => {
                                    return ChainInformationBuild::Finished {
                                        result: Err(err),
                                        virtual_machine,
                                    };
                                }
                            }
                            virtual_machine
                        }
                        Some(RuntimeCall::GrandpaApiAuthorities) => {
                            let result = decode_grandpa_authorities_output(
                                success.virtual_machine.value().as_ref(),
                            );
                            let virtual_machine = success.virtual_machine.into_prototype();
                            match result {
                                Ok(output) => inner.grandpa_autorities_call_output = Some(output),
                                Err(err) => {
                                    return ChainInformationBuild::Finished {
                                        result: Err(err),
                                        virtual_machine,
                                    };
                                }
                            }
                            virtual_machine
                        }
                        Some(RuntimeCall::GrandpaApiCurrentSetId) => {
                            let result = decode_grandpa_current_set_id_output(
                                success.virtual_machine.value().as_ref(),
                            );
                            let virtual_machine = success.virtual_machine.into_prototype();
                            match result {
                                Ok(output) => {
                                    inner.grandpa_current_set_id_call_output = Some(output)
                                }
                                Err(err) => {
                                    return ChainInformationBuild::Finished {
                                        result: Err(err),
                                        virtual_machine,
                                    };
                                }
                            }
                            virtual_machine
                        }
                    });

                    break ChainInformationBuild::start_next_call(inner);
                }
                runtime_call::RuntimeCall::Finished(Err(err)) => {
                    break ChainInformationBuild::Finished {
                        result: Err(Error::WasmVm {
                            call: inner.call_in_progress.unwrap(),
                            error: err.detail,
                        }),
                        virtual_machine: err.prototype,
                    };
                }
                runtime_call::RuntimeCall::StorageGet(call) => {
                    break ChainInformationBuild::InProgress(InProgress::StorageGet(StorageGet(
                        call, inner,
                    )));
                }
                runtime_call::RuntimeCall::NextKey(call) => {
                    break ChainInformationBuild::InProgress(InProgress::NextKey(NextKey(
                        call, inner,
                    )));
                }
                runtime_call::RuntimeCall::ClosestDescendantMerkleValue(call) => {
                    break ChainInformationBuild::InProgress(
                        InProgress::ClosestDescendantMerkleValue(ClosestDescendantMerkleValue(
                            call, inner,
                        )),
                    );
                }
                runtime_call::RuntimeCall::SignatureVerification(sig) => {
                    call = sig.verify_and_resume();
                }
                runtime_call::RuntimeCall::OffchainStorageSet(req) => {
                    // Do nothing.
                    call = req.resume();
                }
                runtime_call::RuntimeCall::Offchain(req) => {
                    let virtual_machine = runtime_call::RuntimeCall::Offchain(req).into_prototype();
                    break ChainInformationBuild::Finished {
                        result: Err(Error::OffchainWorkerHostFunction),
                        virtual_machine,
                    };
                }
                runtime_call::RuntimeCall::LogEmit(req) => {
                    // Generated logs are ignored.
                    call = req.resume();
                }
            }
        }
    }
}

/// Struct shared by all the variants of the [`ChainInformationBuild`] enum. Contains the actual
/// progress of the building.
struct ChainInformationBuildInner {
    /// See [`Config::finalized_block_header`].
    finalized_block_header: ConfigFinalizedBlockHeader,
    /// See [`Config::block_number_bytes`].
    block_number_bytes: usize,

    /// Which call is currently in progress, if any.
    call_in_progress: Option<RuntimeCall>,
    /// Runtime to use to start the calls.
    ///
    /// [`ChainInformationBuildInner::call_in_progress`] and
    /// [`ChainInformationBuildInner::virtual_machine`] are never `Some` at the same time. However,
    /// using an enum wouldn't make the code cleaner because we need to be able to extract the
    /// values temporarily.
    virtual_machine: Option<host::HostVmPrototype>,

    /// If `true`, the runtime supports `AuraApi` functions.
    runtime_has_aura: bool,
    /// If `Some`, the runtime supports `BabeApi` functions. If `true`, the version is 1 (the old
    /// version). If `false`, the version is 2.
    runtime_babeapi_is_v1: Option<bool>,
    /// If `Some`, the runtime supports `GrandpaApi` functions. If `true`, the API supports the
    /// `GrandpaApi_current_set_id` runtime call.
    runtime_grandpa_supports_currentsetid: Option<bool>,

    /// Output of the call to `AuraApi_slot_duration`, if it was already made.
    aura_slot_duration_call_output: Option<NonZero<u64>>,
    /// Output of the call to `AuraApi_authorities`, if it was already made.
    aura_autorities_call_output: Option<Vec<header::AuraAuthority>>,
    /// Output of the call to `BabeApi_current_epoch`, if it was already made.
    babe_current_epoch_call_output: Option<chain_information::BabeEpochInformation>,
    /// Output of the call to `BabeApi_next_epoch`, if it was already made.
    babe_next_epoch_call_output: Option<chain_information::BabeEpochInformation>,
    /// Output of the call to `BabeApi_configuration`, if it was already made.
    babe_configuration_call_output: Option<BabeGenesisConfiguration>,
    /// Output of the call to `GrandpaApi_grandpa_authorities`, if it was already made.
    grandpa_autorities_call_output: Option<Vec<header::GrandpaAuthority>>,
    /// Output of the call to `GrandpaApi_current_set_id`, if it was already made.
    grandpa_current_set_id_call_output: Option<u64>,
}

/// Decodes the output of a call to `AuraApi_slot_duration`.
fn decode_aura_slot_duration_output(bytes: &[u8]) -> Result<NonZero<u64>, Error> {
    <[u8; 8]>::try_from(bytes)
        .ok()
        .and_then(|b| NonZero::<u64>::new(u64::from_le_bytes(b)))
        .ok_or(Error::AuraSlotDurationOutputDecode)
}

/// Decodes the output of a call to `AuraApi_authorities`.
fn decode_aura_authorities_output(
    scale_encoded: &[u8],
) -> Result<Vec<header::AuraAuthority>, Error> {
    match header::AuraAuthoritiesIter::decode(scale_encoded) {
        Ok(iter) => Ok(iter.map(header::AuraAuthority::from).collect::<Vec<_>>()),
        Err(_) => Err(Error::AuraSlotDurationOutputDecode),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BabeGenesisConfiguration {
    slots_per_epoch: NonZero<u64>,
    epoch0_configuration: header::BabeNextConfig,
    epoch0_information: header::BabeNextEpoch,
}

/// Decodes the output of a call to `BabeApi_configuration`.
fn decode_babe_configuration_output(
    bytes: &[u8],
    is_babe_api_v1: bool,
) -> Result<BabeGenesisConfiguration, Error> {
    let result: nom::IResult<_, _> = nom::Parser::parse(
        &mut nom::combinator::all_consuming(nom::combinator::complete(nom::combinator::map(
            (
                nom::number::streaming::le_u64,
                nom::combinator::map_opt(nom::number::streaming::le_u64, NonZero::<u64>::new),
                nom::number::streaming::le_u64,
                nom::number::streaming::le_u64,
                nom::combinator::flat_map(crate::util::nom_scale_compact_usize, |num_elems| {
                    nom::multi::many_m_n(
                        num_elems,
                        num_elems,
                        nom::combinator::map(
                            (
                                nom::bytes::streaming::take(32u32),
                                nom::number::streaming::le_u64,
                            ),
                            move |(public_key, weight)| header::BabeAuthority {
                                public_key: <[u8; 32]>::try_from(public_key).unwrap(),
                                weight,
                            },
                        ),
                    )
                }),
                nom::combinator::map(nom::bytes::streaming::take(32u32), |b| {
                    <[u8; 32]>::try_from(b).unwrap()
                }),
                |b| {
                    if is_babe_api_v1 {
                        nom::Parser::parse(
                            &mut nom::branch::alt((
                                nom::combinator::map(nom::bytes::streaming::tag(&[0][..]), |_| {
                                    header::BabeAllowedSlots::PrimarySlots
                                }),
                                nom::combinator::map(nom::bytes::streaming::tag(&[1][..]), |_| {
                                    header::BabeAllowedSlots::PrimaryAndSecondaryPlainSlots
                                }),
                            )),
                            b,
                        )
                    } else {
                        nom::Parser::parse(
                            &mut nom::branch::alt((
                                nom::combinator::map(nom::bytes::streaming::tag(&[0][..]), |_| {
                                    header::BabeAllowedSlots::PrimarySlots
                                }),
                                nom::combinator::map(nom::bytes::streaming::tag(&[1][..]), |_| {
                                    header::BabeAllowedSlots::PrimaryAndSecondaryPlainSlots
                                }),
                                nom::combinator::map(nom::bytes::streaming::tag(&[2][..]), |_| {
                                    header::BabeAllowedSlots::PrimaryAndSecondaryVrfSlots
                                }),
                            )),
                            b,
                        )
                    }
                },
            ),
            |(_slot_duration, slots_per_epoch, c0, c1, authorities, randomness, allowed_slots)| {
                // Note that the slot duration is unused as it is not modifiable anyway.
                BabeGenesisConfiguration {
                    slots_per_epoch,
                    epoch0_configuration: header::BabeNextConfig {
                        c: (c0, c1),
                        allowed_slots,
                    },
                    epoch0_information: header::BabeNextEpoch {
                        randomness,
                        authorities,
                    },
                }
            },
        ))),
        bytes,
    );

    match result {
        Ok((_, out)) => Ok(out),
        Err(nom::Err::Error(_) | nom::Err::Failure(_)) => Err(Error::BabeConfigurationOutputDecode),
        Err(_) => unreachable!(),
    }
}

/// Decodes the output of a call to `BabeApi_current_epoch` (`is_next_epoch` is `false`) or
/// `BabeApi_next_epoch` (`is_next_epoch` is `true`).
fn decode_babe_epoch_output(
    scale_encoded: &[u8],
    is_next_epoch: bool,
) -> Result<chain_information::BabeEpochInformation, Error> {
    let mut combinator = nom::combinator::all_consuming(nom::combinator::map(
        (
            nom::number::streaming::le_u64,
            nom::number::streaming::le_u64,
            nom::number::streaming::le_u64,
            nom::combinator::flat_map(crate::util::nom_scale_compact_usize, |num_elems| {
                nom::multi::many_m_n(
                    num_elems,
                    num_elems,
                    nom::combinator::map(
                        (
                            nom::bytes::streaming::take(32u32),
                            nom::number::streaming::le_u64,
                        ),
                        move |(public_key, weight)| header::BabeAuthority {
                            public_key: <[u8; 32]>::try_from(public_key).unwrap(),
                            weight,
                        },
                    ),
                )
            }),
            nom::combinator::map(nom::bytes::streaming::take(32u32), |b| {
                <[u8; 32]>::try_from(b).unwrap()
            }),
            nom::number::streaming::le_u64,
            nom::number::streaming::le_u64,
            |b| {
                header::BabeAllowedSlots::from_slice(b)
                    .map(|v| (&[][..], v))
                    .map_err(|_| {
                        nom::Err::Error(nom::error::make_error(b, nom::error::ErrorKind::Verify))
                    })
            },
        ),
        |(
            epoch_index,
            start_slot_number,
            _duration,
            authorities,
            randomness,
            c0,
            c1,
            allowed_slots,
        )| {
            chain_information::BabeEpochInformation {
                epoch_index,
                // Smoldot requires `start_slot_number` to be `None` in the context of next
                // epoch #0, because its start slot number can't be known. The runtime function,
                // however, as it doesn't have a way to represent `None`, instead returns an
                // unspecified value (typically `0`).
                start_slot_number: if !is_next_epoch || epoch_index != 0 {
                    Some(start_slot_number)
                } else {
                    None
                },
                authorities,
                randomness,
                c: (c0, c1),
                allowed_slots,
            }
        },
    ));

    let result: Result<_, nom::Err<nom::error::Error<&[u8]>>> =
        nom::Parser::parse(&mut combinator, scale_encoded);
    match result {
        Ok((_, info)) => Ok(info),
        Err(_) => Err(if is_next_epoch {
            Error::BabeNextEpochOutputDecode
        } else {
            Error::BabeCurrentEpochOutputDecode
        }),
    }
}

/// Decodes the output of a call to `GrandpaApi_grandpa_authorities`, or the content of the
/// `:grandpa_authorities` storage item.
fn decode_grandpa_authorities_output(
    scale_encoded: &[u8],
) -> Result<Vec<header::GrandpaAuthority>, Error> {
    let result: nom::IResult<_, _> = nom::Parser::parse(
        &mut nom::combinator::all_consuming(nom::combinator::complete(nom::combinator::flat_map(
            crate::util::nom_scale_compact_usize,
            |num_elems| {
                nom::multi::fold_many_m_n(
                    num_elems,
                    num_elems,
                    (
                        nom::bytes::streaming::take(32u32),
                        nom::combinator::map_opt(
                            nom::number::streaming::le_u64,
                            NonZero::<u64>::new,
                        ),
                    ),
                    move || Vec::with_capacity(num_elems),
                    |mut acc, (public_key, weight)| {
                        acc.push(header::GrandpaAuthority {
                            public_key: <[u8; 32]>::try_from(public_key).unwrap(),
                            weight,
                        });
                        acc
                    },
                )
            },
        ))),
        scale_encoded,
    );

    match result {
        Ok((_, out)) => Ok(out),
        Err(nom::Err::Error(_) | nom::Err::Failure(_)) => {
            Err(Error::GrandpaAuthoritiesOutputDecode)
        }
        Err(_) => unreachable!(),
    }
}

/// Decodes the output of a call to `GrandpaApi_current_set_id`.
fn decode_grandpa_current_set_id_output(bytes: &[u8]) -> Result<u64, Error> {
    <[u8; 8]>::try_from(bytes)
        .ok()
        .map(u64::from_le_bytes)
        .ok_or(Error::GrandpaCurrentSetIdOutputDecode)
}

#[cfg(test)]
mod tests {
    use crate::header;
    use core::num::NonZero;

    #[test]
    fn decode_babe_epoch_output_sample_decode() {
        // Sample taken from an actual Westend block.
        let sample_data = [
            100, 37, 0, 0, 0, 0, 0, 0, 215, 191, 25, 16, 0, 0, 0, 0, 88, 2, 0, 0, 0, 0, 0, 0, 16,
            102, 85, 132, 42, 246, 238, 38, 228, 88, 181, 254, 162, 211, 181, 190, 178, 221, 140,
            249, 107, 36, 180, 72, 56, 145, 158, 26, 226, 150, 72, 223, 12, 1, 0, 0, 0, 0, 0, 0, 0,
            92, 167, 131, 48, 94, 202, 168, 131, 131, 232, 44, 215, 20, 97, 44, 22, 227, 205, 24,
            232, 243, 118, 34, 15, 45, 159, 187, 181, 132, 214, 138, 105, 1, 0, 0, 0, 0, 0, 0, 0,
            212, 81, 34, 24, 150, 248, 208, 236, 69, 62, 90, 78, 252, 0, 125, 32, 86, 208, 73, 44,
            151, 210, 88, 169, 187, 105, 170, 28, 165, 137, 126, 3, 1, 0, 0, 0, 0, 0, 0, 0, 236,
            198, 169, 213, 112, 57, 219, 36, 157, 140, 107, 231, 182, 155, 98, 72, 224, 156, 194,
            252, 107, 138, 97, 201, 177, 9, 13, 248, 167, 93, 218, 91, 1, 0, 0, 0, 0, 0, 0, 0, 150,
            40, 172, 215, 156, 152, 22, 33, 79, 35, 203, 8, 40, 43, 0, 242, 126, 30, 241, 56, 206,
            56, 36, 189, 60, 22, 121, 195, 168, 34, 207, 236, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0,
            0, 0, 0, 0, 2,
        ];

        super::decode_babe_epoch_output(&sample_data, true).unwrap();
    }

    #[test]
    fn decode_babe_configuration_output_v1() {
        let data = [
            112, 23, 0, 0, 0, 0, 0, 0, 88, 2, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0,
            0, 0, 0, 0, 24, 202, 35, 147, 146, 150, 4, 115, 254, 27, 198, 95, 148, 238, 39, 216,
            144, 164, 156, 27, 32, 12, 0, 111, 245, 220, 197, 37, 51, 14, 204, 22, 119, 1, 0, 0, 0,
            0, 0, 0, 0, 180, 111, 1, 135, 76, 231, 171, 187, 82, 32, 232, 253, 137, 190, 222, 10,
            218, 209, 76, 115, 3, 157, 145, 226, 142, 136, 24, 35, 67, 62, 114, 63, 1, 0, 0, 0, 0,
            0, 0, 0, 214, 132, 217, 23, 109, 110, 182, 152, 135, 84, 12, 154, 137, 250, 96, 151,
            173, 234, 130, 252, 75, 15, 242, 109, 16, 98, 180, 136, 243, 82, 225, 121, 1, 0, 0, 0,
            0, 0, 0, 0, 104, 25, 90, 113, 189, 222, 73, 17, 122, 97, 100, 36, 189, 198, 10, 23, 51,
            233, 106, 203, 29, 165, 174, 171, 93, 38, 140, 242, 165, 114, 233, 65, 1, 0, 0, 0, 0,
            0, 0, 0, 26, 5, 117, 239, 74, 226, 75, 223, 211, 31, 76, 181, 189, 97, 35, 154, 230,
            124, 18, 212, 230, 74, 229, 26, 199, 86, 4, 74, 166, 173, 130, 0, 1, 0, 0, 0, 0, 0, 0,
            0, 24, 22, 143, 42, 173, 0, 129, 162, 87, 40, 150, 30, 224, 6, 39, 207, 227, 94, 57,
            131, 60, 128, 80, 22, 99, 43, 247, 193, 77, 165, 128, 9, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 1,
        ];

        assert_eq!(
            super::decode_babe_configuration_output(&data, true).unwrap(),
            super::BabeGenesisConfiguration {
                slots_per_epoch: NonZero::<u64>::new(600).unwrap(),
                epoch0_configuration: header::BabeNextConfig {
                    allowed_slots: header::BabeAllowedSlots::PrimaryAndSecondaryPlainSlots,
                    c: (1, 4),
                },
                epoch0_information: header::BabeNextEpoch {
                    authorities: vec![
                        header::BabeAuthority {
                            public_key: [
                                202, 35, 147, 146, 150, 4, 115, 254, 27, 198, 95, 148, 238, 39,
                                216, 144, 164, 156, 27, 32, 12, 0, 111, 245, 220, 197, 37, 51, 14,
                                204, 22, 119
                            ],
                            weight: 1
                        },
                        header::BabeAuthority {
                            public_key: [
                                180, 111, 1, 135, 76, 231, 171, 187, 82, 32, 232, 253, 137, 190,
                                222, 10, 218, 209, 76, 115, 3, 157, 145, 226, 142, 136, 24, 35, 67,
                                62, 114, 63
                            ],
                            weight: 1
                        },
                        header::BabeAuthority {
                            public_key: [
                                214, 132, 217, 23, 109, 110, 182, 152, 135, 84, 12, 154, 137, 250,
                                96, 151, 173, 234, 130, 252, 75, 15, 242, 109, 16, 98, 180, 136,
                                243, 82, 225, 121
                            ],
                            weight: 1
                        },
                        header::BabeAuthority {
                            public_key: [
                                104, 25, 90, 113, 189, 222, 73, 17, 122, 97, 100, 36, 189, 198, 10,
                                23, 51, 233, 106, 203, 29, 165, 174, 171, 93, 38, 140, 242, 165,
                                114, 233, 65
                            ],
                            weight: 1
                        },
                        header::BabeAuthority {
                            public_key: [
                                26, 5, 117, 239, 74, 226, 75, 223, 211, 31, 76, 181, 189, 97, 35,
                                154, 230, 124, 18, 212, 230, 74, 229, 26, 199, 86, 4, 74, 166, 173,
                                130, 0
                            ],
                            weight: 1
                        },
                        header::BabeAuthority {
                            public_key: [
                                24, 22, 143, 42, 173, 0, 129, 162, 87, 40, 150, 30, 224, 6, 39,
                                207, 227, 94, 57, 131, 60, 128, 80, 22, 99, 43, 247, 193, 77, 165,
                                128, 9
                            ],
                            weight: 1
                        }
                    ],
                    randomness: [0; 32]
                },
            }
        );
    }
}
