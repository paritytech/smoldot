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
//! This module contains the [`ChainInfoBuild`], a state machine that .

use alloc::vec::Vec;
use core::{fmt, iter, num::NonZeroU64};

use crate::{
    chain::chain_information,
    executor::{host, read_only_runtime_host},
    header, trie,
};

/// Configuration to provide to [`ChainInformationBuild::new`].
pub struct Config {
    /// Header of the finalized block, whose chain information is to retrieve.
    ///
    /// Stored within the chain information at the end.
    pub finalized_block_header: ConfigFinalizedBlockHeader,

    /// Runtime of the finalized block. Must be built using the Wasm code found at the `:code` key
    /// of the block storage.
    pub runtime: host::HostVmPrototype,
}

/// See [`Config::finalized_block_header`].
pub enum ConfigFinalizedBlockHeader {
    /// The block is the genesis block of the chain.
    Genesis {
        /// Hash of the root of the state trie of the genesis.
        state_trie_root_hash: [u8; 32],
    },
    /// The block is not the genesis block of the chain.
    NonGenesis {
        /// Header of the block.
        header: header::Header,
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
    /// Fetching the key that follows a given one is required in order to continue.
    NextKey(NextKey),
}

/// Problem encountered during the chain biulding process.
#[derive(Debug, derive_more::Display)]
pub enum Error {
    /// Error while starting the Wasm virtual machine.
    #[display(fmt = "While calling {:?}: {}", call, error)]
    WasmStart {
        call: RuntimeCall,
        error: host::StartErr,
    },
    /// Error while running the Wasm virtual machine.
    #[display(fmt = "While calling {:?}: {}", call, error)]
    WasmVm {
        call: RuntimeCall,
        error: read_only_runtime_host::ErrorDetail,
    },
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
    /// Failed to decode the output of the `GrandpaApi_authorities` runtime call.
    GrandpaAuthoritiesOutputDecode,
    /// Failed to decode the output of the `GrandpaApi_current_set_id` runtime call.
    GrandpaCurrentSetIdOutputDecode,
    /// The combination of the information retrieved from the runtime doesn't make sense together.
    #[display(fmt = "{}", _0)]
    InvalidChainInformation(chain_information::ValidityError),
    /// No consensus algorithm or multiple consensus algorithms have been detected.
    AmbiguousConsensusAlgorithm,
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
    pub fn parameter_vectored(
        &'_ self,
    ) -> impl Iterator<Item = impl AsRef<[u8]> + Clone + '_> + Clone + '_ {
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
    /// Panics if a [`ConfigFinalizedBlockHeader::NonGenesis`] is provided, and the header has
    /// number 0.
    ///
    pub fn new(config: Config) -> Self {
        // TODO: document
        if let ConfigFinalizedBlockHeader::NonGenesis { header, .. } =
            &config.finalized_block_header
        {
            assert_ne!(header.number, 0);
        }

        // TODO: also check versions?
        let mut runtime_has_aura = false;
        let mut runtime_has_babe = false;
        let mut runtime_has_grandpa = false;
        let aura_api_name = blake2_rfc::blake2b::blake2b(8, &[], b"AuraApi");
        let babe_api_name = blake2_rfc::blake2b::blake2b(8, &[], b"BabeApi");
        let grandpa_api_name = blake2_rfc::blake2b::blake2b(8, &[], b"GrandpaApi");
        for api in config.runtime.runtime_version().decode().apis {
            if api.name_hash == aura_api_name.as_bytes() {
                runtime_has_aura = true;
            } else if api.name_hash == babe_api_name.as_bytes() {
                runtime_has_babe = true;
            } else if api.name_hash == grandpa_api_name.as_bytes() {
                runtime_has_grandpa = true;
            }
        }

        let inner = ChainInformationBuildInner {
            finalized_block_header: config.finalized_block_header,
            call_in_progress: None,
            virtual_machine: Some(config.runtime),
            runtime_has_aura,
            runtime_has_babe,
            runtime_has_grandpa,
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
            InProgress::NextKey(NextKey(_, shared)) => shared,
        };

        ChainInformationBuild::necessary_calls(inner)
    }

    /// Returns the runtime call currently being made.
    pub fn call_in_progress(&self) -> RuntimeCall {
        let inner = match self {
            InProgress::StorageGet(StorageGet(_, shared)) => shared,
            InProgress::NextKey(NextKey(_, shared)) => shared,
        };

        inner.call_in_progress.unwrap()
    }
}

/// Loading a storage value is required in order to continue.
#[must_use]
pub struct StorageGet(
    read_only_runtime_host::StorageGet,
    ChainInformationBuildInner,
);

impl StorageGet {
    /// Returns the key whose value must be passed to [`StorageGet::inject_value`].
    pub fn key(&'_ self) -> impl Iterator<Item = impl AsRef<[u8]> + '_> + '_ {
        self.0.key()
    }

    /// Returns the key whose value must be passed to [`StorageGet::inject_value`].
    ///
    /// This method is a shortcut for calling `key` and concatenating the returned slices.
    pub fn key_as_vec(&self) -> Vec<u8> {
        self.0.key_as_vec()
    }

    /// Injects the corresponding storage value.
    pub fn inject_value(
        self,
        value: Option<impl Iterator<Item = impl AsRef<[u8]>>>,
    ) -> ChainInformationBuild {
        ChainInformationBuild::from_call_in_progress(self.0.inject_value(value), self.1)
    }

    /// Returns the runtime call currently being made.
    pub fn call_in_progress(&self) -> RuntimeCall {
        self.1.call_in_progress.unwrap()
    }
}

/// Fetching the key that follows a given one is required in order to continue.
#[must_use]
pub struct NextKey(read_only_runtime_host::NextKey, ChainInformationBuildInner);

impl NextKey {
    /// Returns the key whose next key must be passed back.
    pub fn key(&'_ self) -> impl AsRef<[u8]> + '_ {
        self.0.key()
    }

    /// Injects the key.
    ///
    /// # Panic
    ///
    /// Panics if the key passed as parameter isn't strictly superior to the requested key.
    ///
    pub fn inject_key(self, key: Option<impl AsRef<[u8]>>) -> ChainInformationBuild {
        ChainInformationBuild::from_call_in_progress(self.0.inject_key(key), self.1)
    }

    /// Returns the runtime call currently being made.
    pub fn call_in_progress(&self) -> RuntimeCall {
        self.1.call_in_progress.unwrap()
    }
}

impl ChainInformationBuild {
    fn necessary_calls(inner: &ChainInformationBuildInner) -> impl Iterator<Item = RuntimeCall> {
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

        let babe_current_epoch = if !matches!(
            inner.finalized_block_header,
            ConfigFinalizedBlockHeader::Genesis { .. }
        ) && inner.runtime_has_babe
            && inner.babe_current_epoch_call_output.is_none()
        {
            Some(RuntimeCall::BabeApiCurrentEpoch)
        } else {
            None
        };

        let babe_next_epoch = if !matches!(
            inner.finalized_block_header,
            ConfigFinalizedBlockHeader::Genesis { .. }
        ) && inner.runtime_has_babe
            && inner.babe_next_epoch_call_output.is_none()
        {
            Some(RuntimeCall::BabeApiNextEpoch)
        } else {
            None
        };

        let babe_configuration =
            if inner.runtime_has_babe && inner.babe_configuration_call_output.is_none() {
                Some(RuntimeCall::BabeApiConfiguration)
            } else {
                None
            };

        let grandpa_authorities = if !matches!(
            inner.finalized_block_header,
            ConfigFinalizedBlockHeader::NonGenesis {
                known_finality: Some(chain_information::ChainInformationFinality::Grandpa { .. }),
                ..
            },
        ) && inner.runtime_has_grandpa
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
            ConfigFinalizedBlockHeader::NonGenesis {
                known_finality: None,
                ..
            },
        ) && inner.runtime_has_grandpa
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
        .filter_map(|c| c)
    }

    fn start_next_call(mut inner: ChainInformationBuildInner) -> Self {
        debug_assert!(inner.call_in_progress.is_none());
        debug_assert!(inner.virtual_machine.is_some());

        if let Some(call) = ChainInformationBuild::necessary_calls(&inner).next() {
            let vm_start_result = read_only_runtime_host::run(read_only_runtime_host::Config {
                function_to_call: call.function_name(),
                parameter: call.parameter_vectored(),
                virtual_machine: inner.virtual_machine.take().unwrap(),
            });

            let vm = match vm_start_result {
                Ok(vm) => vm,
                Err((error, virtual_machine)) => {
                    return ChainInformationBuild::Finished {
                        result: Err(Error::WasmStart { call, error }),
                        virtual_machine,
                    }
                }
            };

            inner.call_in_progress = Some(call);
            ChainInformationBuild::from_call_in_progress(vm, inner)
        } else {
            // If the logic of this module is correct, all the information that we need has been
            // retrieved at this point.

            let consensus = match (
                inner.runtime_has_aura,
                inner.runtime_has_babe,
                &inner.finalized_block_header,
            ) {
                (true, true, _) | (false, false, _) => {
                    return ChainInformationBuild::Finished {
                        result: Err(Error::AmbiguousConsensusAlgorithm),
                        virtual_machine: inner.virtual_machine.take().unwrap(),
                    }
                }
                (false, true, ConfigFinalizedBlockHeader::NonGenesis { .. }) => {
                    chain_information::ChainInformationConsensus::Babe {
                        finalized_block_epoch_information: Some(
                            inner.babe_current_epoch_call_output.take().unwrap(),
                        ),
                        finalized_next_epoch_transition: inner
                            .babe_next_epoch_call_output
                            .take()
                            .unwrap(),
                        slots_per_epoch: inner
                            .babe_configuration_call_output
                            .take()
                            .unwrap()
                            .slots_per_epoch,
                    }
                }
                (false, true, ConfigFinalizedBlockHeader::Genesis { .. }) => {
                    let config = inner.babe_configuration_call_output.take().unwrap();
                    chain_information::ChainInformationConsensus::Babe {
                        slots_per_epoch: config.slots_per_epoch,
                        finalized_block_epoch_information: None,
                        finalized_next_epoch_transition: chain_information::BabeEpochInformation {
                            epoch_index: 0,
                            start_slot_number: None,
                            authorities: config.epoch0_information.authorities,
                            randomness: config.epoch0_information.randomness,
                            c: config.epoch0_configuration.c,
                            allowed_slots: config.epoch0_configuration.allowed_slots,
                        },
                    }
                }
                (true, false, _) => chain_information::ChainInformationConsensus::Aura {
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
                    let header = header::Header {
                        parent_hash: [0; 32],
                        number: 0,
                        state_root: state_trie_root_hash,
                        extrinsics_root: trie::empty_trie_merkle_value(),
                        digest: header::DigestRef::empty().into(),
                    };

                    (header, None)
                }
                ConfigFinalizedBlockHeader::NonGenesis {
                    header,
                    known_finality,
                } => (header, known_finality),
            };

            // Build the finality information if not known yet.
            let finality = if let Some(known_finality) = known_finality {
                known_finality
            } else if inner.runtime_has_grandpa {
                chain_information::ChainInformationFinality::Grandpa {
                    after_finalized_block_authorities_set_id: if finalized_block_header.number == 0
                    {
                        0
                    } else {
                        inner.grandpa_current_set_id_call_output.take().unwrap()
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
                    finalized_block_header,
                    finality,
                    consensus,
                },
            ) {
                Ok(ci) => ci,
                Err(err) => {
                    return ChainInformationBuild::Finished {
                        result: Err(Error::InvalidChainInformation(err)),
                        virtual_machine: inner.virtual_machine.take().unwrap(),
                    }
                }
            };

            ChainInformationBuild::Finished {
                result: Ok(chain_information),
                virtual_machine: inner.virtual_machine.take().unwrap(),
            }
        }
    }

    fn from_call_in_progress(
        mut call: read_only_runtime_host::RuntimeHostVm,
        mut inner: ChainInformationBuildInner,
    ) -> Self {
        loop {
            debug_assert!(inner.call_in_progress.is_some());

            match call {
                read_only_runtime_host::RuntimeHostVm::Finished(Ok(success)) => {
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
                read_only_runtime_host::RuntimeHostVm::Finished(Err(err)) => {
                    break ChainInformationBuild::Finished {
                        result: Err(Error::WasmVm {
                            call: inner.call_in_progress.unwrap(),
                            error: err.detail,
                        }),
                        virtual_machine: err.prototype,
                    }
                }
                read_only_runtime_host::RuntimeHostVm::StorageGet(call) => {
                    break ChainInformationBuild::InProgress(InProgress::StorageGet(StorageGet(
                        call, inner,
                    )))
                }
                read_only_runtime_host::RuntimeHostVm::StorageRoot(get_root) => {
                    call = get_root.resume(match &inner.finalized_block_header {
                        ConfigFinalizedBlockHeader::Genesis {
                            state_trie_root_hash,
                        } => &state_trie_root_hash,
                        ConfigFinalizedBlockHeader::NonGenesis { header, .. } => &header.state_root,
                    })
                }
                read_only_runtime_host::RuntimeHostVm::NextKey(call) => {
                    break ChainInformationBuild::InProgress(InProgress::NextKey(NextKey(
                        call, inner,
                    )))
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

    /// Which call is currently in progress, if any.
    call_in_progress: Option<RuntimeCall>,
    /// Runtime to use to start the calls.
    ///
    /// [`ChainInformationBuildInner::call_in_progress`] and
    /// [`ChainInformationBuildInner::virtual_machine`] are never `Some` at the same time. However,
    /// using an enum wouldn't make the code cleaner because we need to be able to extract the
    /// values temporarily.
    virtual_machine: Option<host::HostVmPrototype>,

    /// If ̀`true`, the runtime supports `AuraApi` functions.
    runtime_has_aura: bool,
    /// If ̀`true`, the runtime supports `BabeApi` functions.
    runtime_has_babe: bool,
    /// If ̀`true`, the runtime supports `GrandpaApi` functions.
    runtime_has_grandpa: bool,

    /// Output of the call to `AuraApi_slot_duration`, if it was already made.
    aura_slot_duration_call_output: Option<NonZeroU64>,
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
fn decode_aura_slot_duration_output(bytes: &[u8]) -> Result<NonZeroU64, Error> {
    <[u8; 8]>::try_from(bytes)
        .ok()
        .and_then(|b| NonZeroU64::new(u64::from_le_bytes(b)))
        .ok_or(Error::AuraSlotDurationOutputDecode)
}

/// Decodes the output of a call to `AuraApi_authorities`.
fn decode_aura_authorities_output(
    scale_encoded: &[u8],
) -> Result<Vec<header::AuraAuthority>, Error> {
    match header::AuraAuthoritiesIter::decode(scale_encoded) {
        Ok(iter) => Ok(iter.map(header::AuraAuthority::from).collect::<Vec<_>>()),
        Err(_) => return Err(Error::AuraSlotDurationOutputDecode),
    }
}

struct BabeGenesisConfiguration {
    slots_per_epoch: NonZeroU64,
    epoch0_configuration: header::BabeNextConfig,
    epoch0_information: header::BabeNextEpoch,
}

/// Decodes the output of a call to `BabeApi_configuration`.
fn decode_babe_configuration_output(bytes: &[u8]) -> Result<BabeGenesisConfiguration, Error> {
    let result: nom::IResult<_, _> =
        nom::combinator::all_consuming(nom::combinator::complete(nom::combinator::map(
            nom::sequence::tuple((
                nom::number::complete::le_u64,
                nom::combinator::map_opt(nom::number::complete::le_u64, NonZeroU64::new),
                nom::number::complete::le_u64,
                nom::number::complete::le_u64,
                nom::combinator::flat_map(crate::util::nom_scale_compact_usize, |num_elems| {
                    nom::multi::many_m_n(
                        num_elems,
                        num_elems,
                        nom::combinator::map(
                            nom::sequence::tuple((
                                nom::bytes::complete::take(32u32),
                                nom::number::complete::le_u64,
                            )),
                            move |(public_key, weight)| header::BabeAuthority {
                                public_key: <[u8; 32]>::try_from(public_key).unwrap(),
                                weight,
                            },
                        ),
                    )
                }),
                nom::combinator::map(nom::bytes::complete::take(32u32), |b| {
                    <[u8; 32]>::try_from(b).unwrap()
                }),
                nom::branch::alt((
                    nom::combinator::map(nom::bytes::complete::tag(&[0]), |_| {
                        header::BabeAllowedSlots::PrimarySlots
                    }),
                    nom::combinator::map(nom::bytes::complete::tag(&[1]), |_| {
                        header::BabeAllowedSlots::PrimaryAndSecondaryPlainSlots
                    }),
                    nom::combinator::map(nom::bytes::complete::tag(&[2]), |_| {
                        header::BabeAllowedSlots::PrimaryAndSecondaryVrfSlots
                    }),
                )),
            )),
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
        )))(bytes);

    match result {
        Ok((_, out)) => Ok(out),
        Err(nom::Err::Error(_) | nom::Err::Failure(_)) => Err(Error::BabeConfigurationOutputDecode),
        Err(_) => unreachable!(),
    }
}

/// Decodes the output of a call to `BabeApi_current_epoch` (`is_next_epoch` is `false`) or
/// `BabeApi_next_epoch` (`is_next_epoch` is `true`).
fn decode_babe_epoch_output(
    scale_encoded: &'_ [u8],
    is_next_epoch: bool,
) -> Result<chain_information::BabeEpochInformation, Error> {
    let mut combinator = nom::combinator::all_consuming(nom::combinator::map(
        nom::sequence::tuple((
            nom::number::complete::le_u64,
            nom::number::complete::le_u64,
            nom::number::complete::le_u64,
            nom::combinator::flat_map(crate::util::nom_scale_compact_usize, |num_elems| {
                nom::multi::many_m_n(
                    num_elems,
                    num_elems,
                    nom::combinator::map(
                        nom::sequence::tuple((
                            nom::bytes::complete::take(32u32),
                            nom::number::complete::le_u64,
                        )),
                        move |(public_key, weight)| header::BabeAuthority {
                            public_key: <[u8; 32]>::try_from(public_key).unwrap(),
                            weight,
                        },
                    ),
                )
            }),
            nom::combinator::map(nom::bytes::complete::take(32u32), |b| {
                <[u8; 32]>::try_from(b).unwrap()
            }),
            nom::number::complete::le_u64,
            nom::number::complete::le_u64,
            |b| {
                header::BabeAllowedSlots::from_slice(b)
                    .map(|v| (&[][..], v))
                    .map_err(|_| {
                        nom::Err::Error(nom::error::make_error(b, nom::error::ErrorKind::Verify))
                    })
            },
        )),
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

    let result: Result<_, nom::Err<nom::error::Error<&'_ [u8]>>> = combinator(scale_encoded);
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
    let result: nom::IResult<_, _> = nom::combinator::all_consuming(nom::combinator::complete(
        nom::combinator::flat_map(crate::util::nom_scale_compact_usize, |num_elems| {
            nom::multi::fold_many_m_n(
                num_elems,
                num_elems,
                nom::sequence::tuple((
                    nom::bytes::complete::take(32u32),
                    nom::combinator::map_opt(nom::number::complete::le_u64, NonZeroU64::new),
                )),
                move || Vec::with_capacity(num_elems),
                |mut acc, (public_key, weight)| {
                    acc.push(header::GrandpaAuthority {
                        public_key: <[u8; 32]>::try_from(public_key).unwrap(),
                        weight,
                    });
                    acc
                },
            )
        }),
    ))(scale_encoded);

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
        .map(|b| u64::from_le_bytes(b))
        .ok_or(Error::GrandpaCurrentSetIdOutputDecode)
}

#[cfg(test)]
mod tests {
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
}
