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

use crate::{
    chain::chain_information,
    executor::{self, host, runtime_host, storage_diff, vm},
    header,
    trie::calculate_root,
    util,
    verify::{aura, babe, inherents},
};

use alloc::{string::String, vec::Vec};
use core::{iter, num::NonZeroU64, time::Duration};

/// Configuration for a block verification.
pub struct Config<'a, TBody> {
    /// Runtime used to check the new block. Must be built using the `:code` of the parent
    /// block.
    pub parent_runtime: host::HostVmPrototype,

    /// Header of the parent of the block to verify.
    ///
    /// The hash of this header must be the one referenced in [`Config::block_header`].
    pub parent_block_header: header::HeaderRef<'a>,

    /// Configuration items related to the consensus engine.
    pub consensus: ConfigConsensus<'a>,

    /// Time elapsed since [the Unix Epoch](https://en.wikipedia.org/wiki/Unix_time) (i.e.
    /// 00:00:00 UTC on 1 January 1970), ignoring leap seconds.
    pub now_from_unix_epoch: Duration,

    /// Header of the block to verify.
    ///
    /// The `parent_hash` field is the hash of the parent whose storage can be accessed through
    /// the other fields.
    pub block_header: header::HeaderRef<'a>,

    /// Body of the block to verify.
    pub block_body: TBody,

    /// Optional cache corresponding to the storage trie root hash calculation of the parent
    /// block.
    pub top_trie_root_calculation_cache: Option<calculate_root::CalculationCache>,
}

/// Extra items of [`Config`] that are dependant on the consensus engine of the chain.
pub enum ConfigConsensus<'a> {
    /// Any node on the chain is allowed to produce blocks.
    ///
    /// No seal must be present in the header.
    ///
    /// > **Note**: Be warned that this variant makes it possible for a huge number of blocks to
    /// >           be produced. If this variant is used, the user is encouraged to limit, through
    /// >           other means, the number of blocks being accepted.
    AllAuthorized,

    /// Chain is using the Aura consensus engine.
    Aura {
        /// Aura authorities that must validate the block.
        ///
        /// This list is either equal to the parent's list, or, if the parent changes the list of
        /// authorities, equal to that new modified list.
        current_authorities: header::AuraAuthoritiesIter<'a>,

        /// Duration of a slot in milliseconds.
        /// Can be found by calling the `AuraApi_slot_duration` runtime function.
        slot_duration: NonZeroU64,
    },

    /// Chain is using the Babe consensus engine.
    Babe {
        /// Number of slots per epoch in the Babe configuration.
        slots_per_epoch: NonZeroU64,

        /// Epoch the parent block belongs to. Must be `None` if and only if the parent block's
        /// number is 0, as block #0 doesn't belong to any epoch.
        parent_block_epoch: Option<chain_information::BabeEpochInformationRef<'a>>,

        /// Epoch that follows the epoch the parent block belongs to.
        parent_block_next_epoch: chain_information::BabeEpochInformationRef<'a>,
    },
}

/// Block successfully verified.
pub struct Success {
    /// Runtime that was passed by [`Config`].
    pub parent_runtime: host::HostVmPrototype,

    /// Contains `Some` if and only if [`Success::storage_top_trie_changes`] contains a change in
    /// the `:code` or `:heappages` keys, indicating that the runtime has been modified. Contains
    /// the new runtime.
    pub new_runtime: Option<host::HostVmPrototype>,

    /// Extra items in [`Success`] relevant to the consensus engine.
    pub consensus: SuccessConsensus,

    /// List of changes to the storage top trie that the block performs.
    pub storage_top_trie_changes: storage_diff::StorageDiff,

    /// List of changes to the off-chain storage that this block performs.
    pub offchain_storage_changes: storage_diff::StorageDiff,

    /// Cache used for calculating the top trie root.
    pub top_trie_root_calculation_cache: calculate_root::CalculationCache,

    /// Concatenation of all the log messages printed by the runtime.
    pub logs: String,
}

/// Extra items in [`Success`] relevant to the consensus engine.
pub enum SuccessConsensus {
    /// [`ConfigConsensus::AllAuthorized`] was passed to [`Config`].
    AllAuthorized,

    /// Chain is using the Aura consensus engine.
    Aura {
        /// True if the list of authorities is modified by this block.
        authorities_change: bool,
    },

    /// Chain is using the Babe consensus engine.
    Babe {
        /// Slot number the block belongs to.
        ///
        /// > **Note**: This is a simple reminder. The value can also be found in the header of the
        /// >           block.
        slot_number: u64,

        /// If `Some`, the verified block contains an epoch transition describing the new
        /// "next epoch". When verifying blocks that are children of this one, the value in this
        /// field must be provided as [`ConfigConsensus::Babe::parent_block_next_epoch`], and the
        /// value previously in [`ConfigConsensus::Babe::parent_block_next_epoch`] must instead be
        /// passed as [`ConfigConsensus::Babe::parent_block_epoch`].
        epoch_transition_target: Option<chain_information::BabeEpochInformation>,
    },
}

/// Error that can happen during the verification.
#[derive(Debug, derive_more::Display)]
pub enum Error {
    /// Error while starting the Wasm virtual machine to execute the block.
    #[display(fmt = "{}", _0)]
    WasmStart(host::StartErr),
    /// Error while running the Wasm virtual machine to execute the block.
    #[display(fmt = "{}", _0)]
    WasmVm(runtime_host::ErrorDetail),
    /// Runtime has returned some errors when verifying inherents.
    #[display(
        fmt = "Runtime has returned some errors when verifying inherents: {:?}",
        errors
    )]
    CheckInherentsError {
        /// List of errors produced by the runtime.
        ///
        /// The first element of each tuple is an identifier of the module that produced the
        /// error, while the second element is a SCALE-encoded piece of data.
        ///
        /// Due to the fact that errors are not supposed to happen, and that the format of errors
        /// has changed depending on runtime versions, no utility is provided to decode them.
        errors: Vec<([u8; 8], Vec<u8>)>,
    },
    /// Failed to parse the output of `BlockBuilder_check_inherents`.
    CheckInherentsOutputParseFailure,
    /// Output of `Core_execute_block` wasn't empty.
    NonEmptyOutput,
    /// Block header contains items relevant to multiple consensus engines at the same time.
    MultipleConsensusEngines,
    /// Failed to verify the authenticity of the block with the AURA algorithm.
    #[display(fmt = "{}", _0)]
    AuraVerification(aura::VerifyError),
    /// Failed to verify the authenticity of the block with the BABE algorithm.
    #[display(fmt = "{}", _0)]
    BabeVerification(babe::VerifyError),
    /// Error while compiling new runtime.
    NewRuntimeCompilationError(host::NewErr),
    /// Block being verified has erased the `:code` key from the storage.
    CodeKeyErased,
    /// Block has modified the `:heappages` key in a way that fails to parse.
    HeapPagesParseError(executor::InvalidHeapPagesError),
    /// Block has modified the `:heappages` key without modifying the `:code` key. This isn't
    /// supported by smoldot.
    // TODO: this is something that we should support but don't because it's annoying to implement and is clearly not worth the effort
    HeapPagesOnlyModification,
}

/// Verifies whether a block is valid.
pub fn verify(
    config: Config<impl ExactSizeIterator<Item = impl AsRef<[u8]> + Clone> + Clone>,
) -> Verify {
    // Start the consensus engine verification process.
    let consensus_success = match &config.consensus {
        ConfigConsensus::AllAuthorized => {
            // `has_any_aura()` and `has_any_babe()` also make sure that no seal is present.
            if config.block_header.digest.has_any_aura()
                || config.block_header.digest.has_any_babe()
            {
                return Verify::Finished(Err((
                    Error::MultipleConsensusEngines,
                    config.parent_runtime,
                )));
            }

            SuccessConsensus::AllAuthorized
        }
        ConfigConsensus::Aura {
            current_authorities,
            slot_duration,
        } => {
            if config.block_header.digest.has_any_babe() {
                return Verify::Finished(Err((
                    Error::MultipleConsensusEngines,
                    config.parent_runtime,
                )));
            }

            let result = aura::verify_header(aura::VerifyConfig {
                header: config.block_header.clone(),
                parent_block_header: config.parent_block_header,
                now_from_unix_epoch: config.now_from_unix_epoch,
                current_authorities: current_authorities.clone(),
                slot_duration: *slot_duration,
            });

            match result {
                Ok(s) => SuccessConsensus::Aura {
                    authorities_change: s.authorities_change,
                },
                Err(err) => {
                    return Verify::Finished(Err((
                        Error::AuraVerification(err),
                        config.parent_runtime,
                    )))
                }
            }
        }
        ConfigConsensus::Babe {
            parent_block_epoch,
            parent_block_next_epoch,
            slots_per_epoch,
        } => {
            if config.block_header.digest.has_any_aura() {
                return Verify::Finished(Err((
                    Error::MultipleConsensusEngines,
                    config.parent_runtime,
                )));
            }

            let result = babe::verify_header(babe::VerifyConfig {
                header: config.block_header.clone(),
                parent_block_header: config.parent_block_header,
                parent_block_next_epoch: parent_block_next_epoch.clone(),
                parent_block_epoch: parent_block_epoch.clone(),
                slots_per_epoch: *slots_per_epoch,
                now_from_unix_epoch: config.now_from_unix_epoch,
            });

            match result {
                Ok(s) => SuccessConsensus::Babe {
                    epoch_transition_target: s.epoch_transition_target,
                    slot_number: s.slot_number,
                },
                Err(err) => {
                    return Verify::Finished(Err((
                        Error::BabeVerification(err),
                        config.parent_runtime,
                    )))
                }
            }
        }
    };

    // Now that we have verified the header, we need to call two runtime functions:
    //
    // - `BlockBuilder_check_inherents`, which does some basic verification of the inherents
    //   contained in the block.
    // - `Core_execute_block`, which goes through transactions and makes sure that everything is
    //   valid.
    //
    // The first parameter of these two runtime functions is the same: a SCALE-encoded
    // `(header, body)` where `body` is a `Vec<Extrinsic>`. We perform the encoding ahead of time
    // in order to re-use it later for the second call.
    let block_parameter = {
        // Consensus engines add a seal at the end of the digest logs. This seal is guaranteed to
        // be the last item. We need to remove it before we can verify the unsealed header.
        let mut unsealed_header = config.block_header.clone();
        let _seal_log = unsealed_header.digest.pop_seal();

        let encoded_body_len = util::encode_scale_compact_usize(config.block_body.len());
        unsealed_header
            .scale_encoding()
            .map(|b| either::Right(either::Left(b)))
            .chain(iter::once(either::Right(either::Right(encoded_body_len))))
            .chain(config.block_body.map(either::Left))
            .fold(Vec::with_capacity(8192), |mut a, b| {
                // TODO: better capacity ^ ?
                a.extend_from_slice(AsRef::<[u8]>::as_ref(&b));
                a
            })
    };

    // Start the virtual machine with `BlockBuilder_check_inherents`.
    let check_inherents_process = {
        // The second parameter of `BlockBuilder_check_inherents` contains information such as
        // the current timestamp.
        // TODO: uncles?! it's a weird inherent as even in Substrate it's half implemented
        let inherent_data = inherents::InherentData {
            timestamp: u64::try_from(config.now_from_unix_epoch.as_millis())
                .unwrap_or(u64::max_value()),
        };

        let vm = runtime_host::run(runtime_host::Config {
            virtual_machine: config.parent_runtime,
            function_to_call: "BlockBuilder_check_inherents",
            parameter: {
                // The `BlockBuilder_check_inherents` function expects a SCALE-encoded list of
                // tuples containing an "inherent identifier" (`[u8; 8]`) and a value (`Vec<u8>`).
                let list = inherent_data.as_raw_list();
                let len = util::encode_scale_compact_usize(list.len());
                let encoded_list = list.flat_map(|(id, value)| {
                    let value_len = util::encode_scale_compact_usize(value.as_ref().len());
                    let value_and_len = iter::once(value_len)
                        .map(either::Left)
                        .chain(iter::once(value).map(either::Right));
                    iter::once(id)
                        .map(either::Left)
                        .chain(value_and_len.map(either::Right))
                });

                [either::Left(&block_parameter), either::Right(len)]
                    .into_iter()
                    .map(either::Left)
                    .chain(encoded_list.map(either::Right))
            },
            top_trie_root_calculation_cache: config.top_trie_root_calculation_cache,
            storage_top_trie_changes: Default::default(),
            offchain_storage_changes: Default::default(),
        });

        match vm {
            Ok(vm) => vm,
            Err((error, prototype)) => {
                return Verify::Finished(Err((Error::WasmStart(error), prototype)))
            }
        }
    };

    VerifyInner {
        inner: check_inherents_process,
        execution_not_started: Some(block_parameter),
        consensus_success,
    }
    .run()
}

/// Current state of the verification.
#[must_use]
pub enum Verify {
    /// Verification is over.
    ///
    /// In case of error, also contains the value that was passed through
    /// [`Config::parent_runtime`].
    Finished(Result<Success, (Error, host::HostVmPrototype)>),
    /// A new runtime must be compiled.
    ///
    /// This variant doesn't require any specific input from the user, but is provided in order to
    /// make it possible to benchmark the time it takes to compile runtimes.
    RuntimeCompilation(RuntimeCompilation),
    /// Loading a storage value is required in order to continue.
    StorageGet(StorageGet),
    /// Fetching the list of keys with a given prefix is required in order to continue.
    StoragePrefixKeys(StoragePrefixKeys),
    /// Fetching the key that follows a given one is required in order to continue.
    StorageNextKey(StorageNextKey),
}

struct VerifyInner {
    inner: runtime_host::RuntimeHostVm,
    /// If `Some`, then we are currently checking inherents, and this field contains the parameter
    /// to later pass when invoking `Core_execute_block`. If `None`, then we are currently
    /// executing the block.
    execution_not_started: Option<Vec<u8>>,
    consensus_success: SuccessConsensus,
}

impl VerifyInner {
    fn run(mut self) -> Verify {
        loop {
            match self.inner {
                runtime_host::RuntimeHostVm::Finished(Err(err)) => {
                    break Verify::Finished(Err((Error::WasmVm(err.detail), err.prototype)))
                }
                runtime_host::RuntimeHostVm::Finished(Ok(success))
                    if self.execution_not_started.is_some() =>
                {
                    // Check the output of the `BlockBuilder_check_inherents` runtime call.
                    let check_inherents_result =
                        check_check_inherents_output(success.virtual_machine.value().as_ref());
                    if let Err(err) = check_inherents_result {
                        return Verify::Finished(Err((
                            err,
                            success.virtual_machine.into_prototype(),
                        )));
                    }

                    // Switch to phase 2: calling `Core_execute_block`.
                    let import_process = {
                        let vm = runtime_host::run(runtime_host::Config {
                            virtual_machine: success.virtual_machine.into_prototype(),
                            function_to_call: "Core_execute_block",
                            parameter: iter::once(&self.execution_not_started.as_ref().unwrap()),
                            top_trie_root_calculation_cache: Some(
                                success.top_trie_root_calculation_cache,
                            ),
                            storage_top_trie_changes: success.storage_top_trie_changes,
                            offchain_storage_changes: success.offchain_storage_changes,
                        });

                        match vm {
                            Ok(vm) => vm,
                            Err((error, prototype)) => {
                                return Verify::Finished(Err((Error::WasmStart(error), prototype)))
                            }
                        }
                    };

                    self = VerifyInner {
                        consensus_success: self.consensus_success,
                        execution_not_started: None,
                        inner: import_process,
                    };
                }
                runtime_host::RuntimeHostVm::Finished(Ok(success)) => {
                    if !success.virtual_machine.value().as_ref().is_empty() {
                        return Verify::Finished(Err((
                            Error::NonEmptyOutput,
                            success.virtual_machine.into_prototype(),
                        )));
                    }

                    match (
                        success.storage_top_trie_changes.diff_get(&b":code"[..]),
                        success
                            .storage_top_trie_changes
                            .diff_get(&b":heappages"[..]),
                    ) {
                        (None, None) => {}
                        (Some(None), _) => {
                            return Verify::Finished(Err((
                                Error::CodeKeyErased,
                                success.virtual_machine.into_prototype(),
                            )))
                        }
                        (None, Some(_)) => {
                            return Verify::Finished(Err((
                                Error::HeapPagesOnlyModification,
                                success.virtual_machine.into_prototype(),
                            )))
                        }
                        (Some(Some(_code)), heap_pages) => {
                            let parent_runtime = success.virtual_machine.into_prototype();

                            let heap_pages = match heap_pages {
                                Some(heap_pages) => {
                                    match executor::storage_heap_pages_to_value(heap_pages) {
                                        Ok(hp) => hp,
                                        Err(err) => {
                                            return Verify::Finished(Err((
                                                Error::HeapPagesParseError(err),
                                                parent_runtime,
                                            )))
                                        }
                                    }
                                }
                                None => parent_runtime.heap_pages(),
                            };

                            return Verify::RuntimeCompilation(RuntimeCompilation {
                                consensus_success: self.consensus_success,
                                parent_runtime,
                                heap_pages,
                                logs: success.logs,
                                offchain_storage_changes: success.offchain_storage_changes,
                                storage_top_trie_changes: success.storage_top_trie_changes,
                                top_trie_root_calculation_cache: success
                                    .top_trie_root_calculation_cache,
                            });
                        }
                    }

                    break Verify::Finished(Ok(Success {
                        parent_runtime: success.virtual_machine.into_prototype(),
                        new_runtime: None,
                        consensus: self.consensus_success,
                        storage_top_trie_changes: success.storage_top_trie_changes,
                        offchain_storage_changes: success.offchain_storage_changes,
                        top_trie_root_calculation_cache: success.top_trie_root_calculation_cache,
                        logs: success.logs,
                    }));
                }
                runtime_host::RuntimeHostVm::StorageGet(inner) => {
                    break Verify::StorageGet(StorageGet {
                        inner,
                        execution_not_started: self.execution_not_started,
                        consensus_success: self.consensus_success,
                    })
                }
                runtime_host::RuntimeHostVm::PrefixKeys(inner) => {
                    break Verify::StoragePrefixKeys(StoragePrefixKeys {
                        inner,
                        execution_not_started: self.execution_not_started,
                        consensus_success: self.consensus_success,
                    })
                }
                runtime_host::RuntimeHostVm::NextKey(inner) => {
                    break Verify::StorageNextKey(StorageNextKey {
                        inner,
                        execution_not_started: self.execution_not_started,
                        consensus_success: self.consensus_success,
                    })
                }
            }
        }
    }
}

/// Loading a storage value is required in order to continue.
#[must_use]
pub struct StorageGet {
    inner: runtime_host::StorageGet,
    /// See [`VerifyInner::execution_not_started`].
    execution_not_started: Option<Vec<u8>>,
    consensus_success: SuccessConsensus,
}

impl StorageGet {
    /// Returns the key whose value must be passed to [`StorageGet::inject_value`].
    pub fn key(&'_ self) -> impl Iterator<Item = impl AsRef<[u8]> + '_> + '_ {
        self.inner.key()
    }

    /// Returns the key whose value must be passed to [`StorageGet::inject_value`].
    ///
    /// This method is a shortcut for calling `key` and concatenating the returned slices.
    pub fn key_as_vec(&self) -> Vec<u8> {
        self.inner.key_as_vec()
    }

    /// Injects the corresponding storage value.
    pub fn inject_value(self, value: Option<impl Iterator<Item = impl AsRef<[u8]>>>) -> Verify {
        VerifyInner {
            inner: self.inner.inject_value(value),
            execution_not_started: self.execution_not_started,
            consensus_success: self.consensus_success,
        }
        .run()
    }
}

/// Fetching the list of keys with a given prefix is required in order to continue.
#[must_use]
pub struct StoragePrefixKeys {
    inner: runtime_host::PrefixKeys,
    /// See [`VerifyInner::execution_not_started`].
    execution_not_started: Option<Vec<u8>>,
    consensus_success: SuccessConsensus,
}

impl StoragePrefixKeys {
    /// Returns the prefix whose keys to load.
    pub fn prefix(&'_ self) -> impl AsRef<[u8]> + '_ {
        self.inner.prefix()
    }

    /// Injects the list of keys ordered lexicographically.
    pub fn inject_keys_ordered(self, keys: impl Iterator<Item = impl AsRef<[u8]>>) -> Verify {
        VerifyInner {
            inner: self.inner.inject_keys_ordered(keys),
            execution_not_started: self.execution_not_started,
            consensus_success: self.consensus_success,
        }
        .run()
    }
}

/// Fetching the key that follows a given one is required in order to continue.
#[must_use]
pub struct StorageNextKey {
    inner: runtime_host::NextKey,
    /// See [`VerifyInner::execution_not_started`].
    execution_not_started: Option<Vec<u8>>,
    consensus_success: SuccessConsensus,
}

impl StorageNextKey {
    /// Returns the key whose next key must be passed back.
    pub fn key(&'_ self) -> impl AsRef<[u8]> + '_ {
        self.inner.key()
    }

    /// Injects the key.
    ///
    /// # Panic
    ///
    /// Panics if the key passed as parameter isn't strictly superior to the requested key.
    ///
    pub fn inject_key(self, key: Option<impl AsRef<[u8]>>) -> Verify {
        VerifyInner {
            inner: self.inner.inject_key(key),
            execution_not_started: self.execution_not_started,
            consensus_success: self.consensus_success,
        }
        .run()
    }
}

/// A new runtime must be compiled.
///
/// This variant doesn't require any specific input from the user, but is provided in order to
/// make it possible to benchmark the time it takes to compile runtimes.
#[must_use]
pub struct RuntimeCompilation {
    parent_runtime: host::HostVmPrototype,
    storage_top_trie_changes: storage_diff::StorageDiff,
    offchain_storage_changes: storage_diff::StorageDiff,
    top_trie_root_calculation_cache: calculate_root::CalculationCache,
    logs: String,
    heap_pages: vm::HeapPages,
    consensus_success: SuccessConsensus,
}

impl RuntimeCompilation {
    /// Performs the runtime compilation.
    pub fn build(self) -> Verify {
        // A `RuntimeCompilation` object is built only if `:code` has been modified and to a
        // specific value.
        let code = self
            .storage_top_trie_changes
            .diff_get(&b":code"[..])
            .unwrap()
            .unwrap();

        let new_runtime = match host::HostVmPrototype::new(host::Config {
            module: code,
            heap_pages: self.heap_pages,
            exec_hint: vm::ExecHint::CompileAheadOfTime,
            allow_unresolved_imports: false,
        }) {
            Ok(vm) => vm,
            Err(err) => {
                return Verify::Finished(Err((
                    Error::NewRuntimeCompilationError(err),
                    self.parent_runtime,
                )))
            }
        };

        Verify::Finished(Ok(Success {
            parent_runtime: self.parent_runtime,
            new_runtime: Some(new_runtime),
            consensus: self.consensus_success,
            storage_top_trie_changes: self.storage_top_trie_changes,
            offchain_storage_changes: self.offchain_storage_changes,
            top_trie_root_calculation_cache: self.top_trie_root_calculation_cache,
            logs: self.logs,
        }))
    }
}

/// Checks the output of the `BlockBuilder_check_inherents` runtime call.
fn check_check_inherents_output(output: &[u8]) -> Result<(), Error> {
    // The format of the output of `check_inherents` consists of two booleans and a list of
    // errors.
    // We don't care about the value of the two booleans, and they are ignored during the parsing.
    // Because we don't pass as parameter the `auraslot` or `babeslot`, errors will be generated
    // on older runtimes that expect these values. For this reason, errors concerning `auraslot`
    // and `babeslot` are ignored.
    let parser = nom::sequence::preceded(
        nom::sequence::tuple((crate::util::nom_bool_decode, crate::util::nom_bool_decode)),
        nom::combinator::flat_map(crate::util::nom_scale_compact_usize, |num_elems| {
            nom::multi::fold_many_m_n(
                num_elems,
                num_elems,
                nom::sequence::tuple((
                    nom::combinator::map(nom::bytes::complete::take(8u8), |b| {
                        <[u8; 8]>::try_from(b).unwrap()
                    }),
                    crate::util::nom_bytes_decode,
                )),
                Vec::new,
                |mut errors, (module, error)| {
                    if module != *b"auraslot" && module != *b"babeslot" {
                        errors.push((module, error.to_vec()));
                    }
                    errors
                },
            )
        }),
    );

    match nom::combinator::all_consuming::<_, _, nom::error::Error<&[u8]>, _>(parser)(output) {
        Err(_err) => Err(Error::CheckInherentsOutputParseFailure),
        Ok((_, errors)) => {
            if errors.is_empty() {
                Ok(())
            } else {
                Err(Error::CheckInherentsError { errors })
            }
        }
    }
}
