// Smoldot
// Copyright (C) 2019-2020  Parity Technologies (UK) Ltd.
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

//! Block generation system.
//!
//! This module provides the actual block generation code. The output is an unsealed header and
//! body.
//!
//! After a block has been generated, it must still be sealed (in other words, signed by its
//! author) by adding a corresponding entry to the log items in its header. This is out of scope
//! of this module.
//!
//! # Detail
//!
//! Building a block consists in four steps:
//!
//! - A runtime call to `Core_initialize_block`, passing a header prototype as input. This call
//!   performs some initial storage writes.
//! - A runtime call to `BlockBuilder_inherent_extrinsics`, passing as input a list of
//!   *intrinsics*. This pure call returns a list of extrinsics.
//! - Zero or more runtime calls to `BlockBuilder_apply_extrinsic`, passing as input an extrinsic.
//!   This must be done once per extrinsic returned by the previous step, plus once for each
//!   transaction to push in the block.
//! - A runtime call to `BlockBuilder_finalize_block`, which returns the newly-created unsealed
//!   block header.
//!
//! The body of the newly-generated block consists in the extrinsics pushed using
//! `BlockBuilder_apply_extrinsic` (including the intrinsics).
//!

// TODO: expand docs
// TODO: explain what an inherent extrinsic is

mod tests;

use crate::{
    executor::{host, runtime_call},
    header, util,
    verify::inherents,
};

use alloc::{borrow::ToOwned as _, vec::Vec};
use core::{iter, mem, slice};

pub use runtime_call::{
    Nibble, StorageChanges, TrieChange, TrieChangeStorageValue, TrieEntryVersion,
};

/// Configuration for a block generation.
pub struct Config<'a> {
    /// Number of bytes used to encode block numbers in the header.
    pub block_number_bytes: usize,

    /// Hash of the parent of the block to generate.
    ///
    /// Used to populate the header of the new block.
    pub parent_hash: &'a [u8; 32],

    /// Height of the parent of the block to generate.
    ///
    /// Used to populate the header of the new block.
    pub parent_number: u64,

    /// Runtime used to check the new block. Must be built using the Wasm code found at the
    /// `:code` key of the parent block storage.
    pub parent_runtime: host::HostVmPrototype,

    /// Consensus-specific item to put in the digest of the header prototype.
    ///
    /// > **Note**: In the case of Aura and Babe, contains the slot being claimed.
    pub consensus_digest_log_item: ConfigPreRuntime<'a>,

    /// Capacity to reserve for the number of extrinsics. Should be higher than the approximate
    /// number of extrinsics that are going to be applied.
    pub block_body_capacity: usize,

    /// Maximum log level of the runtime.
    ///
    /// > **Note**: This value is opaque from the point of the view of the client, and the runtime
    /// >           is free to interpret it the way it wants. However, usually values are: `0` for
    /// >           "off", `1` for "error", `2` for "warn", `3` for "info", `4` for "debug",
    /// >           and `5` for "trace".
    pub max_log_level: u32,

    /// If `true`, then [`StorageChanges::trie_changes_iter_ordered`] will return `Some`.
    /// Passing `None` requires fewer calculation and fewer storage accesses.
    pub calculate_trie_changes: bool,
}

/// Extra configuration depending on the consensus algorithm.
// TODO: consider not exposing `header` in the API
pub enum ConfigPreRuntime<'a> {
    /// Chain uses the Aura consensus algorithm.
    Aura(header::AuraPreDigest),
    /// Chain uses the Babe consensus algorithm.
    Babe(header::BabePreDigestRef<'a>),
}

/// Block successfully verified.
pub struct Success {
    /// SCALE-encoded header of the produced block.
    pub scale_encoded_header: Vec<u8>,
    /// Body of the produced block.
    pub body: Vec<Vec<u8>>,
    /// Runtime that was passed by [`Config`].
    pub parent_runtime: host::HostVmPrototype,
    /// List of changes to the storage main trie that the block performs.
    pub storage_changes: StorageChanges,
    /// State trie version indicated by the runtime. All the storage changes indicated by
    /// [`Success::storage_changes`] should store this version alongside with them.
    pub state_trie_version: TrieEntryVersion,
}

/// Error that can happen during the block production.
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum Error {
    /// Error while executing the Wasm virtual machine.
    #[display("{_0}")]
    WasmVm(runtime_call::ErrorDetail),
    /// Error while initializing the Wasm virtual machine.
    #[display("{_0}")]
    VmInit(host::StartErr),
    /// Overflow when incrementing block height.
    BlockHeightOverflow,
    /// `Core_initialize_block` has returned a non-empty output.
    InitializeBlockNonEmptyOutput,
    /// Error while parsing output of `BlockBuilder_inherent_extrinsics`.
    BadInherentExtrinsicsOutput,
    /// Error while parsing output of `BlockBuilder_apply_extrinsic`.
    BadApplyExtrinsicOutput,
    /// Applying an inherent extrinsic has returned a [`DispatchError`].
    #[display("Error while applying inherent extrinsic: {error}\nExtrinsic: {extrinsic:?}")]
    InherentExtrinsicDispatchError {
        /// Extrinsic that triggered the problem.
        extrinsic: Vec<u8>,
        /// Error returned by the runtime.
        #[error(source)]
        error: DispatchError,
    },
    /// Applying an inherent extrinsic has returned a [`TransactionValidityError`].
    #[display("Error while applying inherent extrinsic: {error}\nExtrinsic: {extrinsic:?}")]
    InherentExtrinsicTransactionValidityError {
        /// Extrinsic that triggered the problem.
        extrinsic: Vec<u8>,
        /// Error returned by the runtime.
        #[error(source)]
        error: TransactionValidityError,
    },
}

/// Start a block building process.
pub fn build_block(config: Config) -> BlockBuild {
    let consensus_digest = match config.consensus_digest_log_item {
        ConfigPreRuntime::Aura(item) => header::DigestItem::AuraPreDigest(item),
        ConfigPreRuntime::Babe(item) => header::DigestItem::BabePreDigest(item.into()),
    };

    let init_result = runtime_call::run(runtime_call::Config {
        function_to_call: "Core_initialize_block",
        parameter: {
            // The `Core_initialize_block` function expects a SCALE-encoded partially-initialized
            // header.
            header::HeaderRef {
                parent_hash: config.parent_hash,
                number: match config.parent_number.checked_add(1) {
                    Some(n) => n,
                    None => {
                        return BlockBuild::Finished(Err((
                            Error::BlockHeightOverflow,
                            config.parent_runtime,
                        )));
                    }
                },
                extrinsics_root: &[0; 32],
                state_root: &[0; 32],
                digest: header::DigestRef::from_slice(slice::from_ref(&consensus_digest)).unwrap(),
            }
            .scale_encoding(config.block_number_bytes)
        },
        virtual_machine: config.parent_runtime,
        storage_main_trie_changes: Default::default(),
        storage_proof_size_behavior: runtime_call::StorageProofSizeBehavior::Unimplemented,
        max_log_level: config.max_log_level,
        calculate_trie_changes: config.calculate_trie_changes,
        // Each call of the block building process starts from the main trie diff of the
        // previous one, which must then hold the new roots of the child tries it modified.
        calculate_child_tries_roots_on_finish: true,
    });

    let vm = match init_result {
        Ok(vm) => vm,
        Err((err, proto)) => return BlockBuild::Finished(Err((Error::VmInit(err), proto))),
    };

    let shared = Shared {
        stage: Stage::InitializeBlock,
        block_body: Vec::with_capacity(config.block_body_capacity),
        max_log_level: config.max_log_level,
        calculate_trie_changes: config.calculate_trie_changes,
    };

    BlockBuild::from_inner(vm, shared)
}

/// Current state of the block building process.
#[must_use]
pub enum BlockBuild {
    /// Block generation is over.
    Finished(Result<Success, (Error, host::HostVmPrototype)>),

    /// The inherent extrinsics are required in order to continue.
    ///
    /// [`BlockBuild::InherentExtrinsics`] is guaranteed to only be emitted once per block
    /// building process.
    ///
    /// The extrinsics returned by the call to `BlockBuilder_inherent_extrinsics` are
    /// automatically pushed to the runtime.
    InherentExtrinsics(InherentExtrinsics),

    /// Block building is ready to accept extrinsics.
    ///
    /// If [`ApplyExtrinsic::add_extrinsic`] is used, then a [`BlockBuild::ApplyExtrinsicResult`]
    /// stage will be emitted later.
    ///
    /// > **Note**: These extrinsics are generally coming from a transactions pool, but this is
    /// >           out of scope of this module.
    ApplyExtrinsic(ApplyExtrinsic),

    /// Result of the previous call to [`ApplyExtrinsic::add_extrinsic`].
    ///
    /// An [`ApplyExtrinsic`] object is provided in order to continue the operation.
    ApplyExtrinsicResult {
        /// Result of the previous call to [`ApplyExtrinsic::add_extrinsic`].
        result: Result<Result<(), DispatchError>, TransactionValidityError>,
        /// Object to use to continue trying to push other transactions or finish the block.
        resume: ApplyExtrinsic,
    },

    /// Loading a storage value from the parent storage is required in order to continue.
    StorageGet(StorageGet),

    /// Obtaining the Merkle value of the closest descendant of a trie node is required in order
    /// to continue.
    ClosestDescendantMerkleValue(ClosestDescendantMerkleValue),

    /// Fetching the key that follows a given one in the parent storage is required in order to
    /// continue.
    NextKey(NextKey),

    /// Setting an offchain storage value is required in order to continue.
    OffchainStorageSet(OffchainStorageSet),
}

impl BlockBuild {
    fn from_inner(inner: runtime_call::RuntimeCall, mut shared: Shared) -> Self {
        enum Inner {
            Runtime(runtime_call::RuntimeCall),
            Transition(runtime_call::Success),
        }

        let mut inner = Inner::Runtime(inner);

        loop {
            match (inner, &mut shared.stage) {
                (Inner::Runtime(runtime_call::RuntimeCall::Finished(Err(err))), _) => {
                    return BlockBuild::Finished(Err((Error::WasmVm(err.detail), err.prototype)));
                }
                (Inner::Runtime(runtime_call::RuntimeCall::StorageGet(inner)), _) => {
                    return BlockBuild::StorageGet(StorageGet(inner, shared));
                }
                (
                    Inner::Runtime(runtime_call::RuntimeCall::ClosestDescendantMerkleValue(inner)),
                    _,
                ) => {
                    return BlockBuild::ClosestDescendantMerkleValue(ClosestDescendantMerkleValue(
                        inner, shared,
                    ));
                }
                (Inner::Runtime(runtime_call::RuntimeCall::NextKey(inner)), _) => {
                    return BlockBuild::NextKey(NextKey(inner, shared));
                }
                (Inner::Runtime(runtime_call::RuntimeCall::OffchainStorageSet(inner)), _) => {
                    return BlockBuild::OffchainStorageSet(OffchainStorageSet(inner, shared));
                }

                (
                    Inner::Runtime(runtime_call::RuntimeCall::Finished(Ok(success))),
                    Stage::InitializeBlock,
                ) => {
                    if !success.virtual_machine.value().as_ref().is_empty() {
                        return BlockBuild::Finished(Err((
                            Error::InitializeBlockNonEmptyOutput,
                            success.virtual_machine.into_prototype(),
                        )));
                    }

                    shared.stage = Stage::InherentExtrinsics;

                    return BlockBuild::InherentExtrinsics(InherentExtrinsics {
                        shared,
                        parent_runtime: success.virtual_machine.into_prototype(),
                        storage_changes: success.storage_changes,
                    });
                }

                (
                    Inner::Runtime(runtime_call::RuntimeCall::Finished(Ok(success))),
                    Stage::InherentExtrinsics,
                ) => {
                    let parse_result =
                        parse_inherent_extrinsics_output(success.virtual_machine.value().as_ref());
                    let extrinsics = match parse_result {
                        Ok(extrinsics) => extrinsics,
                        Err(err) => {
                            return BlockBuild::Finished(Err((
                                err,
                                success.virtual_machine.into_prototype(),
                            )));
                        }
                    };

                    shared.block_body.reserve(extrinsics.len());
                    shared.stage = Stage::ApplyInherentExtrinsic { extrinsics };
                    inner = Inner::Transition(success);
                }

                (Inner::Transition(success), Stage::ApplyInherentExtrinsic { extrinsics })
                    if !extrinsics.is_empty() =>
                {
                    let extrinsic = &extrinsics[0];

                    let init_result = runtime_call::run(runtime_call::Config {
                        virtual_machine: success.virtual_machine.into_prototype(),
                        function_to_call: "BlockBuilder_apply_extrinsic",
                        parameter: iter::once(extrinsic),
                        storage_main_trie_changes: success.storage_changes.into_main_trie_diff(),
                        storage_proof_size_behavior:
                            runtime_call::StorageProofSizeBehavior::Unimplemented,
                        max_log_level: shared.max_log_level,
                        calculate_trie_changes: shared.calculate_trie_changes,
                        calculate_child_tries_roots_on_finish: true,
                    });

                    inner = Inner::Runtime(match init_result {
                        Ok(vm) => vm,
                        Err((err, proto)) => {
                            return BlockBuild::Finished(Err((Error::VmInit(err), proto)));
                        }
                    });
                }

                (Inner::Transition(success), Stage::ApplyInherentExtrinsic { .. }) => {
                    return BlockBuild::ApplyExtrinsic(ApplyExtrinsic {
                        shared,
                        parent_runtime: success.virtual_machine.into_prototype(),
                        storage_changes: success.storage_changes,
                    });
                }

                (
                    Inner::Runtime(runtime_call::RuntimeCall::Finished(Ok(success))),
                    Stage::ApplyInherentExtrinsic { .. },
                ) => {
                    let (extrinsic, new_stage) = match shared.stage {
                        Stage::ApplyInherentExtrinsic { mut extrinsics } => {
                            let extrinsic = extrinsics.remove(0);
                            (extrinsic, Stage::ApplyInherentExtrinsic { extrinsics })
                        }
                        _ => unreachable!(),
                    };

                    shared.stage = new_stage;

                    let parse_result =
                        parse_apply_extrinsic_output(success.virtual_machine.value().as_ref());
                    match parse_result {
                        Ok(Ok(Ok(()))) => {}
                        Ok(Ok(Err(error))) => {
                            return BlockBuild::Finished(Err((
                                Error::InherentExtrinsicDispatchError { extrinsic, error },
                                success.virtual_machine.into_prototype(),
                            )));
                        }
                        Ok(Err(error)) => {
                            return BlockBuild::Finished(Err((
                                Error::InherentExtrinsicTransactionValidityError {
                                    extrinsic,
                                    error,
                                },
                                success.virtual_machine.into_prototype(),
                            )));
                        }
                        Err(err) => {
                            return BlockBuild::Finished(Err((
                                err,
                                success.virtual_machine.into_prototype(),
                            )));
                        }
                    }

                    shared.block_body.push(extrinsic);

                    inner = Inner::Transition(success);
                }

                (
                    Inner::Runtime(runtime_call::RuntimeCall::Finished(Ok(success))),
                    Stage::ApplyExtrinsic(_),
                ) => {
                    let parse_result =
                        parse_apply_extrinsic_output(success.virtual_machine.value().as_ref());
                    let result = match parse_result {
                        Ok(r) => r,
                        Err(err) => {
                            return BlockBuild::Finished(Err((
                                err,
                                success.virtual_machine.into_prototype(),
                            )));
                        }
                    };

                    if result.is_ok() {
                        shared.block_body.push(match &mut shared.stage {
                            Stage::ApplyExtrinsic(ext) => mem::take(ext),
                            _ => unreachable!(),
                        });
                    }

                    // TODO: consider giving back extrinsic to user in case of failure

                    // TODO: IMPORTANT /!\ must throw away storage changes in case of error

                    return BlockBuild::ApplyExtrinsicResult {
                        result,
                        resume: ApplyExtrinsic {
                            shared,
                            parent_runtime: success.virtual_machine.into_prototype(),
                            storage_changes: success.storage_changes,
                        },
                    };
                }

                (
                    Inner::Runtime(runtime_call::RuntimeCall::Finished(Ok(success))),
                    Stage::FinalizeBlock,
                ) => {
                    let scale_encoded_header = success.virtual_machine.value().as_ref().to_owned();
                    return BlockBuild::Finished(Ok(Success {
                        scale_encoded_header,
                        body: shared.block_body,
                        parent_runtime: success.virtual_machine.into_prototype(),
                        storage_changes: success.storage_changes,
                        state_trie_version: success.state_trie_version,
                    }));
                }

                // TODO: what about SignatureVerification and EmitLog? at the time of writing of this comment, it's not worth fixing as this code would get removed by <https://github.com/smol-dot/smoldot/issues/1517>
                (_, s) => unreachable!("{:?}", s),
            }
        }
    }
}

/// Extra information maintained in parallel of the [`runtime_call::RuntimeCall`].
#[derive(Debug)]
struct Shared {
    /// The block building process is separated into multiple stages.
    stage: Stage,
    /// Body of the block under construction. Items are added as construction progresses.
    block_body: Vec<Vec<u8>>,
    /// Value provided by [`Config::max_log_level`].
    max_log_level: u32,
    /// Value provided by [`Config::calculate_trie_changes`].
    calculate_trie_changes: bool,
}

/// The block building process is separated into multiple stages.
#[derive(Debug, Clone)]
enum Stage {
    InitializeBlock,
    InherentExtrinsics,
    ApplyInherentExtrinsic {
        /// List of inherent extrinsics being applied, including the one currently being applied.
        /// This list should thus never be empty.
        extrinsics: Vec<Vec<u8>>,
    },
    ApplyExtrinsic(Vec<u8>),
    FinalizeBlock,
}

/// The list of inherent extrinsics are needed in order to continue.
#[must_use]
pub struct InherentExtrinsics {
    shared: Shared,
    parent_runtime: host::HostVmPrototype,
    storage_changes: StorageChanges,
}

impl InherentExtrinsics {
    /// Injects the inherents extrinsics and resumes execution.
    ///
    /// See the module-level documentation for more information.
    pub fn inject_inherents(self, inherents: inherents::InherentData) -> BlockBuild {
        self.inject_raw_inherents_list(inherents.as_raw_list())
    }

    /// Injects a raw list of inherents and resumes execution.
    ///
    /// This method is a more weakly-typed equivalent to [`InherentExtrinsics::inject_inherents`].
    /// Only use this method if you know what you're doing.
    pub fn inject_raw_inherents_list(
        self,
        list: impl ExactSizeIterator<Item = ([u8; 8], impl AsRef<[u8]> + Clone)> + Clone,
    ) -> BlockBuild {
        debug_assert!(matches!(self.shared.stage, Stage::InherentExtrinsics));

        let init_result = runtime_call::run(runtime_call::Config {
            virtual_machine: self.parent_runtime,
            function_to_call: "BlockBuilder_inherent_extrinsics",
            parameter: {
                // The `BlockBuilder_inherent_extrinsics` function expects a SCALE-encoded list of
                // tuples containing an "inherent identifier" (`[u8; 8]`) and a value (`Vec<u8>`).
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

                iter::once(len)
                    .map(either::Left)
                    .chain(encoded_list.map(either::Right))
            },
            storage_proof_size_behavior: runtime_call::StorageProofSizeBehavior::Unimplemented,
            storage_main_trie_changes: self.storage_changes.into_main_trie_diff(),
            max_log_level: self.shared.max_log_level,
            calculate_trie_changes: self.shared.calculate_trie_changes,
            calculate_child_tries_roots_on_finish: true,
        });

        let vm = match init_result {
            Ok(vm) => vm,
            Err((err, proto)) => return BlockBuild::Finished(Err((Error::VmInit(err), proto))),
        };

        BlockBuild::from_inner(vm, self.shared)
    }
}

/// More transactions can be added.
#[must_use]
pub struct ApplyExtrinsic {
    shared: Shared,
    parent_runtime: host::HostVmPrototype,
    storage_changes: StorageChanges,
}

impl ApplyExtrinsic {
    /// Adds a SCALE-encoded extrinsic and resumes execution.
    ///
    /// See the module-level documentation for more information.
    pub fn add_extrinsic(mut self, extrinsic: Vec<u8>) -> BlockBuild {
        let init_result = runtime_call::run(runtime_call::Config {
            virtual_machine: self.parent_runtime,
            function_to_call: "BlockBuilder_apply_extrinsic",
            parameter: iter::once(&extrinsic),
            storage_proof_size_behavior: runtime_call::StorageProofSizeBehavior::Unimplemented,
            storage_main_trie_changes: self.storage_changes.into_main_trie_diff(),
            max_log_level: self.shared.max_log_level,
            calculate_trie_changes: self.shared.calculate_trie_changes,
            calculate_child_tries_roots_on_finish: true,
        });

        self.shared.stage = Stage::ApplyExtrinsic(extrinsic);

        let vm = match init_result {
            Ok(vm) => vm,
            Err((err, proto)) => return BlockBuild::Finished(Err((Error::VmInit(err), proto))),
        };

        BlockBuild::from_inner(vm, self.shared)
    }

    /// Indicate that no more extrinsics will be added, and resume execution.
    pub fn finish(mut self) -> BlockBuild {
        self.shared.stage = Stage::FinalizeBlock;

        let init_result = runtime_call::run(runtime_call::Config {
            virtual_machine: self.parent_runtime,
            function_to_call: "BlockBuilder_finalize_block",
            parameter: iter::empty::<&[u8]>(),
            storage_proof_size_behavior: runtime_call::StorageProofSizeBehavior::Unimplemented,
            storage_main_trie_changes: self.storage_changes.into_main_trie_diff(),
            max_log_level: self.shared.max_log_level,
            calculate_trie_changes: self.shared.calculate_trie_changes,
            calculate_child_tries_roots_on_finish: true,
        });

        let vm = match init_result {
            Ok(vm) => vm,
            Err((err, proto)) => return BlockBuild::Finished(Err((Error::VmInit(err), proto))),
        };

        BlockBuild::from_inner(vm, self.shared)
    }
}

/// Loading a storage value from the parent storage is required in order to continue.
#[must_use]
pub struct StorageGet(runtime_call::StorageGet, Shared);

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
    ) -> BlockBuild {
        BlockBuild::from_inner(self.0.inject_value(value), self.1)
    }
}

/// Obtaining the Merkle value of the closest descendant of a trie node is required in order
/// to continue.
#[must_use]
pub struct ClosestDescendantMerkleValue(runtime_call::ClosestDescendantMerkleValue, Shared);

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
    pub fn resume_unknown(self) -> BlockBuild {
        BlockBuild::from_inner(self.0.resume_unknown(), self.1)
    }

    /// Injects the corresponding Merkle value.
    ///
    /// `None` can be passed if there is no descendant or, in the case of a child trie read, in
    /// order to indicate that the child trie does not exist.
    pub fn inject_merkle_value(self, merkle_value: Option<&[u8]>) -> BlockBuild {
        BlockBuild::from_inner(self.0.inject_merkle_value(merkle_value), self.1)
    }
}

/// Fetching the key that follows a given one in the parent storage is required in order to
/// continue.
#[must_use]
pub struct NextKey(runtime_call::NextKey, Shared);

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
    ///
    pub fn inject_key(self, key: Option<impl Iterator<Item = Nibble>>) -> BlockBuild {
        BlockBuild::from_inner(self.0.inject_key(key), self.1)
    }
}

/// Setting the value of an offchain storage value is required.
#[must_use]
pub struct OffchainStorageSet(runtime_call::OffchainStorageSet, Shared);

impl OffchainStorageSet {
    /// Returns the key whose value must be set.
    pub fn key(&self) -> impl AsRef<[u8]> {
        self.0.key()
    }

    /// Returns the value to set.
    ///
    /// If `None` is returned, the key should be removed from the storage entirely.
    pub fn value(&self) -> Option<impl AsRef<[u8]>> {
        self.0.value()
    }

    /// Resumes execution after having set the value.
    pub fn resume(self) -> BlockBuild {
        BlockBuild::from_inner(self.0.resume(), self.1)
    }
}

/// Analyzes the output of a call to `BlockBuilder_inherent_extrinsics`, and returns the resulting
/// extrinsics.
// TODO: this method implementation is hacky ; the `BlockBuilder_inherent_extrinsics` function
//       returns a `Vec<Extrinsic>`, where `Extrinsic` is opaque and depends on the chain. Because
//       we don't know the type of `Extrinsic`, a `Vec<Extrinsic>` is undecodable. However, most
//       Substrate chains use `type Extrinsic = OpaqueExtrinsic;` where
//       `type OpaqueExtrinsic = Vec<u8>;` here, which happens to start with a length prefix
//       containing its remaining size; this length prefix is fully part of the `Extrinsic` though.
//       In other words, this function might succeed or fail depending on the Substrate chain.
fn parse_inherent_extrinsics_output(output: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    nom::Parser::parse(
        &mut nom::combinator::all_consuming(nom::combinator::flat_map(
            crate::util::nom_scale_compact_usize,
            |num_elems| {
                nom::multi::many_m_n(
                    num_elems,
                    num_elems,
                    nom::combinator::map(
                        nom::combinator::recognize(nom::combinator::flat_map(
                            crate::util::nom_scale_compact_usize,
                            nom::bytes::streaming::take,
                        )),
                        |v: &[u8]| v.to_vec(),
                    ),
                )
            },
        )),
        output,
    )
    .map(|(_, parse_result)| parse_result)
    .map_err(|_: nom::Err<(&[u8], nom::error::ErrorKind)>| Error::BadInherentExtrinsicsOutput)
}

/// Analyzes the output of a call to `BlockBuilder_apply_extrinsic`.
fn parse_apply_extrinsic_output(
    output: &[u8],
) -> Result<Result<Result<(), DispatchError>, TransactionValidityError>, Error> {
    nom::Parser::parse(
        &mut nom::combinator::all_consuming(apply_extrinsic_result),
        output,
    )
    .map(|(_, parse_result)| parse_result)
    .map_err(|_: nom::Err<nom::error::Error<&[u8]>>| Error::BadApplyExtrinsicOutput)
}

// TODO: some parsers below are common with the tx-pool ; figure out how/whether they should be merged

/// Errors that can occur while checking the validity of a transaction.
#[derive(Debug, derive_more::Display, derive_more::Error, Clone, PartialEq, Eq)]
pub enum TransactionValidityError {
    /// The transaction is invalid.
    #[display("Transaction is invalid: {_0}")]
    Invalid(InvalidTransaction),
    /// Transaction validity can't be determined.
    #[display("Transaction validity couldn't be determined: {_0}")]
    Unknown(UnknownTransaction),
}

/// An invalid transaction validity.
#[derive(Debug, derive_more::Display, derive_more::Error, Clone, PartialEq, Eq)]
pub enum InvalidTransaction {
    /// The call of the transaction is not expected.
    Call,
    /// General error to do with the inability to pay some fees (e.g. account balance too low).
    Payment,
    /// General error to do with the transaction not yet being valid (e.g. nonce too high).
    Future,
    /// General error to do with the transaction being outdated (e.g. nonce too low).
    Stale,
    /// General error to do with the transaction's proofs (e.g. signature).
    ///
    /// # Possible causes
    ///
    /// When using a signed extension that provides additional data for signing, it is required
    /// that the signing and the verifying side use the same additional data. Additional
    /// data will only be used to generate the signature, but will not be part of the transaction
    /// itself. As the verifying side does not know which additional data was used while signing
    /// it will only be able to assume a bad signature and cannot express a more meaningful error.
    BadProof,
    /// The transaction birth block is ancient.
    AncientBirthBlock,
    /// The transaction would exhaust the resources of current block.
    ///
    /// The transaction might be valid, but there are not enough resources
    /// left in the current block.
    ExhaustsResources,
    /// Any other custom invalid validity that is not covered by this enum.
    #[display("Other reason (code: {_0})")]
    Custom(#[error(not(source))] u8),
    /// An extrinsic with a Mandatory dispatch resulted in Error. This is indicative of either a
    /// malicious validator or a buggy `provide_inherent`. In any case, it can result in dangerously
    /// overweight blocks and therefore if found, invalidates the block.
    BadMandatory,
    /// A transaction with a mandatory dispatch. This is invalid; only inherent extrinsics are
    /// allowed to have mandatory dispatches.
    MandatoryDispatch,
}

/// An unknown transaction validity.
#[derive(Debug, derive_more::Display, derive_more::Error, Clone, PartialEq, Eq)]
pub enum UnknownTransaction {
    /// Could not lookup some information that is required to validate the transaction.
    CannotLookup,
    /// No validator found for the given unsigned transaction.
    NoUnsignedValidator,
    /// Any other custom unknown validity that is not covered by this enum.
    #[display("Other reason (code: {_0})")]
    Custom(#[error(not(source))] u8),
}

/// Reason why a dispatch call failed.
#[derive(Debug, derive_more::Display, derive_more::Error, Clone, PartialEq, Eq)]
pub enum DispatchError {
    /// Failed to lookup some data.
    CannotLookup,
    /// A bad origin.
    BadOrigin,
    /// A custom error in a module.
    #[display("Error in module #{index}, error number #{error}")]
    Module {
        /// Module index, matching the metadata module index.
        index: u8,
        /// Module specific error value.
        error: u8,
    },
}

fn apply_extrinsic_result(
    bytes: &[u8],
) -> nom::IResult<&[u8], Result<Result<(), DispatchError>, TransactionValidityError>> {
    nom::Parser::parse(
        &mut nom::error::context(
            "apply extrinsic result",
            nom::branch::alt((
                nom::combinator::map(
                    nom::sequence::preceded(nom::bytes::streaming::tag(&[0][..]), dispatch_outcome),
                    Ok,
                ),
                nom::combinator::map(
                    nom::sequence::preceded(
                        nom::bytes::streaming::tag(&[1][..]),
                        transaction_validity_error,
                    ),
                    Err,
                ),
            )),
        ),
        bytes,
    )
}

fn dispatch_outcome(bytes: &[u8]) -> nom::IResult<&[u8], Result<(), DispatchError>> {
    nom::Parser::parse(
        &mut nom::error::context(
            "dispatch outcome",
            nom::branch::alt((
                nom::combinator::map(nom::bytes::streaming::tag(&[0][..]), |_| Ok(())),
                nom::combinator::map(
                    nom::sequence::preceded(nom::bytes::streaming::tag(&[1][..]), dispatch_error),
                    Err,
                ),
            )),
        ),
        bytes,
    )
}

fn dispatch_error(bytes: &[u8]) -> nom::IResult<&[u8], DispatchError> {
    nom::Parser::parse(
        &mut nom::error::context(
            "dispatch error",
            nom::branch::alt((
                nom::combinator::map(nom::bytes::streaming::tag(&[0][..]), |_| {
                    DispatchError::CannotLookup
                }),
                nom::combinator::map(nom::bytes::streaming::tag(&[1][..]), |_| {
                    DispatchError::BadOrigin
                }),
                nom::combinator::map(
                    nom::sequence::preceded(
                        nom::bytes::streaming::tag(&[2][..]),
                        (nom::number::streaming::u8, nom::number::streaming::u8),
                    ),
                    |(index, error)| DispatchError::Module { index, error },
                ),
            )),
        ),
        bytes,
    )
}

fn transaction_validity_error(bytes: &[u8]) -> nom::IResult<&[u8], TransactionValidityError> {
    nom::Parser::parse(
        &mut nom::error::context(
            "transaction validity error",
            nom::branch::alt((
                nom::combinator::map(
                    nom::sequence::preceded(
                        nom::bytes::streaming::tag(&[0][..]),
                        invalid_transaction,
                    ),
                    TransactionValidityError::Invalid,
                ),
                nom::combinator::map(
                    nom::sequence::preceded(
                        nom::bytes::streaming::tag(&[1][..]),
                        unknown_transaction,
                    ),
                    TransactionValidityError::Unknown,
                ),
            )),
        ),
        bytes,
    )
}

fn invalid_transaction(bytes: &[u8]) -> nom::IResult<&[u8], InvalidTransaction> {
    nom::Parser::parse(
        &mut nom::error::context(
            "invalid transaction",
            nom::branch::alt((
                nom::combinator::map(nom::bytes::streaming::tag(&[0][..]), |_| {
                    InvalidTransaction::Call
                }),
                nom::combinator::map(nom::bytes::streaming::tag(&[1][..]), |_| {
                    InvalidTransaction::Payment
                }),
                nom::combinator::map(nom::bytes::streaming::tag(&[2][..]), |_| {
                    InvalidTransaction::Future
                }),
                nom::combinator::map(nom::bytes::streaming::tag(&[3][..]), |_| {
                    InvalidTransaction::Stale
                }),
                nom::combinator::map(nom::bytes::streaming::tag(&[4][..]), |_| {
                    InvalidTransaction::BadProof
                }),
                nom::combinator::map(nom::bytes::streaming::tag(&[5][..]), |_| {
                    InvalidTransaction::AncientBirthBlock
                }),
                nom::combinator::map(nom::bytes::streaming::tag(&[6][..]), |_| {
                    InvalidTransaction::ExhaustsResources
                }),
                nom::combinator::map(
                    nom::sequence::preceded(
                        nom::bytes::streaming::tag(&[7][..]),
                        nom::bytes::streaming::take(1u32),
                    ),
                    |n: &[u8]| InvalidTransaction::Custom(n[0]),
                ),
                nom::combinator::map(nom::bytes::streaming::tag(&[8][..]), |_| {
                    InvalidTransaction::BadMandatory
                }),
                nom::combinator::map(nom::bytes::streaming::tag(&[9][..]), |_| {
                    InvalidTransaction::MandatoryDispatch
                }),
            )),
        ),
        bytes,
    )
}

fn unknown_transaction(bytes: &[u8]) -> nom::IResult<&[u8], UnknownTransaction> {
    nom::Parser::parse(
        &mut nom::error::context(
            "unknown transaction",
            nom::branch::alt((
                nom::combinator::map(nom::bytes::streaming::tag(&[0][..]), |_| {
                    UnknownTransaction::CannotLookup
                }),
                nom::combinator::map(nom::bytes::streaming::tag(&[1][..]), |_| {
                    UnknownTransaction::NoUnsignedValidator
                }),
                nom::combinator::map(
                    nom::sequence::preceded(
                        nom::bytes::streaming::tag(&[2][..]),
                        nom::bytes::streaming::take(1u32),
                    ),
                    |n: &[u8]| UnknownTransaction::Custom(n[0]),
                ),
            )),
        ),
        bytes,
    )
}
