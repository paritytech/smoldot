// Substrate-lite
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

// TODO: expand docs
// TODO: explain what an inherent extrinsic is

mod tests;

use crate::{
    executor::{self, runtime_externals},
    header,
    trie::calculate_root,
    util,
};

use alloc::{string::String, vec::Vec};
use core::iter;
use hashbrown::HashMap;

/// Configuration for a block generation.
pub struct Config<'a> {
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
    pub parent_runtime: executor::WasmVmPrototype,

    /// Optional cache corresponding to the storage trie root hash calculation coming from the
    /// parent block verification.
    pub top_trie_root_calculation_cache: Option<calculate_root::CalculationCache>,
}

/// Block successfully verified.
pub struct Success {
    /// SCALE-encoded header of the produced block.
    pub scale_encoded_header: Vec<u8>,
    /// Body of the produced block.
    pub body: Vec<Vec<u8>>,
    /// Runtime that was passed by [`Config`].
    pub parent_runtime: executor::WasmVmPrototype,
    /// List of changes to the storage top trie that the block performs.
    pub storage_top_trie_changes: HashMap<Vec<u8>, Option<Vec<u8>>, fnv::FnvBuildHasher>,
    /// List of changes to the offchain storage that this block performs.
    pub offchain_storage_changes: HashMap<Vec<u8>, Option<Vec<u8>>, fnv::FnvBuildHasher>,
    /// Cache used for calculating the top trie root of the new block.
    pub top_trie_root_calculation_cache: calculate_root::CalculationCache,
    /// Concatenation of all the log messages printed by the runtime.
    pub logs: String,
}

/// Error that can happen during the verification.
#[derive(Debug, derive_more::Display)]
pub enum Error {
    /// Error while executing the Wasm virtual machine.
    #[display(fmt = "{}", _0)]
    WasmVm(runtime_externals::Error),
    /// Error while initializing the Wasm virtual machine.
    #[display(fmt = "{}", _0)]
    VmInit(executor::NewErr),
    /// Overflow when incrementing block height.
    BlockHeightOverflow,
    /// `Core_initialize_block` has returned a non-empty output.
    InitializeBlockNonEmptyOutput,
    /// Error while parsing output of `BlockBuilder_inherent_extrinsics`.
    BadInherentExtrinsicsOutput,
}

/// Start a block building process.
pub fn build_block<'a>(config: Config<'a>) -> BlockBuild {
    let init_result = runtime_externals::run(runtime_externals::Config {
        virtual_machine: config.parent_runtime,
        function_to_call: "Core_initialize_block",
        parameter: {
            // The `Core_initialize_block` function expects a SCALE-encoded partially-initialized
            // header.
            header::HeaderRef {
                parent_hash: config.parent_hash,
                number: match config.parent_number.checked_add(1) {
                    Some(n) => n,
                    None => return BlockBuild::Finished(Err(Error::BlockHeightOverflow)),
                },
                extrinsics_root: &[0; 32],
                state_root: &[0; 32],
                // TODO: is it true that the digest is empty? shouldn't it contain some preruntime consensus items?
                digest: header::DigestRef::empty(),
            }
            .scale_encoding()
        },
        top_trie_root_calculation_cache: config.top_trie_root_calculation_cache,
        storage_top_trie_changes: Default::default(),
        offchain_storage_changes: Default::default(),
    });

    let vm = match init_result {
        Ok(vm) => vm,
        Err(err) => return BlockBuild::Finished(Err(Error::VmInit(err))),
    };

    let shared = Shared {
        stage: Stage::InitializeBlock,
        block_body: Vec::new(), // TODO: with_capacity?
        logs: String::new(),
    };

    BlockBuild::from_inner(vm, shared)
}

/// Current state of the block building process.
#[must_use]
pub enum BlockBuild {
    /// Block generation is over.
    Finished(Result<Success, Error>),

    /// The inherent extrinsics are required in order to continue.
    ///
    /// Guaranteed to only be produced once per block building process.
    InherentExtrinsics(InherentExtrinsics),

    /// Block building is ready to accept extrinsics.
    ///
    /// If [`ApplyExtrinsic::add_extrinsic`] is used, then another [`BlockBuild::ApplyExtrinsic`]
    /// stage will be emitted again later.
    ///
    /// > **Note**: These extrinsics are generally coming from a transactions pool, but this is
    /// >           out of scope of this module.
    ApplyExtrinsic(ApplyExtrinsic),

    /// Loading a storage value from the parent storage is required in order to continue.
    StorageGet(StorageGet),

    /// Fetching the list of keys with a given prefix from the parent storage is required in order
    /// to continue.
    PrefixKeys(PrefixKeys),

    /// Fetching the key that follows a given one in the parent storage is required in order to
    /// continue.
    NextKey(NextKey),
}

impl BlockBuild {
    fn from_inner(inner: runtime_externals::RuntimeExternalsVm, mut shared: Shared) -> Self {
        match (inner, shared.stage) {
            (runtime_externals::RuntimeExternalsVm::Finished(Err(err)), _) => {
                BlockBuild::Finished(Err(Error::WasmVm(err)))
            }
            (runtime_externals::RuntimeExternalsVm::StorageGet(inner), _) => {
                BlockBuild::StorageGet(StorageGet(inner, shared))
            }
            (runtime_externals::RuntimeExternalsVm::PrefixKeys(inner), _) => {
                BlockBuild::PrefixKeys(PrefixKeys(inner, shared))
            }
            (runtime_externals::RuntimeExternalsVm::NextKey(inner), _) => {
                BlockBuild::NextKey(NextKey(inner, shared))
            }

            (
                runtime_externals::RuntimeExternalsVm::Finished(Ok(success)),
                Stage::InitializeBlock,
            ) => {
                if !success.virtual_machine.value().is_empty() {
                    return BlockBuild::Finished(Err(Error::InitializeBlockNonEmptyOutput));
                }

                shared.logs.push_str(&success.logs);

                BlockBuild::InherentExtrinsics(InherentExtrinsics {
                    shared,
                    parent_runtime: success.virtual_machine.into_prototype(),
                    storage_top_trie_changes: success.storage_top_trie_changes,
                    offchain_storage_changes: success.offchain_storage_changes,
                    top_trie_root_calculation_cache: success.top_trie_root_calculation_cache,
                })
            }

            (
                runtime_externals::RuntimeExternalsVm::Finished(Ok(success)),
                Stage::InherentExtrinsics,
            ) => {
                match parse_inherent_extrinsics_output(
                    success.virtual_machine.value(),
                    &mut shared.block_body,
                ) {
                    Ok(()) => {}
                    Err(err) => return BlockBuild::Finished(Err(err)),
                };

                shared.logs.push_str(&success.logs);

                BlockBuild::ApplyExtrinsic(ApplyExtrinsic {
                    shared,
                    parent_runtime: success.virtual_machine.into_prototype(),
                    storage_top_trie_changes: success.storage_top_trie_changes,
                    offchain_storage_changes: success.offchain_storage_changes,
                    top_trie_root_calculation_cache: success.top_trie_root_calculation_cache,
                })
            }

            (
                runtime_externals::RuntimeExternalsVm::Finished(Ok(success)),
                Stage::ApplyExtrinsic,
            ) => {
                shared.logs.push_str(&success.logs);

                // TODO: must analyze output value of function ; see https://github.com/paritytech/substrate/blob/38d5bb32c3064113f897cb8ec33eea0f8570981b/primitives/runtime/src/lib.rs#L540
                todo!();

                BlockBuild::ApplyExtrinsic(ApplyExtrinsic {
                    shared,
                    parent_runtime: success.virtual_machine.into_prototype(),
                    storage_top_trie_changes: success.storage_top_trie_changes,
                    offchain_storage_changes: success.offchain_storage_changes,
                    top_trie_root_calculation_cache: success.top_trie_root_calculation_cache,
                })
            }

            (
                runtime_externals::RuntimeExternalsVm::Finished(Ok(success)),
                Stage::FinalizeBlock,
            ) => {
                shared.logs.push_str(&success.logs);
                let scale_encoded_header = success.virtual_machine.value().to_owned();
                BlockBuild::Finished(Ok(Success {
                    scale_encoded_header,
                    body: shared.block_body,
                    parent_runtime: success.virtual_machine.into_prototype(),
                    storage_top_trie_changes: success.storage_top_trie_changes,
                    offchain_storage_changes: success.offchain_storage_changes,
                    top_trie_root_calculation_cache: success.top_trie_root_calculation_cache,
                    logs: shared.logs,
                }))
            }
        }
    }
}

/// Extra information maintained in parallel of the [`runtime_externals::RuntimeExternalsVm`].
#[derive(Debug)]
struct Shared {
    /// The block building process is separated into multiple stages.
    stage: Stage,
    /// Body of the block under construction. Items are added as construction progresses.
    block_body: Vec<Vec<u8>>,
    /// Concatenation of all logs produced by the multiple calls.
    logs: String,
}

/// The block building process is separated into multiple stages.
#[derive(Debug, Copy, Clone)]
enum Stage {
    InitializeBlock,
    InherentExtrinsics,
    ApplyExtrinsic,
    FinalizeBlock,
}

/// The list of inherent extrinsics are needed in order to continue.
#[must_use]
pub struct InherentExtrinsics {
    shared: Shared,
    parent_runtime: executor::WasmVmPrototype,
    storage_top_trie_changes: HashMap<Vec<u8>, Option<Vec<u8>>, fnv::FnvBuildHasher>,
    offchain_storage_changes: HashMap<Vec<u8>, Option<Vec<u8>>, fnv::FnvBuildHasher>,
    top_trie_root_calculation_cache: calculate_root::CalculationCache,
}

impl InherentExtrinsics {
    /// Injects the extrinsics and resumes execution.
    ///
    /// See the module-level documentation for more information.
    pub fn inject_extrinsics(
        self,
        list: impl ExactSizeIterator<Item = ([u8; 8], impl AsRef<[u8]> + Clone)> + Clone,
    ) -> BlockBuild {
        debug_assert!(matches!(self.shared.stage, Stage::InitializeBlock));

        let init_result = runtime_externals::run(runtime_externals::Config {
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
            top_trie_root_calculation_cache: Some(self.top_trie_root_calculation_cache),
            storage_top_trie_changes: self.storage_top_trie_changes,
            offchain_storage_changes: self.offchain_storage_changes,
        });

        let vm = match init_result {
            Ok(vm) => vm,
            Err(err) => return BlockBuild::Finished(Err(Error::VmInit(err))),
        };

        BlockBuild::from_inner(
            vm,
            Shared {
                stage: Stage::InherentExtrinsics,
                ..self.shared
            },
        )
    }
}

/// More transactions can be added.
#[must_use]
pub struct ApplyExtrinsic {
    shared: Shared,
    parent_runtime: executor::WasmVmPrototype,
    storage_top_trie_changes: HashMap<Vec<u8>, Option<Vec<u8>>, fnv::FnvBuildHasher>,
    offchain_storage_changes: HashMap<Vec<u8>, Option<Vec<u8>>, fnv::FnvBuildHasher>,
    top_trie_root_calculation_cache: calculate_root::CalculationCache,
}

impl ApplyExtrinsic {
    /// Adds an extrinsic and resumes execution.
    ///
    /// See the module-level documentation for more information.
    pub fn add_extrinsic(self, extrinsic: &[u8]) -> BlockBuild {
        debug_assert!(
            matches!(self.shared.stage, Stage::ApplyExtrinsic)
                || matches!(self.shared.stage, Stage::InherentExtrinsics)
        );

        let init_result = runtime_externals::run(runtime_externals::Config {
            virtual_machine: self.parent_runtime,
            function_to_call: "BlockBuilder_apply_extrinsic",
            parameter: {
                // The `BlockBuilder_apply_extrinsic` function expects a SCALE-encoded `Vec<u8>`.
                let len = util::encode_scale_compact_usize(extrinsic.len());
                iter::once(len)
                    .map(either::Left)
                    .chain(iter::once(extrinsic).map(either::Right))
            },
            top_trie_root_calculation_cache: Some(self.top_trie_root_calculation_cache),
            storage_top_trie_changes: self.storage_top_trie_changes,
            offchain_storage_changes: self.offchain_storage_changes,
        });

        let vm = match init_result {
            Ok(vm) => vm,
            Err(err) => return BlockBuild::Finished(Err(Error::VmInit(err))),
        };

        BlockBuild::from_inner(
            vm,
            Shared {
                stage: Stage::ApplyExtrinsic,
                ..self.shared
            },
        )
    }

    /// Indicate that no more extrinsics will be added, and resume execution.
    pub fn finish(self) -> BlockBuild {
        debug_assert!(
            matches!(self.shared.stage, Stage::ApplyExtrinsic)
                || matches!(self.shared.stage, Stage::InherentExtrinsics)
        );

        let init_result = runtime_externals::run(runtime_externals::Config {
            virtual_machine: self.parent_runtime,
            function_to_call: "BlockBuilder_finalize_block",
            parameter: iter::empty::<&[u8]>(),
            top_trie_root_calculation_cache: Some(self.top_trie_root_calculation_cache),
            storage_top_trie_changes: self.storage_top_trie_changes,
            offchain_storage_changes: self.offchain_storage_changes,
        });

        let vm = match init_result {
            Ok(vm) => vm,
            Err(err) => return BlockBuild::Finished(Err(Error::VmInit(err))),
        };

        BlockBuild::from_inner(
            vm,
            Shared {
                stage: Stage::FinalizeBlock,
                ..self.shared
            },
        )
    }
}

/// Loading a storage value from the parent storage is required in order to continue.
#[must_use]
pub struct StorageGet(runtime_externals::StorageGet, Shared);

impl StorageGet {
    /// Returns the key whose value must be passed to [`StorageGet::inject_value`].
    pub fn key<'a>(&'a self) -> impl Iterator<Item = impl AsRef<[u8]> + 'a> + 'a {
        self.0.key()
    }

    /// Returns the key whose value must be passed to [`StorageGet::inject_value`].
    ///
    /// This method is a shortcut for calling `key` and concatenating the returned slices.
    pub fn key_as_vec(&self) -> Vec<u8> {
        self.0.key_as_vec()
    }

    /// Injects the corresponding storage value.
    // TODO: `value` parameter should be something like `Iterator<Item = impl AsRef<[u8]>`
    pub fn inject_value(self, value: Option<&[u8]>) -> BlockBuild {
        BlockBuild::from_inner(self.0.inject_value(value), self.1)
    }
}

/// Fetching the list of keys with a given prefix from the parent storage is required in order to
/// continue.
#[must_use]
pub struct PrefixKeys(runtime_externals::PrefixKeys, Shared);

impl PrefixKeys {
    /// Returns the prefix whose keys to load.
    pub fn prefix(&self) -> &[u8] {
        self.0.prefix()
    }

    /// Injects the list of keys.
    pub fn inject_keys(self, keys: impl Iterator<Item = impl AsRef<[u8]>>) -> BlockBuild {
        BlockBuild::from_inner(self.0.inject_keys(keys), self.1)
    }
}

/// Fetching the key that follows a given one in the parent storage is required in order to
/// continue.
#[must_use]
pub struct NextKey(runtime_externals::NextKey, Shared);

impl NextKey {
    /// Returns the key whose next key must be passed back.
    pub fn key(&self) -> &[u8] {
        self.0.key()
    }

    /// Injects the key.
    ///
    /// # Panic
    ///
    /// Panics if the key passed as parameter isn't strictly superior to the requested key.
    ///
    pub fn inject_key(self, key: Option<impl AsRef<[u8]>>) -> BlockBuild {
        BlockBuild::from_inner(self.0.inject_key(key), self.1)
    }
}

/// Analyzes the output of a call to `BlockBuilder_inherent_extrinsics`, and pushes the returned
/// value into `block_body`.
fn parse_inherent_extrinsics_output(
    output: &[u8],
    block_body: &mut Vec<Vec<u8>>,
) -> Result<(), Error> {
    let (_, parse_result) = nom::combinator::all_consuming(nom::combinator::flat_map(
        crate::util::nom_scale_compact_usize,
        |num_elems| {
            nom::multi::many_m_n(num_elems, num_elems, |s| {
                nom::combinator::flat_map(
                    crate::util::nom_scale_compact_usize,
                    nom::bytes::complete::take,
                )(s)
            })
        },
    ))(output)
    .map_err(|_: nom::Err<(&[u8], nom::error::ErrorKind)>| Error::BadInherentExtrinsicsOutput)?;

    for item in parse_result {
        block_body.push(item.to_owned());
    }

    Ok(())
}
