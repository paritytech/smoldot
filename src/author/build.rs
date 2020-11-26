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

// TODO: docs

use crate::{
    author::{aura, runtime},
    executor::host,
    header,
    trie::calculate_root,
    util,
};

use alloc::{string::String, vec::Vec};
use core::{iter, num::NonZeroU64, time::Duration};
use hashbrown::HashMap;

pub use runtime::{InherentData, InherentDataConsensus};

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
    pub parent_runtime: host::HostVmPrototype,

    /// Consensus-specific item to put in the digest of the header prototype.
    ///
    /// > **Note**: In the case of Aura and Babe, contains the slot being claimed.
    pub consensus_digest_log_item: ConfigPreRuntime<'a>,

    /// Optional cache corresponding to the storage trie root hash calculation coming from the
    /// parent block verification.
    pub top_trie_root_calculation_cache: Option<calculate_root::CalculationCache>,
}

pub enum ConfigConsensus<'a, TLocAuth> {
    Aura {
        /// Time elapsed since [the Unix Epoch](https://en.wikipedia.org/wiki/Unix_time) (i.e.
        /// 00:00:00 UTC on 1 January 1970), ignoring leap seconds.
        now_from_unix_epoch: Duration,

        /// Duration, in milliseconds, of an Aura slot.
        slot_duration: NonZeroU64,

        /// List of the Aura authorities of the current best block.
        best_block_authorities: header::AuraAuthoritiesIter<'a>,

        /// Iterator to the list of sr25519 public keys available locally.
        local_authorities: TLocAuth,
    },
}

/// Current state of the block building process.
#[must_use]
pub enum Builder {
    /// Block production is idle, waiting for a slot.
    WaitSlot(WaitSlot),

    /// Block generation finished.
    Produced {
        block: Result<Success, runtime::Error>,
        next_slot: WaitSlot,
    },

    /// Currently authoring a block.
    Authoring(BuilderAuthoring),
}

impl Builder {
    pub fn new(config: Config) -> Self {}
}

/// Current state of the block building process.
#[must_use]
pub enum BuilderAuthoring {
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
    // TODO: change it to be only a documentation of what we do, instead of asking the user
    ApplyExtrinsic(ApplyExtrinsic),

    /// Result of the previous call to [`ApplyExtrinsic::add_extrinsic`].
    ///
    /// An [`ApplyExtrinsic`] object is provided in order to continue the operation.
    // TODO: change it to be only a documentation of what we do, instead of asking the user
    ApplyExtrinsicResult {
        /// Result of the previous call to [`ApplyExtrinsic::add_extrinsic`].
        result: Result<Result<(), DispatchError>, TransactionValidityError>,
        /// Object to use to continue trying to push other transactions or finish the block.
        resume: ApplyExtrinsic,
    },

    /// Loading a storage value from the parent storage is required in order to continue.
    StorageGet(StorageGet),

    /// Fetching the list of keys with a given prefix from the parent storage is required in order
    /// to continue.
    PrefixKeys(PrefixKeys),

    /// Fetching the key that follows a given one in the parent storage is required in order to
    /// continue.
    NextKey(NextKey),
}

/// Block production is idle, waiting for a slot.
#[must_use]
pub struct WaitSlot {
    consensus: WaitSlotConsensus,
    shared: Shared,
}

impl WaitSlot {
    /// Returns when block production can begin, as a UNIX timestamp (i.e. number of seconds since
    /// the UNIX epoch, ignoring leap seconds).
    pub fn when(&self) -> Duration {
        // TODO: we can actually start building the block before our slot in some situations?
        match self.consensus {
            WaitSlotConsensus::Aura(claim) => claim.slot_start_from_unix_epoch,
        }
    }

    /// Start the block production.
    ///
    /// Shouldn't be called before the timestamp returned by [`WaitSlot::when`].
    pub fn start(self) -> AuthoringStart {
        todo!()
    }
}

enum WaitSlotConsensus {
    Aura(aura::SlotClaim),
}

/// Ready to start producing blocks.
pub struct AuthoringStart {
    consensus: WaitSlotConsensus,
    shared: Shared,
}

impl AuthoringStart {
    /// Start producing the block.
    pub fn start(self, config: AuthoringStartConfig) -> BuilderAuthoring {
        let inner_block_build = runtime::build_block(runtime::Config {
            parent_hash: config.parent_hash,
            parent_number: config.parent_number,
            parent_runtime: config.parent_runtime,
            top_trie_root_calculation_cache: config.top_trie_root_calculation_cache,
            consensus_digest_log_item: match self.consensus {
                WaitSlotConsensus::Aura(slot) => {
                    runtime::ConfigPreRuntime::Aura(header::AuraPreDigest {
                        slot_number: slot.slot_number,
                    })
                }
            },
        });

        match self.shared.with_runtime_inner(inner_block_build) {
            Builder::Authoring(a) => a,
            _ => unreachable!(),
        }
    }
}

/// Configuration for a block generation.
pub struct AuthoringStartConfig<'a> {
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

    /// Optional cache corresponding to the storage trie root hash calculation coming from the
    /// parent block verification.
    pub top_trie_root_calculation_cache: Option<calculate_root::CalculationCache>,
}

/// The list of inherent extrinsics are needed in order to continue.
#[must_use]
pub struct InherentExtrinsics {
    inner: runtime::InherentExtrinsics,
    shared: Shared,
}

impl InherentExtrinsics {
    /// Injects the inherents extrinsics and resumes execution.
    ///
    /// See the module-level documentation for more information.
    pub fn inject_inherents<'a>(self, inherents: InherentData) -> Builder {
        self.shared
            .with_runtime_inner(self.inner.inject_inherents(inherents))
    }

    /// Injects a raw list of inherents and resumes execution.
    ///
    /// This method is a more weakly-typed equivalent to [`InherentExtrinsics::inject_inherents`].
    /// Only use this method if you know what you're doing.
    pub fn inject_raw_inherents_list<'a>(
        self,
        list: impl ExactSizeIterator<Item = ([u8; 8], impl AsRef<[u8]> + Clone)> + Clone,
    ) -> Builder {
        self.shared
            .with_runtime_inner(self.inner.inject_raw_inherents_list(list))
    }
}

/// More transactions can be added.
#[must_use]
pub struct ApplyExtrinsic {
    inner: runtime::ApplyExtrinsic,
    shared: Shared,
}

impl ApplyExtrinsic {
    /// Adds a SCALE-encoded extrinsic and resumes execution.
    ///
    /// See the module-level documentation for more information.
    pub fn add_extrinsic(mut self, extrinsic: Vec<u8>) -> Builder {
        self.shared
            .with_runtime_inner(self.inner.add_extrinsic(extrinsic))
    }

    /// Indicate that no more extrinsics will be added, and resume execution.
    pub fn finish(mut self) -> Builder {
        self.shared.with_runtime_inner(self.inner.finish())
    }
}

/// Loading a storage value from the parent storage is required in order to continue.
#[must_use]
pub struct StorageGet(runtime::StorageGet, Shared);

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
    pub fn inject_value(self, value: Option<&[u8]>) -> Builder {
        self.1.with_runtime_inner(self.0.inject_value(value))
    }
}

/// Fetching the list of keys with a given prefix from the parent storage is required in order to
/// continue.
#[must_use]
pub struct PrefixKeys(runtime::PrefixKeys, Shared);

impl PrefixKeys {
    /// Returns the prefix whose keys to load.
    pub fn prefix(&self) -> &[u8] {
        self.0.prefix()
    }

    /// Injects the list of keys.
    pub fn inject_keys(self, keys: impl Iterator<Item = impl AsRef<[u8]>>) -> Builder {
        self.1.with_runtime_inner(self.0.inject_keys(keys))
    }
}

/// Fetching the key that follows a given one in the parent storage is required in order to
/// continue.
#[must_use]
pub struct NextKey(runtime::NextKey, Shared);

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
    pub fn inject_key(self, key: Option<impl AsRef<[u8]>>) -> Builder {
        self.1.with_runtime_inner(self.0.inject_key(key))
    }
}

/// Extra information maintained in all variants of the [`Builder`].
#[derive(Debug)]
struct Shared {}

impl Shared {
    fn with_runtime_inner(self, mut inner: runtime::BlockBuild) -> Builder {
        loop {
            match inner {
                runtime::BlockBuild::Finished(result) => todo!(),
                runtime::BlockBuild::InherentExtrinsics(inner) => {
                    break Builder::Authoring(BuilderAuthoring::InherentExtrinsics(InherentExtrinsics {
                        shared: self,
                        inner,
                    }))
                }
                runtime::BlockBuild::ApplyExtrinsic(a) => {
                    inner = a.finish();
                }
                runtime::BlockBuild::ApplyExtrinsicResult { result, resume } => {
                    break Builder::Authoring(BuilderAuthoring::ApplyExtrinsicResult {
                        result,
                        resume: ApplyExtrinsic {
                            inner: resume,
                            shared: self,
                        },
                    })
                }
                runtime::BlockBuild::StorageGet(inner) => {
                    break Builder::Authoring(BuilderAuthoring::StorageGet(StorageGet(inner, self)))
                }
                runtime::BlockBuild::PrefixKeys(inner) => {
                    break Builder::Authoring(BuilderAuthoring::PrefixKeys(PrefixKeys(inner, self)))
                }
                runtime::BlockBuild::NextKey(inner) => {
                    break Builder::Authoring(BuilderAuthoring::NextKey(NextKey(inner, self)))
                }
            }
        }
    }
}
