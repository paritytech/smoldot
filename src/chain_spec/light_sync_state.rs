// Copyright (C) 2019-2020 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::header::BabeNextConfig;
use alloc::collections::BTreeMap;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct StorageData(#[serde(with = "impl_serde::serialize")] pub(super) Vec<u8>);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub(super) struct LightSyncState {
    babe_epoch_changes: StorageData,
    babe_finalized_block_weight: u32,
    finalized_block_header: StorageData,
    grandpa_authority_set: StorageData,
}

impl LightSyncState {
    pub(super) fn decode(&self) -> DecodedLightSyncState {
        let mut grandpa_authority_set_slice = &self.grandpa_authority_set.0[..];
        let mut babe_epoch_changes_slice = &self.babe_epoch_changes.0[..];

        let decoded = DecodedLightSyncState {
            babe_finalized_block_weight: self.babe_finalized_block_weight,
            finalized_block_header: crate::header::decode(&self.finalized_block_header.0[..])
                .unwrap()
                .into(),
            grandpa_authority_set: AuthoritySet::decode(&mut grandpa_authority_set_slice).unwrap(),
            babe_epoch_changes: EpochChanges::decode(&mut babe_epoch_changes_slice).unwrap(),
        };

        assert!(grandpa_authority_set_slice.is_empty());
        assert!(babe_epoch_changes_slice.is_empty());

        decoded
    }
}

#[derive(Debug)]
pub(super) struct DecodedLightSyncState {
    babe_epoch_changes: EpochChanges,
    babe_finalized_block_weight: u32,
    finalized_block_header: crate::header::Header,
    grandpa_authority_set: AuthoritySet,
}

#[derive(Debug, Decode, Encode)]
pub(super) struct EpochChanges {
    inner: ForkTree<PersistedEpochHeader>,
    epochs: BTreeMap<([u8; 32], u32), PersistedEpoch>,
}

#[derive(Debug, Decode, Encode)]
pub(super) enum PersistedEpochHeader {
    Genesis(EpochHeader, EpochHeader),
    Regular(EpochHeader),
}

#[derive(Debug, Decode, Encode)]
pub(super) struct EpochHeader {
    start_slot: u64,
    end_slot: u64,
}

#[derive(Debug, Decode, Encode)]
pub(super) enum PersistedEpoch {
    Genesis(BabeEpoch, BabeEpoch),
    Regular(BabeEpoch),
}

#[derive(Debug, Decode, Encode)]
pub(super) struct BabeEpoch {
    epoch_index: u64,
    slot_number: u64,
    duration: u64,
    authorities: Vec<BabeAuthority>,
    randomness: [u8; 32],
    config: BabeNextConfig,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Encode, Decode)]
pub struct BabeAuthority {
    /// Sr25519 public key.
    pub public_key: [u8; 32],
    /// Arbitrary number indicating the weight of the authority.
    ///
    /// This value can only be compared to other weight values.
    // TODO: should be NonZeroU64; requires deep changes in decoding code though
    pub weight: u64,
}

#[derive(Debug, Decode, Encode)]
pub(super) struct AuthoritySet {
    current_authorities: Vec<GrandpaAuthority>,
    set_id: u64,
    pending_standard_changes: ForkTree<PendingChange>,
    pending_forced_changes: Vec<PendingChange>,
}

#[derive(Debug, Decode, Encode)]
pub(super) struct PendingChange {
    next_authorities: Vec<GrandpaAuthority>,
    delay: u32,
    canon_height: u32,
    canon_hash: [u8; 32],
    delay_kind: DelayKind,
}

#[derive(Debug, Decode, Encode)]
pub(super) enum DelayKind {
    Finalized,
    Best { median_last_finalized: u32 },
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Encode, Decode)]
pub struct GrandpaAuthority {
    /// Ed25519 public key.
    pub public_key: [u8; 32],

    /// Arbitrary number indicating the weight of the authority.
    ///
    /// This value can only be compared to other weight values.
    // TODO: should be NonZeroU64; requires deep changes in decoding code though
    pub weight: u64,
}

#[derive(Debug, Decode, Encode)]
pub(super) struct ForkTree<T> {
    roots: Vec<ForkTreeNode<T>>,
    best_finalized_number: Option<u32>,
}

#[derive(Debug, Decode, Encode)]
pub(super) struct ForkTreeNode<T> {
    hash: [u8; 32],
    number: u32,
    data: T,
    children: Vec<Self>,
}
