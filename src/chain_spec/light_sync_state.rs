use super::structs::StorageData;
use parity_scale_codec::*;
use primitive_types::H256;
use serde::{Deserialize, Serialize};

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
    epochs: std::collections::BTreeMap<(H256, u32), PersistedEpoch>,
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
    authorities: Vec<([u8; 32], u64)>,
    randomness: [u8; 32],
    config: BabeEpochConfiguration,
}

#[derive(Debug, Decode, Encode)]
pub(super) struct BabeEpochConfiguration {
    c: (u64, u64),
    allowed_slots: AllowedSlots,
}

#[derive(Debug, Encode, Decode)]
pub enum AllowedSlots {
    PrimarySlots,
    PrimaryAndSecondaryPlainSlots,
    PrimaryAndSecondaryVRFSlots,
}

#[derive(Debug, Decode, Encode)]
pub(super) struct AuthoritySet {
    current_authorities: Vec<crate::header::GrandpaAuthority>,
    set_id: u64,
    pending_standard_changes: ForkTree<PendingChange>,
    pending_forced_changes: Vec<PendingChange>,
}

#[derive(Debug, Decode, Encode)]
pub(super) struct PendingChange {
    next_authorities: Vec<crate::header::GrandpaAuthority>,
    delay: u32,
    canon_height: u32,
    canon_hash: H256,
    delay_kind: DelayKind,
}

#[derive(Debug, Decode, Encode)]
pub(super) enum DelayKind {
    Finalized,
    Best { median_last_finalized: u32 },
}

#[derive(Debug, Decode, Encode)]
pub(super) struct ForkTree<T> {
    roots: Vec<ForkTreeNode<T>>,
    best_finalized_number: Option<u32>,
}

#[derive(Debug, Decode, Encode)]
pub(super) struct ForkTreeNode<T> {
    hash: H256,
    number: u32,
    data: T,
    children: Vec<Self>,
}
