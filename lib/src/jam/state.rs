// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Safrole state a light client can maintain from headers alone (Gray Paper 0.8.0).
//!
//! The state holds exactly what [`super::verify::verify_header`] needs: the entropy
//! accumulator and its three epochal snapshots (`η`, C(6)), the active (`κ`) and
//! pending (`γ_k`) validator key pairs, the current epoch's sealing sequence (`γ_s`),
//! the last winning-tickets mark of the current epoch, and the last slot (`τ`).
//! The staging set, ticket accumulator, offenders, and everything else in the
//! Safrole state are deliberately not tracked; the marks in headers replace them.

use super::{
    crypto::blake2b_256,
    params::Params,
    types::{BandersnatchPublic, Ed25519Public, GenesisLightState, Hash, SealingSequence, Ticket},
};
use alloc::{sync::Arc, vec::Vec};
use core::num::NonZeroU32;

/// A validator's Bandersnatch and Ed25519 public keys, as carried by an epoch mark.
pub type ValidatorPair = (BandersnatchPublic, Ed25519Public);

/// Epoch history inherited from the anchor or previous finalized epoch mark.
#[derive(Clone, Debug)]
pub struct PreviousEpoch {
    pub eta1: Hash,
    pub eta2: Hash,
    pub pending: Vec<ValidatorPair>,
}

/// Evidence authenticated by the target's parent hash chain, not peer claims.
#[derive(Clone, Debug)]
pub struct TailEvidence {
    pub parent_slot: u32,
    pub tickets_mark: Option<Vec<Ticket>>,
}

/// Light Safrole state after some header. See the module documentation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochState {
    /// `η`: the entropy accumulator `η0` followed by its value at the end of the
    /// three most recently ended epochs (`η1`, `η2`, `η3`).
    pub history: [Hash; 3],
    /// `κ`: validators sealing the current epoch.
    pub active: Vec<ValidatorPair>,
    /// `γ_k`: validators for the *next* epoch. This is what the epoch mark carries.
    /// At an epoch change: `active ← pending`, then `pending ← epoch_mark.validators`.
    pub pending: Vec<ValidatorPair>,
    /// `γ_s`: the current epoch's sealing sequence, `Params::epoch_len` entries.
    pub sealing: SealingSequence,
}

/// Per-block accumulator and shared immutable epoch data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LightState {
    epoch: Arc<EpochState>,
    eta0: Hash,
    pending_tickets: Option<Arc<[Ticket]>>,
    slot: u32,
}

/// Parameters or a state shape that would make header verification index or
/// divide out of bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateError {
    MissingEpochMark,
    EpochEntropyMismatch,
    InvalidParentEpoch,
    /// `Params::epoch_len` is zero, so slots cannot be mapped to epochs.
    ZeroEpochLength,
    /// `Params::max_validators` is zero, so epoch marks would carry no validators.
    ZeroValidatorCount,
    /// The active or pending validator set is empty.
    EmptyValidatorSet,
    /// A nonempty active or pending count is not a multiple of three in 6..=3C.
    InvalidValidatorCount,
    /// The sealing sequence, or a pending tickets mark, does not have `epoch_len` entries.
    SealingLength,
    /// The anchor's ticket accumulator exceeds `epoch_len` entries.
    TicketAccumulatorTooLong,
}

impl core::fmt::Display for StateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::MissingEpochMark => "missing epoch mark",
            Self::EpochEntropyMismatch => "epoch history does not match the mark",
            Self::InvalidParentEpoch => "parent is not in an earlier epoch",
            Self::ZeroEpochLength => "epoch length is zero",
            Self::ZeroValidatorCount => "validator count is zero",
            Self::EmptyValidatorSet => "empty validator set",
            Self::InvalidValidatorCount => "invalid validator set size",
            Self::SealingLength => "sealing sequence length differs from the epoch length",
            Self::TicketAccumulatorTooLong => "ticket accumulator exceeds the epoch length",
        })
    }
}

impl core::error::Error for StateError {}

impl LightState {
    /// Derives state from a finality-authenticated set-change header and tail.
    /// This does not verify seals or finality.
    pub fn after_set_change(
        params: &Params,
        previous: &PreviousEpoch,
        target: &super::types::Header,
        vrf_output: &Hash,
        tail: &TailEvidence,
    ) -> Result<Self, StateError> {
        let epoch_len = epoch_len(params)?;
        let mark = target
            .epoch_mark
            .as_ref()
            .ok_or(StateError::MissingEpochMark)?;
        if mark.tickets_entropy != previous.eta1 {
            return Err(StateError::EpochEntropyMismatch);
        }
        if !params.is_valid_validator_count(previous.pending.len())
            || !params.is_valid_validator_count(mark.validators.len())
        {
            return Err(StateError::InvalidValidatorCount);
        }
        let parent_epoch = tail.parent_slot / epoch_len;
        let target_epoch = target.slot / epoch_len;
        if parent_epoch >= target_epoch {
            return Err(StateError::InvalidParentEpoch);
        }
        if tail
            .tickets_mark
            .as_ref()
            .is_some_and(|tickets| !has_len(tickets, epoch_len))
        {
            return Err(StateError::SealingLength);
        }
        let sealing = match &tail.tickets_mark {
            Some(tickets)
                if parent_epoch.checked_add(1) == Some(target_epoch)
                    && tail.parent_slot % epoch_len >= params.epoch_tail_start =>
            {
                SealingSequence::Tickets(tickets.clone())
            }
            _ => SealingSequence::Keys(fallback_key_sequence(
                params,
                &previous.eta1,
                &previous.pending,
            )?),
        };
        let mut state = Self::from_parts(
            [mark.entropy, mark.entropy, previous.eta1, previous.eta2],
            previous.pending.clone(),
            mark.validators.clone(),
            sealing,
            None,
            target.slot,
        );
        state.accumulate_entropy(vrf_output);
        state.validate(params)?;
        Ok(state)
    }

    /// Constructs trusted state components. Call `validate` to check their shape.
    pub fn from_parts(
        entropy: [Hash; 4],
        active: Vec<ValidatorPair>,
        pending: Vec<ValidatorPair>,
        sealing: SealingSequence,
        pending_tickets: Option<Vec<Ticket>>,
        slot: u32,
    ) -> Self {
        Self {
            epoch: Arc::new(EpochState {
                history: [entropy[1], entropy[2], entropy[3]],
                active,
                pending,
                sealing,
            }),
            eta0: entropy[0],
            pending_tickets: pending_tickets.map(Arc::from),
            slot,
        }
    }

    /// Immutable epoch-constant state.
    pub fn epoch(&self) -> &EpochState {
        &self.epoch
    }
    #[cfg(test)]
    pub(super) fn epoch_mut(&mut self) -> &mut EpochState {
        Arc::make_mut(&mut self.epoch)
    }
    #[cfg(test)]
    pub(super) fn set_entropy(&mut self, entropy: [Hash; 4]) {
        self.eta0 = entropy[0];
        self.epoch_mut().history = [entropy[1], entropy[2], entropy[3]];
    }
    /// Accumulator followed by the three epoch snapshots.
    pub fn entropy(&self) -> [Hash; 4] {
        [
            self.eta0,
            self.epoch.history[0],
            self.epoch.history[1],
            self.epoch.history[2],
        ]
    }
    /// Winning tickets, already in outside-in order.
    pub fn pending_tickets(&self) -> Option<&[Ticket]> {
        self.pending_tickets.as_deref()
    }
    /// Most recent slot.
    pub fn slot(&self) -> u32 {
        self.slot
    }
    pub(super) fn set_slot(&mut self, slot: u32) {
        self.slot = slot;
    }
    pub(super) fn set_pending_tickets(&mut self, tickets: &[Ticket]) {
        self.pending_tickets = Some(Arc::from(tickets));
    }
    pub(super) fn epoch_allocation(&self) -> (usize, usize) {
        let sealing = match &self.epoch.sealing {
            SealingSequence::Keys(v) => v.capacity() * core::mem::size_of::<BandersnatchPublic>(),
            SealingSequence::Tickets(v) => v.capacity() * core::mem::size_of::<Ticket>(),
        };
        (
            Arc::as_ptr(&self.epoch) as usize,
            core::mem::size_of::<EpochState>()
                + 2 * core::mem::size_of::<usize>()
                + (self.epoch.active.capacity() + self.epoch.pending.capacity())
                    * core::mem::size_of::<ValidatorPair>()
                + sealing,
        )
    }
    pub(super) fn tickets_allocation(&self) -> Option<(usize, usize)> {
        self.pending_tickets.as_ref().map(|v| {
            (
                v.as_ptr() as usize,
                (core::mem::size_of_val(v.as_ref()) + 2 * core::mem::size_of::<usize>())
                    .next_multiple_of(core::mem::align_of::<usize>()),
            )
        })
    }
    /// Bootstraps from trusted genesis or checkpoint state items: `active ← C(8)`,
    /// `pending ← C(4).pending_validators`, `sealing ← C(4).sealing`,
    /// `entropy ← C(6)`, `slot ← C(11)`.
    ///
    /// Recovers winning tickets as `Z(C(4).ticket_accumulator)` only when the
    /// accumulator has exactly `E` entries and `slot % E >= Y`. `Z` orders the
    /// id-sorted accumulator outside-in; header marks already have this order.
    /// `GenesisLightState` is the historical name for these four anchor items.
    /// Rejects oversized accumulators and shapes that [`Self::validate`] rejects.
    /// Checks shape only, not the anchor's authenticity or historical consistency.
    pub fn from_anchor(params: &Params, g: &GenesisLightState) -> Result<Self, StateError> {
        let epoch_len = epoch_len(params)?;
        let accumulator = &g.safrole.ticket_accumulator;
        if accumulator.len() > usize_from(epoch_len.get()) {
            return Err(StateError::TicketAccumulatorTooLong);
        }
        let pairs = |keys: &[super::types::ValidatorKey]| -> Vec<ValidatorPair> {
            keys.iter().map(|k| (k.bandersnatch, k.ed25519)).collect()
        };
        let state = Self::from_parts(
            g.entropy,
            pairs(&g.active_validators),
            pairs(&g.safrole.pending_validators),
            g.safrole.sealing.clone(),
            if has_len(accumulator, epoch_len) && g.slot % epoch_len >= params.epoch_tail_start {
                Some(
                    (0..accumulator.len())
                        .map(|i| {
                            let index = if i % 2 == 0 {
                                i / 2
                            } else {
                                accumulator.len() - 1 - i / 2
                            };
                            accumulator[index].clone()
                        })
                        .collect(),
                )
            } else {
                None
            },
            g.slot,
        );
        state.validate(params)?;
        Ok(state)
    }

    /// Checks the shape invariants header verification relies on: a non-zero epoch
    /// length and validator bound, legal independent active and pending counts, and exactly
    /// `epoch_len` sealing entries (and pending tickets, if any).
    ///
    /// Every state produced by `verify_header` from a valid state is valid again.
    /// This does not authenticate a checkpoint or check its historical consistency.
    pub fn validate(&self, params: &Params) -> Result<(), StateError> {
        let epoch_len = epoch_len(params)?;
        if params.max_validators == 0 {
            return Err(StateError::ZeroValidatorCount);
        }
        if self.epoch.active.is_empty() || self.epoch.pending.is_empty() {
            return Err(StateError::EmptyValidatorSet);
        }
        if !params.is_valid_validator_count(self.epoch.active.len())
            || !params.is_valid_validator_count(self.epoch.pending.len())
        {
            return Err(StateError::InvalidValidatorCount);
        }
        let sealing_len = match &self.epoch.sealing {
            SealingSequence::Tickets(tickets) => tickets.len(),
            SealingSequence::Keys(keys) => keys.len(),
        };
        let pending_ok = self
            .pending_tickets
            .as_ref()
            .is_none_or(|tickets| has_len(tickets, epoch_len));
        if sealing_len != usize_from(epoch_len.get()) || !pending_ok {
            return Err(StateError::SealingLength);
        }
        Ok(())
    }

    /// Applies the epoch change that a header in a later epoch than `self.slot`
    /// implies (Gray Paper `safrole.tex`, key rotation, entropy history, and slot
    /// key sequence). `next_pending` is the epoch mark's validator list;
    /// `consecutive` is whether the header's epoch is exactly `epoch(slot) + 1`.
    ///
    /// Rotates `(η1, η2, η3) ← (η0, η1, η2)` (`η0` is updated separately by
    /// [`Self::accumulate_entropy`]), sets `active ← pending` and
    /// `pending ← next_pending`, then selects the sealing sequence: the tickets
    /// mark seen in the previous epoch if there is one and no epoch was skipped,
    /// otherwise the fallback key sequence `F(η2', active')`.
    pub(super) fn enter_epoch(
        &mut self,
        params: &Params,
        consecutive: bool,
        next_pending: &[ValidatorPair],
    ) -> Result<(), StateError> {
        let [eta0, eta1, eta2, _] = self.entropy();
        let active = self.epoch.pending.clone();
        let sealing = match &self.pending_tickets {
            Some(tickets) if consecutive => SealingSequence::Tickets(tickets.to_vec()),
            _ => SealingSequence::Keys(fallback_key_sequence(params, &eta1, &active)?),
        };
        self.epoch = Arc::new(EpochState {
            history: [eta0, eta1, eta2],
            active,
            pending: next_pending.to_vec(),
            sealing,
        });
        self.pending_tickets = None;
        Ok(())
    }

    /// `η0' = blake2b(η0 ++ output)`, where `output` is the header's entropy VRF output.
    pub(super) fn accumulate_entropy(&mut self, output: &Hash) {
        let mut input = [0; 64];
        input[..32].copy_from_slice(&self.eta0);
        input[32..].copy_from_slice(output);
        self.eta0 = blake2b_256(&input);
    }

    /// The sealing entry for `slot`: `γ_s[slot mod E]`. `None` if the sequence is
    /// shorter than the epoch, which [`Self::validate`] rejects.
    pub(super) fn sealing_entry(
        &self,
        epoch_len: NonZeroU32,
        slot: u32,
    ) -> Option<SealingEntry<'_>> {
        let index = usize_from(slot % epoch_len);
        match &self.epoch.sealing {
            SealingSequence::Tickets(tickets) => tickets.get(index).map(SealingEntry::Ticket),
            SealingSequence::Keys(keys) => keys.get(index).map(SealingEntry::Key),
        }
    }
}

/// One entry of the sealing sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SealingEntry<'a> {
    Ticket(&'a Ticket),
    Key(&'a BandersnatchPublic),
}

/// `Params::epoch_len` as a divisor, or [`StateError::ZeroEpochLength`].
pub(super) fn epoch_len(params: &Params) -> Result<NonZeroU32, StateError> {
    NonZeroU32::new(params.epoch_len).ok_or(StateError::ZeroEpochLength)
}

/// Whether a tickets mark has exactly one ticket per slot of the epoch.
pub(super) fn has_len(tickets: &[Ticket], epoch_len: NonZeroU32) -> bool {
    tickets.len() == usize_from(epoch_len.get())
}

/// The fallback key sequence `F(r, k)` (Gray Paper `safrole.tex`, equation
/// "fallbackkeysequence"): for each slot `i` of the epoch, the Bandersnatch key
/// `k[u32_le(blake2b(r ++ u32_le(i))[..4]) mod len(k)]`.
///
/// `r` is `η2'` and `k` the post-rotation active set. Fails on an empty set.
pub fn fallback_key_sequence(
    params: &Params,
    entropy: &Hash,
    validators: &[ValidatorPair],
) -> Result<Vec<BandersnatchPublic>, StateError> {
    if validators.is_empty() {
        return Err(StateError::EmptyValidatorSet);
    }
    let mut input = [0; 36];
    input[..32].copy_from_slice(entropy);
    Ok((0..params.epoch_len)
        .map(|i| {
            input[32..].copy_from_slice(&i.to_le_bytes());
            let hash = blake2b_256(&input);
            let index = u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]);
            // Cyclic indexing into a non-empty list: the remainder is in range.
            validators[usize_from(index) % validators.len()].0
        })
        .collect())
}

/// Lossless on every target smoldot builds for (`usize` is at least 32 bits).
fn usize_from(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jam::types::{SafroleState, ValidatorKey};
    use alloc::vec;

    pub(crate) fn tiny_params() -> Params {
        Params {
            epoch_len: 12,
            max_validators: 6,
            slot_seconds: 6,
            epoch_tail_start: 10,
            max_tickets_per_ext: 3,
            deposit_per_item: 10,
            deposit_per_byte: 1,
            deposit_per_account: 100,
            core_count: 2,
            min_turnaround_period: 32,
            max_accumulate_gas: 10_000_000,
            max_is_authorized_gas: 50_000_000,
            max_refine_gas: 1_000_000_000,
            block_gas_limit: 20_000_000,
            recent_block_count: 8,
            max_work_items: 16,
            max_dependencies: 8,
            max_lookup_anchor_age: 24,
            auth_window: 8,
            auth_queue_len: 80,
            rotation_period: 4,
            max_extrinsics: 128,
            availability_timeout: 5,
            max_authorizer_code_size: 64_000,
            max_input: 13_791_360,
            max_service_code_size: 4_000_000,
            max_imports: 3072,
            max_report_elective_data: 49_152,
            transfer_memo_size: 128,
            max_exports: 3072,
        }
    }

    #[test]
    fn set_change_derivation_modes_history_and_typed_errors() {
        use crate::jam::types::{EpochMark, Header};
        let params = tiny_params();
        let previous = PreviousEpoch {
            eta1: [1; 32],
            eta2: [2; 32],
            pending: vec![([3; 32], [4; 32]); 6],
        };
        let mut target = Header {
            parent: [0; 32],
            prior_state_root: [0; 32],
            extrinsic_hash: [0; 32],
            slot: 12,
            epoch_mark: Some(EpochMark {
                entropy: [5; 32],
                tickets_entropy: previous.eta1,
                validators: vec![([6; 32], [7; 32]); 6],
            }),
            tickets_mark: None,
            author_index: 0,
            entropy_source: [0; 96],
            offenders_mark: vec![],
            seal: [0; 96],
        };
        let tickets = vec![
            Ticket {
                id: [9; 32],
                attempt: 1
            };
            12
        ];
        for (slot, parent_slot, winners, use_tickets) in [
            (12, 11, true, true),
            (12, 9, true, false),
            (36, 11, true, false),
            (12, 11, false, false),
        ] {
            target.slot = slot;
            let tail = TailEvidence {
                parent_slot,
                tickets_mark: winners.then(|| tickets.clone()),
            };
            let state =
                LightState::after_set_change(&params, &previous, &target, &[8; 32], &tail).unwrap();
            assert_eq!(
                state.entropy(),
                [
                    blake2b_256(&[[5; 32], [8; 32]].concat()),
                    [5; 32],
                    [1; 32],
                    [2; 32]
                ]
            );
            assert_eq!(state.epoch().active, previous.pending);
            assert_eq!(
                state.epoch().pending,
                target.epoch_mark.as_ref().unwrap().validators
            );
            assert_eq!(state.slot(), slot);
            assert_eq!(state.pending_tickets(), None);
            assert_eq!(
                state.epoch().sealing,
                if use_tickets {
                    SealingSequence::Tickets(tickets.clone())
                } else {
                    SealingSequence::Keys(
                        fallback_key_sequence(&params, &previous.eta1, &previous.pending).unwrap(),
                    )
                }
            );
        }
        target.slot = 12;
        let mut tail = TailEvidence {
            parent_slot: 11,
            tickets_mark: Some(vec![]),
        };
        assert_eq!(
            LightState::after_set_change(&params, &previous, &target, &[0; 32], &tail),
            Err(StateError::SealingLength)
        );
        tail.tickets_mark = None;
        tail.parent_slot = 12;
        assert_eq!(
            LightState::after_set_change(&params, &previous, &target, &[0; 32], &tail),
            Err(StateError::InvalidParentEpoch)
        );
        tail.parent_slot = 11;
        target.epoch_mark.as_mut().unwrap().tickets_entropy = [99; 32];
        assert_eq!(
            LightState::after_set_change(&params, &previous, &target, &[0; 32], &tail),
            Err(StateError::EpochEntropyMismatch)
        );
        target.epoch_mark.as_mut().unwrap().tickets_entropy = previous.eta1;
        target.epoch_mark.as_mut().unwrap().validators.pop();
        assert_eq!(
            LightState::after_set_change(&params, &previous, &target, &[0; 32], &tail),
            Err(StateError::InvalidValidatorCount)
        );
        target.epoch_mark = None;
        assert_eq!(
            LightState::after_set_change(&params, &previous, &target, &[0; 32], &tail),
            Err(StateError::MissingEpochMark)
        );
        let mut zero = params;
        zero.epoch_len = 0;
        assert_eq!(
            LightState::after_set_change(&zero, &previous, &target, &[0; 32], &tail),
            Err(StateError::ZeroEpochLength)
        );
    }

    #[test]
    #[ignore = "requires external A5 vectors through JAM_A5_FIXTURES"]
    fn a5_set_change_derivation_matches_recorded_states_and_verifies_successors() {
        use crate::jam::{
            crypto::bandersnatch_vrf_output,
            types::Header,
            verify::{verified_genesis, verify_header},
        };
        use serde_json::Value;
        let root = std::env::var_os("JAM_A5_FIXTURES")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                "/home/sebastian/work/repos/jam-light-client-planning/fixtures".into()
            });
        let load = |path: &std::path::Path| -> Value {
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
        };
        let bytes = |v: &Value| hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap();
        let params = Params::from_protocol_parameters(&bytes(
            &load(&root.join("params.json"))["protocol_parameters"],
        ))
        .unwrap();
        let decode_state = |v: &Value| {
            let items: Vec<([u8; 31], Vec<u8>)> = v["state_items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| {
                    (
                        bytes(&item["key_hex"]).try_into().unwrap(),
                        bytes(&item["value_hex"]),
                    )
                })
                .collect();
            LightState::from_anchor(
                &params,
                &GenesisLightState::from_state_items(
                    &params,
                    items.iter().map(|(k, v)| (k, v.as_slice())),
                )
                .unwrap(),
            )
            .unwrap()
        };
        let genesis = load(&root.join("genesis-state.json"));
        let mut parent = verified_genesis(
            &params,
            Header::decode(&params, &bytes(&genesis["header_hex"])).unwrap(),
            decode_state(&genesis["light_state"]),
        );
        let mut previous = PreviousEpoch {
            eta1: parent.post_state.entropy()[1],
            eta2: parent.post_state.entropy()[2],
            pending: parent.post_state.epoch().pending.clone(),
        };
        let mut paths: Vec<_> = std::fs::read_dir(root.join("headers"))
            .unwrap()
            .map(|p| p.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .collect();
        paths.sort();
        let mut history: Vec<Header> = Vec::new();
        let (mut ticket, mut fallback, mut skipped) = (0, 0, 0);
        for path in paths {
            let fixture = load(&path);
            let header = Header::decode(&params, &bytes(&fixture["header_hex"])).unwrap();
            let verified = verify_header(&params, &parent, header.clone(), 1_900_000_000).unwrap();
            if let Some(mark) = &header.epoch_mark {
                let tickets_mark = history
                    .iter()
                    .rev()
                    .take_while(|h| {
                        h.slot / params.epoch_len == parent.slot / params.epoch_len
                            && h.slot % params.epoch_len >= params.epoch_tail_start
                    })
                    .find_map(|h| h.tickets_mark.clone());
                let state = LightState::after_set_change(
                    &params,
                    &previous,
                    &header,
                    &bandersnatch_vrf_output(&header.entropy_source).unwrap().0,
                    &TailEvidence {
                        parent_slot: parent.slot,
                        tickets_mark,
                    },
                )
                .unwrap();
                assert_eq!(state, decode_state(&fixture["post_light_state"]));
                assert_eq!(state, verified.post_state);
                match state.epoch().sealing {
                    SealingSequence::Tickets(_) => ticket += 1,
                    SealingSequence::Keys(_) => fallback += 1,
                }
                skipped += usize::from(
                    header.slot / params.epoch_len > parent.slot / params.epoch_len + 1,
                );
                previous = PreviousEpoch {
                    eta1: mark.entropy,
                    eta2: mark.tickets_entropy,
                    pending: mark.validators.clone(),
                };
                parent = verified_genesis(&params, header.clone(), state);
            } else {
                parent = verified;
            }
            history.push(header);
        }
        assert!(ticket > 0 && fallback > 0 && skipped > 0);
    }

    fn validator(seed: u8) -> ValidatorKey {
        ValidatorKey {
            bandersnatch: [seed; 32],
            ed25519: [seed.wrapping_add(100); 32],
            bls: [seed; 144],
            metadata: [seed; 128],
        }
    }

    fn genesis(params: &Params) -> GenesisLightState {
        let active: Vec<_> = (1..=params.max_validators)
            .map(|i| validator(u8::try_from(i).unwrap()))
            .collect();
        let pending: Vec<_> = (11..=10 + params.max_validators)
            .map(|i| validator(u8::try_from(i).unwrap()))
            .collect();
        GenesisLightState {
            safrole: SafroleState {
                pending_validators: pending,
                epoch_root: [0; 144],
                sealing: SealingSequence::Keys(vec![[1; 32]; usize_from(params.epoch_len)]),
                ticket_accumulator: Vec::new(),
            },
            entropy: [[0; 32], [1; 32], [2; 32], [3; 32]],
            active_validators: active,
            slot: 0,
        }
    }

    #[test]
    fn cloning_shares_epoch_and_tickets_until_transition() {
        let params = tiny_params();
        let mut parent = LightState::from_anchor(&params, &genesis(&params)).unwrap();
        parent.set_pending_tickets(&vec![
            Ticket {
                id: [7; 32],
                attempt: 0
            };
            12
        ]);
        let mut child = parent.clone();
        child.accumulate_entropy(&[8; 32]);
        child.set_slot(11);
        assert!(Arc::ptr_eq(&parent.epoch, &child.epoch));
        assert!(Arc::ptr_eq(
            parent.pending_tickets.as_ref().unwrap(),
            child.pending_tickets.as_ref().unwrap()
        ));
        assert_eq!(parent.epoch_allocation(), child.epoch_allocation());
        assert_eq!(parent.tickets_allocation(), child.tickets_allocation());
        child
            .enter_epoch(&params, true, &parent.epoch().pending)
            .unwrap();
        assert!(!Arc::ptr_eq(&parent.epoch, &child.epoch));
        assert!(child.pending_tickets().is_none());
        assert!(parent.pending_tickets().is_some());
        assert_ne!(parent.entropy(), child.entropy());
    }

    #[test]
    fn anchor_validates_active_and_pending_counts_independently() {
        let mut params = tiny_params();
        params.core_count = 4;
        params.max_validators = 12;
        for active in [0, 3, 5, 6, 7, 9, 12, 15] {
            for pending in [0, 3, 5, 6, 7, 9, 12, 15] {
                let mut anchor = genesis(&params);
                anchor.active_validators = vec![validator(1); active];
                anchor.safrole.pending_validators = vec![validator(2); pending];
                let result = LightState::from_anchor(&params, &anchor);
                if [6, 9, 12].contains(&active) && [6, 9, 12].contains(&pending) {
                    let state = result.unwrap();
                    assert_eq!(state.epoch().active.len(), active);
                    assert_eq!(state.epoch().pending.len(), pending);
                    assert_eq!(state.validate(&params), Ok(()));
                } else if active == 0 || pending == 0 {
                    assert_eq!(result, Err(StateError::EmptyValidatorSet));
                } else {
                    assert_eq!(result, Err(StateError::InvalidValidatorCount));
                }
            }
        }
    }

    #[test]
    fn from_anchor_maps_genesis_state_items() {
        let params = tiny_params();
        let g = genesis(&params);
        let state = LightState::from_anchor(&params, &g).unwrap();
        assert_eq!(state.entropy(), g.entropy);
        assert_eq!(state.slot, 0);
        assert_eq!(state.pending_tickets, None);
        assert_eq!(state.epoch().sealing, g.safrole.sealing);
        assert_eq!(
            state.epoch().active,
            (1..=6)
                .map(|i| ([i; 32], [i + 100; 32]))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            state.epoch().pending,
            (11..=16)
                .map(|i| ([i; 32], [i + 100; 32]))
                .collect::<Vec<_>>()
        );
        assert_ne!(state.epoch().active, state.epoch().pending);
    }

    #[test]
    fn from_anchor_rejects_unusable_shapes() {
        let params = tiny_params();
        let g = genesis(&params);
        let mut zero_epoch = params.clone();
        zero_epoch.epoch_len = 0;
        assert_eq!(
            LightState::from_anchor(&zero_epoch, &g),
            Err(StateError::ZeroEpochLength)
        );
        let mut zero_validators = params.clone();
        zero_validators.max_validators = 0;
        assert_eq!(
            LightState::from_anchor(&zero_validators, &g),
            Err(StateError::ZeroValidatorCount)
        );
        let mut no_active = g.clone();
        no_active.active_validators.clear();
        assert_eq!(
            LightState::from_anchor(&params, &no_active),
            Err(StateError::EmptyValidatorSet)
        );
        let mut no_pending = g.clone();
        no_pending.safrole.pending_validators.clear();
        assert_eq!(
            LightState::from_anchor(&params, &no_pending),
            Err(StateError::EmptyValidatorSet)
        );
        for len in [0, 11, 13] {
            let mut short = g.clone();
            short.safrole.sealing = SealingSequence::Keys(vec![[1; 32]; len]);
            assert_eq!(
                LightState::from_anchor(&params, &short),
                Err(StateError::SealingLength)
            );
            short.safrole.sealing = SealingSequence::Tickets(vec![
                Ticket {
                    id: [0; 32],
                    attempt: 0
                };
                len
            ]);
            assert_eq!(
                LightState::from_anchor(&params, &short),
                Err(StateError::SealingLength)
            );
        }
        let mut state = LightState::from_anchor(&params, &g).unwrap();
        state.pending_tickets = Some(Arc::from([]));
        assert_eq!(state.validate(&params), Err(StateError::SealingLength));
    }

    #[test]
    fn anchor_ticket_recovery_requires_saturation_and_tail() {
        for (len, order) in [
            (1, vec![0]),
            (5, vec![0, 4, 1, 3, 2]),
            (12, vec![0, 11, 1, 10, 2, 9, 3, 8, 4, 7, 5, 6]),
        ] {
            let mut params = tiny_params();
            params.epoch_len = len;
            params.epoch_tail_start = len - 1;
            let mut g = genesis(&params);
            g.slot = 3 * len - 1;
            g.safrole.ticket_accumulator = (0..len)
                .map(|i| Ticket {
                    id: [u8::try_from(i).unwrap(); 32],
                    attempt: u8::try_from(i % 3).unwrap(),
                })
                .collect();
            let winners: Vec<_> = order
                .into_iter()
                .map(|i| g.safrole.ticket_accumulator[i].clone())
                .collect();
            let mut state = LightState::from_anchor(&params, &g).unwrap();
            assert_eq!(state.pending_tickets(), Some(winners.as_slice()));
            state
                .enter_epoch(&params, true, &state.epoch().pending.clone())
                .unwrap();
            assert_eq!(state.epoch().sealing, SealingSequence::Tickets(winners));
            assert_eq!(state.pending_tickets, None);

            if len > 1 {
                g.slot -= 1;
                let mut state = LightState::from_anchor(&params, &g).unwrap();
                assert_eq!(state.pending_tickets, None);
                let fallback =
                    fallback_key_sequence(&params, &state.entropy()[1], &state.epoch().pending)
                        .unwrap();
                state
                    .enter_epoch(&params, true, &state.epoch().pending.clone())
                    .unwrap();
                assert_eq!(state.epoch().sealing, SealingSequence::Keys(fallback));
                g.slot += 1;
            }
            g.safrole.ticket_accumulator.pop();
            assert_eq!(
                LightState::from_anchor(&params, &g)
                    .unwrap()
                    .pending_tickets,
                None
            );
        }
    }

    #[test]
    fn anchor_rejects_oversized_accumulator_and_zero_epoch() {
        let mut params = tiny_params();
        let mut g = genesis(&params);
        g.safrole.ticket_accumulator = vec![
            Ticket {
                id: [0; 32],
                attempt: 0
            };
            13
        ];
        for slot in [9, 10, 11] {
            g.slot = slot;
            assert_eq!(
                LightState::from_anchor(&params, &g),
                Err(StateError::TicketAccumulatorTooLong)
            );
        }
        params.epoch_len = 0;
        for len in [13, 12, 0] {
            g.safrole.ticket_accumulator.truncate(len);
            assert_eq!(
                LightState::from_anchor(&params, &g),
                Err(StateError::ZeroEpochLength)
            );
        }
    }

    #[test]
    fn fallback_sequence_shape() {
        let params = tiny_params();
        let single = [([7; 32], [8; 32])];
        assert_eq!(
            fallback_key_sequence(&params, &[0; 32], &single),
            Ok(vec![[7; 32]; 12])
        );
        assert_eq!(
            fallback_key_sequence(&params, &[0; 32], &[]),
            Err(StateError::EmptyValidatorSet)
        );
        let many: Vec<_> = (0..6).map(|i| ([i; 32], [i; 32])).collect();
        let a = fallback_key_sequence(&params, &[0; 32], &many).unwrap();
        let b = fallback_key_sequence(&params, &[1; 32], &many).unwrap();
        assert_eq!(a.len(), 12);
        assert_ne!(a, b);
        assert!(a.iter().all(|key| many.iter().any(|(bs, _)| bs == key)));
        // Independent evaluation of the Gray Paper formula for slot 5.
        let mut input = [0; 36];
        input[32..].copy_from_slice(&5_u32.to_le_bytes());
        let hash = blake2b_256(&input);
        let index = u32::from_le_bytes(hash[..4].try_into().unwrap()) % 6;
        assert_eq!(a[5], many[usize::try_from(index).unwrap()].0);
    }

    #[test]
    fn enter_epoch_rotates_pending_into_active() {
        let params = tiny_params();
        let mut state = LightState::from_anchor(&params, &genesis(&params)).unwrap();
        let next: Vec<ValidatorPair> = (21..27).map(|i| ([i; 32], [i; 32])).collect();
        let before = state.clone();
        state.enter_epoch(&params, true, &next).unwrap();
        assert_eq!(state.epoch().active, before.epoch().pending);
        assert_eq!(state.epoch().pending, next);
        assert_eq!(
            state.entropy(),
            [
                before.entropy()[0],
                before.entropy()[0],
                before.entropy()[1],
                before.entropy()[2]
            ]
        );
        assert_eq!(
            state.epoch().sealing,
            SealingSequence::Keys(
                fallback_key_sequence(&params, &before.entropy()[1], &before.epoch().pending)
                    .unwrap()
            )
        );
        assert_eq!(state.pending_tickets, None);
        // η0 is only touched by the entropy accumulation.
        state.accumulate_entropy(&[9; 32]);
        let mut input = [0; 64];
        input[..32].copy_from_slice(&before.entropy()[0]);
        input[32..].fill(9);
        assert_eq!(state.entropy()[0], blake2b_256(&input));
        assert_eq!(state.entropy()[1..], before.entropy()[..3]);
    }

    #[test]
    fn enter_epoch_uses_tickets_only_when_consecutive() {
        let params = tiny_params();
        let tickets: Vec<_> = (0..12)
            .map(|i| Ticket {
                id: [i; 32],
                attempt: 0,
            })
            .collect();
        let base = LightState::from_anchor(&params, &genesis(&params)).unwrap();
        let next = base.epoch().pending.clone();
        let mut consecutive = base.clone();
        consecutive.pending_tickets = Some(Arc::from(tickets.clone()));
        consecutive.enter_epoch(&params, true, &next).unwrap();
        assert_eq!(
            consecutive.epoch().sealing,
            SealingSequence::Tickets(tickets.clone())
        );
        assert_eq!(consecutive.pending_tickets, None);
        let mut skipped = base.clone();
        skipped.pending_tickets = Some(Arc::from(tickets));
        skipped.enter_epoch(&params, false, &next).unwrap();
        assert!(matches!(skipped.epoch().sealing, SealingSequence::Keys(_)));
        assert_eq!(skipped.pending_tickets, None);
        let mut empty = base;
        Arc::make_mut(&mut empty.epoch).pending.clear();
        assert_eq!(
            empty.enter_epoch(&params, true, &next),
            Err(StateError::EmptyValidatorSet)
        );
    }
}
