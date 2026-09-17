// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Authenticated-header verification for JAM (Gray Paper 0.8.0).
//!
//! A header is *authenticated* when it extends a verified parent, its slot is
//! plausible, its author is a validator of the epoch and holds the sealing key or
//! ticket of the slot, and both Bandersnatch VRF signatures check out. Epoch-mark
//! entropy fields must match the parent's tracked entropy before rotation.
//! Validator and ticket contents are adopted, not recomputed: like BABE's
//! next-epoch digest, they are trusted because an authorized author sealed the
//! header carrying them. State roots, extrinsic hashes, the offenders mark, and
//! validator and ticket contents beyond their shape are not checked.

use super::{
    crypto::{VrfError, bandersnatch_vrf_verify, blake2b_256},
    params::Params,
    state::{LightState, SealingEntry, StateError, epoch_len, has_len},
    types::{Hash, Header},
};

/// Unix time of the start of the JAM common era, 2025-01-01 12:00 UTC
/// (Gray Paper `overview.tex`, "Time"). Slot `s` starts at
/// `JAM_COMMON_ERA + s * slot_seconds`.
pub const JAM_COMMON_ERA: u64 = 1_735_732_800;

/// A header that passed [`verify_header`], or a trusted starting point from
/// [`verified_genesis`], with the light state after it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedHeader {
    pub header: Header,
    /// BLAKE2b-256 of the encoded header, including the seal.
    pub hash: Hash,
    pub slot: u32,
    /// `false` for a fallback seal.
    pub sealed_with_ticket: bool,
    /// The header carried an epoch mark and the state rotated into a new epoch.
    pub epoch_changed: bool,
    /// Light state after applying this header; the tree stores it per block so
    /// children can be verified from any fork.
    pub post_state: LightState,
}

/// Why a header is not an authenticated child of its parent. Checks run in the
/// order of the variants and stop at the first failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The parent's light state or the parameters cannot be verified against.
    InvalidParentState(StateError),
    /// `header.parent` is not the parent's hash.
    ParentMismatch,
    /// The slot is not greater than the parent state's slot.
    SlotNotIncreasing,
    /// The slot starts more than one slot after `now_unix_secs`.
    SlotInFuture,
    /// The header starts a new epoch but carries no epoch mark.
    EpochMarkMissing,
    /// The header carries an epoch mark but stays in the parent's epoch.
    EpochMarkUnexpected,
    /// The epoch mark has an invalid validator count (not a multiple of three in 6..=3C).
    EpochMarkLength,
    /// The epoch mark's entropy differs from the parent's entropy accumulator.
    EpochMarkEntropyMismatch,
    /// The epoch mark's tickets entropy differs from the parent's first snapshot.
    EpochMarkTicketsEntropyMismatch,
    /// A tickets mark outside the first block of the epoch's tail.
    TicketsMarkUnexpected,
    /// A tickets mark without exactly `Params::epoch_len` tickets.
    TicketsMarkLength,
    /// `author_index` is not an index into the epoch's active validators.
    AuthorIndexOutOfRange,
    /// Fallback sealing: the slot's key is not the author's key.
    FallbackAuthorMismatch,
    /// The seal VRF does not verify under the seal context and unsigned header.
    BadSealSignature(VrfError),
    /// Ticket sealing: the seal's VRF output is not the slot's ticket identifier.
    SealTicketMismatch,
    /// The entropy-source VRF does not verify under the seal's output.
    BadEntropySignature(VrfError),
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidParentState(error) => write!(f, "invalid parent state: {error}"),
            Self::ParentMismatch => f.write_str("parent hash mismatch"),
            Self::SlotNotIncreasing => f.write_str("slot not greater than the parent's"),
            Self::SlotInFuture => f.write_str("slot is in the future"),
            Self::EpochMarkMissing => f.write_str("epoch mark missing on epoch change"),
            Self::EpochMarkUnexpected => f.write_str("epoch mark without epoch change"),
            Self::EpochMarkLength => f.write_str("epoch mark validator count mismatch"),
            Self::EpochMarkEntropyMismatch => f.write_str("epoch mark entropy mismatch"),
            Self::EpochMarkTicketsEntropyMismatch => {
                f.write_str("epoch mark tickets entropy mismatch")
            }
            Self::TicketsMarkUnexpected => f.write_str("tickets mark outside the epoch tail start"),
            Self::TicketsMarkLength => f.write_str("tickets mark length differs from epoch length"),
            Self::AuthorIndexOutOfRange => f.write_str("author index out of range"),
            Self::FallbackAuthorMismatch => f.write_str("fallback sealing key is not the author"),
            Self::BadSealSignature(error) => write!(f, "seal signature: {error}"),
            Self::SealTicketMismatch => f.write_str("seal output differs from the slot's ticket"),
            Self::BadEntropySignature(error) => write!(f, "entropy signature: {error}"),
        }
    }
}

impl core::error::Error for VerifyError {}

/// Wraps a trusted header (genesis or a checkpoint) and the light state after it,
/// without any check. `sealed_with_ticket` and `epoch_changed` are `false`.
/// Construct the state with [`LightState::from_anchor`]; shape validation does not
/// authenticate either the header or its state.
pub fn verified_genesis(params: &Params, header: Header, state: LightState) -> VerifiedHeader {
    let hash = header.hash(params);
    VerifiedHeader {
        slot: header.slot,
        hash,
        header,
        sealed_with_ticket: false,
        epoch_changed: false,
        post_state: state,
    }
}

/// Verifies that `header` is an authenticated child of `parent` and returns it with
/// the light state after it.
///
/// In order: parent hash; slot increasing and not more than one slot ahead of
/// `now_unix_secs`; epoch mark present exactly on an epoch change, with the expected
/// validator count and entropy fields matching the parent's `η0` and `η1`; state
/// rotated (`active ← pending ← mark`, entropy history, sealing sequence); tickets
/// mark only on the first block of the epoch's tail and with `epoch_len` entries;
/// author index; seal VRF against the slot's ticket or fallback key with `η3'`;
/// entropy VRF against the seal's output, accumulated into `η0'`.
///
/// Total: never panics, whatever the header or parent state.
pub fn verify_header(
    params: &Params,
    parent: &VerifiedHeader,
    header: Header,
    now_unix_secs: u64,
) -> Result<VerifiedHeader, VerifyError> {
    parent
        .post_state
        .validate(params)
        .map_err(VerifyError::InvalidParentState)?;
    let epoch_len = epoch_len(params).map_err(VerifyError::InvalidParentState)?;

    if header.parent != parent.hash {
        return Err(VerifyError::ParentMismatch);
    }

    let parent_slot = parent.post_state.slot;
    if header.slot <= parent_slot {
        return Err(VerifyError::SlotNotIncreasing);
    }
    check_slot_time(params, header.slot, now_unix_secs)?;

    let parent_epoch = parent_slot / epoch_len;
    let epoch = header.slot / epoch_len;
    let epoch_changed = epoch > parent_epoch;
    let next_pending = match (&header.epoch_mark, epoch_changed) {
        (Some(mark), true) => {
            if !params.is_valid_validator_count(mark.validators.len()) {
                return Err(VerifyError::EpochMarkLength);
            }
            if mark.entropy != parent.post_state.entropy[0] {
                return Err(VerifyError::EpochMarkEntropyMismatch);
            }
            if mark.tickets_entropy != parent.post_state.entropy[1] {
                return Err(VerifyError::EpochMarkTicketsEntropyMismatch);
            }
            Some(&mark.validators)
        }
        (None, true) => return Err(VerifyError::EpochMarkMissing),
        (Some(_), false) => return Err(VerifyError::EpochMarkUnexpected),
        (None, false) => None,
    };

    if let Some(tickets) = &header.tickets_mark {
        let tail_start = params.epoch_tail_start;
        let first_tail_block = !epoch_changed
            && parent_slot % epoch_len < tail_start
            && tail_start <= header.slot % epoch_len;
        if !first_tail_block {
            return Err(VerifyError::TicketsMarkUnexpected);
        }
        if !has_len(tickets, epoch_len) {
            return Err(VerifyError::TicketsMarkLength);
        }
    }

    let mut state = parent.post_state.clone();
    if let Some(next_pending) = next_pending {
        state
            .enter_epoch(params, epoch - parent_epoch == 1, next_pending)
            .map_err(VerifyError::InvalidParentState)?;
    }
    if let Some(tickets) = &header.tickets_mark {
        state.pending_tickets = Some(tickets.clone());
    }

    let author = state
        .active
        .get(usize::from(header.author_index))
        .ok_or(VerifyError::AuthorIndexOutOfRange)?
        .0;

    let entry = state
        .sealing_entry(epoch_len, header.slot)
        .ok_or(VerifyError::InvalidParentState(StateError::SealingLength))?;
    let eta3 = &state.entropy[3];
    let mut encoded = header.encode_unsigned(params);
    let (seal_output, sealed_with_ticket) = match entry {
        SealingEntry::Ticket(ticket) => {
            let mut context = [0; 15 + 32 + 1];
            context[..15].copy_from_slice(b"jam_ticket_seal");
            context[15..47].copy_from_slice(eta3);
            context[47] = ticket.attempt;
            let output = bandersnatch_vrf_verify(&author, &context, &encoded, &header.seal)
                .map_err(VerifyError::BadSealSignature)?;
            if output.0 != ticket.id {
                return Err(VerifyError::SealTicketMismatch);
            }
            (output, true)
        }
        SealingEntry::Key(key) => {
            if *key != author {
                return Err(VerifyError::FallbackAuthorMismatch);
            }
            let mut context = [0; 17 + 32];
            context[..17].copy_from_slice(b"jam_fallback_seal");
            context[17..].copy_from_slice(eta3);
            let output = bandersnatch_vrf_verify(&author, &context, &encoded, &header.seal)
                .map_err(VerifyError::BadSealSignature)?;
            (output, false)
        }
    };

    let mut context = [0; 11 + 32];
    context[..11].copy_from_slice(b"jam_entropy");
    context[11..].copy_from_slice(&seal_output.0);
    let entropy_output = bandersnatch_vrf_verify(&author, &context, &[], &header.entropy_source)
        .map_err(VerifyError::BadEntropySignature)?;
    state.accumulate_entropy(&entropy_output.0);
    state.slot = header.slot;

    encoded.extend_from_slice(&header.seal);
    Ok(VerifiedHeader {
        hash: blake2b_256(&encoded),
        slot: header.slot,
        header,
        sealed_with_ticket,
        epoch_changed,
        post_state: state,
    })
}

/// `JAM_COMMON_ERA + slot * slot_seconds <= now + slot_seconds` in widened,
/// checked arithmetic; an overflowing slot start is in the future.
fn check_slot_time(params: &Params, slot: u32, now_unix_secs: u64) -> Result<(), VerifyError> {
    let slot_seconds = u64::from(params.slot_seconds);
    let slot_start = u64::from(slot)
        .checked_mul(slot_seconds)
        .and_then(|offset| offset.checked_add(JAM_COMMON_ERA))
        .ok_or(VerifyError::SlotInFuture)?;
    if slot_start > now_unix_secs.saturating_add(slot_seconds) {
        return Err(VerifyError::SlotInFuture);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
