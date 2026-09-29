// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Verification-only GRANDPA finality for PolkaJam 0.1.29.
//!
//! This is the CE130 justification format, using the JAM codec, not Substrate's
//! SCALE justification format. It contains no voter, gossip or catch-up state.
//! Header lookup must describe authenticated retained headers on the local tree.
//! Verification proves the target's finality under the supplied authority set;
//! the caller must also enforce ordered authority transitions before pruning.

use super::{
    codec::{self, DecodeError, Decoder},
    crypto,
    params::Params,
    types::{Ed25519Public, Hash, Header},
};
use alloc::{collections::BTreeMap, vec::Vec};

/// Independent allocation and ancestry-work bounds for one proof.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_bytes: usize,
    pub max_ancestry_headers: usize,
    /// Total uncached ancestry steps across all precommits, including tree lookups.
    pub max_ancestry_steps: usize,
}

/// One decoded but unverified CE153 fragment.
#[derive(Debug, Clone)]
pub struct WarpFragment {
    pub header: Header,
    pub justification: Justification,
}

/// Allocation bounds for CE153. The protocol cap is always 32 fragments.
#[derive(Debug, Clone, Copy)]
pub struct WarpLimits {
    pub max_fragments: usize,
    pub max_header_bytes: usize,
    pub proof: Limits,
}

/// Decodes a natural-number count followed by header/justification pairs.
pub fn decode_warp_response(
    params: &Params,
    bytes: &[u8],
    limits: &WarpLimits,
) -> Result<Vec<WarpFragment>, Error> {
    let mut input = Decoder::new(bytes);
    let count = input.length(limits.max_fragments.min(32))?;
    // Smallest fragment: a 297-byte header and an 82-byte justification (round,
    // set id, 68-byte commit target, empty precommit and ancestry lists).
    if count > input.remaining().len() / (297 + 82) {
        return Err(DecodeError::UnexpectedEnd.into());
    }
    let mut fragments = Vec::new();
    fragments
        .try_reserve_exact(count)
        .map_err(|_| Error::ResourceLimit)?;
    for _ in 0..count {
        let bytes = input.remaining();
        let window = &bytes[..bytes.len().min(limits.max_header_bytes)];
        let mut header_input = Decoder::new(window);
        let header = codec::read_header(params, &mut header_input).map_err(|error| {
            if window.len() < bytes.len() && error == DecodeError::UnexpectedEnd {
                Error::ResourceLimit
            } else {
                Error::Decode(error)
            }
        })?;
        input.take(window.len() - header_input.remaining().len())?;
        let justification = read_justification(params, &mut input, limits.proof)?;
        fragments.push(WarpFragment {
            header,
            justification,
        });
    }
    input.finish()?;
    Ok(fragments)
}

/// A GRANDPA vote target with the slot every vote carries beside it.
///
/// Mirrors PolkaJam `27d63b8d` `jam-std-common/src/finality.rs` `GrandpaTarget
/// { hash, state_root }` together with the `Slot` of `GrandpaMessage::Precommit`
/// and `GrandpaCommit::target_slot`; on the wire `hash ++ state_root ++ slot`.
/// Gray Paper 0.8.0 `best_chain.tex` (section "Grandpa and the Best Chain"): the
/// vote is on the header together with its *posterior* state root, and the same
/// hash with a different root is a different block. Equality is therefore over
/// all fields; never compare hashes alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target {
    pub hash: Hash,
    /// Posterior state root of the block `hash`, `M_S(σ')`.
    pub state_root: Hash,
    pub slot: u32,
}

/// A decoded, still untrusted CE130 proof. No header or root is mutated by decoding.
#[derive(Debug, Clone)]
pub struct Justification {
    round: u64,
    set_id: u32,
    target: Target,
    precommits: Vec<Precommit>,
    ancestries: Vec<Header>,
}

#[derive(Debug, Clone)]
struct Precommit {
    target: Target,
    signature: [u8; 64],
    authority: Ed25519Public,
}

/// Rejections are separated so callers can distinguish a set gap from a bad proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Decode(DecodeError),
    ResourceLimit,
    InvalidAuthorities,
    MissingGenesisEpochMark,
    MissingEpochMark,
    WrongSetId { expected: u32, received: u32 },
    TargetMismatch,
    UnknownTarget,
    TargetSlotMismatch,
    UnknownAuthority,
    BadSignature,
    InsufficientWeight,
    InvalidAncestry,
    DuplicateAncestry,
    UnusedAncestry,
    SetIdOverflow,
    SkippedAuthorityTransition,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self, f)
    }
}

impl core::error::Error for Error {}

impl From<DecodeError> for Error {
    fn from(error: DecodeError) -> Self {
        Self::Decode(error)
    }
}

/// Evidence returned only by successful signature, quorum and ancestry checks.
/// Possession alone does not authorize skipping intermediate authority transitions.
#[derive(Debug)]
pub struct VerifiedFinality {
    target: Target,
    set_id: u32,
    authority_fingerprint: Hash,
}

impl VerifiedFinality {
    /// The finalized target. Its `state_root` is signed by the quorum, so it is
    /// the finality-authenticated posterior state root of `hash`.
    pub fn target(&self) -> &Target {
        &self.target
    }

    pub fn set_id(&self) -> u32 {
        self.set_id
    }
}

impl Justification {
    /// Bounds counts before allocation and rejects trailing bytes and noncanonical
    /// natural numbers. Up to two votes per validator allows equivocation evidence;
    /// repeated identities never increase weight during verification.
    pub fn decode(params: &Params, bytes: &[u8], limits: Limits) -> Result<Self, Error> {
        if bytes.len() > limits.max_bytes {
            return Err(Error::ResourceLimit);
        }
        let mut input = Decoder::new(bytes);
        let proof = read_justification(params, &mut input, limits)?;
        input.finish()?;
        Ok(proof)
    }

    fn read(params: &Params, input: &mut Decoder<'_>, limits: Limits) -> Result<Self, Error> {
        let round = input.u64()?;
        let set_id = input.u32()?;
        let target = read_target(input)?;
        let count = input.length(usize::from(params.max_validators) * 2)?;
        // 68-byte target, 64-byte signature, 32-byte authority.
        let precommits = input.list(count, 164, |input| {
            Ok(Precommit {
                target: read_target(input)?,
                signature: input.array()?,
                authority: input.array()?,
            })
        })?;
        let count = input.length(limits.max_ancestry_headers)?;
        // A header without marks or offenders occupies 297 bytes.
        let ancestries = input.list(count, 297, |input| codec::read_header(params, input))?;
        Ok(Self {
            round,
            set_id,
            target,
            precommits,
            ancestries,
        })
    }

    pub fn set_id(&self) -> u32 {
        self.set_id
    }

    pub fn target(&self) -> &Target {
        &self.target
    }

    /// Verifies a proof for `expected_target`, which must be present in `lookup`.
    /// Ancestry headers are hash-linked witnesses, not imports: their seals are not
    /// reverified, and they cannot alter the tree or the authority set.
    /// Every vote must descend from the commit target, even for an equivocator.
    ///
    /// `lookup` returns `(hash, parent, parent_state_root, slot)` of an
    /// authenticated header; `parent_state_root` is the header's prior state root,
    /// which is the parent's posterior root. Ancestry is walked over
    /// `(parent, parent_state_root)` pairs as PolkaJam's `AncestryChain` does, so
    /// a vote reaching the commit target's hash under another root is rejected.
    /// The commit target's own root is taken from the signed commit; the caller
    /// learns it from [`VerifiedFinality::target`].
    pub fn verify(
        &self,
        params: &Params,
        expected_set_id: u32,
        authorities: &[Ed25519Public],
        expected_target: &Hash,
        limits: Limits,
        lookup: impl Fn(&Hash) -> Option<(Hash, Hash, Hash, u32)>,
    ) -> Result<VerifiedFinality, Error> {
        validate_authorities(params, authorities)?;
        if self.set_id != expected_set_id {
            return Err(Error::WrongSetId {
                expected: expected_set_id,
                received: self.set_id,
            });
        }
        if self.target.hash != *expected_target {
            return Err(Error::TargetMismatch);
        }
        let target = lookup(expected_target).ok_or(Error::UnknownTarget)?;
        if target.0 != *expected_target {
            return Err(Error::TargetMismatch);
        }
        if target.3 != self.target.slot {
            return Err(Error::TargetSlotMismatch);
        }
        let mut witnesses = BTreeMap::new();
        for header in &self.ancestries {
            let hash = header.hash(params);
            if witnesses.insert(hash, (header, false)).is_some() {
                return Err(Error::DuplicateAncestry);
            }
        }
        // PolkaJam VoterSet aggregates duplicate authority IDs into their combined
        // unit weight. Repeated votes from such a key count that weight only once.
        let mut weights = BTreeMap::new();
        for authority in authorities {
            *weights.entry(authority).or_insert(0usize) += 1;
        }
        // Proven targets keyed by hash, valued by (state root, slot): a hash met
        // again must carry the same root and slot, or it is another target.
        let mut proven = BTreeMap::new();
        proven.insert(self.target.hash, (self.target.state_root, self.target.slot));
        let mut steps = 0usize;
        let mut signed_weight = 0usize;
        for vote in &self.precommits {
            let weight = weights
                .get_mut(&vote.authority)
                .ok_or(Error::UnknownAuthority)?;
            // Offender placeholders and other small-order keys cannot authenticate
            // a vote. Keep their configured weight in the quorum denominator.
            let usable_key = curve25519_dalek::edwards::CompressedEdwardsY(vote.authority)
                .decompress()
                .is_some_and(|point| !point.is_small_order());
            if !usable_key
                || !crypto::ed25519_verify(
                    &vote.authority,
                    &precommit_payload(&vote.target, self.round, self.set_id),
                    &vote.signature,
                )
            {
                return Err(Error::BadSignature);
            }
            signed_weight += *weight;
            *weight = 0;
            let mut hash = vote.target.hash;
            let mut root = vote.target.state_root;
            let mut slot = vote.target.slot;
            let mut path = Vec::new();
            loop {
                if let Some(known) = proven.get(&hash) {
                    if (root, slot) != *known {
                        return Err(Error::InvalidAncestry);
                    }
                    break;
                }
                if slot <= self.target.slot {
                    return Err(Error::InvalidAncestry);
                }
                if steps >= limits.max_ancestry_steps {
                    return Err(Error::ResourceLimit);
                }
                steps += 1;
                let header = if let Some((header, used)) = witnesses.get_mut(&hash) {
                    *used = true;
                    (
                        header.hash(params),
                        header.parent,
                        header.prior_state_root,
                        header.slot,
                    )
                } else {
                    lookup(&hash).ok_or(Error::InvalidAncestry)?
                };
                if header.3 != slot || header.0 != hash {
                    return Err(Error::InvalidAncestry);
                }
                path.push((hash, (root, slot)));
                hash = header.1;
                root = header.2;
                slot = if hash == self.target.hash {
                    self.target.slot
                } else if let Some((header, _)) = witnesses.get(&hash) {
                    header.slot
                } else if let Some((_, known_slot)) = proven.get(&hash) {
                    *known_slot
                } else {
                    lookup(&hash).ok_or(Error::InvalidAncestry)?.3
                };
                if slot >= header.3 {
                    return Err(Error::InvalidAncestry);
                }
            }
            proven.extend(path);
        }
        if signed_weight < (authorities.len() * 2 / 3 + 1) {
            return Err(Error::InsufficientWeight);
        }
        if witnesses.values().any(|(_, used)| !used) {
            return Err(Error::UnusedAncestry);
        }
        Ok(VerifiedFinality {
            target: self.target,
            set_id: self.set_id,
            authority_fingerprint: authority_fingerprint(authorities),
        })
    }
}

fn read_justification(
    params: &Params,
    input: &mut Decoder<'_>,
    limits: Limits,
) -> Result<Justification, Error> {
    let bytes = input.remaining();
    let window = &bytes[..bytes.len().min(limits.max_bytes)];
    let mut proof_input = Decoder::new(window);
    let proof = Justification::read(params, &mut proof_input, limits).map_err(|error| {
        if window.len() < bytes.len() && error == Error::Decode(DecodeError::UnexpectedEnd) {
            Error::ResourceLimit
        } else {
            error
        }
    })?;
    input.take(window.len() - proof_input.remaining().len())?;
    Ok(proof)
}

/// The [`Justification::verify`] lookup entry of a retained authenticated header:
/// `(hash, parent, parent_state_root, slot)`. The parent's posterior root is the
/// header's prior state root, bytes 32 to 64 of the canonical encoding.
pub fn ancestry_link(block: &super::verify::VerifiedHeader) -> Option<(Hash, Hash, Hash, u32)> {
    let prior_state_root = block.encoded.get(32..64)?.try_into().ok()?;
    Some((block.hash, block.parent, prior_state_root, block.slot))
}

fn read_target(input: &mut Decoder<'_>) -> Result<Target, DecodeError> {
    Ok(Target {
        hash: input.array()?,
        state_root: input.array()?,
        slot: input.u32()?,
    })
}

/// The ONE signed-payload constructor, 97 bytes: `"jam_grandpa_vote" ++
/// encode(Precommit(target, slot)) ++ round ++ set_id`, the message being tag 1,
/// header hash, posterior state root and slot (u32 LE), then round (u64 LE) and
/// set id (u32 LE). This is the Gray Paper's vote on header and posterior root;
/// PolkaJam signs the same since PR #1261 (`27d63b8d`
/// `jam-std-common/src/crypto/ed25519.rs:189-194`, `finality.rs` `GrandpaMessage`).
pub(crate) fn precommit_payload(target: &Target, round: u64, set_id: u32) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(97);
    bytes.extend_from_slice(b"jam_grandpa_vote");
    bytes.push(1);
    bytes.extend_from_slice(&target.hash);
    bytes.extend_from_slice(&target.state_root);
    bytes.extend_from_slice(&target.slot.to_le_bytes());
    bytes.extend_from_slice(&round.to_le_bytes());
    bytes.extend_from_slice(&set_id.to_le_bytes());
    bytes
}

/// GRANDPA's finalized current/next sets, separate from B3's import-time state.
/// No round or voter state is necessary to verify a self-contained justification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthoritySet {
    set_id: u32,
    current: Vec<Ed25519Public>,
    next: Vec<Ed25519Public>,
}

impl AuthoritySet {
    /// Authenticates a fragment and prepares its one-step rotation, without mutation.
    /// Returns the rotated set and the verified commit target: its hash is the
    /// fragment header's, its `state_root` the signed posterior root of that header.
    pub fn advance_warp(
        &self,
        params: &Params,
        fragment: &WarpFragment,
        limits: Limits,
    ) -> Result<(Self, Target), Error> {
        if fragment.justification.set_id() != self.set_id {
            return Err(Error::WrongSetId {
                expected: self.set_id,
                received: fragment.justification.set_id(),
            });
        }
        let mark = fragment
            .header
            .epoch_mark
            .as_ref()
            .ok_or(Error::MissingEpochMark)?;
        let hash = fragment.header.hash(params);
        let proof = fragment.justification.verify(
            params,
            self.set_id,
            &self.current,
            &hash,
            limits,
            |target| {
                (*target == hash).then_some((
                    hash,
                    fragment.header.parent,
                    fragment.header.prior_state_root,
                    fragment.header.slot,
                ))
            },
        )?;
        let next = self
            .after_finalizing(
                params,
                &proof,
                hash,
                fragment.header.slot,
                Some(&mark.validators),
            )?
            .ok_or(Error::MissingEpochMark)?;
        Ok((next, *proof.target()))
    }

    /// Shape validation only. The caller must trust this checkpoint data, whose
    /// values describe GRANDPA immediately AFTER finalizing the anchor header.
    pub fn from_checkpoint(
        params: &Params,
        set_id: u32,
        current: Vec<Ed25519Public>,
        next: Vec<Ed25519Public>,
    ) -> Result<Self, Error> {
        validate_authorities(params, &current)?;
        validate_authorities(params, &next)?;
        Ok(Self {
            set_id,
            current,
            next,
        })
    }

    /// PolkaJam voter.rs:349-359 initializes both sets from the genesis mark.
    pub fn from_genesis(params: &Params, header: &Header) -> Result<Self, Error> {
        let mark = header
            .epoch_mark
            .as_ref()
            .ok_or(Error::MissingGenesisEpochMark)?;
        let keys: Vec<_> = mark
            .validators
            .iter()
            .map(|(_, ed25519)| *ed25519)
            .collect();
        Self::from_checkpoint(params, 0, keys.clone(), keys)
    }

    pub fn set_id(&self) -> u32 {
        self.set_id
    }
    pub fn current(&self) -> &[Ed25519Public] {
        &self.current
    }
    pub fn next(&self) -> &[Ed25519Public] {
        &self.next
    }

    /// Prepares a set change without mutating anything. The caller must first
    /// ensure that no earlier epoch-mark block on this branch was skipped, and
    /// install this result only together with successful tree root advancement.
    /// Proofs under a different authority snapshot cannot trigger a transition.
    pub fn after_finalizing(
        &self,
        params: &Params,
        proof: &VerifiedFinality,
        hash: Hash,
        slot: u32,
        validators: Option<&[super::state::ValidatorPair]>,
    ) -> Result<Option<Self>, Error> {
        if proof.set_id != self.set_id {
            return Err(Error::WrongSetId {
                expected: self.set_id,
                received: proof.set_id,
            });
        }
        if proof.authority_fingerprint != authority_fingerprint(&self.current) {
            return Err(Error::InvalidAuthorities);
        }
        if hash != proof.target.hash || slot != proof.target.slot {
            return Err(Error::TargetMismatch);
        }
        let Some(validators) = validators else {
            return Ok(None);
        };
        let next = validators.iter().map(|(_, ed25519)| *ed25519).collect();
        // PolkaJam node/src/finality/authorities.rs:76-80: current <- old next,
        // next <- finalized mark, set_id += 1. Never rotate at header import.
        let set_id = self.set_id.checked_add(1).ok_or(Error::SetIdOverflow)?;
        Self::from_checkpoint(params, set_id, self.next.clone(), next).map(Some)
    }
}

fn validate_authorities(params: &Params, authorities: &[Ed25519Public]) -> Result<(), Error> {
    if !params.is_valid_validator_count(authorities.len()) {
        return Err(Error::InvalidAuthorities);
    }
    Ok(())
}

fn authority_fingerprint(authorities: &[Ed25519Public]) -> Hash {
    let mut hasher = blake2_rfc::blake2b::Blake2b::new(32);
    for authority in authorities {
        hasher.update(authority);
    }
    let mut hash = [0; 32];
    hash.copy_from_slice(hasher.finalize().as_bytes());
    hash
}

#[cfg(test)]
mod tests;
