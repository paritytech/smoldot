// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Gray Paper 0.8.0 appendix C serialization and JAMNP-S message payloads.
//!
//! Decoders consume the entire input, reject non-canonical discriminators, and
//! check lengths against both the chain parameters and the available bytes before
//! allocating. Cryptographic and consensus validity are deliberately not checked.
//! Encoders serialize caller-owned values; callers must respect the documented
//! list lengths (in particular, an epoch's worth of sealing tickets or keys).
//! Epoch-mark and pending/active validator lists carry natural-number length
//! prefixes, bounded by `max_validators`. Consensus validates the actual set sizes.

use super::{
    params::Params,
    types::{
        Announcement, Block, BlockRequest, Direction, Entropy, EpochMark, Final, GenesisLightState,
        Handshake, Hash, Header, SafroleState, SealingSequence, Ticket, TicketEnvelope,
        TicketsMark, ValidatorKey,
    },
};
use alloc::vec::Vec;

/// A malformed encoding or a length which cannot be safely decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    UnexpectedEnd,
    TrailingBytes,
    NonCanonicalNatural,
    InvalidDiscriminant(u8),
    LengthLimit,
    AllocationFailed,
    InvalidParameters,
    MissingStateItem(u8),
    DuplicateStateItem(u8),
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self, f)
    }
}

impl core::error::Error for DecodeError {}

/// A checked cursor shared with the fixed-width protocol parameter parser.
pub(super) struct Decoder<'a> {
    bytes: &'a [u8],
}

impl<'a> Decoder<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        let (value, rest) = self
            .bytes
            .split_at_checked(len)
            .ok_or(DecodeError::UnexpectedEnd)?;
        self.bytes = rest;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        self.take(N)?
            .try_into()
            .map_err(|_| DecodeError::UnexpectedEnd)
    }

    fn byte(&mut self) -> Result<u8, DecodeError> {
        let [value] = self.array()?;
        Ok(value)
    }

    pub(super) fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub(super) fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub(super) fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    pub(super) fn finish(self) -> Result<(), DecodeError> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes)
        }
    }

    fn natural(&mut self) -> Result<u64, DecodeError> {
        let first = self.byte()?;
        let extra = first.leading_ones();
        let value = if extra == 8 {
            self.u64()?
        } else {
            let mut value = u64::from(first & (0x7f >> extra)) << (8 * extra);
            for i in 0..extra {
                value |= u64::from(self.byte()?) << (8 * i);
            }
            value
        };
        if extra != 0 && value < (1_u64 << (7 * extra)) {
            return Err(DecodeError::NonCanonicalNatural);
        }
        Ok(value)
    }

    fn length(&mut self, max: usize) -> Result<usize, DecodeError> {
        let len = usize::try_from(self.natural()?).map_err(|_| DecodeError::LengthLimit)?;
        if len > max {
            return Err(DecodeError::LengthLimit);
        }
        Ok(len)
    }

    fn option<T>(
        &mut self,
        read: impl FnOnce(&mut Self) -> Result<T, DecodeError>,
    ) -> Result<Option<T>, DecodeError> {
        match self.byte()? {
            0 => Ok(None),
            1 => read(self).map(Some),
            tag => Err(DecodeError::InvalidDiscriminant(tag)),
        }
    }

    fn list<T>(
        &mut self,
        count: usize,
        min_size: usize,
        mut read: impl FnMut(&mut Self) -> Result<T, DecodeError>,
    ) -> Result<Vec<T>, DecodeError> {
        // Every caller uses a nonzero minimum encoded size. Division avoids an
        // overflow even when parameters or the encoded count are malicious.
        if count > self.bytes.len().checked_div(min_size).unwrap_or(0) {
            return Err(DecodeError::UnexpectedEnd);
        }
        let mut out = Vec::new();
        out.try_reserve_exact(count)
            .map_err(|_| DecodeError::AllocationFailed)?;
        for _ in 0..count {
            out.push(read(self)?);
        }
        Ok(out)
    }
}

fn complete<T>(
    bytes: &[u8],
    read: impl FnOnce(&mut Decoder<'_>) -> Result<T, DecodeError>,
) -> Result<T, DecodeError> {
    let mut input = Decoder::new(bytes);
    let value = read(&mut input)?;
    input.finish()?;
    Ok(value)
}

/// Decodes exactly one canonical Gray Paper natural number (one to nine bytes).
pub fn decode_natural(bytes: &[u8]) -> Result<u64, DecodeError> {
    complete(bytes, |input| input.natural())
}

/// Encodes a natural number using Gray Paper appendix C, not SCALE compact.
pub fn encode_natural(value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    write_natural(value, &mut out);
    out
}

fn write_natural(value: u64, out: &mut Vec<u8>) {
    for extra in 0..8 {
        if value < (1_u64 << (7 * (extra + 1))) {
            let prefix = if extra == 0 {
                0
            } else {
                u8::MAX << (8 - extra)
            };
            out.push(prefix | (value >> (8 * extra)).to_le_bytes()[0]);
            out.extend(value.to_le_bytes().iter().take(extra));
            return;
        }
    }
    out.push(0xff);
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_length(len: usize, out: &mut Vec<u8>) {
    // usize is at most 64 bits on Rust's supported targets.
    write_natural(len as u64, out);
}

fn epoch_len(params: &Params) -> Result<usize, DecodeError> {
    usize::try_from(params.epoch_len).map_err(|_| DecodeError::InvalidParameters)
}

fn read_ticket(input: &mut Decoder<'_>) -> Result<Ticket, DecodeError> {
    Ok(Ticket {
        id: input.array()?,
        attempt: input.byte()?,
    })
}

fn write_ticket(ticket: &Ticket, out: &mut Vec<u8>) {
    out.extend_from_slice(&ticket.id);
    out.push(ticket.attempt);
}

impl Ticket {
    /// Decodes a 32-byte identifier and a fixed-width one-byte attempt.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        complete(bytes, read_ticket)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_ticket(self, &mut out);
        out
    }
}

/// Decodes the tickets extrinsic: a length-prefixed list of ring-VRF proofs.
/// Proof verification and attempt-number validity are not part of the codec.
pub fn decode_tickets_extrinsic(
    params: &Params,
    bytes: &[u8],
) -> Result<Vec<TicketEnvelope>, DecodeError> {
    complete(bytes, |input| {
        let count = input.length(usize::from(params.max_tickets_per_ext))?;
        input.list(count, 785, |input| {
            Ok(TicketEnvelope {
                attempt: input.byte()?,
                signature: input.array()?,
            })
        })
    })
}

/// Encodes tickets without validating their count. The caller must supply at
/// most `Params::max_tickets_per_ext` envelopes.
pub fn encode_tickets_extrinsic(tickets: &[TicketEnvelope]) -> Vec<u8> {
    let mut out = Vec::new();
    write_length(tickets.len(), &mut out);
    for ticket in tickets {
        out.push(ticket.attempt);
        out.extend_from_slice(&ticket.signature);
    }
    out
}

fn read_validator(input: &mut Decoder<'_>) -> Result<ValidatorKey, DecodeError> {
    Ok(ValidatorKey {
        bandersnatch: input.array()?,
        ed25519: input.array()?,
        bls: input.array()?,
        metadata: input.array()?,
    })
}

fn write_validator(key: &ValidatorKey, out: &mut Vec<u8>) {
    out.extend_from_slice(&key.bandersnatch);
    out.extend_from_slice(&key.ed25519);
    out.extend_from_slice(&key.bls);
    out.extend_from_slice(&key.metadata);
}

impl ValidatorKey {
    /// Decodes the 336-byte key tuple; does not validate curve points.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        complete(bytes, read_validator)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_validator(self, &mut out);
        out
    }
}

fn read_epoch_mark(params: &Params, input: &mut Decoder<'_>) -> Result<EpochMark, DecodeError> {
    let entropy = input.array()?;
    let tickets_entropy = input.array()?;
    let len = input.length(usize::from(params.max_validators))?;
    let validators = input.list(len, 64, |input| Ok((input.array()?, input.array()?)))?;
    Ok(EpochMark {
        entropy,
        tickets_entropy,
        validators,
    })
}

fn write_epoch_mark(mark: &EpochMark, out: &mut Vec<u8>) {
    out.extend_from_slice(&mark.entropy);
    out.extend_from_slice(&mark.tickets_entropy);
    write_length(mark.validators.len(), out);
    for (bandersnatch, ed25519) in &mark.validators {
        out.extend_from_slice(bandersnatch);
        out.extend_from_slice(ed25519);
    }
}

impl EpochMark {
    /// Decodes a present mark, without the surrounding header's option tag.
    pub fn decode(params: &Params, bytes: &[u8]) -> Result<Self, DecodeError> {
        complete(bytes, |input| read_epoch_mark(params, input))
    }

    /// Encodes a present mark without validating its validator count. The caller
    /// must supply at most `params.max_validators` pairs. A count is encoded.
    pub fn encode(&self, _params: &Params) -> Vec<u8> {
        let mut out = Vec::new();
        write_epoch_mark(self, &mut out);
        out
    }
}

/// Decodes exactly `epoch_len` tickets, without a count or an option tag.
pub fn decode_tickets_mark(params: &Params, bytes: &[u8]) -> Result<TicketsMark, DecodeError> {
    complete(bytes, |input| {
        input.list(epoch_len(params)?, 33, read_ticket)
    })
}

/// The caller must supply exactly `epoch_len` tickets.
pub fn encode_tickets_mark(tickets: &[Ticket]) -> Vec<u8> {
    let mut out = Vec::new();
    for ticket in tickets {
        write_ticket(ticket, &mut out);
    }
    out
}

fn read_header(params: &Params, input: &mut Decoder<'_>) -> Result<Header, DecodeError> {
    let parent = input.array()?;
    let prior_state_root = input.array()?;
    let extrinsic_hash = input.array()?;
    let slot = input.u32()?;
    let epoch_mark = input.option(|input| read_epoch_mark(params, input))?;
    let tickets_mark = input.option(|input| input.list(epoch_len(params)?, 33, read_ticket))?;
    let author_index = input.u16()?;
    let entropy_source = input.array()?;
    // Culprits and faults each draw from the current and previous sets. Each
    // list is unique, but their concatenation can repeat a key (GP judgments).
    let max_offenders = usize::from(params.max_validators)
        .checked_mul(4)
        .ok_or(DecodeError::InvalidParameters)?;
    let len = input.length(max_offenders)?;
    let offenders_mark = input.list(len, 32, |input| input.array())?;
    let seal = input.array()?;
    Ok(Header {
        parent,
        prior_state_root,
        extrinsic_hash,
        slot,
        epoch_mark,
        tickets_mark,
        author_index,
        entropy_source,
        offenders_mark,
        seal,
    })
}

fn write_unsigned_header(header: &Header, out: &mut Vec<u8>) {
    out.extend_from_slice(&header.parent);
    out.extend_from_slice(&header.prior_state_root);
    out.extend_from_slice(&header.extrinsic_hash);
    out.extend_from_slice(&header.slot.to_le_bytes());
    match &header.epoch_mark {
        None => out.push(0),
        Some(mark) => {
            out.push(1);
            write_epoch_mark(mark, out);
        }
    }
    match &header.tickets_mark {
        None => out.push(0),
        Some(tickets) => {
            out.push(1);
            for ticket in tickets {
                write_ticket(ticket, out);
            }
        }
    }
    out.extend_from_slice(&header.author_index.to_le_bytes());
    out.extend_from_slice(&header.entropy_source);
    write_length(header.offenders_mark.len(), out);
    for offender in &header.offenders_mark {
        out.extend_from_slice(offender);
    }
}

impl Header {
    /// Decodes exactly one header, including its seal.
    pub fn decode(params: &Params, bytes: &[u8]) -> Result<Header, DecodeError> {
        complete(bytes, |input| read_header(params, input))
    }

    /// Encodes a header whose list lengths satisfy `params`.
    pub fn encode(&self, params: &Params) -> Vec<u8> {
        let mut out = self.encode_unsigned(params);
        out.extend_from_slice(&self.seal);
        out
    }

    /// Encodes everything except the seal, in appendix C wire order.
    pub fn encode_unsigned(&self, _params: &Params) -> Vec<u8> {
        let mut out = Vec::new();
        write_unsigned_header(self, &mut out);
        out
    }

    /// Returns BLAKE2b-256 of the complete encoded header, including the seal.
    pub fn hash(&self, params: &Params) -> Hash {
        let digest = blake2_rfc::blake2b::blake2b(32, &[], &self.encode(params));
        let mut hash = [0; 32];
        hash.copy_from_slice(digest.as_bytes());
        hash
    }
}

fn read_validators(
    params: &Params,
    input: &mut Decoder<'_>,
) -> Result<Vec<ValidatorKey>, DecodeError> {
    let len = input.length(usize::from(params.max_validators))?;
    input.list(len, 336, read_validator)
}

/// Decodes C(8): a counted sequence of at most `max_validators` keys.
pub fn decode_active_validators(
    params: &Params,
    bytes: &[u8],
) -> Result<Vec<ValidatorKey>, DecodeError> {
    complete(bytes, |input| read_validators(params, input))
}

/// Encodes C(8) with a count prefix, without validating its length. The caller
/// must supply at most `Params::max_validators` keys.
pub fn encode_active_validators(validators: &[ValidatorKey]) -> Vec<u8> {
    let mut out = Vec::new();
    write_length(validators.len(), &mut out);
    for validator in validators {
        write_validator(validator, &mut out);
    }
    out
}

/// Decodes C(6), four concatenated entropy hashes without a length prefix.
pub fn decode_entropy(bytes: &[u8]) -> Result<Entropy, DecodeError> {
    complete(bytes, |input| {
        Ok([
            input.array()?,
            input.array()?,
            input.array()?,
            input.array()?,
        ])
    })
}

pub fn encode_entropy(entropy: &Entropy) -> Vec<u8> {
    entropy.iter().flatten().copied().collect()
}

/// Decodes C(11), a fixed-width little-endian slot.
pub fn decode_slot(bytes: &[u8]) -> Result<u32, DecodeError> {
    complete(bytes, |input| input.u32())
}

pub fn encode_slot(slot: u32) -> [u8; 4] {
    slot.to_le_bytes()
}

fn read_sealing(params: &Params, input: &mut Decoder<'_>) -> Result<SealingSequence, DecodeError> {
    match input.byte()? {
        0 => Ok(SealingSequence::Tickets(input.list(
            epoch_len(params)?,
            33,
            read_ticket,
        )?)),
        1 => Ok(SealingSequence::Keys(input.list(
            epoch_len(params)?,
            32,
            |input| input.array(),
        )?)),
        tag => Err(DecodeError::InvalidDiscriminant(tag)),
    }
}

fn write_sealing(sealing: &SealingSequence, out: &mut Vec<u8>) {
    match sealing {
        SealingSequence::Tickets(tickets) => {
            out.push(0);
            for ticket in tickets {
                write_ticket(ticket, out);
            }
        }
        SealingSequence::Keys(keys) => {
            out.push(1);
            for key in keys {
                out.extend_from_slice(key);
            }
        }
    }
}

impl SealingSequence {
    pub fn decode(params: &Params, bytes: &[u8]) -> Result<Self, DecodeError> {
        complete(bytes, |input| read_sealing(params, input))
    }

    /// The sequence must contain exactly `params.epoch_len` tickets or keys.
    pub fn encode(&self, _params: &Params) -> Vec<u8> {
        let mut out = Vec::new();
        write_sealing(self, &mut out);
        out
    }
}

impl SafroleState {
    /// Decodes C(4), including pending keys, ring root, sealing, and accumulator.
    pub fn decode(params: &Params, bytes: &[u8]) -> Result<Self, DecodeError> {
        complete(bytes, |input| {
            let pending_validators = read_validators(params, input)?;
            let epoch_root = input.array()?;
            let sealing = read_sealing(params, input)?;
            let len = input.length(epoch_len(params)?)?;
            let ticket_accumulator = input.list(len, 33, read_ticket)?;
            Ok(Self {
                pending_validators,
                epoch_root,
                sealing,
                ticket_accumulator,
            })
        })
    }

    /// Encodes C(4) without validating lengths. Pending validators must have
    /// at most `params.max_validators` entries, sealing must have `params.epoch_len`
    /// entries, and the ticket accumulator must not exceed `params.epoch_len`.
    pub fn encode(&self, _params: &Params) -> Vec<u8> {
        let mut out = encode_active_validators(&self.pending_validators);
        out.extend_from_slice(&self.epoch_root);
        write_sealing(&self.sealing, &mut out);
        write_length(self.ticket_accumulator.len(), &mut out);
        for ticket in &self.ticket_accumulator {
            write_ticket(ticket, &mut out);
        }
        out
    }
}

impl GenesisLightState {
    /// Decodes C(4), C(6), C(8), and C(11) in any order. Other keys are ignored;
    /// missing or duplicate required keys are rejected, even if values agree.
    pub fn from_state_items<'a>(
        params: &Params,
        items: impl Iterator<Item = (&'a [u8; 31], &'a [u8])>,
    ) -> Result<Self, DecodeError> {
        let mut safrole = None;
        let mut entropy = None;
        let mut active_validators = None;
        let mut slot = None;
        for (key, bytes) in items {
            if *key == state_key(4) {
                if safrole.is_some() {
                    return Err(DecodeError::DuplicateStateItem(4));
                }
                safrole = Some(SafroleState::decode(params, bytes)?);
            } else if *key == state_key(6) {
                if entropy.is_some() {
                    return Err(DecodeError::DuplicateStateItem(6));
                }
                entropy = Some(decode_entropy(bytes)?);
            } else if *key == state_key(8) {
                if active_validators.is_some() {
                    return Err(DecodeError::DuplicateStateItem(8));
                }
                active_validators = Some(decode_active_validators(params, bytes)?);
            } else if *key == state_key(11) {
                if slot.is_some() {
                    return Err(DecodeError::DuplicateStateItem(11));
                }
                slot = Some(decode_slot(bytes)?);
            }
        }
        Ok(Self {
            safrole: safrole.ok_or(DecodeError::MissingStateItem(4))?,
            entropy: entropy.ok_or(DecodeError::MissingStateItem(6))?,
            active_validators: active_validators.ok_or(DecodeError::MissingStateItem(8))?,
            slot: slot.ok_or(DecodeError::MissingStateItem(11))?,
        })
    }
}

/// Returns the state key C(index) from the Gray Paper's state merklization.
pub fn state_key(index: u8) -> [u8; 31] {
    let mut key = [0; 31];
    key[0] = index;
    key
}

fn read_final(input: &mut Decoder<'_>) -> Result<Final, DecodeError> {
    Ok(Final {
        hash: input.array()?,
        slot: input.u32()?,
    })
}

fn write_final(final_: &Final, out: &mut Vec<u8>) {
    out.extend_from_slice(&final_.hash);
    out.extend_from_slice(&final_.slot.to_le_bytes());
}

impl Final {
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        complete(bytes, read_final)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_final(self, &mut out);
        out
    }
}

impl Handshake {
    /// Decodes an UP0 payload, excluding the transport's four-byte byte length.
    ///
    /// JAMNP-S does not bound the number of forks by protocol parameters, so the
    /// caller supplies a local resource limit. PolkaJam uses 64 leaves.
    pub fn decode(bytes: &[u8], max_leaves: usize) -> Result<Self, DecodeError> {
        complete(bytes, |input| {
            let final_ = read_final(input)?;
            let len = input.length(max_leaves)?;
            let leaves = input.list(len, 36, read_final)?;
            Ok(Self { final_, leaves })
        })
    }

    /// Encodes an UP0 payload; framing and stream-kind bytes belong to transport.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.final_.encode();
        write_length(self.leaves.len(), &mut out);
        for leaf in &self.leaves {
            write_final(leaf, &mut out);
        }
        out
    }
}

impl Announcement {
    /// Decodes `Header ++ Final`, with no header byte-length prefix.
    pub fn decode(params: &Params, bytes: &[u8]) -> Result<Self, DecodeError> {
        complete(bytes, |input| {
            Ok(Self {
                header: read_header(params, input)?,
                final_: read_final(input)?,
            })
        })
    }

    pub fn encode(&self, params: &Params) -> Vec<u8> {
        let mut out = self.header.encode(params);
        write_final(&self.final_, &mut out);
        out
    }
}

impl BlockRequest {
    /// Decodes the 37-byte CE128 request payload, excluding transport framing.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        complete(bytes, |input| {
            let hash = input.array()?;
            let direction = match input.byte()? {
                0 => Direction::AscendingExclusive,
                1 => Direction::DescendingInclusive,
                tag => return Err(DecodeError::InvalidDiscriminant(tag)),
            };
            let max_blocks = input.u32()?;
            Ok(Self {
                hash,
                direction,
                max_blocks,
            })
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.hash.to_vec();
        out.push(match self.direction {
            Direction::AscendingExclusive => 0,
            Direction::DescendingInclusive => 1,
        });
        out.extend_from_slice(&self.max_blocks.to_le_bytes());
        out
    }
}

/// Skips an extrinsic prefix without allocating or checking its commitment.
/// GP 0.8.0 serialization.tex:133-175, 202-252, 304-313. Returns bytes consumed.
/// Counts are checked before iteration and every advance is bounded by input.
pub(crate) fn skip_extrinsic(params: &Params, bytes: &[u8]) -> Result<usize, DecodeError> {
    let mut input = Decoder::new(bytes);
    fn fixed(input: &mut Decoder<'_>, max: usize, width: usize) -> Result<(), DecodeError> {
        let count = input.length(max)?;
        input.take(count.checked_mul(width).ok_or(DecodeError::LengthLimit)?)?;
        Ok(())
    }
    fn blob(input: &mut Decoder<'_>) -> Result<(), DecodeError> {
        let len = input.length(input.bytes.len())?;
        input.take(len)?;
        Ok(())
    }
    fn boolean(input: &mut Decoder<'_>) -> Result<(), DecodeError> {
        match input.byte()? {
            0 | 1 => Ok(()),
            tag => Err(DecodeError::InvalidDiscriminant(tag)),
        }
    }
    let validators = usize::from(params.max_validators);
    fixed(&mut input, usize::from(params.max_tickets_per_ext), 785)?;
    let preimages = input.length(input.bytes.len() / 5)?;
    for _ in 0..preimages {
        input.take(4)?;
        blob(&mut input)?;
    }
    let guarantees = input.length(usize::from(params.core_count))?;
    for _ in 0..guarantees {
        // Availability specification (including GP 0.8's erasure shards),
        // followed by refinement context's five hashes and two fixed slots.
        input.take(104 + 168)?;
        fixed(&mut input, usize::from(params.max_dependencies), 32)?;
        input.natural()?; // core index
        input.take(32)?; // authorizer
        input.natural()?; // authorization gas
        blob(&mut input)?; // authorization output
        fixed(&mut input, usize::from(params.max_dependencies), 64)?;
        let results = input.length(usize::from(params.max_work_items))?;
        for _ in 0..results {
            input.take(4 + 32 + 32 + 8)?;
            match input.byte()? {
                0 => blob(&mut input)?,
                1..=6 => {}
                tag => return Err(DecodeError::InvalidDiscriminant(tag)),
            }
            for _ in 0..5 {
                input.natural()?;
            }
        }
        input.take(4)?; // guarantee slot
        fixed(&mut input, 3, 2 + 64)?; // three guarantors per core
    }
    fixed(
        &mut input,
        validators,
        32 + usize::from(params.core_count).div_ceil(8) + 2 + 64,
    )?;
    // Disputes is a tuple of three separately counted lists. Do not impose
    // PolkaJam's local 16-entry cap on GP encodings; input bounds the outer list.
    let verdicts = input.length(input.bytes.len() / 37)?;
    for _ in 0..verdicts {
        input.take(32 + 4)?;
        let votes = input.length(validators)?;
        for _ in 0..votes {
            boolean(&mut input)?;
            input.take(2 + 64)?;
        }
    }
    let max_culprits = input.bytes.len() / 128;
    fixed(&mut input, max_culprits, 32 + 32 + 64)?;
    let faults = input.length(input.bytes.len() / 129)?;
    for _ in 0..faults {
        input.take(32)?;
        boolean(&mut input)?;
        input.take(32 + 64)?;
    }
    Ok(bytes.len() - input.bytes.len())
}

impl Block {
    /// Decodes a complete CE128 block sequence, with no count or block lengths.
    /// Extrinsics are delimited structurally and retained as opaque bodies;
    /// neither their commitments nor consensus validity are checked. Limits
    /// bound the number of blocks and the aggregate bytes copied into bodies.
    /// Any malformed block rejects the entire response, including prior blocks.
    pub fn decode_sequence(
        params: &Params,
        bytes: &[u8],
        max_body_bytes: usize,
        max_blocks: usize,
    ) -> Result<Vec<Self>, DecodeError> {
        let mut input = Decoder::new(bytes);
        let mut blocks = Vec::new();
        let mut body_budget = max_body_bytes;
        while !input.bytes.is_empty() {
            if blocks.len() >= max_blocks {
                return Err(DecodeError::LengthLimit);
            }
            let header = read_header(params, &mut input)?;
            let len = skip_extrinsic(params, input.bytes)?;
            body_budget = body_budget
                .checked_sub(len)
                .ok_or(DecodeError::LengthLimit)?;
            let mut body = Vec::new();
            body.try_reserve_exact(len)
                .map_err(|_| DecodeError::AllocationFailed)?;
            body.extend_from_slice(input.take(len)?);
            blocks
                .try_reserve(1)
                .map_err(|_| DecodeError::AllocationFailed)?;
            blocks.push(Self { header, body });
        }
        Ok(blocks)
    }
}

impl Block {
    /// Decodes one already-delimited block, keeping the remaining body opaque.
    ///
    /// CE128 responses concatenate blocks without counts or per-block lengths.
    /// With an opaque body, only a response to a single-block request supplies
    /// this boundary. Do not pass a multi-block response to this method: its
    /// remaining blocks would become part of the first block's opaque body.
    /// Use `decode_sequence` for structurally delimited CE128 responses.
    /// Framing and FIN checks belong to the caller.
    ///
    /// `max_body_bytes` is a local resource limit, not `Params::max_input` (which
    /// limits work packages, not block bodies). The body is not validated.
    pub fn decode(
        params: &Params,
        bytes: &[u8],
        max_body_bytes: usize,
    ) -> Result<Self, DecodeError> {
        let mut input = Decoder::new(bytes);
        let header = read_header(params, &mut input)?;
        if input.bytes.len() > max_body_bytes {
            return Err(DecodeError::LengthLimit);
        }
        let mut body = Vec::new();
        body.try_reserve_exact(input.bytes.len())
            .map_err(|_| DecodeError::AllocationFailed)?;
        body.extend_from_slice(input.bytes);
        Ok(Self { header, body })
    }

    /// Encodes `Header ++ body`, with no extra count or byte-length prefix.
    pub fn encode(&self, params: &Params) -> Vec<u8> {
        let mut out = self.header.encode(params);
        out.extend_from_slice(&self.body);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, vec};
    use rand::{Rng, RngCore, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    fn params() -> Params {
        // No global production parameters. Individual tests adjust their own copy.
        let mut params = Params::from_protocol_parameters(&{
            let mut bytes = [0; 122];
            bytes[24] = 2;
            bytes
        })
        .unwrap();
        params.epoch_len = 12;
        params.max_validators = 6;

        params.slot_seconds = 6;
        params.epoch_tail_start = 10;
        params.max_tickets_per_ext = 3;
        params
    }

    fn validator() -> ValidatorKey {
        ValidatorKey {
            bandersnatch: [1; 32],
            ed25519: [2; 32],
            bls: [3; 144],
            metadata: [4; 128],
        }
    }

    fn header() -> Header {
        Header {
            parent: [1; 32],
            prior_state_root: [2; 32],
            extrinsic_hash: [3; 32],
            slot: 0x04030201,
            epoch_mark: None,
            tickets_mark: None,
            offenders_mark: Vec::new(),
            author_index: 0x0605,
            entropy_source: [7; 96],
            seal: [8; 96],
        }
    }

    fn ticket() -> Ticket {
        Ticket {
            id: [9; 32],
            attempt: 2,
        }
    }

    #[test]
    fn natural_boundaries_and_canonicality() {
        for (value, bytes) in [
            (0, vec![0]),
            (127, vec![127]),
            (128, vec![128, 128]),
            (255, vec![128, 255]),
            (256, vec![129, 0]),
            (16383, vec![191, 255]),
            (16384, vec![192, 0, 64]),
            (1 << 21, vec![0xe0, 0, 0, 0x20]),
            (1 << 28, vec![0xf0, 0, 0, 0, 0x10]),
            (1 << 35, vec![0xf8, 0, 0, 0, 0, 8]),
            (1 << 42, vec![0xfc, 0, 0, 0, 0, 0, 4]),
            (1 << 49, vec![0xfe, 0, 0, 0, 0, 0, 0, 2]),
            (1 << 56, vec![0xff, 0, 0, 0, 0, 0, 0, 0, 1]),
            (u64::MAX, vec![255; 9]),
        ] {
            assert_eq!(encode_natural(value), bytes);
            assert_eq!(decode_natural(&bytes), Ok(value));
        }
        for extra in 1..=8 {
            let boundary = 1_u64 << (7 * extra);
            assert_eq!(encode_natural(boundary - 1).len(), extra);
            assert_eq!(encode_natural(boundary).len(), extra + 1);
            let mut nonzero_overlong = vec![u8::MAX << (8 - extra)];
            nonzero_overlong.extend_from_slice(&(boundary - 1).to_le_bytes()[..extra]);
            assert_eq!(
                decode_natural(&nonzero_overlong),
                Err(DecodeError::NonCanonicalNatural)
            );
            for value in [boundary - 1, boundary, boundary + 1] {
                let bytes = encode_natural(value);
                assert_eq!(decode_natural(&bytes), Ok(value));
                for end in 0..bytes.len() {
                    assert!(decode_natural(&bytes[..end]).is_err());
                }
                let mut trailing = bytes.clone();
                trailing.push(0);
                assert_eq!(decode_natural(&trailing), Err(DecodeError::TrailingBytes));
            }
            let mut overlong = vec![u8::MAX << (8 - extra)];
            overlong.resize(extra + 1, 0);
            assert_eq!(
                decode_natural(&overlong),
                Err(DecodeError::NonCanonicalNatural)
            );
        }
        let mut rng = ChaCha8Rng::seed_from_u64(71);
        for _ in 0..100_000 {
            let value = rng.next_u64();
            assert_eq!(decode_natural(&encode_natural(value)), Ok(value));
        }
    }

    #[test]
    fn header_wire_order_options_and_lengths() {
        let params = params();
        for epoch in [false, true] {
            for tickets in [false, true] {
                let mut h = header();
                if epoch {
                    h.epoch_mark = Some(EpochMark {
                        entropy: [10; 32],
                        tickets_entropy: [11; 32],
                        validators: vec![([12; 32], [13; 32]); 6],
                    });
                }
                if tickets {
                    h.tickets_mark = Some(vec![ticket(); 12]);
                }
                h.offenders_mark = vec![[14; 32]; 2];
                let encoded = h.encode(&params);
                assert_eq!(Header::decode(&params, &encoded), Ok(h.clone()));
                assert_eq!(&encoded[..96], [[1; 32], [2; 32], [3; 32]].concat());
                assert_eq!(&encoded[96..100], &[1, 2, 3, 4]);
                assert_eq!(encoded[100], u8::from(epoch));
                if epoch {
                    assert_eq!(encoded[165], 6);
                    assert_eq!(&encoded[166..230], [[12; 32], [13; 32]].concat());
                }
                let unsigned = h.encode_unsigned(&params);
                assert_eq!(&encoded[..encoded.len() - 96], unsigned);
                assert_eq!(
                    &unsigned[unsigned.len() - 65..],
                    [vec![2], vec![14; 64]].concat()
                );
                for end in 0..encoded.len() {
                    assert!(
                        Header::decode(&params, &encoded[..end]).is_err(),
                        "prefix {end}"
                    );
                }
                let mut trailing = encoded;
                trailing.push(0);
                assert_eq!(
                    Header::decode(&params, &trailing),
                    Err(DecodeError::TrailingBytes)
                );
                if tickets {
                    let mut other = params.clone();
                    other.epoch_len = 13;
                    assert!(Header::decode(&other, &h.encode(&params)).is_err());
                }
            }
        }
        assert_eq!(header().encode(&params).len(), 297);
        for offset in [100, 101] {
            let mut bad = header().encode(&params);
            bad[offset] = 2;
            assert_eq!(
                Header::decode(&params, &bad),
                Err(DecodeError::InvalidDiscriminant(2))
            );
        }
        let mut h = header();
        let hash = h.hash(&params);
        h.seal[0] ^= 1;
        assert_ne!(h.hash(&params), hash);
    }

    #[test]
    fn network_payload_layouts_and_limits() {
        let params = params();
        let final_ = Final {
            hash: [15; 32],
            slot: 0x04030201,
        };
        assert_eq!(&final_.encode()[32..], &[1, 2, 3, 4]);
        assert_eq!(Final::decode(&final_.encode()), Ok(final_.clone()));
        for count in [0, 1, 64, 128] {
            let handshake = Handshake {
                final_: final_.clone(),
                leaves: vec![final_.clone(); count],
            };
            let encoded = handshake.encode();
            assert_eq!(Handshake::decode(&encoded, count), Ok(handshake));
            assert_eq!(
                &encoded[36..36 + encode_natural(count as u64).len()],
                encode_natural(count as u64)
            );
            if count != 0 {
                assert_eq!(
                    Handshake::decode(&encoded, count - 1),
                    Err(DecodeError::LengthLimit)
                );
            }
            for end in 0..encoded.len() {
                assert!(Handshake::decode(&encoded[..end], count).is_err());
            }
        }
        let announcement = Announcement {
            header: header(),
            final_: final_.clone(),
        };
        let mut encoded = announcement.encode(&params);
        assert_eq!(encoded.len(), 333);
        assert_eq!(&encoded[297..], final_.encode());
        assert_eq!(Announcement::decode(&params, &encoded), Ok(announcement));
        encoded.push(0);
        assert_eq!(
            Announcement::decode(&params, &encoded),
            Err(DecodeError::TrailingBytes)
        );
        for (direction, tag) in [
            (Direction::AscendingExclusive, 0),
            (Direction::DescendingInclusive, 1),
        ] {
            let request = BlockRequest {
                hash: [16; 32],
                direction,
                max_blocks: 0x04030201,
            };
            let mut bytes = request.encode();
            assert_eq!(bytes.len(), 37);
            assert_eq!(&bytes[32..], &[tag, 1, 2, 3, 4]);
            assert_eq!(BlockRequest::decode(&bytes), Ok(request));
            bytes[32] = 2;
            assert_eq!(
                BlockRequest::decode(&bytes),
                Err(DecodeError::InvalidDiscriminant(2))
            );
        }
        let block = Block {
            header: header(),
            body: vec![0, 1, 2, 3, 255],
        };
        let bytes = block.encode(&params);
        assert_eq!(&bytes[297..], block.body);
        assert_eq!(Block::decode(&params, &bytes, 5), Ok(block));
        assert_eq!(
            Block::decode(&params, &bytes, 4),
            Err(DecodeError::LengthLimit)
        );
        // No body validation is promised, including for an empty opaque body.
        assert!(Block::decode(&params, &bytes[..297], 0).is_ok());
    }

    #[test]
    fn state_items_and_primitive_roundtrips() {
        let params = params();
        let key = validator();
        assert_eq!(key.encode().len(), 336);
        assert_eq!(ValidatorKey::decode(&key.encode()), Ok(key.clone()));
        assert_eq!(Ticket::decode(&ticket().encode()), Ok(ticket()));
        assert_eq!(ticket().encode().len(), 33);
        // Attempts are a fixed byte, not compact; codec is not consensus validation.
        let t = Ticket {
            attempt: 255,
            ..ticket()
        };
        assert_eq!(Ticket::decode(&t.encode()), Ok(t));
        for sealing in [
            SealingSequence::Tickets(vec![ticket(); 12]),
            SealingSequence::Keys(vec![[17; 32]; 12]),
        ] {
            let safrole = SafroleState {
                pending_validators: vec![key.clone(); 6],
                epoch_root: [18; 144],
                sealing,
                ticket_accumulator: vec![ticket(); 5],
            };
            let genesis = GenesisLightState {
                safrole: safrole.clone(),
                entropy: [[19; 32]; 4],
                active_validators: vec![key.clone(); 6],
                slot: u32::MAX,
            };
            assert_eq!(
                SafroleState::decode(&params, &safrole.encode(&params)),
                Ok(safrole.clone())
            );
            assert_eq!(
                SealingSequence::decode(&params, &safrole.sealing.encode(&params)),
                Ok(safrole.sealing.clone())
            );
            let items = [
                (state_key(11), encode_slot(genesis.slot).to_vec()),
                (
                    state_key(8),
                    encode_active_validators(&genesis.active_validators),
                ),
                (state_key(6), encode_entropy(&genesis.entropy)),
                (state_key(4), safrole.encode(&params)),
                (state_key(5), vec![255]),
            ];
            let iter = || items.iter().map(|(key, bytes)| (key, bytes.as_slice()));
            assert_eq!(
                GenesisLightState::from_state_items(&params, iter()),
                Ok(genesis)
            );
            assert_eq!(
                GenesisLightState::from_state_items(&params, iter().skip(1)),
                Err(DecodeError::MissingStateItem(11))
            );
            assert_eq!(
                GenesisLightState::from_state_items(&params, iter().chain(iter())),
                Err(DecodeError::DuplicateStateItem(11))
            );
            for end in 0..items[3].1.len() {
                assert!(SafroleState::decode(&params, &items[3].1[..end]).is_err());
            }
        }
        assert_eq!(state_key(255), [vec![255], vec![0; 30]].concat().as_slice());
        let envelopes = vec![
            TicketEnvelope {
                attempt: 2,
                signature: [20; 784]
            };
            3
        ];
        assert_eq!(
            decode_tickets_extrinsic(&params, &encode_tickets_extrinsic(&envelopes)),
            Ok(envelopes)
        );
    }

    #[test]
    fn malformed_counts_fixed_payloads_and_trailing_bytes() {
        let mut params = params();
        let huge = encode_natural(u64::MAX);
        assert_eq!(
            decode_active_validators(&params, &[vec![6], vec![0; 336]].concat()),
            Err(DecodeError::UnexpectedEnd)
        );
        assert_eq!(
            decode_tickets_extrinsic(&params, &huge),
            Err(DecodeError::LengthLimit)
        );
        // Count declares six pairs, but only one is present.
        let epoch = [vec![0; 64], vec![6], vec![0; 64]].concat();
        assert_eq!(
            EpochMark::decode(&params, &epoch),
            Err(DecodeError::UnexpectedEnd)
        );
        let mut handshake = vec![0; 36];
        handshake.extend_from_slice(&huge);
        assert!(Handshake::decode(&handshake, usize::MAX).is_err());
        params.epoch_len = u32::MAX;
        assert!(decode_tickets_mark(&params, &[0; 33]).is_err());
        assert!(SealingSequence::decode(&params, &[0; 34]).is_err());
        let mut h = header().encode(&params);
        h[101] = 1;
        assert!(Header::decode(&params, &h).is_err());
        let mut sequence = vec![0; 385];
        sequence[0] = 2;
        assert_eq!(
            SealingSequence::decode(&params, &sequence),
            Err(DecodeError::InvalidDiscriminant(2))
        );
        let check = |decode: &dyn Fn(&[u8]) -> bool, mut bytes: Vec<u8>| {
            assert!(decode(&bytes));
            bytes.push(0);
            assert!(!decode(&bytes));
        };
        check(&|b| Ticket::decode(b).is_ok(), ticket().encode());
        check(&|b| ValidatorKey::decode(b).is_ok(), validator().encode());
        check(&|b| decode_entropy(b).is_ok(), vec![0; 128]);
        check(&|b| decode_slot(b).is_ok(), vec![0; 4]);
        check(
            &|b| decode_active_validators(&params, b).is_ok(),
            encode_active_validators(&vec![validator(); 6]),
        );
        check(&|b| decode_tickets_extrinsic(&params, b).is_ok(), vec![0]);
        check(&|b| Final::decode(b).is_ok(), vec![0; 36]);
        check(&|b| Handshake::decode(b, 64).is_ok(), vec![0; 37]);
        check(&|b| BlockRequest::decode(b).is_ok(), vec![0; 37]);
    }

    #[test]
    fn validator_counts_use_canonical_naturals_at_each_changed_wire_location() {
        let mut params = params();
        params.max_validators = 1023;
        params.core_count = 341;
        for count in [6, 9, 126, 129, 1023] {
            let mark = EpochMark {
                entropy: [1; 32],
                tickets_entropy: [2; 32],
                validators: vec![([3; 32], [4; 32]); count],
            };
            let keys = vec![validator(); count];
            let state = SafroleState {
                pending_validators: keys.clone(),
                epoch_root: [5; 144],
                sealing: SealingSequence::Keys(vec![[6; 32]; 12]),
                ticket_accumulator: vec![],
            };
            let prefix = encode_natural(u64::try_from(count).unwrap());
            let mark_bytes = mark.encode(&params);
            let active_bytes = encode_active_validators(&keys);
            let state_bytes = state.encode(&params);
            assert_eq!(&mark_bytes[64..64 + prefix.len()], prefix);
            assert!(active_bytes.starts_with(&prefix));
            assert!(state_bytes.starts_with(&prefix));
            assert_eq!(EpochMark::decode(&params, &mark_bytes), Ok(mark));
            assert_eq!(decode_active_validators(&params, &active_bytes), Ok(keys));
            assert_eq!(SafroleState::decode(&params, &state_bytes), Ok(state));
            if count == 6 {
                let mut bad_mark = mark_bytes;
                bad_mark.splice(64..65, [0x80, 6]);
                let mut bad_active = active_bytes;
                bad_active.splice(0..1, [0x80, 6]);
                let mut bad_state = state_bytes;
                bad_state.splice(0..1, [0x80, 6]);
                assert_eq!(
                    EpochMark::decode(&params, &bad_mark),
                    Err(DecodeError::NonCanonicalNatural)
                );
                assert_eq!(
                    decode_active_validators(&params, &bad_active),
                    Err(DecodeError::NonCanonicalNatural)
                );
                assert_eq!(
                    SafroleState::decode(&params, &bad_state),
                    Err(DecodeError::NonCanonicalNatural)
                );
            }
        }
        let oversized = encode_natural(1024);
        assert_eq!(
            decode_active_validators(&params, &oversized),
            Err(DecodeError::LengthLimit)
        );
        assert_eq!(
            SafroleState::decode(&params, &oversized),
            Err(DecodeError::LengthLimit)
        );
        assert_eq!(
            EpochMark::decode(&params, &[vec![0; 64], oversized].concat()),
            Err(DecodeError::LengthLimit)
        );
    }

    #[test]
    fn collection_limit_boundaries_and_each_required_state_key() {
        let mut params = params();
        params.max_validators = 2;
        params.epoch_len = 3;
        params.max_tickets_per_ext = 2;
        let mut state = SafroleState {
            pending_validators: vec![validator(); 2],
            epoch_root: [0; 144],
            sealing: SealingSequence::Keys(vec![[0; 32]; 3]),
            ticket_accumulator: vec![ticket(); 3],
        };
        for count in [0, 1, 2, 3] {
            let mark = EpochMark {
                entropy: [0; 32],
                tickets_entropy: [0; 32],
                validators: vec![([0; 32], [0; 32]); count],
            };
            let expected = count <= 2;
            assert_eq!(
                EpochMark::decode(&params, &mark.encode(&params)).is_ok(),
                expected
            );
            let active = encode_active_validators(&vec![validator(); count]);
            assert_eq!(decode_active_validators(&params, &active).is_ok(), expected);
            if let Some((_, truncated)) = active.split_last() {
                assert!(decode_active_validators(&params, truncated).is_err());
            }
            state.pending_validators = vec![validator(); count];
            assert_eq!(
                SafroleState::decode(&params, &state.encode(&params)).is_ok(),
                expected
            );
            let envelopes = vec![
                TicketEnvelope {
                    attempt: 0,
                    signature: [0; 784]
                };
                count
            ];
            let bytes = encode_tickets_extrinsic(&envelopes);
            assert_eq!(
                decode_tickets_extrinsic(&params, &bytes).is_ok(),
                count <= 2
            );
            assert!(decode_tickets_extrinsic(&params, &bytes[..bytes.len() - 1]).is_err());
        }
        state.pending_validators = vec![validator(); 2];
        for count in [0, 3, 4] {
            state.ticket_accumulator = vec![ticket(); count];
            assert_eq!(
                SafroleState::decode(&params, &state.encode(&params)).is_ok(),
                count <= 3
            );
        }
        for count in [0, 2, 3, 4] {
            let tickets = vec![ticket(); count];
            assert_eq!(
                decode_tickets_mark(&params, &encode_tickets_mark(&tickets)).is_ok(),
                count == 3
            );
            for sealing in [
                SealingSequence::Tickets(tickets),
                SealingSequence::Keys(vec![[0; 32]; count]),
            ] {
                assert_eq!(
                    SealingSequence::decode(&params, &sealing.encode(&params)).is_ok(),
                    count == 3
                );
            }
        }
        state.ticket_accumulator.clear();
        let items = [
            (state_key(4), state.encode(&params)),
            (state_key(6), vec![0; 128]),
            (
                state_key(8),
                encode_active_validators(&state.pending_validators),
            ),
            (state_key(11), vec![0; 4]),
        ];
        for index in [4, 6, 8, 11] {
            let iter = || items.iter().map(|(key, value)| (key, value.as_slice()));
            assert_eq!(
                GenesisLightState::from_state_items(
                    &params,
                    iter().filter(|(key, _)| **key != state_key(index))
                ),
                Err(DecodeError::MissingStateItem(index))
            );
            let duplicate = iter().find(|(key, _)| **key == state_key(index)).unwrap();
            assert_eq!(
                GenesisLightState::from_state_items(
                    &params,
                    iter().chain(core::iter::once(duplicate))
                ),
                Err(DecodeError::DuplicateStateItem(index))
            );
            assert_eq!(
                GenesisLightState::from_state_items(
                    &params,
                    iter().map(|(key, value)| (
                        key,
                        if *key == state_key(index) { &[] } else { value }
                    ))
                ),
                Err(DecodeError::UnexpectedEnd)
            );
            let mut almost = items.clone();
            almost
                .iter_mut()
                .find(|(key, _)| *key == state_key(index))
                .unwrap()
                .0[30] = 1;
            assert_eq!(
                GenesisLightState::from_state_items(
                    &params,
                    almost.iter().map(|(key, value)| (key, value.as_slice()))
                ),
                Err(DecodeError::MissingStateItem(index))
            );
        }
    }

    #[test]
    fn offenders_can_overlap_between_culprits_and_faults() {
        let params = params();
        let mut h = header();
        let keys: Vec<_> = (0..7_u8).map(|key| [key; 32]).collect();
        h.offenders_mark = [keys.clone(), keys].concat();
        let bytes = h.encode(&params);
        assert_eq!(Header::decode(&params, &bytes), Ok(h.clone()));
        // At most two sets per list and two lists, not two sets in total.
        h.offenders_mark = vec![[0; 32]; 24];
        assert_eq!(Header::decode(&params, &h.encode(&params)), Ok(h.clone()));
        h.offenders_mark.push([0; 32]);
        assert_eq!(
            Header::decode(&params, &h.encode(&params)),
            Err(DecodeError::LengthLimit)
        );
    }

    #[test]
    fn arbitrary_bytes_and_header_mutations_never_panic() {
        let mut rng = ChaCha8Rng::seed_from_u64(0x4a414d);
        let params = params();
        let mut extreme = params.clone();
        extreme.epoch_len = u32::MAX;
        extreme.max_validators = u16::MAX;
        let mut populated = header();
        populated.epoch_mark = Some(EpochMark {
            entropy: [10; 32],
            tickets_entropy: [11; 32],
            validators: vec![([12; 32], [13; 32]); 6],
        });
        populated.tickets_mark = Some(vec![ticket(); 12]);
        populated.offenders_mark = vec![[14; 32]; 3];
        let mut state = SafroleState {
            pending_validators: vec![validator(); 6],
            epoch_root: [15; 144],
            sealing: SealingSequence::Keys(vec![[16; 32]; 12]),
            ticket_accumulator: vec![ticket(); 12],
        };
        let key_state = state.encode(&params);
        state.sealing = SealingSequence::Tickets(vec![ticket(); 12]);
        let seeds = [
            header().encode(&params),
            populated.encode(&params),
            key_state,
            state.encode(&params),
        ];
        for i in 0..20_000 {
            let mut bytes = vec![0; rng.gen_range(0..2048)];
            rng.fill_bytes(&mut bytes);
            if i % 5 < seeds.len() {
                bytes = seeds[i % 5].clone();
                let offset = rng.gen_range(0..bytes.len());
                bytes[offset] = rng.next_u32().to_le_bytes()[0];
            }
            for params in [&params, &extreme] {
                if let Ok(value) = Header::decode(params, &bytes) {
                    assert_eq!(value.encode(params), bytes);
                }
                if let Ok(value) = Announcement::decode(params, &bytes) {
                    assert_eq!(value.encode(params), bytes);
                }
                if let Ok(value) = Block::decode(params, &bytes, 4096) {
                    assert_eq!(value.encode(params), bytes);
                }
                if let Ok(value) = SafroleState::decode(params, &bytes) {
                    assert_eq!(value.encode(params), bytes);
                }
                let _ = EpochMark::decode(params, &bytes);
                let _ = SealingSequence::decode(params, &bytes);
                let _ = decode_tickets_mark(params, &bytes);
                let _ = decode_tickets_extrinsic(params, &bytes);
                let _ = decode_active_validators(params, &bytes);
            }
            if let Ok(value) = Handshake::decode(&bytes, 64) {
                assert_eq!(value.encode(), bytes);
            }
            let _ = BlockRequest::decode(&bytes);
            let _ = Params::from_protocol_parameters(&bytes);
            let _ = decode_natural(&bytes);
            let _ = Ticket::decode(&bytes);
            let _ = ValidatorKey::decode(&bytes);
            let _ = decode_entropy(&bytes);
            let _ = decode_slot(&bytes);
        }
    }

    fn json_bytes(value: &serde_json::Value) -> Vec<u8> {
        let text = value.as_str().unwrap();
        hex::decode(text.strip_prefix("0x").unwrap_or(text)).unwrap()
    }

    fn json_array<const N: usize>(value: &serde_json::Value) -> [u8; N] {
        json_bytes(value).try_into().unwrap()
    }

    fn json_ticket(value: &serde_json::Value) -> Ticket {
        Ticket {
            id: json_array(&value["id"]),
            attempt: value["attempt"].as_u64().unwrap().try_into().unwrap(),
        }
    }

    fn json_header(value: &serde_json::Value) -> Header {
        Header {
            parent: json_array(&value["parent"]),
            prior_state_root: json_array(&value["parent_state_root"]),
            extrinsic_hash: json_array(&value["extrinsic_hash"]),
            slot: value["slot"].as_u64().unwrap().try_into().unwrap(),
            epoch_mark: (!value["epoch_mark"].is_null()).then(|| {
                let mark = &value["epoch_mark"];
                EpochMark {
                    entropy: json_array(&mark["entropy"]),
                    tickets_entropy: json_array(&mark["tickets_entropy"]),
                    validators: mark["validators"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| (json_array(&v["bandersnatch"]), json_array(&v["ed25519"])))
                        .collect(),
                }
            }),
            tickets_mark: value["tickets_mark"]
                .as_array()
                .map(|v| v.iter().map(json_ticket).collect()),
            offenders_mark: value["offenders_mark"]
                .as_array()
                .unwrap()
                .iter()
                .map(json_array)
                .collect(),
            author_index: value["author_index"].as_u64().unwrap().try_into().unwrap(),
            entropy_source: json_array(&value["entropy_source"]),
            seal: json_array(&value["seal"]),
        }
    }

    fn load_json(path: &std::path::Path) -> serde_json::Value {
        serde_json::from_reader(std::io::BufReader::new(std::fs::File::open(path).unwrap()))
            .unwrap()
    }

    fn vector_root() -> std::path::PathBuf {
        std::env::var_os("JAM_TEST_VECTORS")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| "/tmp/opencode/jamtestvectors".into())
    }

    fn json_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(root).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                out.extend(json_files(&path));
            } else if path.extension().is_some_and(|ext| ext == "json") {
                out.push(path);
            }
        }
        out.sort();
        out
    }

    fn check_vector_header(params: &Params, expected: &Header, bytes: &[u8]) {
        assert_eq!(Header::decode(params, bytes).unwrap(), *expected);
        assert_eq!(expected.encode(params), bytes);
        let independent_hash = blake2_rfc::blake2b::blake2b(32, &[], bytes);
        assert_eq!(
            expected.hash(params).as_slice(),
            independent_hash.as_bytes()
        );
    }

    #[test]
    #[ignore = "requires external GP 0.7.1 w3f/jamtestvectors (JAM_TEST_VECTORS)"]
    fn legacy_public_codec_vectors() {
        let root = vector_root();
        for (name, validators, slots, expected_hashes) in [
            (
                "tiny",
                6,
                12,
                [
                    "61aca4292501065b86ad0411fdb5fdbfa6621292892d99b7a1eb531b2e1a7ac3",
                    "b2cf4b091da8755d5685fc41737c4626fd4a538b7552cd38710491da9a00733d",
                ],
            ),
            (
                "full",
                1023,
                600,
                [
                    "7c628a886e62e2009ccb3eea777156b9b27a1a51bb106ae7c53b776ecca0794c",
                    "f9477ceee92965c35ea593a3542b1b8d18d8361d7e3f4537c120d00a4a29f90d",
                ],
            ),
        ] {
            let mut params = params();
            params.max_validators = validators;
            params.epoch_len = slots;
            let dir = root.join("codec").join(name);
            for (index, expected_hash) in expected_hashes.into_iter().enumerate() {
                let expected = json_header(&load_json(&dir.join(format!("header_{index}.json"))));
                let bytes = std::fs::read(dir.join(format!("header_{index}.bin"))).unwrap();
                assert_eq!(
                    hex::encode(blake2_rfc::blake2b::blake2b(32, &[], &bytes).as_bytes()),
                    expected_hash
                );
                if expected.epoch_mark.is_some() {
                    // This pinned corpus predates the validator-count prefix.
                    // Do not insert bytes and pretend its old signatures/hashes are 0.8.
                    assert!(Header::decode(&params, &bytes).is_err());
                } else {
                    check_vector_header(&params, &expected, &bytes);
                    assert_eq!(hex::encode(expected.hash(&params)), expected_hash);
                }
                if index == 1 {
                    let tickets = expected.tickets_mark.as_ref().unwrap();
                    assert_eq!(
                        decode_tickets_mark(&params, &encode_tickets_mark(tickets)),
                        Ok(tickets.clone())
                    );
                }
            }
            let tickets_json = load_json(&dir.join("tickets_extrinsic.json"));
            let tickets: Vec<_> = tickets_json
                .as_array()
                .unwrap()
                .iter()
                .map(|v| TicketEnvelope {
                    attempt: v["attempt"].as_u64().unwrap().try_into().unwrap(),
                    signature: json_array(&v["signature"]),
                })
                .collect();
            let bytes = std::fs::read(dir.join("tickets_extrinsic.bin")).unwrap();
            assert_eq!(
                decode_tickets_extrinsic(&params, &bytes),
                Ok(tickets.clone())
            );
            assert_eq!(encode_tickets_extrinsic(&tickets), bytes);
            let block_json = load_json(&dir.join("block.json"));
            assert!(json_header(&block_json["header"]).epoch_mark.is_some());
            let header_bytes = std::fs::read(dir.join("header_0.bin")).unwrap();
            let block_bytes = std::fs::read(dir.join("block.bin")).unwrap();
            assert_eq!(&block_bytes[..header_bytes.len()], header_bytes);
            assert_eq!(
                &block_bytes[header_bytes.len()..],
                std::fs::read(dir.join("extrinsic.bin")).unwrap()
            );
            assert!(Block::decode(&params, &block_bytes, block_bytes.len()).is_err());
        }
        std::println!(
            "legacy vectors: 4 original hashes checked; 2 non-epoch headers and 2 ticket extrinsics unchanged; 2 epoch headers and 2 old block containers rejected"
        );
    }

    fn check_json_tickets(value: &serde_json::Value, count: &mut usize) {
        match value {
            serde_json::Value::Object(object) => {
                if object.contains_key("id") && object.contains_key("attempt") {
                    let ticket = json_ticket(value);
                    let mut bytes = json_bytes(&value["id"]);
                    bytes.push(value["attempt"].as_u64().unwrap().try_into().unwrap());
                    assert_eq!(Ticket::decode(&bytes), Ok(ticket.clone()));
                    assert_eq!(ticket.encode(), bytes);
                    *count += 1;
                }
                for value in object.values() {
                    check_json_tickets(value, count);
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    check_json_tickets(value, count);
                }
            }
            _ => (),
        }
    }

    fn skip_raw_state(input: &mut Decoder<'_>) {
        input.take(32).unwrap();
        let len = input.length(usize::MAX).unwrap();
        for _ in 0..len {
            input.take(31).unwrap();
            let size = input.length(usize::MAX).unwrap();
            input.take(size).unwrap();
        }
    }

    #[test]
    #[ignore = "requires external GP 0.7.1 w3f/jamtestvectors; audits every original trace header"]
    fn legacy_public_trace_headers_and_all_ticket_bodies() {
        let root = vector_root();
        let params = params();
        let mut headers = 0;
        let mut epoch_marks = 0;
        let mut tickets = 0;
        let mut hashes = alloc::collections::BTreeSet::new();
        let mut parents = Vec::new();
        for path in json_files(&root.join("traces")) {
            let json = load_json(&path);
            let genesis = json.get("header").is_some();
            let expected = json_header(if genesis {
                &json["header"]
            } else {
                &json["block"]["header"]
            });
            let binary = std::fs::read(path.with_extension("bin")).unwrap();
            let mut input = Decoder::new(&binary);
            if !genesis {
                skip_raw_state(&mut input);
            }
            // Compute only the old field boundary; never change the captured bytes.
            let prefix_len = expected.epoch_mark.as_ref().map_or(0, |mark| {
                encode_natural(u64::try_from(mark.validators.len()).unwrap()).len()
            });
            let bytes = input
                .take(expected.encode(&params).len() - prefix_len)
                .unwrap();
            if expected.epoch_mark.is_some() {
                assert!(
                    Header::decode(&params, bytes).is_err(),
                    "{}",
                    path.display()
                );
                epoch_marks += 1;
            } else {
                check_vector_header(&params, &expected, bytes);
            }
            let hash: Hash = blake2_rfc::blake2b::blake2b(32, &[], bytes)
                .as_bytes()
                .try_into()
                .unwrap();
            hashes.insert(hash);
            if !genesis {
                parents.push(expected.parent);
            }
            check_json_tickets(&json, &mut tickets);
            headers += 1;
        }
        for parent in &parents {
            assert!(
                hashes.contains(parent),
                "trace parent must name a supplied header"
            );
        }
        for subtree in ["codec", "stf/safrole"] {
            for path in json_files(&root.join(subtree)) {
                check_json_tickets(&load_json(&path), &mut tickets);
            }
        }
        assert_eq!(headers, 1008);
        assert!(epoch_marks > 0);
        assert!(tickets > 600);
        std::println!(
            "{headers} original trace headers audited ({epoch_marks} legacy epoch headers rejected); {} original parent hash links checked; {tickets} ticket bodies checked",
            parents.len()
        );
    }

    #[test]
    #[ignore = "requires external GP 0.7.1 w3f/jamtestvectors for legacy epoch-header rejection"]
    fn legacy_public_epoch_header_is_rejected() {
        let bytes = std::fs::read(vector_root().join("codec/tiny/header_0.bin")).unwrap();
        assert!(Header::decode(&params(), &bytes).is_err());
    }

    fn a5_fixture_root() -> std::path::PathBuf {
        std::env::var_os("JAM_A5_FIXTURES")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                "/home/sebastian/work/repos/jam-light-client-planning/fixtures".into()
            })
    }

    #[derive(Default)]
    struct A5Coverage {
        headers: usize,
        epoch_marks: usize,
        states: usize,
        handshakes: usize,
        announcements: usize,
        responses: usize,
        parameters: usize,
        tickets: usize,
        hashes: alloc::collections::BTreeSet<Hash>,
        parents: Vec<Hash>,
    }

    fn audit_a5_header(params: &Params, bytes: &[u8], expected_hash: Hash) -> Header {
        let raw_hash = blake2_rfc::blake2b::blake2b(32, &[], bytes);
        assert_eq!(raw_hash.as_bytes(), expected_hash);
        let header = Header::decode(params, bytes).unwrap();
        assert_eq!(header.encode(params), bytes);
        assert_eq!(header.hash(params), expected_hash);
        header
    }

    fn audit_a5_state(params: &Params, value: &serde_json::Value) {
        let items: Vec<([u8; 31], Vec<u8>)> = value["state_items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                let index: u8 = v["index"].as_u64().unwrap().try_into().unwrap();
                let key = json_array(&v["key_hex"]);
                assert_eq!(state_key(index), key);
                let bytes = json_bytes(&v["value_hex"]);
                (key, bytes)
            })
            .collect();
        let state = GenesisLightState::from_state_items(
            params,
            items.iter().map(|(key, bytes)| (key, bytes.as_slice())),
        )
        .unwrap();
        assert_eq!(u64::from(state.slot), value["slot"].as_u64().unwrap());
        assert_eq!(
            state.entropy.to_vec(),
            value["entropy"]
                .as_array()
                .unwrap()
                .iter()
                .map(json_array)
                .collect::<Vec<_>>()
        );
        let validators = |v: &serde_json::Value| -> Vec<ValidatorKey> {
            v.as_array()
                .unwrap()
                .iter()
                .map(|v| {
                    let bytes = json_bytes(&v["validator_hex"]);
                    let key = ValidatorKey::decode(&bytes).unwrap();
                    assert_eq!(key.encode(), bytes);
                    assert_eq!(key.bandersnatch, json_array(&v["bandersnatch"]));
                    assert_eq!(key.ed25519, json_array(&v["ed25519"]));
                    key
                })
                .collect()
        };
        assert_eq!(
            state.active_validators,
            validators(&value["active_validators"])
        );
        let safrole = &value["safrole"];
        assert_eq!(
            state.safrole.pending_validators,
            validators(&safrole["pending_validators"])
        );
        assert_eq!(state.safrole.epoch_root, json_array(&safrole["epoch_root"]));
        let sealing = &safrole["sealing"];
        let expected = match sealing["mode"].as_str().unwrap() {
            "fallback" => SealingSequence::Keys(
                sealing["keys"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(json_array)
                    .collect(),
            ),
            "ticket" => SealingSequence::Tickets(
                sealing["tickets"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(json_ticket)
                    .collect(),
            ),
            other => panic!("unknown fixture sealing mode {other}"),
        };
        assert_eq!(state.safrole.sealing, expected);
        assert_eq!(
            state.safrole.ticket_accumulator,
            safrole["ticket_accumulator"]
                .as_array()
                .unwrap()
                .iter()
                .map(json_ticket)
                .collect::<Vec<_>>()
        );
        for (key, bytes) in items {
            match key[0] {
                4 => assert_eq!(state.safrole.encode(params), bytes),
                6 => assert_eq!(encode_entropy(&state.entropy), bytes),
                8 => assert_eq!(encode_active_validators(&state.active_validators), bytes),
                11 => assert_eq!(encode_slot(state.slot).as_slice(), bytes),
                other => panic!("unexpected fixture state item {other}"),
            }
        }
    }

    fn a5_frame_payload(value: &serde_json::Value) -> Vec<u8> {
        let frame = json_bytes(value);
        let mut input = Decoder::new(&frame);
        let len = usize::try_from(input.u32().unwrap()).unwrap();
        let payload = input.take(len).unwrap().to_vec();
        input.finish().unwrap();
        payload
    }

    fn audit_a5_value(params: &Params, value: &serde_json::Value, coverage: &mut A5Coverage) {
        match value {
            serde_json::Value::Object(object) => {
                if object.contains_key("protocol_parameters") {
                    assert_eq!(
                        Params::from_protocol_parameters(&json_bytes(
                            &value["protocol_parameters"]
                        ))
                        .unwrap(),
                        *params
                    );
                    coverage.parameters += 1;
                }
                if object.contains_key("header_hex") && object.contains_key("header_hash") {
                    let bytes = json_bytes(&value["header_hex"]);
                    let hash = json_array(&value["header_hash"]);
                    let header = audit_a5_header(params, &bytes, hash);
                    coverage.headers += 1;
                    coverage.epoch_marks += usize::from(header.epoch_mark.is_some());
                    coverage.hashes.insert(hash);
                    if header.parent != [0; 32] {
                        coverage.parents.push(header.parent);
                    }
                    if let Some(slot) = value["slot"].as_u64() {
                        assert_eq!(u64::from(header.slot), slot);
                    }
                    if object.contains_key("parent_hash") {
                        assert_eq!(header.parent, json_array(&value["parent_hash"]));
                    }
                    if object.contains_key("prior_state_root") {
                        assert_eq!(
                            header.prior_state_root,
                            json_array(&value["prior_state_root"])
                        );
                    }
                    if object.contains_key("seal_aux_hex") {
                        let aux = json_bytes(&value["seal_aux_hex"]);
                        assert_eq!(aux, bytes[..bytes.len() - 96]);
                        assert_eq!(header.encode_unsigned(params), aux);
                        assert_eq!(header.seal, json_array(&value["seal_signature_hex"]));
                        assert_eq!(
                            header.entropy_source,
                            json_array(&value["entropy_signature_hex"])
                        );
                        assert_eq!(
                            header.epoch_mark.is_some(),
                            value["has_epoch_mark"].as_bool().unwrap()
                        );
                        assert_eq!(
                            header.tickets_mark.is_some(),
                            value["has_tickets_mark"].as_bool().unwrap()
                        );
                    }
                }
                if object.contains_key("state_items") {
                    audit_a5_state(params, value);
                    coverage.states += 1;
                }
                if object.contains_key("handshake_frame_hex") {
                    assert_eq!(value["protocol_preamble_in_frames"], false);
                    assert_eq!(value["same_stream"], true);
                    let payload = a5_frame_payload(&value["handshake_frame_hex"]);
                    assert_eq!(Handshake::decode(&payload, 64).unwrap().encode(), payload);
                    coverage.handshakes += 1;
                    let payload = a5_frame_payload(&value["announcement_frame_hex"]);
                    let header = audit_a5_header(
                        params,
                        &payload[..payload.len() - 36],
                        json_array(&value["announcement_header_hash"]),
                    );
                    let announcement = Announcement::decode(params, &payload).unwrap();
                    assert_eq!(announcement.header, header);
                    assert_eq!(announcement.encode(params), payload);
                    coverage.announcements += 1;
                }
                if object.contains_key("request_frame_hex") {
                    assert_eq!(value["protocol_preamble_in_frames"], false);
                    assert_eq!(value["same_stream"], true);
                    assert_eq!(value["response_fin_received"], true);
                    let request_payload = a5_frame_payload(&value["request_frame_hex"]);
                    let request = BlockRequest::decode(&request_payload).unwrap();
                    assert_eq!(request.encode(), request_payload);
                    assert_eq!(
                        request.max_blocks, 1,
                        "opaque-body fixture must be a single-block request"
                    );
                    let payload = a5_frame_payload(&value["response_frame_hex"]);
                    let block = Block::decode(params, &payload, payload.len()).unwrap();
                    assert_eq!(block.encode(params), payload);
                    let raw_header_len = block.header.encode(params).len();
                    assert_eq!(value["block_hashes"].as_array().unwrap().len(), 1);
                    let hash = json_array(&value["block_hashes"][0]);
                    assert_eq!(
                        audit_a5_header(params, &payload[..raw_header_len], hash),
                        block.header
                    );
                    assert_eq!(block.body, payload[raw_header_len..]);
                    match request.direction {
                        Direction::DescendingInclusive => assert_eq!(request.hash, hash),
                        Direction::AscendingExclusive => {
                            assert_eq!(request.hash, block.header.parent)
                        }
                    }
                    coverage.responses += 1;
                }
                for child in object.values() {
                    audit_a5_value(params, child, coverage);
                }
            }
            serde_json::Value::Array(values) => {
                for child in values {
                    audit_a5_value(params, child, coverage);
                }
            }
            _ => (),
        }
    }

    #[test]
    #[ignore = "requires published A5 capture corpus at JAM_A5_FIXTURES or the planning fixtures path"]
    fn a5_all_captured_headers_states_and_messages() {
        let root = a5_fixture_root();
        let spec = load_json(&root.join("chain-spec.polkajam.json"));
        let params =
            Params::from_protocol_parameters(&json_bytes(&spec["protocol_parameters"])).unwrap();
        let mut coverage = A5Coverage::default();
        // D14 has its own sequence/reset audit and an explicitly synthetic
        // signing corpus; neither uses the historical A5 record schema.
        let files: Vec<_> = json_files(&root)
            .into_iter()
            .filter(|path| !path.starts_with(root.join("d14")))
            .collect();
        for path in &files {
            let json = load_json(path);
            audit_a5_value(&params, &json, &mut coverage);
            check_json_tickets(&json, &mut coverage.tickets);
        }
        for parent in &coverage.parents {
            assert!(coverage.hashes.contains(parent));
        }
        let manifest = load_json(&root.join("capture-manifest.json"));
        let published = json_files(&root.join("headers")).len();
        assert_eq!(
            u64::try_from(published).unwrap(),
            manifest["header_count"].as_u64().unwrap()
        );
        assert!(published >= 36);
        assert!(coverage.headers >= published);
        assert!(coverage.epoch_marks > 0 && coverage.headers > coverage.epoch_marks);
        assert!(coverage.states > 0 && coverage.tickets > 0);
        assert!(coverage.handshakes > 0 && coverage.responses > 0);
        std::println!(
            "A5: {} JSON files, {published} published live headers; {} native header records unchanged ({} epoch marks), {} unique hashes, {} parent links, {} native state snapshots, {} ticket bodies, {} parameter blobs, {} handshakes, {} announcements, {} single-block CE128 exchanges",
            files.len(),
            coverage.headers,
            coverage.epoch_marks,
            coverage.hashes.len(),
            coverage.parents.len(),
            coverage.states,
            coverage.tickets,
            coverage.parameters,
            coverage.handshakes,
            coverage.announcements,
            coverage.responses
        );
    }

    #[test]
    #[ignore = "requires A5 chain-spec fixture at JAM_A5_CHAIN_SPEC or the planning fixtures path"]
    fn a5_protocol_parameters_and_genesis() {
        let path = std::env::var_os("JAM_A5_CHAIN_SPEC").map(std::path::PathBuf::from).unwrap_or_else(||
            "/home/sebastian/work/repos/jam-light-client-planning/fixtures/chain-spec.polkajam.json".into());
        let spec = load_json(&path);
        let blob = json_bytes(&spec["protocol_parameters"]);
        let params = Params::from_protocol_parameters(&blob).unwrap();
        let expected = Params {
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
            max_report_elective_data: 48 * 1024,
            transfer_memo_size: 128,
            max_exports: 3072,
        };
        assert_eq!(params, expected);
        assert_eq!(blob.len(), 122);
        for end in 0..blob.len() {
            assert!(Params::from_protocol_parameters(&blob[..end]).is_err());
        }
        let mut trailing = blob.clone();
        trailing.push(0);
        assert_eq!(
            Params::from_protocol_parameters(&trailing),
            Err(DecodeError::TrailingBytes)
        );
        let mut invalid_cores = blob;
        invalid_cores[24..26].copy_from_slice(&342_u16.to_le_bytes());
        assert_eq!(
            Params::from_protocol_parameters(&invalid_cores),
            Err(DecodeError::InvalidParameters)
        );

        let bytes = json_bytes(&spec["genesis_header"]);
        let genesis = Header::decode(&params, &bytes).unwrap();
        assert_eq!(genesis.encode(&params), bytes);
        // Compare with the native node's exported hash, independent of our encoder.
        let native = load_json(&path.parent().unwrap().join("genesis-state.json"));
        assert_eq!(genesis.hash(&params), json_array(&native["header_hash"]));
        assert_eq!(bytes, json_bytes(&native["header_hex"]));
        assert_eq!(genesis.slot, 0);
        assert_eq!(genesis.author_index, u16::MAX);

        let items: Vec<([u8; 31], Vec<u8>)> = spec["genesis_state"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, value)| {
                (
                    hex::decode(key).unwrap().try_into().unwrap(),
                    json_bytes(value),
                )
            })
            .collect();
        let state = GenesisLightState::from_state_items(
            &params,
            items.iter().map(|(key, value)| (key, value.as_slice())),
        )
        .unwrap();
        assert_eq!(state.slot, 0);
        assert_eq!(state.active_validators.len(), 6);
        assert_eq!(state.safrole.pending_validators.len(), 6);
        for (key, value) in &items {
            if *key == state_key(4) {
                assert_eq!(state.safrole.encode(&params), *value);
            }
            if *key == state_key(8) {
                assert_eq!(encode_active_validators(&state.active_validators), *value);
            }
            if *key == state_key(6) {
                assert_eq!(encode_entropy(&state.entropy), *value);
            }
            if *key == state_key(11) {
                assert_eq!(encode_slot(state.slot).as_slice(), *value);
            }
        }
        std::println!(
            "A5: all 29 protocol parameters and derived validator maximum checked; native genesis header hash and all four state items round-trip unchanged"
        );
    }
}

#[cfg(test)]
#[path = "codec/fixtures.rs"]
pub(crate) mod fixtures;

#[cfg(test)]
mod sequence_tests {
    use super::*;
    use alloc::vec;
    use fixtures::{Ce128, Corruption, captured_ce128};
    use rstest::rstest;

    fn params() -> Params {
        let mut bytes = [0; 122];
        bytes[24] = 2;
        let mut p = Params::from_protocol_parameters(&bytes).unwrap();
        p.epoch_len = 12;
        p.max_tickets_per_ext = 3;
        p.max_work_items = 16;
        p.max_dependencies = 8;
        p
    }

    fn header() -> Header {
        Header {
            parent: [0; 32],
            prior_state_root: [1; 32],
            extrinsic_hash: [2; 32],
            slot: 1,
            epoch_mark: None,
            tickets_mark: None,
            author_index: 0,
            entropy_source: [0; 96],
            offenders_mark: vec![],
            seal: [0; 96],
        }
    }

    /// Every component populated, including both result variants and disputes.
    fn all_components() -> Vec<u8> {
        let mut bytes = vec![1]; // ticket
        bytes.extend([0; 785]);
        bytes.push(1); // preimage
        bytes.extend([0; 4]);
        bytes.extend([3, 10, 11, 12]);
        bytes.push(1); // guarantee
        bytes.extend([0; 104 + 168]); // availability spec and context
        bytes.push(1);
        bytes.extend([0; 32]); // prerequisite
        bytes.push(0);
        bytes.extend([0; 32]); // core and authorizer
        bytes.extend(encode_natural(129)); // authorization gas
        bytes.extend([2, 21, 22]); // authorization output
        bytes.push(1);
        bytes.extend([0; 64]); // segment-root lookup
        bytes.push(2); // results
        for tag in [0, 6] {
            bytes.extend([0; 76]);
            bytes.push(tag);
            if tag == 0 {
                bytes.extend([2, 31, 32]);
            }
            for value in [0, 127, 128, 10000, u64::MAX] {
                bytes.extend(encode_natural(value));
            }
        }
        bytes.extend([0; 4]);
        bytes.push(3);
        bytes.extend([0; 3 * 66]); // slot and signatures
        bytes.push(1);
        bytes.extend([0; 32 + 1 + 2 + 64]); // assurance, ceil(2/8) bits
        bytes.push(1);
        bytes.extend([0; 36]);
        bytes.push(1); // verdict and vote
        bytes.push(1);
        bytes.extend([0; 66]);
        bytes.push(1);
        bytes.extend([0; 128]); // culprit
        bytes.push(1);
        bytes.extend([0; 32]);
        bytes.push(0);
        bytes.extend([0; 96]); // fault
        bytes
    }

    #[test]
    fn every_extrinsic_component_delimits_and_truncations_reject() {
        let p = params();
        let body = all_components();
        assert_eq!(skip_extrinsic(&p, &body), Ok(body.len()));
        for end in 0..body.len() {
            assert!(skip_extrinsic(&p, &body[..end]).is_err(), "prefix {end}");
        }
        let first = Block {
            header: header(),
            body: body.clone(),
        };
        let mut second = first.clone();
        second.header.parent = first.header.hash(&p);
        second.header.slot += 1;
        let bytes = [first.encode(&p), second.encode(&p)].concat();
        assert_eq!(
            Block::decode_sequence(&p, &bytes, body.len() * 2, 2),
            Ok(vec![first.clone(), second])
        );
        assert_eq!(
            Block::decode_sequence(&p, &bytes, body.len() * 2 - 1, 2),
            Err(DecodeError::LengthLimit)
        );
        assert_eq!(
            Block::decode_sequence(&p, &bytes, bytes.len(), 1),
            Err(DecodeError::LengthLimit)
        );
        assert_eq!(
            Block::decode_sequence(&p, &bytes[..bytes.len() - 1], bytes.len(), 2),
            Err(DecodeError::UnexpectedEnd)
        );
        let mut malformed = bytes.clone();
        malformed[first.encode(&p).len() + first.header.encode(&p).len()] = 4;
        assert_eq!(
            Block::decode_sequence(&p, &malformed, malformed.len(), 2),
            Err(DecodeError::LengthLimit)
        );
        assert!(Block::decode_sequence(&p, &[], 0, 0).unwrap().is_empty());
        let mut bad_bool = body.clone();
        let fault_vote = bad_bool.len() - 97;
        bad_bool[fault_vote] = 2;
        assert_eq!(
            skip_extrinsic(&p, &bad_bool),
            Err(DecodeError::InvalidDiscriminant(2))
        );
    }

    #[test]
    fn skipper_random_and_mutated_structural_inputs_are_total() {
        let p = params();
        let original = all_components();
        let mut seed = 0xdead_beef_u64;
        for iteration in 0..4096 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let mut bytes = if iteration % 2 == 0 {
                original.clone()
            } else {
                vec![0; iteration % 2048]
            };
            if !bytes.is_empty() {
                let index = usize::try_from(seed % u64::try_from(bytes.len()).unwrap()).unwrap();
                bytes[index] = seed.to_le_bytes()[3];
            }
            if let Ok(consumed) = skip_extrinsic(&p, &bytes) {
                assert!(consumed <= bytes.len());
            }
        }
    }

    #[rstest]
    fn captured_ce128_boundaries_hashes_and_extrinsic_skip(captured_ce128: Ce128) {
        let capture = captured_ce128;
        let blocks = Block::decode_sequence(
            &capture.params,
            capture.payload(),
            capture.payload().len(),
            64,
        )
        .unwrap();
        assert_eq!(blocks.len(), capture.blocks.len());
        assert_eq!(blocks.len(), 5);
        let mut offset = 0;
        for (block, expected) in blocks.iter().zip(&capture.blocks) {
            assert_eq!(expected.start, offset);
            assert_eq!(
                block.header.encode(&capture.params),
                capture.payload()[expected.start..expected.body_start]
            );
            assert_eq!(
                block.body,
                capture.payload()[expected.body_start..expected.end]
            );
            // The skipper must stop at this body even with later blocks in its input.
            assert_eq!(
                skip_extrinsic(&capture.params, &capture.payload()[expected.body_start..]),
                Ok(expected.end - expected.body_start)
            );
            assert_eq!(
                hex::encode(block.header.hash(&capture.params)),
                expected.header_hash
            );
            assert_eq!(hex::encode(block.header.parent), expected.parent_hash);
            assert_eq!(block.header.slot, expected.slot);
            assert_eq!(block.body[0], expected.ticket_count);
            offset = expected.end;
        }
        assert_eq!(offset, capture.payload().len());
        // Three captured ring-VRF ticket proofs, not an all-empty extrinsic.
        assert_eq!(blocks[4].body[0], 3);
        assert_eq!(blocks[4].body.len(), 1 + 3 * 785 + 6);
        assert_eq!(
            blocks
                .iter()
                .flat_map(|b| b.encode(&capture.params))
                .collect::<Vec<_>>(),
            capture.payload()
        );
    }

    #[rstest]
    #[case::exact_budget(0, 5, Ok(5))]
    #[case::body_budget_exceeded(1, 5, Err(DecodeError::LengthLimit))]
    #[case::block_count_exceeded(0, 4, Err(DecodeError::LengthLimit))]
    fn captured_ce128_limits(
        captured_ce128: Ce128,
        #[case] missing_body_bytes: usize,
        #[case] max_blocks: usize,
        #[case] expected: Result<usize, DecodeError>,
    ) {
        let capture = captured_ce128;
        let body_bytes: usize = capture.blocks.iter().map(|b| b.end - b.body_start).sum();
        assert_eq!(
            Block::decode_sequence(
                &capture.params,
                capture.payload(),
                body_bytes - missing_body_bytes,
                max_blocks
            )
            .map(|blocks| blocks.len()),
            expected
        );
    }

    #[rstest]
    #[case::truncated(Corruption::Truncated, DecodeError::UnexpectedEnd)]
    #[case::too_many_tickets(Corruption::TooManyTickets, DecodeError::LengthLimit)]
    fn captured_ce128_rejects_malformed_extrinsics(
        captured_ce128: Ce128,
        #[values(0, 1, 2, 3, 4)] block: usize,
        #[case] corruption: Corruption,
        #[case] expected: DecodeError,
    ) {
        let capture = captured_ce128;
        let payload = capture.corrupted_payload(block, corruption);
        // Valid preceding blocks must not escape as a successful prefix.
        assert_eq!(
            Block::decode_sequence(&capture.params, &payload, capture.payload().len(), 64),
            Err(expected)
        );
    }

    #[rstest]
    fn captured_ce128_mutations_round_trip(captured_ce128: Ce128) {
        let capture = captured_ce128;
        for iteration in 0..4096usize {
            let mut mutated = capture.payload().to_vec();
            let index = iteration.wrapping_mul(7919) % mutated.len();
            mutated[index] ^= 0xff;
            if let Ok(blocks) = Block::decode_sequence(&capture.params, &mutated, mutated.len(), 64)
            {
                assert_eq!(
                    blocks
                        .iter()
                        .flat_map(|b| b.encode(&capture.params))
                        .collect::<Vec<_>>(),
                    mutated
                );
            }
        }
    }

    #[test]
    #[ignore = "requires external D14 CE128 oracle capture; JAM_A5_FIXTURES or planning checkout"]
    fn external_captured_64_block_sequence_and_mutations() {
        let root = std::env::var_os("JAM_A5_FIXTURES")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                "/home/sebastian/work/repos/jam-light-client-planning/fixtures".into()
            });
        let spec: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("chain-spec.polkajam.json")).unwrap())
                .unwrap();
        let decode_hex = |value: &serde_json::Value| {
            hex::decode(value.as_str().unwrap().trim_start_matches("0x")).unwrap()
        };
        let p =
            &Params::from_protocol_parameters(&decode_hex(&spec["protocol_parameters"])).unwrap();
        let genesis = Header::decode(p, &decode_hex(&spec["genesis_header"])).unwrap();
        let capture: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("d14/ce128.json")).unwrap()).unwrap();
        for (name, expected) in [
            ("ascending-single-genesis", 1),
            ("ascending-64-genesis", 64),
            ("descending-two", 2),
        ] {
            let exchange = capture["exchanges"]
                .as_array()
                .unwrap()
                .iter()
                .find(|e| e["name"] == name)
                .unwrap();
            let frame = hex::decode(exchange["response_frame_hex"].as_str().unwrap()).unwrap();
            assert_eq!(
                usize::try_from(u32::from_le_bytes(frame[..4].try_into().unwrap())).unwrap(),
                frame.len() - 4
            );
            let bytes = &frame[4..];
            let blocks = Block::decode_sequence(p, bytes, bytes.len(), 64).unwrap();
            assert_eq!(blocks.len(), expected);
            for pair in blocks.windows(2) {
                if name == "descending-two" {
                    assert_eq!(pair[0].header.parent, pair[1].header.hash(p));
                } else {
                    assert_eq!(pair[1].header.parent, pair[0].header.hash(p));
                }
            }
            assert_eq!(
                blocks.iter().flat_map(|b| b.encode(p)).collect::<Vec<_>>(),
                bytes
            );
            if expected == 64 {
                let prefix: usize = blocks.iter().take(31).map(|b| b.encode(p).len()).sum();
                let end = prefix + blocks[31].encode(p).len();
                assert_eq!(
                    Block::decode_sequence(p, &bytes[..end - 1], bytes.len(), 64),
                    Err(DecodeError::UnexpectedEnd)
                );
                let mut bad = bytes.to_vec();
                bad[prefix + blocks[31].header.encode(p).len()] = 4;
                assert_eq!(
                    Block::decode_sequence(p, &bad, bad.len(), 64),
                    Err(DecodeError::LengthLimit)
                );
                for iteration in 0..4096usize {
                    let mut bad = bytes.to_vec();
                    let index = iteration.wrapping_mul(7919) % bad.len();
                    bad[index] ^= 0xff;
                    if let Ok(decoded) = Block::decode_sequence(p, &bad, bad.len(), 64) {
                        assert_eq!(
                            decoded.iter().flat_map(|b| b.encode(p)).collect::<Vec<_>>(),
                            bad
                        );
                    }
                }
                std::println!(
                    "D14 captured: blocks=64 chained=true mutated_inputs=4096 block_32_truncation=UnexpectedEnd block_32_bad_count=LengthLimit"
                );
            }
        }
        let early = capture["exchanges"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["name"] == "ascending-64-early-stop")
            .unwrap();
        let bytes = hex::decode(early["response_frame_hex"].as_str().unwrap()).unwrap();
        let blocks = Block::decode_sequence(p, &bytes[4..], bytes.len(), 64).unwrap();
        assert!(!blocks.is_empty() && blocks.len() < 64);
        for name in ["unknown-hash", "tip-no-data"] {
            let exchange = capture["exchanges"]
                .as_array()
                .unwrap()
                .iter()
                .find(|e| e["name"] == name)
                .unwrap();
            assert_eq!(exchange["reset"], true);
            assert_eq!(exchange["source"], "stream");
            assert!(exchange.get("response_frame_hex").is_none());
        }
        let early: serde_json::Value = serde_json::from_slice(
            &std::fs::read(root.join("d14/ce128-early-genesis.json")).unwrap(),
        )
        .unwrap();
        let exchange = &early["exchanges"][0];
        let request = hex::decode(exchange["request_frame_hex"].as_str().unwrap()).unwrap();
        let request = BlockRequest::decode(&request[4..]).unwrap();
        assert_eq!(request.hash, genesis.hash(p));
        assert_eq!(request.max_blocks, 64);
        assert_eq!(request.direction, Direction::AscendingExclusive);
        let frame = hex::decode(exchange["response_frame_hex"].as_str().unwrap()).unwrap();
        let blocks = Block::decode_sequence(p, &frame[4..], frame.len(), 64).unwrap();
        assert!(!blocks.is_empty() && blocks.len() < 64);
        assert_eq!(blocks[0].header.parent, request.hash);
        for pair in blocks.windows(2) {
            assert_eq!(pair[1].header.parent, pair[0].header.hash(p));
        }
        std::println!(
            "D14 captured early stop from genesis: requested=64 decoded={}",
            blocks.len()
        );
    }
}
