// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Encoders and decoders that only the tests need: production code reads and
//! writes these items only inside headers and state values.

use super::{
    DecodeError, complete, epoch_len, read_epoch_mark, read_sealing, read_ticket, read_validator,
    write_epoch_mark, write_length, write_sealing, write_ticket, write_validator,
};
use crate::jam::{
    params::Params,
    types::{
        Entropy, EpochMark, SealingSequence, Ticket, TicketEnvelope, TicketsMark, ValidatorKey,
    },
};
use alloc::vec::Vec;

impl Ticket {
    /// Decodes a 32-byte identifier and a fixed-width one-byte attempt.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        complete(bytes, read_ticket)
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_ticket(self, &mut out);
        out
    }
}

/// Decodes the tickets extrinsic: a length-prefixed list of ring-VRF proofs.
/// Proof verification and attempt-number validity are not part of the codec.
pub(crate) fn decode_tickets_extrinsic(
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
pub(crate) fn encode_tickets_extrinsic(tickets: &[TicketEnvelope]) -> Vec<u8> {
    let mut out = Vec::new();
    write_length(tickets.len(), &mut out);
    for ticket in tickets {
        out.push(ticket.attempt);
        out.extend_from_slice(&ticket.signature);
    }
    out
}

impl ValidatorKey {
    /// Decodes the 336-byte key tuple; does not validate curve points.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        complete(bytes, read_validator)
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_validator(self, &mut out);
        out
    }
}

impl EpochMark {
    /// Decodes a present mark, without the surrounding header's option tag.
    pub(crate) fn decode(params: &Params, bytes: &[u8]) -> Result<Self, DecodeError> {
        complete(bytes, |input| read_epoch_mark(params, input))
    }

    /// Encodes a present mark without validating its validator count. The caller
    /// must supply at most `params.max_validators` pairs. A count is encoded.
    pub(crate) fn encode(&self, _params: &Params) -> Vec<u8> {
        let mut out = Vec::new();
        write_epoch_mark(self, &mut out);
        out
    }
}

/// Decodes exactly `epoch_len` tickets, without a count or an option tag.
pub(crate) fn decode_tickets_mark(
    params: &Params,
    bytes: &[u8],
) -> Result<TicketsMark, DecodeError> {
    complete(bytes, |input| {
        input.list(epoch_len(params)?, 33, read_ticket)
    })
}

/// The caller must supply exactly `epoch_len` tickets.
pub(crate) fn encode_tickets_mark(tickets: &[Ticket]) -> Vec<u8> {
    let mut out = Vec::new();
    for ticket in tickets {
        write_ticket(ticket, &mut out);
    }
    out
}

pub(crate) fn encode_entropy(entropy: &Entropy) -> Vec<u8> {
    entropy.iter().flatten().copied().collect()
}

pub(crate) fn encode_slot(slot: u32) -> [u8; 4] {
    slot.to_le_bytes()
}

impl SealingSequence {
    pub(crate) fn decode(params: &Params, bytes: &[u8]) -> Result<Self, DecodeError> {
        complete(bytes, |input| read_sealing(params, input))
    }

    /// The sequence must contain exactly `params.epoch_len` tickets or keys.
    pub(crate) fn encode(&self, _params: &Params) -> Vec<u8> {
        let mut out = Vec::new();
        write_sealing(self, &mut out);
        out
    }
}
