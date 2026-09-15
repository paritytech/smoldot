// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! JAM headers, network messages, and genesis light state.

use alloc::vec::Vec;

pub type Hash = [u8; 32];
pub type BandersnatchPublic = [u8; 32];
/// IETF VRF signature.
pub type BandersnatchSignature = [u8; 96];
pub type Ed25519Public = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorKey {
    pub bandersnatch: BandersnatchPublic,
    pub ed25519: Ed25519Public,
    pub bls: [u8; 144],
    pub metadata: [u8; 128],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochMark {
    pub entropy: Hash,
    pub tickets_entropy: Hash,
    /// Pending keys for the following epoch, not the active set on entry to the
    /// epoch carrying this mark (Gray Paper Safrole validator rotation).
    pub validators: Vec<(BandersnatchPublic, Ed25519Public)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ticket {
    pub id: Hash,
    pub attempt: u8,
}

/// A submitted ticket proof, distinct from a winning ticket's identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TicketEnvelope {
    pub attempt: u8,
    pub signature: [u8; 784],
}

/// Contains `Params::epoch_len` tickets when present in a header.
pub type TicketsMark = Vec<Ticket>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub parent: Hash,
    pub prior_state_root: Hash,
    pub extrinsic_hash: Hash,
    pub slot: u32,
    pub epoch_mark: Option<EpochMark>,
    pub tickets_mark: Option<TicketsMark>,
    pub offenders_mark: Vec<Ed25519Public>,
    pub author_index: u16,
    pub entropy_source: BandersnatchSignature,
    pub seal: BandersnatchSignature,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Final {
    pub hash: Hash,
    pub slot: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handshake {
    pub final_: Final,
    pub leaves: Vec<Final>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Announcement {
    pub header: Header,
    pub final_: Final,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Direction {
    AscendingExclusive,
    DescendingInclusive,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRequest {
    pub hash: Hash,
    pub direction: Direction,
    pub max_blocks: u32,
}

/// An individually delimited block from CE128. The body is opaque; only the
/// header is decoded. A multi-block response does not provide such delimiters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub header: Header,
    pub body: Vec<u8>,
}

/// Contains `Params::epoch_len` tickets or keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SealingSequence {
    Tickets(Vec<Ticket>),
    Keys(Vec<BandersnatchPublic>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafroleState {
    pub pending_validators: Vec<ValidatorKey>,
    pub epoch_root: [u8; 144],
    pub sealing: SealingSequence,
    pub ticket_accumulator: Vec<Ticket>,
}

pub type Entropy = [Hash; 4];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisLightState {
    pub safrole: SafroleState,
    pub entropy: Entropy,
    pub active_validators: Vec<ValidatorKey>,
    pub slot: u32,
}
