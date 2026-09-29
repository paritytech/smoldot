// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Bounded JAM state range proofs (GP 0.8, appendix D).
//! Roots must be authenticated by the caller; the requested block is not itself
//! cryptographically bound by a proof. Keys and branch paths are MSB-first.
//! Limits: 496 boundary nodes, one MiB of encoded entries, depth 248, and
//! 262144 traversal/reconstruction steps shared across both completeness walks.

use super::{
    codec::{self, DecodeError},
    crypto::blake2b_256,
    types::Hash,
};
use alloc::{collections::BTreeMap, vec::Vec};
use core::cell::Cell;

pub use super::codec::state_key;
pub type StateKey = [u8; 31];
pub type Node = [u8; 64];
const MAX_NODES: usize = 496;
const MAX_BYTES: usize = 1024 * 1024;
const MAX_WORK: usize = 262144;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateRequest {
    pub block: Hash,
    pub start: StateKey,
    pub end: StateKey,
    pub max_size: u32,
}

impl StateRequest {
    pub fn encode(&self) -> [u8; 98] {
        let mut out = [0; 98];
        out[..32].copy_from_slice(&self.block);
        out[32..63].copy_from_slice(&self.start);
        out[63..94].copy_from_slice(&self.end);
        out[94..].copy_from_slice(&self.max_size.to_le_bytes());
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateResponse {
    pub nodes: Vec<Node>,
    pub entries: Vec<(StateKey, Vec<u8>)>,
}

pub struct ResponseLimits {
    pub max_nodes: usize,
    pub max_entries: usize,
    pub max_value_bytes: usize,
    pub max_total_bytes: usize,
}

impl StateResponse {
    /// Decodes the two concatenated, count-free CE129 messages. The hard ceiling
    /// also applies to responses constructed directly and passed to verification.
    pub fn decode(
        nodes: &[u8],
        mut entries: &[u8],
        limits: &ResponseLimits,
    ) -> Result<Self, DecodeError> {
        if !nodes.len().is_multiple_of(64) {
            return Err(DecodeError::UnexpectedEnd);
        }
        if nodes.len() / 64 > limits.max_nodes.min(MAX_NODES)
            || nodes
                .len()
                .checked_add(entries.len())
                .is_none_or(|n| n > limits.max_total_bytes.min(MAX_BYTES + MAX_NODES * 64))
            || entries.len() > MAX_BYTES
        {
            return Err(DecodeError::LengthLimit);
        }
        let mut out = Self {
            nodes: Vec::new(),
            entries: Vec::new(),
        };
        out.nodes
            .try_reserve_exact(nodes.len() / 64)
            .map_err(|_| DecodeError::AllocationFailed)?;
        for node in nodes.chunks_exact(64) {
            out.nodes
                .push(node.try_into().map_err(|_| DecodeError::UnexpectedEnd)?);
        }
        while !entries.is_empty() {
            if out.entries.len() >= limits.max_entries {
                return Err(DecodeError::LengthLimit);
            }
            let (key, rest) = entries
                .split_at_checked(31)
                .ok_or(DecodeError::UnexpectedEnd)?;
            let first = rest.first().ok_or(DecodeError::UnexpectedEnd)?;
            let prefix =
                usize::try_from(first.leading_ones()).map_err(|_| DecodeError::LengthLimit)? + 1;
            let (length, rest) = rest
                .split_at_checked(prefix)
                .ok_or(DecodeError::UnexpectedEnd)?;
            let length = usize::try_from(codec::decode_natural(length)?)
                .map_err(|_| DecodeError::LengthLimit)?;
            if length > limits.max_value_bytes {
                return Err(DecodeError::LengthLimit);
            }
            let (value, rest) = rest
                .split_at_checked(length)
                .ok_or(DecodeError::UnexpectedEnd)?;
            let mut owned = Vec::new();
            owned
                .try_reserve_exact(length)
                .map_err(|_| DecodeError::AllocationFailed)?;
            owned.extend_from_slice(value);
            out.entries
                .try_reserve(1)
                .map_err(|_| DecodeError::AllocationFailed)?;
            out.entries.push((
                key.try_into().map_err(|_| DecodeError::UnexpectedEnd)?,
                owned,
            ));
            entries = rest;
        }
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRange {
    pub entries: Vec<(StateKey, Vec<u8>)>,
    /// Inclusive proven upper bound: end of the request if proven, otherwise
    /// the last returned key, or the start key for an empty result. Empty results
    /// prove absence only through this bound, not necessarily the whole request.
    pub complete_to: StateKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProofError {
    InvalidRange,
    Limit,
    UnsortedEntries,
    EntryOutsideRange,
    DuplicateNode,
    InvalidNode,
    MissingNode,
    RootMismatch,
}

/// Verifies every entry and completeness, not just independent inclusion paths.
/// An empty response must prove the start key absent. Coverage extends to the
/// requested end only when the supplied proof also proves that whole interval
/// absent; otherwise `complete_to` is the start key.
pub fn verify_range(
    root: &Hash,
    request: &StateRequest,
    response: &StateResponse,
) -> Result<VerifiedRange, ProofError> {
    if request.start > request.end {
        return Err(ProofError::InvalidRange);
    }
    let mut bytes = 0usize;
    if response.nodes.len() > MAX_NODES {
        return Err(ProofError::Limit);
    }
    for (i, (key, value)) in response.entries.iter().enumerate() {
        if value.len() > MAX_BYTES {
            return Err(ProofError::Limit);
        }
        // Canonical natural length for a value bounded by one MiB.
        let prefix = if value.len() < 128 {
            1
        } else if value.len() < 16384 {
            2
        } else {
            3
        };
        bytes = bytes
            .checked_add(31 + prefix)
            .and_then(|n| n.checked_add(value.len()))
            .ok_or(ProofError::Limit)?;
        if bytes > MAX_BYTES {
            return Err(ProofError::Limit);
        }
        if *key < request.start || *key > request.end {
            return Err(ProofError::EntryOutsideRange);
        }
        if i != 0 && response.entries[i - 1].0 >= *key {
            return Err(ProofError::UnsortedEntries);
        }
    }
    let mut nodes = BTreeMap::new();
    for node in &response.nodes {
        if node[0] & 0x80 != 0 && node[0] != 0xc0 {
            let len = usize::from(node[0] & 0x3f);
            if node[0] & 0x40 != 0 || len > 32 || node[32 + len..].iter().any(|b| *b != 0) {
                return Err(ProofError::InvalidNode);
            }
        }
        if nodes.insert(blake2b_256(node), node).is_some() {
            return Err(ProofError::DuplicateNode);
        }
    }
    // PolkaJam supplies only the start path when no entries are returned. Prove
    // that key absent first, then optionally extend coverage with the same proof.
    let last = response.entries.last().map_or(request.start, |(k, _)| *k);
    let proof = Proof {
        nodes,
        start: request.start,
        work: Cell::new(MAX_WORK),
    };
    proof.walk(
        *root,
        false,
        [0; 31],
        [255; 31],
        0,
        &last,
        &response.entries,
    )?;
    let complete_to = if last == request.end
        || proof
            .walk(
                *root,
                false,
                [0; 31],
                [255; 31],
                0,
                &request.end,
                &response.entries,
            )
            .is_ok()
    {
        request.end
    } else {
        last
    };
    Ok(VerifiedRange {
        entries: response.entries.clone(),
        complete_to,
    })
}

struct Proof<'a> {
    nodes: BTreeMap<Hash, &'a Node>,
    start: StateKey,
    work: Cell<usize>,
}

impl Proof<'_> {
    // Outside subtrees retain their authenticated hashes. Every wholly inside
    // subtree is recomputed exclusively from the returned entries. Therefore an
    // omitted inner entry changes a committed child hash; boundary nodes cannot
    // hide it. Only the two partially overlapping boundary paths are expanded.
    #[allow(clippy::too_many_arguments)]
    fn walk(
        &self,
        hash: Hash,
        masked: bool,
        low: StateKey,
        high: StateKey,
        depth: usize,
        end: &StateKey,
        entries: &[(StateKey, Vec<u8>)],
    ) -> Result<(), ProofError> {
        charge(&self.work)?;
        if high < self.start || low > *end {
            return if entries.is_empty() {
                Ok(())
            } else {
                Err(ProofError::EntryOutsideRange)
            };
        }
        if hash == [0; 32] || (low >= self.start && high <= *end) {
            return if matches_hash(subtree(entries, depth, &self.work)?, hash, masked) {
                Ok(())
            } else {
                Err(ProofError::RootMismatch)
            };
        }
        let node = self
            .nodes
            .get(&hash)
            .or_else(|| {
                if !masked {
                    return None;
                }
                let mut full = hash;
                full[0] |= 0x80;
                self.nodes.get(&full)
            })
            .ok_or(ProofError::MissingNode)?;
        if node[0] & 0x80 != 0 {
            let key: StateKey = node[1..32]
                .try_into()
                .map_err(|_| ProofError::InvalidNode)?;
            if key < low || key > high {
                return Err(ProofError::InvalidNode);
            }
            if key >= self.start && key <= *end {
                if entries.len() != 1 || entries[0].0 != key || leaf(&key, &entries[0].1)? != **node
                {
                    return Err(ProofError::RootMismatch);
                }
            } else if !entries.is_empty() {
                return Err(ProofError::RootMismatch);
            }
            return Ok(());
        }
        if depth >= 248 {
            return Err(ProofError::InvalidNode);
        }
        let mut left_high = high;
        left_high[depth / 8] &= !(0x80 >> (depth % 8));
        let mut right_low = low;
        right_low[depth / 8] |= 0x80 >> (depth % 8);
        let split = entries.partition_point(|(key, _)| *key <= left_high);
        let left = node[..32].try_into().map_err(|_| ProofError::InvalidNode)?;
        let right = node[32..].try_into().map_err(|_| ProofError::InvalidNode)?;
        self.walk(
            left,
            true,
            low,
            left_high,
            depth + 1,
            end,
            &entries[..split],
        )?;
        self.walk(
            right,
            false,
            right_low,
            high,
            depth + 1,
            end,
            &entries[split..],
        )
    }
}

fn matches_hash(mut actual: Hash, expected: Hash, masked: bool) -> bool {
    if masked {
        actual[0] &= 0x7f;
    }
    actual == expected
}

fn leaf(key: &StateKey, value: &[u8]) -> Result<Node, ProofError> {
    let mut node = [0; 64];
    node[1..32].copy_from_slice(key);
    if value.len() <= 32 {
        node[0] = 0x80 | u8::try_from(value.len()).map_err(|_| ProofError::Limit)?;
        node[32..32 + value.len()].copy_from_slice(value);
    } else {
        node[0] = 0xc0;
        node[32..].copy_from_slice(&blake2b_256(value));
    }
    Ok(node)
}

fn charge(work: &Cell<usize>) -> Result<(), ProofError> {
    work.set(work.get().checked_sub(1).ok_or(ProofError::Limit)?);
    Ok(())
}

fn subtree(
    entries: &[(StateKey, Vec<u8>)],
    depth: usize,
    work: &Cell<usize>,
) -> Result<Hash, ProofError> {
    charge(work)?;
    match entries {
        [] => Ok([0; 32]),
        [(key, value)] => Ok(blake2b_256(&leaf(key, value)?)),
        _ => {
            if depth >= 248 {
                return Err(ProofError::UnsortedEntries);
            }
            let split =
                entries.partition_point(|(key, _)| key[depth / 8] & (0x80 >> (depth % 8)) == 0);
            let mut node = [0; 64];
            node[..32].copy_from_slice(&subtree(&entries[..split], depth + 1, work)?);
            node[0] &= 0x7f;
            node[32..].copy_from_slice(&subtree(&entries[split..], depth + 1, work)?);
            Ok(blake2b_256(&node))
        }
    }
}

pub fn verify_value(
    root: &Hash,
    block: &Hash,
    key: &StateKey,
    response: &StateResponse,
) -> Result<Option<Vec<u8>>, ProofError> {
    let request = StateRequest {
        block: *block,
        start: *key,
        end: *key,
        max_size: u32::MAX,
    };
    Ok(verify_range(root, &request, response)?
        .entries
        .into_iter()
        .next()
        .map(|(_, value)| value))
}

pub fn service_key(index: u8, service: u32) -> StateKey {
    let mut key = state_key(index);
    for (i, byte) in service.to_le_bytes().iter().enumerate() {
        key[1 + i * 2] = *byte;
    }
    key
}

/// GP constructor C(s, h). For service storage pass `0xffffffff ++ raw_key`
/// as `key`; preimages and requests use their own GP chapter prefix.
pub fn storage_key(service: u32, key: &[u8]) -> StateKey {
    let hash = blake2b_256(key);
    let mut out = [0; 31];
    for (i, byte) in service.to_le_bytes().iter().enumerate() {
        out[i * 2] = *byte;
        out[i * 2 + 1] = hash[i];
    }
    out[8..].copy_from_slice(&hash[4..27]);
    out
}

#[cfg(test)]
mod tests;
