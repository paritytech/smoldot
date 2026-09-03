// Smoldot
// Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.
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

//! Encoding of Grandpa finality proofs.
//!
//! Commits and justifications carry the same information - a round number, a target block and
//! signed pre-commits - and differ only in their encoding and in how they are transmitted:
//! commits are gossiped, justifications are stored by full nodes and served over block requests
//! and warp sync. Consumers that verify Grandpa on their own expect the justification encoding,
//! which this module produces from a gossiped commit.

use crate::{finality::decode, header, util};

use alloc::{collections::BTreeSet, vec::Vec};

/// Turns a SCALE-encoded Grandpa commit into a SCALE-encoded Grandpa justification targeting the
/// same block.
///
/// The commit **must** have been verified beforehand (see
/// [`crate::finality::verify::verify_commit`]), as this function performs no verification
/// of its own beyond decoding.
///
/// # Vote ancestries
///
/// A commit assumes that its receiver already knows the blocks that the pre-commits target, while
/// a justification must be verifiable in isolation and therefore also carries the headers linking
/// each pre-commit target back to the finalized block: the `votes_ancestries` field.
/// `scale_encoded_header_by_hash` provides those headers, returning `None` for a block the caller
/// doesn't know about.
///
/// Pre-commits that can't be linked back are **left out**: a verifier gives no voting weight to a
/// pre-commit whose ancestry it can't check, so dropping one doesn't change whether the
/// justification is accepted, and keeps it smaller. Pre-commits targeting the finalized block
/// itself, which is the vast majority of them, need no ancestry at all.
pub fn grandpa_commit_to_justification(
    scale_encoded_commit: &[u8],
    block_number_bytes: usize,
    mut scale_encoded_header_by_hash: impl FnMut(&[u8; 32]) -> Option<Vec<u8>>,
) -> Result<Vec<u8>, CommitToJustificationError> {
    let commit = decode::decode_grandpa_commit(scale_encoded_commit, block_number_bytes)
        .map_err(|_| CommitToJustificationError::CommitDecode)?;

    // The commit stores the signatures and public keys of the pre-commits separately from the
    // pre-commits themselves, while the justification stores them inline. The two lists
    // consequently must have the same length.
    if commit.precommits.len() != commit.auth_data.len() {
        return Err(CommitToJustificationError::PrecommitsAuthDataMismatch);
    }

    // SCALE-encoded headers of the `votes_ancestries` field, and the hashes of the blocks that
    // they correspond to. A block is added to this list at most once, and only if it is on the
    // path between a pre-commit target and the target of the commit. Verifiers reject
    // justifications that carry a header that no pre-commit needs.
    let mut votes_ancestries = Vec::new();
    let mut votes_ancestries_hashes = BTreeSet::new();

    // SCALE-encoded pre-commits that are kept, and how many of them there are. Built separately
    // from `out`, as the number of pre-commits isn't known until the ancestry of all of them has
    // been resolved.
    let mut precommits =
        Vec::with_capacity(commit.precommits.len() * (32 + block_number_bytes + 64 + 32));
    let mut num_precommits = 0;

    for (precommit, (signature, authority_public_key)) in
        commit.precommits.iter().zip(commit.auth_data.iter())
    {
        match ancestry_of(
            precommit.target_hash,
            precommit.target_number,
            commit.target_hash,
            commit.target_number,
            block_number_bytes,
            &votes_ancestries_hashes,
            &mut scale_encoded_header_by_hash,
        ) {
            Some(headers) => {
                for (hash, scale_encoded_header) in headers {
                    votes_ancestries_hashes.insert(hash);
                    votes_ancestries.push(scale_encoded_header);
                }
            }
            // The pre-commit targets a block that isn't known to be a descendant of the block
            // that the commit finalizes. See the documentation of this function.
            None => continue,
        }

        precommits.extend_from_slice(precommit.target_hash);
        push_block_number(&mut precommits, precommit.target_number, block_number_bytes)?;
        precommits.extend_from_slice(&signature[..]);
        precommits.extend_from_slice(&authority_public_key[..]);
        num_precommits += 1;
    }

    let mut out = Vec::with_capacity(
        8 + 32
            + block_number_bytes
            + 5
            + precommits.len()
            + 5
            + votes_ancestries.iter().map(|h| h.len()).sum::<usize>(),
    );

    // `round: u64`
    out.extend_from_slice(&commit.round_number.to_le_bytes());
    // `commit.target_hash: [u8; 32]`
    out.extend_from_slice(commit.target_hash);
    // `commit.target_number`, encoded on `block_number_bytes` bytes, little endian.
    push_block_number(&mut out, commit.target_number, block_number_bytes)?;

    // `commit.precommits: Vec<SignedPrecommit>`
    out.extend_from_slice(util::encode_scale_compact_usize(num_precommits).as_ref());
    out.extend_from_slice(&precommits);

    // `votes_ancestries: Vec<Header>`
    out.extend_from_slice(util::encode_scale_compact_usize(votes_ancestries.len()).as_ref());
    for scale_encoded_header in votes_ancestries {
        out.extend_from_slice(&scale_encoded_header);
    }

    Ok(out)
}

/// Returns the headers of the blocks on the path that goes from `precommit_target` (included) down
/// to `commit_target` (excluded), or `None` if no such path can be built out of the blocks that
/// `scale_encoded_header_by_hash` knows about.
///
/// Blocks that are in `already_known` are assumed to have been returned by an earlier call and to
/// already be linked to `commit_target`, and the walk stops there. They are not returned again.
fn ancestry_of(
    precommit_target_hash: &[u8; 32],
    precommit_target_number: u64,
    commit_target_hash: &[u8; 32],
    commit_target_number: u64,
    block_number_bytes: usize,
    already_known: &BTreeSet<[u8; 32]>,
    scale_encoded_header_by_hash: &mut impl FnMut(&[u8; 32]) -> Option<Vec<u8>>,
) -> Option<Vec<([u8; 32], Vec<u8>)>> {
    // A pre-commit that targets the block being finalized needs no ancestry at all. This is the
    // common case.
    if precommit_target_hash == commit_target_hash {
        return Some(Vec::new());
    }

    // Only a descendant of the block being finalized can be linked back to it, and a descendant
    // always has a higher height. This also bounds the number of iterations of the loop below.
    if precommit_target_number <= commit_target_number {
        return None;
    }

    let mut out = Vec::new();
    let mut current_hash = *precommit_target_hash;
    let mut remaining_steps = precommit_target_number - commit_target_number;

    loop {
        if current_hash == *commit_target_hash || already_known.contains(&current_hash) {
            return Some(out);
        }

        if remaining_steps == 0 {
            // The chain of parents is longer than the difference of heights, meaning that one of
            // the headers is inconsistent with the height of the block that it is supposed to be.
            return None;
        }
        remaining_steps -= 1;

        let scale_encoded_header = scale_encoded_header_by_hash(&current_hash)?;
        let parent_hash = *header::decode(&scale_encoded_header, block_number_bytes)
            .ok()?
            .parent_hash;
        out.push((current_hash, scale_encoded_header));
        current_hash = parent_hash;
    }
}

/// Appends `value` to `out`, encoded on `block_number_bytes` bytes in little endian order.
fn push_block_number(
    out: &mut Vec<u8>,
    value: u64,
    block_number_bytes: usize,
) -> Result<(), CommitToJustificationError> {
    let bytes = value.to_le_bytes();

    // Any byte that we are about to truncate away must be zero, otherwise the encoding would
    // silently alter the block number.
    if bytes
        .iter()
        .skip(core::cmp::min(8, block_number_bytes))
        .any(|b| *b != 0)
    {
        return Err(CommitToJustificationError::BlockNumberTooLarge);
    }

    for n in 0..block_number_bytes {
        out.push(bytes.get(n).copied().unwrap_or(0));
    }

    Ok(())
}

/// Error potentially returned by [`grandpa_commit_to_justification`].
#[derive(Debug, derive_more::Display, derive_more::Error, Clone, PartialEq, Eq)]
pub enum CommitToJustificationError {
    /// Failed to decode the commit.
    #[display("Failed to decode the Grandpa commit")]
    CommitDecode,
    /// The number of pre-commits and the number of signatures in the commit differ.
    #[display("Mismatch between the number of pre-commits and of signatures")]
    PrecommitsAuthDataMismatch,
    /// A block number of the commit doesn't fit in `block_number_bytes` bytes.
    #[display("Block number doesn't fit in the block number encoding of the chain")]
    BlockNumberTooLarge,
}

#[cfg(test)]
mod tests {
    use crate::header;
    use alloc::{vec, vec::Vec};

    /// Builds a SCALE-encoded Grandpa commit targeting block `0xaa..aa` at height 1234, with one
    /// pre-commit per entry of `precommit_targets`.
    fn build_commit(precommit_targets: &[([u8; 32], u64)], block_number_bytes: usize) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&5u64.to_le_bytes()); // round number
        out.extend_from_slice(&12u64.to_le_bytes()); // set id
        out.extend_from_slice(&[0xaa; 32]); // target hash
        out.extend_from_slice(&1234u64.to_le_bytes()[..block_number_bytes]); // target number

        out.extend_from_slice(
            crate::util::encode_scale_compact_usize(precommit_targets.len()).as_ref(),
        );
        for (hash, number) in precommit_targets {
            out.extend_from_slice(hash);
            out.extend_from_slice(&number.to_le_bytes()[..block_number_bytes]);
        }

        out.extend_from_slice(
            crate::util::encode_scale_compact_usize(precommit_targets.len()).as_ref(),
        );
        for n in 0..precommit_targets.len() {
            out.extend_from_slice(&[u8::try_from(n).unwrap(); 64]); // signature
            out.extend_from_slice(&[u8::try_from(n).unwrap(); 32]); // public key
        }

        out
    }

    /// Builds a commit whose pre-commits all target the commit's own target block.
    fn build_simple_commit(num_precommits: usize, block_number_bytes: usize) -> Vec<u8> {
        let targets = vec![([0xaa; 32], 1234); num_precommits];
        build_commit(&targets, block_number_bytes)
    }

    /// Builds a header whose only meaningful field is its parent hash.
    fn build_header(parent_hash: [u8; 32], number: u64) -> Vec<u8> {
        header::HeaderRef {
            parent_hash: &parent_hash,
            number,
            extrinsics_root: &[0; 32],
            state_root: &[0; 32],
            digest: header::DigestRef::empty(),
        }
        .scale_encoding_vec(4)
    }

    /// Re-implements the ancestry walk that `bp_header_chain`'s justification verifier performs,
    /// in order to check that the `votes_ancestries` we produce is the list that it expects: every
    /// pre-commit must be reachable from the block being finalized, and no header may be left
    /// unvisited.
    fn verifier_ancestry_check(justification: &[u8], block_number_bytes: usize) {
        use alloc::collections::{BTreeMap, BTreeSet};

        let decoded = crate::finality::decode::decode_grandpa_justification(
            justification,
            block_number_bytes,
        )
        .unwrap();

        let mut parents = BTreeMap::new();
        let mut unvisited = BTreeSet::new();
        for ancestor in decoded.votes_ancestries.clone() {
            let hash = ancestor.hash(block_number_bytes);
            assert!(
                parents.insert(hash, *ancestor.parent_hash).is_none(),
                "duplicate header in votes_ancestries"
            );
            unvisited.insert(hash);
        }

        for precommit in decoded.precommits.iter() {
            let mut current = *precommit.target_hash;
            let mut route = Vec::new();
            while current != *decoded.target_hash {
                let parent = parents
                    .get(&current)
                    .unwrap_or_else(|| panic!("pre-commit is not linked to the finalized block"));
                route.push(current);
                current = *parent;
            }
            for hash in route {
                unvisited.remove(&hash);
            }
        }

        assert!(
            unvisited.is_empty(),
            "votes_ancestries carries {} header(s) that no pre-commit needs",
            unvisited.len()
        );
    }

    #[test]
    fn commit_to_justification_round_trip() {
        let scale_encoded_commit = build_simple_commit(7, 4);

        let justification =
            super::grandpa_commit_to_justification(&scale_encoded_commit, 4, |_| None).unwrap();

        let commit =
            crate::finality::decode::decode_grandpa_commit(&scale_encoded_commit, 4).unwrap();
        let decoded =
            crate::finality::decode::decode_grandpa_justification(&justification, 4).unwrap();

        assert_eq!(decoded.round, commit.round_number);
        assert_eq!(decoded.target_hash, commit.target_hash);
        assert_eq!(decoded.target_number, commit.target_number);
        assert_eq!(decoded.votes_ancestries.len(), 0);
        assert_eq!(decoded.precommits.iter().len(), commit.precommits.len());

        for (justification_precommit, (commit_precommit, (signature, public_key))) in decoded
            .precommits
            .iter()
            .zip(commit.precommits.iter().zip(commit.auth_data.iter()))
        {
            assert_eq!(
                justification_precommit.target_hash,
                commit_precommit.target_hash
            );
            assert_eq!(
                justification_precommit.target_number,
                commit_precommit.target_number
            );
            assert_eq!(justification_precommit.signature, *signature);
            assert_eq!(justification_precommit.authority_public_key, *public_key);
        }

        verifier_ancestry_check(&justification, 4);
    }

    #[test]
    fn commit_to_justification_descendant_precommits_get_an_ancestry() {
        // Chain: target(#1234, 0xaa..) <- child(#1235) <- grandchild(#1236).
        let child = build_header([0xaa; 32], 1235);
        let child_hash = header::hash_from_scale_encoded_header(&child);
        let grandchild = build_header(child_hash, 1236);
        let grandchild_hash = header::hash_from_scale_encoded_header(&grandchild);

        // One vote on the finalized block, one on its child, one on its grandchild.
        let scale_encoded_commit = build_commit(
            &[
                ([0xaa; 32], 1234),
                (child_hash, 1235),
                (grandchild_hash, 1236),
            ],
            4,
        );

        let justification =
            super::grandpa_commit_to_justification(&scale_encoded_commit, 4, |hash| {
                if *hash == child_hash {
                    Some(child.clone())
                } else if *hash == grandchild_hash {
                    Some(grandchild.clone())
                } else {
                    None
                }
            })
            .unwrap();

        let decoded =
            crate::finality::decode::decode_grandpa_justification(&justification, 4).unwrap();

        // All three votes are kept, ...
        assert_eq!(decoded.precommits.iter().len(), 3);
        // ... and the two headers that link them to the finalized block are carried along, each
        // one exactly once even though the grandchild's route goes through the child.
        let ancestries = decoded
            .votes_ancestries
            .clone()
            .map(|h| h.hash(4))
            .collect::<Vec<_>>();
        assert_eq!(ancestries.len(), 2);
        assert!(ancestries.contains(&child_hash));
        assert!(ancestries.contains(&grandchild_hash));

        verifier_ancestry_check(&justification, 4);
    }

    #[test]
    fn commit_to_justification_drops_unresolvable_precommits() {
        // A vote on a block whose header we don't know can't be linked to the finalized block. It
        // would count for zero weight on the verifier's side and make strict verification fail
        // outright, so it must not appear in the justification.
        let scale_encoded_commit = build_commit(&[([0xaa; 32], 1234), ([0xbb; 32], 1235)], 4);

        let justification =
            super::grandpa_commit_to_justification(&scale_encoded_commit, 4, |_| None).unwrap();

        let decoded =
            crate::finality::decode::decode_grandpa_justification(&justification, 4).unwrap();
        assert_eq!(decoded.precommits.iter().len(), 1);
        assert_eq!(
            decoded.precommits.iter().next().unwrap().target_hash,
            &[0xaa; 32]
        );
        assert_eq!(decoded.votes_ancestries.len(), 0);

        verifier_ancestry_check(&justification, 4);
    }

    #[test]
    fn commit_to_justification_drops_precommits_below_the_target() {
        // A vote on a block that is not above the finalized one can't be a descendant of it.
        let scale_encoded_commit = build_commit(&[([0xaa; 32], 1234), ([0xcc; 32], 1233)], 4);

        let justification =
            super::grandpa_commit_to_justification(&scale_encoded_commit, 4, |_| {
                panic!("no header lookup should be needed")
            })
            .unwrap();

        let decoded =
            crate::finality::decode::decode_grandpa_justification(&justification, 4).unwrap();
        assert_eq!(decoded.precommits.iter().len(), 1);
        assert_eq!(decoded.votes_ancestries.len(), 0);
    }

    #[test]
    fn commit_to_justification_rejects_inconsistent_ancestry() {
        // A header that claims a height one above the finalized block but whose parent isn't the
        // finalized block leads nowhere. The walk must stop rather than follow the chain forever.
        let bogus = build_header([0xdd; 32], 1235);
        let bogus_hash = header::hash_from_scale_encoded_header(&bogus);
        let scale_encoded_commit = build_commit(&[(bogus_hash, 1235)], 4);

        let justification =
            super::grandpa_commit_to_justification(&scale_encoded_commit, 4, |hash| {
                if *hash == bogus_hash {
                    Some(bogus.clone())
                } else {
                    // Pretend that every other block exists and is its own parent, so that only
                    // the height bound can stop the walk.
                    Some(build_header(*hash, 0))
                }
            })
            .unwrap();

        let decoded =
            crate::finality::decode::decode_grandpa_justification(&justification, 4).unwrap();
        assert_eq!(decoded.precommits.iter().len(), 0);
        assert_eq!(decoded.votes_ancestries.len(), 0);
    }

    #[test]
    fn commit_to_justification_block_number_bytes() {
        // `decode_grandpa_justification` assumes that block numbers are encoded on 4 bytes (see
        // `PRECOMMIT_ENCODED_LEN`), so the encoding is checked by hand here rather than by
        // decoding it back.
        let scale_encoded_commit = build_simple_commit(3, 8);
        let justification =
            super::grandpa_commit_to_justification(&scale_encoded_commit, 8, |_| None).unwrap();

        assert_eq!(
            justification.len(),
            8 + 32 + 8 + 1 + 3 * (32 + 8 + 64 + 32) + 1
        );
        assert_eq!(&justification[..8], &5u64.to_le_bytes());
        assert_eq!(&justification[8..40], &[0xaa; 32]);
        assert_eq!(&justification[40..48], &1234u64.to_le_bytes());
        // Compact-encoded length of the list of pre-commits.
        assert_eq!(justification[48], 3 << 2);
        // Compact-encoded length of the (empty) list of vote ancestries.
        assert_eq!(*justification.last().unwrap(), 0);
    }

    #[test]
    fn commit_to_justification_block_number_too_large() {
        let mut scale_encoded_commit = build_simple_commit(1, 4);
        // Overwrite the target number with a value that doesn't fit on two bytes.
        scale_encoded_commit[48..52].copy_from_slice(&70000u32.to_le_bytes());
        assert_eq!(
            super::grandpa_commit_to_justification(&scale_encoded_commit, 2, |_| None),
            Err(super::CommitToJustificationError::CommitDecode)
        );
    }

    #[test]
    fn commit_to_justification_invalid_commit() {
        assert!(super::grandpa_commit_to_justification(&[0, 1, 2, 3], 4, |_| None).is_err());
    }
}
