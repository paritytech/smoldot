// Smoldot
// Copyright (C) 2023  Pierre Krieger
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

use crate::finality::decode;

use alloc::vec::Vec;
use core::{cmp, iter, mem};
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{RngCore as _, SeedableRng as _},
};

/// Configuration for a commit verification process.
#[derive(Debug)]
pub struct CommitVerifyConfig<C> {
    /// SCALE-encoded commit to verify.
    pub commit: C,

    /// Number of bytes used for encoding the block number in the SCALE-encoded commit.
    pub block_number_bytes: usize,

    // TODO: document
    pub expected_authorities_set_id: u64,

    /// Number of authorities that are allowed to emit pre-commits. Used to calculate the
    /// threshold of the number of required signatures.
    pub num_authorities: u32,

    /// Seed for a PRNG used for various purposes during the verification.
    ///
    /// > **Note**: The verification is nonetheless deterministic.
    pub randomness_seed: [u8; 32],
}

/// Commit verification in progress.
#[must_use]
pub enum CommitVerify<C> {
    /// See [`CommitVerifyIsAuthority`].
    IsAuthority(CommitVerifyIsAuthority<C>),
    /// See [`CommitVerifyIsParent`].
    IsParent(CommitVerifyIsParent<C>),
    /// Verification is finished. Contains an error if the commit message is invalid.
    Finished(Result<(), CommitVerifyError>),
    /// Verification is finished, but [`CommitVerifyIsParent::resume`] has been called with `None`,
    /// meaning that some signatures couldn't be verified, and the commit message doesn't contain
    /// enough signatures that are known to be valid.
    ///
    /// The commit must be verified again after more blocks are available.
    FinishedUnknown,
}

/// Verifies that a commit is valid.
pub fn verify_commit<C: AsRef<[u8]>>(config: CommitVerifyConfig<C>) -> CommitVerify<C> {
    let decoded_commit =
        match decode::decode_grandpa_commit(config.commit.as_ref(), config.block_number_bytes) {
            Ok(c) => c,
            Err(_) => return CommitVerify::Finished(Err(CommitVerifyError::InvalidFormat)),
        };

    if decoded_commit.set_id != config.expected_authorities_set_id {
        return CommitVerify::Finished(Err(CommitVerifyError::BadSetId));
    }

    if decoded_commit.auth_data.len() != decoded_commit.precommits.len() {
        return CommitVerify::Finished(Err(CommitVerifyError::InvalidFormat));
    }

    let mut randomness = ChaCha20Rng::from_seed(config.randomness_seed);

    // Make sure that there is no duplicate authority public key.
    {
        let mut unique = hashbrown::HashSet::with_capacity_and_hasher(
            decoded_commit.auth_data.len(),
            crate::util::SipHasherBuild::new({
                let mut seed = [0; 16];
                randomness.fill_bytes(&mut seed);
                seed
            }),
        );
        if let Some((_, faulty_pub_key)) = decoded_commit
            .auth_data
            .iter()
            .find(|(_, pubkey)| !unique.insert(pubkey))
        {
            return CommitVerify::Finished(Err(CommitVerifyError::DuplicateSignature {
                authority_key: **faulty_pub_key,
            }));
        }
    }

    CommitVerification {
        commit: config.commit,
        block_number_bytes: config.block_number_bytes,
        next_precommit_index: 0,
        next_precommit_author_verified: false,
        next_precommit_block_verified: false,
        num_verified_signatures: 0,
        num_authorities: config.num_authorities,
        signatures_batch: ed25519_zebra::batch::Verifier::new(),
        randomness,
    }
    .resume()
}

/// Must return whether a certain public key is in the list of authorities that are allowed to
/// generate pre-commits.
#[must_use]
pub struct CommitVerifyIsAuthority<C> {
    inner: CommitVerification<C>,
}

impl<C: AsRef<[u8]>> CommitVerifyIsAuthority<C> {
    /// Public key to verify.
    pub fn authority_public_key(&self) -> &[u8; 32] {
        debug_assert!(!self.inner.next_precommit_author_verified);
        let decoded_commit = decode::decode_grandpa_commit(
            self.inner.commit.as_ref(),
            self.inner.block_number_bytes,
        )
        .unwrap();
        decoded_commit.auth_data[self.inner.next_precommit_index].1
    }

    /// Resumes the verification process.
    ///
    /// Must be passed `true` if the public key is indeed in the list of authorities.
    /// Passing `false` always returns [`CommitVerify::Finished`] containing an error.
    pub fn resume(mut self, is_authority: bool) -> CommitVerify<C> {
        if !is_authority {
            let key = *self.authority_public_key();
            return CommitVerify::Finished(Err(CommitVerifyError::NotAuthority {
                authority_key: key,
            }));
        }

        self.inner.next_precommit_author_verified = true;
        self.inner.resume()
    }
}

/// Must return whether a certain block is a descendant of the target block.
#[must_use]
pub struct CommitVerifyIsParent<C> {
    inner: CommitVerification<C>,
    /// For performance reasons, the block number is copied here, but not the block hash. This
    /// hasn't actually been benchmarked, so feel free to do so.
    block_number: u64,
}

impl<C: AsRef<[u8]>> CommitVerifyIsParent<C> {
    /// Height of the block to check.
    pub fn block_number(&self) -> u64 {
        self.block_number
    }

    /// Hash of the block to check.
    pub fn block_hash(&self) -> &[u8; 32] {
        debug_assert!(!self.inner.next_precommit_block_verified);
        let decoded_commit = decode::decode_grandpa_commit(
            self.inner.commit.as_ref(),
            self.inner.block_number_bytes,
        )
        .unwrap();
        decoded_commit.precommits[self.inner.next_precommit_index].target_hash
    }

    /// Height of the block that must be the ancestor of the block to check.
    pub fn target_block_number(&self) -> u64 {
        let decoded_commit = decode::decode_grandpa_commit(
            self.inner.commit.as_ref(),
            self.inner.block_number_bytes,
        )
        .unwrap();
        decoded_commit.target_number
    }

    /// Hash of the block that must be the ancestor of the block to check.
    pub fn target_block_hash(&self) -> &[u8; 32] {
        let decoded_commit = decode::decode_grandpa_commit(
            self.inner.commit.as_ref(),
            self.inner.block_number_bytes,
        )
        .unwrap();
        decoded_commit.target_hash
    }

    /// Resumes the verification process.
    ///
    /// Must be passed `Some(true)` if the block is known to be a descendant of the target block,
    /// or `None` if it is unknown.
    /// Passing `Some(false)` always returns [`CommitVerify::Finished`] containing an
    /// error.
    pub fn resume(mut self, is_parent: Option<bool>) -> CommitVerify<C> {
        match is_parent {
            None => {}
            Some(true) => self.inner.num_verified_signatures += 1,
            Some(false) => {
                return CommitVerify::Finished(Err(CommitVerifyError::BadAncestry));
            }
        }

        self.inner.next_precommit_block_verified = true;
        self.inner.resume()
    }
}

struct CommitVerification<C> {
    /// Encoded commit message. Guaranteed to decode successfully.
    commit: C,

    /// See [`CommitVerifyConfig::block_number_bytes`].
    block_number_bytes: usize,

    /// Index of the next pre-commit to process within the commit.
    next_precommit_index: usize,

    /// Whether the precommit whose index is [`CommitVerification::next_precommit_index`] has been
    /// verified as coming from the list of authorities.
    next_precommit_author_verified: bool,

    /// Whether the precommit whose index is [`CommitVerification::next_precommit_index`] has been
    /// verified to be about a block that is a descendant of the target block.
    next_precommit_block_verified: bool,

    /// Number of signatures that have been pushed for verification. Needs to be above a certain
    /// threshold for the commit to be valid.
    num_verified_signatures: usize,

    /// Number of authorities in the list. Used to calculate the threshold of the number of
    /// required signatures.
    num_authorities: u32,

    /// Verifying all the signatures together brings better performances than verifying them one
    /// by one.
    /// Note that batched Ed25519 verification has some issues. The code below uses a special
    /// flavor of Ed25519 where ambiguities are removed.
    /// See <https://docs.rs/ed25519-zebra/2.2.0/ed25519_zebra/batch/index.html> and
    /// <https://github.com/zcash/zips/blob/master/zip-0215.rst>
    signatures_batch: ed25519_zebra::batch::Verifier,

    /// Randomness generator used during the batch verification.
    randomness: ChaCha20Rng,
}

impl<C: AsRef<[u8]>> CommitVerification<C> {
    fn resume(mut self) -> CommitVerify<C> {
        // The `verify` function that starts the verification performs the preliminary check that
        // the commit has the correct format.
        let decoded_commit =
            decode::decode_grandpa_commit(self.commit.as_ref(), self.block_number_bytes).unwrap();

        loop {
            if let Some(precommit) = decoded_commit.precommits.get(self.next_precommit_index) {
                if !self.next_precommit_author_verified {
                    return CommitVerify::IsAuthority(CommitVerifyIsAuthority { inner: self });
                }

                if !self.next_precommit_block_verified {
                    if precommit.target_hash == decoded_commit.target_hash
                        && precommit.target_number == decoded_commit.target_number
                    {
                        self.next_precommit_block_verified = true;
                    } else {
                        return CommitVerify::IsParent(CommitVerifyIsParent {
                            block_number: precommit.target_number,
                            inner: self,
                        });
                    }
                }

                let authority_public_key = decoded_commit.auth_data[self.next_precommit_index].1;
                let signature = decoded_commit.auth_data[self.next_precommit_index].0;

                let mut msg = Vec::with_capacity(1 + 32 + self.block_number_bytes + 8 + 8);
                msg.push(1u8); // This `1` indicates which kind of message is being signed.
                msg.extend_from_slice(&precommit.target_hash[..]);
                // The message contains the little endian block number. While simple in concept,
                // in reality it is more complicated because we don't know the number of bytes of
                // this block number at compile time. We thus copy as many bytes as appropriate and
                // pad with 0s if necessary.
                msg.extend_from_slice(
                    &precommit.target_number.to_le_bytes()[..cmp::min(
                        mem::size_of_val(&precommit.target_number),
                        self.block_number_bytes,
                    )],
                );
                msg.extend(
                    iter::repeat(0).take(
                        self.block_number_bytes
                            .saturating_sub(mem::size_of_val(&precommit.target_number)),
                    ),
                );
                msg.extend_from_slice(&u64::to_le_bytes(decoded_commit.round_number)[..]);
                msg.extend_from_slice(&u64::to_le_bytes(decoded_commit.set_id)[..]);
                debug_assert_eq!(msg.len(), msg.capacity());

                self.signatures_batch
                    .queue(ed25519_zebra::batch::Item::from((
                        ed25519_zebra::VerificationKeyBytes::from(*authority_public_key),
                        ed25519_zebra::Signature::from(*signature),
                        &msg,
                    )));

                self.next_precommit_index += 1;
                self.next_precommit_author_verified = false;
                self.next_precommit_block_verified = false;
            } else {
                debug_assert!(!self.next_precommit_author_verified);
                debug_assert!(!self.next_precommit_block_verified);

                // Check that commit contains a number of signatures equal to at least 2/3rd of the
                // number of authorities.
                // Duplicate signatures are checked below.
                // The logic of the check is `actual >= (expected * 2 / 3) + 1`.
                if decoded_commit.precommits.len()
                    < (usize::try_from(self.num_authorities).unwrap() * 2 / 3) + 1
                {
                    return CommitVerify::FinishedUnknown;
                }

                // Actual signatures verification performed here.
                match self.signatures_batch.verify(&mut self.randomness) {
                    Ok(()) => {}
                    Err(_) => return CommitVerify::Finished(Err(CommitVerifyError::BadSignature)),
                }

                return CommitVerify::Finished(Ok(()));
            }
        }
    }
}

/// Error that can happen while verifying a commit.
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum CommitVerifyError {
    /// Failed to decode the commit message.
    InvalidFormat,
    /// The authorities set id of the commit doesn't match the one that is expected.
    BadSetId,
    /// One of the public keys is invalid.
    BadPublicKey,
    /// One of the signatures can't be verified.
    BadSignature,
    /// One authority has produced two signatures.
    #[display("One authority has produced two signatures")]
    DuplicateSignature { authority_key: [u8; 32] },
    /// One of the public keys isn't in the list of authorities.
    #[display("One of the public keys isn't in the list of authorities")]
    NotAuthority { authority_key: [u8; 32] },
    /// Commit contains a vote for a block that isn't a descendant of the target block.
    BadAncestry,
}

// TODO: tests

/// Configuration for a justification verification process.
#[derive(Debug)]
pub struct JustificationVerifyConfig<J, I> {
    /// Justification to verify.
    pub justification: J,

    pub block_number_bytes: usize,

    // TODO: document
    pub authorities_set_id: u64,

    /// List of authorities that are allowed to emit pre-commits for the block referred to by
    /// the justification. Must implement `Iterator<Item = &[u8]>`, where each item is
    /// the public key of an authority.
    pub authorities_list: I,

    /// Seed for a PRNG used for various purposes during the verification.
    ///
    /// > **Note**: The verification is nonetheless deterministic.
    pub randomness_seed: [u8; 32],
}

/// Verifies that a justification is valid.
pub fn verify_justification<'a>(
    config: JustificationVerifyConfig<impl AsRef<[u8]>, impl Iterator<Item = &'a [u8]>>,
) -> Result<(), JustificationVerifyError> {
    let decoded_justification = match decode::decode_grandpa_justification(
        config.justification.as_ref(),
        config.block_number_bytes,
    ) {
        Ok(c) => c,
        Err(_) => return Err(JustificationVerifyError::InvalidFormat),
    };

    let num_precommits = decoded_justification.precommits.iter().count();

    let mut randomness = ChaCha20Rng::from_seed(config.randomness_seed);

    // Collect the authorities in a set in order to be able to determine with a low complexity
    // whether a public key is an authority.
    // For each authority, contains a boolean indicating whether the authority has been seen
    // before in the list of pre-commits.
    let mut authorities_list = {
        let mut list = hashbrown::HashMap::<&[u8], _, _>::with_capacity_and_hasher(
            0,
            crate::util::SipHasherBuild::new({
                let mut seed = [0; 16];
                randomness.fill_bytes(&mut seed);
                seed
            }),
        );
        for authority in config.authorities_list {
            list.insert(authority, false);
        }
        list
    };

    // Check that justification contains a number of signatures equal to at least 2/3rd of the
    // number of authorities.
    // Duplicate signatures are checked below.
    // The logic of the check is `actual >= (expected * 2 / 3) + 1`.
    if num_precommits < (authorities_list.len() * 2 / 3) + 1 {
        return Err(JustificationVerifyError::NotEnoughSignatures);
    }

    // A pre-commit is signed over the block that this specific pre-commit targets, and not over
    // the block that the justification as a whole claims to finalize. In order for the
    // justification to actually prove anything, every pre-commit must therefore target either
    // that block or one of its descendants. The `votes_ancestries` field contains the headers
    // that link the targets of the pre-commits to the target of the justification.
    //
    // The map below contains, for each header found in `votes_ancestries`, the hash of its
    // parent.
    let votes_ancestries = {
        let mut map = hashbrown::HashMap::<[u8; 32], [u8; 32], _>::with_capacity_and_hasher(
            decoded_justification.votes_ancestries.len(),
            crate::util::SipHasherBuild::new({
                let mut seed = [0; 16];
                randomness.fill_bytes(&mut seed);
                seed
            }),
        );
        for header in decoded_justification.votes_ancestries.clone() {
            map.insert(header.hash(config.block_number_bytes), *header.parent_hash);
        }
        map
    };

    // Hashes of the headers found in `votes_ancestries` that at least one pre-commit has walked
    // through. Used at the end to detect headers that no pre-commit needed.
    let mut used_votes_ancestries = hashbrown::HashSet::<[u8; 32], _>::with_capacity_and_hasher(
        votes_ancestries.len(),
        crate::util::SipHasherBuild::new({
            let mut seed = [0; 16];
            randomness.fill_bytes(&mut seed);
            seed
        }),
    );

    // Verifying all the signatures together brings better performances than verifying them one
    // by one.
    // Note that batched ed25519 verification has some issues. The code below uses a special
    // flavour of ed25519 where ambiguities are removed.
    // See https://docs.rs/ed25519-zebra/2.2.0/ed25519_zebra/batch/index.html and
    // https://github.com/zcash/zips/blob/master/zip-0215.rst
    let mut batch = ed25519_zebra::batch::Verifier::new();

    for precommit in decoded_justification.precommits.iter() {
        match authorities_list.entry(precommit.authority_public_key) {
            hashbrown::hash_map::Entry::Occupied(mut entry) => {
                if entry.insert(true) {
                    return Err(JustificationVerifyError::DuplicateSignature {
                        authority_key: *precommit.authority_public_key,
                    });
                }
            }
            hashbrown::hash_map::Entry::Vacant(_) => {
                return Err(JustificationVerifyError::NotAuthority {
                    authority_key: *precommit.authority_public_key,
                });
            }
        }

        // Check that the pre-commit targets either the block that the justification claims to
        // finalize or one of its descendants. Without this check, signatures legitimately
        // produced for one block could be re-used in a justification that claims to finalize a
        // completely different block.
        if precommit.target_hash == decoded_justification.target_hash {
            if precommit.target_number != decoded_justification.target_number {
                return Err(JustificationVerifyError::BadAncestry);
            }
        } else {
            let mut current_hash = *precommit.target_hash;
            let mut num_steps = 0;
            while current_hash != *decoded_justification.target_hash {
                let Some(parent_hash) = votes_ancestries.get(&current_hash) else {
                    return Err(JustificationVerifyError::BadAncestry);
                };
                used_votes_ancestries.insert(current_hash);
                current_hash = *parent_hash;

                // A valid chain of ancestors visits each entry of `votes_ancestries` at most
                // once. Guarantees that the loop always terminates.
                num_steps += 1;
                if num_steps > votes_ancestries.len() {
                    return Err(JustificationVerifyError::BadAncestry);
                }
            }
        }

        let mut msg = Vec::with_capacity(1 + 32 + 4 + 8 + 8);
        msg.push(1u8); // This `1` indicates which kind of message is being signed.
        msg.extend_from_slice(&precommit.target_hash[..]);
        // The message contains the little endian block number. While simple in concept,
        // in reality it is more complicated because we don't know the number of bytes of
        // this block number at compile time. We thus copy as many bytes as appropriate and
        // pad with 0s if necessary.
        msg.extend_from_slice(
            &precommit.target_number.to_le_bytes()[..cmp::min(
                mem::size_of_val(&precommit.target_number),
                config.block_number_bytes,
            )],
        );
        msg.extend(
            iter::repeat(0).take(
                config
                    .block_number_bytes
                    .saturating_sub(mem::size_of_val(&precommit.target_number)),
            ),
        );
        msg.extend_from_slice(&u64::to_le_bytes(decoded_justification.round)[..]);
        msg.extend_from_slice(&u64::to_le_bytes(config.authorities_set_id)[..]);
        debug_assert_eq!(msg.len(), msg.capacity());

        batch.queue(ed25519_zebra::batch::Item::from((
            ed25519_zebra::VerificationKeyBytes::from(*precommit.authority_public_key),
            ed25519_zebra::Signature::from(*precommit.signature),
            &msg,
        )));
    }

    // Reject justifications that contain headers that no pre-commit has made use of.
    if used_votes_ancestries.len() != votes_ancestries.len() {
        return Err(JustificationVerifyError::UnusedAncestryEntry);
    }

    // Actual signatures verification performed here.
    batch
        .verify(&mut randomness)
        .map_err(|_| JustificationVerifyError::BadSignature)?;

    // Note that the "ghost" of the pre-commits is intentionally not calculated. Doing so would
    // additionally detect justifications that could have finalized a block higher than the one
    // that they claim to finalize, which isn't a problem from a safety point of view.

    Ok(())
}

/// Error that can happen while verifying a justification.
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum JustificationVerifyError {
    /// Failed to decode the justification.
    InvalidFormat,
    /// One of the public keys is invalid.
    BadPublicKey,
    /// One of the signatures can't be verified.
    BadSignature,
    /// One authority has produced two signatures.
    #[display("One authority has produced two signatures")]
    DuplicateSignature { authority_key: [u8; 32] },
    /// One of the public keys isn't in the list of authorities.
    #[display("One of the public keys isn't in the list of authorities")]
    NotAuthority { authority_key: [u8; 32] },
    /// Justification doesn't contain enough authorities signatures to be valid.
    NotEnoughSignatures,
    /// One of the pre-commits targets a block that is neither the block that the justification
    /// claims to finalize nor one of its descendants.
    BadAncestry,
    /// The justification contains a header that isn't used by any of the pre-commits.
    UnusedAncestryEntry,
}

#[cfg(test)]
mod tests {
    use super::{JustificationVerifyConfig, JustificationVerifyError, verify_justification};
    use crate::header;

    use alloc::vec::Vec;

    const BLOCK_NUMBER_BYTES: usize = 4;
    const SET_ID: u64 = 12;
    const ROUND: u64 = 34;

    /// Number of authorities used by all the tests below. The number of pre-commits required in
    /// order to reach the threshold is `(NUM_AUTHORITIES * 2 / 3) + 1`, in other words 3.
    const NUM_AUTHORITIES: u8 = 4;

    /// Description of a pre-commit to put in a justification built by [`encode_justification`].
    struct Precommit<'a> {
        /// Key that actually produces the signature.
        signer: &'a ed25519_zebra::SigningKey,
        /// Public key written in the pre-commit. If `None`, the one of [`Precommit::signer`] is
        /// used.
        declared_public_key: Option<[u8; 32]>,
        target_hash: [u8; 32],
        target_number: u64,
    }

    fn precommit(
        signer: &ed25519_zebra::SigningKey,
        target_hash: [u8; 32],
        target_number: u64,
    ) -> Precommit<'_> {
        Precommit {
            signer,
            declared_public_key: None,
            target_hash,
            target_number,
        }
    }

    fn signing_key(index: u8) -> ed25519_zebra::SigningKey {
        ed25519_zebra::SigningKey::from([index + 1; 32])
    }

    fn public_key(key: &ed25519_zebra::SigningKey) -> [u8; 32] {
        <[u8; 32]>::from(ed25519_zebra::VerificationKeyBytes::from(key))
    }

    /// Builds the list of signing keys used by the tests, alongside with the list of their public
    /// keys in the format expected by [`JustificationVerifyConfig::authorities_list`].
    fn authorities() -> (Vec<ed25519_zebra::SigningKey>, Vec<[u8; 32]>) {
        let keys = (0..NUM_AUTHORITIES).map(signing_key).collect::<Vec<_>>();
        let public_keys = keys.iter().map(public_key).collect::<Vec<_>>();
        (keys, public_keys)
    }

    /// Builds a header whose parent is `parent_hash`.
    fn header(parent_hash: [u8; 32], number: u64) -> header::Header {
        header::Header {
            parent_hash,
            number,
            state_root: [0; 32],
            extrinsics_root: [0; 32],
            digest: header::DigestRef::empty().into(),
        }
    }

    /// SCALE-encodes a justification. Note that the pre-commits are always signed over the block
    /// that they themselves target, exactly like a legitimate authority would do.
    fn encode_justification(
        target_hash: [u8; 32],
        target_number: u64,
        precommits: &[Precommit],
        votes_ancestries: &[header::Header],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&ROUND.to_le_bytes());
        out.extend_from_slice(&target_hash);
        out.extend_from_slice(&u32::try_from(target_number).unwrap().to_le_bytes());

        out.extend_from_slice(crate::util::encode_scale_compact_usize(precommits.len()).as_ref());
        for precommit in precommits {
            let target_number = u32::try_from(precommit.target_number)
                .unwrap()
                .to_le_bytes();

            let mut msg = Vec::new();
            msg.push(1u8);
            msg.extend_from_slice(&precommit.target_hash);
            msg.extend_from_slice(&target_number);
            msg.extend_from_slice(&ROUND.to_le_bytes());
            msg.extend_from_slice(&SET_ID.to_le_bytes());

            out.extend_from_slice(&precommit.target_hash);
            out.extend_from_slice(&target_number);
            out.extend_from_slice(&precommit.signer.sign(&msg).to_bytes());
            out.extend_from_slice(
                &precommit
                    .declared_public_key
                    .unwrap_or_else(|| public_key(precommit.signer)),
            );
        }

        out.extend_from_slice(
            crate::util::encode_scale_compact_usize(votes_ancestries.len()).as_ref(),
        );
        for header in votes_ancestries {
            out.extend_from_slice(&header.scale_encoding_vec(BLOCK_NUMBER_BYTES));
        }

        out
    }

    fn verify(
        justification: &[u8],
        authorities_list: &[[u8; 32]],
    ) -> Result<(), JustificationVerifyError> {
        verify_justification(JustificationVerifyConfig {
            justification,
            block_number_bytes: BLOCK_NUMBER_BYTES,
            authorities_set_id: SET_ID,
            authorities_list: authorities_list.iter().map(|a| &a[..]),
            randomness_seed: [0; 32],
        })
    }

    #[test]
    fn valid_justification_without_ancestries() {
        let (keys, authorities) = authorities();
        let target_hash = [0xaa; 32];

        let justification = encode_justification(
            target_hash,
            10,
            &keys[..3]
                .iter()
                .map(|k| precommit(k, target_hash, 10))
                .collect::<Vec<_>>(),
            &[],
        );

        let result = verify(&justification, &authorities);
        assert!(matches!(result, Ok(())), "{result:?}");
    }

    #[test]
    fn valid_justification_with_ancestries() {
        let (keys, authorities) = authorities();
        let target_hash = [0xaa; 32];
        let child = header(target_hash, 11);
        let child_hash = child.hash(BLOCK_NUMBER_BYTES);
        let grand_child = header(child_hash, 12);
        let grand_child_hash = grand_child.hash(BLOCK_NUMBER_BYTES);

        // The three pre-commits target three different blocks: the target of the justification
        // itself, one of its children, and one of its grand-children.
        let justification = encode_justification(
            target_hash,
            10,
            &[
                precommit(&keys[0], target_hash, 10),
                precommit(&keys[1], child_hash, 11),
                precommit(&keys[2], grand_child_hash, 12),
            ],
            &[child, grand_child],
        );

        let result = verify(&justification, &authorities);
        assert!(matches!(result, Ok(())), "{result:?}");
    }

    /// Regression test for the vulnerability where pre-commits are never bound to the block that
    /// the justification claims to finalize. Genuine signatures produced for one block must not
    /// be accepted as a proof that some other block is finalized.
    #[test]
    fn precommits_cant_be_retargeted() {
        let (keys, authorities) = authorities();
        let genuinely_signed_block = [0xaa; 32];
        let fabricated_block = [0xbb; 32];

        let justification = encode_justification(
            fabricated_block,
            10,
            &keys[..3]
                .iter()
                .map(|k| precommit(k, genuinely_signed_block, 10))
                .collect::<Vec<_>>(),
            &[],
        );

        let result = verify(&justification, &authorities);
        assert!(
            matches!(result, Err(JustificationVerifyError::BadAncestry)),
            "{result:?}"
        );
    }

    /// Same as [`valid_justification_with_ancestries`], but the headers that link the pre-commits
    /// to the target of the justification are missing.
    #[test]
    fn missing_ancestry_headers() {
        let (keys, authorities) = authorities();
        let target_hash = [0xaa; 32];
        let child = header(target_hash, 11);
        let child_hash = child.hash(BLOCK_NUMBER_BYTES);

        let justification = encode_justification(
            target_hash,
            10,
            &keys[..3]
                .iter()
                .map(|k| precommit(k, child_hash, 11))
                .collect::<Vec<_>>(),
            &[],
        );

        let result = verify(&justification, &authorities);
        assert!(
            matches!(result, Err(JustificationVerifyError::BadAncestry)),
            "{result:?}"
        );
    }

    /// A pre-commit that targets the same hash as the justification but a different height must
    /// be rejected.
    #[test]
    fn precommit_target_height_mismatch() {
        let (keys, authorities) = authorities();
        let target_hash = [0xaa; 32];

        let justification = encode_justification(
            target_hash,
            10,
            &[
                precommit(&keys[0], target_hash, 10),
                precommit(&keys[1], target_hash, 10),
                precommit(&keys[2], target_hash, 11),
            ],
            &[],
        );

        let result = verify(&justification, &authorities);
        assert!(
            matches!(result, Err(JustificationVerifyError::BadAncestry)),
            "{result:?}"
        );
    }

    #[test]
    fn unused_ancestry_entry() {
        let (keys, authorities) = authorities();
        let target_hash = [0xaa; 32];
        let child = header(target_hash, 11);
        let child_hash = child.hash(BLOCK_NUMBER_BYTES);

        let justification = encode_justification(
            target_hash,
            10,
            &keys[..3]
                .iter()
                .map(|k| precommit(k, child_hash, 11))
                .collect::<Vec<_>>(),
            &[child, header([0xcc; 32], 99)],
        );

        let result = verify(&justification, &authorities);
        assert!(
            matches!(result, Err(JustificationVerifyError::UnusedAncestryEntry)),
            "{result:?}"
        );
    }

    #[test]
    fn bad_signature_detected() {
        let (keys, authorities) = authorities();
        let target_hash = [0xaa; 32];

        // The last pre-commit is signed by `keys[2]` but claims to come from `keys[3]`.
        let justification = encode_justification(
            target_hash,
            10,
            &[
                precommit(&keys[0], target_hash, 10),
                precommit(&keys[1], target_hash, 10),
                Precommit {
                    declared_public_key: Some(public_key(&keys[3])),
                    ..precommit(&keys[2], target_hash, 10)
                },
            ],
            &[],
        );

        let result = verify(&justification, &authorities);
        assert!(
            matches!(result, Err(JustificationVerifyError::BadSignature)),
            "{result:?}"
        );
    }

    #[test]
    fn not_authority_detected() {
        let (keys, authorities) = authorities();
        let not_an_authority = signing_key(NUM_AUTHORITIES);
        let target_hash = [0xaa; 32];

        let justification = encode_justification(
            target_hash,
            10,
            &[
                precommit(&keys[0], target_hash, 10),
                precommit(&keys[1], target_hash, 10),
                precommit(&not_an_authority, target_hash, 10),
            ],
            &[],
        );

        let result = verify(&justification, &authorities);
        assert!(
            matches!(result, Err(JustificationVerifyError::NotAuthority { .. })),
            "{result:?}"
        );
    }

    #[test]
    fn not_enough_signatures() {
        let (keys, authorities) = authorities();
        let target_hash = [0xaa; 32];

        let justification = encode_justification(
            target_hash,
            10,
            &keys[..2]
                .iter()
                .map(|k| precommit(k, target_hash, 10))
                .collect::<Vec<_>>(),
            &[],
        );

        let result = verify(&justification, &authorities);
        assert!(
            matches!(result, Err(JustificationVerifyError::NotEnoughSignatures)),
            "{result:?}"
        );
    }
}
