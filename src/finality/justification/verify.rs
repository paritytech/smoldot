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

use crate::finality::justification::decode;

use alloc::vec::Vec;
use core::{cmp, iter, mem};
use rand::Rng as _;
use rand_chacha::{rand_core::SeedableRng as _, ChaCha20Rng};

/// Configuration for a justification verification process.
#[derive(Debug)]
pub struct Config<'a, I> {
    /// Justification to verify.
    pub justification: decode::GrandpaJustificationRef<'a>,

    pub block_number_bytes: usize,

    // TODO: document
    pub authorities_set_id: u64,

    /// List of authorities that are allowed to emit pre-commits for the block referred to by
    /// the justification. Must implement `Iterator<Item = impl AsRef<[u8]>> + Clone`, where
    /// each item is the public key of an authority.
    pub authorities_list: I,

    /// Seed for a PRNG used for various purposes during the verification.
    ///
    /// > **Note**: The verification is nonetheless deterministic.
    pub randomness_seed: [u8; 32],
}

// TODO: rewrite as a generator-style process?

/// Verifies that a justification is valid.
pub fn verify(config: Config<impl Iterator<Item = impl AsRef<[u8]>> + Clone>) -> Result<(), Error> {
    let num_precommits = config.justification.precommits.iter().count();

    // Check that justification contains a number of signatures equal to at least 2/3rd of the
    // number of authorities.
    // Duplicate signatures are checked below.
    // The logic of the check is `actual >= (expected * 2 / 3) + 1`.
    if num_precommits < (config.authorities_list.clone().count() * 2 / 3) + 1 {
        return Err(Error::NotEnoughSignatures);
    }

    let mut randomness = ChaCha20Rng::from_seed(config.randomness_seed);

    // Used to store the authority public keys that have been seen, in order to check for
    // duplicates.
    let mut seen_pub_keys = hashbrown::HashSet::with_capacity_and_hasher(
        num_precommits,
        crate::util::SipHasherBuild::new(randomness.gen()),
    );

    // Verifying all the signatures together brings better performances than verifying them one
    // by one.
    // Note that batched ed25519 verification has some issues. The code below uses a special
    // flavour of ed25519 where ambiguities are removed.
    // See https://docs.rs/ed25519-zebra/2.2.0/ed25519_zebra/batch/index.html and
    // https://github.com/zcash/zips/blob/master/zip-0215.rst
    let mut batch = ed25519_zebra::batch::Verifier::new();

    for precommit in config.justification.precommits.iter() {
        if !config
            .authorities_list
            .clone()
            .any(|a| a.as_ref() == precommit.authority_public_key)
        {
            return Err(Error::NotAuthority(*precommit.authority_public_key));
        }

        // Make sure that the public key isn't in `seen_pub_keys` yet, and insert it in there.
        if !seen_pub_keys.insert(precommit.authority_public_key) {
            return Err(Error::DuplicateSignature(*precommit.authority_public_key));
        }

        // TODO: must check signed block ancestry using `votes_ancestries`

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
        msg.extend_from_slice(&u64::to_le_bytes(config.justification.round)[..]);
        msg.extend_from_slice(&u64::to_le_bytes(config.authorities_set_id)[..]);
        debug_assert_eq!(msg.len(), msg.capacity());

        batch.queue(ed25519_zebra::batch::Item::from((
            ed25519_zebra::VerificationKeyBytes::from(*precommit.authority_public_key),
            ed25519_zebra::Signature::from(*precommit.signature),
            &msg,
        )));
    }

    // Actual signatures verification performed here.
    batch
        .verify(&mut randomness)
        .map_err(|_| Error::BadSignature)?;

    // TODO: must check that votes_ancestries doesn't contain any unused entry
    // TODO: there's also a "ghost" thing?

    Ok(())
}

/// Error that can happen while verifying a justification.
#[derive(Debug, derive_more::Display)]
pub enum Error {
    /// One of the public keys is invalid.
    BadPublicKey,
    /// One of the signatures can't be verified.
    BadSignature,
    /// One authority has produced two signatures.
    #[display(fmt = "One authority has produced two signatures")]
    DuplicateSignature([u8; 32]),
    /// One of the public keys isn't in the list of authorities.
    #[display(fmt = "One of the public keys isn't in the list of authorities")]
    NotAuthority([u8; 32]),
    /// Justification doesn't contain enough authorities signatures to be valid.
    NotEnoughSignatures,
}
