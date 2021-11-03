// Smoldot
// Copyright (C) 2019-2021  Parity Technologies (UK) Ltd.
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

// TODO: doc

#![cfg(all(feature = "std"))]
#![cfg_attr(docsrs, doc(cfg(all(feature = "std"))))]

use futures::lock::Mutex;
use rand::{Rng as _, SeedableRng as _};

/// Namespace of the key.
// TODO: document
pub type KeyNamespace = [u8; 4];

/// Collection of keypairs.
///
/// This module doesn't give you access to the content of private keys, only to signing
/// capabilities.
pub struct Keystore {
    guarded: Mutex<Guarded>,
}

impl Keystore {
    /// Initializes a new keystore.
    ///
    /// Must be passed bytes of entropy that are used to avoid hash collision attacks and to
    /// generate private keys.
    pub fn new(randomness_seed: [u8; 32]) -> Self {
        let mut gen_rng = rand_chacha::ChaCha20Rng::from_seed(randomness_seed);

        let keys = hashbrown::HashMap::with_capacity_and_hasher(32, {
            ahash::RandomState::with_seeds(
                gen_rng.sample(rand::distributions::Standard),
                gen_rng.sample(rand::distributions::Standard),
                gen_rng.sample(rand::distributions::Standard),
                gen_rng.sample(rand::distributions::Standard),
            )
        });

        Keystore {
            guarded: Mutex::new(Guarded { gen_rng, keys }),
        }
    }

    /// Generates a new ed25519 key and inserts it in the keystore.
    ///
    /// Returns the corresponding public key.
    // TODO: add a `save: bool` parameter that saves the key to the file system
    pub async fn generate_ed25519(&self, namespace: KeyNamespace) -> [u8; 32] {
        let mut guarded = self.guarded.lock().await;

        // Note: it is in principle possible to generate some entropy from the PRNG, then unlock
        // the mutex while the private key is being generated. This reduces the time during which
        // the mutex is locked, but in practice generating a key is a rare enough event that this
        // is not worth the effort.
        let private_key = ed25519_zebra::SigningKey::new(&mut guarded.gen_rng);
        let public_key = ed25519_zebra::VerificationKey::from(&private_key);
        guarded.keys.insert(
            (namespace, public_key.into()),
            PrivateKey::MemoryEd25519(private_key),
        );

        public_key.into()
    }

    /// Returns the list of all keys known to this keystore.
    ///
    /// > **Note**: Keep in mind that this function is racy, as keys can be added and removed
    /// >           in parallel.
    pub async fn keys(&self) -> impl Iterator<Item = (KeyNamespace, [u8; 32])> {
        let guarded = self.guarded.lock().await;
        guarded.keys.keys().cloned().collect::<Vec<_>>().into_iter()
    }

    /// Generates a new sr25519 key and inserts it in the keystore.
    ///
    /// Returns the corresponding public key.
    // TODO: add a `save: bool` parameter that saves the key to the file system
    pub async fn generate_sr25519(&self, namespace: KeyNamespace) -> [u8; 32] {
        let mut guarded = self.guarded.lock().await;

        // Note: it is in principle possible to generate some entropy from the PRNG, then unlock
        // the mutex while the private key is being generated. This reduces the time during which
        // the mutex is locked, but in practice generating a key is a rare enough event that this
        // is not worth the effort.
        let keypair = schnorrkel::Keypair::generate_with(&mut guarded.gen_rng);
        let public_key = keypair.public.to_bytes();
        guarded
            .keys
            .insert((namespace, public_key), PrivateKey::MemorySr25519(keypair));

        public_key
    }

    /// Signs the given payload using the private key associated to the public key passed as
    /// parameter.
    pub async fn sign(
        &self,
        key_namespace: KeyNamespace,
        public_key: &[u8; 32],
        payload: &[u8],
    ) -> Result<[u8; 64], SignError> {
        let guarded = self.guarded.lock().await;
        let key = guarded
            .keys
            .get(&(key_namespace, *public_key))
            .ok_or(SignError::UnknownPublicKey)?;

        match key {
            PrivateKey::MemoryEd25519(key) => Ok(key.sign(payload).into()),
            PrivateKey::MemorySr25519(key) => {
                // TODO: is creating the signing context expensive?
                let context = schnorrkel::signing_context(b"substrate");
                Ok(key.sign(context.bytes(payload)).to_bytes())
            }
        }
    }

    // TODO: doc
    ///
    /// Note that the labels must be `'static` due to requirements from the underlying library.
    // TODO: unclear why this can't be an async function; getting lifetime errors
    pub fn sign_sr25519_vrf<'a>(
        &'a self,
        key_namespace: KeyNamespace,
        public_key: &'a [u8; 32],
        label: &'static [u8],
        transcript_items: impl Iterator<Item = (&'static [u8], either::Either<&'a [u8], u64>)> + 'a,
    ) -> impl core::future::Future<Output = Result<VrfSignature, SignVrfError>> + 'a {
        async move {
            let guarded = self.guarded.lock().await;
            let key = guarded
                .keys
                .get(&(key_namespace, *public_key))
                .ok_or(SignVrfError::Sign(SignError::UnknownPublicKey))?;

            match key {
                PrivateKey::MemoryEd25519(_) => Err(SignVrfError::WrongKeyAlgorithm),
                PrivateKey::MemorySr25519(key) => {
                    let mut transcript = merlin::Transcript::new(label);
                    for (label, value) in transcript_items {
                        match value {
                            either::Left(bytes) => {
                                transcript.append_message(label, &bytes);
                            }
                            either::Right(value) => {
                                transcript.append_u64(label, value);
                            }
                        }
                    }

                    let (_in_out, proof, _) = key.vrf_sign(transcript);
                    Ok(VrfSignature {
                        // TODO: should probably output the `_in_out` as well
                        proof: proof.to_bytes(),
                    })
                }
            }
        }
    }
}

struct Guarded {
    gen_rng: rand_chacha::ChaCha20Rng,
    keys: hashbrown::HashMap<(KeyNamespace, [u8; 32]), PrivateKey, ahash::RandomState>,
}

pub struct VrfSignature {
    pub proof: [u8; 64],
}

pub enum SignError {
    UnknownPublicKey,
}

pub enum SignVrfError {
    Sign(SignError),
    WrongKeyAlgorithm,
}

enum PrivateKey {
    MemoryEd25519(ed25519_zebra::SigningKey),
    MemorySr25519(schnorrkel::Keypair),
    // TODO: File(path::PathBuf),
}
