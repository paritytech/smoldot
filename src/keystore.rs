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
use rand::SeedableRng as _;

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
    /// Must be passed bytes of entropy that are used to generate private keys.
    pub fn new(randomness_seed: [u8; 32]) -> Self {
        Keystore {
            guarded: Mutex::new(Guarded {
                gen_rng: rand_chacha::ChaCha20Rng::from_seed(randomness_seed),
                keys: hashbrown::HashMap::with_capacity(32),
            }),
        }
    }

    /// Generates a new key and inserts it in the keystore.
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
        }
    }
}

struct Guarded {
    gen_rng: rand_chacha::ChaCha20Rng,
    keys: hashbrown::HashMap<(KeyNamespace, [u8; 32]), PrivateKey>,
}

pub enum SignError {
    UnknownPublicKey,
}

enum PrivateKey {
    MemoryEd25519(ed25519_zebra::SigningKey),
    // TODO: File(path::PathBuf),
}
