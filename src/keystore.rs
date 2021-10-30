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

#![cfg(all(feature = "std"))]
#![cfg_attr(docsrs, doc(cfg(all(feature = "std"))))]

#![allow(dead_code)] // TODO: this whole module is a draft

use std::path;

/// Namespace of the key.
pub type KeyNamespace = [u8; 4];

/// Access to private keys through various methods.
pub struct Keystore {
    keys: hashbrown::HashMap<Vec<u8>, KeyAccess>,
}

impl Keystore {
    /// Initializes a new keystore.
    pub fn new() -> Self {
        Keystore {
            keys: hashbrown::HashMap::with_capacity(32),
        }
    }

    /// Generates a new key and inserts it in the keystore.
    ///
    /// Returns the corresponding public key.
    pub fn generate(&self, namespace: KeyNamespace) -> [u8; 32] {
        todo!()
    }

    /// Signs the given payload using the private key associated to the public key passed as
    /// parameter.
    pub async fn sign(
        &self,
        key_namespace: KeyNamespace,
        public_key: &[u8; 32],
        payload: &[u8],
    ) -> Result<[u8; 64], SignError> {
        todo!()
    }
}

pub enum SignError {
    UnknownPublicKey,
}

enum KeyAccess {
    Memory,
    File(path::PathBuf),
}
