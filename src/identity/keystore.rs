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

//! Data structure containing cryptographic key pairs.
//!
//! The keystore is a shared data structure (i.e. all of its functions accept `&self` rather than
//! `&mut self`, making it possible to share it through an `Arc` for example) containing a list of
//! cryptographic key pairs (i.e. both the public and secret keys).
//!
//! Each key pair contained within the keystore is identified as a `(KeyNamespace, [u8; 32])`
//! tuple, where the `[u8; 32]` is the public key. See [`KeyNamespace`].
//!
//! A keystore is optionally associated with a directory of the file system into which it will
//! store secret keys permanently. Keys present in this directory are considered to be the content
//! of the keystore data structure.
//!
//! For caching reasons, adding and removing keys to the directory manually (for example through
//! the [`std::fs`] API) doesn't automatically propagate to the public API of the keystore.
//! Similarly, it is not intended to be possible to create two [`Keystore`] instances associated
//! to the same directory at the same time.

#![cfg(all(feature = "std"))]
#![cfg_attr(docsrs, doc(cfg(all(feature = "std"))))]

use crate::{identity::seed_phrase, util::SipHasherBuild};

use futures::lock::Mutex;
use rand::{Rng as _, SeedableRng as _};
use std::{borrow::Cow, fs, io, path, str};

/// Namespace of the key.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
// TODO: document
pub enum KeyNamespace {
    Aura,
    AuthorityDiscovery,
    Babe,
    Grandpa,
    ImOnline,
    // TODO: there exists other variants in Substrate but it's unclear whether they're in use (see https://github.com/paritytech/substrate/blob/cafe12e7785bf92e5dc04780c10e7f8330a15a4c/primitives/core/src/crypto.rs)
}

impl KeyNamespace {
    /// Returns all existing variants of [`KeyNamespace`].
    pub fn all() -> impl ExactSizeIterator<Item = KeyNamespace> {
        [
            KeyNamespace::Aura,
            KeyNamespace::AuthorityDiscovery,
            KeyNamespace::Babe,
            KeyNamespace::Grandpa,
            KeyNamespace::ImOnline,
        ]
        .into_iter()
    }

    fn from_string(str: &str) -> Option<Self> {
        match str {
            "aura" => Some(KeyNamespace::Aura),
            "audi" => Some(KeyNamespace::AuthorityDiscovery),
            "babe" => Some(KeyNamespace::Babe),
            "gran" => Some(KeyNamespace::Grandpa),
            "imon" => Some(KeyNamespace::ImOnline),
            _ => None,
        }
    }

    fn as_string(&self) -> &'static str {
        match self {
            KeyNamespace::Aura => "aura",
            KeyNamespace::AuthorityDiscovery => "audi",
            KeyNamespace::Babe => "babe",
            KeyNamespace::Grandpa => "gran",
            KeyNamespace::ImOnline => "imon",
        }
    }
}

/// Collection of key pairs.
///
/// This module doesn't give you access to the content of private keys, only to signing
/// capabilities.
pub struct Keystore {
    keys_directory: Option<path::PathBuf>,
    guarded: Mutex<Guarded>,
}

impl Keystore {
    /// Initializes a new keystore.
    ///
    /// Must be passed bytes of entropy that are used to avoid hash collision attacks and to
    /// generate private keys.
    ///
    /// An error is returned if the `keys_directory` couldn't be opened because, for example, of
    /// some missing permission or because it isn't a directory.
    /// If the `keys_directory` doesn't exist, it will be created using `fs::create_dir_all`.
    pub async fn new(
        keys_directory: Option<path::PathBuf>,
        randomness_seed: [u8; 32],
    ) -> Result<Self, io::Error> {
        let mut gen_rng = rand_chacha::ChaCha20Rng::from_seed(randomness_seed);

        let mut keys = hashbrown::HashMap::with_capacity_and_hasher(32, {
            SipHasherBuild::new(gen_rng.sample(rand::distributions::Standard))
        });

        // Load the keys from the disk.
        // TODO: return some diagnostic about invalid files?
        if let Some(keys_directory) = &keys_directory {
            if !keys_directory.try_exists()? {
                fs::create_dir_all(keys_directory)?;
            }

            for entry in fs::read_dir(keys_directory)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    continue;
                }

                // Try to match the file name.
                let file_name = match entry.file_name().into_string() {
                    Ok(n) => n,
                    Err(_) => continue,
                };

                let mut parser =
                    nom::combinator::all_consuming::<_, _, (&str, nom::error::ErrorKind), _>(
                        nom::combinator::complete(nom::sequence::tuple((
                            nom::combinator::map_opt(
                                nom::bytes::complete::take(4u32),
                                KeyNamespace::from_string,
                            ),
                            nom::bytes::complete::tag("-"),
                            nom::combinator::map_opt(
                                nom::bytes::complete::take(7u32),
                                |b| match b {
                                    "ed25519" => Some(PrivateKey::FileEd25519),
                                    "sr25519" => Some(PrivateKey::FileSr25519),
                                    _ => None,
                                },
                            ),
                            nom::bytes::complete::tag("-"),
                            nom::combinator::map_opt(
                                nom::bytes::complete::take_while(|c| {
                                    (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
                                }),
                                |k: &str| {
                                    if k.len() == 64 {
                                        Some(<[u8; 32]>::try_from(hex::decode(k).unwrap()).unwrap())
                                    } else {
                                        None
                                    }
                                },
                            ),
                        ))),
                    );

                let (namespace, _, algorithm, _, public_key) = match parser(&file_name) {
                    Ok((_, v)) => v,
                    Err(_) => continue,
                };

                // Make sure that the content of the file is valid and that it corresponds to
                // the public key advertised in the file name.
                match algorithm {
                    PrivateKey::FileEd25519 => {
                        match Self::load_ed25519_from_file(keys_directory.join(entry.path())).await
                        {
                            Ok(kp) => {
                                if ed25519_zebra::VerificationKey::from(&kp).as_ref() != public_key
                                {
                                    continue;
                                }
                            }
                            Err(_) => continue,
                        }
                    }
                    PrivateKey::FileSr25519 => {
                        match Self::load_sr25519_from_file(keys_directory.join(entry.path())).await
                        {
                            Ok(kp) => {
                                if kp.public.to_bytes() != public_key {
                                    continue;
                                }
                            }
                            Err(err) => panic!("{:?}", err),
                        }
                    }
                    _ => unreachable!(),
                }

                keys.insert((namespace, public_key), algorithm);
            }
        }

        Ok(Keystore {
            keys_directory,
            guarded: Mutex::new(Guarded { gen_rng, keys }),
        })
    }

    /// Inserts an Sr25519 private key in the keystore.
    ///
    /// Returns the corresponding public key.
    ///
    /// This is meant to be called with publicly-known private keys. Use
    /// [`Keystore::generate_sr25519`] if the private key is meant to actually be private.
    ///
    /// The key is not saved on disk.
    ///
    /// # Panic
    ///
    /// Panics if the key isn't a valid Sr25519 private key. This function is meant to be used
    /// with hard coded values which are known to be correct. Please do not call it with any
    /// sort of user input.
    ///
    pub fn insert_sr25519_memory(
        &mut self,
        namespaces: impl Iterator<Item = KeyNamespace>,
        private_key: &[u8; 64],
    ) -> [u8; 32] {
        let private_key = schnorrkel::SecretKey::from_bytes(&private_key[..]).unwrap();
        let keypair = private_key.to_keypair();
        let public_key = keypair.public.to_bytes();

        for namespace in namespaces {
            self.guarded.get_mut().keys.insert(
                (namespace, public_key),
                PrivateKey::MemorySr25519(keypair.clone()),
            );
        }

        public_key
    }

    /// Generates a new Ed25519 key and inserts it in the keystore.
    ///
    /// If `save` is `true`, the generated key is saved in the file system. This function returns
    /// an error only if `save` is `true` and the key couldn't be written to the file system.
    /// The value of `save` is silently ignored if no path was provided to [`Keystore::new`].
    ///
    /// Returns the corresponding public key.
    pub async fn generate_ed25519(
        &self,
        namespace: KeyNamespace,
        save: bool,
    ) -> Result<[u8; 32], io::Error> {
        let mut guarded = self.guarded.lock().await;

        // Note: it is in principle possible to generate some entropy from the PRNG, then unlock
        // the mutex while the private key is being generated. This reduces the time during which
        // the mutex is locked, but in practice generating a key is a rare enough event that this
        // is not worth the effort.
        let private_key = ed25519_zebra::SigningKey::new(&mut guarded.gen_rng);
        let public_key: [u8; 32] = ed25519_zebra::VerificationKey::from(&private_key).into();

        let save_path = if save {
            self.path_of_key_ed25519(namespace, &public_key)
        } else {
            None
        };

        if let Some(save_path) = save_path {
            Self::write_to_file_ed25519(&save_path, &private_key).await?;
            guarded
                .keys
                .insert((namespace, public_key), PrivateKey::FileEd25519);
        } else {
            guarded.keys.insert(
                (namespace, public_key),
                PrivateKey::MemoryEd25519(private_key),
            );
        }

        Ok(public_key)
    }

    /// Returns the list of all keys known to this keystore.
    ///
    /// > **Note**: Keep in mind that this function is racy, as keys can be added and removed
    /// >           in parallel of this function being called.
    pub async fn keys(&self) -> impl Iterator<Item = (KeyNamespace, [u8; 32])> {
        let guarded = self.guarded.lock().await;
        guarded.keys.keys().cloned().collect::<Vec<_>>().into_iter()
    }

    /// Generates a new Sr25519 key and inserts it in the keystore.
    ///
    /// If `save` is `true`, the generated key is saved in the file system. This function returns
    /// an error only if `save` is `true` and the key couldn't be written to the file system.
    /// The value of `save` is silently ignored if no path was provided to [`Keystore::new`].
    ///
    /// Returns the corresponding public key.
    pub async fn generate_sr25519(
        &self,
        namespace: KeyNamespace,
        save: bool,
    ) -> Result<[u8; 32], io::Error> {
        let mut guarded = self.guarded.lock().await;

        // Note: it is in principle possible to generate some entropy from the PRNG, then unlock
        // the mutex while the private key is being generated. This reduces the time during which
        // the mutex is locked, but in practice generating a key is a rare enough event that this
        // is not worth the effort.
        let mini_secret = schnorrkel::MiniSecretKey::generate_with(&mut guarded.gen_rng);
        let keypair = mini_secret.expand_to_keypair(schnorrkel::ExpansionMode::Ed25519);
        let public_key = keypair.public.to_bytes();

        let save_path = if save {
            self.path_of_key_sr25519(namespace, &public_key)
        } else {
            None
        };

        if let Some(save_path) = save_path {
            Self::write_to_file_sr25519(&save_path, &mini_secret).await?;
            guarded
                .keys
                .insert((namespace, public_key), PrivateKey::FileSr25519);
        } else {
            guarded
                .keys
                .insert((namespace, public_key), PrivateKey::MemorySr25519(keypair));
        }

        Ok(public_key)
    }

    /// Signs the given payload using the private key associated to the public key passed as
    /// parameter.
    ///
    /// An error is returned if the key-namespace combination is not in the keystore, or if the
    /// key couldn't be loaded from disk. In the case when a key couldn't be loaded from disk, it
    /// is automatically removed from the keystore.
    pub async fn sign(
        &self,
        key_namespace: KeyNamespace,
        public_key: &[u8; 32],
        payload: &[u8],
    ) -> Result<[u8; 64], SignError> {
        let mut guarded = self.guarded.lock().await;
        let key = guarded
            .keys
            .get(&(key_namespace, *public_key))
            .ok_or(SignError::UnknownPublicKey)?;

        match key {
            PrivateKey::MemoryEd25519(key) => Ok(key.sign(payload).into()),
            PrivateKey::FileEd25519 => {
                match Self::load_ed25519_from_file(
                    self.path_of_key_ed25519(key_namespace, public_key).unwrap(),
                )
                .await
                {
                    Ok(key) => {
                        drop(guarded);
                        Ok(key.sign(payload).into())
                    }
                    Err(err) => {
                        guarded.keys.remove(&(key_namespace, *public_key));
                        return Err(err.into());
                    }
                }
            }
            PrivateKey::MemorySr25519(key) => {
                // TODO: is creating the signing context expensive?
                let context = schnorrkel::signing_context(b"substrate");
                Ok(key.sign(context.bytes(payload)).to_bytes())
            }
            PrivateKey::FileSr25519 => {
                match Self::load_sr25519_from_file(
                    self.path_of_key_sr25519(key_namespace, public_key).unwrap(),
                )
                .await
                {
                    Ok(key) => {
                        drop(guarded);
                        // TODO: is creating the signing context expensive?
                        let context = schnorrkel::signing_context(b"substrate");
                        Ok(key.sign(context.bytes(payload)).to_bytes())
                    }
                    Err(err) => {
                        guarded.keys.remove(&(key_namespace, *public_key));
                        return Err(err.into());
                    }
                }
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
            let mut guarded = self.guarded.lock().await;
            let key = guarded
                .keys
                .get(&(key_namespace, *public_key))
                .ok_or(SignVrfError::Sign(SignError::UnknownPublicKey))?;

            match key {
                PrivateKey::MemoryEd25519(_) | PrivateKey::FileEd25519 => {
                    Err(SignVrfError::WrongKeyAlgorithm)
                }
                PrivateKey::MemorySr25519(_) | PrivateKey::FileSr25519 => {
                    let key = match key {
                        PrivateKey::MemorySr25519(key) => Cow::Borrowed(key),
                        PrivateKey::FileSr25519 => {
                            match Self::load_sr25519_from_file(
                                self.path_of_key_sr25519(key_namespace, public_key).unwrap(),
                            )
                            .await
                            {
                                Ok(key) => {
                                    drop(guarded);
                                    // TODO: is creating the signing context expensive?
                                    Cow::Owned(key)
                                }
                                Err(err) => {
                                    guarded.keys.remove(&(key_namespace, *public_key));
                                    return Err(err.into());
                                }
                            }
                        }
                        _ => unreachable!(),
                    };

                    let mut transcript = merlin::Transcript::new(label);
                    for (label, value) in transcript_items {
                        match value {
                            either::Left(bytes) => {
                                transcript.append_message(label, bytes);
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

    async fn load_ed25519_from_file(
        path: impl AsRef<path::Path>,
    ) -> Result<ed25519_zebra::SigningKey, KeyLoadError> {
        // TODO: read asynchronously?
        let bytes = fs::read(path).map_err(KeyLoadError::Io)?;
        let phrase =
            str::from_utf8(&bytes).map_err(|err| KeyLoadError::BadFormat(err.to_string()))?;
        let private_key = seed_phrase::decode_ed25519_private_key(phrase)
            .map_err(|err| KeyLoadError::BadFormat(err.to_string()))?;
        // TODO: zero memory of the private key on drop ^
        Ok(ed25519_zebra::SigningKey::from(private_key))
    }

    async fn load_sr25519_from_file(
        path: impl AsRef<path::Path>,
    ) -> Result<schnorrkel::Keypair, KeyLoadError> {
        // TODO: read asynchronously?
        let bytes = fs::read(path).map_err(KeyLoadError::Io)?;
        let phrase =
            str::from_utf8(&bytes).map_err(|err| KeyLoadError::BadFormat(err.to_string()))?;
        let private_key = seed_phrase::decode_sr25519_private_key(phrase)
            .map_err(|err| KeyLoadError::BadFormat(err.to_string()))?;
        // TODO: zero memory of the private key on drop ^
        // `from_bytes` only panics if the key is of the wrong length, which we know can't
        // happen here.
        Ok(schnorrkel::SecretKey::from_bytes(&private_key)
            .unwrap()
            .into())
    }

    async fn write_to_file_ed25519(
        path: impl AsRef<path::Path>,
        key: &ed25519_zebra::SigningKey,
    ) -> Result<(), io::Error> {
        let phrase = hex::encode(key.as_ref());
        Self::write_to_file(path, &phrase).await
    }

    async fn write_to_file_sr25519(
        path: impl AsRef<path::Path>,
        key: &schnorrkel::MiniSecretKey,
    ) -> Result<(), io::Error> {
        let phrase = hex::encode(key.to_bytes());
        Self::write_to_file(path, &phrase).await
    }

    async fn write_to_file(
        path: impl AsRef<path::Path>,
        key_phrase: &str,
    ) -> Result<(), io::Error> {
        let mut file = fs::File::create(path)?;
        // TODO: proper security flags on Windows?
        #[cfg(target_family = "unix")]
        file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o400))?;
        io::Write::write_all(&mut file, b"0x")?;
        io::Write::write_all(&mut file, key_phrase.as_bytes())?;
        io::Write::flush(&mut file)?; // This call is generally useless, but doesn't hurt.
        file.sync_all()?;
        Ok(())
    }

    fn path_of_key_ed25519(
        &self,
        key_namespace: KeyNamespace,
        public_key: &[u8; 32],
    ) -> Option<path::PathBuf> {
        self.path_of_key(key_namespace, "ed25519", public_key)
    }

    fn path_of_key_sr25519(
        &self,
        key_namespace: KeyNamespace,
        public_key: &[u8; 32],
    ) -> Option<path::PathBuf> {
        self.path_of_key(key_namespace, "sr25519", public_key)
    }

    fn path_of_key(
        &self,
        key_namespace: KeyNamespace,
        key_algorithm: &str,
        public_key: &[u8; 32],
    ) -> Option<path::PathBuf> {
        let keys_directory = match &self.keys_directory {
            Some(k) => k,
            None => return None,
        };

        // We don't use the same pathing scheme as Substrate, for two reasons:
        // - The fact that Substrate hex-encodes the namespace is completely unnecessary and
        // confusing.
        // - Substrate doesn't indicate whether the key is ed25519 or sr25519, because the
        // algorithm to use is provided when signing or verifying. This is weird and in my opinion
        // not a good practice.

        let mut file_name = String::with_capacity(256); // 256 is more than enough.
        file_name.push_str(key_namespace.as_string());
        file_name.push('-');
        file_name.push_str(key_algorithm);
        file_name.push('-');
        file_name.push_str(&hex::encode(public_key));

        let mut path =
            path::PathBuf::with_capacity(keys_directory.as_os_str().len() + file_name.len() + 16);
        path.push(&keys_directory);
        path.push(file_name);
        Some(path)
    }
}

struct Guarded {
    gen_rng: rand_chacha::ChaCha20Rng,
    keys: hashbrown::HashMap<(KeyNamespace, [u8; 32]), PrivateKey, SipHasherBuild>,
}

pub struct VrfSignature {
    pub proof: [u8; 64],
}

#[derive(Debug, derive_more::Display)]
pub enum SignError {
    /// The given `(namespace, public key)` combination is unknown to this keystore.
    UnknownPublicKey,

    /// Error while accessing the file containing the secret key.
    /// Typically indicates the content of the file has been modified by something else than
    /// the keystore.
    #[display(fmt = "Error loading the secret key; {}", _0)]
    KeyLoad(KeyLoadError),
}

#[derive(Debug, derive_more::Display)]
pub enum KeyLoadError {
    /// Error reported by the operating system.
    #[display(fmt = "{}", _0)]
    Io(io::Error),
    /// Content of the file is invalid. Contains a human-readable error message as a string.
    /// Because the format of the content of the file is an implementation detail, no detail is
    /// provided.
    #[display(fmt = "{}", _0)]
    BadFormat(String),
}

#[derive(Debug, derive_more::Display)]
pub enum SignVrfError {
    #[display(fmt = "{}", _0)]
    Sign(SignError),
    WrongKeyAlgorithm,
}

enum PrivateKey {
    MemoryEd25519(ed25519_zebra::SigningKey),
    MemorySr25519(schnorrkel::Keypair),
    FileEd25519,
    FileSr25519,
}

impl From<KeyLoadError> for SignError {
    fn from(err: KeyLoadError) -> SignError {
        SignError::KeyLoad(err)
    }
}

impl From<KeyLoadError> for SignVrfError {
    fn from(err: KeyLoadError) -> SignVrfError {
        SignVrfError::Sign(SignError::KeyLoad(err))
    }
}

#[cfg(test)]
mod tests {
    use super::{KeyNamespace, Keystore};

    #[test]
    fn disk_storage_works_ed25519() {
        futures::executor::block_on(async move {
            let path = tempfile::tempdir().unwrap();

            let keystore1 = Keystore::new(Some(path.path().to_owned()), rand::random())
                .await
                .unwrap();
            let public_key = keystore1
                .generate_ed25519(KeyNamespace::Babe, true)
                .await
                .unwrap();
            drop(keystore1);

            let keystore2 = Keystore::new(Some(path.path().to_owned()), rand::random())
                .await
                .unwrap();
            assert_eq!(
                keystore2.keys().await.next(),
                Some((KeyNamespace::Babe, public_key))
            );

            let signature = keystore2
                .sign(KeyNamespace::Babe, &public_key, b"hello world")
                .await
                .unwrap();

            assert!(ed25519_zebra::VerificationKey::try_from(public_key)
                .unwrap()
                .verify(&ed25519_zebra::Signature::from(signature), b"hello world")
                .is_ok());
        });
    }

    #[test]
    fn disk_storage_works_sr25519() {
        futures::executor::block_on(async move {
            let path = tempfile::tempdir().unwrap();

            let keystore1 = Keystore::new(Some(path.path().to_owned()), rand::random())
                .await
                .unwrap();
            let public_key = keystore1
                .generate_sr25519(KeyNamespace::Aura, true)
                .await
                .unwrap();
            drop(keystore1);

            let keystore2 = Keystore::new(Some(path.path().to_owned()), rand::random())
                .await
                .unwrap();
            assert_eq!(
                keystore2.keys().await.next(),
                Some((KeyNamespace::Aura, public_key))
            );

            let signature = keystore2
                .sign(KeyNamespace::Aura, &public_key, b"hello world")
                .await
                .unwrap();

            assert!(schnorrkel::PublicKey::from_bytes(&public_key)
                .unwrap()
                .verify_simple(
                    b"substrate",
                    b"hello world",
                    &schnorrkel::Signature::from_bytes(&signature).unwrap()
                )
                .is_ok());
        });
    }
}
