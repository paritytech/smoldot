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

//! Runtime call to obtain the transactions validity status.

use crate::{
    executor::{self, host, runtime_host},
    header, util,
};

use alloc::{borrow::ToOwned as _, collections::BTreeMap, vec::Vec};
use core::{iter, num::NonZeroU64};

/// Configuration for a transaction validation process.
pub struct Config<'a, TTx> {
    /// Runtime used to get the validate the transaction. Must be built using the Wasm code found
    /// at the `:code` key of the block storage.
    pub runtime: host::HostVmPrototype,

    /// Header of the block to verify the transaction against, in SCALE encoding.
    /// The runtime of this block must be the one in [`Config::runtime`].
    pub scale_encoded_header: &'a [u8],

    /// SCALE-encoded transaction.
    pub scale_encoded_transaction: TTx,

    /// Source of the transaction.
    ///
    /// This information is passed to the runtime, which might perform some additional
    /// verifications if the source isn't trusted.
    pub source: TransactionSource,
}

/// Source of the transaction.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TransactionSource {
    /// Transaction is already included in a block.
    ///
    /// It isn't possible to tell where the transaction is coming from, since it's already in a
    /// received block.
    InBlock,

    /// Transaction is coming from a local source.
    ///
    /// The transaction was produced internally by the node (for instance an off-chain worker).
    /// This transaction therefore has a higher level of trust compared to the other variants.
    Local,

    /// Transaction has been received externally.
    ///
    /// The transaction has been received from an "untrusted" source, such as the network or the
    /// JSON-RPC server.
    External,
}

/// Information concerning a valid transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidTransaction {
    /// Priority of the transaction.
    ///
    /// Priority determines the ordering of two transactions that have all
    /// [their required tags](ValidTransaction::requires) satisfied. Transactions with a higher
    /// priority should be included first.
    pub priority: u64,

    /// Transaction dependencies.
    ///
    /// Contains a list of so-called *tags*. The actual bytes of the tags can be compared in order
    /// to determine whether two tags are equal, but aren't meaningful from the client
    /// perspective.
    ///
    /// A non-empty list signifies that this transaction can't be included before some other
    /// transactions which [provide](ValidTransaction::provides) the given tags. *All* the tags
    /// must be fulfilled before the transaction can be included.
    // TODO: better type than `Vec<Vec<u8>>`? I feel like this could be a single `Vec<u8>` that is decoded on the fly?
    pub requires: Vec<Vec<u8>>,

    /// Tags provided by the transaction.
    ///
    /// The bytes of the tags aren't meaningful from the client's perspective, but are used to
    /// enforce an ordering between transactions. See [`ValidTransaction::requires`].
    ///
    /// Two transactions that have a provided tag in common are mutually exclusive, and cannot be
    /// both included in the same chain of blocks.
    ///
    /// Guaranteed to never be empty.
    // TODO: better type than `Vec<Vec<u8>>`? I feel like this could be a single `Vec<u8>` that is decoded on the fly?
    pub provides: Vec<Vec<u8>>,

    /// Transaction longevity.
    ///
    /// This value provides a hint of the number of blocks during which the client can assume the
    /// transaction to be valid. This is provided for optimization purposes, to save the client
    /// from re-validating every pending transaction at each new block. It is only a hint, and the
    /// transaction might become invalid sooner.
    ///
    /// After this period, transaction should be removed from the pool or revalidated.
    ///
    /// > **Note**: Many transactions are "mortal", meaning that they automatically become invalid
    /// >           after a certain number of blocks. In that case, the longevity returned by the
    /// >           validation function will be at most this number of blocks. The concept of
    /// >           mortal transactions, however, is not relevant from the client's perspective.
    pub longevity: NonZeroU64,

    /// A flag indicating whether the transaction should be propagated to other peers.
    ///
    /// If `false`, the transaction will still be considered for inclusion in blocks that are
    /// authored locally, but will not be sent to the rest of the network.
    ///
    /// > **Note**: A value of `false` is typically returned for transctions that are very heavy.
    pub propagate: bool,
}

/// An invalid transaction validity.
#[derive(Debug, derive_more::Display, Clone, PartialEq, Eq)]
pub enum InvalidTransaction {
    /// The call of the transaction is not expected.
    Call,
    /// General error to do with the inability to pay some fees (e.g. account balance too low).
    Payment,
    /// General error to do with the transaction not yet being valid (e.g. nonce too high).
    Future,
    /// General error to do with the transaction being outdated (e.g. nonce too low).
    Stale,
    /// General error to do with the transaction's proofs (e.g. signature).
    ///
    /// # Possible causes
    ///
    /// When using a signed extension that provides additional data for signing, it is required
    /// that the signing and the verifying side use the same additional data. Additional
    /// data will only be used to generate the signature, but will not be part of the transaction
    /// itself. As the verifying side does not know which additional data was used while signing
    /// it will only be able to assume a bad signature and cannot express a more meaningful error.
    BadProof,
    /// The transaction birth block is ancient.
    AncientBirthBlock,
    /// The transaction would exhaust the resources of current block.
    ///
    /// The transaction might be valid, but there are not enough resources
    /// left in the current block.
    ExhaustsResources,
    /// Any other custom invalid validity that is not covered by this enum.
    Custom(u8),
    /// An extrinsic with a Mandatory dispatch resulted in Error. This is indicative of either a
    /// malicious validator or a buggy `provide_inherent`. In any case, it can result in dangerously
    /// overweight blocks and therefore if found, invalidates the block.
    BadMandatory,
    /// A transaction with a mandatory dispatch. This is invalid; only inherent extrinsics are
    /// allowed to have mandatory dispatches.
    MandatoryDispatch,
}

/// An unknown transaction validity.
#[derive(Debug, derive_more::Display, Clone, PartialEq, Eq)]
pub enum UnknownTransaction {
    /// Could not lookup some information that is required to validate the transaction.
    CannotLookup,
    /// No validator found for the given unsigned transaction.
    NoUnsignedValidator,
    /// Any other custom unknown validity that is not covered by this enum.
    Custom(u8),
}

/// Problem encountered during a call to [`validate_transaction`].
#[derive(Debug, derive_more::Display)]
pub enum Error {
    /// Error while decoding the block header against which to make the call.
    InvalidHeader(header::Error),
    /// Failed to determine the runtime version of the runtime.
    RuntimeVersion(executor::CoreVersionError),
    /// Transaction validation API version unrecognized.
    UnknownApiVersion,
    /// Error while starting the Wasm virtual machine.
    #[display(fmt = "{}", _0)]
    WasmStart(host::StartErr),
    /// Error while running the Wasm virtual machine.
    #[display(fmt = "{}", _0)]
    WasmVmReadWrite(runtime_host::ErrorDetail),
    /// Error while running the Wasm virtual machine.
    #[display(fmt = "{}", _0)]
    WasmVmReadOnly(runtime_host::ErrorDetail),
    /// Error while decoding the output of the runtime.
    OutputDecodeError(DecodeError),
    /// The list of provided tags ([`ValidTransaction::provides`]). This is a bug in the runtime.
    EmptyProvidedTags,
}

/// Error that can happen during the decoding.
#[derive(Debug, derive_more::Display)]
pub struct DecodeError();

/// Errors that can occur while checking the validity of a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionValidityError {
    /// The transaction is invalid.
    Invalid(InvalidTransaction),
    /// Transaction validity can't be determined.
    Unknown(UnknownTransaction),
}

/// Produces the input to pass to the `TaggedTransactionQueue_validate_transaction` runtime call.
pub fn validate_transaction_runtime_parameters_v2<'a>(
    scale_encoded_transaction: impl Iterator<Item = impl AsRef<[u8]> + 'a> + Clone + 'a,
    source: TransactionSource,
) -> impl Iterator<Item = impl AsRef<[u8]> + 'a> + Clone + 'a {
    validate_transaction_runtime_parameters_inner(scale_encoded_transaction, source, &[])
}

/// Produces the input to pass to the `TaggedTransactionQueue_validate_transaction` runtime call.
pub fn validate_transaction_runtime_parameters_v3<'a>(
    scale_encoded_transaction: impl Iterator<Item = impl AsRef<[u8]> + 'a> + Clone + 'a,
    source: TransactionSource,
    block_hash: &'a [u8; 32],
) -> impl Iterator<Item = impl AsRef<[u8]> + 'a> + Clone + 'a {
    validate_transaction_runtime_parameters_inner(scale_encoded_transaction, source, block_hash)
}

fn validate_transaction_runtime_parameters_inner<'a>(
    scale_encoded_transaction: impl Iterator<Item = impl AsRef<[u8]> + 'a> + Clone + 'a,
    source: TransactionSource,
    block_hash: &'a [u8],
) -> impl Iterator<Item = impl AsRef<[u8]> + 'a> + Clone + 'a {
    // The `TaggedTransactionQueue_validate_transaction` function expects a SCALE-encoded
    // `(source, tx)`. The encoding is performed manually in order to avoid performing
    // redundant data copies.
    let source = match source {
        TransactionSource::InBlock => &[0],
        TransactionSource::Local => &[1],
        TransactionSource::External => &[2],
    };

    iter::once(source)
        .map(either::Left)
        .chain(
            scale_encoded_transaction
                .map(either::Right)
                .map(either::Right),
        )
        .chain(iter::once(block_hash).map(either::Left).map(either::Right))
}

/// Name of the runtime function to call in order to validate a transaction.
pub const VALIDATION_FUNCTION_NAME: &str = "TaggedTransactionQueue_validate_transaction";

/// Attempt to decode the return value of the  `TaggedTransactionQueue_validate_transaction`
/// runtime call.
pub fn decode_validate_transaction_return_value(
    scale_encoded: &[u8],
) -> Result<Result<ValidTransaction, TransactionValidityError>, DecodeError> {
    match nom::combinator::all_consuming(transaction_validity)(scale_encoded) {
        Ok((_, data)) => Ok(data),
        Err(_) => Err(DecodeError()),
    }
}

/// Validates a transaction by calling `TaggedTransactionQueue_validate_transaction`.
pub fn validate_transaction(
    config: Config<impl ExactSizeIterator<Item = impl AsRef<[u8]> + Clone> + Clone>,
) -> Query {
    // The parameters of the function, and whether to call `Core_initialize_block` beforehand,
    // depend on the API version.
    // TODO: should the runtime spec be cached into the `HostVmPrototype`?
    let (api_version, virtual_machine) = match executor::core_version(config.runtime) {
        (Ok(runtime_spec), runtime) => {
            let expected = blake2_rfc::blake2b::blake2b(8, &[], b"TaggedTransactionQueue");
            let version = runtime_spec
                .decode()
                .apis
                .find(|api| api.name_hash == expected.as_ref())
                .map(|api| api.version);
            (version, runtime)
        }
        (Err(err), virtual_machine) => {
            return Query::Finished {
                result: Err(Error::RuntimeVersion(err)),
                virtual_machine,
            }
        }
    };

    match api_version {
        Some(2) => {
            // In version 2, we need to call `Core_initialize_block` beforehand.

            // The `Core_initialize_block` function called below expects a partially-initialized
            // SCALE-encoded header. Importantly, passing the entire header will lead to different code
            // paths in the runtime and not match what Substrate does.
            let decoded_header = match header::decode(config.scale_encoded_header) {
                Ok(h) => h,
                Err(err) => {
                    return Query::Finished {
                        result: Err(Error::InvalidHeader(err)),
                        virtual_machine,
                    }
                }
            };

            // Start the call to `Core_initialize_block`.
            let vm = runtime_host::run(runtime_host::Config {
                virtual_machine,
                function_to_call: "Core_initialize_block",
                parameter: header::HeaderRef {
                    parent_hash: &decoded_header.hash(),
                    number: decoded_header.number + 1,
                    extrinsics_root: &[0; 32],
                    state_root: &[0; 32],
                    digest: header::DigestRef::empty(),
                }
                .scale_encoding(),
                top_trie_root_calculation_cache: None,
                storage_top_trie_changes: BTreeMap::new(),
                offchain_storage_changes: hashbrown::HashMap::default(),
            });

            // Information used later, after `Core_initialize_block` is done.
            let stage1 = Stage1 {
                transaction_source: config.source,
                scale_encoded_transaction: config.scale_encoded_transaction.fold(
                    Vec::new(),
                    |mut a, b| {
                        a.extend_from_slice(b.as_ref());
                        a
                    },
                ),
            };

            match vm {
                Ok(vm) => Query::from_step1(vm, stage1),
                Err((err, virtual_machine)) => Query::Finished {
                    result: Err(Error::WasmStart(err)),
                    virtual_machine,
                },
            }
        }
        Some(3) => {
            // In version 3, we don't need to call `Core_initialize_block`.

            let vm = runtime_host::run(runtime_host::Config {
                virtual_machine,
                function_to_call: VALIDATION_FUNCTION_NAME,
                parameter: validate_transaction_runtime_parameters_v3(
                    config.scale_encoded_transaction,
                    config.source,
                    &header::hash_from_scale_encoded_header(config.scale_encoded_header),
                ),
                top_trie_root_calculation_cache: None,
                storage_top_trie_changes: BTreeMap::default(),
                offchain_storage_changes: hashbrown::HashMap::default(),
            });

            match vm {
                Ok(vm) => Query::from_step2(vm, Stage2 {}),
                Err((err, virtual_machine)) => Query::Finished {
                    result: Err(Error::WasmStart(err)),
                    virtual_machine,
                },
            }
        }
        _ => Query::Finished {
            result: Err(Error::UnknownApiVersion),
            virtual_machine,
        },
    }
}

/// Current state of the operation.
#[must_use]
pub enum Query {
    /// Validating the transaction is over.
    Finished {
        /// Outcome of the verification.
        ///
        /// The outer `Result` contains an error if the runtime call has failed, while the inner
        /// `Result` contains an error if the transaction is invalid.
        result: Result<Result<ValidTransaction, TransactionValidityError>, Error>,
        /// Virtual machine initially passed through the configuration.
        virtual_machine: host::HostVmPrototype,
    },
    /// Loading a storage value is required in order to continue.
    StorageGet(StorageGet),
    /// Fetching the key that follows a given one is required in order to continue.
    NextKey(NextKey),
    /// Fetching the list of keys with a given prefix from the storage is required in order to
    /// continue.
    PrefixKeys(PrefixKeys),
}

impl Query {
    /// Cancels execution of the virtual machine and returns back the prototype.
    pub fn into_prototype(self) -> host::HostVmPrototype {
        match self {
            Query::Finished {
                virtual_machine, ..
            } => virtual_machine,
            Query::StorageGet(StorageGet(StorageGetInner::Stage1(inner, _))) => {
                runtime_host::RuntimeHostVm::StorageGet(inner).into_prototype()
            }
            Query::StorageGet(StorageGet(StorageGetInner::Stage2(inner, _))) => {
                runtime_host::RuntimeHostVm::StorageGet(inner).into_prototype()
            }
            Query::NextKey(NextKey(NextKeyInner::Stage1(inner, _))) => {
                runtime_host::RuntimeHostVm::NextKey(inner).into_prototype()
            }
            Query::NextKey(NextKey(NextKeyInner::Stage2(inner, _))) => {
                runtime_host::RuntimeHostVm::NextKey(inner).into_prototype()
            }
            Query::PrefixKeys(PrefixKeys(PrefixKeysInner::Stage1(inner, _))) => {
                runtime_host::RuntimeHostVm::PrefixKeys(inner).into_prototype()
            }
            Query::PrefixKeys(PrefixKeys(PrefixKeysInner::Stage2(inner, _))) => {
                runtime_host::RuntimeHostVm::PrefixKeys(inner).into_prototype()
            }
        }
    }

    fn from_step1(inner: runtime_host::RuntimeHostVm, info: Stage1) -> Self {
        match inner {
            runtime_host::RuntimeHostVm::Finished(Ok(success)) => {
                // No output expected from `Core_initialize_block`.
                if !success.virtual_machine.value().as_ref().is_empty() {
                    return Query::Finished {
                        result: Err(Error::OutputDecodeError(DecodeError())),
                        virtual_machine: success.virtual_machine.into_prototype(),
                    };
                }

                let vm = runtime_host::run(runtime_host::Config {
                    virtual_machine: success.virtual_machine.into_prototype(),
                    function_to_call: VALIDATION_FUNCTION_NAME,
                    parameter: validate_transaction_runtime_parameters_v2(
                        iter::once(info.scale_encoded_transaction),
                        info.transaction_source,
                    ),
                    storage_top_trie_changes: success.storage_top_trie_changes,
                    offchain_storage_changes: success.offchain_storage_changes,
                    top_trie_root_calculation_cache: Some(success.top_trie_root_calculation_cache),
                });

                match vm {
                    Ok(vm) => Query::from_step2(vm, Stage2 {}),
                    Err((err, virtual_machine)) => Query::Finished {
                        result: Err(Error::WasmStart(err)),
                        virtual_machine,
                    },
                }
            }
            runtime_host::RuntimeHostVm::Finished(Err(err)) => Query::Finished {
                result: Err(Error::WasmVmReadWrite(err.detail)),
                virtual_machine: err.prototype,
            },
            runtime_host::RuntimeHostVm::StorageGet(i) => {
                Query::StorageGet(StorageGet(StorageGetInner::Stage1(i, info)))
            }
            runtime_host::RuntimeHostVm::PrefixKeys(i) => {
                Query::PrefixKeys(PrefixKeys(PrefixKeysInner::Stage1(i, info)))
            }
            runtime_host::RuntimeHostVm::NextKey(inner) => {
                Query::NextKey(NextKey(NextKeyInner::Stage1(inner, info)))
            }
        }
    }

    fn from_step2(inner: runtime_host::RuntimeHostVm, info: Stage2) -> Self {
        match inner {
            runtime_host::RuntimeHostVm::Finished(Ok(success)) => {
                // This decoding is done in multiple steps in order to solve borrow checking
                // errors.
                let result = {
                    let output = success.virtual_machine.value();
                    decode_validate_transaction_return_value(output.as_ref())
                        .map_err(Error::OutputDecodeError)
                };

                let result = match result {
                    Ok(res) => {
                        if let Ok(res) = res.as_ref() {
                            if res.provides.is_empty() {
                                return Query::Finished {
                                    result: Err(Error::EmptyProvidedTags),
                                    virtual_machine: success.virtual_machine.into_prototype(),
                                };
                            }
                        }
                        res
                    }
                    Err(err) => {
                        return Query::Finished {
                            result: Err(err),
                            virtual_machine: success.virtual_machine.into_prototype(),
                        }
                    }
                };

                Query::Finished {
                    result: Ok(result),
                    virtual_machine: success.virtual_machine.into_prototype(),
                }
            }
            runtime_host::RuntimeHostVm::Finished(Err(err)) => Query::Finished {
                result: Err(Error::WasmVmReadOnly(err.detail)),
                virtual_machine: err.prototype,
            },
            runtime_host::RuntimeHostVm::StorageGet(i) => {
                Query::StorageGet(StorageGet(StorageGetInner::Stage2(i, info)))
            }
            runtime_host::RuntimeHostVm::PrefixKeys(i) => {
                Query::PrefixKeys(PrefixKeys(PrefixKeysInner::Stage2(i, info)))
            }
            runtime_host::RuntimeHostVm::NextKey(inner) => {
                Query::NextKey(NextKey(NextKeyInner::Stage2(inner, info)))
            }
        }
    }
}

struct Stage1 {
    /// Same value as [`Config::source`].
    transaction_source: TransactionSource,
    /// Same value as [`Config::scale_encoded_transaction`].
    scale_encoded_transaction: Vec<u8>,
}

struct Stage2 {}

/// Loading a storage value is required in order to continue.
#[must_use]
pub struct StorageGet(StorageGetInner);

enum StorageGetInner {
    Stage1(runtime_host::StorageGet, Stage1),
    Stage2(runtime_host::StorageGet, Stage2),
}

impl StorageGet {
    /// Returns the key whose value must be passed to [`StorageGet::inject_value`].
    pub fn key(&'_ self) -> impl Iterator<Item = impl AsRef<[u8]> + '_> + '_ {
        match &self.0 {
            StorageGetInner::Stage1(inner, _) => either::Left(inner.key().map(either::Left)),
            StorageGetInner::Stage2(inner, _) => either::Right(inner.key().map(either::Right)),
        }
    }

    /// Returns the key whose value must be passed to [`StorageGet::inject_value`].
    ///
    /// This method is a shortcut for calling `key` and concatenating the returned slices.
    pub fn key_as_vec(&self) -> Vec<u8> {
        match &self.0 {
            StorageGetInner::Stage1(inner, _) => inner.key_as_vec(),
            StorageGetInner::Stage2(inner, _) => inner.key_as_vec(),
        }
    }

    /// Injects the corresponding storage value.
    pub fn inject_value(self, value: Option<impl Iterator<Item = impl AsRef<[u8]>>>) -> Query {
        match self.0 {
            StorageGetInner::Stage1(inner, stage) => {
                Query::from_step1(inner.inject_value(value), stage)
            }
            StorageGetInner::Stage2(inner, stage) => {
                Query::from_step2(inner.inject_value(value), stage)
            }
        }
    }
}

/// Fetching the key that follows a given one is required in order to continue.
#[must_use]
pub struct NextKey(NextKeyInner);

enum NextKeyInner {
    Stage1(runtime_host::NextKey, Stage1),
    Stage2(runtime_host::NextKey, Stage2),
}

impl NextKey {
    /// Returns the key whose next key must be passed back.
    pub fn key(&'_ self) -> impl AsRef<[u8]> + '_ {
        match &self.0 {
            NextKeyInner::Stage1(inner, _) => either::Left(inner.key()),
            NextKeyInner::Stage2(inner, _) => either::Right(inner.key()),
        }
    }

    /// Injects the key.
    ///
    /// # Panic
    ///
    /// Panics if the key passed as parameter isn't strictly superior to the requested key.
    ///
    pub fn inject_key(self, key: Option<impl AsRef<[u8]>>) -> Query {
        match self.0 {
            NextKeyInner::Stage1(inner, stage1) => Query::from_step1(inner.inject_key(key), stage1),
            NextKeyInner::Stage2(inner, stage2) => Query::from_step2(inner.inject_key(key), stage2),
        }
    }
}

/// Fetching the list of keys with a given prefix from the parent storage is required in order to
/// continue.
#[must_use]
pub struct PrefixKeys(PrefixKeysInner);

enum PrefixKeysInner {
    Stage1(runtime_host::PrefixKeys, Stage1),
    Stage2(runtime_host::PrefixKeys, Stage2),
}

impl PrefixKeys {
    /// Returns the prefix whose keys to load.
    pub fn prefix(&'_ self) -> impl AsRef<[u8]> + '_ {
        match &self.0 {
            PrefixKeysInner::Stage1(inner, _) => either::Left(inner.prefix()),
            PrefixKeysInner::Stage2(inner, _) => either::Right(inner.prefix()),
        }
    }

    /// Injects the list of keys ordered lexicographically.
    pub fn inject_keys_ordered(self, keys: impl Iterator<Item = impl AsRef<[u8]>>) -> Query {
        match self.0 {
            PrefixKeysInner::Stage1(inner, stage1) => {
                Query::from_step1(inner.inject_keys_ordered(keys), stage1)
            }
            PrefixKeysInner::Stage2(inner, stage2) => {
                Query::from_step2(inner.inject_keys_ordered(keys), stage2)
            }
        }
    }
}

// `nom` parser functions can be found below.

fn transaction_validity(
    bytes: &[u8],
) -> nom::IResult<&[u8], Result<ValidTransaction, TransactionValidityError>> {
    nom::error::context(
        "transaction validity",
        nom::branch::alt((
            nom::combinator::map(
                nom::sequence::preceded(nom::bytes::complete::tag(&[0]), valid_transaction),
                Ok,
            ),
            nom::combinator::map(
                nom::sequence::preceded(
                    nom::bytes::complete::tag(&[1]),
                    transaction_validity_error,
                ),
                Err,
            ),
        )),
    )(bytes)
}

fn valid_transaction(bytes: &[u8]) -> nom::IResult<&[u8], ValidTransaction> {
    nom::error::context(
        "valid transaction",
        nom::combinator::map(
            nom::sequence::tuple((
                nom::number::complete::le_u64,
                tags,
                tags,
                nom::combinator::map_opt(nom::number::complete::le_u64, NonZeroU64::new),
                util::nom_bool_decode,
            )),
            |(priority, requires, provides, longevity, propagate)| ValidTransaction {
                priority,
                requires,
                provides,
                longevity,
                propagate,
            },
        ),
    )(bytes)
}

fn transaction_validity_error(bytes: &[u8]) -> nom::IResult<&[u8], TransactionValidityError> {
    nom::error::context(
        "transaction validity error",
        nom::branch::alt((
            nom::combinator::map(
                nom::sequence::preceded(nom::bytes::complete::tag(&[0]), invalid_transaction),
                TransactionValidityError::Invalid,
            ),
            nom::combinator::map(
                nom::sequence::preceded(nom::bytes::complete::tag(&[1]), unknown_transaction),
                TransactionValidityError::Unknown,
            ),
        )),
    )(bytes)
}

fn invalid_transaction(bytes: &[u8]) -> nom::IResult<&[u8], InvalidTransaction> {
    nom::error::context(
        "invalid transaction",
        nom::branch::alt((
            nom::combinator::map(nom::bytes::complete::tag(&[0]), |_| {
                InvalidTransaction::Call
            }),
            nom::combinator::map(nom::bytes::complete::tag(&[1]), |_| {
                InvalidTransaction::Payment
            }),
            nom::combinator::map(nom::bytes::complete::tag(&[2]), |_| {
                InvalidTransaction::Future
            }),
            nom::combinator::map(nom::bytes::complete::tag(&[3]), |_| {
                InvalidTransaction::Stale
            }),
            nom::combinator::map(nom::bytes::complete::tag(&[4]), |_| {
                InvalidTransaction::BadProof
            }),
            nom::combinator::map(nom::bytes::complete::tag(&[5]), |_| {
                InvalidTransaction::AncientBirthBlock
            }),
            nom::combinator::map(nom::bytes::complete::tag(&[6]), |_| {
                InvalidTransaction::ExhaustsResources
            }),
            nom::combinator::map(
                nom::sequence::preceded(
                    nom::bytes::complete::tag(&[7]),
                    nom::bytes::complete::take(1u32),
                ),
                |n: &[u8]| InvalidTransaction::Custom(n[0]),
            ),
            nom::combinator::map(nom::bytes::complete::tag(&[8]), |_| {
                InvalidTransaction::BadMandatory
            }),
            nom::combinator::map(nom::bytes::complete::tag(&[9]), |_| {
                InvalidTransaction::MandatoryDispatch
            }),
        )),
    )(bytes)
}

fn unknown_transaction(bytes: &[u8]) -> nom::IResult<&[u8], UnknownTransaction> {
    nom::error::context(
        "unknown transaction",
        nom::branch::alt((
            nom::combinator::map(nom::bytes::complete::tag(&[0]), |_| {
                UnknownTransaction::CannotLookup
            }),
            nom::combinator::map(nom::bytes::complete::tag(&[1]), |_| {
                UnknownTransaction::NoUnsignedValidator
            }),
            nom::combinator::map(
                nom::sequence::preceded(
                    nom::bytes::complete::tag(&[2]),
                    nom::bytes::complete::take(1u32),
                ),
                |n: &[u8]| UnknownTransaction::Custom(n[0]),
            ),
        )),
    )(bytes)
}

fn tags(bytes: &[u8]) -> nom::IResult<&[u8], Vec<Vec<u8>>> {
    nom::combinator::flat_map(crate::util::nom_scale_compact_usize, |num_elems| {
        nom::multi::many_m_n(
            num_elems,
            num_elems,
            nom::combinator::map(
                nom::multi::length_data(crate::util::nom_scale_compact_usize),
                |tag| tag.to_owned(),
            ),
        )
    })(bytes)
}
