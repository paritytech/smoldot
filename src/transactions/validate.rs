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
    executor::{host, read_only_runtime_host},
    util,
};

use alloc::{borrow::ToOwned as _, vec::Vec};
use core::{iter, num::NonZeroU64};

/// Configuration for a transaction validation process.
pub struct Config<TTx> {
    /// Runtime used to get the validate the transaction. Must be built using the Wasm code found
    /// at the `:code` key of the block storage.
    pub runtime: host::HostVmPrototype,

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
    /// Error while starting the Wasm virtual machine.
    #[display(fmt = "{}", _0)]
    WasmStart(host::StartErr),
    /// Error while running the Wasm virtual machine.
    #[display(fmt = "{}", _0)]
    WasmVm(read_only_runtime_host::ErrorDetail),
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
pub fn validate_transaction_runtime_parameters(
    scale_encoded_transaction: impl Iterator<Item = impl AsRef<[u8]>> + Clone,
    source: TransactionSource,
) -> impl Iterator<Item = impl AsRef<[u8]>> + Clone {
    // The `TaggedTransactionQueue_validate_transaction` function expects a SCALE-encoded
    // `(source, tx)`. The encoding is performed manually in order to avoid performing
    // redundant data copies.
    let source = match source {
        TransactionSource::InBlock => &[0],
        TransactionSource::Local => &[1],
        TransactionSource::External => &[2],
    };

    iter::once(source)
        .map(either::Either::Left)
        .chain(scale_encoded_transaction.map(either::Either::Right))
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
    config: Config<impl Iterator<Item = impl AsRef<[u8]>> + Clone>,
) -> Query {
    let vm = read_only_runtime_host::run(read_only_runtime_host::Config {
        virtual_machine: config.runtime,
        function_to_call: VALIDATION_FUNCTION_NAME,
        parameter: validate_transaction_runtime_parameters(
            config.scale_encoded_transaction,
            config.source,
        ),
    });

    match vm {
        Ok(vm) => Query::from_inner(vm),
        Err((err, virtual_machine)) => Query::Finished {
            result: Err(Error::WasmStart(err)),
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
    /// Fetching the storage trie root is required in order to continue.
    StorageRoot(StorageRoot),
}

impl Query {
    fn from_inner(inner: read_only_runtime_host::RuntimeHostVm) -> Self {
        match inner {
            read_only_runtime_host::RuntimeHostVm::Finished(Ok(success)) => {
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
            read_only_runtime_host::RuntimeHostVm::Finished(Err(err)) => Query::Finished {
                result: Err(Error::WasmVm(err.detail)),
                virtual_machine: err.prototype,
            },
            read_only_runtime_host::RuntimeHostVm::StorageGet(inner) => {
                Query::StorageGet(StorageGet(inner))
            }
            read_only_runtime_host::RuntimeHostVm::StorageRoot(inner) => {
                Query::StorageRoot(StorageRoot(inner))
            }
            read_only_runtime_host::RuntimeHostVm::NextKey(inner) => Query::NextKey(NextKey(inner)),
        }
    }
}

/// Loading a storage value is required in order to continue.
#[must_use]
pub struct StorageGet(read_only_runtime_host::StorageGet);

impl StorageGet {
    /// Returns the key whose value must be passed to [`StorageGet::inject_value`].
    pub fn key(&'_ self) -> impl Iterator<Item = impl AsRef<[u8]> + '_> + '_ {
        self.0.key()
    }

    /// Returns the key whose value must be passed to [`StorageGet::inject_value`].
    ///
    /// This method is a shortcut for calling `key` and concatenating the returned slices.
    pub fn key_as_vec(&self) -> Vec<u8> {
        self.0.key_as_vec()
    }

    /// Injects the corresponding storage value.
    pub fn inject_value(self, value: Option<impl Iterator<Item = impl AsRef<[u8]>>>) -> Query {
        Query::from_inner(self.0.inject_value(value))
    }
}

/// Fetching the key that follows a given one is required in order to continue.
#[must_use]
pub struct NextKey(read_only_runtime_host::NextKey);

impl NextKey {
    /// Returns the key whose next key must be passed back.
    pub fn key(&'_ self) -> impl AsRef<[u8]> + '_ {
        self.0.key()
    }

    /// Injects the key.
    ///
    /// # Panic
    ///
    /// Panics if the key passed as parameter isn't strictly superior to the requested key.
    ///
    pub fn inject_key(self, key: Option<impl AsRef<[u8]>>) -> Query {
        Query::from_inner(self.0.inject_key(key))
    }
}

/// Fetching the storage trie root is required in order to continue.
#[must_use]
pub struct StorageRoot(read_only_runtime_host::StorageRoot);

impl StorageRoot {
    /// Writes the trie root hash to the Wasm VM and prepares it for resume.
    pub fn resume(self, hash: &[u8; 32]) -> Query {
        Query::from_inner(self.0.resume(hash))
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
