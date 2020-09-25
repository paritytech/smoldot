// Copyright (C) 2019-2020 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Transactions validation.
//!
//! When the node is informed of a transaction, the first step is to perform a runtime function
//! call with the `TaggedTransactionQueue_validate_transaction` entry point, passing the opaque
//! SCALE-encoded transaction as input. On success, the runtime returns a variety of information
//! regarding this transaction in the form of a [`ValidTransaction`].
// TODO: finish doc

use crate::executor;

use core::{convert::TryFrom as _, iter};

/// Configuration for a transaction validation.
pub struct Config<TTx> {
    /// Runtime used to check the transaction. Must be built using the Wasm code found at the
    /// `:code` key of the relevant block.
    pub runtime: executor::WasmVmPrototype,

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

/// Block successfully verified.
pub struct Success {
    /// Information about the valid transaction.
    pub transaction: ValidTransaction,
    /// Runtime that was passed by [`Config`].
    pub runtime: executor::WasmVmPrototype,
    /// Concatenation of all the log messages printed by the runtime.
    pub logs: String,
}

/// Information concerning a valid transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidTransaction {
    /// Priority of the transaction.
    ///
    /// Priority determines the ordering of two transactions that have all
    /// their dependencies (required tags) satisfied. Higher is better.
    pub priority: u64,

    /// Transaction dependencies
    ///
    /// A non-empty list signifies that some other transactions which provide
    /// given tags are required to be included before that one.
    // TODO: better type than `Vec<Vec<u8>>`? I feel like this could be a single `Vec<u8>` that is decoded on the fly?
    pub requires: Vec<Vec<u8>>,

    /// Provided tags
    ///
    /// A list of tags this transaction provides. Successfully importing the transaction
    /// will enable other transactions that depend on (require) those tags to be included as well.
    /// Provided and required tags allow Substrate to build a dependency graph of transactions
    /// and import them in the right (linear) order.
    // TODO: better type than `Vec<Vec<u8>>`? I feel like this could be a single `Vec<u8>` that is decoded on the fly?
    pub provides: Vec<Vec<u8>>,

    /// Transaction longevity
    ///
    /// Longevity describes minimum number of blocks the validity is correct.
    /// After this period transaction should be removed from the pool or revalidated.
    ///
    /// Minimum number of blocks a transaction will remain valid for.
    /// `u64::max_value()` means "forever".
    pub longevity: u64,

    /// A flag indicating if the transaction should be propagated to other peers.
    ///
    /// By setting `false` here the transaction will still be considered for
    /// including in blocks that are authored on the current node, but will
    /// never be sent to other peers.
    pub propagate: bool,
}

/// Error that can happen during the validation.
#[derive(Debug, Clone, derive_more::Display)]
pub enum Error {
    /// The transaction is invalid.
    Invalid(InvalidTransaction),
    /// Transaction validity can't be determined.
    Unknown(UnknownTransaction),
    /// Error while executing the Wasm virtual machine.
    Trapped {
        /// Concatenation of all the log messages printed by the runtime.
        logs: String,
    },
    /// Failed to decode output of `TaggedTransactionQueue_validate_transaction`.
    OutputDecodeError,
    /// Size of the logs generated by the runtime exceeds the limit.
    LogsTooLong,
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

/// Verifies whether a block is valid.
pub fn execute_block(
    config: Config<impl ExactSizeIterator<Item = impl AsRef<[u8]> + Clone> + Clone>,
) -> Verify {
    let vm = config
        .runtime
        .run_vectored("TaggedTransactionQueue_validate_transaction", {
            // The `TaggedTransactionQueue_validate_transaction` function expects a SCALE-encoded
            // `(source, tx)`. The encoding is performed manually in order to avoid performing
            // redundant data copies.
            let source = match config.source {
                TransactionSource::InBlock => &[0],
                TransactionSource::Local => &[1],
                TransactionSource::External => &[2],
            };

            iter::once(source)
                .map(either::Either::Left)
                .chain(config.scale_encoded_transaction.map(either::Either::Right))
        })
        .unwrap();

    VerifyInner {
        vm,
        logs: String::new(),
    }
    .run()
}

/// Current state of the validation.
#[must_use]
pub enum Verify {
    /// Validation is over.
    Finished(Result<Success, Error>),
    /// Loading a storage value is required in order to continue.
    StorageGet(StorageGet),
    /// Fetching the key that follows a given one is required in order to continue.
    NextKey(NextKey),
}

/// Loading a storage value is required in order to continue.
#[must_use]
pub struct StorageGet {
    inner: VerifyInner,
}

impl StorageGet {
    /// Returns the key whose value must be passed to [`StorageGet::inject_value`].
    // TODO: shouldn't be mut
    pub fn key<'a>(&'a mut self) -> impl Iterator<Item = impl AsRef<[u8]> + 'a> + 'a {
        match self.inner.vm.state() {
            executor::State::ExternalStorageGet { storage_key, .. } => iter::once(storage_key),
            _ => unreachable!(),
        }
    }

    /// Returns the key whose value must be passed to [`StorageGet::inject_value`].
    ///
    /// This method is a shortcut for calling `key` and concatenating the returned slices.
    // TODO: shouldn't be mut
    pub fn key_as_vec(&mut self) -> Vec<u8> {
        self.key().fold(Vec::new(), |mut a, b| {
            a.extend_from_slice(b.as_ref());
            a
        })
    }

    /// Injects the corresponding storage value.
    // TODO: `value` parameter should be something like `Iterator<Item = impl AsRef<[u8]>`
    pub fn inject_value(mut self, value: Option<&[u8]>) -> Verify {
        match self.inner.vm.state() {
            executor::State::ExternalStorageGet {
                offset,
                max_size,
                resolve,
                ..
            } => {
                if let Some(mut value) = value {
                    if usize::try_from(offset).unwrap() < value.len() {
                        value = &value[usize::try_from(offset).unwrap()..];
                        if usize::try_from(max_size).unwrap() < value.len() {
                            value = &value[..usize::try_from(max_size).unwrap()];
                        }
                    }

                    resolve.finish_call(Some(value.to_vec())); // TODO: overhead
                } else {
                    resolve.finish_call(None);
                }
            }
            _ => unreachable!(),
        };

        self.inner.run()
    }
}

/// Fetching the key that follows a given one is required in order to continue.
#[must_use]
pub struct NextKey {
    inner: VerifyInner,
}

impl NextKey {
    /// Returns the key whose next key must be passed back.
    // TODO: don't take &mut mut but &self
    pub fn key(&mut self) -> &[u8] {
        match self.inner.vm.state() {
            executor::State::ExternalStorageNextKey { storage_key, .. } => storage_key,
            _ => unreachable!(),
        }
    }

    /// Injects the key.
    pub fn inject_key(mut self, key: Option<impl AsRef<[u8]>>) -> Verify {
        match self.inner.vm.state() {
            executor::State::ExternalStorageNextKey { resolve, .. } => {
                resolve.finish_call(key.as_ref().map(|k| k.as_ref().to_owned()));
            }
            _ => unreachable!(),
        };

        self.inner.run()
    }
}

/// Implementation detail of the validation. Shared by all the variants of [`Verify`] except
/// [`Verify::Finished`].
struct VerifyInner {
    /// Virtual machine running the call.
    vm: executor::WasmVm,

    /// Concatenation of all the log messages generated by the runtime.
    logs: String,
}

impl VerifyInner {
    /// Continues the validation.
    fn run(mut self) -> Verify {
        loop {
            match self.vm.state() {
                executor::State::ReadyToRun(r) => r.run(),

                executor::State::Trapped => {
                    return Verify::Finished(Err(Error::Trapped { logs: self.logs }))
                }
                executor::State::Finished(output) => {
                    let (_, result) =
                        match nom::combinator::all_consuming(transaction_validity)(output) {
                            Ok(s) => s,
                            Err(_) => return Verify::Finished(Err(Error::OutputDecodeError)),
                        };

                    let success = match result {
                        Ok(s) => s,
                        Err(TransactionValidityError::Invalid(invalid)) => {
                            return Verify::Finished(Err(Error::Invalid(invalid)))
                        }
                        Err(TransactionValidityError::Unknown(unknown)) => {
                            return Verify::Finished(Err(Error::Unknown(unknown)))
                        }
                    };

                    return Verify::Finished(Ok(Success {
                        transaction: success,
                        runtime: self.vm.into_prototype(),
                        logs: self.logs,
                    }));
                }

                executor::State::ExternalStorageGet { .. } => {
                    return Verify::StorageGet(StorageGet { inner: self });
                }

                executor::State::ExternalStorageNextKey { .. } => {
                    return Verify::NextKey(NextKey { inner: self })
                }

                executor::State::CallRuntimeVersion { wasm_blob, resolve } => {
                    // The code below compiles the provided WebAssembly runtime code, which is a
                    // relatively expensive operation (in the order of milliseconds).
                    // While it could be tempting to use a system cache, this function is expected
                    // to be called only right before runtime upgrades. Considering that runtime
                    // upgrades are quite uncommon and that a caching system is rather non-trivial
                    // to set up, the approach of recompiling every single time is preferred here.
                    // TODO: number of heap pages?! 1024 is default, but not sure whether that's correct or if we have to take the current heap pages
                    let vm_prototype = match executor::WasmVmPrototype::new(wasm_blob, 1024) {
                        Ok(w) => w,
                        Err(_) => {
                            resolve.finish_call(Err(()));
                            continue;
                        }
                    };

                    match executor::core_version(vm_prototype) {
                        Ok((version, _)) => {
                            resolve.finish_call(Ok(parity_scale_codec::Encode::encode(&version)));
                        }
                        Err(_) => {
                            resolve.finish_call(Err(()));
                        }
                    }
                }

                executor::State::LogEmit { message, resolve } => {
                    // We add a hardcoded limit to the logs generated by the runtime in order to
                    // make sure that there is no memory leak. In practice, the runtime should
                    // rarely log more than a few hundred bytes. This limit is hardcoded rather
                    // than configurable because it is not expected to be reachable unless
                    // something is very wrong.
                    if self.logs.len().saturating_add(message.len()) >= 1024 * 1024 {
                        return Verify::Finished(Err(Error::LogsTooLong));
                    }

                    self.logs.push_str(message);
                    resolve.finish_call(());
                }

                s => unimplemented!("unimplemented externality: {:?}", s),
            }
        }
    }
}

/// Errors that can occur while checking the validity of a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TransactionValidityError {
    /// The transaction is invalid.
    Invalid(InvalidTransaction),
    /// Transaction validity can't be determined.
    Unknown(UnknownTransaction),
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
                nom::bytes::complete::take(8u32),
                tags,
                tags,
                nom::bytes::complete::take(8u32),
                bool,
            )),
            |(priority, requires, provides, longevity, propagate)| ValidTransaction {
                priority: u64::from_le_bytes(<[u8; 8]>::try_from(priority).unwrap()),
                requires,
                provides,
                longevity: u64::from_le_bytes(<[u8; 8]>::try_from(longevity).unwrap()),
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

fn bool(bytes: &[u8]) -> nom::IResult<&[u8], bool> {
    nom::branch::alt((
        nom::combinator::map(nom::bytes::complete::tag(&[0]), |_| false),
        nom::combinator::map(nom::bytes::complete::tag(&[1]), |_| true),
    ))(bytes)
}
