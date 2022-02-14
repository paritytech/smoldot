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

//! List of requests and how to answer them.

use super::parse;
use crate::header;

use alloc::{
    boxed::Box,
    format,
    string::{String, ToString as _},
    vec,
    vec::Vec,
};
use core::fmt;
use hashbrown::HashMap;

/// Parses a JSON call (usually received from a JSON-RPC server).
///
/// On success, returns a JSON-encoded identifier for that request that must be passed back when
/// emitting the response.
pub fn parse_json_call(message: &str) -> Result<(&str, MethodCall), ParseError> {
    let call_def = parse::parse_call(message).map_err(ParseError::JsonRpcParse)?;

    // No notification is supported by this server. If the `id` field is missing in the request,
    // assuming that this is a notification and return an appropriate error.
    let request_id = match call_def.id_json {
        Some(id) => id,
        None => return Err(ParseError::UnknownNotification(call_def.method)),
    };

    let call = match MethodCall::from_defs(call_def.method, call_def.params_json) {
        Ok(c) => c,
        Err(error) => return Err(ParseError::Method { request_id, error }),
    };

    Ok((request_id, call))
}

/// Builds a JSON call, to send it to a JSON-RPC server.
///
/// # Panic
///
/// Panics if the `id_json` isn't valid JSON.
///
pub fn build_json_call_object_parameters(id_json: Option<&str>, method: MethodCall) -> String {
    method.to_json_call_object_parameters(id_json)
}

/// Error produced by [`parse_json_call`].
#[derive(Debug, derive_more::Display)]
pub enum ParseError<'a> {
    /// Could not parse the body of the message as a valid JSON-RPC message.
    JsonRpcParse(parse::ParseError),
    /// Call concerns a notification that isn't recognized.
    UnknownNotification(&'a str),
    /// JSON-RPC request is valid, but there is a problem related to the method being called.
    #[display(fmt = "{}", error)]
    Method {
        /// Identifier of the request sent by the user.
        request_id: &'a str,
        /// Problem that happens.
        error: MethodError<'a>,
    },
}

/// See [`ParseError::Method`].
#[derive(Debug, derive_more::Display)]
pub enum MethodError<'a> {
    /// Call concerns a method that isn't recognized.
    UnknownMethod(&'a str),
    /// Format the parameters is plain invalid.
    #[display(fmt = "Invalid parameters format when calling {}", rpc_method)]
    InvalidParametersFormat {
        /// Name of the JSON-RPC method that was attempted to be called.
        rpc_method: &'static str,
    },
    /// Too many parameters have been passed to the function.
    #[display(
        fmt = "{} expects {} parameters, but got {}",
        rpc_method,
        expected,
        actual
    )]
    TooManyParameters {
        /// Name of the JSON-RPC method that was attempted to be called.
        rpc_method: &'static str,
        /// Number of parameters that are expected to be received.
        expected: usize,
        /// Number of parameters actually received.
        actual: usize,
    },
    /// One of the parameters of the function call is invalid.
    #[display(
        fmt = "Parameter #{} is invalid when calling {}: {}",
        parameter_index,
        rpc_method,
        error
    )]
    InvalidParameter {
        /// Name of the JSON-RPC method that was attempted to be called.
        rpc_method: &'static str,
        /// 0-based index of the parameter whose format is invalid.
        parameter_index: usize,
        /// Reason why it failed.
        error: InvalidParameterError,
    },
}

impl<'a> MethodError<'a> {
    /// Turns the error into a JSON string representing the error response to send back.
    ///
    /// `id_json` must be a valid JSON-formatted request identifier, the same the user
    /// passed in the request.
    ///
    /// # Panic
    ///
    /// Panics if `id_json` isn't valid JSON.
    ///
    pub fn to_json_error(&self, id_json: &str) -> String {
        parse::build_error_response(
            id_json,
            match self {
                MethodError::UnknownMethod(_) => parse::ErrorResponse::MethodNotFound,
                MethodError::InvalidParametersFormat { .. }
                | MethodError::TooManyParameters { .. }
                | MethodError::InvalidParameter { .. } => parse::ErrorResponse::InvalidParams,
            },
            None,
        )
    }
}

/// Could not parse the body of the message as a valid JSON-RPC message.
#[derive(Debug, derive_more::Display)]
pub struct JsonRpcParseError(serde_json::Error);

/// The parameter of a function call is invalid.
#[derive(Debug, derive_more::Display)]
pub struct InvalidParameterError(serde_json::Error);

/// Generates two enums, one for requests and one for responses, based on the list of supported
/// requests.
macro_rules! define_methods {
    ($rq_name:ident, $rp_name:ident $(<$l:lifetime>)*, $(
        $(#[$attrs:meta])*
        $name:ident ($($(#[rename = $p_rpc_name:expr])* $p_name:ident: $p_ty:ty),*) -> $ret_ty:ty
            $([$($alias:ident),*])*
        ,
    )*) => {
        #[allow(non_camel_case_types, non_snake_case)]
        #[derive(Debug, Clone)]
        pub enum $rq_name<'a> {
            $(
                $(#[$attrs])*
                $name {
                    $($p_name: $p_ty),*
                },
            )*
        }

        impl<'a> $rq_name<'a> {
            /// Returns a list of RPC method names of all the methods in the enum.
            pub fn method_names() -> impl ExactSizeIterator<Item = &'static str> {
                [$(stringify!($name)),*].iter().copied()
            }

            /// Returns the name of the method.
            pub fn name(&self) -> &'static str {
                match self {
                    $($rq_name::$name { .. } => stringify!($name),)*
                }
            }

            /// Returns an JSON object containing the list of the parameters of the method.
            pub fn params_to_json_object(&self) -> String {
                match self {
                    $($rq_name::$name { $($p_name),* } => {
                        #[derive(serde::Serialize)]
                        struct Params<'a> {
                            $(
                                $(#[serde(rename = $p_rpc_name)])*
                                $p_name: &'a $p_ty,
                            )*

                            // This `_dummy` field is necessary to not have an "unused lifetime"
                            // error if the parameters don't have a lifetime.
                            #[serde(skip)]
                            _dummy: core::marker::PhantomData<&'a ()>,
                        }

                        serde_json::to_string(&Params {
                            $($p_name,)*
                            _dummy: core::marker::PhantomData
                        }).unwrap()
                    },)*
                }
            }

            /// Builds a JSON call, to send it to a JSON-RPC server.
            ///
            /// # Panic
            ///
            /// Panics if the `id_json` isn't valid JSON.
            ///
            pub fn to_json_call_object_parameters(&self, id_json: Option<&str>) -> String {
                parse::build_call(parse::Call {
                    id_json,
                    method: self.name(),
                    params_json: &self.params_to_json_object(),
                })
            }

            fn from_defs(name: &'a str, params: &'a str) -> Result<Self, MethodError<'a>> {
                #![allow(unused, unused_mut)]

                $(
                    if name == stringify!($name) $($(|| name == stringify!($alias))*)* {
                        // First, try parse parameters as if they were passed by name in a map.
                        // For example, a method `my_method(foo: i32, bar: &str)` accepts
                        // parameters formatted as `{"foo":5, "bar":"hello"}`.
                        #[derive(serde::Deserialize)]
                        struct Params<'a> {
                            $(
                                $(#[serde(rename = $p_rpc_name)])*
                                $p_name: $p_ty,
                            )*

                            // This `_dummy` field is necessary to not have an "unused lifetime"
                            // error if the parameters don't have a lifetime.
                            #[serde(skip)]
                            _dummy: core::marker::PhantomData<&'a ()>,
                        }
                        if let Ok(params) = serde_json::from_str(params) {
                            let Params { _dummy: _, $($p_name),* } = params;
                            return Ok($rq_name::$name {
                                $($p_name,)*
                            })
                        }

                        // Otherwise, try parse parameters as if they were passed by array.
                        // For example, a method `my_method(foo: i32, bar: &str)` also accepts
                        // parameters formatted as `[5, "hello"]`.
                        // To make things more complex, optional parameters can be omitted.
                        //
                        // The code below allocates a `Vec`, but at the time of writing there is
                        // no way to ask `serde_json` to parse an array without doing so.
                        if let Ok(params) = serde_json::from_str::<Vec<&'a serde_json::value::RawValue>>(params) {
                            let mut n = 0;
                            $(
                                // Missing parameters are implicitly equal to null.
                                let $p_name = match params.get(n)
                                    .map(|val| serde_json::from_str(val.get()))
                                    .unwrap_or_else(|| serde_json::from_str("null"))
                                {
                                    Ok(v) => v,
                                    Err(err) => return Err(MethodError::InvalidParameter {
                                        rpc_method: stringify!($name),
                                        parameter_index: n,
                                        error: InvalidParameterError(err),
                                    })
                                };
                                n += 1;
                            )*
                            if params.get(n).is_some() {
                                return Err(MethodError::TooManyParameters {
                                    rpc_method: stringify!($name),
                                    expected: n,
                                    actual: params.len(),
                                })
                            }
                            return Ok($rq_name::$name {
                                $($p_name,)*
                            })
                        }

                        return Err(MethodError::InvalidParametersFormat {
                            rpc_method: stringify!($name),
                        });
                    }
                )*

                Err(MethodError::UnknownMethod(name))
            }
        }

        #[allow(non_camel_case_types)]
        #[derive(Debug, Clone)]
        pub enum $rp_name $(<$l>)* {
            $(
                $name($ret_ty),
            )*
        }

        impl$(<$l>)* $rp_name$(<$l>)* {
            /// Serializes the response into a JSON string.
            ///
            /// `id_json` must be a valid JSON-formatted request identifier, the same the user
            /// passed in the request.
            ///
            /// # Panic
            ///
            /// Panics if `id_json` isn't valid JSON.
            ///
            pub fn to_json_response(&self, id_json: &str) -> String {
                match self {
                    $(
                        $rp_name::$name(out) => {
                            let result_json = serde_json::to_string(&out).unwrap();
                            parse::build_success_response(id_json, &result_json)
                        },
                    )*
                }
            }
        }
    };
}

// TODO: change everything to take parameters by ref when possible
// TODO: change everything to return values by ref when possible
define_methods! {
    MethodCall,
    Response<'a>,
    account_nextIndex() -> (), // TODO:
    author_hasKey() -> (), // TODO:
    author_hasSessionKeys() -> (), // TODO:
    author_insertKey() -> (), // TODO:
    author_pendingExtrinsics() -> Vec<HexString>,  // TODO: what does the returned value mean?
    author_removeExtrinsic() -> (), // TODO:
    author_rotateKeys() -> HexString,
    author_submitAndWatchExtrinsic(transaction: HexString) -> &'a str,
    author_submitExtrinsic(transaction: HexString) -> HashHexString,
    author_unwatchExtrinsic(subscription: &'a str) -> bool,
    babe_epochAuthorship() -> (), // TODO:
    chain_getBlock(hash: Option<HashHexString>) -> Block,
    chain_getBlockHash(height: Option<u64>) -> HashHexString [chain_getHead],
    chain_getFinalizedHead() -> HashHexString [chain_getFinalisedHead],
    chain_getHeader(hash: Option<HashHexString>) -> Header, // TODO: return type is guessed
    chain_subscribeAllHeads() -> &'a str,
    chain_subscribeFinalizedHeads() -> &'a str [chain_subscribeFinalisedHeads],
    chain_subscribeNewHeads() -> &'a str [subscribe_newHead, chain_subscribeNewHead],
    chain_unsubscribeAllHeads(subscription: String) -> bool,
    chain_unsubscribeFinalizedHeads(subscription: String) -> bool [chain_unsubscribeFinalisedHeads],
    chain_unsubscribeNewHeads(subscription: String) -> bool [unsubscribe_newHead, chain_unsubscribeNewHead],
    childstate_getKeys() -> (), // TODO:
    childstate_getStorage() -> (), // TODO:
    childstate_getStorageHash() -> (), // TODO:
    childstate_getStorageSize() -> (), // TODO:
    grandpa_roundState() -> (), // TODO:
    offchain_localStorageGet() -> (), // TODO:
    offchain_localStorageSet() -> (), // TODO:
    payment_queryInfo(extrinsic: HexString, hash: Option<HashHexString>) -> RuntimeDispatchInfo,
    /// Returns a list of all JSON-RPC methods that are available.
    rpc_methods() -> RpcMethods,
    state_call() -> () [state_callAt], // TODO:
    state_getKeys() -> (), // TODO:
    state_getKeysPaged(prefix: Option<HexString>, count: u32, start_key: Option<HexString>, hash: Option<HashHexString>) -> Vec<HexString> [state_getKeysPagedAt],
    state_getMetadata(hash: Option<HashHexString>) -> HexString,
    state_getPairs() -> (), // TODO:
    state_getReadProof() -> (), // TODO:
    state_getRuntimeVersion(at: Option<HashHexString>) -> RuntimeVersion<'a> [chain_getRuntimeVersion],
    state_getStorage(key: HexString, hash: Option<HashHexString>) -> HexString [state_getStorageAt],
    state_getStorageHash() -> () [state_getStorageHashAt], // TODO:
    state_getStorageSize() -> () [state_getStorageSizeAt], // TODO:
    state_queryStorage() -> (), // TODO:
    state_queryStorageAt(keys: Vec<HexString>, at: Option<HashHexString>) -> Vec<StorageChangeSet>, // TODO:
    state_subscribeRuntimeVersion() -> &'a str [chain_subscribeRuntimeVersion],
    state_subscribeStorage(list: Vec<HexString>) -> &'a str,
    state_unsubscribeRuntimeVersion(subscription: &'a str) -> bool [chain_unsubscribeRuntimeVersion],
    state_unsubscribeStorage(subscription: &'a str) -> bool,
    system_accountNextIndex(account: AccountId) -> u64,
    system_addReservedPeer() -> (), // TODO:
    system_chain() -> &'a str,
    system_chainType() -> &'a str,
    system_dryRun() -> () [system_dryRunAt], // TODO:
    system_health() -> SystemHealth,
    system_localListenAddresses() -> Vec<String>,
    /// Returns the base58 encoding of the network identity of the node on the peer-to-peer network.
    system_localPeerId() -> &'a str,
    /// Returns, as an opaque string, the name of the client serving these JSON-RPC requests.
    system_name() -> &'a str,
    system_networkState() -> (), // TODO:
    system_nodeRoles() -> (), // TODO:
    system_peers() -> Vec<SystemPeer>,
    system_properties() -> Box<serde_json::value::RawValue>,
    system_removeReservedPeer() -> (), // TODO:
    /// Returns, as an opaque string, the version of the client serving these JSON-RPC requests.
    system_version() -> &'a str,

    // The functions below are experimental and are defined in the document https://github.com/paritytech/json-rpc-interface-spec/
    chainHead_unstable_body(
        #[rename = "followSubscription"] follow_subscription: &'a str,
        hash: HashHexString,
        #[rename = "networkConfig"] network_config: Option<NetworkConfig>
    ) -> &'a str,
    chainHead_unstable_call(
        #[rename = "followSubscription"] follow_subscription: &'a str,
        hash: HashHexString,
        function: &'a str,
        #[rename = "callParameters"] call_parameters: HexString,
        #[rename = "networkConfig"] network_config: Option<NetworkConfig>
    ) -> &'a str,
    chainHead_unstable_follow(
        #[rename = "runtimeUpdates"] runtime_updates: bool
    ) -> &'a str,
    chainHead_unstable_genesisHash() -> HashHexString,
    chainHead_unstable_header(
        #[rename = "followSubscription"] follow_subscription: &'a str,
        hash: HashHexString
    ) -> Option<HexString>,
    chainHead_unstable_stopBody(
        subscription: &'a str
    ) -> (),
    chainHead_unstable_stopCall(
        subscription: &'a str
    ) -> (),
    chainHead_unstable_stopStorage(
        subscription: &'a str
    ) -> (),
    chainHead_unstable_storage(
        #[rename = "followSubscription"] follow_subscription: &'a str,
        hash: HashHexString,
        key: HexString,
        #[rename = "childKey"] child_key: Option<HexString>,
        r#type: StorageQueryType,
        #[rename = "networkConfig"] network_config: Option<NetworkConfig>
    ) -> &'a str,
    chainHead_unstable_unfollow(
        #[rename = "followSubscription"] follow_subscription: &'a str
    ) -> (),
    chainHead_unstable_unpin(
        #[rename = "followSubscription"] follow_subscription: &'a str,
        hash: HashHexString
    ) -> (),

    chainSpec_unstable_chainName() -> &'a str,
    chainSpec_unstable_genesisHash() -> HashHexString,
    chainSpec_unstable_properties() -> Box<serde_json::value::RawValue>,

    sudo_unstable_p2pDiscover(multiaddr: &'a str) -> (),
    sudo_unstable_version() -> &'a str,

    transaction_unstable_submitAndWatch(transaction: HexString) -> &'a str,
    transaction_unstable_unwatch(subscription: &'a str) -> (),
}

define_methods! {
    ServerToClient,
    ServerToClientResponse, // TODO: unnecessary
    author_extrinsicUpdate(subscription: &'a str, result: TransactionStatus) -> (),
    chain_finalizedHead(subscription: &'a str, result: Header) -> (),
    chain_newHead(subscription: &'a str, result: Header) -> (),
    state_runtimeVersion(subscription: &'a str, result: Option<RuntimeVersion<'a>>) -> (), // TODO: the Option is a custom addition
    state_storage(subscription: &'a str, result: StorageChangeSet) -> (),

    // The functions below are experimental and are defined in the document https://github.com/paritytech/json-rpc-interface-spec/
    chainHead_unstable_bodyEvent(subscription: &'a str, result: ChainHeadBodyEvent) -> (),
    chainHead_unstable_callEvent(subscription: &'a str, result: ChainHeadCallEvent<'a>) -> (),
    chainHead_unstable_followEvent(subscription: &'a str, result: FollowEvent<'a>) -> (),
    chainHead_unstable_storageEvent(subscription: &'a str, result: ChainHeadStorageEvent) -> (),
    transaction_unstable_watchEvent(subscription: &'a str, result: TransactionWatchEvent<'a>) -> (),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HexString(pub Vec<u8>);

impl AsRef<[u8]> for HexString {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// TODO: not great for type in public API
impl<'a> serde::Deserialize<'a> for HexString {
    fn deserialize<D>(deserializer: D) -> Result<HexString, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        let string = String::deserialize(deserializer)?;

        if string.is_empty() {
            return Ok(HexString(Vec::new()));
        }

        if !string.starts_with("0x") {
            return Err(serde::de::Error::custom(
                "hexadecimal string doesn't start with 0x",
            ));
        }

        let bytes = hex::decode(&string[2..]).map_err(serde::de::Error::custom)?;
        Ok(HexString(bytes))
    }
}

#[derive(Debug, Clone)]
pub struct HashHexString(pub [u8; 32]);

// TODO: not great for type in public API
impl<'a> serde::Deserialize<'a> for HashHexString {
    fn deserialize<D>(deserializer: D) -> Result<HashHexString, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        let string = String::deserialize(deserializer)?;

        if !string.starts_with("0x") {
            return Err(serde::de::Error::custom("hash doesn't start with 0x"));
        }

        let bytes = hex::decode(&string[2..]).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::invalid_length(
                bytes.len(),
                &"a 32 bytes hash",
            ));
        }

        let mut out = [0; 32];
        out.copy_from_slice(&bytes);
        Ok(HashHexString(out))
    }
}

/// Contains the public key of an account.
///
/// The deserialization involves decoding an SS58 address into this public key.
#[derive(Debug, Clone)]
pub struct AccountId(pub [u8; 32]);

impl serde::Serialize for AccountId {
    fn serialize<S>(&self, _: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        todo!() // TODO: /!\
    }
}

// TODO: not great for type in public API
impl<'a> serde::Deserialize<'a> for AccountId {
    fn deserialize<D>(deserializer: D) -> Result<AccountId, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        let string = <&str>::deserialize(deserializer)?;
        let decoded = match bs58::decode(&string).into_vec() {
            // TODO: don't use into_vec
            Ok(d) => d,
            Err(_) => return Err(serde::de::Error::custom("AccountId isn't in base58 format")),
        };

        // TODO: soon might be 36 bytes as well
        if decoded.len() != 35 {
            return Err(serde::de::Error::custom("unexpected length for AccountId"));
        }

        // TODO: finish implementing this properly ; must notably check checksum
        // see https://github.com/paritytech/substrate/blob/74a50abd6cbaad1253daf3585d5cdaa4592e9184/primitives/core/src/crypto.rs#L228

        let account_id = <[u8; 32]>::try_from(&decoded[1..33]).unwrap();
        Ok(AccountId(account_id))
    }
}

#[derive(Debug, Clone)]
pub struct Block {
    pub extrinsics: Vec<HexString>,
    pub header: Header,
    /// List of justifications. Each justification is made of a consensus engine id and of the
    /// actual SCALE-encoded justification.
    pub justifications: Option<Vec<([u8; 4], Vec<u8>)>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "event")]
pub enum FollowEvent<'a> {
    #[serde(rename = "initialized")]
    Initialized {
        #[serde(rename = "finalizedBlockHash")]
        finalized_block_hash: HashHexString,
        #[serde(
            rename = "finalizedBlockRuntime",
            skip_serializing_if = "Option::is_none"
        )]
        finalized_block_runtime: Option<MaybeRuntimeSpec<'a>>,
    },
    #[serde(rename = "newBlock")]
    NewBlock {
        #[serde(rename = "blockHash")]
        block_hash: HashHexString,
        #[serde(rename = "parentBlockHash")]
        parent_block_hash: HashHexString,
        #[serde(rename = "newRuntime", borrow)]
        // TODO: must not be present if runtime_updates: false
        new_runtime: Option<MaybeRuntimeSpec<'a>>,
    },
    #[serde(rename = "bestBlockChanged")]
    BestBlockChanged {
        #[serde(rename = "bestBlockHash")]
        best_block_hash: HashHexString,
    },
    #[serde(rename = "finalized")]
    Finalized {
        #[serde(rename = "finalizedBlocksHashes")]
        finalized_blocks_hashes: Vec<HashHexString>,
        #[serde(rename = "prunedBlocksHashes")]
        pruned_blocks_hashes: Vec<HashHexString>,
    },
    #[serde(rename = "stop")]
    Stop {},
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "event")]
pub enum ChainHeadBodyEvent {
    #[serde(rename = "done")]
    Done { value: Vec<HexString> },
    #[serde(rename = "inaccessible")]
    Inaccessible {},
    #[serde(rename = "disjoint")]
    Disjoint {},
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "event")]
pub enum ChainHeadCallEvent<'a> {
    #[serde(rename = "done")]
    Done { output: HexString },
    #[serde(rename = "inaccessible")]
    Inaccessible { error: &'a str },
    #[serde(rename = "error")]
    Error { error: &'a str },
    #[serde(rename = "disjoint")]
    Disjoint {},
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "event")]
pub enum ChainHeadStorageEvent {
    #[serde(rename = "done")]
    Done { value: Option<String> },
    #[serde(rename = "inaccessible")]
    Inaccessible {},
    #[serde(rename = "disjoint")]
    Disjoint {},
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "event")]
pub enum TransactionWatchEvent<'a> {
    #[serde(rename = "validated")]
    Validated {},
    #[serde(rename = "broadcasted")]
    Broadcasted {
        #[serde(rename = "numPeers")]
        num_peers: u32,
    },
    #[serde(rename = "bestChainBlockIncluded")]
    BestChainBlockIncluded {
        #[serde(rename = "block")]
        block: Option<TransactionWatchEventBlock>,
    },
    #[serde(rename = "finalized")]
    Finalized {
        #[serde(rename = "block")]
        block: TransactionWatchEventBlock,
    },
    #[serde(rename = "error")]
    Error { error: &'a str },
    #[serde(rename = "invalid")]
    Invalid { error: &'a str },
    #[serde(rename = "dropped")]
    Dropped { broadcasted: bool, error: &'a str },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TransactionWatchEventBlock {
    pub hash: HashHexString,
    pub index: NumberAsString,
}

#[derive(Debug, Clone)]
pub struct NumberAsString(pub u32);

impl serde::Serialize for NumberAsString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.to_string().serialize(serializer)
    }
}

impl<'a> serde::Deserialize<'a> for NumberAsString {
    fn deserialize<D>(deserializer: D) -> Result<NumberAsString, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        let string = String::deserialize(deserializer)?;
        match string.parse() {
            Ok(num) => Ok(NumberAsString(num)),
            Err(_) => Err(<D::Error as serde::de::Error>::invalid_value(
                serde::de::Unexpected::Other("invalid number string"),
                &"a valid number",
            )),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Header {
    #[serde(rename = "parentHash")]
    pub parent_hash: HashHexString,
    #[serde(rename = "extrinsicsRoot")]
    pub extrinsics_root: HashHexString,
    #[serde(rename = "stateRoot")]
    pub state_root: HashHexString,
    #[serde(serialize_with = "hex_num")]
    pub number: u64,
    pub digest: HeaderDigest,
}

impl Header {
    /// Creates a [`Header`] from a SCALE-encoded header.
    ///
    /// Returns an error if the encoding is incorrect.
    pub fn from_scale_encoded_header(header: &[u8]) -> Result<Header, header::Error> {
        let header = header::decode(header)?;
        Ok(Header {
            parent_hash: HashHexString(*header.parent_hash),
            extrinsics_root: HashHexString(*header.extrinsics_root),
            state_root: HashHexString(*header.state_root),
            number: header.number,
            digest: HeaderDigest {
                logs: header
                    .digest
                    .logs()
                    .map(|log| {
                        HexString(log.scale_encoding().fold(Vec::new(), |mut a, b| {
                            a.extend_from_slice(b.as_ref());
                            a
                        }))
                    })
                    .collect(),
            },
        })
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HeaderDigest {
    pub logs: Vec<HexString>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NetworkConfig {
    #[serde(rename = "totalAttempts")]
    pub total_attempts: u32,
    #[serde(rename = "maxParallel")]
    pub max_parallel: u32, // TODO: NonZeroU32?
    #[serde(rename = "timeoutMs")]
    pub timeout_ms: u32,
}

#[derive(Debug, Clone)]
pub struct RpcMethods {
    pub version: u64,
    pub methods: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum MaybeRuntimeSpec<'a> {
    #[serde(rename = "valid")]
    Valid {
        #[serde(borrow)]
        spec: RuntimeSpec<'a>,
    },
    #[serde(rename = "invalid")]
    Invalid { error: String }, // TODO: String because it's more convenient; improve
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RuntimeSpec<'a> {
    #[serde(rename = "specName")]
    pub spec_name: &'a str,
    #[serde(rename = "implName")]
    pub impl_name: &'a str,
    #[serde(rename = "authoringVersion")]
    pub authoring_version: u32,
    #[serde(rename = "specVersion")]
    pub spec_version: u32,
    #[serde(rename = "implVersion")]
    pub impl_version: u32,
    #[serde(rename = "transactionVersion", skip_serializing_if = "Option::is_none")]
    pub transaction_version: Option<u32>,
    // TODO: add `state_version`? would need a JSON-RPC API interface spec change
    pub apis: HashMap<HexString, u32, fnv::FnvBuildHasher>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RuntimeVersion<'a> {
    #[serde(rename = "specName")]
    pub spec_name: &'a str,
    #[serde(rename = "implName")]
    pub impl_name: &'a str,
    #[serde(rename = "authoringVersion")]
    pub authoring_version: u64,
    #[serde(rename = "specVersion")]
    pub spec_version: u64,
    #[serde(rename = "implVersion")]
    pub impl_version: u64,
    #[serde(rename = "transactionVersion", skip_serializing_if = "Option::is_none")]
    pub transaction_version: Option<u64>,
    #[serde(rename = "stateVersion", skip_serializing_if = "Option::is_none")]
    pub state_version: Option<u64>,
    // TODO: optimize?
    pub apis: Vec<(HexString, u32)>,
}

#[derive(Debug, Copy, Clone)]
pub struct RuntimeDispatchInfo {
    pub weight: u64,
    pub class: DispatchClass,
    pub partial_fee: u128,
}

#[derive(Debug, Copy, Clone)]
pub enum DispatchClass {
    Normal,
    Operational,
    Mandatory,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StorageChangeSet {
    pub block: HashHexString,
    pub changes: Vec<(HexString, Option<HexString>)>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum StorageQueryType {
    #[serde(rename = "value")]
    Value,
    #[serde(rename = "hash")]
    Hash,
    #[serde(rename = "size")]
    Size,
}

#[derive(Debug, Clone)]
pub struct SystemHealth {
    pub is_syncing: bool,
    pub peers: u64,
    pub should_have_peers: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SystemPeer {
    #[serde(rename = "peerId")]
    pub peer_id: String, // Example: "12D3KooWHEQXbvCzLYvc87obHV6HY4rruHz8BJ9Lw1Gg2csVfR6Z"
    pub roles: SystemPeerRole,
    #[serde(rename = "bestHash")]
    pub best_hash: HashHexString,
    #[serde(rename = "bestNumber")]
    pub best_number: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub enum SystemPeerRole {
    #[serde(rename = "AUTHORITY")]
    Authority,
    #[serde(rename = "FULL")]
    Full,
    #[serde(rename = "LIGHT")]
    Light,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum TransactionStatus {
    Future,
    Ready,
    Broadcast(Vec<String>), // Base58 PeerIds  // TODO: stronger typing
    InBlock(HashHexString),
    Retracted(HashHexString),
    FinalityTimeout(HashHexString),
    Finalized(HashHexString),
    Usurped(HashHexString),
    Dropped,
    Invalid,
}

impl serde::Serialize for HashHexString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        format!("0x{}", hex::encode(&self.0[..])).serialize(serializer)
    }
}

impl fmt::Display for HexString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", hex::encode(&self.0[..]))
    }
}

impl serde::Serialize for HexString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl serde::Serialize for RpcMethods {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(serde::Serialize)]
        struct SerdeRpcMethods<'a> {
            version: u64,
            methods: &'a [String],
        }

        SerdeRpcMethods {
            version: self.version,
            methods: &self.methods,
        }
        .serialize(serializer)
    }
}

impl serde::Serialize for Block {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(serde::Serialize)]
        struct SerdeBlock<'a> {
            block: SerdeBlockInner<'a>,
        }

        #[derive(serde::Serialize)]
        struct SerdeBlockInner<'a> {
            extrinsics: &'a [HexString],
            header: &'a Header,
            justifications: Option<Vec<Vec<Vec<u8>>>>,
        }

        SerdeBlock {
            block: SerdeBlockInner {
                extrinsics: &self.extrinsics,
                header: &self.header,
                justifications: self.justifications.as_ref().map(|list| {
                    list.iter()
                        .map(|(e, j)| vec![e.to_vec(), j.clone()])
                        .collect()
                }),
            },
        }
        .serialize(serializer)
    }
}

impl serde::Serialize for RuntimeDispatchInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(serde::Serialize)]
        struct SerdeRuntimeDispatchInfo {
            weight: u64,
            class: &'static str,
            /// Sent back as a string in order to not accidentally lose precision.
            #[serde(rename = "partialFee")]
            partial_fee: String,
        }

        SerdeRuntimeDispatchInfo {
            weight: self.weight,
            class: match self.class {
                DispatchClass::Normal => "normal",
                DispatchClass::Operational => "operational",
                DispatchClass::Mandatory => "mandatory",
            },
            partial_fee: self.partial_fee.to_string(),
        }
        .serialize(serializer)
    }
}

impl serde::Serialize for SystemHealth {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(serde::Serialize)]
        struct SerdeSystemHealth {
            #[serde(rename = "isSyncing")]
            is_syncing: bool,
            peers: u64,
            #[serde(rename = "shouldHavePeers")]
            should_have_peers: bool,
        }

        SerdeSystemHealth {
            is_syncing: self.is_syncing,
            peers: self.peers,
            should_have_peers: self.should_have_peers,
        }
        .serialize(serializer)
    }
}

fn hex_num<S>(num: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serde::Serialize::serialize(&format!("0x{:x}", *num), serializer)
}
