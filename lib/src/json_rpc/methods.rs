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
use crate::{header, identity::ss58};

use alloc::{
    borrow::Cow,
    boxed::Box,
    format,
    string::{String, ToString as _},
    vec,
    vec::Vec,
};
use core::fmt;
use hashbrown::HashMap;

/// Parses a JSON call (usually sent from a JSON-RPC client and received by a JSON-RPC server).
///
/// On success, returns a JSON-encoded identifier for that request that must be passed back when
/// emitting the response.
pub fn parse_jsonrpc_client_to_server(
    message: &'_ str,
) -> Result<(&'_ str, MethodCall<'_>), ParseClientToServerError<'_>> {
    let call_def = parse::parse_request(message).map_err(ParseClientToServerError::JsonRpcParse)?;

    // No notification is supported by this server. If the `id` field is missing in the request,
    // assuming that this is a notification and return an appropriate error.
    let request_id = match call_def.id_json {
        Some(id) => id,
        None => {
            return Err(ParseClientToServerError::UnknownNotification {
                notification_name: call_def.method,
            });
        }
    };

    let call = match MethodCall::from_defs(call_def.method, call_def.params_json) {
        Ok(c) => c,
        Err(error) => return Err(ParseClientToServerError::Method { request_id, error }),
    };

    Ok((request_id, call))
}

/// Error produced by [`parse_jsonrpc_client_to_server`].
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum ParseClientToServerError<'a> {
    /// Could not parse the body of the message as a valid JSON-RPC message.
    JsonRpcParse(parse::ParseError),
    /// Call concerns a notification that isn't recognized.
    #[display("Call concerns a notification that isn't recognized: {notification_name:?}.")]
    UnknownNotification {
        /// Unknown notification.
        notification_name: &'a str,
    },
    /// JSON-RPC request is valid, but there is a problem related to the method being called.
    #[display("{error}")]
    Method {
        /// Identifier of the request sent by the user.
        request_id: &'a str,
        /// Problem that happens.
        // TODO: this can't be marked as error source because sources must have 'static lifetime; evaluate trade-offs
        error: MethodError<'a>,
    },
}

/// Parses a JSON notification.
pub fn parse_notification(
    message: &'_ str,
) -> Result<ServerToClient<'_>, ParseNotificationError<'_>> {
    let call_def = parse::parse_request(message).map_err(ParseNotificationError::JsonRpcParse)?;
    let call = ServerToClient::from_defs(call_def.method, call_def.params_json)
        .map_err(ParseNotificationError::Method)?;
    Ok(call)
}

/// Error produced by [`parse_notification`].
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum ParseNotificationError<'a> {
    /// Could not parse the body of the message as a valid JSON-RPC message.
    #[display("{_0}")]
    JsonRpcParse(parse::ParseError),
    /// JSON-RPC request is valid, but there is a problem related to the method being called.
    #[display("{_0}")]
    // TODO: this can't be marked as error source because sources must have 'static lifetime; evaluate trade-offs
    Method(#[error(not(source))] MethodError<'a>),
}

/// Builds a JSON call, to send it to a JSON-RPC server.
///
/// # Panic
///
/// Panics if the `id_json` isn't valid JSON.
///
pub fn build_json_call_object_parameters(id_json: Option<&str>, method: MethodCall) -> String {
    method.to_json_request_object_parameters(id_json)
}

/// See [`ParseClientToServerError::Method`] or [`ParseNotificationError::Method`].
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum MethodError<'a> {
    /// Call concerns a method that isn't recognized.
    #[display("Call concerns a method that isn't recognized: {method_name:?}")]
    UnknownMethod {
        /// Name of the unrecognized method.
        method_name: &'a str,
    },
    /// Format the parameters is plain invalid.
    #[display("Invalid parameters format when calling {rpc_method}")]
    InvalidParametersFormat {
        /// Name of the JSON-RPC method that was attempted to be called.
        rpc_method: &'static str,
    },
    /// Too many parameters have been passed to the function.
    #[display("{rpc_method} expects {expected} parameters, but got {actual}")]
    TooManyParameters {
        /// Name of the JSON-RPC method that was attempted to be called.
        rpc_method: &'static str,
        /// Number of parameters that are expected to be received.
        expected: usize,
        /// Number of parameters actually received.
        actual: usize,
    },
    /// One of the parameters of the function call is invalid.
    #[display("Parameter of index {parameter_index} is invalid when calling {rpc_method}: {error}")]
    InvalidParameter {
        /// Name of the JSON-RPC method that was attempted to be called.
        rpc_method: &'static str,
        /// 0-based index of the parameter whose format is invalid.
        parameter_index: usize,
        /// Reason why it failed.
        #[error(source)]
        error: InvalidParameterError,
    },
    /// The parameters of the function call are missing.
    MissingParameters {
        /// Name of the JSON-RPC method that was attempted to be called.
        rpc_method: &'static str,
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
                MethodError::UnknownMethod { .. } => parse::ErrorResponse::MethodNotFound,
                MethodError::InvalidParametersFormat { .. }
                | MethodError::TooManyParameters { .. }
                | MethodError::InvalidParameter { .. }
                | MethodError::MissingParameters { .. } => parse::ErrorResponse::InvalidParams,
            },
            None,
        )
    }
}

/// The parameter of a function call is invalid.
#[derive(Debug, derive_more::Display, derive_more::Error)]
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

            /// Builds a JSON request, to send it to a JSON-RPC server.
            ///
            /// # Panic
            ///
            /// Panics if the `id_json` isn't valid JSON.
            ///
            pub fn to_json_request_object_parameters(&self, id_json: Option<&str>) -> String {
                parse::build_request(&parse::Request {
                    id_json,
                    method: self.name(),
                    // Note that we never skip the `params` field, even if empty. This is an
                    // arbitrary choice.
                    params_json: Some(&self.params_to_json_object()),
                })
            }

            fn from_defs(name: &'a str, params: Option<&'a str>) -> Result<Self, MethodError<'a>> {
                #![allow(unused, unused_mut)]

                $(
                    if name == stringify!($name) $($(|| name == stringify!($alias))*)* {
                        // First, if parameters are missing (i.e. the `params` field isn't there),
                        // accept the call provided there is no parameter.
                        if params.is_none() {
                            // TODO: use `count(p_name) when stable; https://rust-lang.github.io/rfcs/3086-macro-metavar-expr.html
                            if !has_params!($($p_name),*) {
                                return Ok($rq_name::$name {
                                    // This code can't be reached if there is any parameter, thus
                                    // `unreachable!()` is never called.
                                    $($p_name: unreachable!(),)*
                                })
                            } else {
                                return Err(MethodError::MissingParameters {
                                    rpc_method: stringify!($name),
                                });
                            }
                        }

                        // Then, try parse parameters as if they were passed by name in a map.
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
                            #[serde(borrow, skip)]
                            _dummy: core::marker::PhantomData<&'a ()>,
                        }
                        if let Some(Ok(params)) = params.as_ref().map(|p| serde_json::from_str(p)) {
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
                        if let Some(Ok(params)) = params.as_ref().map(|p| serde_json::from_str::<Vec<&'a serde_json::value::RawValue>>(p)) {
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

                Err(MethodError::UnknownMethod { method_name: name })
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

macro_rules! has_params {
    () => {
        false
    };
    ($p1:ident $(, $p:ident)*) => {
        true
    };
}

// Note: `&str` shouldn't be used, because of https://github.com/serde-rs/json/issues/742
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
    author_submitAndWatchExtrinsic(transaction: HexString) -> Cow<'a, str>,
    author_submitExtrinsic(transaction: HexString) -> HashHexString,
    author_unwatchExtrinsic(subscription: Cow<'a, str>) -> bool,
    babe_epochAuthorship() -> (), // TODO:
    chain_getBlock(hash: Option<HashHexString>) -> Block,
    chain_getBlockHash(height: Option<u64>) -> HashHexString [chain_getHead],
    chain_getFinalizedHead() -> HashHexString [chain_getFinalisedHead],
    chain_getHeader(hash: Option<HashHexString>) -> Header, // TODO: return type is guessed
    chain_subscribeAllHeads() -> Cow<'a, str>,
    chain_subscribeFinalizedHeads() -> Cow<'a, str> [chain_subscribeFinalisedHeads],
    chain_subscribeNewHeads() -> Cow<'a, str> [subscribe_newHead, chain_subscribeNewHead],
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
    state_call(name: Cow<'a, str>, parameters: HexString, hash: Option<HashHexString>) -> HexString [state_callAt],
    state_getKeys(prefix: HexString, hash: Option<HashHexString>) -> Vec<HexString>,
    state_getKeysPaged(prefix: Option<HexString>, count: u32, start_key: Option<HexString>, hash: Option<HashHexString>) -> Vec<HexString> [state_getKeysPagedAt],
    state_getMetadata(hash: Option<HashHexString>) -> HexString,
    state_getPairs() -> (), // TODO:
    state_getReadProof(keys: Vec<HexString>, at: Option<HashHexString>) -> ReadProof,
    state_getRuntimeVersion(at: Option<HashHexString>) -> RuntimeVersion<'a> [chain_getRuntimeVersion],
    state_getStorage(key: HexString, hash: Option<HashHexString>) -> HexString [state_getStorageAt],
    state_getStorageHash() -> () [state_getStorageHashAt], // TODO:
    state_getStorageSize() -> () [state_getStorageSizeAt], // TODO:
    state_queryStorage() -> (), // TODO:
    state_queryStorageAt(keys: Vec<HexString>, at: Option<HashHexString>) -> Vec<StorageChangeSet>, // TODO:
    state_subscribeRuntimeVersion() -> Cow<'a, str> [chain_subscribeRuntimeVersion],
    state_subscribeStorage(list: Vec<HexString>) -> Cow<'a, str>,
    state_unsubscribeRuntimeVersion(subscription: Cow<'a, str>) -> bool [chain_unsubscribeRuntimeVersion],
    state_unsubscribeStorage(subscription: Cow<'a, str>) -> bool,
    system_accountNextIndex(account: AccountId) -> u64,
    system_addReservedPeer() -> (), // TODO:
    system_chain() -> Cow<'a, str>,
    system_chainType() -> Cow<'a, str>,
    system_dryRun() -> () [system_dryRunAt], // TODO:
    system_health() -> SystemHealth,
    system_localListenAddresses() -> Vec<String>,
    /// Returns the Base58 encoding of the network identity of the node on the peer-to-peer network.
    system_localPeerId() -> Cow<'a, str>,
    /// Returns, as an opaque string, the name of the client serving these JSON-RPC requests.
    system_name() -> Cow<'a, str>,
    system_networkState() -> (), // TODO:
    system_nodeRoles() -> Cow<'a, [NodeRole]>,
    system_peers() -> Vec<SystemPeer>,
    system_properties() -> Box<serde_json::value::RawValue>,
    system_removeReservedPeer() -> (), // TODO:
    /// Returns, as an opaque string, the version of the client serving these JSON-RPC requests.
    system_version() -> Cow<'a, str>,

    /// Submit a new statement to the store and broadcast to peers.
    statement_submit(encoded: HexString) -> StatementSubmitResult,
    /// Subscribe to statements matching the given filter. Returns subscription ID.
    statement_subscribe(filter: crate::network::codec::TopicFilter) -> Cow<'a, str>,
    /// Unsubscribe from statement notifications.
    statement_unsubscribe(subscription: String) -> bool,

    // The functions below are experimental and are defined in the document https://github.com/paritytech/json-rpc-interface-spec/
    chainHead_v1_body(
        #[rename = "followSubscription"] follow_subscription: Cow<'a, str>,
        hash: HashHexString
    ) -> ChainHeadBodyCallReturn<'a>,
    chainHead_v1_call(
        #[rename = "followSubscription"] follow_subscription: Cow<'a, str>,
        hash: HashHexString,
        function: Cow<'a, str>,
        #[rename = "callParameters"] call_parameters: HexString
    ) -> ChainHeadBodyCallReturn<'a>,
    chainHead_v1_follow(
        #[rename = "withRuntime"] with_runtime: bool
    ) -> Cow<'a, str>,
    chainHead_v1_header(
        #[rename = "followSubscription"] follow_subscription: Cow<'a, str>,
        hash: HashHexString
    ) -> Option<HexString>,
    chainHead_v1_stopOperation(
        #[rename = "followSubscription"] follow_subscription: Cow<'a, str>,
        #[rename = "operationId"] operation_id: Cow<'a, str>
    ) -> (),
    chainHead_v1_storage(
        #[rename = "followSubscription"] follow_subscription: Cow<'a, str>,
        hash: HashHexString,
        items: Vec<ChainHeadStorageRequestItem>,
        #[rename = "childTrie"] child_trie: Option<HexString>
    ) -> ChainHeadStorageReturn<'a>,
    chainHead_v1_continue(
        #[rename = "followSubscription"] follow_subscription: Cow<'a, str>,
        #[rename = "operationId"] operation_id: Cow<'a, str>
    ) -> (),
    chainHead_v1_unfollow(
        #[rename = "followSubscription"] follow_subscription: Cow<'a, str>
    ) -> (),
    chainHead_v1_unpin(
        #[rename = "followSubscription"] follow_subscription: Cow<'a, str>,
        #[rename = "hashOrHashes"] hash_or_hashes: HashHexStringSingleOrArray
    ) -> (),

    chainSpec_v1_chainName() -> Cow<'a, str>,
    chainSpec_v1_genesisHash() -> HashHexString,
    chainSpec_v1_properties() -> Box<serde_json::value::RawValue>,

    sudo_unstable_p2pDiscover(multiaddr: Cow<'a, str>) -> (),
    sudo_unstable_version() -> Cow<'a, str>,

    transaction_v1_broadcast(transaction: HexString) -> Cow<'a, str>,
    transaction_v1_stop(#[rename = "operationId"] operation_id: Cow<'a, str>) -> (),

    transactionWatch_v1_submitAndWatch(transaction: HexString) -> Cow<'a, str>,
    transactionWatch_v1_unwatch(subscription: Cow<'a, str>) -> (),

    // These functions are a custom addition in smoldot. As of the writing of this comment, there
    // is no plan to standardize them. See <https://github.com/paritytech/smoldot/issues/2245> and
    // <https://github.com/paritytech/smoldot/issues/2456>.
    sudo_network_unstable_watch() -> Cow<'a, str>,
    sudo_network_unstable_unwatch(subscription: Cow<'a, str>) -> (),
    chainHead_unstable_finalizedDatabase(#[rename = "maxSizeBytes"] max_size_bytes: Option<u64>) -> Cow<'a, str>,
}

define_methods! {
    ServerToClient,
    ServerToClientResponse, // TODO: unnecessary
    author_extrinsicUpdate(subscription: Cow<'a, str>, result: TransactionStatus) -> (),
    chain_finalizedHead(subscription: Cow<'a, str>, result: Header) -> (),
    chain_newHead(subscription: Cow<'a, str>, result: Header) -> (),
    chain_allHead(subscription: Cow<'a, str>, result: Header) -> (),
    state_runtimeVersion(subscription: Cow<'a, str>, result: Option<RuntimeVersion<'a>>) -> (), // TODO: the Option is a custom addition
    state_storage(subscription: Cow<'a, str>, result: StorageChangeSet) -> (),

    // The functions below are experimental and are defined in the document https://github.com/paritytech/json-rpc-interface-spec/
    chainHead_v1_followEvent(subscription: Cow<'a, str>, result: FollowEvent<'a>) -> (),
    transactionWatch_v1_watchEvent(subscription: Cow<'a, str>, result: TransactionWatchEvent<'a>) -> (),

    // This function is a custom addition in smoldot. As of the writing of this comment, there is
    // no plan to standardize it. See https://github.com/paritytech/smoldot/issues/2245.
    sudo_networkState_event(subscription: Cow<'a, str>, result: NetworkEvent) -> (),

    // Statement notification sent when a statement matching subscribed topics is received.
    statement_notification(subscription: Cow<'a, str>, statement: HexString) -> (),
}

#[derive(Clone, PartialEq, Eq, Hash)]
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

impl fmt::Debug for HexString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", hex::encode(&self.0))
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum HashHexStringSingleOrArray {
    Single(HashHexString),
    Array(Vec<HashHexString>),
}

/// Removes the length prefix at the beginning of `metadata`. Used for the `Metadata_metadata`
/// JSON-RPC request. Returns an error if there is no valid length prefix.
pub fn remove_metadata_length_prefix(
    metadata: &[u8],
) -> Result<&[u8], RemoveMetadataLengthPrefixError> {
    let (after_prefix, length) = crate::util::nom_scale_compact_usize(metadata).map_err(
        |_: nom::Err<nom::error::Error<&[u8]>>| {
            RemoveMetadataLengthPrefixError::InvalidLengthPrefix
        },
    )?;

    // Verify that the length prefix indeed matches the metadata's length.
    if length != after_prefix.len() {
        return Err(RemoveMetadataLengthPrefixError::LengthMismatch);
    }

    Ok(after_prefix)
}

/// Error potentially returned by [`remove_metadata_length_prefix`].
#[derive(Debug, Clone, derive_more::Display, derive_more::Error)]
pub enum RemoveMetadataLengthPrefixError {
    /// The length prefix at the beginning of the metadata is invalid.
    InvalidLengthPrefix,
    /// Length indicated by the length prefix doesn't match the size of the metadata.
    LengthMismatch,
}

/// Contains the public key of an account.
///
/// The deserialization involves decoding an SS58 address into this public key.
#[derive(Debug, Clone)]
pub struct AccountId(pub Vec<u8>);

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
        let decoded = match ss58::decode(string) {
            Ok(d) => d,
            Err(err) => return Err(serde::de::Error::custom(err.to_string())),
        };

        // TODO: check the prefix against the one of the current chain?

        Ok(AccountId(decoded.public_key.as_ref().to_vec()))
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
        #[serde(rename = "finalizedBlockHashes")]
        finalized_block_hashes: Vec<HashHexString>,
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
        #[serde(rename = "newRuntime")]
        // TODO: must not be present if with_runtime: false
        new_runtime: Option<MaybeRuntimeSpec<'a>>,
    },
    #[serde(rename = "bestBlockChanged")]
    BestBlockChanged {
        #[serde(rename = "bestBlockHash")]
        best_block_hash: HashHexString,
    },
    #[serde(rename = "finalized")]
    Finalized {
        #[serde(rename = "finalizedBlockHashes")]
        finalized_blocks_hashes: Vec<HashHexString>,
        #[serde(rename = "prunedBlockHashes")]
        pruned_blocks_hashes: Vec<HashHexString>,
    },
    #[serde(rename = "operationBodyDone")]
    OperationBodyDone {
        #[serde(rename = "operationId")]
        operation_id: Cow<'a, str>,
        value: Vec<HexString>,
    },
    #[serde(rename = "operationCallDone")]
    OperationCallDone {
        #[serde(rename = "operationId")]
        operation_id: Cow<'a, str>,
        output: HexString,
    },
    #[serde(rename = "operationInaccessible")]
    OperationInaccessible {
        #[serde(rename = "operationId")]
        operation_id: Cow<'a, str>,
    },
    #[serde(rename = "operationStorageItems")]
    OperationStorageItems {
        #[serde(rename = "operationId")]
        operation_id: Cow<'a, str>,
        items: Vec<ChainHeadStorageResponseItem>,
    },
    #[serde(rename = "operationStorageDone")]
    OperationStorageDone {
        #[serde(rename = "operationId")]
        operation_id: Cow<'a, str>,
    },
    #[serde(rename = "operationWaitingForContinue")]
    OperationWaitingForContinue,
    #[serde(rename = "operationError")]
    OperationError {
        #[serde(rename = "operationId")]
        operation_id: Cow<'a, str>,
        error: Cow<'a, str>,
    },
    #[serde(rename = "stop")]
    Stop {},
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "result")]
pub enum ChainHeadBodyCallReturn<'a> {
    #[serde(rename = "started")]
    Started {
        #[serde(rename = "operationId")]
        operation_id: Cow<'a, str>,
    },
    #[serde(rename = "limitReached")]
    LimitReached {},
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "result")]
pub enum ChainHeadStorageReturn<'a> {
    #[serde(rename = "started")]
    Started {
        #[serde(rename = "operationId")]
        operation_id: Cow<'a, str>,
        #[serde(rename = "discardedItems")]
        discarded_items: usize,
    },
    #[serde(rename = "limitReached")]
    LimitReached {},
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChainHeadStorageRequestItem {
    pub key: HexString,
    #[serde(rename = "type")]
    pub ty: ChainHeadStorageType,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChainHeadStorageResponseItem {
    pub key: HexString,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<HexString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<HexString>,
    #[serde(
        rename = "closestDescendantMerkleValue",
        skip_serializing_if = "Option::is_none"
    )]
    pub closest_descendant_merkle_value: Option<HexString>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ChainHeadStorageType {
    #[serde(rename = "value")]
    Value,
    #[serde(rename = "hash")]
    Hash,
    #[serde(rename = "closestDescendantMerkleValue")]
    ClosestDescendantMerkleValue,
    #[serde(rename = "descendantsValues")]
    DescendantsValues,
    #[serde(rename = "descendantsHashes")]
    DescendantsHashes,
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
    Error { error: Cow<'a, str> },
    #[serde(rename = "invalid")]
    Invalid { error: Cow<'a, str> },
    #[serde(rename = "dropped")]
    Dropped {
        broadcasted: bool,
        error: Cow<'a, str>,
    },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TransactionWatchEventBlock {
    pub hash: HashHexString,
    pub index: u32,
}

/// Unstable event.
/// See <https://github.com/paritytech/smoldot/issues/2245>.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "event")]
pub enum NetworkEvent {
    #[serde(rename = "connectionState")]
    ConnectionState {
        #[serde(rename = "connectionId")]
        connection_id: u32,
        #[serde(rename = "targetPeerId", skip_serializing_if = "Option::is_none")]
        target_peer_id: Option<String>,
        #[serde(rename = "targetMultiaddr")]
        target_multiaddr: String,
        status: NetworkEventStatus,
        direction: NetworkEventDirection,
        when: u64,
    },
    #[serde(rename = "substreamState")]
    SubstreamState {
        #[serde(rename = "connectionId")]
        connection_id: u32,
        #[serde(rename = "substreamId")]
        substream_id: u32,
        status: NetworkEventStatus,
        #[serde(rename = "protocolName")]
        protocol_name: String,
        direction: NetworkEventDirection,
        when: u64,
    },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum NetworkEventStatus {
    #[serde(rename = "connecting")]
    Connecting,
    #[serde(rename = "open")]
    Open,
    #[serde(rename = "closed")]
    Close,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum NetworkEventDirection {
    #[serde(rename = "in")]
    In,
    #[serde(rename = "out")]
    Out,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Header {
    #[serde(rename = "parentHash")]
    pub parent_hash: HashHexString,
    #[serde(rename = "extrinsicsRoot")]
    pub extrinsics_root: HashHexString,
    #[serde(rename = "stateRoot")]
    pub state_root: HashHexString,
    #[serde(
        serialize_with = "hex_num_serialize",
        deserialize_with = "hex_num_deserialize"
    )]
    pub number: u64,
    pub digest: HeaderDigest,
}

impl Header {
    /// Creates a [`Header`] from a SCALE-encoded header.
    ///
    /// Returns an error if the encoding is incorrect.
    pub fn from_scale_encoded_header(
        header: &[u8],
        block_number_bytes: usize,
    ) -> Result<Header, header::Error> {
        let header = header::decode(header, block_number_bytes)?;
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
                        HexString(log.scale_encoding(block_number_bytes).fold(
                            Vec::new(),
                            |mut a, b| {
                                a.extend_from_slice(b.as_ref());
                                a
                            },
                        ))
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

#[derive(Debug, Clone)]
pub struct RpcMethods {
    pub methods: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum MaybeRuntimeSpec<'a> {
    #[serde(rename = "valid")]
    Valid { spec: RuntimeSpec<'a> },
    #[serde(rename = "invalid")]
    Invalid { error: String }, // TODO: String because it's more convenient; improve
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum NodeRole {
    // Note that "Light" isn't in the Substrate source code and is a custom addition.
    #[serde(rename = "Light")]
    Light,
    #[serde(rename = "Full")]
    Full,
    #[serde(rename = "Authority")]
    Authority,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RuntimeSpec<'a> {
    #[serde(rename = "specName")]
    pub spec_name: Cow<'a, str>,
    #[serde(rename = "implName")]
    pub impl_name: Cow<'a, str>,
    #[serde(rename = "specVersion")]
    pub spec_version: u32,
    #[serde(rename = "implVersion")]
    pub impl_version: u32,
    #[serde(rename = "transactionVersion", skip_serializing_if = "Option::is_none")]
    pub transaction_version: Option<u32>,
    pub apis: HashMap<HexString, u32, fnv::FnvBuildHasher>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RuntimeVersion<'a> {
    #[serde(rename = "specName")]
    pub spec_name: Cow<'a, str>,
    #[serde(rename = "implName")]
    pub impl_name: Cow<'a, str>,
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

#[derive(Debug, Clone)]
pub struct SystemHealth {
    pub is_syncing: bool,
    pub peers: u64,
    pub should_have_peers: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ReadProof {
    pub at: HashHexString,
    pub proof: Vec<HexString>,
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

/// Result of submitting a statement to the statement store.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum StatementSubmitResult {
    /// Statement was accepted and broadcasted to peers.
    #[serde(rename = "ok_broadcast")]
    OkBroadcast {
        /// Number of peers the statement was successfully sent to.
        sent: usize,
        /// Total number of peers attempted.
        total: usize,
    },
    /// Statement was accepted but will not be broadcast (e.g., duplicate).
    #[serde(rename = "ok_ignore")]
    OkIgnore,
    /// Statement was invalid or rejected.
    #[serde(rename = "error")]
    Error(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum TransactionStatus {
    #[serde(rename = "future")]
    Future,
    #[serde(rename = "ready")]
    Ready,
    #[serde(rename = "broadcast")]
    Broadcast(Vec<String>), // Base58 PeerIds  // TODO: stronger typing
    #[serde(rename = "inBlock")]
    InBlock(HashHexString),
    #[serde(rename = "retracted")]
    Retracted(HashHexString),
    #[serde(rename = "finalityTimeout")]
    FinalityTimeout(HashHexString),
    #[serde(rename = "finalized")]
    Finalized(HashHexString),
    #[serde(rename = "usurped")]
    Usurped(HashHexString),
    #[serde(rename = "dropped")]
    Dropped,
    #[serde(rename = "invalid")]
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
            methods: &'a [String],
        }

        SerdeRpcMethods {
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

#[derive(serde::Serialize, serde::Deserialize)]
struct SerdeSystemHealth {
    #[serde(rename = "isSyncing")]
    is_syncing: bool,
    peers: u64,
    #[serde(rename = "shouldHavePeers")]
    should_have_peers: bool,
}

impl serde::Serialize for SystemHealth {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        SerdeSystemHealth {
            is_syncing: self.is_syncing,
            peers: self.peers,
            should_have_peers: self.should_have_peers,
        }
        .serialize(serializer)
    }
}

impl<'a> serde::Deserialize<'a> for SystemHealth {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        let h: SerdeSystemHealth = serde::Deserialize::deserialize(deserializer)?;
        Ok(SystemHealth {
            is_syncing: h.is_syncing,
            peers: h.peers,
            should_have_peers: h.should_have_peers,
        })
    }
}

fn hex_num_serialize<S>(num: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serde::Serialize::serialize(&format!("0x{:x}", *num), serializer)
}

fn hex_num_deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let mut string: String = serde::Deserialize::deserialize(deserializer)?;
    if !string.starts_with("0x") {
        return Err(serde::de::Error::custom("number doesn't start with 0x"));
    }
    if string.len() % 2 != 0 {
        string.insert(2, '0');
    }
    let decoded = hex::decode(&string[2..]).map_err(serde::de::Error::custom)?;
    if decoded.len() > 8 {
        return Err(serde::de::Error::custom("number overflow"));
    }

    let mut num = [0u8; 8];
    num[..decoded.len()].copy_from_slice(&decoded);
    Ok(u64::from_be_bytes(num))
}

#[cfg(test)]
mod tests {
    #[test]
    fn no_params_accepted() {
        // No `params` field in the request.
        let (_, call) = super::parse_jsonrpc_client_to_server(
            r#"{"jsonrpc":"2.0","id":2,"method":"chainSpec_v1_chainName"}"#,
        )
        .unwrap();

        assert!(matches!(call, super::MethodCall::chainSpec_v1_chainName {}));
    }

    #[test]
    fn no_params_refused() {
        // No `params` field in the request.
        let err = super::parse_jsonrpc_client_to_server(
            r#"{"jsonrpc":"2.0","id":2,"method":"chainHead_v1_follow"}"#,
        );

        assert!(matches!(
            err,
            Err(super::ParseClientToServerError::Method {
                request_id: "2",
                error: super::MethodError::MissingParameters {
                    rpc_method: "chainHead_v1_follow"
                }
            })
        ));
    }

    #[test]
    fn statement_submit_parse_valid() {
        let (id, call) = super::parse_jsonrpc_client_to_server(
            r#"{"jsonrpc":"2.0","id":1,"method":"statement_submit","params":["0x1234"]}"#,
        )
        .unwrap();

        assert_eq!(id, "1");
        assert!(matches!(call, super::MethodCall::statement_submit { .. }));
    }

    #[test]
    fn statement_submit_result_ok_broadcast_serialization() {
        let result = super::StatementSubmitResult::OkBroadcast { sent: 5, total: 10 };
        let serialized = serde_json::to_string(&result).unwrap();
        assert_eq!(serialized, r#"{"ok_broadcast":{"sent":5,"total":10}}"#);

        let deserialized: super::StatementSubmitResult = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(
            deserialized,
            super::StatementSubmitResult::OkBroadcast { sent: 5, total: 10 }
        ));
    }

    #[test]
    fn statement_subscribe_parse_any() {
        let (id, call) = super::parse_jsonrpc_client_to_server(
            r#"{"jsonrpc":"2.0","id":2,"method":"statement_subscribe","params":[{"type":"any"}]}"#,
        )
        .unwrap();

        assert_eq!(id, "2");
        assert!(matches!(
            call,
            super::MethodCall::statement_subscribe {
                filter: crate::network::codec::TopicFilter::Any
            }
        ));
    }

    #[test]
    fn statement_subscribe_parse_match_any() {
        let (id, call) = super::parse_jsonrpc_client_to_server(
            r#"{"jsonrpc":"2.0","id":2,"method":"statement_subscribe","params":[{"type":"match_any","topics":["0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"]}]}"#,
        )
        .unwrap();

        assert_eq!(id, "2");
        assert!(matches!(
            call,
            super::MethodCall::statement_subscribe {
                filter: crate::network::codec::TopicFilter::MatchAny(_)
            }
        ));
    }

    #[test]
    fn statement_subscribe_parse_match_all() {
        let (id, call) = super::parse_jsonrpc_client_to_server(
            r#"{"jsonrpc":"2.0","id":2,"method":"statement_subscribe","params":[{"type":"match_all","topics":["0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"]}]}"#,
        )
        .unwrap();

        assert_eq!(id, "2");
        assert!(matches!(
            call,
            super::MethodCall::statement_subscribe {
                filter: crate::network::codec::TopicFilter::MatchAll(_)
            }
        ));
    }

    #[test]
    fn statement_unsubscribe_parse_valid() {
        let (id, call) = super::parse_jsonrpc_client_to_server(
            r#"{"jsonrpc":"2.0","id":4,"method":"statement_unsubscribe","params":["sub123"]}"#,
        )
        .unwrap();

        assert_eq!(id, "4");
        assert!(matches!(
            call,
            super::MethodCall::statement_unsubscribe { .. }
        ));
    }
}
