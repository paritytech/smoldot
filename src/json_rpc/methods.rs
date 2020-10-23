// Substrate-lite
// Copyright (C) 2019-2020  Parity Technologies (UK) Ltd.
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

/// Parses a JSON call (usually received from a JSON-RPC server).
///
/// On success, returns a JSON-encoded identifier for that request that must be passed back when
/// emitting the response.
pub fn parse_json_call(message: &str) -> Result<(&str, MethodCall), ParseError> {
    let call_def = parse::parse_call(message).map_err(ParseError::JsonRpcParse)?;

    // No notifications are supported by this server.
    let id = match call_def.id_json {
        Some(id) => id,
        None => return Err(ParseError::UnknownNotification(call_def.method.to_owned())),
    };

    let call = match MethodCall::from_defs(&call_def.method, call_def.params_json) {
        Some(call) => call,
        None => return Err(ParseError::UnknownMethod(call_def.method.to_owned())),
    };

    Ok((id, call))
}

/// Error produced by [`parse_json_call`].
#[derive(Debug, derive_more::Display)]
pub enum ParseError {
    /// Could not parse the body of the message as a valid JSON-RPC message.
    JsonRpcParse(parse::ParseError),
    /// Call concerns a method that isn't recognized.
    UnknownMethod(String),
    /// Call concerns a notification that isn't recognized.
    UnknownNotification(String),
}

/// Could not parse the body of the message as a valid JSON-RPC message.
#[derive(Debug, derive_more::Display)]
pub struct JsonRpcParseError(serde_json::Error);

/// Generates the [`MethodCall`] and [`Response`] enums based on the list of supported requests.
macro_rules! define_methods {
    ($($name:ident($($p_name:ident: $p_ty:ty),*) -> $ret_ty:ty $([$($alias:ident),*])*,)*) => {
        #[allow(non_camel_case_types)]
        #[derive(Debug, Clone)]
        pub enum MethodCall {
            $(
                $name {
                    $($p_name: $p_ty),*
                },
            )*
        }

        impl MethodCall {
            /// Returns a list of RPC method names of all the methods in the [`MethodCall`] enum.
            pub fn method_names() -> impl ExactSizeIterator<Item = &'static str> {
                [$(stringify!($name)),*].iter().copied()
            }

            fn from_defs(name: &str, params: &str) -> Option<Self> {
                #![allow(unused, unused_mut)]

                $(
                    if name == stringify!($name) $($(|| name == stringify!($alias))*)* {
                        #[derive(serde::Deserialize)]
                        struct Params {
                            $(
                                $p_name: $p_ty,
                            )*
                        }

                        if let Ok(params) = serde_json::from_str(params) {
                            let Params { $($p_name),* } = params;
                            return Some(MethodCall::$name {
                                $($p_name,)*
                            })
                        }

                        // TODO: code below is messy
                        if let Ok(params) = serde_json::from_str::<Vec<serde_json::Value>>(params) {
                            let mut n = 0;
                            $(
                                let $p_name = serde_json::from_value(params.get(n).cloned().unwrap_or(serde_json::Value::Null)).unwrap(); // TODO: don't panic
                                n += 1;
                            )*
                            return Some(MethodCall::$name {
                                $($p_name,)*
                            })
                        }

                        todo!("bad params for {} => {}", name, params) // TODO: ?
                    }
                )*

                None
            }
        }

        #[allow(non_camel_case_types)]
        #[derive(Debug, Clone)]
        pub enum Response<'a> {
            $(
                $name($ret_ty),
            )*
        }

        impl<'a> Response<'a> {
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
                        Response::$name(out) => {
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
    account_nextIndex() -> (), // TODO:
    author_hasKey() -> (), // TODO:
    author_hasSessionKeys() -> (), // TODO:
    author_insertKey() -> (), // TODO:
    author_pendingExtrinsics() -> Vec<HexString>,
    author_removeExtrinsic() -> (), // TODO:
    author_rotateKeys() -> HexString,
    author_submitAndWatchExtrinsic() -> (), // TODO:
    author_submitExtrinsic() -> (), // TODO:
    author_unwatchExtrinsic() -> (), // TODO:
    babe_epochAuthorship() -> (), // TODO:
    chain_getBlock(hash: Option<HashHexString>) -> (), // TODO: bad return type
    chain_getBlockHash(height: u64) -> HashHexString [chain_getHead], // TODO: wrong param
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
    payment_queryInfo() -> (), // TODO:
    rpc_methods() -> RpcMethods,
    state_call() -> () [state_callAt], // TODO:
    state_getKeys() -> (), // TODO:
    state_getKeysPaged(prefix: Option<HexString>, count: u32, start_key: Option<HexString>, hash: Option<HashHexString>) -> Vec<HexString> [state_getKeysPagedAt],
    state_getMetadata() -> HexString,
    state_getPairs() -> (), // TODO:
    state_getReadProof() -> (), // TODO:
    state_getRuntimeVersion() -> RuntimeVersion [chain_getRuntimeVersion],
    state_getStorage(key: HexString, hash: Option<HashHexString>) -> HexString [state_getStorageAt],
    state_getStorageHash() -> () [state_getStorageHashAt], // TODO:
    state_getStorageSize() -> () [state_getStorageSizeAt], // TODO:
    state_queryStorage() -> (), // TODO:
    state_queryStorageAt(keys: Vec<HexString>, at: Option<HashHexString>) -> Vec<StorageChangeSet>, // TODO:
    state_subscribeRuntimeVersion() -> &'a str [chain_subscribeRuntimeVersion],
    state_subscribeStorage(list: Vec<HexString>) -> &'a str,
    state_unsubscribeRuntimeVersion() -> bool [chain_unsubscribeRuntimeVersion],
    state_unsubscribeStorage(subscription: String) -> bool,
    system_accountNextIndex() -> (), // TODO:
    system_addReservedPeer() -> (), // TODO:
    system_chain() -> &'a str,
    system_chainType() -> &'a str,
    system_dryRun() -> () [system_dryRunAt], // TODO:
    system_health() -> SystemHealth,
    system_localListenAddresses() -> Vec<String>,
    system_localPeerId() -> &'a str,
    system_name() -> &'a str,
    system_networkState() -> (), // TODO:
    system_nodeRoles() -> (), // TODO:
    system_peers() -> Vec<SystemPeer>,
    system_properties() -> Box<serde_json::value::RawValue>,
    system_removeReservedPeer() -> (), // TODO:
    system_version() -> &'a str,
}

#[derive(Debug, Clone)]
pub struct HexString(pub Vec<u8>);

// TODO: not great for type in public API
impl<'a> serde::Deserialize<'a> for HexString {
    fn deserialize<D>(deserializer: D) -> Result<HexString, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        let string = String::deserialize(deserializer)?;

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

#[derive(Debug, Clone, serde::Serialize)]
pub struct Header {
    #[serde(rename = "parentHash")]
    pub parent_hash: HashHexString,
    #[serde(rename = "extrinsicsRoot")]
    pub extrinsics_root: HashHexString,
    #[serde(rename = "stateRoot")]
    pub state_root: HashHexString,
    pub number: u64,
    pub digest: HeaderDigest,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct HeaderDigest {
    pub logs: Vec<HexString>,
}

#[derive(Debug, Clone)]
pub struct RpcMethods {
    pub version: u64,
    pub methods: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RuntimeVersion {
    pub spec_name: String,
    pub impl_name: String,
    pub authoring_version: u64,
    pub spec_version: u64,
    pub impl_version: u64,
    pub transaction_version: u64,
    // TODO: apis missing
}

#[derive(Debug, Clone, serde::Serialize)]
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
pub struct SystemPeer {
    #[serde(rename = "peerId")]
    pub peer_id: String,
    pub roles: String,
    #[serde(rename = "bestHash")]
    pub best_hash: HashHexString,
    #[serde(rename = "bestNumber")]
    pub best_number: u64,
}

impl serde::Serialize for HashHexString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        format!("0x{}", hex::encode(&self.0[..])).serialize(serializer)
    }
}

impl serde::Serialize for HexString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        format!("0x{}", hex::encode(&self.0[..])).serialize(serializer)
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

impl serde::Serialize for RuntimeVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // TODO: not sure about the camelCasing
        #[derive(serde::Serialize)]
        struct SerdeRuntimeVersion<'a> {
            spec_name: &'a str,
            impl_name: &'a str,
            authoring_version: u64,
            spec_version: u64,
            impl_version: u64,
            transaction_version: u64,
        }

        SerdeRuntimeVersion {
            spec_name: &self.spec_name,
            impl_name: &self.impl_name,
            authoring_version: self.authoring_version,
            spec_version: self.spec_version,
            impl_version: self.impl_version,
            transaction_version: self.transaction_version,
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
