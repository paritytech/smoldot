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

//! Parse JSON-RPC method calls and notifications, and build responses messages.

/// Parses a JSON-encoded RPC method call or notification.
pub fn parse_call(call_json: &str) -> Result<Call, ParseError> {
    let serde_call: SerdeCall = serde_json::from_str(call_json).map_err(ParseError)?;

    if let Some(id) = &serde_call.id {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        #[serde(untagged)]
        enum SerdeId {
            Num(u64),
            Str(String),
        }

        if let Err(err) = serde_json::from_str::<SerdeId>(id.get()) {
            return Err(ParseError(err));
        }
    }

    Ok(Call {
        id_json: serde_call.id.map(|v| v.get()),
        method: serde_call.method,
        params_json: serde_call.params.get(),
    })
}

/// Parsed JSON-RPC call.
#[derive(Debug)]
pub struct Call<'a> {
    /// JSON-formatted identifier of the request. `None` for notifications.
    pub id_json: Option<&'a str>,
    /// Name of the method that is being called.
    pub method: &'a str,
    /// JSON-formatted list of parameters.
    pub params_json: &'a str,
}

/// Error while parsing a call.
#[derive(Debug, derive_more::Display)]
pub struct ParseError(serde_json::Error);

/// Builds a JSON response.
///
/// `id_json` must be the JSON-formatted identifier of the request, found in [`Call::id_json`].
/// `result_json` must be the JSON-formatted result of the request.
///
/// # Example
///
/// ```
/// # use substrate_lite::json_rpc::parse;
/// let result_json = parse::build_success_response("27", r#"[1, 2, {"foo":"bar"}]"#);
///
/// // Note that the output is guaranteed to be stable.
/// assert_eq!(result_json, r#"{"jsonrpc":"2.0","id":27,"result":[1, 2, {"foo":"bar"}]}"#);
/// ```
///
/// # Panic
///
/// Panics if `id_json` or `result_json` aren't valid JSON.
///
pub fn build_success_response(id_json: &str, result_json: &str) -> String {
    serde_json::to_string(&SerdeSuccess {
        jsonrpc: SerdeVersion::V2,
        id: serde_json::from_str(id_json).expect("invalid id_json"),
        result: serde_json::from_str(result_json).expect("invalid result_json"),
    })
    .unwrap()
}

/// Builds a JSON event to a subscription.
///
/// `method` must be the name of the method that was used for the subscription. `id` must
/// be the identifier of the subscription, as previously attributed by the server and returned to
/// the client. `result_json` must be the JSON-formatted event.
///
/// # Panic
///
/// Panics if `result_json` isn't valid JSON.
///
pub fn build_subscription_event(method: &str, id: &str, result_json: &str) -> String {
    serde_json::to_string(&SerdeSubscriptionEvent {
        jsonrpc: SerdeVersion::V2,
        method,
        params: SerdeSubscriptionEventParams {
            subscription: id,
            result: serde_json::from_str(result_json).expect("invalid result_json"),
        },
    })
    .unwrap()
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct SerdeCall<'a> {
    jsonrpc: SerdeVersion,
    #[serde(borrow)]
    id: Option<&'a serde_json::value::RawValue>,
    #[serde(borrow)]
    method: &'a str,
    #[serde(borrow)]
    params: &'a serde_json::value::RawValue,
}

#[derive(Debug, PartialEq, Clone, Copy, Hash, Eq)]
enum SerdeVersion {
    V2,
}

impl serde::Serialize for SerdeVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match *self {
            SerdeVersion::V2 => "2.0".serialize(serializer),
        }
    }
}

impl<'a> serde::Deserialize<'a> for SerdeVersion {
    fn deserialize<D>(deserializer: D) -> Result<SerdeVersion, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        let string = <&str>::deserialize(deserializer)?;
        if string != "2.0" {
            return Err(serde::de::Error::custom("unknown version"));
        }
        Ok(SerdeVersion::V2)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SerdeSuccess<'a> {
    jsonrpc: SerdeVersion,
    #[serde(borrow)]
    id: &'a serde_json::value::RawValue,
    result: &'a serde_json::value::RawValue,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SerdeFailure<'a> {
    version: SerdeVersion,
    #[serde(borrow)]
    id: &'a serde_json::value::RawValue,
    error: SerdeError,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(untagged)]
enum SerdeOutput<'a> {
    #[serde(borrow)]
    Success(SerdeSuccess<'a>),
    #[serde(borrow)]
    Failure(SerdeFailure<'a>),
}

#[derive(Debug, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SerdeError {
    code: SerdeErrorCode,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
}

#[derive(Debug, PartialEq, Clone)]
enum SerdeErrorCode {
    ParseError,
    InvalidRequest,
    MethodNotFound,
    InvalidParams,
    InternalError,
    ServerError(i64),
    MethodError(i64),
}

impl<'a> serde::Deserialize<'a> for SerdeErrorCode {
    fn deserialize<D>(deserializer: D) -> Result<SerdeErrorCode, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        let code: i64 = serde::Deserialize::deserialize(deserializer)?;

        Ok(match code {
            -32700 => SerdeErrorCode::ParseError,
            -32600 => SerdeErrorCode::InvalidRequest,
            -32601 => SerdeErrorCode::MethodNotFound,
            -32602 => SerdeErrorCode::InvalidParams,
            -32603 => SerdeErrorCode::InternalError,
            -32099..=-32000 => SerdeErrorCode::ServerError(code),
            code => SerdeErrorCode::MethodError(code),
        })
    }
}

impl serde::Serialize for SerdeErrorCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let code = match *self {
            SerdeErrorCode::ParseError => -32700,
            SerdeErrorCode::InvalidRequest => -32600,
            SerdeErrorCode::MethodNotFound => -32601,
            SerdeErrorCode::InvalidParams => -32602,
            SerdeErrorCode::InternalError => -32603,
            SerdeErrorCode::ServerError(code) => code,
            SerdeErrorCode::MethodError(code) => code,
        };

        serializer.serialize_i64(code)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct SerdeSubscriptionEvent<'a> {
    jsonrpc: SerdeVersion,
    method: &'a str,
    params: SerdeSubscriptionEventParams<'a>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct SerdeSubscriptionEventParams<'a> {
    subscription: &'a str,
    result: &'a serde_json::value::RawValue,
}
