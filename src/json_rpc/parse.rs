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

//! Parse JSON-RPC method calls and notifications, and build responses messages.

use alloc::{borrow::Cow, string::String};

/// Parses a JSON-encoded RPC method call or notification.
pub fn parse_call(call_json: &str) -> Result<Call, ParseError> {
    let serde_call: SerdeCall = serde_json::from_str(call_json).map_err(ParseError)?;

    if let Some(id) = &serde_call.id {
        // Because of https://github.com/serde-rs/json/issues/742, we can't use ̀`&str`.
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        #[serde(untagged)]
        enum SerdeId<'a> {
            Num(u64),
            Str(Cow<'a, str>),
        }

        if let Err(err) = serde_json::from_str::<SerdeId>(id.get()) {
            return Err(ParseError(err));
        }
    }

    Ok(Call {
        id_json: serde_call.id.map(|v| v.get()),
        method: serde_call.method,
        params_json: serde_call.params.map(|p| p.get()),
    })
}

/// Builds a JSON call.
///
/// `method` must be the name of the method to call. `params_json` must be the JSON-formatted
/// object or array containing the parameters of the call.
///
/// # Panic
///
/// Panics if the [`Call::id_json`] or [`Call::params_json`] isn't valid JSON.
///
pub fn build_call(call: Call) -> String {
    serde_json::to_string(&SerdeCall {
        jsonrpc: SerdeVersion::V2,
        id: call.id_json.map(|id| serde_json::from_str(id).unwrap()),
        method: call.method,
        params: call.params_json.map(|p| serde_json::from_str(p).unwrap()),
    })
    .unwrap()
}

/// Decoded JSON-RPC call.
#[derive(Debug)]
pub struct Call<'a> {
    /// JSON-formatted identifier of the request. `None` for notifications.
    pub id_json: Option<&'a str>,
    /// Name of the method that is being called.
    pub method: &'a str,
    /// JSON-formatted list of parameters.
    pub params_json: Option<&'a str>,
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
/// # use smoldot::json_rpc::parse;
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

/// Builds a JSON response.
///
/// `id_json` must be the JSON-formatted identifier of the request, found in [`Call::id_json`].
///
/// # Example
///
/// ```
/// # use smoldot::json_rpc::parse;
/// let _result_json = parse::build_error_response("43", parse::ErrorResponse::ParseError, None);
/// ```
///
/// # Panic
///
/// Panics if `id_json` or `data_json` aren't valid JSON.
/// Panics if the code in the [`ErrorResponse`] doesn't respect the rules documented under
/// certain variants.
///
pub fn build_error_response(
    id_json: &str,
    error: ErrorResponse,
    data_json: Option<&str>,
) -> String {
    let (code, message) = match error {
        ErrorResponse::ParseError => (
            SerdeErrorCode::ParseError,
            "Invalid JSON was received by the server.",
        ),
        ErrorResponse::InvalidRequest => (
            SerdeErrorCode::InvalidRequest,
            "The JSON sent is not a valid Request object.",
        ),
        ErrorResponse::MethodNotFound => (
            SerdeErrorCode::MethodNotFound,
            "The method does not exist / is not available.",
        ),
        ErrorResponse::InvalidParams => (
            SerdeErrorCode::InvalidParams,
            "Invalid method parameter(s).",
        ),
        ErrorResponse::InternalError => (SerdeErrorCode::InternalError, "Internal JSON-RPC error."),
        ErrorResponse::ServerError(n, msg) => {
            assert!((-32099..=-32000).contains(&n));
            (SerdeErrorCode::ServerError(n), msg)
        }
        ErrorResponse::ApplicationDefined(n, msg) => {
            assert!(!(-32700..=-32000).contains(&n));
            (SerdeErrorCode::MethodError(n), msg)
        }
    };

    serde_json::to_string(&SerdeFailure {
        jsonrpc: SerdeVersion::V2,
        id: serde_json::from_str(id_json).expect("invalid id_json"),
        error: SerdeError {
            code,
            message,
            data: data_json.map(|d| serde_json::from_str(d).expect("invalid result_json")),
        },
    })
    .unwrap()
}

/// Error that can be reported to the JSON-RPC client.
#[derive(Debug)]
pub enum ErrorResponse<'a> {
    /// Invalid JSON was received by the server.
    ParseError,

    /// The JSON sent is not a valid Request object.
    InvalidRequest,

    /// The method does not exist / is not available.
    MethodNotFound,

    /// Invalid method parameter(s).
    InvalidParams,

    /// Internal JSON-RPC error.
    InternalError,

    /// Other internal server error.
    /// Contains a more precise error code and a custom message.
    /// Error code must be in the range -32000 to -32099 included.
    ServerError(i64, &'a str),

    /// Method-specific error.
    /// Contains a more precise error code and a custom message.
    /// Error code must be outside of the range -32000 to -32700.
    ApplicationDefined(i64, &'a str),
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct SerdeCall<'a> {
    jsonrpc: SerdeVersion,
    #[serde(borrow, skip_serializing_if = "Option::is_none")]
    id: Option<&'a serde_json::value::RawValue>,
    #[serde(borrow)]
    method: &'a str,
    #[serde(borrow)]
    params: Option<&'a serde_json::value::RawValue>,
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
    jsonrpc: SerdeVersion,
    #[serde(borrow)]
    id: &'a serde_json::value::RawValue,
    error: SerdeError<'a>,
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
struct SerdeError<'a> {
    code: SerdeErrorCode,
    #[serde(borrow)]
    message: &'a str,
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

#[cfg(test)]
mod tests {
    #[test]
    fn parse_basic_works() {
        let call = super::parse_call(
            r#"{"jsonrpc":"2.0","id":5,"method":"foo","params":[5,true, "hello"]}"#,
        )
        .unwrap();
        assert_eq!(call.id_json.unwrap(), "5");
        assert_eq!(call.method, "foo");
        assert_eq!(call.params_json, Some("[5,true, \"hello\"]"));
    }

    #[test]
    fn parse_missing_id() {
        let call = super::parse_call(r#"{"jsonrpc":"2.0","method":"foo","params":[]}"#).unwrap();
        assert!(call.id_json.is_none());
        assert_eq!(call.method, "foo");
        assert_eq!(call.params_json, Some("[]"));
    }

    #[test]
    fn parse_id_string() {
        let call =
            super::parse_call(r#"{"jsonrpc":"2.0","id":"hello","method":"foo","params":[]}"#)
                .unwrap();
        assert_eq!(call.id_json.unwrap(), "\"hello\"");
        assert_eq!(call.method, "foo");
        assert_eq!(call.params_json, Some("[]"));
    }

    #[test]
    fn parse_id_string_escaped() {
        let call =
            super::parse_call(r#"{"jsonrpc":"2.0","id":"extern:\"health-checker:0\"","method":"system_health","params":[]}"#)
                .unwrap();
        assert_eq!(call.id_json.unwrap(), r#""extern:\"health-checker:0\"""#);
        assert_eq!(call.method, "system_health");
        assert_eq!(call.params_json, Some("[]"));
    }

    #[test]
    fn missing_params() {
        let call = super::parse_call(r#"{"jsonrpc":"2.0","id":2,"method":"foo"}"#).unwrap();
        assert_eq!(call.id_json.unwrap(), r#"2"#);
        assert_eq!(call.method, "foo");
        assert_eq!(call.params_json, None);
    }

    #[test]
    fn parse_wrong_jsonrpc() {
        assert!(
            super::parse_call(r#"{"jsonrpc":"2.1","id":5,"method":"foo","params":[]}"#).is_err()
        );
    }

    #[test]
    fn parse_bad_id() {
        assert!(
            super::parse_call(r#"{"jsonrpc":"2.0","id":{},"method":"foo","params":[]}"#).is_err()
        );
    }
}
