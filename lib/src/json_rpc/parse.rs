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
pub fn parse_request(request_json: &'_ str) -> Result<Request<'_>, ParseError> {
    let serde_request: SerdeRequest = serde_json::from_str(request_json).map_err(ParseError)?;

    if let Some(id) = &serde_request.id {
        // Because of https://github.com/serde-rs/json/issues/742, we can't use ̀`&str`.
        #[allow(dead_code)] // Necessary to silence warnings about unused fields.
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

    Ok(Request {
        id_json: serde_request.id.map(|v| v.get()),
        method: serde_request.method,
        params_json: serde_request.params.map(|p| p.get()),
    })
}

/// Parses a JSON-encoded RPC response.
pub fn parse_response(response_json: &'_ str) -> Result<Response<'_>, ParseError> {
    let error = match serde_json::from_str::<SerdeSuccess>(response_json) {
        Err(err) => err,
        Ok(SerdeSuccess {
            jsonrpc: _,
            id,
            result,
        }) => {
            // Because of https://github.com/serde-rs/json/issues/742, we can't use ̀`&str`.
            #[allow(dead_code)] // Necessary to silence warnings about unused fields.
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

            return Ok(Response::Success {
                id_json: id.get(),
                result_json: result.get(),
            });
        }
    };

    match serde_json::from_str::<SerdeFailure>(response_json) {
        Ok(SerdeFailure {
            jsonrpc: _,
            id,
            error:
                SerdeError {
                    code,
                    message,
                    data,
                },
        }) if id.get() != "null" => {
            // Because of https://github.com/serde-rs/json/issues/742, we can't use ̀`&str`.
            #[allow(dead_code)] // Necessary to silence warnings about unused fields.
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

            Ok(Response::Error {
                id_json: id.get(),
                error_code: code.to_num(),
                error_message: message,
                error_data_json: data.map(|d| d.get()),
            })
        }
        Ok(SerdeFailure {
            jsonrpc: _,
            id: _,
            error:
                SerdeError {
                    code,
                    message,
                    data,
                },
        }) => Ok(Response::ParseError {
            error_code: code.to_num(),
            error_message: message,
            error_data_json: data.map(|d| d.get()),
        }),
        Err(_) => Err(ParseError(error)),
    }
}

/// Builds a JSON request.
///
/// `method` must be the name of the method to request. `params_json` must be the JSON-formatted
/// object or array containing the parameters of the request.
///
/// # Panic
///
/// Panics if the [`Request::id_json`] or [`Request::params_json`] isn't valid JSON.
///
pub fn build_request(request: &Request) -> String {
    serde_json::to_string(&SerdeRequest {
        jsonrpc: SerdeVersion::V2,
        id: request.id_json.map(|id| serde_json::from_str(id).unwrap()),
        method: request.method,
        params: request
            .params_json
            .map(|p| serde_json::from_str(p).unwrap()),
    })
    .unwrap()
}

/// Decoded JSON-RPC request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request<'a> {
    /// JSON-formatted identifier of the request. `None` for notifications.
    pub id_json: Option<&'a str>,
    /// Name of the method that is being called.
    pub method: &'a str,
    /// JSON-formatted list of parameters. `None` iff the `params` field is missing.
    pub params_json: Option<&'a str>,
}

/// Decoded JSON-RPC response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response<'a> {
    /// Successful request.
    Success {
        /// JSON-formatted identifier of the request the response corresponds to.
        id_json: &'a str,
        /// JSON-formatted result.
        result_json: &'a str,
    },

    /// Request has failed.
    Error {
        /// JSON-formatted identifier of the request the response corresponds to.
        id_json: &'a str,
        /// Integer indicating the nature of the error.
        ///
        /// See [the JSON-RPC specification](https://www.jsonrpc.org/specification#error_object)
        /// for reference.
        error_code: i64,
        /// Short description of the error.
        error_message: &'a str,
        /// JSON-formatted data associated with the response. `None` if omitted.
        error_data_json: Option<&'a str>,
    },

    /// The JSON-RPC server indicates that it couldn't parse a request.
    ParseError {
        /// Integer indicating the nature of the error.
        ///
        /// See [the JSON-RPC specification](https://www.jsonrpc.org/specification#error_object)
        /// for reference.
        error_code: i64,
        /// Short description of the error.
        error_message: &'a str,
        /// JSON-formatted data associated with the response. `None` if omitted.
        error_data_json: Option<&'a str>,
    },
}

impl<'a> Response<'a> {
    /// Utility function that returns `Some` if `self` is [`Response::Success`]. If `Some` is
    /// returned, it contains in order the JSON-formatted identifier of the request and the
    /// JSON-formatted content of the `result` field.
    pub fn into_success(self) -> Option<(&'a str, &'a str)> {
        if let Response::Success {
            id_json,
            result_json,
        } = self
        {
            Some((id_json, result_json))
        } else {
            None
        }
    }
}

/// Error while parsing a request.
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub struct ParseError(serde_json::Error);

/// Builds a JSON response.
///
/// `id_json` must be the JSON-formatted identifier of the request, found in [`Request::id_json`].
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
/// `id_json` must be the JSON-formatted identifier of the request, found in [`Request::id_json`].
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
        ErrorResponse::InvalidParams(msg) => (
            SerdeErrorCode::InvalidParams,
            msg.unwrap_or("Invalid method parameter(s)."),
        ),
        ErrorResponse::InternalError => (SerdeErrorCode::InternalError, "Internal JSON-RPC error."),
        ErrorResponse::ServerError(n, msg) => {
            assert!((-32099..=-32000).contains(&n));
            (SerdeErrorCode::ServerError(n), msg)
        }
        ErrorResponse::ApplicationDefined(n, msg) => {
            assert!(!(-32768..=-32000).contains(&n));
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
    /// Optionally contains a custom message.
    InvalidParams(Option<&'a str>),

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

/// Builds a JSON error response when a request couldn't be decoded.
///
/// # Example
///
/// ```
/// # use smoldot::json_rpc::parse;
/// let _result_json = parse::build_parse_error_response();
/// ```
///
/// # Panic
///
/// Panics if `id_json` or `data_json` aren't valid JSON.
/// Panics if the code in the [`ErrorResponse`] doesn't respect the rules documented under
/// certain variants.
///
pub fn build_parse_error_response() -> String {
    serde_json::to_string(&SerdeFailure {
        jsonrpc: SerdeVersion::V2,
        id: serde_json::from_str("null").unwrap(),
        error: SerdeError {
            code: SerdeErrorCode::ParseError,
            message: "Parse error",
            data: None,
        },
    })
    .unwrap()
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct SerdeRequest<'a> {
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
    #[serde(borrow)]
    result: &'a serde_json::value::RawValue,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SerdeFailure<'a> {
    jsonrpc: SerdeVersion,
    #[serde(borrow)]
    id: &'a serde_json::value::RawValue,
    #[serde(borrow)]
    error: SerdeError<'a>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SerdeError<'a> {
    code: SerdeErrorCode,
    #[serde(borrow)]
    message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<&'a serde_json::value::RawValue>,
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

impl SerdeErrorCode {
    fn to_num(&self) -> i64 {
        match *self {
            SerdeErrorCode::ParseError => -32700,
            SerdeErrorCode::InvalidRequest => -32600,
            SerdeErrorCode::MethodNotFound => -32601,
            SerdeErrorCode::InvalidParams => -32602,
            SerdeErrorCode::InternalError => -32603,
            SerdeErrorCode::ServerError(code) => code,
            SerdeErrorCode::MethodError(code) => code,
        }
    }
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
        serializer.serialize_i64(self.to_num())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn parse_request_basic_works() {
        let request = super::parse_request(
            r#"{"jsonrpc":"2.0","id":5,"method":"foo","params":[5,true, "hello"]}"#,
        )
        .unwrap();
        assert_eq!(request.id_json.unwrap(), "5");
        assert_eq!(request.method, "foo");
        assert_eq!(request.params_json, Some("[5,true, \"hello\"]"));
    }

    #[test]
    fn parse_response_basic_works() {
        let (id, result) = super::parse_response(r#"{"jsonrpc":"2.0","id":5,"result":true}"#)
            .unwrap()
            .into_success()
            .unwrap();
        assert_eq!(id, "5");
        assert_eq!(result, "true");
    }

    #[test]
    fn parse_error_response() {
        let response = super::parse_response(r#"{"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}, "id": "1"}"#)
            .unwrap();

        let super::Response::Error {
            id_json,
            error_code,
            error_message,
            error_data_json,
        } = response
        else {
            panic!()
        };
        assert_eq!(id_json, "\"1\"");
        assert_eq!(error_code, -32601);
        assert_eq!(error_message, "Method not found");
        assert!(error_data_json.is_none());
    }

    #[test]
    fn parse_parse_error_response() {
        let response = super::parse_response(r#"{"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}, "id": null}"#)
            .unwrap();

        let super::Response::ParseError {
            error_code,
            error_message,
            error_data_json,
        } = response
        else {
            panic!()
        };
        assert_eq!(error_code, -32600);
        assert_eq!(error_message, "Invalid Request");
        assert!(error_data_json.is_none());
    }

    #[test]
    fn parse_request_missing_id() {
        let request =
            super::parse_request(r#"{"jsonrpc":"2.0","method":"foo","params":[]}"#).unwrap();
        assert!(request.id_json.is_none());
        assert_eq!(request.method, "foo");
        assert_eq!(request.params_json, Some("[]"));
    }

    #[test]
    fn parse_request_id_string() {
        let request =
            super::parse_request(r#"{"jsonrpc":"2.0","id":"hello","method":"foo","params":[]}"#)
                .unwrap();
        assert_eq!(request.id_json.unwrap(), "\"hello\"");
        assert_eq!(request.method, "foo");
        assert_eq!(request.params_json, Some("[]"));
    }

    #[test]
    fn parse_request_id_string_escaped() {
        let request =
            super::parse_request(r#"{"jsonrpc":"2.0","id":"extern:\"health-checker:0\"","method":"system_health","params":[]}"#)
                .unwrap();
        assert_eq!(request.id_json.unwrap(), r#""extern:\"health-checker:0\"""#);
        assert_eq!(request.method, "system_health");
        assert_eq!(request.params_json, Some("[]"));
    }

    #[test]
    fn parse_response_id_string_escaped() {
        let (id, result) = super::parse_response(
            r#"{"jsonrpc":"2.0","id":"extern:\"health-checker:0\"","result":[]}"#,
        )
        .unwrap()
        .into_success()
        .unwrap();
        assert_eq!(id, r#""extern:\"health-checker:0\"""#);
        assert_eq!(result, "[]");
    }

    #[test]
    fn request_missing_params() {
        let request = super::parse_request(r#"{"jsonrpc":"2.0","id":2,"method":"foo"}"#).unwrap();
        assert_eq!(request.id_json.unwrap(), r#"2"#);
        assert_eq!(request.method, "foo");
        assert_eq!(request.params_json, None);
    }

    #[test]
    fn parse_request_wrong_jsonrpc() {
        assert!(
            super::parse_request(r#"{"jsonrpc":"2.1","id":5,"method":"foo","params":[]}"#).is_err()
        );
    }

    #[test]
    fn parse_response_wrong_jsonrpc() {
        assert!(super::parse_response(r#"{"jsonrpc":"2.1","id":5,"result":null}"#).is_err());
    }

    #[test]
    fn parse_request_bad_id() {
        assert!(
            super::parse_request(r#"{"jsonrpc":"2.0","id":{},"method":"foo","params":[]}"#)
                .is_err()
        );
    }

    #[test]
    fn parse_response_missing_id() {
        assert!(
            super::parse_response(
                r#"{"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"} }"#
            )
            .is_err()
        );
    }

    #[test]
    fn parse_response_bad_id_success() {
        assert!(super::parse_response(r#"{"jsonrpc":"2.0","id":{},"result":5}"#).is_err());
    }

    #[test]
    fn parse_response_bad_id_error() {
        assert!(super::parse_response(
            r#"{"jsonrpc":"2.0","id":{},"error": {"code": -32601, "message": "Method not found"}}"#
        )
        .is_err());
    }

    #[test]
    fn build_request() {
        let request = super::Request {
            id_json: Some("5"),
            method: "test",
            params_json: Some("{}"),
        };

        let encoded = super::build_request(&request);
        assert_eq!(super::parse_request(&encoded).unwrap(), request);
    }

    #[test]
    #[should_panic]
    fn build_request_panics_invalid_id() {
        super::build_request(&super::Request {
            id_json: Some("test"),
            method: "test",
            params_json: None,
        });
    }

    #[test]
    #[should_panic]
    fn build_request_panics_invalid_params() {
        super::build_request(&super::Request {
            id_json: Some("5"),
            method: "test",
            params_json: Some("invalid"),
        });
    }

    #[test]
    fn build_parse_error() {
        let response = super::build_parse_error_response();
        assert_eq!(
            response,
            "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32700,\"message\":\"Parse error\"}}"
        );
    }
}
