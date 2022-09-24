//! Module containing serializable JSON RPC data types.

use serde::{
    de::{self, Deserializer},
    Deserialize, Serialize,
};
use serde_json::Value;
use thiserror::Error;

/// JSON RPC supported version.
#[derive(Debug, Deserialize, Serialize)]
pub enum Version {
    /// Version 2.0 of the JSON RPC specification.
    #[serde(rename = "2.0")]
    V2,
}

/// Request and response ID.
///
/// Note that `u32` is used. This is so it always fits in a `f64` and obeys the
/// "SHOULD NOT have fractional parts" rule from the specification.  Since the
/// ID is set by the client, we shouldn't run into issues where a numerical ID
/// does not fit into this value or a string ID is used.
#[derive(Debug, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Id(pub u32);

/// A request object.
#[derive(Debug, Serialize)]
pub struct Request<'a, P> {
    pub jsonrpc: Version,
    pub method: &'a str,
    pub params: P,
    pub id: Id,
}

/// Notification object.
#[derive(Debug, Deserialize)]
pub struct Notification<P> {
    pub jsonrpc: Version,
    pub method: String,
    pub params: P,
}

/// Response object.
#[derive(Debug)]
pub struct Response<R> {
    pub jsonrpc: Version,
    pub result: Result<R, Error>,
    pub id: Option<Id>,
}

impl<'de, R> Deserialize<'de> for Response<R>
where
    R: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Response<R> {
            jsonrpc: Version,
            result: Option<R>,
            error: Option<Error>,
            id: Option<Id>,
        }

        let raw = Response::<R>::deserialize(deserializer)?;
        Ok(Self {
            jsonrpc: raw.jsonrpc,
            result: match (raw.result, raw.error) {
                (Some(result), _) => Ok(result),
                (None, Some(error)) => Err(error),
                (None, None) => return Err(de::Error::custom("missing 'result' or 'error' field")),
            },
            id: raw.id,
        })
    }
}

/// An RPC error that may be produced on a response.
#[derive(Debug, Deserialize, Error)]
#[error("{code}: {message}")]
#[serde(deny_unknown_fields)]
pub struct Error {
    pub code: ErrorCode,
    pub message: String,
    pub data: Value,
}

/// An error code.
#[derive(Debug, Deserialize, Error)]
#[serde(from = "i32")]
pub enum ErrorCode {
    #[error("parse error")]
    ParseError,
    #[error("invalid request")]
    InvalidRequest,
    #[error("method not found")]
    MethodNotFound,
    #[error("invalid params")]
    InvalidParams,
    #[error("internal error")]
    InternalError,
    #[error("server error ({0})")]
    ServerError(i32),
    #[error("reserved ({0})")]
    Reserved(i32),
    #[error("{0}")]
    Other(i32),
}

impl From<i32> for ErrorCode {
    fn from(code: i32) -> Self {
        #[allow(clippy::match_overlapping_arm)]
        match code {
            -32700 => ErrorCode::ParseError,
            -32600 => ErrorCode::InvalidRequest,
            -32601 => ErrorCode::MethodNotFound,
            -32602 => ErrorCode::InvalidParams,
            -32603 => ErrorCode::InternalError,
            -32099..=-32000 => ErrorCode::ServerError(code),
            -32768..=-32000 => ErrorCode::Reserved(code),
            _ => ErrorCode::Other(code),
        }
    }
}
