//! Internal Ethereum RPC types used for facilitating serialization.

use crate::serialization;
use serde::Deserialize;

/// Serialize bytes as hexadecimal.
#[derive(Deserialize)]
#[serde(transparent)]
pub struct Bytes(#[serde(with = "serialization::bytes")] pub Vec<u8>);

impl From<Bytes> for Vec<u8> {
    fn from(bytes: Bytes) -> Self {
        bytes.0
    }
}
