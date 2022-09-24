//! JSON serialization helpers.

#![allow(dead_code)]

use serde::{Deserialize as _, Deserializer, Serialize as _, Serializer};

/// Serialize an `Option<[u8]>`
pub mod option_bytes {
    use super::{
        bytes::{decode, encode},
        *,
    };
    use std::{borrow::Cow, str};

    #[doc(hidden)]
    pub fn serialize<T, S>(value: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: AsRef<[u8]>,
        S: Serializer,
    {
        let bytes = match value {
            Some(value) => value.as_ref(),
            None => return serializer.serialize_none(),
        };

        serializer.serialize_some(&encode(bytes))
    }

    #[doc(hidden)]
    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
    where
        T: From<Vec<u8>>,
        D: Deserializer<'de>,
    {
        let hex = match Option::<Cow<str>>::deserialize(deserializer)? {
            Some(value) => value,
            None => return Ok(None),
        };

        Ok(Some(decode(&hex)?.into()))
    }
}

pub mod bytes {
    use super::*;
    use serde::de;
    use std::{borrow::Cow, fmt::Write as _, str};

    #[doc(hidden)]
    pub fn encode(bytes: &[u8]) -> String {
        let mut buffer = String::with_capacity(2 + bytes.len() * 2);
        buffer.push_str("0x");
        for byte in bytes {
            write!(&mut buffer, "{byte:02x}").unwrap();
        }
        buffer
    }

    #[doc(hidden)]
    pub fn decode<E>(hex: &str) -> Result<Vec<u8>, E>
    where
        E: de::Error,
    {
        let hex = hex
            .strip_prefix("0x")
            .ok_or_else(|| de::Error::custom("bytes missing '0x' prefix"))?;

        if hex.len() % 2 != 0 {
            return Err(de::Error::custom("odd number of characters in hex string"));
        }

        let nibble = |x: u8| -> Result<u8, E> {
            match x {
                b'0'..=b'9' => Ok(x - b'0'),
                b'a'..=b'f' => Ok(x - b'a' + 0xa),
                b'A'..=b'F' => Ok(x - b'A' + 0xa),
                _ => Err(de::Error::custom("invalid hex ASCII digit {x:02#x}")),
            }
        };

        let mut bytes = Vec::with_capacity(hex.len() / 2);
        for chunk in hex.as_bytes().chunks_exact(2) {
            bytes.push((nibble(chunk[0])? << 4) + nibble(chunk[1])?);
        }

        Ok(bytes)
    }

    #[doc(hidden)]
    pub fn serialize<T, S>(value: T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: AsRef<[u8]>,
        S: Serializer,
    {
        encode(value.as_ref()).serialize(serializer)
    }

    #[doc(hidden)]
    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: From<Vec<u8>>,
        D: Deserializer<'de>,
    {
        Ok(decode(&Cow::<str>::deserialize(deserializer)?)?.into())
    }
}
