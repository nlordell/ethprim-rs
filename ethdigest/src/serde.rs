//! Serde serialization implementation for Ethereum 32-byte digests.

use crate::Digest;
use core::fmt::{self, Formatter};
use serde::{
    de::{self, Deserializer, Visitor},
    ser::Serializer,
    Deserialize, Serialize,
};

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(DigestVisitor)
    }
}

struct DigestVisitor;

impl<'de> Visitor<'de> for DigestVisitor {
    type Value = Digest;

    fn expecting(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str("a `0x`-prefixed 20-byte hex string")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        s.strip_prefix("0x")
            .ok_or_else(|| de::Error::custom("missing `0x`-prefix"))?
            .parse()
            .map_err(de::Error::custom)
    }
}

impl Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let buffer = self.fmt_buffer(Default::default());
        serializer.serialize_str(buffer.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::value::{self, BorrowedStrDeserializer};

    #[test]
    fn deserialize_digest() {
        for s in [
            "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "0xeEeEeEeEeEeEeEeEeEeEeEeEeEeEeEeEeEeEeEeEeEeEeEeEeEeEeEeEeEeEeEeE",
            "0xEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
        ] {
            let deserializer = BorrowedStrDeserializer::<value::Error>::new(s);
            assert_eq!(
                Digest::deserialize(deserializer).unwrap(),
                Digest([0xee; 32]),
            )
        }
    }

    #[test]
    fn deserialize_digest_requires_0x_prefix() {
        let without_prefix = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        let deserializer = BorrowedStrDeserializer::<value::Error>::new(without_prefix);
        assert!(Digest::deserialize(deserializer).is_err());
    }
}
