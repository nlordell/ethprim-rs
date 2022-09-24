//! Internal module used for hex-string parsing.

use core::{
    fmt::{self, Display, Formatter},
    mem::{self, MaybeUninit},
};

/// Decode a hex string into digest bytes.
pub fn decode(s: &str) -> Result<[u8; 32], ParseDigestError> {
    let (s, ch_offset) = match s.strip_prefix("0x") {
        Some(s) => (s, 2),
        None => (s, 0),
    };
    if s.len() != 64 {
        return Err(ParseDigestError::InvalidLength);
    }

    let mut bytes = [MaybeUninit::<u8>::uninit(); 32];
    let nibble = |c| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'A'..=b'F' => Some(c - b'A' + 0xa),
        b'a'..=b'f' => Some(c - b'a' + 0xa),
        _ => None,
    };
    let invalid_char = |i: usize| ParseDigestError::InvalidHexCharacter {
        c: s[i..].chars().next().unwrap(),
        index: i + ch_offset,
    };

    for (i, ch) in s.as_bytes().chunks(2).enumerate() {
        let hi = nibble(ch[0]).ok_or_else(|| invalid_char(i * 2))?;
        let lo = nibble(ch[1]).ok_or_else(|| invalid_char(i * 2 + 1))?;
        bytes[i].write((hi << 4) + lo);
    }

    let bytes = unsafe { mem::transmute(bytes) };
    Ok(bytes)
}

/// Represents an error parsing an digest from a string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseDigestError {
    /// The hex string does not have the correct length.
    InvalidLength,
    /// An invalid character was found.
    InvalidHexCharacter { c: char, index: usize },
}

impl Display for ParseDigestError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::InvalidLength { .. } => write!(f, "invalid hex string length"),
            Self::InvalidHexCharacter { c, index } => {
                write!(f, "invalid character `{c}` at position {index}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseDigestError {}
