//! Internal module used for hex-string parsing.

use core::{
    fmt::{self, Display, Formatter},
    mem::MaybeUninit,
    slice, str,
};

/// Decode a hex string into a byte array.
pub fn decode<const N: usize>(s: &str) -> Result<[u8; N], ParseHexError> {
    let (s, ch_offset) = match s.strip_prefix("0x") {
        Some(s) => (s, 2),
        None => (s, 0),
    };
    if s.len() != N * 2 {
        return Err(ParseHexError::InvalidLength);
    }

    let mut bytes = [MaybeUninit::<u8>::uninit(); N];
    let nibble = |c| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'A'..=b'F' => Some(c - b'A' + 0xa),
        b'a'..=b'f' => Some(c - b'a' + 0xa),
        _ => None,
    };
    let invalid_char = |i: usize| ParseHexError::InvalidHexCharacter {
        c: s[i..].chars().next().unwrap(),
        index: i + ch_offset,
    };

    for (i, ch) in s.as_bytes().chunks(2).enumerate() {
        let hi = nibble(ch[0]).ok_or_else(|| invalid_char(i * 2))?;
        let lo = nibble(ch[1]).ok_or_else(|| invalid_char(i * 2 + 1))?;
        bytes[i].write((hi << 4) + lo);
    }

    let bytes = unsafe { (&bytes as *const _ as *const [u8; N]).read() };
    Ok(bytes)
}

/// Decode a hex string into a byte array as a `const fn`.
pub const fn const_decode<const N: usize>(s: &str) -> [u8; N] {
    let b = strip_hex_prefix(s).as_bytes();
    assert!(b.len() == N * 2, "invalid hex length");

    let mut bytes = [0; N];
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'A'..=b'F' => c - b'A' + 0xa,
            b'a'..=b'f' => c - b'a' + 0xa,
            _ => panic!("invalid hex digit"),
        }
    }

    let mut i = 0;
    while i < N {
        let hi = nibble(b[i * 2]);
        let lo = nibble(b[i * 2 + 1]);
        bytes[i] = (hi << 4) + lo;
        i += 1;
    }

    bytes
}

pub const fn strip_hex_prefix(s: &str) -> &str {
    let b = s.as_bytes();
    let start = 2 * ((b.len() > 2 && b[0] == b'0' && b[1] == b'x') as usize);
    let len = b.len() - start;

    // SAFETY: The string is long enough, and it will be valid UTF-8 as the
    // prefix is ASCII.
    unsafe { str::from_utf8_unchecked(slice::from_raw_parts(b.as_ptr().add(start), len)) }
}

/// Encode a byte array into a stack-allocated buffer.
pub fn encode<const N: usize, const M: usize>(
    bytes: &[u8; N],
    alphabet: Alphabet,
) -> FormattingBuffer<M> {
    debug_assert_eq!(2 + N * 2, M, "bytes and formatting buffer size mismatch");

    let mut buffer = [MaybeUninit::<u8>::uninit(); M];

    buffer[0].write(b'0');
    buffer[1].write(b'x');

    let lut = alphabet.lut();
    let nibble = |c: u8| lut[c as usize];
    for (i, byte) in bytes.iter().enumerate() {
        let j = i * 2 + 2;
        buffer[j].write(nibble(byte >> 4));
        buffer[j + 1].write(nibble(byte & 0xf));
    }

    let buffer = unsafe { (&buffer as *const _ as *const [u8; M]).read() };
    FormattingBuffer(buffer)
}

/// Encode a byte array into a stack-allocated buffer.
#[allow(dead_code)]
pub const fn const_encode<const N: usize, const M: usize>(
    bytes: &[u8; N],
    alphabet: Alphabet,
) -> FormattingBuffer<M> {
    if 2 + N * 2 != M {
        panic!("bytes and formatting buffer size mismatch");
    }

    let mut buffer = [0; M];

    buffer[0] = b'0';
    buffer[1] = b'x';

    let lut = alphabet.lut();
    let mut i = 0;
    while i < N {
        let byte = bytes[i];
        let j = i * 2 + 2;
        buffer[j] = lut[(byte >> 4) as usize];
        buffer[j + 1] = lut[(byte & 0xf) as usize];
        i += 1;
    }

    FormattingBuffer(buffer)
}

/// A formatting buffer.
pub struct FormattingBuffer<const N: usize>([u8; N]);

impl<const N: usize> FormattingBuffer<N> {
    /// Returns a mutable reference to the underlying buffer.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that the contents of the buffer is a valid
    /// UTF-8 string.
    #[allow(dead_code)]
    pub unsafe fn as_bytes_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }

    /// Returns the buffered string.
    pub const fn as_str(&self) -> &str {
        // SAFETY: Buffer should only ever contain a valid UTF-8 string.
        unsafe { str::from_utf8_unchecked(&self.0) }
    }

    /// Returns the hex bytes of the buffered string without the 0x prefix.
    pub const fn as_bytes_str(&self) -> &str {
        // SAFETY: Buffer always starts with `0x` prefix, so it is long enough
        // and won't get sliced in the middle of a UTF-8 codepoint.
        unsafe {
            let bytes = slice::from_raw_parts(self.0.as_slice().as_ptr().add(2), N - 2);
            str::from_utf8_unchecked(bytes)
        }
    }
}

/// The alphatbet to use.
#[derive(Default)]
pub enum Alphabet {
    #[default]
    Lower,
    Upper,
}

impl Alphabet {
    /// Returns the nibble lookup-table for the alphabet.
    const fn lut(&self) -> &'static [u8; 16] {
        match self {
            Alphabet::Lower => b"0123456789abcdef",
            Alphabet::Upper => b"0123456789ABCDEF",
        }
    }
}

/// Represents an error parsing a hex string into fixed bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseHexError {
    /// The hex string does not have the correct length.
    InvalidLength,
    /// An invalid character was found.
    InvalidHexCharacter { c: char, index: usize },
}

impl Display for ParseHexError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::InvalidLength { .. } => write!(f, "invalid hex string length"),
            Self::InvalidHexCharacter { c, index } => {
                write!(f, "invalid character `{c}` at position {index}")
            }
        }
    }
}
