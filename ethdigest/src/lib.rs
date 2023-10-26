//! Implementation of Ethereum digest and hashing for Rust.
//!
//! This crate provides a [`Digest`] type for representing an Ethereum 32-byte
//! digest as well as various Keccak-256 hashing utilities for computing them.
//!
//! # Features
//!
//! This crate supports the following features:
//! - **_default_ `std`**: Additional integration with Rust standard library
//! types. Notably, this includes `std::error::Error` implementation on the
//! [`ParseDigestError`] and conversions from `Vec<u8>`.
//! - **`serde`**: Serialization traits for the [`serde`](::serde) crate. Note
//! that the implementation is very much geared towards JSON serialization with
//! `serde_json`.
//! - **`sha3`**: Use the Rust-Crypto Keccak-256 implementation (provided by the
//! [`sha3`] crate) instead of the built-in one.

#![cfg_attr(not(any(feature = "std", test)), no_std)]

mod hasher;
mod hex;
mod keccak;
#[cfg(feature = "serde")]
mod serde;

pub use crate::hasher::Hasher;
use crate::hex::{Alphabet, FormattingBuffer, ParseHexError};
use core::{
    array::{IntoIter, TryFromSliceError},
    fmt::{self, Debug, Display, Formatter, LowerHex, UpperHex},
    ops::{Deref, DerefMut},
    slice::Iter,
    str::FromStr,
};

/// Macro to create Ethereum digest values from string literals that get parsed
/// at compile time. A compiler error will be generated if an invalid digest is
/// specified.
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// # use ethdigest::{digest, Digest};
/// for digest in [
///     digest!("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
///     digest!("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"),
/// ] {
///     assert_eq!(digest, Digest([0xee; 32]));
/// }
/// ```
///
/// The macro generate compile errors on invalid input:
///
/// ```compile_fail
/// # use ethdigest::digest;
/// let _ = digest!("not a valid hex digest literal!");
/// ```
#[macro_export]
macro_rules! digest {
    ($digest:literal) => {{
        const VALUE: $crate::Digest = $crate::Digest::const_from_str($digest);
        VALUE
    }};
}

/// Macro to create Ethereum digest values from compile-time hashed input.
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// # use ethdigest::{keccak, Digest};
/// assert_eq!(
///     Digest::of("Hello Ethereum!"),
///     keccak!("Hello Ethereum!"),
/// );
/// ```
#[macro_export]
macro_rules! keccak {
    ($data:literal) => {{
        const VALUE: $crate::Digest = $crate::Digest::const_of($data);
        VALUE
    }};
}

/// A 32-byte digest.
#[repr(transparent)]
#[derive(Copy, Clone, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    /// Creates a digest from a slice.
    ///
    /// # Panics
    ///
    /// This method panics if the length of the slice is not 32 bytes.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use ethdigest::Digest;
    /// let buffer = (0..255).collect::<Vec<_>>();
    /// assert_eq!(
    ///     Digest::from_slice(&buffer[0..32]),
    ///     Digest([
    ///         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    ///         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ///         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    ///         0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ///     ]),
    /// );
    /// ```
    pub fn from_slice(slice: &[u8]) -> Self {
        slice.try_into().unwrap()
    }

    /// Creates a reference to a digest from a reference to a 32-byte array.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use ethdigest::Digest;
    /// let arrays = [[0; 32], [1; 32]];
    /// for digest in arrays.iter().map(Digest::from_ref) {
    ///     println!("{digest}");
    /// }
    /// ```
    pub fn from_ref(array: &[u8; 32]) -> &'_ Self {
        // SAFETY: `Digest` and `[u8; 32]` have the same memory layout.
        unsafe { &*(array as *const [u8; 32]).cast::<Self>() }
    }

    /// Creates a mutable reference to a digest from a mutable reference to a
    /// 32-byte array.
    pub fn from_mut(array: &mut [u8; 32]) -> &'_ mut Self {
        // SAFETY: `Digest` and `[u8; 32]` have the same memory layout.
        unsafe { &mut *(array as *mut [u8; 32]).cast::<Self>() }
    }

    /// Creates a digest by hashing some input.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use ethdigest::Digest;
    /// assert_eq!(
    ///     Digest::of("Hello Ethereum!"),
    ///     Digest([
    ///         0x67, 0xe0, 0x83, 0xfb, 0x08, 0x73, 0x8b, 0x8d,
    ///         0x79, 0x84, 0xe3, 0x49, 0x68, 0x7f, 0xec, 0x5b,
    ///         0xf0, 0x32, 0x24, 0xc2, 0xda, 0xd4, 0x90, 0x60,
    ///         0x20, 0xdf, 0xab, 0x9a, 0x0e, 0x4c, 0xee, 0xac,
    ///     ]),
    /// );
    /// ```
    pub fn of(data: impl AsRef<[u8]>) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(data);
        hasher.finalize()
    }

    /// Same as [`Digest::of`] but as a `const fn`. This method is not intended
    /// to be used directly but rather through the [`crate::keccak`] macro.
    #[doc(hidden)]
    pub const fn const_of(data: &str) -> Self {
        Self(keccak::v256(data.as_bytes()))
    }

    /// Same as [`FromStr::from_str`] but as a `const fn`. This method is not
    /// intended to be used directly but rather through the [`crate::digest`]
    /// macro.
    #[doc(hidden)]
    pub const fn const_from_str(src: &str) -> Self {
        Self(hex::const_decode(src))
    }

    /// Returns a stack-allocated formatted string with the specified alphabet.
    fn fmt_buffer(&self, alphabet: Alphabet) -> FormattingBuffer<66> {
        hex::encode(self, alphabet)
    }
}

impl Debug for Digest {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_tuple("Digest")
            .field(&format_args!("{self}"))
            .finish()
    }
}

impl Display for Digest {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.pad(self.fmt_buffer(Alphabet::default()).as_str())
    }
}

impl LowerHex for Digest {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let buffer = self.fmt_buffer(Alphabet::default());
        f.pad(if f.alternate() {
            buffer.as_str()
        } else {
            buffer.as_bytes_str()
        })
    }
}

impl UpperHex for Digest {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let buffer = hex::encode::<32, 66>(self, Alphabet::Upper);
        f.pad(if f.alternate() {
            buffer.as_str()
        } else {
            buffer.as_bytes_str()
        })
    }
}

impl AsRef<[u8; 32]> for Digest {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8; 32]> for Digest {
    fn as_mut(&mut self) -> &mut [u8; 32] {
        &mut self.0
    }
}

impl AsMut<[u8]> for Digest {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Deref for Digest {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Digest {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl FromStr for Digest {
    type Err = ParseDigestError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(hex::decode(s)?))
    }
}

impl IntoIterator for Digest {
    type Item = u8;
    type IntoIter = IntoIter<u8, 32>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Digest {
    type Item = &'a u8;
    type IntoIter = Iter<'a, u8>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl PartialEq<[u8; 32]> for Digest {
    fn eq(&self, other: &'_ [u8; 32]) -> bool {
        **self == *other
    }
}

impl PartialEq<[u8]> for Digest {
    fn eq(&self, other: &'_ [u8]) -> bool {
        **self == *other
    }
}

impl PartialEq<&'_ [u8]> for Digest {
    fn eq(&self, other: &&'_ [u8]) -> bool {
        **self == **other
    }
}

impl PartialEq<&'_ mut [u8]> for Digest {
    fn eq(&self, other: &&'_ mut [u8]) -> bool {
        **self == **other
    }
}

#[cfg(feature = "std")]
impl PartialEq<Vec<u8>> for Digest {
    fn eq(&self, other: &Vec<u8>) -> bool {
        **self == **other
    }
}

impl TryFrom<&'_ [u8]> for Digest {
    type Error = TryFromSliceError;

    fn try_from(value: &'_ [u8]) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl TryFrom<&'_ mut [u8]> for Digest {
    type Error = TryFromSliceError;

    fn try_from(value: &'_ mut [u8]) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl<'a> TryFrom<&'a [u8]> for &'a Digest {
    type Error = TryFromSliceError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Ok(Digest::from_ref(value.try_into()?))
    }
}

impl<'a> TryFrom<&'a mut [u8]> for &'a mut Digest {
    type Error = TryFromSliceError;

    fn try_from(value: &'a mut [u8]) -> Result<Self, Self::Error> {
        Ok(Digest::from_mut(value.try_into()?))
    }
}

#[cfg(feature = "std")]
impl TryFrom<Vec<u8>> for Digest {
    type Error = Vec<u8>;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

/// Represents an error parsing a digest from a string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseDigestError {
    /// The string does not have the correct length.
    InvalidLength,
    /// An invalid character was found.
    InvalidHexCharacter { c: char, index: usize },
}

impl Display for ParseDigestError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::InvalidLength => write!(f, "{}", ParseHexError::InvalidLength),
            Self::InvalidHexCharacter { c, index } => {
                let (c, index) = (*c, *index);
                write!(f, "{}", ParseHexError::InvalidHexCharacter { c, index })
            }
        }
    }
}

impl From<ParseHexError> for ParseDigestError {
    fn from(err: ParseHexError) -> Self {
        match err {
            ParseHexError::InvalidLength => Self::InvalidLength,
            ParseHexError::InvalidHexCharacter { c, index } => {
                Self::InvalidHexCharacter { c, index }
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseDigestError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_formatting() {
        let digest = Digest([0xee; 32]);
        assert_eq!(
            format!("{digest:?}"),
            "Digest(0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee)"
        );
        assert_eq!(
            format!("{digest}"),
            "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        );
        assert_eq!(
            format!("{digest:x}"),
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        );
        assert_eq!(
            format!("{digest:#x}"),
            "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        );
        assert_eq!(
            format!("{digest:X}"),
            "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
        );
        assert_eq!(
            format!("{digest:#X}"),
            "0xEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
        );
    }
}
