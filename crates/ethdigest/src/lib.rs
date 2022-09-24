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
//! - **`keccak`**: Include Keccak-256 hasing utilities (provided by the
//! [`sha3`] crate).
//! - **`macros`**: Adds a [`digest`] procedural macro for compile-time
//! digest literals and a [`keccak`] procedural macro for compile-time hashing.
//! - **`serde`**: Serialization traits for the [`serde`](::serde) crate. Note
//! that the implementation is very much geared towards JSON serialiazation with
//! `serde_json`.

#![cfg_attr(not(any(feature = "std", test)), no_std)]

mod buffer;
mod hex;
#[cfg(feature = "keccak")]
mod keccak;
#[cfg(feature = "serde")]
mod serde;

use crate::buffer::Alphabet;
pub use crate::hex::ParseDigestError;
#[cfg(feature = "keccak")]
pub use crate::keccak::Keccak;
use core::{
    array::{IntoIter, TryFromSliceError},
    fmt::{self, Debug, Display, Formatter, LowerHex, UpperHex},
    ops::{Deref, DerefMut},
    slice::Iter,
    str::FromStr,
};

/// Procedural macro to create Ethereum digest values from string literals that
/// get parsed at compile time. A compiler error will be generated if an invalid
/// digest is specified.
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
/// The procedural macro generate compile errors on invalid input:
///
/// ```compile_fail
/// # use ethdigest::digest;
/// let _ = digest!("not a valid hex digest literal!");
/// ```
#[cfg(feature = "macros")]
pub use ethdigest_macros::digest;

/// Procedural macro to create Ethereum digest values from compile-time hashed
/// input.
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
#[cfg(feature = "macros")]
pub use ethdigest_macros::keccak;

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
    #[cfg(feature = "keccak")]
    pub fn of(data: impl AsRef<[u8]>) -> Self {
        let mut hasher = Keccak::new();
        hasher.update(data);
        hasher.finalize()
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
        f.pad(buffer::fmt(self, Alphabet::default()).as_str())
    }
}

impl LowerHex for Digest {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let buffer = buffer::fmt(self, Alphabet::Lower);
        f.pad(if f.alternate() {
            buffer.as_str()
        } else {
            buffer.as_bytes_str()
        })
    }
}

impl UpperHex for Digest {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let buffer = buffer::fmt(self, Alphabet::Upper);
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
        hex::decode(s).map(Self)
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
