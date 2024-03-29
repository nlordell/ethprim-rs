//! Implementation of Ethereum public addresses for Rust.
//!
//! This crate provides an [`Address`] type for representing Ethereum public
//! addresses.
//!
//! # Checksums
//!
//! Addresses are by default formatted with [ERC-55] mixed-case checksum
//! encoding. Addresses checksums may optionally be verified when parsing with
//! [`Address::from_str_checksum()`].
//!
//! # [`address!`] Macro
//!
//! This crate exports an [`address!`] macro that can be used for creating
//! compile-time address constants. Under the hood, it is implemented with
//! `const fn` and does not use procedural macros.
//!
//! # Features
//!
//! - **_default_ `std`**: Additional integration with Rust standard library
//!   types. Notably, this includes [`std::error::Error`] implementation on the
//!   [`ParseAddressError`] type and conversions from [`Vec<u8>`].
//! - **`serde`**: Serialization traits for the [`serde`] crate. Note that the
//!   implementation is very much geared towards JSON serialization with
//!   [`serde_json`].
//! - **`sha3`**: Use the Rust Crypto Keccak-256 implementation (provided by the
//!   [`sha3`] crate) instead of the built-in one. Note that the [`address!`]
//!   macro will always use the built-in Keccak-256 implementation for checksum
//!   verification, as [`sha3`] does not expose a `const fn` API.
//!
//! [ERC-55]: https://eips.ethereum.org/EIPS/eip-55
//! [`serde`]: https://crates.io/crates/serde
//! [`serde_json`]: https://crates.io/crates/serde_json
//! [`sha3`]: https://crates.io/crates/sha3

#![cfg_attr(not(any(feature = "std", test)), no_std)]

mod checksum;
mod hex;
mod keccak;
#[cfg(feature = "serde")]
mod serde;

use crate::hex::{Alphabet, FormattingBuffer, ParseHexError};
use core::{
    array::{IntoIter, TryFromSliceError},
    fmt::{self, Debug, Display, Formatter, LowerHex, UpperHex},
    ops::{Deref, DerefMut},
    slice::Iter,
    str::{self, FromStr},
};

/// Macro to create Ethereum public address values from string literals that get
/// verified at compile time. A compiler error will be generated if an invalid
/// address is specified.
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// # use ethaddr::{address, Address};
/// for address in [
///     address!("0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE"),
///     address!("EeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE"),
/// ] {
///     assert_eq!(address, Address([0xee; 20]));
/// }
/// ```
///
/// Note that by default, the macro will verify address checksums:
///
/// ```compile_fail
/// # use ethaddr::address;
/// let _ = address!("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
/// ```
///
/// However, this behaviour can be ignored by prefixing the address with a `~`:
///
/// ```
/// # use ethaddr::address;
/// let _ = address!(~"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
/// ```
///
/// Note that this can be used in `const` contexts, but unfortunately not in
/// pattern matching contexts:
///
/// ```
/// # use ethaddr::{address, Address};
/// const ADDRESS: Address = address!("0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE");
/// ```
///
/// ```compile_fail
/// # use ethaddr::{address, Address};
/// match Address([0xee; 20]) {
///     address!("0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE") => println!("matches"),
///     _ => println!("doesn't match"),
/// }
/// ```
#[macro_export]
macro_rules! address {
    ($address:expr $(,)?) => {{
        const VALUE: $crate::Address = $crate::Address::const_from_str_checksum($address);
        VALUE
    }};
    (~$address:expr $(,)?) => {{
        const VALUE: $crate::Address = $crate::Address::const_from_str($address);
        VALUE
    }};
}

/// An Ethereum public address.
#[repr(transparent)]
#[derive(Copy, Clone, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Address(pub [u8; 20]);

impl Address {
    /// Creates an address from a slice.
    ///
    /// # Panics
    ///
    /// This method panics if the length of the slice is not 20 bytes.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use ethaddr::{address, Address};
    /// let buffer = (0..255).collect::<Vec<_>>();
    /// assert_eq!(
    ///     Address::from_slice(&buffer[0..20]),
    ///     address!("0x000102030405060708090a0b0c0d0e0f10111213"),
    /// );
    /// ```
    pub fn from_slice(slice: &[u8]) -> Self {
        slice.try_into().unwrap()
    }

    /// Creates a reference to an address from a reference to a 20-byte array.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use ethaddr::Address;
    /// let arrays = [[0; 20], [1; 20]];
    /// for address in arrays.iter().map(Address::from_ref) {
    ///     println!("{address}");
    /// }
    /// ```
    pub fn from_ref(array: &[u8; 20]) -> &'_ Self {
        // SAFETY: `Address` and `[u8; 20]` have the same memory layout.
        unsafe { &*(array as *const [u8; 20]).cast::<Self>() }
    }

    /// Creates a mutable reference to an address from a mutable reference to a
    /// 20-byte array.
    pub fn from_mut(array: &mut [u8; 20]) -> &'_ mut Self {
        // SAFETY: `Address` and `[u8; 20]` have the same memory layout.
        unsafe { &mut *(array as *mut [u8; 20]).cast::<Self>() }
    }

    /// Parses a checksummed `Address` from a string.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use ethaddr::Address;
    /// assert!(Address::from_str_checksum("0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE").is_ok());
    /// assert!(Address::from_str_checksum("EeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE").is_ok());
    /// assert!(Address::from_str_checksum("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").is_err());
    /// ```
    pub fn from_str_checksum(s: &str) -> Result<Self, ParseAddressError> {
        let bytes = hex::decode(s)?;
        checksum::verify(&bytes, s).map_err(|_| ParseAddressError::ChecksumMismatch)?;
        Ok(Self(bytes))
    }

    /// Same as [`FromStr::from_str()`] but as a `const fn`. This method is not
    /// intended to be used directly but rather through the [`address!`]
    /// macro.
    #[doc(hidden)]
    pub const fn const_from_str(src: &str) -> Self {
        Self(hex::const_decode(src))
    }

    /// Same as [`Self::from_str_checksum()`] but as a `const fn`. This method
    /// is not intended to be used directly but rather through the [`address!`]
    /// macro.
    #[doc(hidden)]
    pub const fn const_from_str_checksum(src: &str) -> Self {
        let Address(addr) = Self::const_from_str(src);
        if !checksum::const_verify(&addr, src) {
            // TODO: It would be nice for the compiler error to tell you what
            // the expected checksummed address is, but alas that is currently
            // not possible.
            panic!("invalid address checksum");
        }
        Address(addr)
    }

    /// Returns a stack-allocated formatted string with the specified alphabet.
    fn fmt_buffer(&self, alphabet: Alphabet) -> FormattingBuffer<42> {
        hex::encode(self, alphabet)
    }

    /// Default formatting method for an address.
    fn fmt(&self) -> FormattingBuffer<42> {
        checksum::fmt(self)
    }
}

impl Debug for Address {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_tuple("Address")
            .field(&format_args!("{self}"))
            .finish()
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.pad(self.fmt().as_str())
    }
}

impl LowerHex for Address {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let buffer = self.fmt_buffer(Alphabet::Lower);
        f.pad(if f.alternate() {
            buffer.as_str()
        } else {
            buffer.as_bytes_str()
        })
    }
}

impl UpperHex for Address {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let buffer = self.fmt_buffer(Alphabet::Upper);
        f.pad(if f.alternate() {
            buffer.as_str()
        } else {
            buffer.as_bytes_str()
        })
    }
}

impl AsRef<[u8; 20]> for Address {
    fn as_ref(&self) -> &[u8; 20] {
        &self.0
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8; 20]> for Address {
    fn as_mut(&mut self) -> &mut [u8; 20] {
        &mut self.0
    }
}

impl AsMut<[u8]> for Address {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Deref for Address {
    type Target = [u8; 20];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Address {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl FromStr for Address {
    type Err = ParseAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(hex::decode(s)?))
    }
}

impl IntoIterator for Address {
    type Item = u8;
    type IntoIter = IntoIter<u8, 20>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Address {
    type Item = &'a u8;
    type IntoIter = Iter<'a, u8>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl PartialEq<[u8; 20]> for Address {
    fn eq(&self, other: &'_ [u8; 20]) -> bool {
        **self == *other
    }
}

impl PartialEq<[u8]> for Address {
    fn eq(&self, other: &'_ [u8]) -> bool {
        **self == *other
    }
}

impl PartialEq<&'_ [u8]> for Address {
    fn eq(&self, other: &&'_ [u8]) -> bool {
        **self == **other
    }
}

impl PartialEq<&'_ mut [u8]> for Address {
    fn eq(&self, other: &&'_ mut [u8]) -> bool {
        **self == **other
    }
}

#[cfg(feature = "std")]
impl PartialEq<Vec<u8>> for Address {
    fn eq(&self, other: &Vec<u8>) -> bool {
        **self == **other
    }
}

impl TryFrom<&'_ [u8]> for Address {
    type Error = TryFromSliceError;

    fn try_from(value: &'_ [u8]) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl TryFrom<&'_ mut [u8]> for Address {
    type Error = TryFromSliceError;

    fn try_from(value: &'_ mut [u8]) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl<'a> TryFrom<&'a [u8]> for &'a Address {
    type Error = TryFromSliceError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Ok(Address::from_ref(value.try_into()?))
    }
}

impl<'a> TryFrom<&'a mut [u8]> for &'a mut Address {
    type Error = TryFromSliceError;

    fn try_from(value: &'a mut [u8]) -> Result<Self, Self::Error> {
        Ok(Address::from_mut(value.try_into()?))
    }
}

#[cfg(feature = "std")]
impl TryFrom<Vec<u8>> for Address {
    type Error = Vec<u8>;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

/// Represents an error parsing an address from a string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseAddressError {
    /// The string does not have the correct length.
    InvalidLength,
    /// An invalid character was found.
    InvalidHexCharacter { c: char, index: usize },
    /// The checksum encoded in the hex string's case does not match the
    /// address.
    ChecksumMismatch,
}

impl Display for ParseAddressError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::InvalidLength => write!(f, "{}", ParseHexError::InvalidLength),
            Self::InvalidHexCharacter { c, index } => {
                let (c, index) = (*c, *index);
                write!(f, "{}", ParseHexError::InvalidHexCharacter { c, index })
            }
            Self::ChecksumMismatch => {
                write!(f, "address checksum does not match")
            }
        }
    }
}

impl From<ParseHexError> for ParseAddressError {
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
impl std::error::Error for ParseAddressError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_address() {
        for s in [
            "0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1",
            "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE",
        ] {
            let address = s.parse::<Address>().unwrap();
            assert_eq!(address.to_string(), s);
        }
    }

    #[test]
    fn without_prefix_and_checksum() {
        assert_eq!(
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                .parse::<Address>()
                .unwrap(),
            Address([0xee; 20]),
        );
    }

    #[test]
    fn verify_address_checksum() {
        for address in [
            "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE",
            "EeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE",
        ] {
            assert_eq!(
                Address::from_str_checksum(address).unwrap(),
                Address([0xee; 20])
            );
            assert_eq!(
                Address::const_from_str_checksum(address),
                Address([0xee; 20])
            );
        }

        for address in [
            "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        ] {
            assert!(Address::from_str_checksum(address).is_err());
        }
    }

    #[test]
    #[should_panic]
    fn const_verify_address_checksum_error() {
        Address::const_from_str_checksum("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
    }

    #[test]
    fn hex_formatting() {
        let address = Address([0xee; 20]);
        assert_eq!(
            format!("{address:x}"),
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        );
        assert_eq!(
            format!("{address:#x}"),
            "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        );
        assert_eq!(
            format!("{address:X}"),
            "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
        );
        assert_eq!(
            format!("{address:#X}"),
            "0xEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
        );
    }
}
