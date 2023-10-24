//! Module implementing Ethereum Keccak-256 hashing utilities.

use crate::Digest;
use core::fmt::{self, Debug, Formatter};

#[cfg(feature = "sha3")]
type Impl = sha3::Keccak256;
#[cfg(not(feature = "sha3"))]
type Impl = crate::keccak::V256;

/// A Keccak-256 hasher.
///
/// # Examples
///
/// A Keccak-256 [`Hasher`] can be used to compute a digest for data in chinks:
///
/// ```
/// # use ethdigest::{keccak, Digest, Hasher};
/// let mut hasher = Hasher::new();
/// hasher.update("Hello ");
/// hasher.update("Ethereum!");
/// let digest = hasher.finalize();
/// assert_eq!(digest, keccak!("Hello Ethereum!"));
/// assert_eq!(
///     digest,
///     Digest([
///         0x67, 0xe0, 0x83, 0xfb, 0x08, 0x73, 0x8b, 0x8d,
///         0x79, 0x84, 0xe3, 0x49, 0x68, 0x7f, 0xec, 0x5b,
///         0xf0, 0x32, 0x24, 0xc2, 0xda, 0xd4, 0x90, 0x60,
///         0x20, 0xdf, 0xab, 0x9a, 0x0e, 0x4c, 0xee, 0xac,
///     ]),
/// );
/// ```
///
/// Additionally, the hasher implements [`std::io::Write`] and
/// [`core::fmt::Write`] traits, allowing you to use it for writing buffered
/// data or formatted input:
///
/// ```
/// # use ethdigest::{keccak, Digest, Hasher};
/// # fn main() -> std::fmt::Result {
/// use std::fmt::Write;
/// let answer = 42;
/// let mut hasher = Hasher::new();
/// write!(&mut hasher, "The Answer is {answer}")?;
/// let digest = hasher.finalize();
/// assert_eq!(digest, keccak!("The Answer is 42"));
/// assert_eq!(
///     digest,
///     Digest([
///         0xf9, 0xd9, 0xf4, 0xd1, 0x55, 0xc9, 0x1f, 0x31,
///         0x3f, 0x10, 0x4a, 0x6d, 0x5d, 0x01, 0x39, 0x59,
///         0xdf, 0xa8, 0x19, 0x49, 0x0d, 0xf1, 0x82, 0xa4,
///         0xbc, 0xda, 0x75, 0x2e, 0xe9, 0x83, 0x3d, 0x5d,
///     ]),
/// );
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Default)]
pub struct Hasher(Impl);

impl Hasher {
    /// Creates a new [`Hasher`] istance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Processes new data and updates the hasher.
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        #[cfg(feature = "sha3")]
        {
            sha3::Digest::update(&mut self.0, data.as_ref());
        }
        #[cfg(not(feature = "sha3"))]
        {
            self.0 = self.0.absorb(data.as_ref());
        }
    }

    /// Retrieve the resulting digest.
    pub fn finalize(self) -> Digest {
        #[cfg(feature = "sha3")]
        {
            Digest(sha3::Digest::finalize(self.0).into())
        }
        #[cfg(not(feature = "sha3"))]
        {
            Digest(self.0.squeeze())
        }
    }
}

impl Debug for Hasher {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_tuple("Hasher").finish()
    }
}

impl fmt::Write for Hasher {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.update(s);
        Ok(())
    }
}

#[cfg(feature = "std")]
mod io {
    use super::Hasher;
    use std::io::{self, Write};

    impl Write for Hasher {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.update(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
