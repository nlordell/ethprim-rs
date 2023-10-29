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
/// A Keccak-256 [`Hasher`] can be used to compute a digest for data in chunks:
///
/// ```
/// # use ethdigest::{keccak, digest, Hasher};
/// let mut hasher = Hasher::new();
/// hasher.update("Hello ");
/// hasher.update("Ethereum!");
/// let digest = hasher.finalize();
/// assert_eq!(digest, keccak!(b"Hello Ethereum!"));
/// assert_eq!(
///     digest,
///     digest!("0x67e083fb08738b8d7984e349687fec5bf03224c2dad4906020dfab9a0e4ceeac"),
/// );
/// ```
///
/// Additionally, the hasher implements [`std::io::Write`] and
/// [`core::fmt::Write`] traits, allowing you to use it for writing buffered
/// data or formatted input:
///
/// ```
/// # use ethdigest::{keccak, digest, Hasher};
/// # fn main() -> std::fmt::Result {
/// use std::fmt::Write;
/// let answer = 42;
/// let mut hasher = Hasher::new();
/// write!(&mut hasher, "The Answer is {answer}")?;
/// let digest = hasher.finalize();
/// assert_eq!(digest, keccak!(b"The Answer is 42"));
/// assert_eq!(
///     digest,
///     digest!("0xf9d9f4d155c91f313f104a6d5d013959dfa819490df182a4bcda752ee9833d5d"),
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
