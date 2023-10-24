//! Checksummed formatting for Ethereum public addresses.

use crate::{
    hex::{self, Alphabet, FormattingBuffer},
    keccak,
};
use core::str;

/// Format address bytes with EIP-55 checksum.
pub fn fmt(bytes: &[u8; 20]) -> FormattingBuffer<42> {
    let mut buffer = hex::encode(bytes, Alphabet::Lower);

    // SAFETY: We only ever change lowercase ASCII characters to upper case
    // characters, so the buffer remains valid UTF-8 bytes.
    let addr = unsafe { &mut buffer.as_bytes_mut()[2..] };
    let digest = keccak256(addr);
    for i in 0..addr.len() {
        let byte = digest[i / 2];
        let nibble = 0xf & if i % 2 == 0 { byte >> 4 } else { byte };
        if nibble >= 8 {
            addr[i] = addr[i].to_ascii_uppercase();
        }
    }

    buffer
}

/// Verifies an address checksum.
pub fn verify(bytes: &[u8; 20], checksum: &str) -> Result<(), FormattingBuffer<42>> {
    let expected = fmt(bytes);
    if checksum.strip_prefix("0x").unwrap_or(checksum) != expected.as_bytes_str() {
        return Err(expected);
    }
    Ok(())
}

/// Verifies an address checksum as a `const fn`. Returns `true` if the checksum
/// matches the address.
pub const fn const_verify(bytes: &[u8; 20], checksum: &str) -> bool {
    const ALPHABET: [u8; 16] = *b"0123456789abcdef";

    let mut addr = [0; 40];
    let mut i = 0;
    while i < 20 {
        addr[i * 2] += ALPHABET[(bytes[i] >> 4) as usize];
        addr[i * 2 + 1] += ALPHABET[(bytes[i] & 15) as usize];
        i += 1;
    }

    let digest = keccak::v256(&addr);
    let mut i = 0;
    while i < 40 {
        let byte = digest[i / 2];
        let nibble = 0xf & if i % 2 == 0 { byte >> 4 } else { byte };
        if nibble >= 8 {
            addr[i] = addr[i].to_ascii_uppercase();
        }
        i += 1;
    }

    let checksum = hex::strip_hex_prefix(checksum).as_bytes();
    if checksum.len() != addr.len() {
        return false;
    }

    let mut i = 0;
    while i < 40 {
        if checksum[i] != addr[i] {
            return false;
        }
        i += 1;
    }

    true
}

/// Perform Keccak-256 hash over some input bytes.
fn keccak256(bytes: &[u8]) -> [u8; 32] {
    #[cfg(feature = "sha3")]
    {
        let mut hasher = sha3::Keccak256::default();
        sha3::Digest::update(&mut hasher, bytes);
        sha3::Digest::finalize(hasher).into()
    }
    #[cfg(not(feature = "sha3"))]
    {
        keccak::v256(bytes)
    }
}
