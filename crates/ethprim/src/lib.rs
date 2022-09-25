//! A meta-crate that aggregates various Ethereum primitive types.
//!
//! Currently, this crate re-exports:
//! - [`ethaddr`]: Ethereum public address
//! - [`ethdigest`]: Ethereum digest and hashing utilities
//! - [`ethnum`]: 256-bit integers

#![no_std]

#[cfg(feature = "macros")]
pub use ethaddr::address;
pub use ethaddr::{Address, ParseAddressError};
#[cfg(feature = "macros")]
pub use ethdigest::{digest, keccak};
pub use ethdigest::{Digest, Keccak, ParseDigestError};
#[cfg(feature = "macros")]
pub use ethnum::{int, uint};
pub use ethnum::{AsI256, AsU256, I256, U256};

/// Re-export of all included crates.
pub mod meta {
    pub use ethaddr;
    pub use ethdigest;
    pub use ethnum;
}

/// 256-bit integer re-exports.
pub mod num {
    pub use ethnum::intrinsics;
    #[cfg(feature = "serde")]
    pub use ethnum::serde;
}

/// Convenience re-export of core types and traits.
pub mod prelude {
    pub use ethaddr::Address;
    pub use ethdigest::Digest;
    pub use ethnum::{AsI256, AsU256, I256, U256};
}
