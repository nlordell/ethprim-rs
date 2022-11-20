//! A simple Ethereum RPC implementation.

#[cfg(feature = "http")]
pub mod http;
pub mod jsonrpc;
#[macro_use]
pub mod method;
mod serialization;
pub mod types;

#[cfg(feature = "http")]
pub use reqwest;

use self::types::*;

module! {
    /// The `web3` namespace.
    pub mod web3 {
        /// Gets the current client version.
        pub struct ClientVersion as "web3_clientVersion"
            Empty => String;
    }
}

module! {
    /// The `eth` namespace.
    ///
    /// Documentation for the APIs can be found here:
    /// <https://ethereum.github.io/execution-apis/api-documentation/>
    pub mod eth {
        /// Gets the current client version.
        pub struct BlockNumber as "eth_blockNumber"
            Empty => U256;

        /// Simulates a transaction without adding it to the blockchain.
        pub struct Call as "eth_call"
            (TransactionCall, BlockId) => Vec<u8> [serialization::bytes];
    }
}

/// Module containing common extentions to the standard Ethereum RPC methods.
pub mod ext {
    use crate::{serialization, types::*};

    module! {
        /// Extensions to the `eth` namespace.
        pub mod eth {
            /// Simulates a transaction without adding it to the blockchain with
            /// support for state overrides.
            pub struct Call as "eth_call"
                (TransactionCall, BlockId, StateOverrides) => Vec<u8> [serialization::bytes];
        }
    }
}
