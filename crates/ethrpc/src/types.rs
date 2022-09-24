//! Ethereum RPC types.

pub mod internal;

use crate::serialization;
use ethnum::AsU256 as _;
use serde::{
    de::{self, Deserializer},
    ser::{SerializeSeq as _, Serializer},
    Deserialize, Serialize,
};
use std::collections::HashMap;

pub use ethaddr::Address;
pub use ethdigest::Digest;
pub use ethnum::{I256, U256};

/// Empty JSON RPC parameters.
pub struct Empty;

impl Serialize for Empty {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_seq(Some(0))?.end()
    }
}

/// An Ethereum block specifier.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BlockSpec {
    /// Block by number.
    Number(U256),
    /// Block by tag.
    Tag(BlockTag),
}

impl Default for BlockSpec {
    fn default() -> Self {
        Self::Tag(Default::default())
    }
}

impl From<U256> for BlockSpec {
    fn from(number: U256) -> Self {
        Self::Number(number)
    }
}

impl From<u64> for BlockSpec {
    fn from(number: u64) -> Self {
        number.as_u256().into()
    }
}

impl From<BlockTag> for BlockSpec {
    fn from(tag: BlockTag) -> Self {
        Self::Tag(tag)
    }
}

/// An Ethereum block id.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BlockId {
    /// Block by number.
    Number(U256),
    /// Block by hash.
    Hash(Digest),
    /// Block by tag.
    Tag(BlockTag),
}

impl Default for BlockId {
    fn default() -> Self {
        Self::Tag(Default::default())
    }
}

impl From<U256> for BlockId {
    fn from(number: U256) -> Self {
        Self::Number(number)
    }
}

impl From<u64> for BlockId {
    fn from(number: u64) -> Self {
        number.as_u256().into()
    }
}

impl From<BlockTag> for BlockId {
    fn from(tag: BlockTag) -> Self {
        Self::Tag(tag)
    }
}

impl From<BlockSpec> for BlockId {
    fn from(spec: BlockSpec) -> Self {
        match spec {
            BlockSpec::Number(number) => Self::Number(number),
            BlockSpec::Tag(tag) => Self::Tag(tag),
        }
    }
}

/// An Ethereum block tag.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BlockTag {
    /// The lowest numbered block the client has available.
    Earliest,
    /// The most recent crypto-economically secure block, cannot be re-orged
    /// outside of manual intervention driven by community coordination.
    Finalized,
    /// The most recent block that is safe from re-orgs under honest majority
    /// and certain synchronicity assumptions.
    Safe,
    /// The most recent block in the canonical chain observed by the client,
    /// this block may be re-orged out of the canonical chain even under
    /// healthy/normal conditions.
    #[default]
    Latest,
    /// A sample next block built by the client on top of [`BlockTag::Latest`]
    /// and containing the set of transactions usually taken from local mempool.
    Pending,
}

/// An Ethereum transaction call objection.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionCall {
    /// The account sending the transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<Address>,
    /// The transaction type.
    pub kind: Option<TransactionKind>,
    /// The transaction nonce.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<U256>,
    /// The transaction recipient.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<Address>,
    /// The limit in gas units for the transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas: Option<U256>,
    /// The Ether value associated with the transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<U256>,
    /// The calldata associated with the transaction.
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "serialization::option_bytes"
    )]
    pub input: Option<Vec<u8>>,
    /// Gas price willing to be paid by the sender.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_price: Option<U256>,
    /// Maximum fee per gas the sender is willing to pay to miners in wei
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_priority_fee_per_gas: Option<U256>,
    /// The maximum total fee per gas the sender is willing to pay, including
    /// the network (A.K.A. base) fee and miner (A.K.A priority) fee.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_fee_per_gas: Option<U256>,
    /// State access list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_list: Option<AccessList>,
    /// Chain ID that the transaction is valid on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<U256>,
}

/// Ethereum transaction kind.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub enum TransactionKind {
    /// Legacy transaction type.
    #[default]
    Legacy = 0,
    /// An EIP-2930 transaction type.
    Eip2930 = 1,
    /// An EIP-1559 transaction type.
    Eip1559 = 2,
}

impl Serialize for TransactionKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (*self as u8).as_u256().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TransactionKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = U256::deserialize(deserializer)?;
        match u8::try_from(value) {
            Ok(0) => Ok(Self::Legacy),
            Ok(1) => Ok(Self::Eip2930),
            Ok(2) => Ok(Self::Eip1559),
            _ => Err(de::Error::custom(format!(
                "invalid transaction type {value}"
            ))),
        }
    }
}

/// An access list.
pub type AccessList = Vec<AccessListEntry>;

/// Access list entry.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct AccessListEntry {
    /// The address.
    pub address: Address,
    /// The storage keys.
    pub storage_keys: Vec<U256>,
}

/// State overrides.
pub type StateOverrides = HashMap<Address, StateOverride>;

/// State override object.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StateOverride {
    /// Fake balance to set for the account before executing the call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance: Option<U256>,
    /// Fake nonce to set for the account before executing the call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<U256>,
    /// Fake EVM bytecode to inject into the account before executing the call.
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "serialization::option_bytes"
    )]
    pub code: Option<Vec<u8>>,
    /// Fake key-value mapping to override **all** slots in the account storage
    /// before executing the call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<HashMap<U256, U256>>,
    /// Fake key-value mapping to override **individual** slots in the account
    /// storage before executing the call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_diff: Option<HashMap<U256, U256>>,
}
