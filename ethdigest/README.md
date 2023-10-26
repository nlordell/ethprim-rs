# Implementation of Ethereum 32-byte digests for Rust.

This crate provides a `Digest` type for representing Ethereum 32-byte digests.

## Usage

Just add a dependency to your `Cargo.toml`:

```toml
[dependencies]
ethdigest = "*"
```

For complete documentation checkout [`docs.rs`](https://docs.rs/ethdigest).

## Features

This crate provides a few features for fine-grained control of what gets
included with the crate.

> I want `#[no_std]`!

```toml
[dependencies]
ethdigest = { version = "*", default-features = false }
```

> I want to use the Rust-Crypto `sha3` crate for hashing!

```toml
[dependencies]
ethaddr = { version = "*", features = ["sha3"] }
```

> I want `serde` support!

```toml
[dependencies]
ethaddr = { version = "*", features = ["serde"] }
```
