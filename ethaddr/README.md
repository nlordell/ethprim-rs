# Implementation of Ethereum public addresses for Rust.

This crate provides an `Address` type for representing Ethereum public
addresses.

## Usage

Just add a dependency to your `Cargo.toml`:

```toml
[dependencies]
ethaddr = "*"
```

For complete documentation checkout [`docs.rs`](https://docs.rs/ethaddr).

## Features

This crate provides a few features for fine-grained control of what gets
included with the crate.

> I want `#[no_std]`!

```toml
[dependencies]
ethaddr = { version = "*", default-features = false }
```

> I want to use the Rust-Crypto `sha3` crate for computing address checksums!

```toml
[dependencies]
ethaddr = { version = "*", features = ["sha3"] }
```

> I want `serde` support!

```toml
[dependencies]
ethaddr = { version = "*", features = ["serde"] }
```
