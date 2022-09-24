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

> I want runtime Keccak-256 hashing utilities!

```toml
[dependencies]
ethdigest = { version = "*", features = ["keccak"] }
```

> I want a macro for compile-time `Digest` literals and compilt-time Keccak-256
> hash computation, as well as `serde` support!

```toml
[dependencies]
ethdigest = { version = "*", features = ["macros", "serde"] }
```
