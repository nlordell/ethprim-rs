# Implementation of Ethereum 32-byte digests for Rust.

This crate provides a `Digest` type for representing Ethereum 32-byte digests.

Additionally it includes macros for digest constants, both from hexidecimal
strings, but also by compile-time Keccak-256 hashing inputs. Under the hood,
they are implemented with `const fn` and do not use procedural macros.

## Usage

Just add a dependency to your `Cargo.toml`:

```toml
[dependencies]
ethdigest = "*"
```

For complete documentation checkout [`docs.rs`](https://docs.rs/ethdigest).
