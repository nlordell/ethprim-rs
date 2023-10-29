# Implementation of Ethereum public addresses for Rust.

This crate provides an `Address` type for representing Ethereum public
addresses. It implements [ERC-55](https://eips.ethereum.org/EIPS/eip-55)
mixed-case checksum `Display` formatting and parsing with verification using
`Address::from_str_checksum()`.

Additionally an `address!` macro is included for compile-time verified address
constants. Under the hood, it is implemented with `const fn` and does not use
procedural macros.

## Usage

Just add a dependency to your `Cargo.toml`:

```toml
[dependencies]
ethaddr = "*"
```

For complete documentation checkout [`docs.rs`](https://docs.rs/ethaddr).
