# Ethereum Digest Literals and Compile-time Hashing

This crate provides a procedural macro for compile-time Ethereum 32-byte digests
and hashing.

This is typically not used directly, but instead included with `ethdigest`:

```toml
[dependencies]
ethdigest = { version = "*", features = ["macros"] }
```
