//! Stand-alone Rust source files that are shared between various crates via
//! symbolic links.
//!
//! These are distributed as stand-alone modules as they are small and simple
//! enough that I don't think it makes sense to bundle them into a crate.
//!
//! Note that we also have a `shared` just to simplify code editing and tooling
//! integration when working within the `ethcrates` workspace.

#![cfg_attr(not(test), no_std)]

pub mod hex;
pub mod keccak;
