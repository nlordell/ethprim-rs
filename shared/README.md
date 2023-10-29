# Shared Rust Modules

This directory contains stand-alone Rust source files that are shared between
various crates by creating symbolic links to these files.

These are distributed as stand-alone modules as they are small and simple enough
that I don't think it makes sense to bundle them into a crate.

Note that `shared` is also a crate added to the workspace just to simplify code
editing and tooling integration when working with this repository.
