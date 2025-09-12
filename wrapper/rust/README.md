# wolfSSL Rust Wrapper

## Building the wolfssl Rust Wrapper

First, configure and build wolfssl C library.

Then build the wolfssl Rust wrapper with:

    make -C wrapper/rust

## Repository Directory Structure

| Repository Directory | Description |
| --- | --- |
| `/wrapper/rust` | Top level container for all Rust wrapper functionality. |
| `/wrapper/rust/wolfssl` | Top level for the `wolfssl` library crate. This crate contains high-level Rust sources that use the bindings from the `wolfssl-sys` crate. |
| `/wrapper/rust/wolfssl-sys` | Top level for the `wolfssl-sys` library crate. This crate contains only automatically generated bindings to the `wolfssl` C library. |
