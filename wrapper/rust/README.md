# wolfSSL Rust Wrapper

The wolfSSL Rust wrapper currently consists of a single Rust crate named
`wolfssl-wolfcrypt`.
The `wolfssl-wolfcrypt` crate is a Rust wrapper for the wolfCrypt cryptographic
algorithms portion of the wolfSSL C library.

## Locally building and testing the wolfSSL Rust Wrapper

First, configure and build wolfssl C library.

Then build the wolfssl Rust wrapper with:

    make -C wrapper/rust

Run tests with:

    make -C wrapper/rust test

## Repository Directory Structure

| Repository Directory | Description |
| --- | --- |
| `/wrapper/rust` | Top level container for all Rust wrapper functionality. |
| `/wrapper/rust/wolfssl-wolfcrypt` | Top level for the `wolfssl-wolfcrypt` library crate. |
| `/wrapper/rust/wolfssl-wolfcrypt/src` | Source directory for `wolfssl-wolfcrypt` crate top-level modules. |
