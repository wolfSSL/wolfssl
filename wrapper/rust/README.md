# wolfSSL Rust Wrapper

## Building the wolfssl Rust Wrapper

First, configure and build wolfssl C library.

Then build the wolfssl Rust wrapper with:

    make -C wrapper/rust

Run tests with:

    make -C wrapper/rust test

## Repository Directory Structure

| Repository Directory | Description |
| --- | --- |
| `/wrapper/rust` | Top level container for all Rust wrapper functionality. |
| `/wrapper/rust/wolfssl` | Top level for the `wolfssl` library crate. |
| `/wrapper/rust/wolfssl/src` | Source directory for `wolfssl` crate top-level modules. |
| `/wrapper/rust/wolfssl/src/wolfcrypt` | Source directory for submodules of `wolfssl::wolfcrypt` module. |
