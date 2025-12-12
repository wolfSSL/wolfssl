# wolfSSL Rust Wrapper

The wolfSSL Rust wrapper currently consists of a single Rust crate named
`wolfssl-wolfcrypt`. This crate provides wrappers for the cryptographic
algorithms supported by wolfCrypt in the wolfSSL library.

The `wolfssl-wolfcrypt` crate is intended to be published to
[crates.io](https://crates.io/) and can be used by including it in your
project's `Cargo.toml` file.

It can also be built locally from within the wolfssl C library repository to
test changes to the C library using the Rust API.

## Locally building the wolfssl-wolfcrypt crate

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

## API Coverage

The wolfSSL Rust wrapper provides a wrapper API for the following C library
functionality:

  * AES
    * CBC, CCM, CFB, CTR, EAX, ECB, GCM, OFB, XTS
  * CMAC
  * DH
  * ECC
  * Ed448
  * Ed25519
  * HKDF
  * HMAC
  * PBKDF2
  * PKCS #12 PBKDF
  * PRF
  * RSA
  * RNG
  * SHA
    * SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA3-224, SHA3-256, SHA3-384,
      SHA3-512, SHAKE128, SHAKE256
  * SRTP/SRTCP KDF
  * SSH KDF
  * TLSv1.3 HKDF
