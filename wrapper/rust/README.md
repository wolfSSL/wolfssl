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
