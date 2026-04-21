# wolfssl-wolfcrypt crate

The `wolfssl-wolfcrypt` crate is a Rust wrapper for the wolfCrypt cryptographic
algorithms portion of the wolfSSL C library.

## Installation

The `wolfssl` C library must be installed to be used by the Rust crate.

The `wolfssl-wolfcrypt` crate can be used by including it as a dependency in
your project's `Cargo.toml` file.

For example:

```
[dependencies]
wolfssl-wolfcrypt = "1.0"
```

## API Coverage

This crate provides a wrapper API for the following wolfCrypt C library
functionality:

  * AES
    * CBC, CCM, CFB, CTR, EAX, ECB, GCM, OFB, XTS
  * BLAKE2
  * CMAC
  * ChaCha20-Poly1305
  * Curve25519
  * DH
  * ECC
  * Ed25519
  * Ed448
  * HKDF
  * HMAC
  * LMS
  * ML-DSA
  * ML-KEM
  * PBKDF2
  * PKCS #12 PBKDF
  * PRF
  * RNG
  * RSA
  * SHA
    * SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA3-224, SHA3-256, SHA3-384,
      SHA3-512, SHAKE128, SHAKE256
  * SRTP/SRTCP KDF
  * SSH KDF
  * TLSv1.3 HKDF

## Build Notes

### WOLFSSL_PREFIX

If the wolfSSL C library is not installed in a default location, you can
specify the installation prefix with the `WOLFSSL_PREFIX` environment variable
when building the `wolfssl-wolfcrypt` crate.

For example:

```
WOLFSSL_PREFIX=/opt/my-wolfssl-build cargo build
```

### Cross-Compiling

Ensure that the target you want to build for is installed for Rust.
For example:

```
rustup target add riscv64imac-unknown-none-elf
```

Build with the `--target` option if building manually:

```
export WOLFSSL_PREFIX=/opt/wolfssl-riscv64
cargo build --target riscv64imac-unknown-none-elf
```

To specify the linker for the target:

```
export CARGO_TARGET_RISCV64IMAC_UNKNOWN_NONE_ELF_LINKER=riscv64-elf-gcc
```
