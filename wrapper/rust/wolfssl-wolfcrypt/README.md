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
