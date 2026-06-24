# wolfssl-wolfcrypt Change Log

## v2.0.0

New features:

- Add RustCrypto trait support: digest, signature, mac, cipher, aead, rand_core,
  kem, and password-hash traits
- Add RSA-OAEP API
- Add scrypt KDF support and scrypt password-hash trait implementation
- Add BLAKE2 digest module (blake2_digest)
- Add BLAKE2 MAC module (blake2_mac)
- Add Aes192Ccm and Aes192Gcm
- Implement Clone for HMAC types
- Improve cross-compilation and bare-metal target support in build.rs

Fixes and improvements:

- LMS fixes and improvements
- Replace Lms::sigs_left() with Lms::has_sigs_left()
- Fix CFB::encrypt1 and CFB::decrypt1 to take size in bits
- Dilithium: fix context-length API to take length in bytes
- Handle MAC_CMP_FAILED_E from CMAC::verify{,_ex}()
- Numerous memory-safety, zeroization, and buffer-length validation hardening
  fixes (zeroize structs on drop, check slice/buffer length conversions, avoid
  uninitialized and overlapping buffers, fix possible ECC resource leaks)
- Document minimum wolfSSL version requirement

## v1.2.0

- Add LMS wrapper (wolfssl_wolfcrypt::lms module)
- Add ML-DSA wrapper (wolfssl_wolfcrypt::dilithium module)
- Add ML-KEM wrapper (wolfssl_wolfcrypt::mlkem module)
- Fix no_std support
- Add compatibility with older FIPS v5 package

## v1.1.0

- Add FIPS support
- ECC: allow `import_private_*()` calls with empty pub_buf slices
- Add HMAC-BLAKE2[bs] wrappers
- Add support for ChaCha20_Poly1305
- Add support for Curve25519
- Add support for BLAKE2b and BLAKE2s

## v1.0.0

- Bump version to 1.0 after testing

## v0.1.1

- Only set link-search and link-arg for local repo build

## v0.1.0

- Initial test version
