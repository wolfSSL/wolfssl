# wolfssl-wolfcrypt Change Log

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
