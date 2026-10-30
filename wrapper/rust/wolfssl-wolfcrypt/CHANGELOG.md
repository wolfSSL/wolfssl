# wolfssl-wolfcrypt Change Log

## v3.0.0

Breaking changes:

- Curve25519Key::generate() now takes ownership of the RNG instead of borrowing
  it; the key holds the RNG for its lifetime
- The rand_core::TryRng implementation for RNG is now truly fallible: its
  associated Error type is the new random::RngError, which carries the wolfSSL
  library error code, instead of core::convert::Infallible. Entropy, reseed
  and hardware failures are returned to the caller instead of panicking inside
  the library. As a consequence RNG no longer implements the infallible
  rand_core::Rng and rand_core::CryptoRng traits; wrap it in
  rand_core::UnwrapErr to keep the previous panic-on-failure behavior
- Ed25519 and Ed448 no longer implement the signature crate's Keypair trait;
  use the new SigningKey types instead
- MlDsa::LEVEL_44, MlDsa::LEVEL_65 and MlDsa::LEVEL_87 are now gated on the
  mldsa_level2, mldsa_level3 and mldsa_level5 cfgs, so selecting a parameter
  set the library was not built with is a compile error instead of a runtime
  NOT_COMPILED_IN
- Replace Lms::export_pub_from() with Lms::export_pub(), which returns a new
  verify only key instead of re-initializing an existing one; this fixes a leak
  of the destination's private key data
- CMAC::generate_ex() and CMAC::verify_ex() have been removed. They
  re-initialized an already-initialized CMAC object without freeing its
  existing resources, and left the object unusable afterward. Use
  CMAC::new_ex() followed by the new CMAC::update_and_finalize() or
  CMAC::update_and_verify() methods instead
- Key export methods now return the number of bytes written instead of ():
  Ed25519 and Ed448 export_public(), export_private() and
  export_private_only() return Result<usize, i32>, and Ed25519/Ed448
  export_key(), Curve25519Key::export_key_raw(),
  Curve25519Key::export_key_raw_ex() and MlDsa::export_key() return
  Result<(usize, usize), i32> holding the private and public key sizes.
  Previously, callers passing an oversized output buffer had no way to know
  where the exported key ended
- ChaCha20Poly1305::finalize() now fails with BAD_FUNC_ARG on a decryption
  instance; use finalize_verify() to authenticate decrypted data
- Ed25519 signing and verification methods taking a variant and context now
  return BAD_FUNC_ARG when a non-empty context is passed with the pure
  Ed25519::ED25519 variant, which does not bind a context and previously
  silently ignored it. Ed25519 and Ed448 also reject unknown variant values
- The crate build now fails instead of falling back to another wolfSSL when
  WOLFSSL_PREFIX is set but does not point at a usable installation, or when
  the containing wolfSSL repository is configured (wolfssl/options.h exists)
  but the library has not been built there. Previously the build could
  silently link against a system library built with different options
- The crate build now fails if wolfSSL was built with asynchronous crypto
  support (WOLFSSL_ASYNC_CRYPT), which the wrapper does not support

New features:

- Add the rand_core_0_9 feature: RNG implements the rand_core 0.9
  TryRngCore and TryCryptoRng traits, alongside the rand_core 0.10 ones, for
  users of the rand 0.9 ecosystem
- Add Curve25519Key::generate_shared_rng() to generate a key from an RNG shared
  between keys via Rc (requires the alloc feature)
- Add HMAC::copy(), a fallible equivalent of HMAC::clone()
- Add ed25519::SigningKey and ed448::SigningKey, which always carry a public
  key and so implement Keypair::verifying_key() without it being able to fail
- Add Lms::export_pub_ex() to set the heap hint and device ID of the exported
  verify only key
- The crate now declares `links = "wolfssl"` and publishes the directory of a
  shared wolfSSL library as the LIBDIRS metadata, so dependent crates' build
  scripts can read it from DEP_WOLFSSL_LIBDIRS (e.g. to set an rpath)
- build.rs looks for the library under either lib or lib64 in WOLFSSL_PREFIX,
  recognizes MinGW, Cygwin and MSVC library file names, and reruns when
  WOLFSSL_PREFIX changes

Fixes and improvements:

- Fix undefined behavior in HMAC::clone(): wc_HmacCopy() takes its source by
  non-const pointer and may write through it, but the pointer was cast from a
  shared reference. The wolfSSL context is now held in an UnsafeCell
- Fix a panic in Keypair::verifying_key() for Ed25519 and Ed448 keys with no
  public key, such as after new() or import_private_only()
- Validate PBKDF2 and scrypt password hash output length against the PHC
  minimum before running the KDF
- Fix detection of the built-in ML-DSA parameter sets: the mldsa_level2,
  mldsa_level3 and mldsa_level5 cfgs probed the WC_MLDSA_NN_KEY_SIZE macros,
  which wc_mldsa.h defines unconditionally, so all three were always enabled
- XChaCha20Poly1305Aead's AeadInPlace implementation no longer allocates a
  4112-byte buffer on the stack for every call and no longer limits messages to
  4096 bytes. Decryption now verifies the authentication tag before decrypting,
  so the caller's buffer is left unmodified when verification fails
- The rsa_oaep feature (RSA::public_encrypt_oaep(),
  RSA::private_decrypt_oaep() and the rsa_oaep module) is no longer enabled
  when wolfSSL is built with WC_NO_RSA_OAEP. Previously it failed to link, or
  with WC_RSA_NO_PADDING always returned an unsupported-padding error
- The ecdsa and rsa_pkcs1v15 modules are no longer enabled when wolfSSL is
  built with NO_SIG_WRAPPER. Both are built on wc_SignatureGenerate() and
  wc_SignatureVerify(), so previously they failed to link
- Ed25519 and Ed448 streaming verification with the prehash variant now
  requires exactly PREHASH_SIZE (64) bytes of input, matching one-shot
  verification
- RNG::generate_block() (and the rand_core implementation built on it) now
  fills buffers larger than RNG_MAX_BLOCK_LEN by splitting them into multiple
  DRBG requests, instead of failing with BAD_FUNC_ARG
- RustCrypto digest and MAC update implementations (SHA, BLAKE2, HMAC, CMAC)
  now split inputs larger than 4GB into multiple wolfCrypt updates instead of
  panicking
- AES CTR and OFB StreamCipher implementations no longer panic on buffers of
  4GB or more, and no longer create aliasing shared and mutable references to
  in-place buffers
- rsa_pkcs1v15::SigningKey validates its public components at construction,
  so Keypair::verifying_key() can no longer panic; rsa_pkcs1v15::VerifyingKey
  is now usable in builds without RNG support
- Fix memory leak when re-initializing SHA, SHA-2, SHA-3 and SHAKE instances
- Fix a possible dangling WC_RNG pointer held by a Curve25519Key
- ECC keys are created with wc_ecc_key_new_ex() when available so the heap
  hint and device ID are applied at initialization
- kdf::ssh_kdf() rejects hash type values that do not fit in a byte instead
  of truncating them
- Zeroize additional sensitive temporaries: ML-KEM private keys and shared
  secrets, PBKDF2/scrypt intermediate password hashes, AEAD keys, and the
  ChaCha20-Poly1305 context on error paths
- Numerous cfg detection fixes so the crate builds and links against reduced
  wolfSSL configurations, including: separate SHA3-224/256/384/512 detection;
  AES-CFB/OFB decrypt; verify-only ECC (ecdsa module) and ECC export;
  RSA without RNG, private key or signing support; Ed25519/Ed448 without RNG
  or key generation; Curve25519 import, export and shared secret; ML-KEM per
  operation and parameter set, and builds with WC_NO_CONSTRUCTORS; ML-DSA
  public/private import and export; LMS without key generation; PBKDF2
  password hashing with only some of SHA-256/384/512 enabled; and the rsa_oaep
  probe under FIPS
- Numerous documentation corrections, including output buffer sizes for HKDF,
  KDF and BLAKE2, AES-XTS key sizes, Ed448 prehash (SHAKE256), and documenting
  wolfcrypt_cleanup() preconditions and RNG::health_test_ex() seed_b
  requirements

## v2.2.0

New features:

- Add DH::prime_size() to query the DH prime size, which is the minimum output
  buffer size DH::shared_secret() requires
- Add ChaCha20Poly1305::finalize_verify()

Fixes and improvements:

- Fix DH::shared_secret() writing past the end of an output buffer smaller than
  the DH prime; it now returns BUFFER_E instead

## v2.1.0

Fixes:

- Fix Ed25519/Ed448 signature verify failed return values
- Validate WOLFSSL_PREFIX in build.rs
- Rename dilithium to mldsa

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
