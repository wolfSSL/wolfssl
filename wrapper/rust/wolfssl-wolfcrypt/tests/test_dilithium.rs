/*
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#![cfg(dilithium)]

mod common;

use wolfssl_wolfcrypt::dilithium::Dilithium;
#[cfg(any(dilithium_make_key, dilithium_sign))]
use wolfssl_wolfcrypt::random::RNG;

/// Verify the level constants have the correct numeric values required by
/// the wolfCrypt API.
#[test]
fn test_level_constants() {
    assert_eq!(Dilithium::LEVEL_44, 2);
    assert_eq!(Dilithium::LEVEL_65, 3);
    assert_eq!(Dilithium::LEVEL_87, 5);
}

/// Verify `new()` + `set_level()` + `get_level()` for all three parameter sets.
#[test]
fn test_new_and_level() {
    common::setup();

    let mut key = Dilithium::new().expect("Error with new()");

    key.set_level(Dilithium::LEVEL_44).expect("Error with set_level()");
    assert_eq!(key.get_level().expect("Error with get_level()"), Dilithium::LEVEL_44);

    key.set_level(Dilithium::LEVEL_65).expect("Error with set_level()");
    assert_eq!(key.get_level().expect("Error with get_level()"), Dilithium::LEVEL_65);

    key.set_level(Dilithium::LEVEL_87).expect("Error with set_level()");
    assert_eq!(key.get_level().expect("Error with get_level()"), Dilithium::LEVEL_87);
}

/// Verify that `new_ex()` accepts the optional heap and device ID parameters.
#[test]
fn test_new_ex() {
    common::setup();
    let mut key = Dilithium::new_ex(None, None).expect("Error with new_ex()");
    key.set_level(Dilithium::LEVEL_44).expect("Error with set_level()");
    assert_eq!(key.get_level().expect("Error with get_level()"), Dilithium::LEVEL_44);
}

/// Verify the runtime size queries match the compile-time constants for
/// ML-DSA-44.
#[test]
#[cfg(all(dilithium_make_key, dilithium_level2))]
fn test_sizes_level44() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    let mut key = Dilithium::generate(Dilithium::LEVEL_44, &mut rng)
        .expect("Error with generate()");
    assert_eq!(key.size().expect("Error with size()"), Dilithium::LEVEL2_KEY_SIZE);
    assert_eq!(key.priv_size().expect("Error with priv_size()"), Dilithium::LEVEL2_PRV_KEY_SIZE);
    assert_eq!(key.pub_size().expect("Error with pub_size()"), Dilithium::LEVEL2_PUB_KEY_SIZE);
    assert_eq!(key.sig_size().expect("Error with sig_size()"), Dilithium::LEVEL2_SIG_SIZE);
}

/// Verify the runtime size queries match the compile-time constants for
/// ML-DSA-65.
#[test]
#[cfg(all(dilithium_make_key, dilithium_level3))]
fn test_sizes_level65() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    let mut key = Dilithium::generate(Dilithium::LEVEL_65, &mut rng)
        .expect("Error with generate()");
    assert_eq!(key.size().expect("Error with size()"), Dilithium::LEVEL3_KEY_SIZE);
    assert_eq!(key.priv_size().expect("Error with priv_size()"), Dilithium::LEVEL3_PRV_KEY_SIZE);
    assert_eq!(key.pub_size().expect("Error with pub_size()"), Dilithium::LEVEL3_PUB_KEY_SIZE);
    assert_eq!(key.sig_size().expect("Error with sig_size()"), Dilithium::LEVEL3_SIG_SIZE);
}

/// Verify the runtime size queries match the compile-time constants for
/// ML-DSA-87.
#[test]
#[cfg(all(dilithium_make_key, dilithium_level5))]
fn test_sizes_level87() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    let mut key = Dilithium::generate(Dilithium::LEVEL_87, &mut rng)
        .expect("Error with generate()");
    assert_eq!(key.size().expect("Error with size()"), Dilithium::LEVEL5_KEY_SIZE);
    assert_eq!(key.priv_size().expect("Error with priv_size()"), Dilithium::LEVEL5_PRV_KEY_SIZE);
    assert_eq!(key.pub_size().expect("Error with pub_size()"), Dilithium::LEVEL5_PUB_KEY_SIZE);
    assert_eq!(key.sig_size().expect("Error with sig_size()"), Dilithium::LEVEL5_SIG_SIZE);
}

/// Verify that `check_key()` accepts a freshly generated ML-DSA-44 key pair.
#[test]
#[cfg(all(dilithium_make_key, dilithium_check_key))]
fn test_check_key_level44() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    let mut key = Dilithium::generate(Dilithium::LEVEL_44, &mut rng)
        .expect("Error with generate()");
    key.check_key().expect("Error with check_key()");
}

/// Verify that `check_key()` accepts a freshly generated ML-DSA-65 key pair.
#[test]
#[cfg(all(dilithium_make_key, dilithium_check_key))]
fn test_check_key_level65() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    let mut key = Dilithium::generate(Dilithium::LEVEL_65, &mut rng)
        .expect("Error with generate()");
    key.check_key().expect("Error with check_key()");
}

/// Verify that `check_key()` accepts a freshly generated ML-DSA-87 key pair.
#[test]
#[cfg(all(dilithium_make_key, dilithium_check_key))]
fn test_check_key_level87() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    let mut key = Dilithium::generate(Dilithium::LEVEL_87, &mut rng)
        .expect("Error with generate()");
    key.check_key().expect("Error with check_key()");
}

/// Sign and verify a message round-trip using ML-DSA-44.
///
/// Also verifies that a tampered message or signature produces a
/// verification failure rather than an error.
#[test]
#[cfg(all(dilithium_make_key, dilithium_sign, dilithium_verify))]
fn test_sign_verify_level44() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    let mut key = Dilithium::generate(Dilithium::LEVEL_44, &mut rng)
        .expect("Error with generate()");
    let message = b"Hello, ML-DSA-44!";
    let mut sig = vec![0u8; key.sig_size().expect("Error with sig_size()")];

    let sig_len = key.sign_msg(message, &mut sig, Some(&mut rng))
        .expect("Error with sign_msg()");
    assert_eq!(sig_len, sig.len());

    let valid = key.verify_msg(&sig, message).expect("Error with verify_msg()");
    assert!(valid, "Valid signature should verify");

    // A different message must not verify with the original signature.
    let valid = key.verify_msg(&sig, b"Tampered message")
        .expect("Error with verify_msg() on tampered message");
    assert!(!valid, "Tampered message should not verify");
}

/// Sign and verify a message round-trip using ML-DSA-65.
#[test]
#[cfg(all(dilithium_make_key, dilithium_sign, dilithium_verify))]
fn test_sign_verify_level65() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    let mut key = Dilithium::generate(Dilithium::LEVEL_65, &mut rng)
        .expect("Error with generate()");
    let message = b"Hello, ML-DSA-65!";
    let mut sig = vec![0u8; key.sig_size().expect("Error with sig_size()")];

    let sig_len = key.sign_msg(message, &mut sig, Some(&mut rng))
        .expect("Error with sign_msg()");
    assert_eq!(sig_len, sig.len());

    let valid = key.verify_msg(&sig, message).expect("Error with verify_msg()");
    assert!(valid, "Valid signature should verify");
}

/// Sign and verify a message round-trip using ML-DSA-87.
#[test]
#[cfg(all(dilithium_make_key, dilithium_sign, dilithium_verify))]
fn test_sign_verify_level87() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    let mut key = Dilithium::generate(Dilithium::LEVEL_87, &mut rng)
        .expect("Error with generate()");
    let message = b"Hello, ML-DSA-87!";
    let mut sig = vec![0u8; key.sig_size().expect("Error with sig_size()")];

    let sig_len = key.sign_msg(message, &mut sig, Some(&mut rng))
        .expect("Error with sign_msg()");
    assert_eq!(sig_len, sig.len());

    let valid = key.verify_msg(&sig, message).expect("Error with verify_msg()");
    assert!(valid, "Valid signature should verify");
}

/// Sign with a context string and verify using ML-DSA-44.
///
/// Also verifies that a mismatched context causes verification to fail.
#[test]
#[cfg(all(dilithium_make_key, dilithium_sign, dilithium_verify))]
fn test_sign_ctx_verify_level44() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    let mut key = Dilithium::generate(Dilithium::LEVEL_44, &mut rng)
        .expect("Error with generate()");
    let message = b"Context-bound message";
    let ctx = b"my context";
    let mut sig = vec![0u8; key.sig_size().expect("Error with sig_size()")];

    let sig_len = key.sign_ctx_msg(ctx, message, &mut sig, Some(&mut rng))
        .expect("Error with sign_ctx_msg()");

    let valid = key.verify_ctx_msg(&sig[..sig_len], ctx, message)
        .expect("Error with verify_ctx_msg()");
    assert!(valid, "Valid context signature should verify");

    // Wrong context must not verify.
    let valid = key.verify_ctx_msg(&sig[..sig_len], b"wrong context", message)
        .expect("Error with verify_ctx_msg() with wrong context");
    assert!(!valid, "Wrong context should not verify");
}

/// Export both keys, re-import them separately, and verify that:
/// - a signature from the original key is accepted by a public-key-only
///   import, and
/// - the re-imported private key can sign messages that verify with the
///   original public key.
#[test]
#[cfg(all(dilithium_make_key, dilithium_import, dilithium_export, dilithium_sign, dilithium_verify))]
fn test_import_export_level44() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    let mut key = Dilithium::generate(Dilithium::LEVEL_44, &mut rng)
        .expect("Error with generate()");

    let priv_size = key.size().expect("Error with size()");
    let pub_size = key.pub_size().expect("Error with pub_size()");
    let sig_size = key.sig_size().expect("Error with sig_size()");

    let mut priv_buf = vec![0u8; priv_size];
    let mut pub_buf = vec![0u8; pub_size];
    key.export_key(&mut priv_buf, &mut pub_buf).expect("Error with export_key()");

    // Verify export_public and export_private return the same bytes.
    let mut pub_buf2 = vec![0u8; pub_size];
    let pub_written = key.export_public(&mut pub_buf2).expect("Error with export_public()");
    assert_eq!(pub_written, pub_size);
    assert_eq!(pub_buf2, pub_buf);

    let mut priv_buf2 = vec![0u8; priv_size];
    let priv_written = key.export_private(&mut priv_buf2).expect("Error with export_private()");
    assert_eq!(priv_written, priv_size);
    assert_eq!(priv_buf2, priv_buf);

    // Sign with the original key.
    let message = b"Import/export test message";
    let mut sig = vec![0u8; sig_size];
    let sig_len = key.sign_msg(message, &mut sig, Some(&mut rng))
        .expect("Error with sign_msg()");

    // Re-import public key only and verify.
    let mut pub_key = Dilithium::new().expect("Error with new()");
    pub_key.set_level(Dilithium::LEVEL_44).expect("Error with set_level()");
    pub_key.import_public(&pub_buf).expect("Error with import_public()");
    let valid = pub_key.verify_msg(&sig[..sig_len], message)
        .expect("Error with verify_msg() via imported public key");
    assert!(valid, "Imported public key should accept original signature");

    // Re-import private key, sign a message, and verify with the original key.
    let mut priv_key = Dilithium::new().expect("Error with new()");
    priv_key.set_level(Dilithium::LEVEL_44).expect("Error with set_level()");
    priv_key.import_private(&priv_buf).expect("Error with import_private()");
    let mut sig2 = vec![0u8; sig_size];
    let sig2_len = priv_key.sign_msg(message, &mut sig2, Some(&mut rng))
        .expect("Error with sign_msg() from imported private key");
    let valid = key.verify_msg(&sig2[..sig2_len], message)
        .expect("Error with verify_msg() after import_private");
    assert!(valid, "Signature from re-imported private key should verify");
}

/// Export both keys, import them together via `import_key()`, then sign and
/// verify using the re-imported key pair.
#[test]
#[cfg(all(dilithium_make_key, dilithium_import, dilithium_export, dilithium_sign, dilithium_verify))]
fn test_import_key_level44() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    let mut key = Dilithium::generate(Dilithium::LEVEL_44, &mut rng)
        .expect("Error with generate()");

    let priv_size = key.size().expect("Error with size()");
    let pub_size = key.pub_size().expect("Error with pub_size()");
    let sig_size = key.sig_size().expect("Error with sig_size()");

    let mut priv_buf = vec![0u8; priv_size];
    let mut pub_buf = vec![0u8; pub_size];
    key.export_key(&mut priv_buf, &mut pub_buf).expect("Error with export_key()");

    let mut key2 = Dilithium::new().expect("Error with new()");
    key2.set_level(Dilithium::LEVEL_44).expect("Error with set_level()");
    key2.import_key(&priv_buf, &pub_buf).expect("Error with import_key()");

    let message = b"import_key round-trip";
    let mut sig = vec![0u8; sig_size];
    let sig_len = key2.sign_msg(message, &mut sig, Some(&mut rng))
        .expect("Error with sign_msg() from imported key pair");
    let valid = key.verify_msg(&sig[..sig_len], message)
        .expect("Error with verify_msg()");
    assert!(valid, "Imported key pair should produce valid signatures");
}

/// Verify that `generate_from_seed()` is deterministic: the same seed
/// produces the same key pair on repeated calls.
#[test]
#[cfg(all(dilithium_make_key_from_seed, dilithium_export))]
fn test_generate_from_seed_determinism() {
    common::setup();
    // DILITHIUM_PRIV_SEED_SZ = 64 bytes
    let seed = [0x42u8; 64];

    let mut key1 = Dilithium::generate_from_seed(Dilithium::LEVEL_44, &seed)
        .expect("Error with generate_from_seed() first call");
    let mut key2 = Dilithium::generate_from_seed(Dilithium::LEVEL_44, &seed)
        .expect("Error with generate_from_seed() second call");

    let pub_size = key1.pub_size().expect("Error with pub_size()");
    let mut pub1 = vec![0u8; pub_size];
    let mut pub2 = vec![0u8; pub_size];
    key1.export_public(&mut pub1).expect("Error with export_public() key1");
    key2.export_public(&mut pub2).expect("Error with export_public() key2");
    assert_eq!(pub1, pub2, "Same seed must yield same public key");

    let priv_size = key1.size().expect("Error with size()");
    let mut priv1 = vec![0u8; priv_size];
    let mut priv2 = vec![0u8; priv_size];
    key1.export_private(&mut priv1).expect("Error with export_private() key1");
    key2.export_private(&mut priv2).expect("Error with export_private() key2");
    assert_eq!(priv1, priv2, "Same seed must yield same private key");
}

/// Verify that `sign_msg_with_seed()` is deterministic: the same key,
/// message, and signing seed always produce the same signature bytes, and
/// the signature verifies correctly.
#[test]
#[cfg(all(dilithium_make_key_from_seed, dilithium_sign_with_seed, dilithium_verify))]
fn test_sign_with_seed_determinism() {
    common::setup();
    // DILITHIUM_PRIV_SEED_SZ = 64 bytes
    let key_seed = [0x42u8; 64];
    // DILITHIUM_RND_SZ = 32 bytes
    let sign_seed = [0x55u8; 32];
    let message = b"Deterministic ML-DSA signing test";

    let mut key = Dilithium::generate_from_seed(Dilithium::LEVEL_44, &key_seed)
        .expect("Error with generate_from_seed()");

    let sig_size = key.sig_size().expect("Error with sig_size()");
    let mut sig1 = vec![0u8; sig_size];
    let mut sig2 = vec![0u8; sig_size];

    let len1 = key.sign_msg_with_seed(message, &mut sig1, &sign_seed)
        .expect("Error with sign_msg_with_seed() first call");
    let len2 = key.sign_msg_with_seed(message, &mut sig2, &sign_seed)
        .expect("Error with sign_msg_with_seed() second call");

    assert_eq!(len1, len2, "Signature lengths must match");
    assert_eq!(sig1[..len1], sig2[..len2], "Same inputs must yield same signature");

    let valid = key.verify_msg(&sig1[..len1], message)
        .expect("Error with verify_msg()");
    assert!(valid, "Deterministically signed message should verify");
}

/// Verify that `sign_ctx_msg_with_seed()` is deterministic and that the
/// produced signature verifies with `verify_ctx_msg()`.
#[test]
#[cfg(all(dilithium_make_key_from_seed, dilithium_sign_with_seed, dilithium_verify))]
fn test_sign_ctx_with_seed_determinism() {
    common::setup();
    let key_seed = [0x11u8; 64];
    let sign_seed = [0x22u8; 32];
    let message = b"Context deterministic signing test";
    let ctx = b"test-context";

    let mut key = Dilithium::generate_from_seed(Dilithium::LEVEL_44, &key_seed)
        .expect("Error with generate_from_seed()");

    let sig_size = key.sig_size().expect("Error with sig_size()");
    let mut sig1 = vec![0u8; sig_size];
    let mut sig2 = vec![0u8; sig_size];

    let len1 = key.sign_ctx_msg_with_seed(ctx, message, &mut sig1, &sign_seed)
        .expect("Error with sign_ctx_msg_with_seed() first call");
    let len2 = key.sign_ctx_msg_with_seed(ctx, message, &mut sig2, &sign_seed)
        .expect("Error with sign_ctx_msg_with_seed() second call");

    assert_eq!(len1, len2);
    assert_eq!(sig1[..len1], sig2[..len2], "Same inputs must yield same signature");

    let valid = key.verify_ctx_msg(&sig1[..len1], ctx, message)
        .expect("Error with verify_ctx_msg()");
    assert!(valid, "Context-signed message should verify");
}

/// Verify that `generate_from_seed()` + `sign_msg_with_seed()` +
/// `verify_msg()` work across all three security levels.
#[test]
#[cfg(all(dilithium_make_key_from_seed, dilithium_sign_with_seed, dilithium_verify))]
fn test_seed_sign_verify_all_levels() {
    common::setup();
    let key_seed = [0xABu8; 64];
    let sign_seed = [0xCDu8; 32];
    let message = b"All-levels seed sign/verify test";

    for level in [Dilithium::LEVEL_44, Dilithium::LEVEL_65, Dilithium::LEVEL_87] {
        let mut key = Dilithium::generate_from_seed(level, &key_seed)
            .expect("Error with generate_from_seed()");
        let sig_size = key.sig_size().expect("Error with sig_size()");
        let mut sig = vec![0u8; sig_size];
        let sig_len = key.sign_msg_with_seed(message, &mut sig, &sign_seed)
            .expect("Error with sign_msg_with_seed()");
        let valid = key.verify_msg(&sig[..sig_len], message)
            .expect("Error with verify_msg()");
        assert!(valid, "Level {} seed-signed message should verify", level);
    }
}
