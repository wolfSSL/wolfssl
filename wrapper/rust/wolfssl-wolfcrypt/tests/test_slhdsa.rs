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

#![cfg(slhdsa)]

mod common;

#[cfg(all(random, slhdsa_sign))]
use wolfssl_wolfcrypt::random::RNG;
use wolfssl_wolfcrypt::slhdsa::SlhDsa;

struct TestParams {
    params: u8,
    priv_size: usize,
    pub_size: usize,
    sig_size: usize,
}

const SHAKE_PARAMS: [TestParams; 6] = [
    TestParams {
        params: SlhDsa::SHAKE_128S,
        priv_size: SlhDsa::SHAKE_128S_PRV_KEY_SIZE,
        pub_size: SlhDsa::SHAKE_128S_PUB_KEY_SIZE,
        sig_size: SlhDsa::SHAKE_128S_SIG_SIZE,
    },
    TestParams {
        params: SlhDsa::SHAKE_128F,
        priv_size: SlhDsa::SHAKE_128F_PRV_KEY_SIZE,
        pub_size: SlhDsa::SHAKE_128F_PUB_KEY_SIZE,
        sig_size: SlhDsa::SHAKE_128F_SIG_SIZE,
    },
    TestParams {
        params: SlhDsa::SHAKE_192S,
        priv_size: SlhDsa::SHAKE_192S_PRV_KEY_SIZE,
        pub_size: SlhDsa::SHAKE_192S_PUB_KEY_SIZE,
        sig_size: SlhDsa::SHAKE_192S_SIG_SIZE,
    },
    TestParams {
        params: SlhDsa::SHAKE_192F,
        priv_size: SlhDsa::SHAKE_192F_PRV_KEY_SIZE,
        pub_size: SlhDsa::SHAKE_192F_PUB_KEY_SIZE,
        sig_size: SlhDsa::SHAKE_192F_SIG_SIZE,
    },
    TestParams {
        params: SlhDsa::SHAKE_256S,
        priv_size: SlhDsa::SHAKE_256S_PRV_KEY_SIZE,
        pub_size: SlhDsa::SHAKE_256S_PUB_KEY_SIZE,
        sig_size: SlhDsa::SHAKE_256S_SIG_SIZE,
    },
    TestParams {
        params: SlhDsa::SHAKE_256F,
        priv_size: SlhDsa::SHAKE_256F_PRV_KEY_SIZE,
        pub_size: SlhDsa::SHAKE_256F_PUB_KEY_SIZE,
        sig_size: SlhDsa::SHAKE_256F_SIG_SIZE,
    },
];

#[cfg(slhdsa_sha2)]
const SHA2_PARAMS: [TestParams; 6] = [
    TestParams {
        params: SlhDsa::SHA2_128S,
        priv_size: SlhDsa::SHA2_128S_PRV_KEY_SIZE,
        pub_size: SlhDsa::SHA2_128S_PUB_KEY_SIZE,
        sig_size: SlhDsa::SHA2_128S_SIG_SIZE,
    },
    TestParams {
        params: SlhDsa::SHA2_128F,
        priv_size: SlhDsa::SHA2_128F_PRV_KEY_SIZE,
        pub_size: SlhDsa::SHA2_128F_PUB_KEY_SIZE,
        sig_size: SlhDsa::SHA2_128F_SIG_SIZE,
    },
    TestParams {
        params: SlhDsa::SHA2_192S,
        priv_size: SlhDsa::SHA2_192S_PRV_KEY_SIZE,
        pub_size: SlhDsa::SHA2_192S_PUB_KEY_SIZE,
        sig_size: SlhDsa::SHA2_192S_SIG_SIZE,
    },
    TestParams {
        params: SlhDsa::SHA2_192F,
        priv_size: SlhDsa::SHA2_192F_PRV_KEY_SIZE,
        pub_size: SlhDsa::SHA2_192F_PUB_KEY_SIZE,
        sig_size: SlhDsa::SHA2_192F_SIG_SIZE,
    },
    TestParams {
        params: SlhDsa::SHA2_256S,
        priv_size: SlhDsa::SHA2_256S_PRV_KEY_SIZE,
        pub_size: SlhDsa::SHA2_256S_PUB_KEY_SIZE,
        sig_size: SlhDsa::SHA2_256S_SIG_SIZE,
    },
    TestParams {
        params: SlhDsa::SHA2_256F,
        priv_size: SlhDsa::SHA2_256F_PRV_KEY_SIZE,
        pub_size: SlhDsa::SHA2_256F_PUB_KEY_SIZE,
        sig_size: SlhDsa::SHA2_256F_SIG_SIZE,
    },
];

/// Verify the SHAKE parameters constants have the correct numeric values required by
/// the wolfCrypt API.
#[test]
fn test_shake_param_constants() {
    assert_eq!(SlhDsa::SHAKE_128S, 0);
    assert_eq!(SlhDsa::SHAKE_128F, 1);
    assert_eq!(SlhDsa::SHAKE_192S, 2);
    assert_eq!(SlhDsa::SHAKE_192F, 3);
    assert_eq!(SlhDsa::SHAKE_256S, 4);
    assert_eq!(SlhDsa::SHAKE_256F, 5);
}

/// Verify the SHA2 parameters constants have the correct numeric values required by
/// the wolfCrypt API.
#[test]
#[cfg(slhdsa_sha2)]
fn test_sha2_param_constants() {
    assert_eq!(SlhDsa::SHA2_128S, 6);
    assert_eq!(SlhDsa::SHA2_128F, 7);
    assert_eq!(SlhDsa::SHA2_192S, 8);
    assert_eq!(SlhDsa::SHA2_192F, 9);
    assert_eq!(SlhDsa::SHA2_256S, 10);
    assert_eq!(SlhDsa::SHA2_256F, 11);
}

/// Verify `new()` for all SHAKE parameter sets.
#[test]
fn test_new_shake() {
    common::setup();

    for params in SHAKE_PARAMS {
        SlhDsa::new(params.params).expect("Error with new()");
    }
}

/// Verify `new()` for all SHA2 parameter sets.
#[test]
#[cfg(slhdsa_sha2)]
fn test_new_sha2() {
    common::setup();

    for params in SHA2_PARAMS {
        SlhDsa::new(params.params).expect("Error with new()");
    }
}

/// Verify the runtime size queries match the compile-time constants for
/// SHAKE parameter sets.
#[test]
fn test_sizes_shake() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    for params in SHAKE_PARAMS {
        let mut key = SlhDsa::generate(params.params, &mut rng).expect("Error with generate()");
        assert_eq!(
            key.priv_size().expect("Error with priv_size()"),
            params.priv_size
        );
        assert_eq!(
            key.pub_size().expect("Error with pub_size()"),
            params.pub_size
        );
        assert_eq!(
            key.sig_size().expect("Error with sig_size()"),
            params.sig_size
        );
    }
}

/// Verify the runtime size queries match the compile-time constants for
/// SHA2 parameter sets.
#[test]
#[cfg(slhdsa_sha2)]
fn test_sizes_sha2() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    for params in SHA2_PARAMS {
        let mut key = SlhDsa::generate(params.params, &mut rng).expect("Error with generate()");
        assert_eq!(
            key.priv_size().expect("Error with priv_size()"),
            params.priv_size
        );
        assert_eq!(
            key.pub_size().expect("Error with pub_size()"),
            params.pub_size
        );
        assert_eq!(
            key.sig_size().expect("Error with sig_size()"),
            params.sig_size
        );
    }
}

/// Verify that `check_key()` accepts a freshly generated SLH-DSA key pair for
/// SHAKE parameter sets
#[test]
#[cfg(slhdsa_sign)]
fn test_check_key_shake() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    for params in SHAKE_PARAMS {
        let mut key = SlhDsa::generate(params.params, &mut rng).expect("Error with generate()");
        key.check_key().expect("Error with check_key()");
    }
}

/// Verify that `check_key()` accepts a freshly generated SLH-DSA key pair for
/// SHA2 parameter sets
#[test]
#[cfg(all(slhdsa_sign, slhdsa_sha2))]
fn test_check_key_sha2() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    for params in SHA2_PARAMS {
        let mut key = SlhDsa::generate(params.params, &mut rng).expect("Error with generate()");
        key.check_key().expect("Error with check_key()");
    }
}

/// Sign and verify a message round-trip using SLH-DSA for SHAKE
/// parameter sets
///
/// Also verifies that a tampered message or signature produces a
/// verification failure rather than an error.
#[test]
#[cfg(slhdsa_sign)]
fn test_sign_verify_shake() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    for params in SHAKE_PARAMS {
        let mut key = SlhDsa::generate(params.params, &mut rng).expect("Error with generate()");
        let message = b"Hello, SLH-DSA-SHAKE!";
        let mut sig = vec![0u8; key.sig_size().expect("Error with sig_size()")];

        let sig_len = key
            .sign_msg(message, &mut sig, &mut rng)
            .expect("Error with sign_msg()");
        assert_eq!(sig_len, sig.len());

        let valid = key.verify_msg(&sig, message);
        assert!(valid.is_ok(), "Valid signature should verify");

        // A different message must not verify with the original signature.
        let valid = key.verify_msg(&sig, b"Tampered message");
        assert!(valid.is_err(), "Tampered message should not verify");
    }
}

/// Sign and verify a message round-trip using SLH-DSA for SHA2
/// parameter sets
///
/// Also verifies that a tampered message or signature produces a
/// verification failure rather than an error.
#[test]
#[cfg(all(slhdsa_sign, slhdsa_sha2))]
fn test_sign_verify_sha2() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    for params in SHA2_PARAMS {
        let mut key = SlhDsa::generate(params.params, &mut rng).expect("Error with generate()");
        let message = b"Hello, SLH-DSA-SHA2!";
        let mut sig = vec![0u8; key.sig_size().expect("Error with sig_size()")];

        let sig_len = key
            .sign_msg(message, &mut sig, &mut rng)
            .expect("Error with sign_msg()");
        assert_eq!(sig_len, sig.len());

        let valid = key.verify_msg(&sig, message);
        assert!(valid.is_ok(), "Valid signature should verify");

        // A different message must not verify with the original signature.
        let valid = key.verify_msg(&sig, b"Tampered message");
        assert!(valid.is_err(), "Tampered message should not verify");
    }
}

/// Sign with a context string and verify using SLH-DSA for SHAKE
/// parameter sets
///
/// Also verifies that a mismatched context causes verification to fail.
#[test]
#[cfg(slhdsa_sign)]
fn test_sign_ctx_verify_shake() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    for params in SHAKE_PARAMS {
        let mut key = SlhDsa::generate(params.params, &mut rng).expect("Error with generate()");
        let message = b"Context-bound message";
        let ctx = b"my context";
        let mut sig = vec![0u8; key.sig_size().expect("Error with sig_size()")];

        let sig_len = key
            .sign_ctx_msg(ctx, message, &mut sig, &mut rng)
            .expect("Error with sign_ctx_msg()");

        let valid = key.verify_ctx_msg(&sig[..sig_len], ctx, message);
        assert!(valid.is_ok(), "Valid context signature should verify");

        // Wrong context must not verify.
        let valid = key.verify_ctx_msg(&sig[..sig_len], b"wrong context", message);
        assert!(valid.is_err(), "Wrong context should not verify");
    }
}

/// Sign with a context string and verify using SLH-DSA for SHA2
/// parameter sets
///
/// Also verifies that a mismatched context causes verification to fail.
#[test]
#[cfg(all(slhdsa_sign, slhdsa_sha2))]
fn test_sign_ctx_verify_sha2() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    for params in SHA2_PARAMS {
        let mut key = SlhDsa::generate(params.params, &mut rng).expect("Error with generate()");
        let message = b"Context-bound message";
        let ctx = b"my context";
        let mut sig = vec![0u8; key.sig_size().expect("Error with sig_size()")];

        let sig_len = key
            .sign_ctx_msg(ctx, message, &mut sig, &mut rng)
            .expect("Error with sign_ctx_msg()");

        let valid = key.verify_ctx_msg(&sig[..sig_len], ctx, message);
        assert!(valid.is_ok(), "Valid context signature should verify");

        // Wrong context must not verify.
        let valid = key.verify_ctx_msg(&sig[..sig_len], b"wrong context", message);
        assert!(valid.is_err(), "Wrong context should not verify");
    }
}

/// Export both keys for SHAKE parameter sets, re-import them separately,
/// and verify that:
/// - a signature from the original key is accepted by a public-key-only
///   import, and
/// - the re-imported private key can sign messages that verify with the
///   original public key.
#[test]
#[cfg(slhdsa_sign)]
fn test_import_export_shake() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    for params in SHAKE_PARAMS {
        let mut key = SlhDsa::generate(params.params, &mut rng).expect("Error with generate()");

        let priv_size = key.priv_size().expect("Error with priv_size()");
        let pub_size = key.pub_size().expect("Error with pub_size()");
        let sig_size = key.sig_size().expect("Error with sig_size()");

        let mut pub_buf = vec![0u8; pub_size];
        let pub_written = key
            .export_public(&mut pub_buf)
            .expect("Error with export_public()");
        assert_eq!(pub_written, pub_size);

        let mut priv_buf = vec![0u8; priv_size];
        let priv_written = key
            .export_private(&mut priv_buf)
            .expect("Error with export_private()");
        assert_eq!(priv_written, priv_size);

        // Sign with the original key.
        let message = b"Import/export test message";
        let mut sig = vec![0u8; sig_size];
        let sig_len = key
            .sign_msg(message, &mut sig, &mut rng)
            .expect("Error with sign_msg()");

        // Re-import public key only and verify.
        let mut pub_key = SlhDsa::new(params.params).expect("Error with new()");
        pub_key
            .import_public(&pub_buf)
            .expect("Error with import_public()");
        let valid = pub_key.verify_msg(&sig[..sig_len], message);
        assert!(
            valid.is_ok(),
            "Imported public key should accept original signature"
        );

        // Re-import private key, sign a message, and verify with the original key.
        let mut priv_key = SlhDsa::new(params.params).expect("Error with new()");
        priv_key
            .import_private(&priv_buf)
            .expect("Error with import_private()");
        let mut sig2 = vec![0u8; sig_size];
        let sig2_len = priv_key
            .sign_msg(message, &mut sig2, &mut rng)
            .expect("Error with sign_msg() from imported private key");
        let valid = key.verify_msg(&sig2[..sig2_len], message);
        assert!(
            valid.is_ok(),
            "Signature from re-imported private key should verify"
        );
    }
}

/// Export both keys for SHA2 parameter sets, re-import them separately,
/// and verify that:
/// - a signature from the original key is accepted by a public-key-only
///   import, and
/// - the re-imported private key can sign messages that verify with the
///   original public key.
#[test]
#[cfg(all(slhdsa_sign, slhdsa_sha2))]
fn test_import_export_sha2() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    for params in SHA2_PARAMS {
        let mut key = SlhDsa::generate(params.params, &mut rng).expect("Error with generate()");

        let priv_size = key.priv_size().expect("Error with priv_size()");
        let pub_size = key.pub_size().expect("Error with pub_size()");
        let sig_size = key.sig_size().expect("Error with sig_size()");

        let mut pub_buf = vec![0u8; pub_size];
        let pub_written = key
            .export_public(&mut pub_buf)
            .expect("Error with export_public()");
        assert_eq!(pub_written, pub_size);

        let mut priv_buf = vec![0u8; priv_size];
        let priv_written = key
            .export_private(&mut priv_buf)
            .expect("Error with export_private()");
        assert_eq!(priv_written, priv_size);

        // Sign with the original key.
        let message = b"Import/export test message";
        let mut sig = vec![0u8; sig_size];
        let sig_len = key
            .sign_msg(message, &mut sig, &mut rng)
            .expect("Error with sign_msg()");

        // Re-import public key only and verify.
        let mut pub_key = SlhDsa::new(params.params).expect("Error with new()");
        pub_key
            .import_public(&pub_buf)
            .expect("Error with import_public()");
        let valid = pub_key.verify_msg(&sig[..sig_len], message);
        assert!(
            valid.is_ok(),
            "Imported public key should accept original signature"
        );

        // Re-import private key, sign a message, and verify with the original key.
        let mut priv_key = SlhDsa::new(params.params).expect("Error with new()");
        priv_key
            .import_private(&priv_buf)
            .expect("Error with import_private()");
        let mut sig2 = vec![0u8; sig_size];
        let sig2_len = priv_key
            .sign_msg(message, &mut sig2, &mut rng)
            .expect("Error with sign_msg() from imported private key");
        let valid = key.verify_msg(&sig2[..sig2_len], message);
        assert!(
            valid.is_ok(),
            "Signature from re-imported private key should verify"
        );
    }
}

/// Verify that `sign_msg_deterministic()` is deterministic for SHAKE
/// parameter sets: the same key and message produce the same signature
/// bytes, and the signature verifies correctly.
#[test]
#[cfg(slhdsa_sign)]
fn test_sign_with_determinism_shake() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    let message = b"Deterministic SLH-DSA signing test";
    for params in SHAKE_PARAMS {
        let mut key = SlhDsa::generate(params.params, &mut rng).expect("Error with generate");

        let sig_size = key.sig_size().expect("Error with sig_size()");
        let mut sig1 = vec![0u8; sig_size];
        let mut sig2 = vec![0u8; sig_size];

        let len1 = key
            .sign_msg_deterministic(message, &mut sig1)
            .expect("Error with sign_msg_deterministic() first call");
        let len2 = key
            .sign_msg_deterministic(message, &mut sig2)
            .expect("Error with sign_msg_deterministic() second call");

        assert_eq!(len1, len2, "Signature lengths must match");
        assert_eq!(
            sig1[..len1],
            sig2[..len2],
            "Same inputs must yield same signature"
        );

        let valid = key
            .verify_msg(&sig1[..len1], message);
        assert!(valid.is_ok(), "Deterministically signed message should verify");
    }
}

/// Verify that `sign_msg_deterministic()` is deterministic for SHA2
/// parameter sets: the same key and message produce the same signature
/// bytes, and the signature verifies correctly.
#[test]
#[cfg(all(slhdsa_sign, slhdsa_sha2))]
fn test_sign_with_determinism_sha2() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    let message = b"Deterministic SLH-DSA signing test";
    for params in SHA2_PARAMS {
        let mut key = SlhDsa::generate(params.params, &mut rng).expect("Error with generate");

        let sig_size = key.sig_size().expect("Error with sig_size()");
        let mut sig1 = vec![0u8; sig_size];
        let mut sig2 = vec![0u8; sig_size];

        let len1 = key
            .sign_msg_deterministic(message, &mut sig1)
            .expect("Error with sign_msg_deterministic() first call");
        let len2 = key
            .sign_msg_deterministic(message, &mut sig2)
            .expect("Error with sign_msg_deterministic() second call");

        assert_eq!(len1, len2, "Signature lengths must match");
        assert_eq!(
            sig1[..len1],
            sig2[..len2],
            "Same inputs must yield same signature"
        );

        let valid = key
            .verify_msg(&sig1[..len1], message);
        assert!(valid.is_ok(), "Deterministically signed message should verify");
    }
}

/// Verify that `sign_ctx_msg_deterministic()` is deterministic for SHAKE
/// parameter sets: the same key and message produce the same signature
/// bytes, and the signature verifies correctly.
#[test]
#[cfg(slhdsa_sign)]
fn test_sign_ctx_with_determinism_shake() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    let message = b"Deterministic SLH-DSA signing test";
    let ctx = b"test-context";
    for params in SHAKE_PARAMS {
        let mut key = SlhDsa::generate(params.params, &mut rng).expect("Error with generate");

        let sig_size = key.sig_size().expect("Error with sig_size()");
        let mut sig1 = vec![0u8; sig_size];
        let mut sig2 = vec![0u8; sig_size];

        let len1 = key
            .sign_ctx_msg_deterministic(ctx, message, &mut sig1)
            .expect("Error with sign_msg_deterministic() first call");
        let len2 = key
            .sign_ctx_msg_deterministic(ctx, message, &mut sig2)
            .expect("Error with sign_msg_deterministic() second call");

        assert_eq!(len1, len2, "Signature lengths must match");
        assert_eq!(
            sig1[..len1],
            sig2[..len2],
            "Same inputs must yield same signature"
        );

        let valid = key
            .verify_ctx_msg(&sig1[..len1], ctx, message);
        assert!(valid.is_ok(), "Deterministically signed message should verify");
    }
}

/// Verify that `sign_ctx_msg_deterministic()` is deterministic for SHA2
/// parameter sets: the same key and message produce the same signature
/// bytes, and the signature verifies correctly.
#[test]
#[cfg(all(slhdsa_sign, slhdsa_sha2))]
fn test_sign_ctx_with_determinism_sha2() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    let message = b"Deterministic SLH-DSA signing test";
    let ctx = b"test-context";
    for params in SHA2_PARAMS {
        let mut key = SlhDsa::generate(params.params, &mut rng).expect("Error with generate");

        let sig_size = key.sig_size().expect("Error with sig_size()");
        let mut sig1 = vec![0u8; sig_size];
        let mut sig2 = vec![0u8; sig_size];

        let len1 = key
            .sign_ctx_msg_deterministic(ctx, message, &mut sig1)
            .expect("Error with sign_msg_deterministic() first call");
        let len2 = key
            .sign_ctx_msg_deterministic(ctx, message, &mut sig2)
            .expect("Error with sign_msg_deterministic() second call");

        assert_eq!(len1, len2, "Signature lengths must match");
        assert_eq!(
            sig1[..len1],
            sig2[..len2],
            "Same inputs must yield same signature"
        );

        let valid = key
            .verify_ctx_msg(&sig1[..len1], ctx, message);
        assert!(valid.is_ok(), "Deterministically signed message should verify");
    }
}
