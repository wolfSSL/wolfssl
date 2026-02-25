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

#![cfg(mlkem)]

mod common;

use wolfssl_wolfcrypt::mlkem::MlKem;
#[cfg(random)]
use wolfssl_wolfcrypt::random::RNG;

/// Verify the type constants have the correct numeric values required by
/// the wolfCrypt API.
#[test]
fn test_type_constants() {
    assert_eq!(MlKem::TYPE_512, 0);
    assert_eq!(MlKem::TYPE_768, 1);
    assert_eq!(MlKem::TYPE_1024, 2);
}

/// Verify the shared constants have the correct values.
#[test]
fn test_shared_constants() {
    assert_eq!(MlKem::SYM_SIZE, 32);
    assert_eq!(MlKem::SHARED_SECRET_SIZE, 32);
    assert_eq!(MlKem::MAKEKEY_RAND_SIZE, 64);
    assert_eq!(MlKem::ENC_RAND_SIZE, 32);
}

/// Verify that `new()` creates an initialized key for each type.
#[test]
fn test_new() {
    common::setup();
    MlKem::new(MlKem::TYPE_512).expect("Error with new() TYPE_512");
    MlKem::new(MlKem::TYPE_768).expect("Error with new() TYPE_768");
    MlKem::new(MlKem::TYPE_1024).expect("Error with new() TYPE_1024");
}

/// Verify that `new_ex()` accepts the optional heap and device ID parameters.
#[test]
fn test_new_ex() {
    common::setup();
    MlKem::new_ex(MlKem::TYPE_768, None, None).expect("Error with new_ex()");
}

/// Verify that the runtime size queries return plausible values for each key type.
#[test]
fn test_size_queries() {
    common::setup();
    for key_type in [MlKem::TYPE_512, MlKem::TYPE_768, MlKem::TYPE_1024] {
        let mut key = MlKem::new(key_type).expect("Error with new()");
        let pub_size = key.public_key_size().expect("Error with public_key_size()");
        let priv_size = key.private_key_size().expect("Error with private_key_size()");
        let ct_size = key.cipher_text_size().expect("Error with cipher_text_size()");
        let ss_size = key.shared_secret_size().expect("Error with shared_secret_size()");
        assert!(pub_size > 0, "public_key_size must be positive for key_type {}", key_type);
        assert!(priv_size > 0, "private_key_size must be positive for key_type {}", key_type);
        assert!(ct_size > 0, "cipher_text_size must be positive for key_type {}", key_type);
        assert_eq!(
            ss_size,
            MlKem::SHARED_SECRET_SIZE,
            "shared_secret_size must equal SHARED_SECRET_SIZE for key_type {}",
            key_type
        );
    }
}

/// Encapsulate and decapsulate with ML-KEM-512, verifying that both sides
/// arrive at the same shared secret.
#[test]
#[cfg(random)]
fn test_encap_decap_type512() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    let mut key = MlKem::generate(MlKem::TYPE_512, &mut rng)
        .expect("Error with generate() TYPE_512");

    let ct_size = key.cipher_text_size().expect("Error with cipher_text_size()");
    let ss_size = key.shared_secret_size().expect("Error with shared_secret_size()");

    let mut ct = vec![0u8; ct_size];
    let mut ss_enc = vec![0u8; ss_size];
    key.encapsulate(&mut ct, &mut ss_enc, &mut rng)
        .expect("Error with encapsulate()");

    let mut ss_dec = vec![0u8; ss_size];
    key.decapsulate(&mut ss_dec, &ct)
        .expect("Error with decapsulate()");

    assert_eq!(ss_enc, ss_dec, "Shared secrets must match after encap/decap");
}

/// Encapsulate and decapsulate with ML-KEM-768, verifying that both sides
/// arrive at the same shared secret. Also verifies that a tampered cipher text
/// produces a different (implicit rejection) shared secret.
#[test]
#[cfg(random)]
fn test_encap_decap_type768() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    let mut key = MlKem::generate(MlKem::TYPE_768, &mut rng)
        .expect("Error with generate() TYPE_768");

    let ct_size = key.cipher_text_size().expect("Error with cipher_text_size()");
    let ss_size = key.shared_secret_size().expect("Error with shared_secret_size()");

    let mut ct = vec![0u8; ct_size];
    let mut ss_enc = vec![0u8; ss_size];
    key.encapsulate(&mut ct, &mut ss_enc, &mut rng)
        .expect("Error with encapsulate()");

    let mut ss_dec = vec![0u8; ss_size];
    key.decapsulate(&mut ss_dec, &ct)
        .expect("Error with decapsulate()");

    assert_eq!(ss_enc, ss_dec, "Shared secrets must match after encap/decap");

    // Tamper with the cipher text. ML-KEM uses implicit rejection, so
    // decapsulation succeeds but returns a different (pseudorandom) secret.
    let mut ct_tampered = ct.clone();
    ct_tampered[0] ^= 0xFF;
    let mut ss_tampered = vec![0u8; ss_size];
    key.decapsulate(&mut ss_tampered, &ct_tampered)
        .expect("Error with decapsulate() on tampered ct");
    assert_ne!(ss_enc, ss_tampered, "Tampered ct must yield different shared secret");
}

/// Encapsulate and decapsulate with ML-KEM-1024, verifying that both sides
/// arrive at the same shared secret.
#[test]
#[cfg(random)]
fn test_encap_decap_type1024() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    let mut key = MlKem::generate(MlKem::TYPE_1024, &mut rng)
        .expect("Error with generate() TYPE_1024");

    let ct_size = key.cipher_text_size().expect("Error with cipher_text_size()");
    let ss_size = key.shared_secret_size().expect("Error with shared_secret_size()");

    let mut ct = vec![0u8; ct_size];
    let mut ss_enc = vec![0u8; ss_size];
    key.encapsulate(&mut ct, &mut ss_enc, &mut rng)
        .expect("Error with encapsulate()");

    let mut ss_dec = vec![0u8; ss_size];
    key.decapsulate(&mut ss_dec, &ct)
        .expect("Error with decapsulate()");

    assert_eq!(ss_enc, ss_dec, "Shared secrets must match after encap/decap");
}

/// Verify that `generate_with_random()` is deterministic: the same random
/// bytes produce the same key pair on repeated calls.
#[test]
fn test_generate_with_random_determinism() {
    common::setup();
    // MAKEKEY_RAND_SIZE = 64 bytes
    let rand = [0x42u8; 64];

    let mut key1 = MlKem::generate_with_random(MlKem::TYPE_768, &rand)
        .expect("Error with generate_with_random() first call");
    let mut key2 = MlKem::generate_with_random(MlKem::TYPE_768, &rand)
        .expect("Error with generate_with_random() second call");

    let pub_size = key1.public_key_size().expect("Error with public_key_size()");
    let mut pub1 = vec![0u8; pub_size];
    let mut pub2 = vec![0u8; pub_size];
    key1.encode_public_key(&mut pub1).expect("Error with encode_public_key() key1");
    key2.encode_public_key(&mut pub2).expect("Error with encode_public_key() key2");
    assert_eq!(pub1, pub2, "Same random must yield same public key");

    let priv_size = key1.private_key_size().expect("Error with private_key_size()");
    let mut priv1 = vec![0u8; priv_size];
    let mut priv2 = vec![0u8; priv_size];
    key1.encode_private_key(&mut priv1).expect("Error with encode_private_key() key1");
    key2.encode_private_key(&mut priv2).expect("Error with encode_private_key() key2");
    assert_eq!(priv1, priv2, "Same random must yield same private key");
}

/// Verify that `encapsulate_with_random()` is deterministic: the same public
/// key and random bytes produce the same cipher text and shared secret.
#[test]
fn test_encapsulate_with_random_determinism() {
    common::setup();
    let key_rand = [0x11u8; 64];
    let enc_rand = [0x22u8; 32];

    let mut key = MlKem::generate_with_random(MlKem::TYPE_768, &key_rand)
        .expect("Error with generate_with_random()");

    let ct_size = key.cipher_text_size().expect("Error with cipher_text_size()");
    let ss_size = key.shared_secret_size().expect("Error with shared_secret_size()");

    let mut ct1 = vec![0u8; ct_size];
    let mut ss1 = vec![0u8; ss_size];
    key.encapsulate_with_random(&mut ct1, &mut ss1, &enc_rand)
        .expect("Error with encapsulate_with_random() first call");

    let mut ct2 = vec![0u8; ct_size];
    let mut ss2 = vec![0u8; ss_size];
    key.encapsulate_with_random(&mut ct2, &mut ss2, &enc_rand)
        .expect("Error with encapsulate_with_random() second call");

    assert_eq!(ct1, ct2, "Same inputs must yield same cipher text");
    assert_eq!(ss1, ss2, "Same inputs must yield same shared secret");

    // Decapsulate and verify the shared secrets match.
    let mut ss_dec = vec![0u8; ss_size];
    key.decapsulate(&mut ss_dec, &ct1)
        .expect("Error with decapsulate()");
    assert_eq!(ss1, ss_dec, "Shared secret from encapsulate must match decapsulate");
}

/// Encode and decode the public key for ML-KEM-768, verifying the round-trip
/// preserves the key bytes and that encapsulation works with the re-imported key.
#[test]
#[cfg(random)]
fn test_encode_decode_public_key() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    let mut key = MlKem::generate(MlKem::TYPE_768, &mut rng)
        .expect("Error with generate()");

    let pub_size = key.public_key_size().expect("Error with public_key_size()");
    let ct_size = key.cipher_text_size().expect("Error with cipher_text_size()");
    let ss_size = key.shared_secret_size().expect("Error with shared_secret_size()");

    let mut pub_buf = vec![0u8; pub_size];
    let written = key.encode_public_key(&mut pub_buf)
        .expect("Error with encode_public_key()");
    assert_eq!(written, pub_size);

    // Re-import public key and encapsulate.
    let mut pub_key = MlKem::new(MlKem::TYPE_768).expect("Error with new()");
    pub_key.decode_public_key(&pub_buf).expect("Error with decode_public_key()");

    let mut ct = vec![0u8; ct_size];
    let mut ss_enc = vec![0u8; ss_size];
    pub_key.encapsulate(&mut ct, &mut ss_enc, &mut rng)
        .expect("Error with encapsulate() via imported public key");

    // Decapsulate with the original full key pair.
    let mut ss_dec = vec![0u8; ss_size];
    key.decapsulate(&mut ss_dec, &ct)
        .expect("Error with decapsulate()");

    assert_eq!(ss_enc, ss_dec, "Shared secrets must match after public key import");
}

/// Encode and decode the private key for ML-KEM-768, verifying that
/// decapsulation works with the re-imported key.
#[test]
#[cfg(random)]
fn test_encode_decode_private_key() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    let mut key = MlKem::generate(MlKem::TYPE_768, &mut rng)
        .expect("Error with generate()");

    let priv_size = key.private_key_size().expect("Error with private_key_size()");
    let ct_size = key.cipher_text_size().expect("Error with cipher_text_size()");
    let ss_size = key.shared_secret_size().expect("Error with shared_secret_size()");

    let mut priv_buf = vec![0u8; priv_size];
    let written = key.encode_private_key(&mut priv_buf)
        .expect("Error with encode_private_key()");
    assert_eq!(written, priv_size);

    // Encapsulate with the original key.
    let mut ct = vec![0u8; ct_size];
    let mut ss_enc = vec![0u8; ss_size];
    key.encapsulate(&mut ct, &mut ss_enc, &mut rng)
        .expect("Error with encapsulate()");

    // Re-import private key and decapsulate.
    let mut priv_key = MlKem::new(MlKem::TYPE_768).expect("Error with new()");
    priv_key.decode_private_key(&priv_buf).expect("Error with decode_private_key()");

    let mut ss_dec = vec![0u8; ss_size];
    priv_key.decapsulate(&mut ss_dec, &ct)
        .expect("Error with decapsulate() via imported private key");

    assert_eq!(ss_enc, ss_dec, "Shared secrets must match after private key import");
}

/// Verify that encapsulate/decapsulate round-trips work across all three
/// security levels.
#[test]
#[cfg(random)]
fn test_encap_decap_all_types() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");

    for key_type in [MlKem::TYPE_512, MlKem::TYPE_768, MlKem::TYPE_1024] {
        let mut key = MlKem::generate(key_type, &mut rng)
            .expect("Error with generate()");

        let ct_size = key.cipher_text_size().expect("Error with cipher_text_size()");
        let ss_size = key.shared_secret_size().expect("Error with shared_secret_size()");

        let mut ct = vec![0u8; ct_size];
        let mut ss_enc = vec![0u8; ss_size];
        key.encapsulate(&mut ct, &mut ss_enc, &mut rng)
            .expect("Error with encapsulate()");

        let mut ss_dec = vec![0u8; ss_size];
        key.decapsulate(&mut ss_dec, &ct)
            .expect("Error with decapsulate()");

        assert_eq!(
            ss_enc, ss_dec,
            "Shared secrets must match for key_type {}",
            key_type
        );
        assert_eq!(
            ss_size,
            MlKem::SHARED_SECRET_SIZE,
            "Shared secret size must equal SHARED_SECRET_SIZE for key_type {}",
            key_type
        );
    }
}
