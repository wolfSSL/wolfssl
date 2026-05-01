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

#![cfg(all(mlkem, random, feature = "kem", feature = "rand_core"))]

mod common;

use kem::{Decapsulate, Decapsulator, Encapsulate, Kem, TryKeyInit, KeyExport};
use kem::Generate;
use wolfssl_wolfcrypt::mlkem::MlKem;
use wolfssl_wolfcrypt::mlkem_kem::*;
use wolfssl_wolfcrypt::random::RNG;

/// Verify that the compile-time sizes used by the kem types match the runtime
/// sizes reported by wolfCrypt.
#[test]
fn test_sizes_match_runtime() {
    common::setup();

    let key512 = MlKem::new(MlKem::TYPE_512).expect("new TYPE_512");
    assert_eq!(key512.public_key_size().unwrap(), 800);
    assert_eq!(key512.private_key_size().unwrap(), 1632);
    assert_eq!(key512.cipher_text_size().unwrap(), 768);

    let key768 = MlKem::new(MlKem::TYPE_768).expect("new TYPE_768");
    assert_eq!(key768.public_key_size().unwrap(), 1184);
    assert_eq!(key768.private_key_size().unwrap(), 2400);
    assert_eq!(key768.cipher_text_size().unwrap(), 1088);

    let key1024 = MlKem::new(MlKem::TYPE_1024).expect("new TYPE_1024");
    assert_eq!(key1024.public_key_size().unwrap(), 1568);
    assert_eq!(key1024.private_key_size().unwrap(), 3168);
    assert_eq!(key1024.cipher_text_size().unwrap(), 1568);
}

/// Generate, encapsulate, and decapsulate with ML-KEM-512 via the kem traits.
#[test]
fn test_kem_512_round_trip() {
    common::setup();
    let mut rng = RNG::new().expect("RNG creation failed");

    let (dk, ek) = MlKem512::generate_keypair_from_rng(&mut rng);
    let (ct, k_send) = ek.encapsulate_with_rng(&mut rng);
    let k_recv = dk.decapsulate(&ct);
    assert_eq!(k_send, k_recv);
}

/// Generate, encapsulate, and decapsulate with ML-KEM-768 via the kem traits.
#[test]
fn test_kem_768_round_trip() {
    common::setup();
    let mut rng = RNG::new().expect("RNG creation failed");

    let (dk, ek) = MlKem768::generate_keypair_from_rng(&mut rng);
    let (ct, k_send) = ek.encapsulate_with_rng(&mut rng);
    let k_recv = dk.decapsulate(&ct);
    assert_eq!(k_send, k_recv);
}

/// Generate, encapsulate, and decapsulate with ML-KEM-1024 via the kem traits.
#[test]
fn test_kem_1024_round_trip() {
    common::setup();
    let mut rng = RNG::new().expect("RNG creation failed");

    let (dk, ek) = MlKem1024::generate_keypair_from_rng(&mut rng);
    let (ct, k_send) = ek.encapsulate_with_rng(&mut rng);
    let k_recv = dk.decapsulate(&ct);
    assert_eq!(k_send, k_recv);
}

/// Verify that `Generate::generate_from_rng` produces a usable decapsulation
/// key and that the associated encapsulation key is consistent.
#[test]
fn test_generate_from_rng() {
    common::setup();
    let mut rng = RNG::new().expect("RNG creation failed");

    let dk = MlKem768DecapsulationKey::generate_from_rng(&mut rng);
    let ek = dk.encapsulation_key();

    let (ct, k_send) = ek.encapsulate_with_rng(&mut rng);
    let k_recv = dk.decapsulate(&ct);
    assert_eq!(k_send, k_recv);
}

/// Verify that a tampered ciphertext produces a different shared secret
/// (ML-KEM implicit rejection).
#[test]
fn test_implicit_rejection() {
    common::setup();
    let mut rng = RNG::new().expect("RNG creation failed");

    let (dk, ek) = MlKem768::generate_keypair_from_rng(&mut rng);
    let (ct, k_send) = ek.encapsulate_with_rng(&mut rng);

    let mut ct_tampered = ct.clone();
    ct_tampered[0] ^= 0xFF;
    let k_tampered = dk.decapsulate(&ct_tampered);

    assert_eq!(k_send, dk.decapsulate(&ct));
    assert_ne!(k_send, k_tampered);
}

/// Verify that `TryKeyInit` and `KeyExport` round-trip the encapsulation key.
#[test]
fn test_ek_export_import() {
    common::setup();
    let mut rng = RNG::new().expect("RNG creation failed");

    let (dk, ek) = MlKem768::generate_keypair_from_rng(&mut rng);

    // Export and re-import the encapsulation key.
    let exported = ek.to_bytes();
    let ek2 = MlKem768EncapsulationKey::new(&exported)
        .expect("TryKeyInit failed");
    assert_eq!(ek, ek2);

    // Encapsulate with the re-imported key; the original DK must decapsulate.
    let (ct, k_send) = ek2.encapsulate_with_rng(&mut rng);
    let k_recv = dk.decapsulate(&ct);
    assert_eq!(k_send, k_recv);
}

/// Verify that `TryKeyInit` doesn't panic on a zeroed key.
#[test]
fn test_ek_try_new_zeroed_key() {
    common::setup();

    // A zero-filled buffer of the correct size. Whether this succeeds or fails
    // depends on wolfCrypt's decode_public_key validation. The key point is it
    // shouldn't panic.
    let zeroed = kem::Key::<MlKem768EncapsulationKey>::default();
    let _ = MlKem768EncapsulationKey::new(&zeroed);
}

/// Verify the `Decapsulator::encapsulation_key` method returns a key that
/// can be used for encapsulation.
#[test]
fn test_decapsulator_encapsulation_key() {
    common::setup();
    let mut rng = RNG::new().expect("RNG creation failed");

    let dk = MlKem512DecapsulationKey::generate_from_rng(&mut rng);
    let ek = dk.encapsulation_key().clone();

    let (ct, k_send) = ek.encapsulate_with_rng(&mut rng);
    let k_recv = dk.decapsulate(&ct);
    assert_eq!(k_send, k_recv);
}
