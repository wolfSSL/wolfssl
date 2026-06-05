#![cfg(all(rsa, rsa_oaep, random))]

mod common;

use std::fs;
use wolfssl_wolfcrypt::random::RNG;

#[test]
#[cfg(all(sha256, rsa_keygen))]
fn test_rsa2048_sha256_oaep_round_trip() {
    use wolfssl_wolfcrypt::rsa_oaep::{Ciphertext, DecryptingKey, EncryptingKey, Sha256};

    common::setup();

    let pad_rng = RNG::new().expect("RNG");
    let mut dk: DecryptingKey<Sha256, 256> =
        DecryptingKey::generate(RNG::new().expect("RNG")).expect("generate 2048");
    let ek: EncryptingKey<Sha256, 256> = dk.encrypting_key().expect("encrypting_key");

    let msg = b"rsa oaep sha256 round trip test";
    let ct: Ciphertext<256> = ek.encrypt(&pad_rng, msg).expect("encrypt");

    // Encoding round-trip.
    let bytes = ct.to_bytes();
    assert_eq!(bytes.len(), 256);
    let ct2 = Ciphertext::<256>::try_from(bytes.as_ref()).expect("parse ct");
    assert_eq!(ct, ct2);

    // Wrong length must fail.
    assert!(Ciphertext::<256>::try_from(&bytes[..255]).is_err());

    let mut out = [0u8; 256];
    let n = dk.decrypt(&ct, &mut out).expect("decrypt");
    assert_eq!(&out[..n], msg);

    // EncryptingKey rebuilt from raw components is equivalent.
    let ek_copy = EncryptingKey::<Sha256, 256>::from_components(ek.modulus(), ek.exponent())
        .expect("from_components");
    assert_eq!(ek, ek_copy);
    let ct3: Ciphertext<256> = ek_copy.encrypt(&pad_rng, msg).expect("encrypt via rebuilt ek");
    let n2 = dk.decrypt(&ct3, &mut out).expect("decrypt via rebuilt ek");
    assert_eq!(&out[..n2], msg);
}

#[test]
#[cfg(sha384)]
fn test_rsa2048_sha384_oaep_with_der_keys() {
    use wolfssl_wolfcrypt::rsa_oaep::{DecryptingKey, EncryptingKey, Sha384};

    common::setup();

    let pad_rng = RNG::new().expect("RNG");

    let pub_der: Vec<u8> = fs::read("../../../certs/client-keyPub.der")
        .expect("read client-keyPub.der");
    let priv_der: Vec<u8> = fs::read("../../../certs/client-key.der")
        .expect("read client-key.der");

    let ek: EncryptingKey<Sha384, 256> = EncryptingKey::from_public_der(&pub_der)
        .expect("EncryptingKey::from_public_der");
    let mut dk: DecryptingKey<Sha384, 256> = DecryptingKey::from_private_der(&priv_der, RNG::new().expect("RNG"))
        .expect("DecryptingKey::from_private_der");

    let msg = b"oaep sha384 + der keys";
    let ct = ek.encrypt(&pad_rng, msg).expect("encrypt");
    let mut out = [0u8; 256];
    let n = dk.decrypt(&ct, &mut out).expect("decrypt");
    assert_eq!(&out[..n], msg);
}

#[test]
#[cfg(all(sha256, rsa_keygen))]
fn test_oaep_label_round_trip_and_mismatch() {
    use wolfssl_wolfcrypt::rsa_oaep::{DecryptingKey, EncryptingKey, Sha256};

    common::setup();

    let pad_rng = RNG::new().expect("RNG");
    let mut dk: DecryptingKey<Sha256, 256> =
        DecryptingKey::generate(RNG::new().expect("RNG")).expect("generate 2048");
    let ek: EncryptingKey<Sha256, 256> = dk.encrypting_key().expect("encrypting_key");

    let msg = b"oaep with label";
    let label: &[u8] = b"context-info";
    let ct = ek.encrypt_with_label(&pad_rng, msg, label).expect("encrypt_with_label");

    let mut out = [0u8; 256];

    // Correct label succeeds.
    let n = dk.decrypt_with_label(&ct, &mut out, label).expect("decrypt_with_label");
    assert_eq!(&out[..n], msg);

    // Wrong label must fail.
    assert!(dk.decrypt_with_label(&ct, &mut out, b"other-label").is_err());

    // Missing label must fail.
    assert!(dk.decrypt(&ct, &mut out).is_err());
}

#[test]
#[cfg(all(sha256, rsa_keygen))]
fn test_oaep_modulus_size_mismatch_rejected() {
    use wolfssl_wolfcrypt::rsa::RSA;
    use wolfssl_wolfcrypt::rsa_oaep::{DecryptingKey, EncryptingKey, Sha256};

    common::setup();

    let rng = RNG::new().expect("RNG");
    let rsa2048 = RSA::generate(2048, 65537, &rng).expect("generate");

    let ek_result: Result<EncryptingKey<Sha256, 384>, _> = EncryptingKey::from_rsa(&rsa2048);
    assert!(ek_result.is_err(), "encrypting key modulus mismatch must be rejected");

    let dk_rng = RNG::new().expect("RNG");
    let dk_result: Result<DecryptingKey<Sha256, 384>, _> = DecryptingKey::from_rsa(rsa2048, dk_rng);
    assert!(dk_result.is_err(), "decrypting key modulus mismatch must be rejected");
}

#[test]
#[cfg(all(sha256, rsa_keygen))]
fn test_oaep_tampered_ciphertext_rejected() {
    use wolfssl_wolfcrypt::rsa_oaep::{DecryptingKey, Sha256};

    common::setup();

    let pad_rng = RNG::new().expect("RNG");
    let mut dk: DecryptingKey<Sha256, 256> =
        DecryptingKey::generate(RNG::new().expect("RNG")).expect("generate 2048");
    let ek = dk.encrypting_key().expect("encrypting_key");

    let msg = b"some bytes";
    let mut ct = ek.encrypt(&pad_rng, msg).expect("encrypt");
    let mut bytes = ct.to_bytes();
    bytes[0] ^= 0x01;
    ct = wolfssl_wolfcrypt::rsa_oaep::Ciphertext::from_bytes(bytes);

    let mut out = [0u8; 256];
    assert!(dk.decrypt(&ct, &mut out).is_err());
}
