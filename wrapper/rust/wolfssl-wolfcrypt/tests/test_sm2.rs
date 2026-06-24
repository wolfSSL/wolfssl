#![cfg(sm2)]

mod common;

#[cfg(all(random, sm2_dh))]
use std::rc::Rc;
#[cfg(random)]
use wolfssl_wolfcrypt::random::RNG;
use wolfssl_wolfcrypt::sm2::SM2;

#[test]
#[cfg(random)]
fn test_sm2_set_rng() {
    common::setup();
    let key_gen_rng = RNG::new().expect("Failed to create key generation RNG");
    let blinding_rng = RNG::new().expect("Failed to create blinding RNG");
    let mut key = SM2::generate(&key_gen_rng, SM2::FLAG_NONE).expect("Error with generate()");

    key.set_rng(blinding_rng).expect("Error with set_rng()");
}

#[test]
#[cfg(random)]
fn test_sm2_generate() {
    common::setup();
    let rng = RNG::new().expect("Failed to create RNG");
    SM2::generate(&rng, SM2::FLAG_NONE).expect("Error with generate()");
}

#[test]
#[cfg(all(random, sm2_digest, sm3))]
fn test_sm2_create_digest_with_sm3() {
    common::setup();
    let rng = RNG::new().expect("Failed to create RNG");
    let mut key = SM2::generate(&rng, SM2::FLAG_NONE).expect("Error generating SM2 key");
    let mut digest = [0u8; 32];

    key.create_digest(
        SM2::CERT_SIG_ID,
        b"message digest",
        SM2::HASH_TYPE_SM3,
        &mut digest,
    )
    .expect("Error creating SM2 digest");

    assert_ne!(digest, [0u8; 32]);
}

#[test]
#[cfg(all(random, sm2_digest, sm2_sign, sm2_verify, sm3))]
fn test_sm2_sign_and_verify_with_sm3_digest() {
    common::setup();
    let rng = RNG::new().expect("Failed to create RNG");
    let mut key = SM2::generate(&rng, SM2::FLAG_NONE).expect("Error generating SM2 key");
    let mut digest = [0u8; 32];
    key.create_digest(
        SM2::CERT_SIG_ID,
        b"message digest",
        SM2::HASH_TYPE_SM3,
        &mut digest,
    )
    .expect("Error creating SM2 digest");

    let mut signature = [0u8; 80];
    let signature_len = key
        .sign_hash(&digest, &mut signature, &rng)
        .expect("Error signing SM2 digest");
    assert!(signature_len > 0 && signature_len <= signature.len());

    let valid = key
        .verify_hash(&signature[..signature_len], &digest)
        .expect("Error verifying SM2 signature");
    assert!(valid);

    digest[0] ^= 0x01;
    let valid = key
        .verify_hash(&signature[..signature_len], &digest)
        .expect("Error verifying modified SM2 digest");
    assert!(!valid);
}

#[test]
#[cfg(all(random, sm2_digest, sm3))]
fn test_sm2_create_digest_with_sm3_rejects_small_buffer() {
    common::setup();
    let rng = RNG::new().expect("Failed to create RNG");
    let mut key = SM2::generate(&rng, SM2::FLAG_NONE).expect("Error generating SM2 key");
    let mut digest = [0u8; 31];

    let result = key.create_digest(
        SM2::CERT_SIG_ID,
        b"message digest",
        SM2::HASH_TYPE_SM3,
        &mut digest,
    );
    assert!(result.is_err());
}

#[test]
#[cfg(all(random, sm2_sign))]
fn test_sm2_sign_hash_rejects_small_buffer() {
    common::setup();
    let rng = RNG::new().expect("Failed to create RNG");
    let mut key = SM2::generate(&rng, SM2::FLAG_NONE).expect("Error generating SM2 key");
    let digest = [0x42u8; 32];
    let mut signature = [0u8; 1];

    assert!(key.sign_hash(&digest, &mut signature, &rng).is_err());
}

#[test]
#[cfg(all(random, sm2_sign, sm2_verify))]
fn test_sm2_sign_and_verify_hash() {
    common::setup();
    let rng = RNG::new().expect("Failed to create RNG");
    let mut key = SM2::generate(&rng, SM2::FLAG_NONE).expect("Error generating SM2 key");
    let mut digest = [0x42u8; 32];
    let mut signature = [0u8; 80];

    let signature_len = key
        .sign_hash(&digest, &mut signature, &rng)
        .expect("Error signing SM2 hash");
    assert!(signature_len > 0 && signature_len <= signature.len());

    let valid = key
        .verify_hash(&signature[..signature_len], &digest)
        .expect("Error verifying SM2 signature");
    assert!(valid);

    digest[0] ^= 0x01;
    let valid = key
        .verify_hash(&signature[..signature_len], &digest)
        .expect("Error verifying modified SM2 hash");
    assert!(!valid);
}

#[test]
#[cfg(all(random, sm2_dh))]
fn test_sm2_shared_secret() {
    common::setup();
    let rng = Rc::new(RNG::new().expect("Failed to create RNG"));
    let mut alice = SM2::generate(&rng, SM2::FLAG_NONE).expect("Error generating Alice key");
    let mut bob = SM2::generate(&rng, SM2::FLAG_NONE).expect("Error generating Bob key");
    alice
        .set_shared_rng(Rc::clone(&rng))
        .expect("Error with set_shared_rng()");
    bob.set_shared_rng(Rc::clone(&rng))
        .expect("Error with set_shared_rng()");
    let mut alice_secret = [0u8; SM2::KEY_SIZE];
    let mut bob_secret = [0u8; SM2::KEY_SIZE];

    let alice_len = alice
        .shared_secret(&mut bob, &mut alice_secret)
        .expect("Error deriving Alice shared secret");
    let bob_len = bob
        .shared_secret(&mut alice, &mut bob_secret)
        .expect("Error deriving Bob shared secret");

    assert!(alice_len > 0 && alice_len <= SM2::KEY_SIZE);
    assert!(bob_len > 0 && bob_len <= SM2::KEY_SIZE);
    assert_eq!(alice_len, bob_len);
    assert_eq!(alice_secret[..alice_len], bob_secret[..bob_len]);
}

#[test]
#[cfg(all(random, sm2_dh))]
fn test_sm2_shared_secret_rejects_small_buffer() {
    common::setup();
    let rng = Rc::new(RNG::new().expect("Failed to create RNG"));
    let mut alice = SM2::generate(&rng, SM2::FLAG_NONE).expect("Error generating Alice key");
    let mut bob = SM2::generate(&rng, SM2::FLAG_NONE).expect("Error generating Bob key");
    alice
        .set_shared_rng(Rc::clone(&rng))
        .expect("Error with set_shared_rng()");
    bob.set_shared_rng(Rc::clone(&rng))
        .expect("Error with set_shared_rng()");
    let mut secret = [0u8; 1];

    assert!(alice.shared_secret(&mut bob, &mut secret).is_err());
}
