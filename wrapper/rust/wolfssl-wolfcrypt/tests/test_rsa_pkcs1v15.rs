#![cfg(all(feature = "signature", rsa, random))]

mod common;

use signature::{Keypair, SignerMut, Verifier};
use wolfssl_wolfcrypt::random::RNG;

#[test]
#[cfg(all(sha256, rsa_keygen))]
fn test_rsa2048_sha256_sign_verify() {
    use wolfssl_wolfcrypt::rsa_pkcs1v15::{Sha256, Signature, SigningKey, VerifyingKey};

    common::setup();

    let rng = RNG::new().expect("RNG");
    let mut sk: SigningKey<Sha256, 256> = SigningKey::generate(rng).expect("generate 2048");

    let msg = b"rsa pkcs1v15 sha256 signature trait test";
    let sig: Signature<256> = sk.sign(msg);

    // Encoding round-trip.
    let bytes = sig.to_bytes();
    assert_eq!(bytes.len(), 256);
    let sig2 = Signature::<256>::try_from(bytes.as_ref()).expect("parse sig");
    assert_eq!(sig, sig2);

    // Wrong length must fail.
    assert!(Signature::<256>::try_from(&bytes[..255]).is_err());

    // Keypair gives a matching verifying key.
    let vk: VerifyingKey<Sha256, 256> = sk.verifying_key();
    vk.verify(msg, &sig).expect("verify");

    // Tampered message fails.
    let mut tampered = *msg;
    tampered[0] ^= 0x01;
    assert!(vk.verify(&tampered, &sig).is_err());

    // VerifyingKey rebuilt from raw components still verifies.
    let vk_copy = VerifyingKey::<Sha256, 256>::from_components(vk.modulus(), vk.exponent())
        .expect("from_components");
    assert_eq!(vk, vk_copy);
    vk_copy.verify(msg, &sig).expect("verify via rebuilt vk");
}

#[test]
#[cfg(all(sha384, rsa_keygen))]
fn test_rsa3072_sha384_sign_verify() {
    use wolfssl_wolfcrypt::rsa_pkcs1v15::{Sha384, Signature, SigningKey, VerifyingKey};

    common::setup();

    let rng = RNG::new().expect("RNG");
    let mut sk: SigningKey<Sha384, 384> = SigningKey::generate(rng).expect("generate 3072");

    let msg = b"rsa pkcs1v15 sha384 signature trait test";
    let sig: Signature<384> = sk.sign(msg);
    assert_eq!(sig.to_bytes().len(), 384);

    let vk: VerifyingKey<Sha384, 384> = sk.verifying_key();
    vk.verify(msg, &sig).expect("verify");

    let mut tampered = *msg;
    tampered[2] ^= 0x10;
    assert!(vk.verify(&tampered, &sig).is_err());
}

#[test]
#[cfg(all(sha256, rsa_keygen))]
fn test_modulus_size_mismatch_rejected() {
    use wolfssl_wolfcrypt::rsa::RSA;
    use wolfssl_wolfcrypt::rsa_pkcs1v15::{Sha256, SigningKey};

    common::setup();

    let mut rng = RNG::new().expect("RNG");
    let rsa2048 = RSA::generate(2048, 65537, &mut rng).expect("generate");
    // Attempt to adopt a 2048-bit key as if it were 3072.
    let result: Result<SigningKey<Sha256, 384>, _> = SigningKey::from_rsa(rsa2048, rng);
    assert!(result.is_err(), "modulus size mismatch must be rejected");
}
