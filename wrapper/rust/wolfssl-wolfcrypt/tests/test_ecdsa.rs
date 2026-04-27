#![cfg(all(feature = "signature", ecc, ecc_sign, ecc_verify, ecc_curve_ids, random))]

mod common;

use signature::{Keypair, SignerMut, Verifier};
use wolfssl_wolfcrypt::random::RNG;

#[test]
#[cfg(sha256)]
fn test_p256_sign_verify() {
    use wolfssl_wolfcrypt::ecdsa::{P256Signature, P256SigningKey, P256VerifyingKey};

    common::setup();

    let rng = RNG::new().expect("RNG");
    let mut sk = P256SigningKey::generate(rng).expect("generate P256");

    let msg = b"ecdsa p256 signature trait test";
    let sig: P256Signature = sk.sign(msg);

    // Encoding round-trip.
    let bytes = sig.to_bytes();
    assert_eq!(bytes.len(), 64);
    let sig2 = P256Signature::try_from(bytes.as_ref()).expect("parse sig");
    assert_eq!(sig, sig2);

    // Wrong length must fail.
    assert!(P256Signature::try_from(&bytes[..63]).is_err());

    // Keypair provides a matching verifying key.
    let vk: P256VerifyingKey = sk.verifying_key();
    vk.verify(msg, &sig).expect("verify");

    // Tampered message fails.
    let mut tampered = *msg;
    tampered[0] ^= 0x01;
    assert!(vk.verify(&tampered, &sig).is_err());

    // VerifyingKey bytes round-trip.
    let vk_bytes = vk.to_bytes();
    assert_eq!(vk_bytes.len(), 65);
    assert_eq!(vk_bytes[0], 0x04); // uncompressed X9.63 tag
    let vk2 = P256VerifyingKey::try_from(vk_bytes.as_ref()).expect("parse vk");
    assert_eq!(vk, vk2);
    vk2.verify(msg, &sig).expect("verify via rebuilt vk");
}

#[test]
#[cfg(sha256)]
fn test_p256_import_unsigned_and_x963() {
    use wolfssl_wolfcrypt::ecc::ECC;
    use wolfssl_wolfcrypt::ecdsa::{P256SigningKey, P256VerifyingKey};

    common::setup();

    // Start from a freshly generated key so we have known-good (qx, qy, d).
    let mut rng = RNG::new().expect("RNG");
    let mut src = ECC::generate_ex(32, &mut rng, ECC::SECP256R1, None, None)
        .expect("generate ECC");
    let mut qx = [0u8; 32];
    let mut qy = [0u8; 32];
    let mut d_buf = [0u8; 32];
    let mut qx_len = 0u32;
    let mut qy_len = 0u32;
    let mut d_len = 0u32;
    src.export_ex(&mut qx, &mut qx_len, &mut qy, &mut qy_len, &mut d_buf, &mut d_len, false)
        .expect("export_ex");
    assert_eq!(qx_len as usize, 32);
    assert_eq!(qy_len as usize, 32);
    assert_eq!(d_len as usize, 32);
    let mut x963 = [0u8; 65];
    let x963_written = src.export_x963(&mut x963).expect("export_x963");
    assert_eq!(x963_written, 65);

    let msg = b"ecdsa p256 import path";

    // Path 1: raw unsigned components.
    let rng = RNG::new().expect("RNG");
    let mut sk_a = P256SigningKey::import_unsigned(&qx, &qy, &d_buf, rng)
        .expect("import_unsigned");
    let sig_a = sk_a.sign(msg);
    sk_a.verifying_key().verify(msg, &sig_a).expect("verify a");

    // Path 2: X9.63 public + private scalar.
    let rng = RNG::new().expect("RNG");
    let mut sk_b = P256SigningKey::import_x963(&x963, &d_buf, rng)
        .expect("import_x963");
    let sig_b = sk_b.sign(msg);
    sk_b.verifying_key().verify(msg, &sig_b).expect("verify b");

    // Both imported keys produce the same public key bytes.
    let vk_a: P256VerifyingKey = sk_a.verifying_key();
    let vk_b: P256VerifyingKey = sk_b.verifying_key();
    assert_eq!(vk_a, vk_b);

    // Cross-verify: vk_a verifies a signature produced by sk_b.
    vk_a.verify(msg, &sig_b).expect("cross-verify a/b");
}

#[test]
#[cfg(sha384)]
fn test_p384_sign_verify() {
    use wolfssl_wolfcrypt::ecdsa::{P384Signature, P384SigningKey, P384VerifyingKey};

    common::setup();

    let rng = RNG::new().expect("RNG");
    let mut sk = P384SigningKey::generate(rng).expect("generate P384");

    let msg = b"ecdsa p384 signature trait test";
    let sig: P384Signature = sk.sign(msg);
    assert_eq!(sig.to_bytes().len(), 96);

    let vk: P384VerifyingKey = sk.verifying_key();
    vk.verify(msg, &sig).expect("verify p384");

    let mut tampered = *msg;
    tampered[5] ^= 0x80;
    assert!(vk.verify(&tampered, &sig).is_err());
}

#[test]
#[cfg(sha512)]
fn test_p521_sign_verify() {
    use wolfssl_wolfcrypt::ecdsa::{P521Signature, P521SigningKey, P521VerifyingKey};

    common::setup();

    let rng = RNG::new().expect("RNG");
    let mut sk = P521SigningKey::generate(rng).expect("generate P521");

    let msg = b"ecdsa p521 signature trait test";
    let sig: P521Signature = sk.sign(msg);
    assert_eq!(sig.to_bytes().len(), 132);

    let vk: P521VerifyingKey = sk.verifying_key();
    vk.verify(msg, &sig).expect("verify p521");

    let mut tampered = *msg;
    tampered[10] ^= 0x55;
    assert!(vk.verify(&tampered, &sig).is_err());
}
