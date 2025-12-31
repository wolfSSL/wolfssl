#![cfg(all(curve25519, random))]

use wolfssl_wolfcrypt::curve25519::*;
use wolfssl_wolfcrypt::random::RNG;

#[test]
fn test_check_pub() {
    let mut rng = RNG::new().expect("Error with new()");
    let mut private_buffer = [0u8; Curve25519Key::KEYSIZE];
    Curve25519Key::generate_priv(&mut rng, &mut private_buffer).expect("Error with generate_priv()");
    let mut public_buffer = [0u8; Curve25519Key::KEYSIZE];
    Curve25519Key::make_pub(&private_buffer, &mut public_buffer).expect("Error with make_pub()");
    Curve25519Key::check_public(&public_buffer, false).expect("Error with check_public()");
}

#[test]
fn test_generate_priv() {
    let mut rng = RNG::new().expect("Error with new()");
    let mut private_buffer = [0u8; Curve25519Key::KEYSIZE];
    Curve25519Key::generate_priv(&mut rng, &mut private_buffer).expect("Error with generate_priv()");
}

#[test]
fn test_import_export_private() {
    let mut rng = RNG::new().expect("Error with new()");
    let mut curve25519key = Curve25519Key::generate(&mut rng).expect("Error with generate()");
    let mut private_buffer = [0u8; Curve25519Key::KEYSIZE];
    curve25519key.export_private_raw(&mut private_buffer).expect("Error with export_private_raw()");
    Curve25519Key::import_private(&private_buffer).expect("Error with import_private()");
}

#[test]
fn test_import_export_private_ex() {
    let mut rng = RNG::new().expect("Error with new()");
    let mut curve25519key = Curve25519Key::generate(&mut rng).expect("Error with generate()");
    let mut private_buffer = [0u8; Curve25519Key::KEYSIZE];
    curve25519key.export_private_raw_ex(&mut private_buffer, false).expect("Error with export_private_raw_ex()");
    Curve25519Key::import_private_ex(&private_buffer, false).expect("Error with import_private_ex()");
}

#[test]
fn test_import_export_raw() {
    let mut rng = RNG::new().expect("Error with new()");
    let mut curve25519key = Curve25519Key::generate(&mut rng).expect("Error with generate()");
    let mut private_buffer = [0u8; Curve25519Key::KEYSIZE];
    let mut public_buffer = [0u8; Curve25519Key::KEYSIZE];
    curve25519key.export_key_raw(&mut private_buffer, &mut public_buffer).expect("Error with export_key_raw()");
    Curve25519Key::import_private_raw(&private_buffer, &public_buffer).expect("Error with import_private_raw()");
}

#[test]
fn test_import_export_raw_ex() {
    let mut rng = RNG::new().expect("Error with new()");
    let mut curve25519key = Curve25519Key::generate(&mut rng).expect("Error with generate()");
    let mut private_buffer = [0u8; Curve25519Key::KEYSIZE];
    let mut public_buffer = [0u8; Curve25519Key::KEYSIZE];
    curve25519key.export_key_raw_ex(&mut private_buffer, &mut public_buffer, false).expect("Error with export_key_raw_ex()");
    Curve25519Key::import_private_raw_ex(&private_buffer, &public_buffer, false).expect("Error with import_private_raw_ex()");
}

#[test]
fn test_import_export_public() {
    let mut rng = RNG::new().expect("Error with new()");
    let mut curve25519key = Curve25519Key::generate(&mut rng).expect("Error with generate()");
    let mut public_buffer = [0u8; Curve25519Key::KEYSIZE];
    curve25519key.export_public(&mut public_buffer).expect("Error with export_public()");
    Curve25519Key::import_public(&public_buffer).expect("Error with import_public()");
}

#[test]
fn test_import_export_public_ex() {
    let mut rng = RNG::new().expect("Error with new()");
    let mut curve25519key = Curve25519Key::generate(&mut rng).expect("Error with generate()");
    let mut public_buffer = [0u8; Curve25519Key::KEYSIZE];
    curve25519key.export_public_ex(&mut public_buffer, false).expect("Error with export_public_ex()");
    Curve25519Key::import_public_ex(&public_buffer, false).expect("Error with import_public_ex()");
}

#[test]
fn test_make_pub() {
    let mut rng = RNG::new().expect("Error with new()");
    let mut private_buffer = [0u8; Curve25519Key::KEYSIZE];
    Curve25519Key::generate_priv(&mut rng, &mut private_buffer).expect("Error with generate_priv()");
    let mut public_buffer = [0u8; Curve25519Key::KEYSIZE];
    Curve25519Key::make_pub(&private_buffer, &mut public_buffer).expect("Error with make_pub()");
}

#[test]
#[cfg(curve25519_blinding)]
fn test_make_pub_blind() {
    let mut rng = RNG::new().expect("Error with new()");
    let mut private_buffer = [0u8; Curve25519Key::KEYSIZE];
    Curve25519Key::generate_priv(&mut rng, &mut private_buffer).expect("Error with generate_priv()");
    let mut public_buffer = [0u8; Curve25519Key::KEYSIZE];
    Curve25519Key::make_pub_blind(&private_buffer, &mut public_buffer, &mut rng).expect("Error with make_pub_blind()");
}

#[test]
fn test_shared_secret() {
    let mut rng = RNG::new().expect("Error with new()");
    let mut key1 = Curve25519Key::generate(&mut rng).expect("Error with generate()");
    let mut key2 = Curve25519Key::generate(&mut rng).expect("Error with generate()");

    #[cfg(curve25519_blinding)]
    key1.set_rng(&mut rng).expect("Error with set_rng()");
    #[cfg(curve25519_blinding)]
    key2.set_rng(&mut rng).expect("Error with set_rng()");

    let mut public_buffer = [0u8; Curve25519Key::KEYSIZE];
    key1.export_public(&mut public_buffer).expect("Error with export_public()");
    let mut key1public = Curve25519Key::import_public(&public_buffer).expect("Error with import_public()");
    key2.export_public(&mut public_buffer).expect("Error with export_public()");
    let mut key2public = Curve25519Key::import_public(&public_buffer).expect("Error with import_public()");

    let mut ss1 = [0u8; Curve25519Key::KEYSIZE];
    let mut ss2 = [0u8; Curve25519Key::KEYSIZE];
    Curve25519Key::shared_secret(&mut key1, &mut key2public, &mut ss1).expect("Error with shared_secret()");
    Curve25519Key::shared_secret(&mut key2, &mut key1public, &mut ss2).expect("Error with shared_secret()");

    assert_eq!(ss1, ss2);
}

#[test]
fn test_shared_secret_ex() {
    let mut rng = RNG::new().expect("Error with new()");
    let mut key1 = Curve25519Key::generate(&mut rng).expect("Error with generate()");
    let mut key2 = Curve25519Key::generate(&mut rng).expect("Error with generate()");

    #[cfg(curve25519_blinding)]
    key1.set_rng(&mut rng).expect("Error with set_rng()");
    #[cfg(curve25519_blinding)]
    key2.set_rng(&mut rng).expect("Error with set_rng()");

    let mut public_buffer = [0u8; Curve25519Key::KEYSIZE];
    key1.export_public(&mut public_buffer).expect("Error with export_public()");
    let mut key1public = Curve25519Key::import_public(&public_buffer).expect("Error with import_public()");
    key2.export_public(&mut public_buffer).expect("Error with export_public()");
    let mut key2public = Curve25519Key::import_public(&public_buffer).expect("Error with import_public()");

    let mut ss1 = [0u8; Curve25519Key::KEYSIZE];
    let mut ss2 = [0u8; Curve25519Key::KEYSIZE];
    Curve25519Key::shared_secret_ex(&mut key1, &mut key2public, &mut ss1, false).expect("Error with shared_secret()");
    Curve25519Key::shared_secret_ex(&mut key2, &mut key1public, &mut ss2, false).expect("Error with shared_secret()");

    assert_eq!(ss1, ss2);
}
