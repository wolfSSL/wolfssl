#![cfg(all(curve25519, random))]

#[cfg(feature = "alloc")]
use std::rc::Rc;
use wolfssl_wolfcrypt::curve25519::*;
use wolfssl_wolfcrypt::random::RNG;

#[test]
fn test_check_pub() {
    let rng = RNG::new().expect("Error with new()");
    let mut private_buffer = [0u8; Curve25519Key::KEYSIZE];
    Curve25519Key::generate_priv(&rng, &mut private_buffer).expect("Error with generate_priv()");
    let mut public_buffer = [0u8; Curve25519Key::KEYSIZE];
    Curve25519Key::make_pub(&private_buffer, &mut public_buffer).expect("Error with make_pub()");
    Curve25519Key::check_public(&public_buffer, false).expect("Error with check_public()");
}

#[test]
fn test_generate_priv() {
    let rng = RNG::new().expect("Error with new()");
    let mut private_buffer = [0u8; Curve25519Key::KEYSIZE];
    Curve25519Key::generate_priv(&rng, &mut private_buffer).expect("Error with generate_priv()");
}

#[test]
fn test_generate() {
    let rng = RNG::new().expect("Error with new()");
    let key = Curve25519Key::generate(rng).expect("Error with generate()");
    /* The key takes ownership of the RNG and keeps it alive. */
    assert!(key.rng().is_some());
}

#[test]
#[cfg(feature = "alloc")]
fn test_generate_shared_rng() {
    let rng = Rc::new(RNG::new().expect("Error with new()"));
    let mut key1 = Curve25519Key::generate_shared_rng(Rc::clone(&rng)).expect("Error with generate_shared_rng()");
    let mut key2 = Curve25519Key::generate_shared_rng(Rc::clone(&rng)).expect("Error with generate_shared_rng()");
    /* Both keys hold a reference to the same shared RNG. */
    assert_eq!(Rc::strong_count(&rng), 3);
    assert!(key1.rng().is_some());
    assert!(key2.rng().is_some());

    /* The keys are still independently generated. */
    let mut public1 = [0u8; Curve25519Key::KEYSIZE];
    let mut public2 = [0u8; Curve25519Key::KEYSIZE];
    key1.export_public(&mut public1).expect("Error with export_public()");
    key2.export_public(&mut public2).expect("Error with export_public()");
    assert_ne!(public1, public2);

    /* Dropping the keys releases their references to the shared RNG. */
    drop(key1);
    drop(key2);
    assert_eq!(Rc::strong_count(&rng), 1);
}

#[test]
fn test_import_no_rng() {
    let rng = RNG::new().expect("Error with new()");
    let mut key = Curve25519Key::generate(rng).expect("Error with generate()");
    let mut private_buffer = [0u8; Curve25519Key::KEYSIZE];
    key.export_private_raw(&mut private_buffer).expect("Error with export_private_raw()");
    /* An imported key has no RNG bound to it until set_rng() is called. */
    let imported = Curve25519Key::import_private(&private_buffer).expect("Error with import_private()");
    assert!(imported.rng().is_none());
}

#[test]
fn test_import_export_private() {
    let rng = RNG::new().expect("Error with new()");
    let mut curve25519key = Curve25519Key::generate(rng).expect("Error with generate()");
    let mut private_buffer = [0u8; Curve25519Key::KEYSIZE];
    curve25519key.export_private_raw(&mut private_buffer).expect("Error with export_private_raw()");
    Curve25519Key::import_private(&private_buffer).expect("Error with import_private()");
}

#[test]
fn test_import_export_private_ex() {
    let rng = RNG::new().expect("Error with new()");
    let mut curve25519key = Curve25519Key::generate(rng).expect("Error with generate()");
    let mut private_buffer = [0u8; Curve25519Key::KEYSIZE];
    curve25519key.export_private_raw_ex(&mut private_buffer, false).expect("Error with export_private_raw_ex()");
    Curve25519Key::import_private_ex(&private_buffer, false).expect("Error with import_private_ex()");
}

#[test]
fn test_import_export_raw() {
    let rng = RNG::new().expect("Error with new()");
    let mut curve25519key = Curve25519Key::generate(rng).expect("Error with generate()");
    let mut private_buffer = [0u8; Curve25519Key::KEYSIZE];
    let mut public_buffer = [0u8; Curve25519Key::KEYSIZE];
    curve25519key.export_key_raw(&mut private_buffer, &mut public_buffer).expect("Error with export_key_raw()");
    Curve25519Key::import_private_raw(&private_buffer, &public_buffer).expect("Error with import_private_raw()");
}

#[test]
fn test_import_export_raw_ex() {
    let rng = RNG::new().expect("Error with new()");
    let mut curve25519key = Curve25519Key::generate(rng).expect("Error with generate()");
    let mut private_buffer = [0u8; Curve25519Key::KEYSIZE];
    let mut public_buffer = [0u8; Curve25519Key::KEYSIZE];
    curve25519key.export_key_raw_ex(&mut private_buffer, &mut public_buffer, false).expect("Error with export_key_raw_ex()");
    Curve25519Key::import_private_raw_ex(&private_buffer, &public_buffer, false).expect("Error with import_private_raw_ex()");
}

#[test]
fn test_import_export_public() {
    let rng = RNG::new().expect("Error with new()");
    let mut curve25519key = Curve25519Key::generate(rng).expect("Error with generate()");
    let mut public_buffer = [0u8; Curve25519Key::KEYSIZE];
    curve25519key.export_public(&mut public_buffer).expect("Error with export_public()");
    Curve25519Key::import_public(&public_buffer).expect("Error with import_public()");
}

#[test]
fn test_import_export_public_ex() {
    let rng = RNG::new().expect("Error with new()");
    let mut curve25519key = Curve25519Key::generate(rng).expect("Error with generate()");
    let mut public_buffer = [0u8; Curve25519Key::KEYSIZE];
    curve25519key.export_public_ex(&mut public_buffer, false).expect("Error with export_public_ex()");
    Curve25519Key::import_public_ex(&public_buffer, false).expect("Error with import_public_ex()");
}

#[test]
fn test_make_pub() {
    let rng = RNG::new().expect("Error with new()");
    let mut private_buffer = [0u8; Curve25519Key::KEYSIZE];
    Curve25519Key::generate_priv(&rng, &mut private_buffer).expect("Error with generate_priv()");
    let mut public_buffer = [0u8; Curve25519Key::KEYSIZE];
    Curve25519Key::make_pub(&private_buffer, &mut public_buffer).expect("Error with make_pub()");
}

#[test]
#[cfg(curve25519_blinding)]
fn test_make_pub_blind() {
    let rng = RNG::new().expect("Error with new()");
    let mut private_buffer = [0u8; Curve25519Key::KEYSIZE];
    Curve25519Key::generate_priv(&rng, &mut private_buffer).expect("Error with generate_priv()");
    let mut public_buffer = [0u8; Curve25519Key::KEYSIZE];
    Curve25519Key::make_pub_blind(&private_buffer, &mut public_buffer, &rng).expect("Error with make_pub_blind()");
}

#[test]
fn test_shared_secret() {
    /* With the alloc feature the two keys can share a single RNG. */
    #[cfg(feature = "alloc")]
    let rng = Rc::new(RNG::new().expect("Error with new()"));
    #[cfg(feature = "alloc")]
    let mut key1 = Curve25519Key::generate_shared_rng(Rc::clone(&rng)).expect("Error with generate_shared_rng()");
    #[cfg(feature = "alloc")]
    let mut key2 = Curve25519Key::generate_shared_rng(Rc::clone(&rng)).expect("Error with generate_shared_rng()");
    /* Without it, each key owns its own RNG. */
    #[cfg(not(feature = "alloc"))]
    let mut key1 = Curve25519Key::generate(RNG::new().expect("Error with new()")).expect("Error with generate()");
    #[cfg(not(feature = "alloc"))]
    let mut key2 = Curve25519Key::generate(RNG::new().expect("Error with new()")).expect("Error with generate()");

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
    /* With the alloc feature the two keys can share a single RNG. */
    #[cfg(feature = "alloc")]
    let rng = Rc::new(RNG::new().expect("Error with new()"));
    #[cfg(feature = "alloc")]
    let mut key1 = Curve25519Key::generate_shared_rng(Rc::clone(&rng)).expect("Error with generate_shared_rng()");
    #[cfg(feature = "alloc")]
    let mut key2 = Curve25519Key::generate_shared_rng(Rc::clone(&rng)).expect("Error with generate_shared_rng()");
    /* Without it, each key owns its own RNG. */
    #[cfg(not(feature = "alloc"))]
    let mut key1 = Curve25519Key::generate(RNG::new().expect("Error with new()")).expect("Error with generate()");
    #[cfg(not(feature = "alloc"))]
    let mut key2 = Curve25519Key::generate(RNG::new().expect("Error with new()")).expect("Error with generate()");

    #[cfg(all(curve25519_blinding, feature = "alloc"))]
    key1.set_shared_rng(Rc::clone(&rng)).expect("Error with set_shared_rng()");
    #[cfg(all(curve25519_blinding, feature = "alloc"))]
    key2.set_shared_rng(Rc::clone(&rng)).expect("Error with set_shared_rng()");
    #[cfg(all(curve25519_blinding, not(feature = "alloc")))]
    key1.set_rng(RNG::new().expect("Error with new()")).expect("Error with set_rng()");
    #[cfg(all(curve25519_blinding, not(feature = "alloc")))]
    key2.set_rng(RNG::new().expect("Error with new()")).expect("Error with set_rng()");

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
