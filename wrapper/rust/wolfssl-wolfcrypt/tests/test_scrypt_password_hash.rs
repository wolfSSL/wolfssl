#![cfg(all(feature = "password-hash", kdf_scrypt))]

mod common;

use password_hash::phc::PasswordHash;
use password_hash::{CustomizedPasswordHasher, PasswordHasher, PasswordVerifier};
use wolfssl_wolfcrypt::scrypt_password_hash::*;

/// Use modest scrypt parameters in tests to keep them fast while still
/// exercising the full code path.
fn test_params() -> Params {
    Params { log_n: 10, r: 8, p: 1, output_len: 32 }
}

#[test]
fn test_hash_and_verify() {
    common::setup();

    let hasher = Scrypt { params: test_params() };
    let salt = b"0123456789abcdef";
    let password = b"hunter2";

    let hash = hasher
        .hash_password_with_salt(password, salt)
        .expect("hashing failed");

    assert!(hash.salt.is_some());
    assert!(hash.hash.is_some());
    assert_eq!(hash.hash.as_ref().unwrap().len(), 32);

    hasher
        .verify_password(password, &hash)
        .expect("verification of correct password failed");

    assert!(hasher.verify_password(b"wrong_password", &hash).is_err());
}

#[test]
fn test_hash_roundtrip_phc_string() {
    common::setup();

    let hasher = Scrypt { params: test_params() };
    let salt = b"0123456789abcdef";
    let password = b"password";

    let hash = hasher
        .hash_password_with_salt(password, salt)
        .expect("hashing failed");

    let phc_string = hash.to_string();
    assert!(phc_string.starts_with("$scrypt$"));
    assert!(phc_string.contains("ln=10"));
    assert!(phc_string.contains("r=8"));
    assert!(phc_string.contains("p=1"));

    let parsed = PasswordHash::new(&phc_string).expect("parsing PHC string failed");

    hasher
        .verify_password(password, &parsed)
        .expect("verification of parsed hash failed");
}

#[test]
fn test_default_params() {
    common::setup();

    let hasher = Scrypt::default();
    assert_eq!(hasher.params.log_n, RECOMMENDED_LOG_N);
    assert_eq!(hasher.params.r, RECOMMENDED_R);
    assert_eq!(hasher.params.p, RECOMMENDED_P);
    assert_eq!(hasher.params.output_len, DEFAULT_OUTPUT_LEN);
}

#[test]
fn test_customized_hash() {
    common::setup();

    let hasher = Scrypt::default();
    let salt = b"0123456789abcdef";
    let password = b"password";
    let custom = Params { log_n: 11, r: 8, p: 2, output_len: 48 };

    let hash = hasher
        .hash_password_with_params(password, salt, custom)
        .expect("customized hashing failed");

    assert_eq!(hash.hash.as_ref().unwrap().len(), 48);
    assert_eq!(hash.params.get_decimal("ln"), Some(11));
    assert_eq!(hash.params.get_decimal("r"), Some(8));
    assert_eq!(hash.params.get_decimal("p"), Some(2));

    hasher
        .verify_password(password, &hash)
        .expect("customized hash verification failed");
}

#[test]
fn test_version_rejected() {
    common::setup();

    let hasher = Scrypt { params: test_params() };
    let salt = b"0123456789abcdef";

    let result = hasher.hash_password_customized(
        b"password", salt, None, Some(1), test_params());
    assert!(result.is_err());
}

#[test]
fn test_unknown_algorithm_rejected() {
    common::setup();

    let hasher = Scrypt { params: test_params() };
    let salt = b"0123456789abcdef";

    let result = hasher.hash_password_customized(
        b"password", salt, Some("argon2id"), None, test_params());
    assert!(result.is_err());
}

#[test]
fn test_invalid_params_rejected() {
    common::setup();

    let hasher = Scrypt { params: test_params() };
    let salt = b"0123456789abcdef";

    // r out of range
    let bad = Params { log_n: 10, r: 9, p: 1, output_len: 32 };
    assert!(hasher.hash_password_with_params(b"pw", salt, bad).is_err());

    // p must be > 0
    let bad = Params { log_n: 10, r: 8, p: 0, output_len: 32 };
    assert!(hasher.hash_password_with_params(b"pw", salt, bad).is_err());

    // log_n must be > 0
    let bad = Params { log_n: 0, r: 8, p: 1, output_len: 32 };
    assert!(hasher.hash_password_with_params(b"pw", salt, bad).is_err());
}

#[test]
fn test_deterministic_output() {
    common::setup();

    let hasher = Scrypt { params: test_params() };
    let salt = b"0123456789abcdef";
    let password = b"password";

    let h1 = hasher.hash_password_with_salt(password, salt).unwrap();
    let h2 = hasher.hash_password_with_salt(password, salt).unwrap();
    assert_eq!(h1.hash, h2.hash);
}

#[test]
fn test_different_salts_produce_different_hashes() {
    common::setup();

    let hasher = Scrypt { params: test_params() };
    let password = b"password";

    let h1 = hasher.hash_password_with_salt(password, b"salt_aaaaaaaaaa01").unwrap();
    let h2 = hasher.hash_password_with_salt(password, b"salt_aaaaaaaaaa02").unwrap();
    assert_ne!(h1.hash, h2.hash);
}
