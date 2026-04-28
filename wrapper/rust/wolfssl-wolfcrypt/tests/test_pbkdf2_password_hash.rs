#![cfg(all(feature = "password-hash", hmac, kdf_pbkdf2))]

mod common;

use password_hash::phc::PasswordHash;
use password_hash::{CustomizedPasswordHasher, PasswordHasher, PasswordVerifier};
use wolfssl_wolfcrypt::pbkdf2_password_hash::*;

#[test]
fn test_hash_and_verify() {
    common::setup();

    let hasher = Pbkdf2 {
        algorithm: Algorithm::Pbkdf2Sha256,
        params: Params {
            rounds: 4096,
            output_len: 32,
        },
    };

    let salt = b"0123456789abcdef"; // 16 bytes
    let password = b"hunter2";

    let hash = hasher
        .hash_password_with_salt(password, salt)
        .expect("hashing failed");

    assert_eq!(hash.algorithm, Algorithm::Pbkdf2Sha256.ident());
    assert!(hash.salt.is_some());
    assert!(hash.hash.is_some());
    assert_eq!(hash.hash.as_ref().unwrap().len(), 32);

    // Verify correct password succeeds
    hasher
        .verify_password(password, &hash)
        .expect("verification of correct password failed");

    // Verify wrong password fails
    let result = hasher.verify_password(b"wrong_password", &hash);
    assert!(result.is_err());
}

#[test]
fn test_hash_roundtrip_phc_string() {
    common::setup();

    let hasher = Pbkdf2 {
        algorithm: Algorithm::Pbkdf2Sha256,
        params: Params {
            rounds: 4096,
            output_len: 32,
        },
    };

    let salt = b"0123456789abcdef";
    let password = b"password";

    let hash = hasher
        .hash_password_with_salt(password, salt)
        .expect("hashing failed");

    // Serialize to PHC string and parse back
    let phc_string = hash.to_string();
    assert!(phc_string.starts_with("$pbkdf2-sha256$"));

    let parsed = PasswordHash::new(&phc_string).expect("parsing PHC string failed");

    // Verify with the parsed hash
    hasher
        .verify_password(password, &parsed)
        .expect("verification of parsed hash failed");
}

#[test]
fn test_default_params() {
    common::setup();

    let hasher = Pbkdf2::default();
    assert_eq!(hasher.algorithm, Algorithm::Pbkdf2Sha256);
    assert_eq!(hasher.params.rounds, DEFAULT_ROUNDS);
    assert_eq!(hasher.params.output_len, DEFAULT_OUTPUT_LEN);
}

#[test]
fn test_sha384_algorithm() {
    common::setup();

    let hasher = Pbkdf2 {
        algorithm: Algorithm::Pbkdf2Sha384,
        params: Params {
            rounds: 4096,
            output_len: 48,
        },
    };

    let salt = b"0123456789abcdef";
    let password = b"password";

    let hash = hasher
        .hash_password_with_salt(password, salt)
        .expect("hashing with SHA-384 failed");
    assert_eq!(hash.algorithm, Algorithm::Pbkdf2Sha384.ident());
    assert_eq!(hash.hash.as_ref().unwrap().len(), 48);

    hasher
        .verify_password(password, &hash)
        .expect("SHA-384 verification failed");
}

#[test]
#[cfg(sha512)]
fn test_sha512_algorithm() {
    common::setup();

    let hasher = Pbkdf2 {
        algorithm: Algorithm::Pbkdf2Sha512,
        params: Params {
            rounds: 4096,
            output_len: 64,
        },
    };

    let salt = b"0123456789abcdef";
    let password = b"password";

    let hash = hasher
        .hash_password_with_salt(password, salt)
        .expect("hashing with SHA-512 failed");
    assert_eq!(hash.algorithm, Algorithm::Pbkdf2Sha512.ident());
    assert_eq!(hash.hash.as_ref().unwrap().len(), 64);

    hasher
        .verify_password(password, &hash)
        .expect("SHA-512 verification failed");
}

#[test]
fn test_customized_hash() {
    common::setup();

    let hasher = Pbkdf2::default();

    let salt = b"0123456789abcdef";
    let password = b"password";
    let custom_params = Params {
        rounds: 8192,
        output_len: 48,
    };

    let hash = hasher
        .hash_password_with_params(password, salt, custom_params)
        .expect("customized hashing failed");

    assert_eq!(hash.hash.as_ref().unwrap().len(), 48);
    assert_eq!(hash.params.get_decimal("i"), Some(8192));

    hasher
        .verify_password(password, &hash)
        .expect("customized hash verification failed");
}

#[test]
#[cfg(sha512)]
fn test_customized_hash_with_algorithm_override() {
    common::setup();

    let hasher = Pbkdf2::default();

    let salt = b"0123456789abcdef";
    let password = b"password";
    let params = Params {
        rounds: 4096,
        output_len: 64,
    };

    let hash = hasher
        .hash_password_customized(password, salt, Some("pbkdf2-sha512"), None, params)
        .expect("algorithm override failed");

    assert_eq!(hash.algorithm, Algorithm::Pbkdf2Sha512.ident());
    assert_eq!(hash.hash.as_ref().unwrap().len(), 64);

    // Verify with a Pbkdf2 instance using the matching algorithm
    let verifier = Pbkdf2 {
        algorithm: Algorithm::Pbkdf2Sha512,
        ..Pbkdf2::default()
    };
    verifier
        .verify_password(password, &hash)
        .expect("verification with algorithm override failed");
}

#[test]
fn test_version_rejected() {
    common::setup();

    let hasher = Pbkdf2::default();
    let salt = b"0123456789abcdef";

    let result =
        hasher.hash_password_customized(b"password", salt, None, Some(1), Params::default());
    assert!(result.is_err());
}

#[test]
fn test_unknown_algorithm_rejected() {
    common::setup();

    let hasher = Pbkdf2::default();
    let salt = b"0123456789abcdef";

    let result = hasher.hash_password_customized(
        b"password",
        salt,
        Some("argon2id"),
        None,
        Params::default(),
    );
    assert!(result.is_err());
}

#[test]
fn test_deterministic_output() {
    common::setup();

    let hasher = Pbkdf2 {
        algorithm: Algorithm::Pbkdf2Sha256,
        params: Params {
            rounds: 4096,
            output_len: 32,
        },
    };

    let salt = b"0123456789abcdef";
    let password = b"password";

    let hash1 = hasher
        .hash_password_with_salt(password, salt)
        .expect("first hash failed");
    let hash2 = hasher
        .hash_password_with_salt(password, salt)
        .expect("second hash failed");

    assert_eq!(hash1.hash, hash2.hash);
}

#[test]
fn test_different_salts_produce_different_hashes() {
    common::setup();

    let hasher = Pbkdf2 {
        algorithm: Algorithm::Pbkdf2Sha256,
        params: Params {
            rounds: 4096,
            output_len: 32,
        },
    };

    let password = b"password";

    let hash1 = hasher
        .hash_password_with_salt(password, b"salt_aaaaaaaaaa01")
        .expect("first hash failed");
    let hash2 = hasher
        .hash_password_with_salt(password, b"salt_aaaaaaaaaa02")
        .expect("second hash failed");

    assert_ne!(hash1.hash, hash2.hash);
}
