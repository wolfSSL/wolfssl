#![cfg(all(hmac, sha256, feature = "mac"))]

use digest::{KeyInit, Mac};
use wolfssl_wolfcrypt::hmac_mac::HmacSha256;

#[test]
fn test_hmac_sha256_mac_trait() {
    let key = b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
    let input = b"Hi There";
    let expected = b"\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b\x88\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37\x6c\x2e\x32\xcf\xf7";

    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC init failed");
    mac.update(input);
    mac.verify_slice(expected).expect("HMAC verification failed");
}

#[test]
fn test_hmac_sha256_mac_chain() {
    let key = b"Jefe";
    let input = b"what do ya want for nothing?";
    let expected = b"\x5b\xdc\xc1\x46\xbf\x60\x75\x4e\x6a\x04\x24\x26\x08\x95\x75\xc7\x5a\x00\x3f\x08\x9d\x27\x39\x83\x9d\xec\x58\xb9\x64\xec\x38\x43";

    let mac = HmacSha256::new_from_slice(key)
        .expect("HMAC init failed")
        .chain_update(input);
    mac.verify_slice(expected).expect("HMAC verification failed");
}

#[test]
fn test_hmac_sha256_mac_finalize() {
    let key = b"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA";
    let input = b"\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD";
    let expected: &[u8] = b"\x77\x3e\xa9\x1e\x36\x80\x0e\x46\x85\x4d\xb8\xeb\xd0\x91\x81\xa7\x29\x59\x09\x8b\x3e\xf8\xc1\x22\xd9\x63\x55\x14\xce\xd5\x65\xfe";

    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC init failed");
    mac.update(input);
    let result = mac.finalize();
    assert_eq!(result.as_bytes().as_slice(), expected);
}

#[test]
fn test_hmac_sha256_mac_verify_fail() {
    let key = b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
    let input = b"Hi There";
    let wrong_tag = [0u8; 32];

    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC init failed");
    mac.update(input);
    assert!(mac.verify_slice(&wrong_tag).is_err());
}
