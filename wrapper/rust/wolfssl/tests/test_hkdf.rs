use wolfssl::wolfcrypt::hkdf::*;
use wolfssl::wolfcrypt::hmac::HMAC;
use wolfssl::wolfcrypt::sha::SHA256;

#[test]
fn test_hkdf_extract_expand() {
    let ikm = b"MyPassword0";
    let salt = b"12345678ABCDEFGH";
    let mut extract_out = [0u8; SHA256::DIGEST_SIZE];
    hkdf_extract(HMAC::TYPE_SHA256, Some(salt), ikm, &mut extract_out).expect("Error with hkdf_extract()");
    hkdf_extract_ex(HMAC::TYPE_SHA256, Some(salt), ikm, &mut extract_out, None, None).expect("Error with hkdf_extract_ex()");

    let info = b"0";
    let mut expand_out = [0u8; 16];
    hkdf_expand(HMAC::TYPE_SHA256, &extract_out, Some(info), &mut expand_out).expect("Error with hkdf_expand()");
    hkdf_expand_ex(HMAC::TYPE_SHA256, &extract_out, Some(info), &mut expand_out, None, None).expect("Error with hkdf_expand_ex()");

    let expected_key = [
        0x17, 0x5F, 0x24, 0xB3, 0x18, 0x20, 0xF3, 0xD4,
        0x71, 0x97, 0x8A, 0x98, 0x9E, 0xB2, 0xC1, 0x35
    ];
    assert_eq!(expand_out, expected_key);
}

#[test]
fn test_hkdf_one_shot() {
    let ikm = b"MyPassword0";
    let salt = b"12345678ABCDEFGH";
    let info = b"0";
    let mut out = [0u8; 16];
    hkdf(HMAC::TYPE_SHA256, ikm, Some(salt), Some(info), &mut out).expect("Error with hkdf()");

    let expected_out = [
        0x17, 0x5F, 0x24, 0xB3, 0x18, 0x20, 0xF3, 0xD4,
        0x71, 0x97, 0x8A, 0x98, 0x9E, 0xB2, 0xC1, 0x35
    ];
    assert_eq!(out, expected_out);
}
