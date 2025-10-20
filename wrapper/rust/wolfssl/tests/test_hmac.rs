use wolfssl::wolfcrypt::hmac::*;
use wolfssl_sys as ws;

#[test]
fn test_hmac_sha256() {
    let hmac_size = HMAC::get_hmac_size_by_type(HMAC::TYPE_SHA256).expect("Error with get_hmac_size_by_type()");
    assert_eq!(hmac_size, ws::WC_SHA256_DIGEST_SIZE as usize);

    let keys: [&[u8]; 5] = [
        b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
        b"Jefe",
        b"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA",
        b"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA",
        b"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA",
    ];

    let inputs: [&[u8]; 5] = [
        b"Hi There",
        b"what do ya want for nothing?",
        b"\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD",
        b"",
        b"Test Using Larger Than Block-Size Key - Hash Key First",
    ];

    let expected: [&[u8]; 5] = [
        b"\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b\x88\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37\x6c\x2e\x32\xcf\xf7",
        b"\x5b\xdc\xc1\x46\xbf\x60\x75\x4e\x6a\x04\x24\x26\x08\x95\x75\xc7\x5a\x00\x3f\x08\x9d\x27\x39\x83\x9d\xec\x58\xb9\x64\xec\x38\x43",
        b"\x77\x3e\xa9\x1e\x36\x80\x0e\x46\x85\x4d\xb8\xeb\xd0\x91\x81\xa7\x29\x59\x09\x8b\x3e\xf8\xc1\x22\xd9\x63\x55\x14\xce\xd5\x65\xfe",
        b"\x86\xe5\x4f\xd4\x48\x72\x5d\x7e\x5d\xcf\xe2\x23\x53\xc8\x28\xaf\x48\x78\x1e\xb4\x8c\xae\x81\x06\xa7\xe1\xd4\x98\x94\x9f\x3e\x46",
        b"\x60\xe4\x31\x59\x1e\xe0\xb6\x7f\x0d\x8a\x26\xaa\xcb\xf5\xb7\x7f\x8e\x0b\xc6\x21\x37\x28\xc5\x14\x05\x46\x04\x0f\x0e\xe3\x7f\x54",
    ];

    for i in 0..keys.len() {
        let mut hmac =
            if keys[i].len() < 14 {
                HMAC::new_allow_short_key(HMAC::TYPE_SHA256, keys[i]).expect("Error with new_allow_short_key()")
            } else {
                HMAC::new(HMAC::TYPE_SHA256, keys[i]).expect("Error with new()")
            };
        let hmac_size = hmac.get_hmac_size().expect("Error with get_hmac_size()");
        assert_eq!(hmac_size, ws::WC_SHA256_DIGEST_SIZE as usize);
        hmac.update(inputs[i]).expect("Error with update()");
        let mut hash = [0u8; ws::WC_SHA256_DIGEST_SIZE as usize];
        hmac.finalize(&mut hash).expect("Error with finalize()");
        assert_eq!(*expected[i], hash);
    }
}

#[test]
fn test_hkdf_extract_expand() {
    let ikm = b"MyPassword0";
    let salt = b"12345678ABCDEFGH";
    let mut extract_out = [0u8; ws::WC_SHA256_DIGEST_SIZE as usize];
    HKDF::extract(HMAC::TYPE_SHA256, Some(salt), ikm, &mut extract_out).expect("Error with extract()");

    let info = b"0";
    let mut expand_out = [0u8; 16];
    HKDF::expand(HMAC::TYPE_SHA256, &extract_out, Some(info), &mut expand_out).expect("Error with expand()");

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
    HKDF::hkdf(HMAC::TYPE_SHA256, ikm, Some(salt), Some(info), &mut out).expect("Error with hkdf()");

    let expected_out = [
        0x17, 0x5F, 0x24, 0xB3, 0x18, 0x20, 0xF3, 0xD4,
        0x71, 0x97, 0x8A, 0x98, 0x9E, 0xB2, 0xC1, 0x35
    ];
    assert_eq!(out, expected_out);
}
