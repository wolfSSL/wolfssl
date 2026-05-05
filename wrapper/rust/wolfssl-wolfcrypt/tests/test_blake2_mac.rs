#![cfg(all(any(blake2b, blake2s), feature = "mac"))]

use digest::{KeyInit, Mac};

#[test]
#[cfg(blake2b)]
fn test_blake2b_mac_512() {
    use wolfssl_wolfcrypt::blake2::BLAKE2b;
    use wolfssl_wolfcrypt::blake2_mac::Blake2bMac512;

    let key = [0x42u8; 64];
    let input = b"The quick brown fox jumps over the lazy dog";

    let mut reference = BLAKE2b::new_with_key(64, &key)
        .expect("Error with new_with_key()");
    reference.update(input).expect("Error with update()");
    let mut expected = [0u8; 64];
    reference.finalize(&mut expected)
        .expect("Error with finalize()");

    let mut mac = Blake2bMac512::new_from_slice(&key)
        .expect("Blake2bMac512 init failed");
    mac.update(input);
    let tag = mac.finalize();
    assert_eq!(tag.into_bytes().as_slice(), &expected);
}

#[test]
#[cfg(blake2b)]
fn test_blake2b_mac_256() {
    use wolfssl_wolfcrypt::blake2::BLAKE2b;
    use wolfssl_wolfcrypt::blake2_mac::Blake2bMac256;

    let key = [0x33u8; 64];
    let input = b"libsodium crypto_generichash analog";

    let mut reference = BLAKE2b::new_with_key(32, &key)
        .expect("Error with new_with_key()");
    reference.update(input).expect("Error with update()");
    let mut expected = [0u8; 32];
    reference.finalize(&mut expected)
        .expect("Error with finalize()");

    let mut mac = Blake2bMac256::new_from_slice(&key)
        .expect("Blake2bMac256 init failed");
    mac.update(input);
    let tag = mac.finalize();
    assert_eq!(tag.into_bytes().as_slice(), &expected);
}

#[test]
#[cfg(blake2b)]
fn test_blake2b_mac_384() {
    use wolfssl_wolfcrypt::blake2::BLAKE2b;
    use wolfssl_wolfcrypt::blake2_mac::Blake2bMac384;

    let key = [0x77u8; 64];
    let input = b"sha-384 sized blake2b mac";

    let mut reference = BLAKE2b::new_with_key(48, &key)
        .expect("Error with new_with_key()");
    reference.update(input).expect("Error with update()");
    let mut expected = [0u8; 48];
    reference.finalize(&mut expected)
        .expect("Error with finalize()");

    let mut mac = Blake2bMac384::new_from_slice(&key)
        .expect("Blake2bMac384 init failed");
    mac.update(input);
    let tag = mac.finalize();
    assert_eq!(tag.into_bytes().as_slice(), &expected);
}

#[test]
#[cfg(blake2b)]
fn test_blake2b_mac_512_chunked() {
    use wolfssl_wolfcrypt::blake2::BLAKE2b;
    use wolfssl_wolfcrypt::blake2_mac::Blake2bMac512;

    let key = [0xA5u8; 64];
    let input: Vec<u8> = (0u8..200).collect();

    let mut reference = BLAKE2b::new_with_key(64, &key)
        .expect("Error with new_with_key()");
    reference.update(&input).expect("Error with update()");
    let mut expected = [0u8; 64];
    reference.finalize(&mut expected)
        .expect("Error with finalize()");

    let mut mac = Blake2bMac512::new_from_slice(&key)
        .expect("Blake2bMac512 init failed");
    for chunk in input.chunks(17) {
        mac.update(chunk);
    }
    mac.verify_slice(&expected)
        .expect("Blake2bMac512 verify failed");
}

#[test]
#[cfg(blake2s)]
fn test_blake2s_mac_128() {
    use wolfssl_wolfcrypt::blake2::BLAKE2s;
    use wolfssl_wolfcrypt::blake2_mac::Blake2sMac128;

    let key = [0x55u8; 32];
    let input = b"short blake2s mac";

    let mut reference = BLAKE2s::new_with_key(16, &key)
        .expect("Error with new_with_key()");
    reference.update(input).expect("Error with update()");
    let mut expected = [0u8; 16];
    reference.finalize(&mut expected)
        .expect("Error with finalize()");

    let mut mac = Blake2sMac128::new_from_slice(&key)
        .expect("Blake2sMac128 init failed");
    mac.update(input);
    let tag = mac.finalize();
    assert_eq!(tag.into_bytes().as_slice(), &expected);
}

#[test]
#[cfg(blake2s)]
fn test_blake2s_mac_192() {
    use wolfssl_wolfcrypt::blake2::BLAKE2s;
    use wolfssl_wolfcrypt::blake2_mac::Blake2sMac192;

    let key = [0x99u8; 32];
    let input = b"medium blake2s mac";

    let mut reference = BLAKE2s::new_with_key(24, &key)
        .expect("Error with new_with_key()");
    reference.update(input).expect("Error with update()");
    let mut expected = [0u8; 24];
    reference.finalize(&mut expected)
        .expect("Error with finalize()");

    let mut mac = Blake2sMac192::new_from_slice(&key)
        .expect("Blake2sMac192 init failed");
    mac.update(input);
    let tag = mac.finalize();
    assert_eq!(tag.into_bytes().as_slice(), &expected);
}

#[test]
#[cfg(blake2s)]
fn test_blake2s_mac_256() {
    use wolfssl_wolfcrypt::blake2::BLAKE2s;
    use wolfssl_wolfcrypt::blake2_mac::Blake2sMac256;

    let key = [0x42u8; 32];
    let input = b"The quick brown fox jumps over the lazy dog";

    let mut reference = BLAKE2s::new_with_key(32, &key)
        .expect("Error with new_with_key()");
    reference.update(input).expect("Error with update()");
    let mut expected = [0u8; 32];
    reference.finalize(&mut expected)
        .expect("Error with finalize()");

    let mut mac = Blake2sMac256::new_from_slice(&key)
        .expect("Blake2sMac256 init failed");
    mac.update(input);
    let tag = mac.finalize();
    assert_eq!(tag.into_bytes().as_slice(), &expected);
}

#[test]
#[cfg(blake2s)]
fn test_blake2s_mac_256_verify_fail() {
    use wolfssl_wolfcrypt::blake2_mac::Blake2sMac256;

    let key = [0x0Bu8; 32];
    let input = b"hello";
    let wrong_tag = [0u8; 32];

    let mut mac = Blake2sMac256::new_from_slice(&key)
        .expect("Blake2sMac256 init failed");
    mac.update(input);
    assert!(mac.verify_slice(&wrong_tag).is_err());
}
