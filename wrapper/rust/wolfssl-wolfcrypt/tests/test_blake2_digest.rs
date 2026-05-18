#![cfg(all(any(blake2b, blake2s), feature = "digest"))]

use digest::{Digest, FixedOutputReset};
use digest::block_api::BlockSizeUser;

mod common;

fn check_digest<D: Digest + BlockSizeUser + FixedOutputReset + Default>(
    input: &[u8],
    expected: &[u8],
    expected_block_size: usize,
) {
    assert_eq!(<D as Digest>::output_size(), expected.len());
    assert_eq!(<D as BlockSizeUser>::block_size(), expected_block_size);

    /* One-shot digest via associated function. */
    let out = D::digest(input);
    assert_eq!(out.as_slice(), expected);

    /* Streaming via Digest::update and finalize. */
    let mut hasher = D::new();
    Digest::update(&mut hasher, input);
    let out = hasher.finalize();
    assert_eq!(out.as_slice(), expected);

    /* Split update via Default + Update + FixedOutputReset::finalize_reset. */
    let mut hasher = D::default();
    if input.len() >= 2 {
        let mid = input.len() / 2;
        Digest::update(&mut hasher, &input[..mid]);
        Digest::update(&mut hasher, &input[mid..]);
    } else {
        Digest::update(&mut hasher, input);
    }
    let out = hasher.finalize_reset();
    assert_eq!(out.as_slice(), expected);

    /* After reset, the same hasher should produce the same result. */
    Digest::update(&mut hasher, input);
    let out = hasher.finalize();
    assert_eq!(out.as_slice(), expected);
}

#[test]
#[cfg(blake2b)]
fn test_digest_blake2b_512() {
    use wolfssl_wolfcrypt::blake2_digest::Blake2b512;
    common::setup();
    check_digest::<Blake2b512>(
        b"abc",
        b"\xBA\x80\xA5\x3F\x98\x1C\x4D\x0D\x6A\x27\x97\xB6\x9F\x12\xF6\xE9\x4C\x21\x2F\x14\x68\x5A\xC4\xB7\x4B\x12\xBB\x6F\xDB\xFF\xA2\xD1\x7D\x87\xC5\x39\x2A\xAB\x79\x2D\xC2\x52\xD5\xDE\x45\x33\xCC\x95\x18\xD3\x8A\xA8\xDB\xF1\x92\x5A\xB9\x23\x86\xED\xD4\x00\x99\x23",
        128,
    );
}

#[test]
#[cfg(blake2b)]
fn test_digest_blake2b_384() {
    use wolfssl_wolfcrypt::blake2::BLAKE2b;
    use wolfssl_wolfcrypt::blake2_digest::Blake2b384;
    common::setup();

    let mut reference = BLAKE2b::new(48).expect("Error with new()");
    reference.update(b"abc").expect("Error with update()");
    let mut expected = [0u8; 48];
    reference.finalize(&mut expected).expect("Error with finalize()");

    check_digest::<Blake2b384>(b"abc", &expected, 128);
}

#[test]
#[cfg(blake2b)]
fn test_digest_blake2b_256() {
    use wolfssl_wolfcrypt::blake2::BLAKE2b;
    use wolfssl_wolfcrypt::blake2_digest::Blake2b256;
    common::setup();

    let mut reference = BLAKE2b::new(32).expect("Error with new()");
    reference.update(b"abc").expect("Error with update()");
    let mut expected = [0u8; 32];
    reference.finalize(&mut expected).expect("Error with finalize()");

    check_digest::<Blake2b256>(b"abc", &expected, 128);
}

#[test]
#[cfg(blake2s)]
fn test_digest_blake2s_256() {
    use wolfssl_wolfcrypt::blake2_digest::Blake2s256;
    common::setup();
    check_digest::<Blake2s256>(
        b"abc",
        b"\x50\x8C\x5E\x8C\x32\x7C\x14\xE2\xE1\xA7\x2B\xA3\x4E\xEB\x45\x2F\x37\x45\x8B\x20\x9E\xD6\x3A\x29\x4D\x99\x9B\x4C\x86\x67\x59\x82",
        64,
    );
}

#[test]
#[cfg(blake2s)]
fn test_digest_blake2s_192() {
    use wolfssl_wolfcrypt::blake2::BLAKE2s;
    use wolfssl_wolfcrypt::blake2_digest::Blake2s192;
    common::setup();

    let mut reference = BLAKE2s::new(24).expect("Error with new()");
    reference.update(b"abc").expect("Error with update()");
    let mut expected = [0u8; 24];
    reference.finalize(&mut expected).expect("Error with finalize()");

    check_digest::<Blake2s192>(b"abc", &expected, 64);
}

#[test]
#[cfg(blake2s)]
fn test_digest_blake2s_128() {
    use wolfssl_wolfcrypt::blake2::BLAKE2s;
    use wolfssl_wolfcrypt::blake2_digest::Blake2s128;
    common::setup();

    let mut reference = BLAKE2s::new(16).expect("Error with new()");
    reference.update(b"abc").expect("Error with update()");
    let mut expected = [0u8; 16];
    reference.finalize(&mut expected).expect("Error with finalize()");

    check_digest::<Blake2s128>(b"abc", &expected, 64);
}
