#![cfg(feature = "digest")]

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

    /* Split update, via Default + Update + FixedOutputReset::finalize_reset. */
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
#[cfg(sha)]
fn test_digest_sha() {
    use wolfssl_wolfcrypt::sha::SHA;
    common::setup();
    check_digest::<SHA>(
        b"abc",
        b"\xA9\x99\x3E\x36\x47\x06\x81\x6A\xBA\x3E\x25\x71\x78\x50\xC2\x6C\x9C\xD0\xD8\x9D",
        64,
    );
}

#[test]
#[cfg(sha224)]
fn test_digest_sha224() {
    use wolfssl_wolfcrypt::sha::SHA224;
    common::setup();
    check_digest::<SHA224>(
        b"abc",
        b"\x23\x09\x7d\x22\x34\x05\xd8\x22\x86\x42\xa4\x77\xbd\xa2\x55\xb3\x2a\xad\xbc\xe4\xbd\xa0\xb3\xf7\xe3\x6c\x9d\xa7",
        64,
    );
}

#[test]
#[cfg(sha256)]
fn test_digest_sha256() {
    use wolfssl_wolfcrypt::sha::SHA256;
    common::setup();
    check_digest::<SHA256>(
        b"abc",
        b"\xBA\x78\x16\xBF\x8F\x01\xCF\xEA\x41\x41\x40\xDE\x5D\xAE\x22\x23\xB0\x03\x61\xA3\x96\x17\x7A\x9C\xB4\x10\xFF\x61\xF2\x00\x15\xAD",
        64,
    );
}

#[test]
#[cfg(sha384)]
fn test_digest_sha384() {
    use wolfssl_wolfcrypt::sha::SHA384;
    common::setup();
    check_digest::<SHA384>(
        b"abc",
        b"\xcb\x00\x75\x3f\x45\xa3\x5e\x8b\xb5\xa0\x3d\x69\x9a\xc6\x50\x07\x27\x2c\x32\xab\x0e\xde\xd1\x63\x1a\x8b\x60\x5a\x43\xff\x5b\xed\x80\x86\x07\x2b\xa1\xe7\xcc\x23\x58\xba\xec\xa1\x34\xc8\x25\xa7",
        128,
    );
}

#[test]
#[cfg(sha512)]
fn test_digest_sha512() {
    use wolfssl_wolfcrypt::sha::SHA512;
    common::setup();
    check_digest::<SHA512>(
        b"abc",
        b"\xdd\xaf\x35\xa1\x93\x61\x7a\xba\xcc\x41\x73\x49\xae\x20\x41\x31\x12\xe6\xfa\x4e\x89\xa9\x7e\xa2\x0a\x9e\xee\xe6\x4b\x55\xd3\x9a\x21\x92\x99\x2a\x27\x4f\xc1\xa8\x36\xba\x3c\x23\xa3\xfe\xeb\xbd\x45\x4d\x44\x23\x64\x3c\xe8\x0e\x2a\x9a\xc9\x4f\xa5\x4c\xa4\x9f",
        128,
    );
}

#[test]
#[cfg(sha3)]
fn test_digest_sha3_224() {
    use wolfssl_wolfcrypt::sha::SHA3_224;
    common::setup();
    check_digest::<SHA3_224>(
        b"abc",
        b"\xe6\x42\x82\x4c\x3f\x8c\xf2\x4a\xd0\x92\x34\xee\x7d\x3c\x76\x6f\xc9\xa3\xa5\x16\x8d\x0c\x94\xad\x73\xb4\x6f\xdf",
        144,
    );
}

#[test]
#[cfg(sha3)]
fn test_digest_sha3_256() {
    use wolfssl_wolfcrypt::sha::SHA3_256;
    common::setup();
    check_digest::<SHA3_256>(
        b"abc",
        b"\x3a\x98\x5d\xa7\x4f\xe2\x25\xb2\x04\x5c\x17\x2d\x6b\xd3\x90\xbd\x85\x5f\x08\x6e\x3e\x9d\x52\x5b\x46\xbf\xe2\x45\x11\x43\x15\x32",
        136,
    );
}

#[test]
#[cfg(sha3)]
fn test_digest_sha3_384() {
    use wolfssl_wolfcrypt::sha::SHA3_384;
    common::setup();
    check_digest::<SHA3_384>(
        b"abc",
        b"\xec\x01\x49\x82\x88\x51\x6f\xc9\x26\x45\x9f\x58\xe2\xc6\xad\x8d\xf9\xb4\x73\xcb\x0f\xc0\x8c\x25\x96\xda\x7c\xf0\xe4\x9b\xe4\xb2\x98\xd8\x8c\xea\x92\x7a\xc7\xf5\x39\xf1\xed\xf2\x28\x37\x6d\x25",
        104,
    );
}

#[test]
#[cfg(sha3)]
fn test_digest_sha3_512() {
    use wolfssl_wolfcrypt::sha::SHA3_512;
    common::setup();
    check_digest::<SHA3_512>(
        b"abc",
        b"\xb7\x51\x85\x0b\x1a\x57\x16\x8a\x56\x93\xcd\x92\x4b\x6b\x09\x6e\x08\xf6\x21\x82\x74\x44\xf7\x0d\x88\x4f\x5d\x02\x40\xd2\x71\x2e\x10\xe1\x16\xe9\x19\x2a\xf3\xc9\x1a\x7e\xc5\x76\x47\xe3\x93\x40\x57\x34\x0b\x4c\xf4\x08\xd5\xa5\x65\x92\xf8\x27\x4e\xec\x53\xf0",
        72,
    );
}
