#![cfg(any(feature = "digest", feature = "mac"))]

/*
 * The infallible RustCrypto `Update` implementations split an input slice
 * longer than u32::MAX into chunks before handing it to wolfCrypt, and
 * u32::MAX is not a multiple of any algorithm's block size. The chunk
 * boundary is therefore unaligned in general.
 *
 * A chunk of that size cannot be allocated in a test, so these tests check
 * the property the chunking relies on instead: that splitting an input at
 * an arbitrary offset produces the same result as a single call. Every
 * offset of a multi-block input is tried, which covers unaligned splits,
 * splits exactly on a block boundary, and empty leading/trailing pieces.
 */

/* 200 bytes crosses the 16-byte (CMAC), 64-byte (SHA-256, BLAKE2s) and
 * 128-byte (SHA-512, BLAKE2b) block sizes several times. */
const INPUT_LEN: usize = 200;

fn input() -> Vec<u8> {
    (0..INPUT_LEN).map(|i| (i * 7 + 1) as u8).collect()
}

/* Check every split offset of `data` against the single-call result. */
macro_rules! check_digest_splits {
    ($ty:ty, $name:expr) => {{
        use digest::Digest;

        let data = input();
        let one_shot = <$ty as Digest>::digest(&data);

        for split in 0..=data.len() {
            let mut hasher = <$ty as Digest>::new();
            Digest::update(&mut hasher, &data[..split]);
            Digest::update(&mut hasher, &data[split..]);
            assert_eq!(
                hasher.finalize().as_slice(),
                one_shot.as_slice(),
                "{} differs when the input is split at offset {}",
                $name,
                split
            );
        }
    }};
}

macro_rules! check_mac_splits {
    ($ty:ty, $key:expr, $name:expr) => {{
        use digest::{KeyInit, Mac};

        let data = input();
        let one_shot = <$ty as KeyInit>::new_from_slice($key)
            .expect("MAC init failed")
            .chain_update(&data)
            .finalize()
            .into_bytes();

        for split in 0..=data.len() {
            let mut mac = <$ty as KeyInit>::new_from_slice($key)
                .expect("MAC init failed");
            Mac::update(&mut mac, &data[..split]);
            Mac::update(&mut mac, &data[split..]);
            assert_eq!(
                mac.finalize().into_bytes().as_slice(),
                one_shot.as_slice(),
                "{} differs when the input is split at offset {}",
                $name,
                split
            );
        }
    }};
}

#[test]
#[cfg(all(sha, feature = "digest"))]
fn test_sha_update_splits() {
    check_digest_splits!(wolfssl_wolfcrypt::sha::SHA, "SHA-1");
}

#[test]
#[cfg(all(sha256, feature = "digest"))]
fn test_sha256_update_splits() {
    check_digest_splits!(wolfssl_wolfcrypt::sha::SHA256, "SHA-256");
}

#[test]
#[cfg(all(sha512, feature = "digest"))]
fn test_sha512_update_splits() {
    check_digest_splits!(wolfssl_wolfcrypt::sha::SHA512, "SHA-512");
}

#[test]
#[cfg(all(sha3_256, feature = "digest"))]
fn test_sha3_256_update_splits() {
    check_digest_splits!(wolfssl_wolfcrypt::sha::SHA3_256, "SHA3-256");
}

#[test]
#[cfg(all(blake2b, feature = "digest"))]
fn test_blake2b_update_splits() {
    check_digest_splits!(
        wolfssl_wolfcrypt::blake2_digest::Blake2b512, "BLAKE2b-512");
}

#[test]
#[cfg(all(blake2s, feature = "digest"))]
fn test_blake2s_update_splits() {
    check_digest_splits!(
        wolfssl_wolfcrypt::blake2_digest::Blake2s256, "BLAKE2s-256");
}

#[test]
#[cfg(all(hmac, sha256, feature = "mac"))]
fn test_hmac_sha256_update_splits() {
    check_mac_splits!(
        wolfssl_wolfcrypt::hmac_mac::HmacSha256, &[0x42u8; 32],
        "HMAC-SHA-256");
}

#[test]
#[cfg(all(blake2b, feature = "mac"))]
fn test_blake2b_mac_update_splits() {
    check_mac_splits!(
        wolfssl_wolfcrypt::blake2_mac::Blake2bMac512, &[0x42u8; 64],
        "BLAKE2b-512 MAC");
}

#[test]
#[cfg(all(blake2s, feature = "mac"))]
fn test_blake2s_mac_update_splits() {
    check_mac_splits!(
        wolfssl_wolfcrypt::blake2_mac::Blake2sMac256, &[0x42u8; 32],
        "BLAKE2s-256 MAC");
}

#[test]
#[cfg(all(cmac, feature = "mac"))]
fn test_cmac_aes128_update_splits() {
    check_mac_splits!(
        wolfssl_wolfcrypt::cmac_mac::CmacAes128, &[0x42u8; 16],
        "AES-128-CMAC");
}
