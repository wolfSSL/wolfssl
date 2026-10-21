#![cfg(fips)]

use std::thread;
use wolfssl_wolfcrypt::fips::{self, PrivateKeyRead};
use wolfssl_wolfcrypt::sys;

fn read_enable_count() -> i32 {
    unsafe { sys::wolfCrypt_GetPrivateKeyReadEnable_fips(sys::wc_KeyType_WC_KEYTYPE_ALL) }
}

#[test]
fn test_private_key_read_guard_counts() {
    // Other tests may have enabled reads on this thread already.
    let before = read_enable_count();
    {
        let _outer = PrivateKeyRead::enable().expect("Error with PrivateKeyRead::enable()");
        assert_eq!(read_enable_count(), before + 1);
        {
            let _inner = PrivateKeyRead::enable().expect("Error with PrivateKeyRead::enable()");
            assert_eq!(read_enable_count(), before + 2);
        }
        assert_eq!(read_enable_count(), before + 1);
    }
    assert_eq!(read_enable_count(), before);
}

#[cfg(hkdf)]
#[test]
fn test_private_key_read_guard_unlocks_hkdf() {
    use wolfssl_wolfcrypt::hkdf::hkdf_extract;
    use wolfssl_wolfcrypt::hmac::HMAC;
    use wolfssl_wolfcrypt::sha::SHA256;

    // A new thread starts with private key reads disabled.
    thread::spawn(|| {
        let ikm = b"MyPassword0";
        let salt = b"12345678ABCDEFGH";
        let mut out = [0u8; SHA256::DIGEST_SIZE];
        let extract = |out: &mut [u8]| hkdf_extract(HMAC::TYPE_SHA256, Some(salt), ikm, out);

        assert_eq!(extract(&mut out), Err(sys::wolfCrypt_ErrorCodes_FIPS_PRIVATE_KEY_LOCKED_E));
        {
            let _read = PrivateKeyRead::enable().expect("Error with PrivateKeyRead::enable()");
            extract(&mut out).expect("Error with hkdf_extract()");
        }
        assert_eq!(extract(&mut out), Err(sys::wolfCrypt_ErrorCodes_FIPS_PRIVATE_KEY_LOCKED_E));
    })
    .join()
    .unwrap();
}

#[test]
fn test_run_all_self_tests() {
    let handles: Vec<_> = (0..8).map(|_| thread::spawn(fips::run_all_self_tests)).collect();
    for handle in handles {
        assert_eq!(handle.join().unwrap(), Ok(()));
    }
    assert_eq!(fips::run_all_self_tests(), Ok(()));
}
