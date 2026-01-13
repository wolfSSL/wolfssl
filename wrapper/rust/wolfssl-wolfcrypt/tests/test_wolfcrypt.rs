use wolfssl_wolfcrypt::*;

#[test]
fn test_wolfcrypt_init_and_cleanup() {
    wolfcrypt_init().expect("Error with wolfcrypt_init()");
    wolfcrypt_cleanup().expect("Error with wolfcrypt_cleanup()");
}
