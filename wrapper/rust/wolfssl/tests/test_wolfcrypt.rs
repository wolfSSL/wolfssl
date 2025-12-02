use wolfssl::wolfcrypt::*;

#[test]
fn test_wolfcrypt_init() {
    wolfcrypt_init().expect("Error with wolfcrypt_init()");
}

#[test]
fn test_wolfcrypt_cleanup() {
    wolfcrypt_cleanup().expect("Error with wolfcrypt_cleanup()");
}
