#![cfg(cmac)]

use wolfssl_wolfcrypt::cmac::CMAC;

#[test]
#[cfg(aes)]
fn test_cmac() {
    let key = [
        0x2bu8, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    ];
    let message = [
        0x6bu8, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    ];
    let expected_cmac = [
        0x07u8, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
        0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c
    ];
    let incorrect_cmac = [
        0x06u8, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
        0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c
    ];
    let mut cmac = CMAC::new(&key).expect("Error with new()");
    cmac.update(&message).expect("Error with update()");
    let mut finalize_out = [0u8; 16];
    cmac.finalize(&mut finalize_out).expect("Error with finalize()");
    assert_eq!(finalize_out, expected_cmac);

    let mut generate_out = [0u8; 16];
    CMAC::generate(&key, &message, &mut generate_out).expect("Error with generate()");
    assert_eq!(generate_out, finalize_out);
    let valid = CMAC::verify(&key, &message, &generate_out).expect("Error with verify()");
    assert!(valid);
    let valid = CMAC::verify(&key, &message, &incorrect_cmac).expect("Error with verify()");
    assert!(!valid);

    let cmac = CMAC::new_ex(&key, None, None).expect("Error with new_ex()");
    let mut generate_out = [0u8; 16];
    cmac.update_and_finalize(&message, &mut generate_out).expect("Error with update_and_finalize()");
    assert_eq!(generate_out, expected_cmac);

    let cmac = CMAC::new_ex(&key, None, None).expect("Error with new_ex()");
    let valid = cmac.update_and_verify(&message, &expected_cmac).expect("Error with update_and_verify()");
    assert!(valid);
    let cmac = CMAC::new_ex(&key, None, None).expect("Error with new_ex()");
    let valid = cmac.update_and_verify(&message, &incorrect_cmac).expect("Error with update_and_verify()");
    assert!(!valid);

    /* Streamed input followed by a verify with no additional data. */
    let mut cmac = CMAC::new(&key).expect("Error with new()");
    cmac.update(&message[..5]).expect("Error with update()");
    cmac.update(&message[5..]).expect("Error with update()");
    let valid = cmac.update_and_verify(&[], &expected_cmac).expect("Error with update_and_verify()");
    assert!(valid);

    /* Truncated tag. */
    let cmac = CMAC::new(&key).expect("Error with new()");
    let valid = cmac.update_and_verify(&message, &expected_cmac[..8]).expect("Error with update_and_verify()");
    assert!(valid);

    /* Tag longer than the maximum CMAC size. */
    let cmac = CMAC::new(&key).expect("Error with new()");
    assert!(cmac.update_and_verify(&message, &[0u8; 17]).is_err());
}
