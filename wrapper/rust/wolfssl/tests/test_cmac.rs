#![cfg(cmac)]

use wolfssl::wolfcrypt::cmac::CMAC;

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

    let mut cmac = CMAC::new(&key).expect("Error with new()");
    let mut generate_out = [0u8; 16];
    cmac.generate_ex(&key, &message, &mut generate_out, None, None).expect("Error with generate_ex()");
    assert_eq!(generate_out, finalize_out);
    let valid = cmac.verify_ex(&key, &message, &generate_out, None, None).expect("Error with verify_ex()");
    assert!(valid);
}
