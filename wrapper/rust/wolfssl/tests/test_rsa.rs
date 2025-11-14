#![cfg(rsa)]

use std::fs;
use wolfssl::wolfcrypt::random::RNG;
use wolfssl::wolfcrypt::rsa::*;

#[test]
#[cfg(rsa_keygen)]
fn test_rsa_generate() {
    let mut rng = RNG::new().expect("Error creating RNG");
    let mut rsa = RSA::generate(2048, 65537, &mut rng).expect("Error with generate()");
    rsa.check().expect("Error with check()");

    let encrypt_size = rsa.get_encrypt_size().expect("Error with get_encrypt_size()");
    assert_eq!(encrypt_size, 256);

    let mut e: [u8; 256] = [0; 256];
    let mut e_size: u32 = 0;
    let mut n: [u8; 256] = [0; 256];
    let mut n_size: u32 = 0;
    let mut d: [u8; 256] = [0; 256];
    let mut d_size: u32 = 0;
    let mut p: [u8; 256] = [0; 256];
    let mut p_size: u32 = 0;
    let mut q: [u8; 256] = [0; 256];
    let mut q_size: u32 = 0;
    rsa.export_key(&mut e, &mut e_size, &mut n, &mut n_size,
        &mut d, &mut d_size, &mut p, &mut p_size, &mut q, &mut q_size).expect("Error with export_key()");
    assert_ne!(e, [0; 256]);
    assert!(e_size > 0);
    assert_ne!(n, [0; 256]);
    assert!(n_size > 0);
    assert_ne!(d, [0; 256]);
    assert!(d_size > 0);
    assert_ne!(p, [0; 256]);
    assert!(p_size > 0);
    assert_ne!(q, [0; 256]);
    assert!(q_size > 0);

    let mut e: [u8; 256] = [0; 256];
    let mut e_size: u32 = 0;
    let mut n: [u8; 256] = [0; 256];
    let mut n_size: u32 = 0;
    rsa.export_public_key(&mut e, &mut e_size, &mut n, &mut n_size).expect("Error with export_public_key()");
    assert_ne!(e, [0; 256]);
    assert!(e_size > 0);
    assert_ne!(n, [0; 256]);
    assert!(n_size > 0);
}

#[test]
fn test_rsa_encrypt_decrypt() {
    let mut rng = RNG::new().expect("Error creating RNG");
    let key_path = "../../../certs/client-keyPub.der";
    let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    let mut rsa = RSA::new_public_from_der(&der).expect("Error with new_public_from_der()");
    rsa.set_rng(&mut rng).expect("Error with set_rng()");
    let plain: &[u8] = b"Test message";
    let mut enc: [u8; 512] = [0; 512];
    let enc_len = rsa.public_encrypt(plain, &mut enc, &mut rng).expect("Error with public_encrypt()");
    assert!(enc_len > 0 && enc_len <= 512);

    let key_path = "../../../certs/client-key.der";
    let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    let mut rsa = RSA::new_from_der(&der).expect("Error with new_from_der()");
    rsa.set_rng(&mut rng).expect("Error with set_rng()");
    let mut plain_out: [u8; 512] = [0; 512];
    let dec_len = rsa.private_decrypt(&enc[0..enc_len], &mut plain_out).expect("Error with private_decrypt()");
    assert!(dec_len as usize == plain.len());
    assert_eq!(plain_out[0..dec_len], *plain);
}

#[test]
#[cfg(sha256)]
fn test_rsa_pss() {
    let mut rng = RNG::new().expect("Error creating RNG");

    let key_path = "../../../certs/client-key.der";
    let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    let mut rsa = RSA::new_from_der(&der).expect("Error with new_from_der()");
    let msg: &[u8] = b"This is the string to be signed!";
    let mut signature: [u8; 512] = [0; 512];
    let sig_len = rsa.pss_sign(msg, &mut signature, RSA::HASH_TYPE_SHA256, RSA::MGF1SHA256, &mut rng).expect("Error with pss_sign()");
    assert!(sig_len > 0 && sig_len <= 512);

    let key_path = "../../../certs/client-keyPub.der";
    let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    let mut rsa = RSA::new_public_from_der(&der).expect("Error with new_public_from_der()");
    rsa.set_rng(&mut rng).expect("Error with set_rng()");
    let signature = &signature[0..sig_len];
    let mut verify_out: [u8; 512] = [0; 512];
    let verify_out_size = rsa.pss_verify(signature, &mut verify_out, RSA::HASH_TYPE_SHA256, RSA::MGF1SHA256).expect("Error with pss_verify()");
    let verify_out = &verify_out[0..verify_out_size];
    rsa.pss_check_padding(msg, verify_out, RSA::HASH_TYPE_SHA256).expect("Error with pss_check_padding()");

    let mut verify_out: [u8; 512] = [0; 512];
    rsa.pss_verify_check(signature, &mut verify_out, msg, RSA::HASH_TYPE_SHA256, RSA::MGF1SHA256).expect("Error with pss_verify_check()");
}

#[test]
#[cfg(rsa_direct)]
fn test_rsa_direct() {
    let mut rng = RNG::new().expect("Error creating RNG");

    let key_path = "../../../certs/client-key.der";
    let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    let mut rsa = RSA::new_from_der(&der).expect("Error with new_from_der()");
    let msg = b"A rsa_direct() test input string";
    let mut plain = [0u8; 256];
    plain[..msg.len()].copy_from_slice(msg);
    let mut enc = [0u8; 256];
    let enc_len = rsa.rsa_direct(&plain, &mut enc, RSA::PRIVATE_ENCRYPT, &mut rng).expect("Error with rsa_direct()");
    assert_eq!(enc_len, 256);
    let mut plain_out = [0u8; 256];
    let dec_len = rsa.rsa_direct(&enc, &mut plain_out, RSA::PUBLIC_DECRYPT, &mut rng).expect("Error with rsa_direct()");
    assert_eq!(dec_len, 256);
    assert_eq!(plain_out, plain);
}

#[test]
fn test_rsa_ssl() {
    let mut rng = RNG::new().expect("Error creating RNG");

    let key_path = "../../../certs/client-key.der";
    let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    let mut rsa = RSA::new_from_der(&der).expect("Error with new_from_der()");
    let msg: &[u8] = b"This is the string to be signed!";
    let mut signature: [u8; 512] = [0; 512];
    let sig_len = rsa.ssl_sign(msg, &mut signature, &mut rng).expect("Error with ssl_sign()");
    assert!(sig_len > 0 && sig_len <= 512);

    let key_path = "../../../certs/client-keyPub.der";
    let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    let mut rsa = RSA::new_public_from_der(&der).expect("Error with new_public_from_der()");
    rsa.set_rng(&mut rng).expect("Error with set_rng()");
    let signature = &signature[0..sig_len];
    let mut verify_out: [u8; 512] = [0; 512];
    let verify_out_size = rsa.ssl_verify(signature, &mut verify_out).expect("Error with ssl_verify()");
    assert!(verify_out_size > 0 && verify_out_size <= 512);
}
