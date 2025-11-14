#![cfg(ecc)]

use std::fs;
use wolfssl::wolfcrypt::ecc::*;
use wolfssl::wolfcrypt::random::RNG;

#[test]
fn test_ecc_generate() {
    let mut rng = RNG::new().expect("Failed to create RNG");
    let mut ecc = ECC::generate(32, &mut rng, None, None).expect("Error with generate()");
    ecc.check().expect("Error with check()");
}

#[test]
fn test_ecc_generate_ex() {
    let mut rng = RNG::new().expect("Failed to create RNG");
    let curve_id = ECC::SECP256R1;
    let curve_size = ECC::get_curve_size_from_id(curve_id).expect("Error with get_curve_size_from_id()");
    assert_eq!(curve_size, 32);
    let mut ecc = ECC::generate_ex(curve_size, &mut rng, curve_id, None, None).expect("Error with generate_ex()");
    ecc.check().expect("Error with check()");
}

#[test]
#[cfg(all(ecc_import, ecc_export))]
fn test_ecc_import_x963() {
    let mut rng = RNG::new().expect("Failed to create RNG");
    let curve_id = ECC::SECP256R1;
    let curve_size = ECC::get_curve_size_from_id(curve_id).expect("Error with get_curve_size_from_id()");
    assert_eq!(curve_size, 32);
    let mut ecc = ECC::generate_ex(curve_size, &mut rng, curve_id, None, None).expect("Error with generate_ex()");
    ecc.check().expect("Error with check()");

    let mut x963 = [0u8; 128];
    let x963_size = ecc.export_x963(&mut x963).expect("Error with export_x963()");
    let x963 = &x963[0..x963_size];
    let mut ecc = ECC::import_x963_ex(x963, ECC::SECP256R1, None, None).expect("Error with import_x963_ex");
    ecc.check().expect("Error with check()");
}

#[test]
fn test_ecc_generate_ex2() {
    let mut rng = RNG::new().expect("Failed to create RNG");
    let curve_id = ECC::SECP256R1;
    let curve_size = ECC::get_curve_size_from_id(curve_id).expect("Error with get_curve_size_from_id()");
    assert_eq!(curve_size, 32);
    let mut ecc = ECC::generate_ex2(curve_size, &mut rng, curve_id, ECC::FLAG_COFACTOR, None, None).expect("Error with generate_ex2()");
    ecc.check().expect("Error with check()");
}

fn bytes_to_asciiz_hex_string(bytes: &[u8]) -> String {
    let mut hex_string = String::with_capacity(bytes.len() * 2 + 1);
    for byte in bytes {
        hex_string.push_str(&format!("{:02X}", byte));
    }
    hex_string.push('\0');
    hex_string
}

#[test]
#[cfg(all(ecc_import, ecc_export, ecc_sign, ecc_verify))]
fn test_ecc_import_export_sign_verify() {
    let mut rng = RNG::new().expect("Failed to create RNG");
    let key_path = "../../../certs/ecc-client-key.der";
    let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    let mut ecc = ECC::import_der(&der, None, None).expect("Error with import_der()");
    let hash = [0x42u8; 32];
    let mut signature = [0u8; 128];
    let signature_length = ecc.sign_hash(&hash, &mut signature, &mut rng).expect("Error with sign_hash()");
    assert!(signature_length > 0 && signature_length <= signature.len());

    let signature = &mut signature[0..signature_length];
    let key_path = "../../../certs/ecc-client-keyPub.der";
    let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    let mut ecc = ECC::import_public_der(&der, None, None).expect("Error with import_public_der()");
    let valid = ecc.verify_hash(&signature, &hash).expect("Error with verify_hash()");
    assert_eq!(valid, true);

    let mut x963 = [0u8; 128];
    let x963_size = ecc.export_x963(&mut x963).expect("Error with export_x963()");
    let x963 = &x963[0..x963_size];
    let mut ecc = ECC::import_x963(x963, None, None).expect("Error with import_x963");
    let valid = ecc.verify_hash(&signature, &hash).expect("Error with verify_hash()");
    assert_eq!(valid, true);

    #[cfg(ecc_comp_key)]
    {
        let mut x963 = [0u8; 128];
        let x963_size = ecc.export_x963_compressed(&mut x963).expect("Error with export_x963_compressed()");
        let x963 = &x963[0..x963_size];
        let mut ecc = ECC::import_x963(x963, None, None).expect("Error with import_x963");
        let valid = ecc.verify_hash(&signature, &hash).expect("Error with verify_hash()");
        assert_eq!(valid, true);
    }

    let mut r = [0u8; 32];
    let mut r_size = 0u32;
    let mut s = [0u8; 32];
    let mut s_size = 0u32;
    ECC::sig_to_rs(signature, &mut r, &mut r_size, &mut s, &mut s_size).expect("Error with sig_to_rs()");
    assert!(r_size > 0 && r_size <= 32);
    assert!(s_size > 0 && s_size <= 32);
    let r = &r[0..r_size as usize];
    let s = &s[0..s_size as usize];
    let mut sig_out = [0u8; 128];
    let sig_out_size = ECC::rs_bin_to_sig(r, s, &mut sig_out).expect("Error with rs_bin_to_sig()");
    assert_eq!(*signature, *&sig_out[0..sig_out_size]);

    let r_hex_string = bytes_to_asciiz_hex_string(r);
    let s_hex_string = bytes_to_asciiz_hex_string(s);
    let mut sig_out = [0u8; 128];
    let sig_out_size = ECC::rs_hex_to_sig(&r_hex_string[0..r_hex_string.len()].as_bytes(), &s_hex_string[0..s_hex_string.len()].as_bytes(), &mut sig_out).expect("Error with rs_hex_to_sig()");
    assert_eq!(*signature, *&sig_out[0..sig_out_size]);

    signature[signature.len() - 2] = 0xDEu8;
    signature[signature.len() - 1] = 0xADu8;
    let valid = ecc.verify_hash(&signature, &hash).expect("Error with verify_hash()");
    assert_eq!(valid, false);

    ecc.set_rng(&mut rng).expect("Error with set_rng()");
}

#[test]
#[cfg(ecc_dh)]
fn test_ecc_shared_secret() {
    let mut rng = RNG::new().expect("Failed to create RNG");
    let mut ecc0 = ECC::generate(32, &mut rng, None, None).expect("Error with generate()");
    let mut ecc1 = ECC::generate(32, &mut rng, None, None).expect("Error with generate()");
    let mut ss0 = [0u8; 128];
    let mut ss1 = [0u8; 128];
    ecc0.set_rng(&mut rng).expect("Error with set_rng()");
    ecc1.set_rng(&mut rng).expect("Error with set_rng()");
    let ss0_size = ecc0.shared_secret(&mut ecc1, &mut ss0).expect("Error with shared_secret()");
    let ss1_size = ecc1.shared_secret(&mut ecc0, &mut ss1).expect("Error with shared_secret()");
    assert_eq!(ss0_size, ss1_size);
    let ss0 = &ss0[0..ss0_size];
    let ss1 = &ss1[0..ss1_size];
    assert_eq!(*ss0, *ss1);

    let mut ss0 = [0u8; 128];
    let ecc_point = ecc1.make_pub_to_point(None, None).expect("Error with make_pub_to_point()");
    let ss0_size = ecc0.shared_secret_ex(&ecc_point, &mut ss0).expect("Error with shared_secret_ex()");
    let ss0 = &ss0[0..ss0_size];
    assert_eq!(*ss0, *ss1);
}

#[test]
#[cfg(ecc_export)]
fn test_ecc_export() {
    let mut rng = RNG::new().expect("Failed to create RNG");
    let mut ecc = ECC::generate(32, &mut rng, None, None).expect("Error with generate()");
    let mut qx = [0u8; 32];
    let mut qx_len = 0u32;
    let mut qy = [0u8; 32];
    let mut qy_len = 0u32;
    let mut d = [0u8; 32];
    let mut d_len = 0u32;
    ecc.export(&mut qx, &mut qx_len, &mut qy, &mut qy_len, &mut d, &mut d_len).expect("Error with export()");
}

#[test]
#[cfg(ecc_export)]
fn test_ecc_export_ex() {
    let mut rng = RNG::new().expect("Failed to create RNG");
    let mut ecc = ECC::generate(32, &mut rng, None, None).expect("Error with generate()");
    let mut qx = [0u8; 32];
    let mut qx_len = 0u32;
    let mut qy = [0u8; 32];
    let mut qy_len = 0u32;
    let mut d = [0u8; 32];
    let mut d_len = 0u32;
    ecc.export_ex(&mut qx, &mut qx_len, &mut qy, &mut qy_len, &mut d, &mut d_len, false).expect("Error with export_ex()");
}

#[test]
#[cfg(all(ecc_import, ecc_export, ecc_sign, ecc_verify))]
fn test_ecc_import_export_private() {
    let mut rng = RNG::new().expect("Failed to create RNG");
    let mut ecc = ECC::generate(32, &mut rng, None, None).expect("Error with generate()");
    let hash = [0x42u8; 32];
    let mut signature = [0u8; 128];
    let signature_length = ecc.sign_hash(&hash, &mut signature, &mut rng).expect("Error with sign_hash()");
    let signature = &signature[0..signature_length];

    let mut d = [0u8; 32];
    let d_size = ecc.export_private(&mut d).expect("Error with export_private()");
    assert_eq!(d_size, 32);
    let mut x963 = [0u8; 128];
    let x963_size = ecc.export_x963(&mut x963).expect("Error with export_x963()");
    let x963 = &x963[0..x963_size];

    let mut ecc2 = ECC::import_private_key(&d, x963, None, None).expect("Error with import_private_key()");
    let valid = ecc2.verify_hash(&signature, &hash).expect("Error with verify_hash()");
    assert_eq!(valid, true);
}

#[test]
#[cfg(all(ecc_import, ecc_export, ecc_sign, ecc_verify))]
fn test_ecc_import_export_private_ex() {
    let mut rng = RNG::new().expect("Failed to create RNG");
    let curve_id = ECC::SECP256R1;
    let curve_size = ECC::get_curve_size_from_id(curve_id).expect("Error with get_curve_size_from_id()");
    let mut ecc = ECC::generate_ex(curve_size, &mut rng, curve_id, None, None).expect("Error with generate_ex()");
    let hash = [0x42u8; 32];
    let mut signature = [0u8; 128];
    let signature_length = ecc.sign_hash(&hash, &mut signature, &mut rng).expect("Error with sign_hash()");
    let signature = &signature[0..signature_length];

    let mut d = [0u8; 32];
    let d_size = ecc.export_private(&mut d).expect("Error with export_private()");
    assert_eq!(d_size, 32);
    let mut x963 = [0u8; 128];
    let x963_size = ecc.export_x963(&mut x963).expect("Error with export_x963()");
    let x963 = &x963[0..x963_size];

    let mut ecc2 = ECC::import_private_key_ex(&d, x963, curve_id, None, None).expect("Error with import_private_key_ex()");
    let valid = ecc2.verify_hash(&signature, &hash).expect("Error with verify_hash()");
    assert_eq!(valid, true);
}

#[test]
#[cfg(ecc_export)]
fn test_ecc_export_public() {
    let mut rng = RNG::new().expect("Failed to create RNG");
    let mut ecc = ECC::generate(32, &mut rng, None, None).expect("Error with generate()");
    let mut qx = [0u8; 32];
    let mut qx_len = 0u32;
    let mut qy = [0u8; 32];
    let mut qy_len = 0u32;
    ecc.export_public(&mut qx, &mut qx_len, &mut qy, &mut qy_len).expect("Error with export_public()");
}

#[test]
#[cfg(all(ecc_import, ecc_export, ecc_sign, ecc_verify))]
fn test_ecc_import_unsigned() {
    let mut rng = RNG::new().expect("Failed to create RNG");
    let curve_id = ECC::SECP256R1;
    let curve_size = ECC::get_curve_size_from_id(curve_id).expect("Error with get_curve_size_from_id()");
    let mut ecc = ECC::generate_ex(curve_size, &mut rng, curve_id, None, None).expect("Error with generate()");
    let mut qx = [0u8; 32];
    let mut qx_len = 0u32;
    let mut qy = [0u8; 32];
    let mut qy_len = 0u32;
    let mut d = [0u8; 32];
    let mut d_len = 0u32;
    ecc.export_ex(&mut qx, &mut qx_len, &mut qy, &mut qy_len, &mut d, &mut d_len, false).expect("Error with export_ex()");

    let mut ecc2 = ECC::import_unsigned(&qx, &qy, &d, curve_id, None, None).expect("Error with import_unsigned()");

    let hash = [0x42u8; 32];
    let mut signature = [0u8; 128];
    let signature_length = ecc.sign_hash(&hash, &mut signature, &mut rng).expect("Error with sign_hash()");
    let signature = &signature[0..signature_length];
    let valid = ecc2.verify_hash(signature, &hash).expect("Error with verify_hash()");
    assert_eq!(valid, true);
}

#[test]
fn test_ecc_make_pub() {
    let mut rng = RNG::new().expect("Failed to create RNG");
    let key_path = "../../../certs/ecc-client-key.der";
    let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    let mut ecc = ECC::import_der(&der, None, None).expect("Error with import_der()");
    ecc.make_pub(Some(&mut rng)).expect("Error with make_pub()");
    ecc.make_pub(None).expect("Error with make_pub()");
    ecc.make_pub_to_point(Some(&mut rng), None).expect("Error with make_pub_to_point()");
    ecc.make_pub_to_point(None, None).expect("Error with make_pub_to_point()");
}

#[test]
#[cfg(ecc_export)]
fn test_ecc_point() {
    let mut rng = RNG::new().expect("Failed to create RNG");
    let curve_id = ECC::SECP256R1;
    let curve_size = ECC::get_curve_size_from_id(curve_id).expect("Error with get_curve_size_from_id()");
    let mut ecc = ECC::generate_ex(curve_size, &mut rng, curve_id, None, None).expect("Error with generate()");
    let mut ecc_point = ecc.make_pub_to_point(Some(&mut rng), None).expect("Error with make_pub_to_point()");
    let mut der = [0u8; 128];
    let size = ecc_point.export_der(&mut der, curve_id).expect("Error with export_der()");
    assert!(size > 0 && size <= der.len());
    ecc_point.forcezero();
}

#[test]
#[cfg(all(ecc_import, ecc_export))]
fn test_ecc_point_import() {
    let mut rng = RNG::new().expect("Failed to create RNG");
    let curve_id = ECC::SECP256R1;
    let curve_size = ECC::get_curve_size_from_id(curve_id).expect("Error with get_curve_size_from_id()");
    let mut ecc = ECC::generate_ex(curve_size, &mut rng, curve_id, None, None).expect("Error with generate()");
    let mut ecc_point = ecc.make_pub_to_point(Some(&mut rng), None).expect("Error with make_pub_to_point()");
    let mut der = [0u8; 128];
    let size = ecc_point.export_der(&mut der, curve_id).expect("Error with export_der()");
    assert!(size > 0 && size <= der.len());
    ECCPoint::import_der(&der[0..size], curve_id, None).expect("Error with import_der()");
    ecc_point.forcezero();
}

#[test]
#[cfg(all(ecc_import, ecc_export, ecc_comp_key))]
fn test_ecc_point_import_compressed() {
    let mut rng = RNG::new().expect("Failed to create RNG");
    let curve_id = ECC::SECP256R1;
    let curve_size = ECC::get_curve_size_from_id(curve_id).expect("Error with get_curve_size_from_id()");
    let mut ecc = ECC::generate_ex(curve_size, &mut rng, curve_id, None, None).expect("Error with generate()");
    let mut ecc_point = ecc.make_pub_to_point(Some(&mut rng), None).expect("Error with make_pub_to_point()");
    let mut der = [0u8; 128];
    let size = ecc_point.export_der_compressed(&mut der, curve_id).expect("Error with export_der_compressed()");
    ECCPoint::import_der_ex(&der[0..size], curve_id, 1, None).expect("Error with import_der_ex()");
    ecc_point.forcezero();
}

#[test]
#[cfg(ecc_import)]
fn test_ecc_import() {
    let qx = b"7a4e287890a1a47ad3457e52f2f76a83ce46cbc947616d0cbaa82323818a793d\0";
    let qy = b"eec4084f5b29ebf29c44cce3b3059610922f8b30ea6e8811742ac7238fe87308\0";
    let d  = b"8c14b793cb19137e323a6d2e2a870bca2e7a493ec1153b3a95feb8a4873f8d08\0";
    ECC::import_raw(qx, qy, d, b"SECP256R1\0", None, None).expect("Error with import_raw()");
    ECC::import_raw_ex(qx, qy, d, ECC::SECP256R1, None, None).expect("Error with import_raw_ex()");
}
