/*
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Boston, MA 02110-1335, USA
 */

#![cfg(all(slhdsa, random))]

mod common;

use wolfssl_wolfcrypt::random::RNG;
use wolfssl_wolfcrypt::slhdsa::SlhDsa;

#[test]
fn test_parameter_constants() {
    assert_eq!(SlhDsa::SHAKE128S, 0);
    assert_eq!(SlhDsa::SHAKE128F, 1);
    assert_eq!(SlhDsa::SHAKE192S, 2);
    assert_eq!(SlhDsa::SHAKE192F, 3);
    assert_eq!(SlhDsa::SHAKE256S, 4);
    assert_eq!(SlhDsa::SHAKE256F, 5);
}

#[test]
fn test_new_ex_and_parameter_sizes() {
    common::setup();
    let mut key =
        SlhDsa::new_ex(SlhDsa::SHAKE128S, None, None).expect("Error creating key with new_ex()");
    assert_eq!(key.priv_size().expect("Error querying priv_size()"), 64);
    assert_eq!(key.pub_size().expect("Error querying pub_size()"), 32);
    assert_eq!(key.sig_size().expect("Error querying sig_size()"), 7856);

    #[cfg(slhdsa_private_size_from_param)]
    assert_eq!(SlhDsa::priv_size_from_param(SlhDsa::SHAKE128S).unwrap(), 64);
    #[cfg(slhdsa_public_size_from_param)]
    assert_eq!(SlhDsa::pub_size_from_param(SlhDsa::SHAKE128S).unwrap(), 32);
    #[cfg(slhdsa_sig_size_from_param)]
    assert_eq!(
        SlhDsa::sig_size_from_param(SlhDsa::SHAKE128S).unwrap(),
        7856
    );
}

#[test]
fn test_sign_verify_and_export() {
    common::setup();
    let rng = RNG::new().expect("Error creating RNG");
    let mut key = SlhDsa::generate(SlhDsa::SHAKE128S, &rng).expect("Error generating SLH-DSA key");

    let public_size = key.pub_size().expect("Error querying public size");
    let signature_size = key.sig_size().expect("Error querying signature size");
    assert!(public_size > 0);
    assert!(signature_size > 0);

    let mut public_key = vec![0u8; public_size];
    let public_len = key
        .export_public(&mut public_key)
        .expect("Error exporting public key");
    assert_eq!(public_len, public_size);
    assert!(public_key.iter().any(|byte| *byte != 0));

    #[cfg(all(slhdsa_import_private, slhdsa_export_private, slhdsa_check_key))]
    {
        let private_size = key.priv_size().expect("Error querying private size");
        let mut private_key = vec![0u8; private_size];
        let private_len = key
            .export_private(&mut private_key)
            .expect("Error exporting private key");
        assert_eq!(private_len, private_size);

        let mut imported = SlhDsa::new(SlhDsa::SHAKE128S).expect("Error creating import key");
        imported
            .import_private(&private_key)
            .expect("Error importing private key");
        imported.check_key().expect("Error checking imported key");
    }

    #[cfg(slhdsa_check_key)]
    key.check_key().expect("Error checking generated key");

    let message = b"SLH-DSA Rust wrapper test";
    let mut signature = vec![0u8; signature_size];
    let signature_len = key
        .sign_msg(message, &mut signature, &rng)
        .expect("Error signing message");
    assert_eq!(signature_len, signature_size);

    assert!(key
        .verify_msg(&signature, message)
        .expect("Error verifying valid signature"));

    let mut tampered_message = message.to_vec();
    tampered_message[0] ^= 1;
    assert!(!key
        .verify_msg(&signature, &tampered_message)
        .expect("Error verifying tampered message"));

    signature[0] ^= 1;
    assert!(!key
        .verify_msg(&signature, message)
        .expect("Error verifying tampered signature"));
}

#[test]
#[cfg(all(slhdsa_sign, slhdsa_verify, random))]
fn test_context_and_deterministic_signing() {
    common::setup();
    let rng = RNG::new().expect("Error creating RNG");
    let mut key = SlhDsa::generate(SlhDsa::SHAKE128S, &rng).expect("Error generating SLH-DSA key");
    let message = b"SLH-DSA context test";
    let context = b"test context";
    let sig_size = key.sig_size().expect("Error querying signature size");

    let mut contextual_signature = vec![0u8; sig_size];
    let contextual_len = key
        .sign_ctx_msg(context, message, &mut contextual_signature, &rng)
        .expect("Error signing contextual message");
    assert!(key
        .verify_ctx_msg(&contextual_signature[..contextual_len], context, message)
        .expect("Error verifying contextual message"));
    assert!(!key
        .verify_ctx_msg(
            &contextual_signature[..contextual_len],
            b"wrong context",
            message
        )
        .expect("Error verifying wrong context"));

    let mut deterministic_one = vec![0u8; sig_size];
    let mut deterministic_two = vec![0u8; sig_size];
    let first_len = key
        .sign_msg_deterministic(message, &mut deterministic_one)
        .expect("Error creating deterministic signature");
    let second_len = key
        .sign_msg_deterministic(message, &mut deterministic_two)
        .expect("Error creating second deterministic signature");
    assert_eq!(first_len, second_len);
    assert_eq!(deterministic_one, deterministic_two);
}

fn sign_verify_parameter(param: i32, name: &str) {
    let rng = RNG::new().expect("Error creating RNG");
    let mut key =
        SlhDsa::generate(param, &rng).unwrap_or_else(|_| panic!("Error generating {} key", name));
    let message = format!("SLH-DSA {} parameter test", name);
    let sig_size = key
        .sig_size()
        .unwrap_or_else(|_| panic!("Error querying {} signature size", name));
    let mut signature = vec![0u8; sig_size];
    let written = key
        .sign_msg(message.as_bytes(), &mut signature, &rng)
        .unwrap_or_else(|_| panic!("Error signing with {}", name));
    assert_eq!(written, sig_size, "{} signature size mismatch", name);
    assert!(
        key.verify_msg(&signature, message.as_bytes())
            .unwrap_or_else(|_| panic!("Error verifying with {}", name)),
        "{} signature should verify",
        name
    );
}

#[test]
#[cfg(all(slhdsa_make_key, slhdsa_sign, slhdsa_verify, random))]
fn test_all_shake_parameter_sets() {
    common::setup();
    sign_verify_parameter(SlhDsa::SHAKE128S, "SHAKE128s");
    sign_verify_parameter(SlhDsa::SHAKE128F, "SHAKE128f");
    sign_verify_parameter(SlhDsa::SHAKE192S, "SHAKE192s");
    sign_verify_parameter(SlhDsa::SHAKE192F, "SHAKE192f");
    sign_verify_parameter(SlhDsa::SHAKE256S, "SHAKE256s");
    sign_verify_parameter(SlhDsa::SHAKE256F, "SHAKE256f");
}

#[test]
#[cfg(all(slhdsa_sha2, slhdsa_make_key, slhdsa_sign, slhdsa_verify, random))]
fn test_all_sha2_parameter_sets() {
    common::setup();
    sign_verify_parameter(SlhDsa::SHA2_128S, "SHA2-128s");
    sign_verify_parameter(SlhDsa::SHA2_128F, "SHA2-128f");
    sign_verify_parameter(SlhDsa::SHA2_192S, "SHA2-192s");
    sign_verify_parameter(SlhDsa::SHA2_192F, "SHA2-192f");
    sign_verify_parameter(SlhDsa::SHA2_256S, "SHA2-256s");
    sign_verify_parameter(SlhDsa::SHA2_256F, "SHA2-256f");
}
