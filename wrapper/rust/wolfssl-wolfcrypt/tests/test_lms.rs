/*
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#![cfg(lms)]

mod common;

use wolfssl_wolfcrypt::lms::Lms;
use wolfssl_wolfcrypt::sys;
#[cfg(all(lms_make_key, random))]
use wolfssl_wolfcrypt::random::RNG;

/// Private key NV storage for tests that require make_key / sign / reload.
///
/// The write and read callbacks use a raw pointer to this struct as the
/// context argument. Each test that needs persistent NV storage creates its
/// own instance and boxes it to keep it alive for the duration of the test.
#[cfg(lms_make_key)]
struct KeyStore {
    buf: [u8; 16384],
}

#[cfg(lms_make_key)]
unsafe extern "C" fn write_key_cb(
    priv_data: *const u8,
    priv_sz: u32,
    ctx: *mut core::ffi::c_void,
) -> i32 {
    let store = unsafe { &mut *(ctx as *mut KeyStore) };
    let priv_sz = priv_sz as usize;
    store.buf[..priv_sz]
        .copy_from_slice(unsafe { core::slice::from_raw_parts(priv_data, priv_sz) });
    sys::wc_LmsRc_WC_LMS_RC_SAVED_TO_NV_MEMORY as i32
}

#[cfg(lms_make_key)]
unsafe extern "C" fn read_key_cb(
    priv_data: *mut u8,
    priv_sz: u32,
    ctx: *mut core::ffi::c_void,
) -> i32 {
    let store = unsafe { &*(ctx as *mut KeyStore) };
    let priv_sz = priv_sz as usize;
    unsafe { core::slice::from_raw_parts_mut(priv_data, priv_sz) }
        .copy_from_slice(&store.buf[..priv_sz]);
    sys::wc_LmsRc_WC_LMS_RC_READ_TO_MEMORY as i32
}

/// Register the write and read callbacks and a context pointer on `key`.
#[cfg(lms_make_key)]
fn setup_callbacks(key: &mut Lms, ctx: *mut core::ffi::c_void) {
    key.set_write_cb(Some(write_key_cb)).expect("Error with set_write_cb()");
    key.set_read_cb(Some(read_key_cb)).expect("Error with set_read_cb()");
    // Safety: ctx points to a BoxedKeyStore that outlives all callback invocations.
    unsafe { key.set_context(ctx).expect("Error with set_context()") };
}

// ---------------------------------------------------------------------------
// Constant and construction tests (no keygen required)
// ---------------------------------------------------------------------------

/// Verify the KEY_ID_LEN constant matches the C `WC_LMS_I_LEN` value.
#[test]
fn test_key_id_len_constant() {
    assert_eq!(Lms::KEY_ID_LEN, 16);
}

/// Verify that `new()` succeeds.
#[test]
fn test_new() {
    common::setup();
    Lms::new().expect("Error with Lms::new()");
}

/// Verify that `new_ex()` accepts the optional heap and device ID parameters.
#[test]
fn test_new_ex() {
    common::setup();
    Lms::new_ex(None, None).expect("Error with Lms::new_ex()");
}

/// Verify that `set_parm()` accepts a predefined wc_LmsParm value.
#[test]
fn test_set_parm() {
    common::setup();
    let mut key = Lms::new().expect("Error with Lms::new()");
    key.set_parm(Lms::PARM_L1_H5_W8).expect("Error with set_parm()");
}

/// Verify that `set_parameters()` accepts explicit L/H/W values and that
/// `get_parameters()` returns them unchanged.
#[test]
fn test_set_get_parameters() {
    common::setup();

    for &(levels, height, winternitz) in &[(1, 5, 8), (1, 10, 4), (2, 5, 8)] {
        // Use a fresh key for each parameter set; wc_LmsKey_SetParameters does
        // not allow re-setting parameters on an already-configured key.
        let mut k = Lms::new().expect("Error with Lms::new()");
        k.set_parameters(levels, height, winternitz)
            .expect("Error with set_parameters()");
        let (l, h, w) = k.get_parameters().expect("Error with get_parameters()");
        assert_eq!(l, levels, "levels mismatch for ({},{},{})", levels, height, winternitz);
        assert_eq!(h, height, "height mismatch for ({},{},{})", levels, height, winternitz);
        assert_eq!(w, winternitz, "winternitz mismatch for ({},{},{})", levels, height, winternitz);
    }
}

/// Verify that `get_sig_len()` and `get_pub_len()` return positive values
/// after setting a predefined parameter set.
#[test]
fn test_size_queries_after_set_parm() {
    common::setup();
    for &parm in &[
        Lms::PARM_L1_H5_W8,
        Lms::PARM_L1_H5_W4,
        Lms::PARM_L1_H10_W8,
    ] {
        let mut key = Lms::new().expect("Error with Lms::new()");
        key.set_parm(parm).expect("Error with set_parm()");
        let sig_len = key.get_sig_len().expect("Error with get_sig_len()");
        let pub_len = key.get_pub_len().expect("Error with get_pub_len()");
        assert!(sig_len > 0, "sig_len must be positive for parm {}", parm);
        assert!(pub_len > 0, "pub_len must be positive for parm {}", parm);
    }
}

/// Verify that `get_sig_len()` grows with the number of levels (higher
/// level count increases signature size significantly).
#[test]
fn test_sig_len_increases_with_levels() {
    common::setup();
    let mut key1 = Lms::new().expect("Error with Lms::new()");
    key1.set_parm(Lms::PARM_L1_H5_W8).expect("Error with set_parm()");
    let sig_len_l1 = key1.get_sig_len().expect("Error with get_sig_len() L1");

    let mut key2 = Lms::new().expect("Error with Lms::new()");
    key2.set_parm(Lms::PARM_L2_H5_W8).expect("Error with set_parm()");
    let sig_len_l2 = key2.get_sig_len().expect("Error with get_sig_len() L2");

    assert!(
        sig_len_l2 > sig_len_l1,
        "L2 sig_len ({}) must exceed L1 sig_len ({})",
        sig_len_l2,
        sig_len_l1
    );
}

// ---------------------------------------------------------------------------
// Private-key-length query (needs lms_make_key for the API)
// ---------------------------------------------------------------------------

/// Verify that `get_priv_len()` returns a positive value after parameters
/// are set. No key generation is required for this query.
#[test]
#[cfg(lms_make_key)]
fn test_get_priv_len() {
    common::setup();
    let mut key = Lms::new().expect("Error with Lms::new()");
    key.set_parm(Lms::PARM_L1_H5_W8).expect("Error with set_parm()");
    let priv_len = key.get_priv_len().expect("Error with get_priv_len()");
    assert!(priv_len > 0, "priv_len must be positive");
}

// ---------------------------------------------------------------------------
// Key generation and signing tests
// ---------------------------------------------------------------------------

/// Verify that `make_key()` completes without error for the test parameter set.
#[test]
#[cfg(all(lms_make_key, random))]
fn test_make_key() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    let mut store = Box::new(KeyStore { buf: [0u8; 16384] });
    let ctx = store.as_mut() as *mut KeyStore as *mut core::ffi::c_void;

    let mut key = Lms::new().expect("Error with Lms::new()");
    key.set_parm(Lms::PARM_L1_H5_W8).expect("Error with set_parm()");
    setup_callbacks(&mut key, ctx);
    key.make_key(&mut rng).expect("Error with make_key()");

    let _ = store; // keep alive
}

/// Sign a message and verify it with the same key.
#[test]
#[cfg(all(lms_make_key, random))]
fn test_sign_verify() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    let mut store = Box::new(KeyStore { buf: [0u8; 16384] });
    let ctx = store.as_mut() as *mut KeyStore as *mut core::ffi::c_void;

    let mut key = Lms::new().expect("Error with Lms::new()");
    key.set_parm(Lms::PARM_L1_H5_W8).expect("Error with set_parm()");
    setup_callbacks(&mut key, ctx);
    key.make_key(&mut rng).expect("Error with make_key()");

    let message = b"Hello, LMS/HSS!";
    let sig_len = key.get_sig_len().expect("Error with get_sig_len()");
    let mut sig = vec![0u8; sig_len];

    let written = key.sign(message, &mut sig).expect("Error with sign()");
    assert_eq!(written, sig_len, "sign() must fill the entire signature buffer");

    key.verify(&sig, message).expect("Valid signature must verify");

    let _ = store;
}

/// Verify that a signature does not verify for a different message.
#[test]
#[cfg(all(lms_make_key, random))]
fn test_sign_tampered_message() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    let mut store = Box::new(KeyStore { buf: [0u8; 16384] });
    let ctx = store.as_mut() as *mut KeyStore as *mut core::ffi::c_void;

    let mut key = Lms::new().expect("Error with Lms::new()");
    key.set_parm(Lms::PARM_L1_H5_W8).expect("Error with set_parm()");
    setup_callbacks(&mut key, ctx);
    key.make_key(&mut rng).expect("Error with make_key()");

    let message = b"Authentic message";
    let sig_len = key.get_sig_len().expect("Error with get_sig_len()");
    let mut sig = vec![0u8; sig_len];
    key.sign(message, &mut sig).expect("Error with sign()");

    let result = key.verify(&sig, b"Tampered message");
    assert!(result.is_err(), "Signature must not verify for a different message");

    let _ = store;
}

/// Verify that a tampered signature is rejected.
#[test]
#[cfg(all(lms_make_key, random))]
fn test_sign_tampered_signature() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    let mut store = Box::new(KeyStore { buf: [0u8; 16384] });
    let ctx = store.as_mut() as *mut KeyStore as *mut core::ffi::c_void;

    let mut key = Lms::new().expect("Error with Lms::new()");
    key.set_parm(Lms::PARM_L1_H5_W8).expect("Error with set_parm()");
    setup_callbacks(&mut key, ctx);
    key.make_key(&mut rng).expect("Error with make_key()");

    let message = b"Message under test";
    let sig_len = key.get_sig_len().expect("Error with get_sig_len()");
    let mut sig = vec![0u8; sig_len];
    key.sign(message, &mut sig).expect("Error with sign()");

    // Flip a byte in the signature body.
    sig[sig_len / 2] ^= 0xFF;

    let result = key.verify(&sig, message);
    assert!(result.is_err(), "Tampered signature must be rejected");

    let _ = store;
}

/// Export the raw public key, import it into a fresh key, and verify a
/// signature produced by the original key.
#[test]
#[cfg(all(lms_make_key, random))]
fn test_export_pub_raw_import_verify() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    let mut store = Box::new(KeyStore { buf: [0u8; 16384] });
    let ctx = store.as_mut() as *mut KeyStore as *mut core::ffi::c_void;

    let mut sign_key = Lms::new().expect("Error with Lms::new()");
    sign_key.set_parm(Lms::PARM_L1_H5_W8).expect("Error with set_parm()");
    setup_callbacks(&mut sign_key, ctx);
    sign_key.make_key(&mut rng).expect("Error with make_key()");

    let pub_len = sign_key.get_pub_len().expect("Error with get_pub_len()");
    let sig_len = sign_key.get_sig_len().expect("Error with get_sig_len()");

    let mut pub_buf = vec![0u8; pub_len];
    let written = sign_key.export_pub_raw(&mut pub_buf)
        .expect("Error with export_pub_raw()");
    assert_eq!(written, pub_len, "export_pub_raw must fill the entire buffer");

    let message = b"Public key export/import test";
    let mut sig = vec![0u8; sig_len];
    sign_key.sign(message, &mut sig).expect("Error with sign()");

    // Import the raw public key into a new key and verify.
    // wc_LmsKey_ImportPubRaw requires params to be set first.
    let mut verify_key = Lms::new().expect("Error with Lms::new() for verify");
    verify_key.set_parm(Lms::PARM_L1_H5_W8).expect("Error with set_parm() for verify key");
    verify_key.import_pub_raw(&pub_buf)
        .expect("Error with import_pub_raw()");
    verify_key.verify(&sig, message)
        .expect("Signature must verify against imported public key");

    let _ = store;
}

/// Verify that `export_pub_from()` copies the public key into a destination
/// key and that signatures from the source verify against that destination.
#[test]
#[cfg(all(lms_make_key, random))]
fn test_export_pub_from() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    let mut store = Box::new(KeyStore { buf: [0u8; 16384] });
    let ctx = store.as_mut() as *mut KeyStore as *mut core::ffi::c_void;

    let mut sign_key = Lms::new().expect("Error with Lms::new()");
    sign_key.set_parm(Lms::PARM_L1_H5_W8).expect("Error with set_parm()");
    setup_callbacks(&mut sign_key, ctx);
    sign_key.make_key(&mut rng).expect("Error with make_key()");

    let message = b"export_pub_from test message";
    let sig_len = sign_key.get_sig_len().expect("Error with get_sig_len()");
    let mut sig = vec![0u8; sig_len];
    sign_key.sign(message, &mut sig).expect("Error with sign()");

    // Copy the public portion into a fresh key.
    let mut verify_key = Lms::new().expect("Error with Lms::new() for verify");
    verify_key.set_parm(Lms::PARM_L1_H5_W8).expect("Error with set_parm() for verify key");
    verify_key.export_pub_from(&sign_key)
        .expect("Error with export_pub_from()");

    verify_key.verify(&sig, message)
        .expect("Signature must verify against export_pub_from() key");

    let _ = store;
}

/// Verify that `sigs_left()` indicates signatures are available immediately
/// after `make_key()`.
#[test]
#[cfg(all(lms_make_key, random))]
fn test_sigs_left_after_make_key() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    let mut store = Box::new(KeyStore { buf: [0u8; 16384] });
    let ctx = store.as_mut() as *mut KeyStore as *mut core::ffi::c_void;

    let mut key = Lms::new().expect("Error with Lms::new()");
    key.set_parm(Lms::PARM_L1_H5_W8).expect("Error with set_parm()");
    setup_callbacks(&mut key, ctx);
    key.make_key(&mut rng).expect("Error with make_key()");

    let remaining = key.sigs_left().expect("Error with sigs_left()");
    assert!(remaining, "sigs_left must be true immediately after make_key()");

    let _ = store;
}

/// Verify that `get_kid()` returns a slice of exactly `KEY_ID_LEN` bytes
/// after key generation.
#[test]
#[cfg(all(lms_make_key, random))]
fn test_get_kid() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    let mut store = Box::new(KeyStore { buf: [0u8; 16384] });
    let ctx = store.as_mut() as *mut KeyStore as *mut core::ffi::c_void;

    let mut key = Lms::new().expect("Error with Lms::new()");
    key.set_parm(Lms::PARM_L1_H5_W8).expect("Error with set_parm()");
    setup_callbacks(&mut key, ctx);
    key.make_key(&mut rng).expect("Error with make_key()");

    let kid = key.get_kid().expect("Error with get_kid()");
    assert_eq!(kid.len(), Lms::KEY_ID_LEN, "kid must be KEY_ID_LEN bytes");

    let _ = store;
}

/// Verify that `reload()` restores a key to a usable signing state and that
/// a signature produced by the reloaded key verifies correctly.
#[test]
#[cfg(all(lms_make_key, random))]
fn test_reload() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");
    let mut store = Box::new(KeyStore { buf: [0u8; 16384] });
    let ctx = store.as_mut() as *mut KeyStore as *mut core::ffi::c_void;

    // Generate a key pair and export the public key.
    let mut key = Lms::new().expect("Error with Lms::new()");
    key.set_parm(Lms::PARM_L1_H5_W8).expect("Error with set_parm()");
    setup_callbacks(&mut key, ctx);
    key.make_key(&mut rng).expect("Error with make_key()");

    let pub_len = key.get_pub_len().expect("Error with get_pub_len()");
    let mut pub_buf = vec![0u8; pub_len];
    key.export_pub_raw(&mut pub_buf).expect("Error with export_pub_raw()");

    // Create a new key, reload from NV storage (written by make_key above).
    let mut reloaded = Lms::new().expect("Error with Lms::new() for reload");
    reloaded.set_parm(Lms::PARM_L1_H5_W8).expect("Error with set_parm() for reload");
    setup_callbacks(&mut reloaded, ctx);
    reloaded.reload().expect("Error with reload()");

    // Sign with the reloaded key and verify against the exported public key.
    let message = b"Reload round-trip message";
    let sig_len = reloaded.get_sig_len().expect("Error with get_sig_len()");
    let mut sig = vec![0u8; sig_len];
    reloaded.sign(message, &mut sig).expect("Error with sign() after reload");

    let mut verify_key = Lms::new().expect("Error with Lms::new() for verify");
    // wc_LmsKey_ImportPubRaw requires params to be set first.
    verify_key.set_parm(Lms::PARM_L1_H5_W8).expect("Error with set_parm() for verify key");
    verify_key.import_pub_raw(&pub_buf).expect("Error with import_pub_raw()");
    verify_key.verify(&sig, message)
        .expect("Signature from reloaded key must verify");

    let _ = store;
}

/// Sign and verify round-trips across several predefined parameter sets,
/// confirming the implementation is parameter-agnostic.
#[test]
#[cfg(all(lms_make_key, random))]
fn test_sign_verify_multiple_parms() {
    common::setup();
    let mut rng = RNG::new().expect("Error creating RNG");

    for &parm in &[
        Lms::PARM_L1_H5_W8,
        Lms::PARM_L1_H5_W4,
        Lms::PARM_L1_H5_W2,
    ] {
        let mut store = Box::new(KeyStore { buf: [0u8; 16384] });
        let ctx = store.as_mut() as *mut KeyStore as *mut core::ffi::c_void;

        let mut key = Lms::new().expect("Error with Lms::new()");
        key.set_parm(parm).expect("Error with set_parm()");
        setup_callbacks(&mut key, ctx);
        key.make_key(&mut rng)
            .unwrap_or_else(|e| panic!("make_key failed for parm {}: {}", parm, e));

        let message = b"Parameter set round-trip";
        let sig_len = key.get_sig_len().expect("Error with get_sig_len()");
        let mut sig = vec![0u8; sig_len];

        key.sign(message, &mut sig)
            .unwrap_or_else(|e| panic!("sign failed for parm {}: {}", parm, e));
        key.verify(&sig, message)
            .unwrap_or_else(|e| panic!("verify failed for parm {}: {}", parm, e));

        let _ = store;
    }
}
