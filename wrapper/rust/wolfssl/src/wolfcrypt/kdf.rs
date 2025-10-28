/*
 * Copyright (C) 2025 wolfSSL Inc.
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

/*!
This module provides a Rust wrapper for the wolfCrypt library's Key Derivation
Function (KDF) functionality.

It leverages the `wolfssl-sys` crate for low-level FFI bindings, encapsulating
the raw C functions in a memory-safe and easy-to-use Rust API.
*/

use crate::wolfcrypt::hmac::HMAC;
use wolfssl_sys as ws;

/// Perform RFC 5869 HKDF-Extract operation for TLS v1.3 key derivation.
///
/// # Parameters
///
/// * `typ`: Hash type, one of `HMAC::TYPE_*`.
/// * `salt`: Optional Salt value.
/// * `key`: Optional Initial Key Material (IKM).
/// * `out`: Output buffer to store TLS1.3 HKDF-Extract result (generated
///   Pseudo-Random Key (PRK)). The size of this buffer must match
///   `HMAC::get_hmac_size_by_type(typ)`.
///
/// # Returns
///
/// Returns either Ok(()) on success or Err(e) containing the wolfSSL
/// library error code value.
///
/// # Example
///
/// ```rust
/// use wolfssl::wolfcrypt::hmac::HMAC;
/// use wolfssl::wolfcrypt::kdf::*;
/// use wolfssl::wolfcrypt::sha::SHA256;
/// let mut secret = [0u8; SHA256::DIGEST_SIZE];
/// tls13_hkdf_extract(HMAC::TYPE_SHA256, None, None, &mut secret).expect("Error with tls13_hkdf_extract()");
/// ```
pub fn tls13_hkdf_extract(typ: i32, salt: Option<&[u8]>, key: Option<&mut [u8]>, out: &mut [u8]) -> Result<(), i32> {
    let mut salt_ptr = core::ptr::null();
    let mut salt_size = 0u32;
    if let Some(salt) = salt {
        salt_ptr = salt.as_ptr();
        salt_size = salt.len() as u32;
    }
    let mut ikm_buf = [0u8; ws::WC_MAX_DIGEST_SIZE as usize];
    let mut ikm_ptr = ikm_buf.as_mut_ptr();
    let mut ikm_size = 0u32;
    if let Some(key) = key {
        if key.len() > 0 {
            ikm_ptr = key.as_mut_ptr();
            ikm_size = key.len() as u32;
        }
    }
    if out.len() != HMAC::get_hmac_size_by_type(typ)? {
        return Err(ws::wolfCrypt_ErrorCodes_BUFFER_E);
    }
    let rc = unsafe {
        ws::wc_Tls13_HKDF_Extract(out.as_mut_ptr(), salt_ptr, salt_size,
            ikm_ptr, ikm_size, typ)
    };
    if rc != 0 {
        return Err(rc);
    }
    Ok(())
}

/// Perform RFC 5869 HKDF-Expand operation for TLS v1.3 key derivation.
///
/// This utilizes HMAC to convert `key`, `label`, and `info` into a
/// derived key which is written to `out`.
///
/// # Parameters
///
/// * `typ`: Hash type, one of `HMAC::TYPE_*`.
/// * `key`: Key to use for KDF (typically output of `tls13_hkdf_extract()`).
/// * `protocol`: Buffer containing TLS protocol.
/// * `label`: Buffer containing label.
/// * `info`: Buffer containing additional info.
/// * `out`: Output buffer to store TLS1.3 HKDF-Expand result. The buffer can be
///   any size.
///
/// # Returns
///
/// Returns either Ok(()) on success or Err(e) containing the wolfSSL
/// library error code value.
///
/// # Example
///
/// ```rust
/// use wolfssl::wolfcrypt::hmac::HMAC;
/// use wolfssl::wolfcrypt::kdf::*;
/// use wolfssl::wolfcrypt::sha::SHA256;
/// let hash_hello1 = [
///     0x63u8, 0x83, 0x58, 0xab, 0x36, 0xcd, 0x0c, 0xf3,
///     0x26, 0x07, 0xb5, 0x5f, 0x0b, 0x8b, 0x45, 0xd6,
///     0x7d, 0x5b, 0x42, 0xdc, 0xa8, 0xaa, 0x06, 0xfb,
///     0x20, 0xa5, 0xbb, 0x85, 0xdb, 0x54, 0xd8, 0x8b
/// ];
/// let client_early_traffic_secret = [
///     0x20u8, 0x18, 0x72, 0x7c, 0xde, 0x3a, 0x85, 0x17, 0x72, 0xdc, 0xd7, 0x72,
///     0xb0, 0xfc, 0x45, 0xd0, 0x62, 0xb9, 0xbb, 0x38, 0x69, 0x05, 0x7b, 0xb4,
///     0x5e, 0x58, 0x5d, 0xed, 0xcd, 0x0b, 0x96, 0xd3
/// ];
/// let mut secret = [0u8; SHA256::DIGEST_SIZE];
/// tls13_hkdf_extract(HMAC::TYPE_SHA256, None, None, &mut secret).expect("Error with tls13_hkdf_extract()");
/// let protocol_label = b"tls13 ";
/// let ce_traffic_label = b"c e traffic";
/// let mut expand_out = [0u8; SHA256::DIGEST_SIZE];
/// tls13_hkdf_expand_label(HMAC::TYPE_SHA256, &secret,
///     protocol_label, ce_traffic_label,
///     &hash_hello1, &mut expand_out).expect("Error with tls13_hkdf_expand_label()");
/// ```
pub fn tls13_hkdf_expand_label(typ: i32, key: &[u8], protocol: &[u8], label: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), i32> {
    let key_size = key.len() as u32;
    let protocol_size = protocol.len() as u32;
    let label_size = label.len() as u32;
    let info_size = info.len() as u32;
    let out_size = out.len() as u32;
    let rc = unsafe {
        ws::wc_Tls13_HKDF_Expand_Label(out.as_mut_ptr(), out_size,
            key.as_ptr(), key_size, protocol.as_ptr(), protocol_size,
            label.as_ptr(), label_size, info.as_ptr(), info_size, typ)
    };
    if rc != 0 {
        return Err(rc);
    }
    Ok(())
}

/// Perform SSH KDF operation.
///
/// # Parameters
///
/// * `typ`: Hash type, one of `HMAC::TYPE_*`.
/// * `key_id`: Key ID, typically 'A' through 'F'.
/// * `k`: Initial key.
/// * `h`: Exchange hash.
/// * `session_id`: Unique identifier for the SSH session.
/// * `key`: Output buffer.
///
/// # Returns
///
/// Returns either Ok(()) on success or Err(e) containing the wolfSSL
/// library error code value.
///
/// # Example
///
/// ```rust
/// use wolfssl::wolfcrypt::hmac::HMAC;
/// use wolfssl::wolfcrypt::kdf::*;
/// let k = [0x42u8; 256];
/// let h = [0x43u8; 32];
/// let sid = [0x44u8; 32];
/// let mut out = [0u8; 16];
/// ssh_kdf(HMAC::TYPE_SHA256, b'A', &k, &h, &sid, &mut out).expect("Error with ssh_kdf()");
/// ```
pub fn ssh_kdf(typ: i32, key_id: u8, k: &[u8], h: &[u8], session_id: &[u8], key: &mut [u8]) -> Result<(), i32> {
    let key_size = key.len() as u32;
    let k_size = k.len() as u32;
    let h_size = h.len() as u32;
    let session_size = session_id.len() as u32;
    let rc = unsafe {
        ws::wc_SSH_KDF(typ as u8, key_id,
            key.as_mut_ptr(), key_size,
            k.as_ptr(), k_size, h.as_ptr(), h_size,
            session_id.as_ptr(), session_size)
    };
    if rc != 0 {
        return Err(rc);
    }
    Ok(())
}
