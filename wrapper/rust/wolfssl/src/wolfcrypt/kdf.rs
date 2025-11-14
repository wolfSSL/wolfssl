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
*/

use crate::sys;
use crate::wolfcrypt::hmac::HMAC;

#[cfg(kdf_srtp)]
pub const SRTP_LABEL_ENCRYPTION: u8 = sys::WC_SRTP_LABEL_ENCRYPTION as u8;
#[cfg(kdf_srtp)]
pub const SRTP_LABEL_MSG_AUTH: u8 = sys::WC_SRTP_LABEL_MSG_AUTH as u8;
#[cfg(kdf_srtp)]
pub const SRTP_LABEL_SALT: u8 = sys::WC_SRTP_LABEL_SALT as u8;
#[cfg(kdf_srtp)]
pub const SRTCP_LABEL_ENCRYPTION: u8 = sys::WC_SRTCP_LABEL_ENCRYPTION as u8;
#[cfg(kdf_srtp)]
pub const SRTCP_LABEL_MSG_AUTH: u8 = sys::WC_SRTCP_LABEL_MSG_AUTH as u8;
#[cfg(kdf_srtp)]
pub const SRTCP_LABEL_SALT: u8 = sys::WC_SRTCP_LABEL_SALT as u8;
#[cfg(kdf_srtp)]
pub const SRTP_LABEL_HDR_ENCRYPTION: u8 = sys::WC_SRTP_LABEL_HDR_ENCRYPTION as u8;
#[cfg(kdf_srtp)]
pub const SRTP_LABEL_HDR_SALT: u8 = sys::WC_SRTP_LABEL_HDR_SALT as u8;

/// Implement Password Based Key Derivation Function 2 (PBKDF2) converting an
/// input password with a concatenated salt into a more secure key which is
/// written to the `out` buffer.
///
/// # Parameters
///
/// * `password`: Password to use for key derivation.
/// * `salt`: Salt value to use for key derivation.
/// * `iterations`: Number of times to process the hash.
/// * `typ`: Hash type, one of `HMAC::TYPE_*`.
/// * `out`: Output buffer in which to store the generated key.
///
/// # Returns
///
/// Returns either Ok(()) on success or Err(e) containing the wolfSSL
/// library error code value.
///
/// # Example
///
/// ```rust
/// #[cfg(kdf_pbkdf2)]
/// {
/// use wolfssl::wolfcrypt::kdf::pbkdf2;
/// use wolfssl::wolfcrypt::hmac::HMAC;
/// let password = b"passwordpassword";
/// let salt = [0x78u8, 0x57, 0x8E, 0x5a, 0x5d, 0x63, 0xcb, 0x06];
/// let iterations = 2048;
/// let expected_key = [
///     0x43u8, 0x6d, 0xb5, 0xe8, 0xd0, 0xfb, 0x3f, 0x35, 0x42, 0x48, 0x39, 0xbc,
///     0x2d, 0xd4, 0xf9, 0x37, 0xd4, 0x95, 0x16, 0xa7, 0x2a, 0x9a, 0x21, 0xd1
/// ];
/// let mut keyout = [0u8; 24];
/// pbkdf2(password, &salt, iterations, HMAC::TYPE_SHA256, &mut keyout).expect("Error with pbkdf2()");
/// assert_eq!(keyout, expected_key);
/// }
/// ```
#[cfg(kdf_pbkdf2)]
pub fn pbkdf2(password: &[u8], salt: &[u8], iterations: i32, typ: i32, out: &mut [u8]) -> Result<(), i32> {
    pbkdf2_ex(password, salt, iterations, typ, None, None, out)
}

/// Implement Password Based Key Derivation Function 2 (PBKDF2) converting an
/// input password with a concatenated salt into a more secure key which is
/// written to the `out` buffer.
/// This version allows optional heap hint and device ID parameters.
///
/// # Parameters
///
/// * `password`: Password to use for key derivation.
/// * `salt`: Salt value to use for key derivation.
/// * `iterations`: Number of times to process the hash.
/// * `typ`: Hash type, one of `HMAC::TYPE_*`.
/// * `heap`: Optional heap hint.
/// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
/// * `out`: Output buffer in which to store the generated key.
///
/// # Returns
///
/// Returns either Ok(()) on success or Err(e) containing the wolfSSL
/// library error code value.
///
/// # Example
///
/// ```rust
/// #[cfg(kdf_pbkdf2)]
/// {
/// use wolfssl::wolfcrypt::kdf::pbkdf2_ex;
/// use wolfssl::wolfcrypt::hmac::HMAC;
/// let password = b"passwordpassword";
/// let salt = [0x78u8, 0x57, 0x8E, 0x5a, 0x5d, 0x63, 0xcb, 0x06];
/// let iterations = 2048;
/// let expected_key = [
///     0x43u8, 0x6d, 0xb5, 0xe8, 0xd0, 0xfb, 0x3f, 0x35, 0x42, 0x48, 0x39, 0xbc,
///     0x2d, 0xd4, 0xf9, 0x37, 0xd4, 0x95, 0x16, 0xa7, 0x2a, 0x9a, 0x21, 0xd1
/// ];
/// let mut keyout = [0u8; 24];
/// pbkdf2_ex(password, &salt, iterations, HMAC::TYPE_SHA256, None, None, &mut keyout).expect("Error with pbkdf2_ex()");
/// assert_eq!(keyout, expected_key);
/// }
/// ```
#[cfg(kdf_pbkdf2)]
pub fn pbkdf2_ex(password: &[u8], salt: &[u8], iterations: i32, typ: i32, heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>, out: &mut [u8]) -> Result<(), i32> {
    let password_size = password.len() as i32;
    let salt_size = salt.len() as i32;
    let out_size = out.len() as i32;
    let heap = match heap {
        Some(heap) => heap,
        None => core::ptr::null_mut(),
    };
    let dev_id = match dev_id {
        Some(dev_id) => dev_id,
        None => sys::INVALID_DEVID,
    };
    let rc = unsafe {
        sys::wc_PBKDF2_ex(out.as_mut_ptr(), password.as_ptr(), password_size,
            salt.as_ptr(), salt_size, iterations, out_size, typ, heap, dev_id)
    };
    if rc != 0 {
        return Err(rc);
    }
    Ok(())
}

/// This function implements the Password Based Key Derivation Function
/// (PBKDF) described in RFC 7292 Appendix B. This function converts an input
/// password with a concatenated salt into a more secure key, which it stores
/// in `out`. It allows the user to select any of the supported HMAC hash
/// functions, including: WC_MD5, WC_SHA, WC_SHA256, WC_SHA384, WC_SHA512,
/// WC_SHA3_224, WC_SHA3_256, WC_SHA3_384 or WC_SHA3_512.
///
/// # Parameters
///
/// * `password`: Password to use for key derivation.
/// * `salt`: Salt value to use for key derivation.
/// * `iterations`: Number of times to process the hash.
/// * `typ`: Hash type, one of `HMAC::TYPE_*`.
/// * `id`: Byte identifier indicating the purpose of key generation. It is
///   used to diversify the key output, and should be assigned as follows:
///   ID=1: pseudorandom bits are to be used as key material for performing
///   encryption or decryption. ID=2: pseudorandom bits are to be used an IV
///   (Initial Value) for encryption or decryption.  ID=3: pseudorandom bits
///   are to be used as an integrity key for MACing.
/// * `out`: Output buffer in which to store the generated key.
///
/// # Returns
///
/// Returns either Ok(()) on success or Err(e) containing the wolfSSL
/// library error code value.
///
/// # Example
///
/// ```rust
/// #[cfg(kdf_pkcs12)]
/// {
/// use wolfssl::wolfcrypt::kdf::pkcs12_pbkdf;
/// use wolfssl::wolfcrypt::hmac::HMAC;
/// let password = [0x00u8, 0x73, 0x00, 0x6d, 0x00, 0x65, 0x00, 0x67, 0x00, 0x00];
/// let salt = [0x0au8, 0x58, 0xCF, 0x64, 0x53, 0x0d, 0x82, 0x3f];
/// let expected_key = [
///     0x27u8, 0xE9, 0x0D, 0x7E, 0xD5, 0xA1, 0xC4, 0x11,
///     0xBA, 0x87, 0x8B, 0xC0, 0x90, 0xF5, 0xCE, 0xBE,
///     0x5E, 0x9D, 0x5F, 0xE3, 0xD6, 0x2B, 0x73, 0xAA
/// ];
/// let iterations = 1;
/// let mut keyout = [0u8; 24];
/// pkcs12_pbkdf(&password, &salt, iterations, HMAC::TYPE_SHA256, 1, &mut keyout).expect("Error with pkcs12_pbkdf()");
/// assert_eq!(keyout, expected_key);
/// }
/// ```
#[cfg(kdf_pkcs12)]
pub fn pkcs12_pbkdf(password: &[u8], salt: &[u8], iterations: i32, typ: i32, id: i32, out: &mut [u8]) -> Result<(), i32> {
    pkcs12_pbkdf_ex(password, salt, iterations, typ, id, None, out)
}

/// This function implements the Password Based Key Derivation Function
/// (PBKDF) described in RFC 7292 Appendix B. This function converts an input
/// password with a concatenated salt into a more secure key, which it stores
/// in `out`. It allows the user to select any of the supported HMAC hash
/// functions, including: WC_MD5, WC_SHA, WC_SHA256, WC_SHA384, WC_SHA512,
/// WC_SHA3_224, WC_SHA3_256, WC_SHA3_384 or WC_SHA3_512.
/// This version allows an optional heap hint parameter.
///
/// # Parameters
///
/// * `password`: Password to use for key derivation.
/// * `salt`: Salt value to use for key derivation.
/// * `iterations`: Number of times to process the hash.
/// * `typ`: Hash type, one of `HMAC::TYPE_*`.
/// * `id`: Byte identifier indicating the purpose of key generation. It is
///   used to diversify the key output, and should be assigned as follows:
///   ID=1: pseudorandom bits are to be used as key material for performing
///   encryption or decryption. ID=2: pseudorandom bits are to be used an IV
///   (Initial Value) for encryption or decryption.  ID=3: pseudorandom bits
///   are to be used as an integrity key for MACing.
/// * `heap`: Optional heap hint.
/// * `out`: Output buffer in which to store the generated key.
///
/// # Returns
///
/// Returns either Ok(()) on success or Err(e) containing the wolfSSL
/// library error code value.
///
/// # Example
///
/// ```rust
/// #[cfg(kdf_pkcs12)]
/// {
/// use wolfssl::wolfcrypt::kdf::pkcs12_pbkdf_ex;
/// use wolfssl::wolfcrypt::hmac::HMAC;
/// let password = [0x00u8, 0x73, 0x00, 0x6d, 0x00, 0x65, 0x00, 0x67, 0x00, 0x00];
/// let salt = [0x0au8, 0x58, 0xCF, 0x64, 0x53, 0x0d, 0x82, 0x3f];
/// let expected_key = [
///     0x27u8, 0xE9, 0x0D, 0x7E, 0xD5, 0xA1, 0xC4, 0x11,
///     0xBA, 0x87, 0x8B, 0xC0, 0x90, 0xF5, 0xCE, 0xBE,
///     0x5E, 0x9D, 0x5F, 0xE3, 0xD6, 0x2B, 0x73, 0xAA
/// ];
/// let iterations = 1;
/// let mut keyout = [0u8; 24];
/// pkcs12_pbkdf_ex(&password, &salt, iterations, HMAC::TYPE_SHA256, 1, None, &mut keyout).expect("Error with pkcs12_pbkdf_ex()");
/// assert_eq!(keyout, expected_key);
/// }
/// ```
#[cfg(kdf_pkcs12)]
pub fn pkcs12_pbkdf_ex(password: &[u8], salt: &[u8], iterations: i32, typ: i32, id: i32, heap: Option<*mut std::os::raw::c_void>, out: &mut [u8]) -> Result<(), i32> {
    let password_size = password.len() as i32;
    let salt_size = salt.len() as i32;
    let out_size = out.len() as i32;
    let heap = match heap {
        Some(heap) => heap,
        None => core::ptr::null_mut(),
    };
    let rc = unsafe {
        sys::wc_PKCS12_PBKDF_ex(out.as_mut_ptr(), password.as_ptr(), password_size,
            salt.as_ptr(), salt_size, iterations, out_size, typ, id, heap)
    };
    if rc != 0 {
        return Err(rc);
    }
    Ok(())
}

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
/// #[cfg(kdf_tls13)]
/// {
/// use wolfssl::wolfcrypt::hmac::HMAC;
/// use wolfssl::wolfcrypt::kdf::*;
/// use wolfssl::wolfcrypt::sha::SHA256;
/// let mut secret = [0u8; SHA256::DIGEST_SIZE];
/// tls13_hkdf_extract(HMAC::TYPE_SHA256, None, None, &mut secret).expect("Error with tls13_hkdf_extract()");
/// }
/// ```
#[cfg(kdf_tls13)]
pub fn tls13_hkdf_extract(typ: i32, salt: Option<&[u8]>, key: Option<&mut [u8]>, out: &mut [u8]) -> Result<(), i32> {
    tls13_hkdf_extract_ex(typ, salt, key, out, None, None)
}

/// Perform RFC 5869 HKDF-Extract operation for TLS v1.3 key derivation (with
/// optional heap and device ID).
///
/// # Parameters
///
/// * `typ`: Hash type, one of `HMAC::TYPE_*`.
/// * `salt`: Optional Salt value.
/// * `key`: Optional Initial Key Material (IKM).
/// * `out`: Output buffer to store TLS1.3 HKDF-Extract result (generated
///   Pseudo-Random Key (PRK)). The size of this buffer must match
///   `HMAC::get_hmac_size_by_type(typ)`.
/// * `heap`: Optional heap hint.
/// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
///
/// # Returns
///
/// Returns either Ok(()) on success or Err(e) containing the wolfSSL
/// library error code value.
///
/// # Example
///
/// ```rust
/// #[cfg(kdf_tls13)]
/// {
/// use wolfssl::wolfcrypt::hmac::HMAC;
/// use wolfssl::wolfcrypt::kdf::*;
/// use wolfssl::wolfcrypt::sha::SHA256;
/// let mut secret = [0u8; SHA256::DIGEST_SIZE];
/// tls13_hkdf_extract_ex(HMAC::TYPE_SHA256, None, None, &mut secret, None, None).expect("Error with tls13_hkdf_extract_ex()");
/// }
/// ```
#[cfg(kdf_tls13)]
pub fn tls13_hkdf_extract_ex(typ: i32, salt: Option<&[u8]>, key: Option<&mut [u8]>, out: &mut [u8], heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<(), i32> {
    let mut salt_ptr = core::ptr::null();
    let mut salt_size = 0u32;
    if let Some(salt) = salt {
        salt_ptr = salt.as_ptr();
        salt_size = salt.len() as u32;
    }
    let mut ikm_buf = [0u8; sys::WC_MAX_DIGEST_SIZE as usize];
    let mut ikm_ptr = ikm_buf.as_mut_ptr();
    let mut ikm_size = 0u32;
    if let Some(key) = key {
        if key.len() > 0 {
            ikm_ptr = key.as_mut_ptr();
            ikm_size = key.len() as u32;
        }
    }
    if out.len() != HMAC::get_hmac_size_by_type(typ)? {
        return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
    }
    let heap = match heap {
        Some(heap) => heap,
        None => core::ptr::null_mut(),
    };
    let dev_id = match dev_id {
        Some(dev_id) => dev_id,
        None => sys::INVALID_DEVID,
    };
    let rc = unsafe {
        sys::wc_Tls13_HKDF_Extract_ex(out.as_mut_ptr(), salt_ptr, salt_size,
            ikm_ptr, ikm_size, typ, heap, dev_id)
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
/// #[cfg(kdf_tls13)]
/// {
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
/// }
/// ```
#[cfg(kdf_tls13)]
pub fn tls13_hkdf_expand_label(typ: i32, key: &[u8], protocol: &[u8], label: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), i32> {
    tls13_hkdf_expand_label_ex(typ, key, protocol, label, info, out, None, None)
}

/// Perform RFC 5869 HKDF-Expand operation for TLS v1.3 key derivation (with
/// optional heap and device ID).
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
/// * `heap`: Optional heap hint.
/// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
///
/// # Returns
///
/// Returns either Ok(()) on success or Err(e) containing the wolfSSL
/// library error code value.
///
/// # Example
///
/// ```rust
/// #[cfg(kdf_tls13)]
/// {
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
/// tls13_hkdf_expand_label_ex(HMAC::TYPE_SHA256, &secret,
///     protocol_label, ce_traffic_label,
///     &hash_hello1, &mut expand_out, None, None).expect("Error with tls13_hkdf_expand_label_ex()");
/// }
/// ```
#[cfg(kdf_tls13)]
pub fn tls13_hkdf_expand_label_ex(typ: i32, key: &[u8], protocol: &[u8], label: &[u8], info: &[u8], out: &mut [u8], heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<(), i32> {
    let key_size = key.len() as u32;
    let protocol_size = protocol.len() as u32;
    let label_size = label.len() as u32;
    let info_size = info.len() as u32;
    let out_size = out.len() as u32;
    let heap = match heap {
        Some(heap) => heap,
        None => core::ptr::null_mut(),
    };
    let dev_id = match dev_id {
        Some(dev_id) => dev_id,
        None => sys::INVALID_DEVID,
    };
    let rc = unsafe {
        sys::wc_Tls13_HKDF_Expand_Label_ex(out.as_mut_ptr(), out_size,
            key.as_ptr(), key_size, protocol.as_ptr(), protocol_size,
            label.as_ptr(), label_size, info.as_ptr(), info_size, typ,
            heap, dev_id)
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
/// #[cfg(kdf_ssh)]
/// {
/// use wolfssl::wolfcrypt::hmac::HMAC;
/// use wolfssl::wolfcrypt::kdf::*;
/// let k = [0x42u8; 256];
/// let h = [0x43u8; 32];
/// let sid = [0x44u8; 32];
/// let mut out = [0u8; 16];
/// ssh_kdf(HMAC::TYPE_SHA256, b'A', &k, &h, &sid, &mut out).expect("Error with ssh_kdf()");
/// }
/// ```
#[cfg(kdf_ssh)]
pub fn ssh_kdf(typ: i32, key_id: u8, k: &[u8], h: &[u8], session_id: &[u8], key: &mut [u8]) -> Result<(), i32> {
    let key_size = key.len() as u32;
    let k_size = k.len() as u32;
    let h_size = h.len() as u32;
    let session_size = session_id.len() as u32;
    let rc = unsafe {
        sys::wc_SSH_KDF(typ as u8, key_id,
            key.as_mut_ptr(), key_size,
            k.as_ptr(), k_size, h.as_ptr(), h_size,
            session_id.as_ptr(), session_size)
    };
    if rc != 0 {
        return Err(rc);
    }
    Ok(())
}

/// Perform SRTP KDF algorithm to derive keys.
///
/// # Parameters
///
/// * `key`: Key to use with encryption.
/// * `salt`: Random non-secret value.
/// * `kdr_index`: Key derivation rate: -1 for 0, otherwise KDR = 2^kdr_index.
/// * `idx`: Index value to XOR in.
/// * `key1`: Output buffer for first key (label of 0x00).
/// * `key2`: Output buffer for second key (label of 0x01).
/// * `key3`: Output buffer for third key (label of 0x02).
///
/// # Returns
///
/// Returns either Ok(()) on success or Err(e) containing the wolfSSL
/// library error code value.
///
/// # Example
///
/// ```rust
/// #[cfg(kdf_srtp)]
/// {
/// use wolfssl::wolfcrypt::kdf::*;
/// let key = [0xc4u8, 0x80, 0x9f, 0x6d, 0x36, 0x98, 0x88, 0x72,
///     0x8e, 0x26, 0xad, 0xb5, 0x32, 0x12, 0x98, 0x90];
/// let salt = [0x0eu8, 0x23, 0x00, 0x6c, 0x6c, 0x04, 0x4f, 0x56,
///     0x62, 0x40, 0x0e, 0x9d, 0x1b, 0xd6];
/// let index = [0x48u8, 0x71, 0x65, 0x64, 0x9c, 0xca];
/// let mut key_e = [0u8; 16];
/// let mut key_a = [0u8; 20];
/// let mut key_s = [0u8; 14];
/// srtp_kdf(&key, &salt, -1, &index, &mut key_e, &mut key_a, &mut key_s).expect("Error with srtp_kdf()");
/// }
/// ```
#[cfg(kdf_srtp)]
pub fn srtp_kdf(key: &[u8], salt: &[u8], kdr_index: i32, idx: &[u8],
        key1: &mut [u8], key2: &mut [u8], key3: &mut [u8]) -> Result<(), i32> {
    let key_size = key.len() as u32;
    let salt_size = salt.len() as u32;
    let key1_size = key1.len() as u32;
    let key2_size = key2.len() as u32;
    let key3_size = key3.len() as u32;
    let rc = unsafe {
        sys::wc_SRTP_KDF(key.as_ptr(), key_size, salt.as_ptr(), salt_size,
            kdr_index, idx.as_ptr(), key1.as_mut_ptr(), key1_size,
            key2.as_mut_ptr(), key2_size, key3.as_mut_ptr(), key3_size)
    };
    if rc != 0 {
        return Err(rc);
    }
    Ok(())
}

/// Perform SRTP KDF algorithm to derive a key with a given label.
///
/// # Parameters
///
/// * `key`: Key to use with encryption.
/// * `salt`: Random non-secret value.
/// * `kdr_index`: Key derivation rate: -1 for 0, otherwise KDR = 2^kdr_index.
/// * `idx`: Index value to XOR in.
/// * `label`: Label: typically one of `SRTP_LABEL_*`.
/// * `keyout`: Output buffer for generated key.
///
/// # Returns
///
/// Returns either Ok(()) on success or Err(e) containing the wolfSSL
/// library error code value.
///
/// # Example
///
/// ```rust
/// #[cfg(kdf_srtp)]
/// {
/// use wolfssl::wolfcrypt::kdf::*;
/// let key = [0xc4u8, 0x80, 0x9f, 0x6d, 0x36, 0x98, 0x88, 0x72,
///     0x8e, 0x26, 0xad, 0xb5, 0x32, 0x12, 0x98, 0x90];
/// let salt = [0x0eu8, 0x23, 0x00, 0x6c, 0x6c, 0x04, 0x4f, 0x56,
///     0x62, 0x40, 0x0e, 0x9d, 0x1b, 0xd6];
/// let index = [0x48u8, 0x71, 0x65, 0x64, 0x9c, 0xca];
/// let mut key_a = [0u8; 20];
/// srtp_kdf_label(&key, &salt, -1, &index, SRTP_LABEL_MSG_AUTH, &mut key_a).expect("Error with srtp_kdf_label()");
/// }
/// ```
#[cfg(kdf_srtp)]
pub fn srtp_kdf_label(key: &[u8], salt: &[u8], kdr_index: i32, idx: &[u8],
        label: u8, keyout: &mut [u8]) -> Result<(), i32> {
    let key_size = key.len() as u32;
    let salt_size = salt.len() as u32;
    let keyout_size = keyout.len() as u32;
    let rc = unsafe {
        sys::wc_SRTP_KDF_label(key.as_ptr(), key_size, salt.as_ptr(), salt_size,
            kdr_index, idx.as_ptr(), label, keyout.as_mut_ptr(), keyout_size)
    };
    if rc != 0 {
        return Err(rc);
    }
    Ok(())
}

/// Perform SRTCP KDF algorithm to derive keys.
///
/// # Parameters
///
/// * `key`: Key to use with encryption. Key length must be 16, 24, or 32.
/// * `salt`: Random non-secret value.
/// * `kdr_index`: Key derivation rate: -1 for 0, otherwise KDR = 2^kdr_index.
/// * `idx`: Index value to XOR in.
/// * `key1`: Output buffer for first key (label of 0x00).
/// * `key2`: Output buffer for second key (label of 0x01).
/// * `key3`: Output buffer for third key (label of 0x02).
///
/// # Returns
///
/// Returns either Ok(()) on success or Err(e) containing the wolfSSL
/// library error code value.
///
/// # Example
///
/// ```rust
/// #[cfg(kdf_srtp)]
/// {
/// use wolfssl::wolfcrypt::kdf::*;
/// let key = [0xc4u8, 0x80, 0x9f, 0x6d, 0x36, 0x98, 0x88, 0x72,
///     0x8e, 0x26, 0xad, 0xb5, 0x32, 0x12, 0x98, 0x90];
/// let salt = [0x0eu8, 0x23, 0x00, 0x6c, 0x6c, 0x04, 0x4f, 0x56,
///     0x62, 0x40, 0x0e, 0x9d, 0x1b, 0xd6];
/// let index = [0x48u8, 0x71, 0x65, 0x64, 0x9c, 0xca];
/// let mut key_e = [0u8; 16];
/// let mut key_a = [0u8; 20];
/// let mut key_s = [0u8; 14];
/// srtcp_kdf(&key, &salt, -1, &index, &mut key_e, &mut key_a, &mut key_s).expect("Error with srtcp_kdf()");
/// }
/// ```
#[cfg(kdf_srtp)]
pub fn srtcp_kdf(key: &[u8], salt: &[u8], kdr_index: i32, idx: &[u8],
        key1: &mut [u8], key2: &mut [u8], key3: &mut [u8]) -> Result<(), i32> {
    let key_size = key.len() as u32;
    let salt_size = salt.len() as u32;
    let key1_size = key1.len() as u32;
    let key2_size = key2.len() as u32;
    let key3_size = key3.len() as u32;
    let rc = unsafe {
        sys::wc_SRTCP_KDF(key.as_ptr(), key_size, salt.as_ptr(), salt_size,
            kdr_index, idx.as_ptr(), key1.as_mut_ptr(), key1_size,
            key2.as_mut_ptr(), key2_size, key3.as_mut_ptr(), key3_size)
    };
    if rc != 0 {
        return Err(rc);
    }
    Ok(())
}

/// Perform SRTCP KDF algorithm to derive a key with a given label.
///
/// # Parameters
///
/// * `key`: Key to use with encryption.
/// * `salt`: Random non-secret value.
/// * `kdr_index`: Key derivation rate: -1 for 0, otherwise KDR = 2^kdr_index.
/// * `idx`: Index value to XOR in.
/// * `label`: Label: typically one of `SRTCP_LABEL_*`.
/// * `keyout`: Output buffer for generated key.
///
/// # Returns
///
/// Returns either Ok(()) on success or Err(e) containing the wolfSSL
/// library error code value.
///
/// # Example
///
/// ```rust
/// #[cfg(kdf_srtp)]
/// {
/// use wolfssl::wolfcrypt::kdf::*;
/// let key = [0xc4u8, 0x80, 0x9f, 0x6d, 0x36, 0x98, 0x88, 0x72,
///     0x8e, 0x26, 0xad, 0xb5, 0x32, 0x12, 0x98, 0x90];
/// let salt = [0x0eu8, 0x23, 0x00, 0x6c, 0x6c, 0x04, 0x4f, 0x56,
///     0x62, 0x40, 0x0e, 0x9d, 0x1b, 0xd6];
/// let index = [0x48u8, 0x71, 0x65, 0x64, 0x9c, 0xca];
/// let mut key_a = [0u8; 20];
/// srtcp_kdf_label(&key, &salt, -1, &index, SRTCP_LABEL_MSG_AUTH, &mut key_a).expect("Error with srtcp_kdf_label()");
/// }
/// ```
#[cfg(kdf_srtp)]
pub fn srtcp_kdf_label(key: &[u8], salt: &[u8], kdr_index: i32, idx: &[u8],
        label: u8, keyout: &mut [u8]) -> Result<(), i32> {
    let key_size = key.len() as u32;
    let salt_size = salt.len() as u32;
    let keyout_size = keyout.len() as u32;
    let rc = unsafe {
        sys::wc_SRTCP_KDF_label(key.as_ptr(), key_size, salt.as_ptr(), salt_size,
            kdr_index, idx.as_ptr(), label, keyout.as_mut_ptr(), keyout_size)
    };
    if rc != 0 {
        return Err(rc);
    }
    Ok(())
}

/// Convert a Key Derivation Rate (KDR) value to an index for use in the
/// SRTP/SRTCP KDF API.
///
/// # Parameters
///
/// * `kdr`: Key derivation rate to convert.
///
/// # Returns
///
/// Key derivation rate index (kdr_index).
///
/// # Example
///
/// ```rust
/// #[cfg(kdf_srtp)]
/// {
/// use wolfssl::wolfcrypt::kdf::*;
/// let kdr_index = srtp_kdr_to_index(16);
/// }
/// ```
#[cfg(kdf_srtp)]
pub fn srtp_kdr_to_index(kdr: u32) -> i32 {
    unsafe { sys::wc_SRTP_KDF_kdr_to_idx(kdr) }
}
