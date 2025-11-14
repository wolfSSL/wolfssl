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
This module provides a Rust wrapper for the wolfCrypt library's HMAC Key
Derivation Function (HKDF) functionality.
*/

use crate::sys;
use crate::wolfcrypt::hmac::HMAC;

/// Perform HKDF-Extract operation.
///
/// This utilizes HMAC to convert `key`, with an optional `salt`, into a
/// derived key which is written to `out`.
///
/// # Parameters
///
/// * `typ`: Hash type, one of `HMAC::TYPE_*`.
/// * `salt`: Salt value (optional).
/// * `key`: Initial Key Material (IKM).
/// * `out`: Output buffer to store HKDF-Extract result. The size of this
///   buffer must match `HMAC::get_hmac_size_by_type(typ)`.
///
/// # Returns
///
/// Returns either Ok(()) on success or Err(e) containing the wolfSSL
/// library error code value.
///
/// # Example
///
/// ```rust
/// use wolfssl::wolfcrypt::hkdf::*;
/// use wolfssl::wolfcrypt::hmac::HMAC;
/// use wolfssl::wolfcrypt::sha::SHA256;
/// let ikm = b"MyPassword0";
/// let salt = b"12345678ABCDEFGH";
/// let mut extract_out = [0u8; SHA256::DIGEST_SIZE];
/// hkdf_extract(HMAC::TYPE_SHA256, Some(salt), ikm, &mut extract_out).expect("Error with hkdf_extract()");
/// ```
pub fn hkdf_extract(typ: i32, salt: Option<&[u8]>, key: &[u8], out: &mut [u8]) -> Result<(), i32> {
    hkdf_extract_ex(typ, salt, key, out, None, None)
}

/// Perform HKDF-Extract operation (with optional heap and device ID).
///
/// This utilizes HMAC to convert `key`, with an optional `salt`, into a
/// derived key which is written to `out`.
///
/// # Parameters
///
/// * `typ`: Hash type, one of `HMAC::TYPE_*`.
/// * `salt`: Salt value (optional).
/// * `key`: Initial Key Material (IKM).
/// * `out`: Output buffer to store HKDF-Extract result. The size of this
///   buffer must match `HMAC::get_hmac_size_by_type(typ)`.
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
/// use wolfssl::wolfcrypt::hkdf::*;
/// use wolfssl::wolfcrypt::hmac::HMAC;
/// use wolfssl::wolfcrypt::sha::SHA256;
/// let ikm = b"MyPassword0";
/// let salt = b"12345678ABCDEFGH";
/// let mut extract_out = [0u8; SHA256::DIGEST_SIZE];
/// hkdf_extract_ex(HMAC::TYPE_SHA256, Some(salt), ikm, &mut extract_out, None, None).expect("Error with hkdf_extract_ex()");
/// ```
pub fn hkdf_extract_ex(typ: i32, salt: Option<&[u8]>, key: &[u8], out: &mut [u8], heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<(), i32> {
    let mut salt_ptr = core::ptr::null();
    let mut salt_size = 0u32;
    if let Some(salt) = salt {
        salt_ptr = salt.as_ptr();
        salt_size = salt.len() as u32;
    }
    let key_size = key.len() as u32;
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
        sys::wc_HKDF_Extract_ex(typ, salt_ptr, salt_size,
            key.as_ptr(), key_size, out.as_mut_ptr(), heap, dev_id)
    };
    if rc != 0 {
        return Err(rc);
    }
    Ok(())
}

/// Perform HKDF-Expand operation.
///
/// This utilizes HMAC to convert `key`, with optional `info`, into a
/// derived key which is written to `out`.
///
/// # Parameters
///
/// * `typ`: Hash type, one of `HMAC::TYPE_*`.
/// * `key`: Key to use for KDF (typically output of `hkdf_extract()`).
/// * `info`: Optional buffer containing additional info.
/// * `out`: Output buffer to store HKDF-Expand result. The buffer can be
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
/// use wolfssl::wolfcrypt::hkdf::*;
/// use wolfssl::wolfcrypt::hmac::HMAC;
/// use wolfssl::wolfcrypt::sha::SHA256;
/// let ikm = b"MyPassword0";
/// let salt = b"12345678ABCDEFGH";
/// let mut extract_out = [0u8; SHA256::DIGEST_SIZE];
/// hkdf_extract(HMAC::TYPE_SHA256, Some(salt), ikm, &mut extract_out).expect("Error with hkdf_extract()");
/// let info = b"0";
/// let mut expand_out = [0u8; 16];
/// hkdf_expand(HMAC::TYPE_SHA256, &extract_out, Some(info), &mut expand_out).expect("Error with hkdf_expand()");
/// ```
pub fn hkdf_expand(typ: i32, key: &[u8], info: Option<&[u8]>, out: &mut [u8]) -> Result<(), i32> {
    hkdf_expand_ex(typ, key, info, out, None, None)
}

/// Perform HKDF-Expand operation (with optional heap and device ID).
///
/// This utilizes HMAC to convert `key`, with optional `info`, into a
/// derived key which is written to `out`.
///
/// # Parameters
///
/// * `typ`: Hash type, one of `HMAC::TYPE_*`.
/// * `key`: Key to use for KDF (typically output of `hkdf_extract()`).
/// * `info`: Optional buffer containing additional info.
/// * `out`: Output buffer to store HKDF-Expand result. The buffer can be
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
/// use wolfssl::wolfcrypt::hkdf::*;
/// use wolfssl::wolfcrypt::hmac::HMAC;
/// use wolfssl::wolfcrypt::sha::SHA256;
/// let ikm = b"MyPassword0";
/// let salt = b"12345678ABCDEFGH";
/// let mut extract_out = [0u8; SHA256::DIGEST_SIZE];
/// hkdf_extract(HMAC::TYPE_SHA256, Some(salt), ikm, &mut extract_out).expect("Error with hkdf_extract()");
/// let info = b"0";
/// let mut expand_out = [0u8; 16];
/// hkdf_expand_ex(HMAC::TYPE_SHA256, &extract_out, Some(info), &mut expand_out, None, None).expect("Error with hkdf_expand_ex()");
/// ```
pub fn hkdf_expand_ex(typ: i32, key: &[u8], info: Option<&[u8]>, out: &mut [u8], heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<(), i32> {
    let key_size = key.len() as u32;
    let mut info_ptr = core::ptr::null();
    let mut info_size = 0u32;
    if let Some(info) = info {
        info_ptr = info.as_ptr();
        info_size = info.len() as u32;
    }
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
        sys::wc_HKDF_Expand_ex(typ, key.as_ptr(), key_size,
            info_ptr, info_size, out.as_mut_ptr(), out_size, heap, dev_id)
    };
    if rc != 0 {
        return Err(rc);
    }
    Ok(())
}

/// Perform HMAC Key Derivation Function (HKDF) operation.
///
/// This utilizes HMAC to convert `key`, with an optional `salt` and
/// optional `info` into a derived key which is written to `out`.
///
/// This one-shot function is a combination of `hkdf_extract()` and `hkdf_expand()`.
///
/// # Parameters
///
/// * `typ`: Hash type, one of `HMAC::TYPE_*`.
/// * `key`: Initial Key Material (IKM).
/// * `salt`: Salt value (optional).
/// * `info`: Optional buffer containing additional info.
/// * `out`: Output buffer to store HKDF result. The buffer can be any size.
///
/// # Returns
///
/// Returns either Ok(()) on success or Err(e) containing the wolfSSL
/// library error code value.
///
/// # Example
///
/// ```rust
/// use wolfssl::wolfcrypt::hkdf::*;
/// use wolfssl::wolfcrypt::hmac::HMAC;
/// let ikm = b"MyPassword0";
/// let salt = b"12345678ABCDEFGH";
/// let info = b"0";
/// let mut out = [0u8; 16];
/// hkdf(HMAC::TYPE_SHA256, ikm, Some(salt), Some(info), &mut out).expect("Error with hkdf()");
/// ```
pub fn hkdf(typ: i32, key: &[u8], salt: Option<&[u8]>, info: Option<&[u8]>, out: &mut[u8]) -> Result<(), i32> {
    let key_size = key.len() as u32;
    let mut salt_ptr = core::ptr::null();
    let mut salt_size = 0u32;
    if let Some(salt) = salt {
        salt_ptr = salt.as_ptr();
        salt_size = salt.len() as u32;
    }
    let mut info_ptr = core::ptr::null();
    let mut info_size = 0u32;
    if let Some(info) = info {
        info_ptr = info.as_ptr();
        info_size = info.len() as u32;
    }
    let out_size = out.len() as u32;
    let rc = unsafe {
        sys::wc_HKDF(typ, key.as_ptr(), key_size, salt_ptr, salt_size,
            info_ptr, info_size, out.as_mut_ptr(), out_size)
    };
    if rc != 0 {
        return Err(rc);
    }
    Ok(())
}
