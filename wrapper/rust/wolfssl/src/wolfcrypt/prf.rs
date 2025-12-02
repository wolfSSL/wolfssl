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
This module provides a Rust wrapper for the wolfCrypt library's Pseudo Random
Function (PRF) functionality.
*/

use crate::sys;

pub const PRF_HASH_NONE: i32 = sys::wc_MACAlgorithm_no_mac as i32;
pub const PRF_HASH_MD5: i32 = sys::wc_MACAlgorithm_md5_mac as i32;
pub const PRF_HASH_SHA: i32 = sys::wc_MACAlgorithm_sha_mac as i32;
pub const PRF_HASH_SHA224: i32 = sys::wc_MACAlgorithm_sha224_mac as i32;
pub const PRF_HASH_SHA256: i32 = sys::wc_MACAlgorithm_sha256_mac as i32;
pub const PRF_HASH_SHA384: i32 = sys::wc_MACAlgorithm_sha384_mac as i32;
pub const PRF_HASH_SHA512: i32 = sys::wc_MACAlgorithm_sha512_mac as i32;
pub const PRF_HASH_RMD: i32 = sys::wc_MACAlgorithm_rmd_mac as i32;
pub const PRF_HASH_BLAKE2B: i32 = sys::wc_MACAlgorithm_blake2b_mac as i32;
pub const PRF_HASH_SM3: i32 = sys::wc_MACAlgorithm_sm3_mac as i32;

/// Pseudo Random Function for MD5, SHA-1, SHA-256, SHA-384, or SHA-512.
///
/// # Parameters
///
/// * `secret`: Secret key.
/// * `seed`: Seed.
/// * `hash_type`: PRF Hash type, one of `PRF_HASH_*`.
/// * `dout`: Output buffer.
///
/// # Returns
///
/// Returns either Ok(()) on success or Err(e) containing the wolfSSL
/// library error code value.
///
/// # Example
///
/// ```rust
/// use wolfssl::wolfcrypt::prf::*;
/// let secret = [0x10u8, 0xbc, 0xb4, 0xa2, 0xe8, 0xdc, 0xf1, 0x9b, 0x4c,
///     0x51, 0x9c, 0xed, 0x31, 0x1b, 0x51, 0x57, 0x02, 0x3f,
///     0xa1, 0x7d, 0xfb, 0x0e, 0xf3, 0x4e, 0x8f, 0x6f, 0x71,
///     0xa3, 0x67, 0x76, 0x6b, 0xfa, 0x5d, 0x46, 0x4a, 0xe8,
///     0x61, 0x18, 0x81, 0xc4, 0x66, 0xcc, 0x6f, 0x09, 0x99,
///     0x9d, 0xfc, 0x47];
/// let seed = [0x73u8, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x66, 0x69,
///     0x6e, 0x69, 0x73, 0x68, 0x65, 0x64, 0x0b, 0x46, 0xba,
///     0x56, 0xbf, 0x1f, 0x5d, 0x99, 0xff, 0xe9, 0xbb, 0x43,
///     0x01, 0xe7, 0xca, 0x2c, 0x00, 0xdf, 0x9a, 0x39, 0x6e,
///     0xcf, 0x6d, 0x15, 0x27, 0x4d, 0xf2, 0x93, 0x96, 0x4a,
///     0x91, 0xde, 0x5c, 0xc0, 0x47, 0x7c, 0xa8, 0xae, 0xcf,
///     0x5d, 0x93, 0x5f, 0x4c, 0x92, 0xcc, 0x98, 0x5b, 0x43];
/// let mut out = [0u8; 12];
/// prf(&secret, &seed, PRF_HASH_SHA384, &mut out).expect("Error with prf()");
/// ```
pub fn prf(secret: &[u8], seed: &[u8], hash_type: i32, dout: &mut [u8]) -> Result<(), i32> {
    prf_ex(secret, seed, hash_type, None, None, dout)
}

/// Pseudo Random Function for MD5, SHA-1, SHA-256, SHA-384, or SHA-512 with
/// optional heap and device ID.
///
/// # Parameters
///
/// * `secret`: Secret key.
/// * `seed`: Seed.
/// * `hash_type`: PRF Hash type, one of `PRF_HASH_*`.
/// * `heap`: Optional heap hint.
/// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
/// * `dout`: Output buffer.
///
/// # Returns
///
/// Returns either Ok(()) on success or Err(e) containing the wolfSSL
/// library error code value.
///
/// # Example
///
/// ```rust
/// use wolfssl::wolfcrypt::prf::*;
/// let secret = [0x10u8, 0xbc, 0xb4, 0xa2, 0xe8, 0xdc, 0xf1, 0x9b, 0x4c,
///     0x51, 0x9c, 0xed, 0x31, 0x1b, 0x51, 0x57, 0x02, 0x3f,
///     0xa1, 0x7d, 0xfb, 0x0e, 0xf3, 0x4e, 0x8f, 0x6f, 0x71,
///     0xa3, 0x67, 0x76, 0x6b, 0xfa, 0x5d, 0x46, 0x4a, 0xe8,
///     0x61, 0x18, 0x81, 0xc4, 0x66, 0xcc, 0x6f, 0x09, 0x99,
///     0x9d, 0xfc, 0x47];
/// let seed = [0x73u8, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x66, 0x69,
///     0x6e, 0x69, 0x73, 0x68, 0x65, 0x64, 0x0b, 0x46, 0xba,
///     0x56, 0xbf, 0x1f, 0x5d, 0x99, 0xff, 0xe9, 0xbb, 0x43,
///     0x01, 0xe7, 0xca, 0x2c, 0x00, 0xdf, 0x9a, 0x39, 0x6e,
///     0xcf, 0x6d, 0x15, 0x27, 0x4d, 0xf2, 0x93, 0x96, 0x4a,
///     0x91, 0xde, 0x5c, 0xc0, 0x47, 0x7c, 0xa8, 0xae, 0xcf,
///     0x5d, 0x93, 0x5f, 0x4c, 0x92, 0xcc, 0x98, 0x5b, 0x43];
/// let mut out = [0u8; 12];
/// prf_ex(&secret, &seed, PRF_HASH_SHA384, None, None, &mut out).expect("Error with prf_ex()");
/// ```
pub fn prf_ex(secret: &[u8], seed: &[u8], hash_type: i32, heap: Option<*mut ::std::os::raw::c_void>, dev_id: Option<i32>, dout: &mut [u8]) -> Result<(), i32> {
    let secret_size = secret.len() as u32;
    let seed_size = seed.len() as u32;
    let dout_size = dout.len() as u32;
    let heap = match heap {
        Some(heap) => heap,
        None => core::ptr::null_mut(),
    };
    let dev_id = match dev_id {
        Some(dev_id) => dev_id,
        None => sys::INVALID_DEVID,
    };
    let rc = unsafe {
        sys::wc_PRF(dout.as_mut_ptr(), dout_size,
            secret.as_ptr(), secret_size,
            seed.as_ptr(), seed_size,
            hash_type, heap, dev_id)
    };
    if rc != 0 {
        return Err(rc);
    }
    Ok(())
}
