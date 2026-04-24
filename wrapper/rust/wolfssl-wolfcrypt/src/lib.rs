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

#![no_std]

/* bindgen-generated bindings to the C library */
pub mod sys;

/// Zeroize the raw bytes of a value. For use in `zeroize()` methods on C FFI
/// structs where `#[derive(Zeroize)]` cannot be used.
///
/// # Safety
///
/// `val` must be a valid, initialized value whose entire `size_of_val` byte
/// representation is safe to overwrite with zeroes.
pub(crate) unsafe fn zeroize_raw<T>(val: &mut T) {
    use zeroize::Zeroize;
    unsafe {
        core::slice::from_raw_parts_mut(
            val as *mut T as *mut u8,
            core::mem::size_of_val(val),
        ).zeroize();
    }
}

pub mod aes;
pub mod blake2;
pub mod chacha20_poly1305;
pub mod cmac;
pub mod curve25519;
pub mod dh;
pub mod dilithium;
pub mod ecc;
#[cfg(feature = "signature")]
pub mod ecdsa;
pub mod ed25519;
pub mod ed448;
pub mod fips;
pub mod hkdf;
pub mod hmac;
pub mod kdf;
pub mod lms;
pub mod mlkem;
pub mod prf;
pub mod random;
pub mod rsa;
#[cfg(feature = "signature")]
pub mod rsa_pkcs1v15;
pub mod sha;
#[cfg(feature = "digest")]
pub mod sha_digest;

/// Convert a buffer length to `u32`, returning `BUFFER_E` if it overflows.
pub(crate) fn buffer_len_to_u32(len: usize) -> Result<u32, i32> {
    u32::try_from(len).map_err(|_| sys::wolfCrypt_ErrorCodes_BUFFER_E)
}

/// Convert a buffer length to `i32`, returning `BUFFER_E` if it overflows.
pub(crate) fn buffer_len_to_i32(len: usize) -> Result<i32, i32> {
    i32::try_from(len).map_err(|_| sys::wolfCrypt_ErrorCodes_BUFFER_E)
}

/// Initialize resources used by wolfCrypt.
///
/// # Returns
///
/// Returns either Ok(()) on success or Err(e) containing the wolfSSL
/// library error code value.
///
/// # Example
///
/// ```rust
/// use wolfssl_wolfcrypt::*;
/// wolfcrypt_init().expect("Error with wolfcrypt_init()");
/// // ... use the library ...
/// wolfcrypt_cleanup().expect("wolfCrypt_Cleanup failed");
/// ```
pub fn wolfcrypt_init() -> Result<(), i32> {
    let rc = unsafe { sys::wolfCrypt_Init() };
    if rc != 0 {
        return Err(rc);
    }
    Ok(())
}

/// Clean up resources used by wolfCrypt.
///
/// # Returns
///
/// Returns either Ok(()) on success or Err(e) containing the wolfSSL
/// library error code value.
///
/// See also: [`wolfcrypt_init`]
pub fn wolfcrypt_cleanup() -> Result<(), i32> {
    let rc = unsafe { sys::wolfCrypt_Cleanup() };
    if rc != 0 {
        return Err(rc);
    }
    Ok(())
}
