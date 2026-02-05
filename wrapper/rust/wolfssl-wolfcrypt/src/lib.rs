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

/* bindgen-generated bindings to the C library */
pub mod sys;

pub mod aes;
pub mod blake2;
pub mod chacha20_poly1305;
pub mod cmac;
pub mod curve25519;
pub mod dh;
pub mod ecc;
pub mod ed25519;
pub mod ed448;
pub mod fips;
pub mod hkdf;
pub mod hmac;
pub mod kdf;
pub mod prf;
pub mod random;
pub mod rsa;
pub mod sha;

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
