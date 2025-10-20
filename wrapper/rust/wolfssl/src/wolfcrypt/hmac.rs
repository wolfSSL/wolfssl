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
This module provides a Rust wrapper for the wolfCrypt library's HMAC
functionality.

It leverages the `wolfssl-sys` crate for low-level FFI bindings, encapsulating
the raw C functions in a memory-safe and easy-to-use Rust API.
*/

use wolfssl_sys as ws;

use std::mem::MaybeUninit;

/// Rust wrapper for wolfSSL `Hmac` object.
pub struct HMAC {
    wc_hmac: ws::Hmac,
}

impl HMAC {
    pub const TYPE_MD5: i32 = ws::wc_HashType_WC_HASH_TYPE_MD5 as i32;
    pub const TYPE_SHA: i32 = ws::wc_HashType_WC_HASH_TYPE_SHA as i32;
    pub const TYPE_SHA256: i32 = ws::wc_HashType_WC_HASH_TYPE_SHA256 as i32;
    pub const TYPE_SHA512: i32 = ws::wc_HashType_WC_HASH_TYPE_SHA512 as i32;
    pub const TYPE_SHA512_224: i32 = ws::wc_HashType_WC_HASH_TYPE_SHA512_224 as i32;
    pub const TYPE_SHA512_256: i32 = ws::wc_HashType_WC_HASH_TYPE_SHA512_256 as i32;
    pub const TYPE_SHA384: i32 = ws::wc_HashType_WC_HASH_TYPE_SHA384 as i32;
    pub const TYPE_SHA224: i32 = ws::wc_HashType_WC_HASH_TYPE_SHA224 as i32;
    pub const TYPE_SHA3_224: i32 = ws::wc_HashType_WC_HASH_TYPE_SHA3_224 as i32;
    pub const TYPE_SHA3_256: i32 = ws::wc_HashType_WC_HASH_TYPE_SHA3_256 as i32;
    pub const TYPE_SHA3_384: i32 = ws::wc_HashType_WC_HASH_TYPE_SHA3_384 as i32;
    pub const TYPE_SHA3_512: i32 = ws::wc_HashType_WC_HASH_TYPE_SHA3_512 as i32;

    /// Get HMAC hash size by type.
    ///
    /// # Parameters
    ///
    /// * `typ`: Hash type, one of `HMAC::TYPE_*`.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the HMAC hash size or Err(e)
    /// containing the wolfSSL library error code value.
    pub fn get_hmac_size_by_type(typ: i32) -> Result<usize, i32> {
        let rc = unsafe { ws::wc_HmacSizeByType(typ) };
        if rc < 0 {
            return Err(rc);
        }
        Ok(rc as u32 as usize)
    }

    /// Create a new HMAC object with the given hash type and encryption key.
    ///
    /// # Parameters
    ///
    /// * `typ`: Hash type, one of `HMAC::TYPE_*`.
    /// * `key`: Encryption key.
    ///
    /// # Returns
    ///
    /// Returns either Ok(hmac) containing the HMAC struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::hmac::HMAC;
    /// let key = [0x42u8; 16];
    /// let mut hmac = HMAC::new(HMAC::TYPE_SHA256, &key).expect("Error with new()");
    /// ```
    pub fn new(typ: i32, key: &[u8]) -> Result<Self, i32> {
        let key_size = key.len() as u32;
        let mut wc_hmac: MaybeUninit<ws::Hmac> = MaybeUninit::uninit();
        let rc = unsafe {
            ws::wc_HmacInit(wc_hmac.as_mut_ptr(), core::ptr::null_mut(), ws::INVALID_DEVID)
        };
        if rc != 0 {
            return Err(rc);
        }
        let wc_hmac = unsafe { wc_hmac.assume_init() };
        let mut hmac = HMAC { wc_hmac };
        let rc = unsafe {
            ws::wc_HmacSetKey(&mut hmac.wc_hmac, typ, key.as_ptr(), key_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(hmac)
    }

    /// Create a new HMAC object with the given hash type and encryption key,
    /// allowing for short encryption keys (< 112 bits) to be used.
    ///
    /// # Parameters
    ///
    /// * `typ`: Hash type, one of `HMAC::TYPE_*`.
    /// * `key`: Encryption key.
    ///
    /// # Returns
    ///
    /// Returns either Ok(hmac) containing the HMAC struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::hmac::HMAC;
    /// let key = [0x42u8; 3];
    /// let mut hmac = HMAC::new_allow_short_key(HMAC::TYPE_SHA256, &key).expect("Error with new_allow_short_key()");
    /// ```
    pub fn new_allow_short_key(typ: i32, key: &[u8]) -> Result<Self, i32> {
        let key_size = key.len() as u32;
        let mut wc_hmac: MaybeUninit<ws::Hmac> = MaybeUninit::uninit();
        let rc = unsafe {
            ws::wc_HmacInit(wc_hmac.as_mut_ptr(), core::ptr::null_mut(), ws::INVALID_DEVID)
        };
        if rc != 0 {
            return Err(rc);
        }
        let wc_hmac = unsafe { wc_hmac.assume_init() };
        let mut hmac = HMAC { wc_hmac };
        let rc = unsafe {
            ws::wc_HmacSetKey_ex(&mut hmac.wc_hmac, typ, key.as_ptr(), key_size, 1)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(hmac)
    }

    /// Update the message to authenticate using HMAC.
    ///
    /// This function may be called multiple times to update the message to
    /// hash.
    ///
    /// # Parameters
    ///
    /// * `data`: Buffer containing message data to append.
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
    /// let key = [0x42u8; 16];
    /// let mut hmac = HMAC::new(HMAC::TYPE_SHA256, &key).expect("Error with new()");
    /// hmac.update(b"input").expect("Error with update()");
    /// ```
    pub fn update(&mut self, data: &[u8]) -> Result<(), i32> {
        let data_size = data.len() as u32;
        let rc = unsafe {
            ws::wc_HmacUpdate(&mut self.wc_hmac, data.as_ptr(), data_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Compute the final hash of the input message.
    ///
    /// # Parameters
    ///
    /// * `hash`: Output buffer to contain the calculated hash. The length must
    ///   match that returned by `get_hmac_size()`.
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
    /// let key = [0x42u8; 16];
    /// let mut hmac = HMAC::new(HMAC::TYPE_SHA256, &key).expect("Error with new()");
    /// hmac.update(b"input").expect("Error with update()");
    /// let hash_size = hmac.get_hmac_size().expect("Error with get_hmac_size()");
    /// let mut hash = vec![0u8; hash_size];
    /// hmac.finalize(&mut hash).expect("Error with finalize()");
    /// ```
    pub fn finalize(&mut self, hash: &mut [u8]) -> Result<(), i32> {
        // Check the output buffer size since wc_HmacFinal() does not accept
        // a length parameter.
        let typ = self.wc_hmac.macType as u32 as i32;
        let rc = unsafe { ws::wc_HmacSizeByType(typ) };
        if rc < 0 {
            return Err(rc);
        }
        let expected_size = rc as u32 as usize;
        if hash.len() != expected_size {
            return Err(ws::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let rc = unsafe {
            ws::wc_HmacFinal(&mut self.wc_hmac, hash.as_mut_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Get the HMAC hash size.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the HMAC hash size or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::hmac::HMAC;
    /// let key = [0x42u8; 16];
    /// let mut hmac = HMAC::new(HMAC::TYPE_SHA256, &key).expect("Error with new()");
    /// hmac.update(b"input").expect("Error with update()");
    /// let hash_size = hmac.get_hmac_size().expect("Error with get_hmac_size()");
    /// let mut hash = vec![0u8; hash_size];
    /// hmac.finalize(&mut hash).expect("Error with finalize()");
    /// ```
    pub fn get_hmac_size(&mut self) -> Result<usize, i32> {
        let typ = self.wc_hmac.macType as u32 as i32;
        let rc = unsafe { ws::wc_HmacSizeByType(typ) };
        if rc < 0 {
            return Err(rc);
        }
        let expected_size = rc as u32 as usize;
        Ok(expected_size)
    }
}

impl Drop for HMAC {
    /// Safely free the underlying wolfSSL Hmac context.
    ///
    /// This calls the `wc_HmacFree()` wolfssl library function.
    ///
    /// The Rust Drop trait guarantees that this method is called when the
    /// HMAC struct instance goes out of scope, automatically cleaning up
    /// resources and preventing memory leaks.
    fn drop(&mut self) {
        unsafe { ws::wc_HmacFree(&mut self.wc_hmac); }
    }
}

/// HMAC Key Derivation Function (HKDF) functionality.
pub struct HKDF {
}

impl HKDF {
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
    /// use wolfssl::wolfcrypt::hmac::{HMAC,HKDF};
    /// use wolfssl_sys as ws;
    /// let ikm = b"MyPassword0";
    /// let salt = b"12345678ABCDEFGH";
    /// let mut extract_out = [0u8; ws::WC_SHA256_DIGEST_SIZE as usize];
    /// HKDF::extract(HMAC::TYPE_SHA256, Some(salt), ikm, &mut extract_out).expect("Error with extract()");
    /// ```
    pub fn extract(typ: i32, salt: Option<&[u8]>, key: &[u8], out: &mut [u8]) -> Result<(), i32> {
        let mut salt_ptr = core::ptr::null();
        let mut salt_size = 0u32;
        if let Some(salt) = salt {
            salt_ptr = salt.as_ptr();
            salt_size = salt.len() as u32;
        }
        let key_size = key.len() as u32;
        if out.len() != HMAC::get_hmac_size_by_type(typ)? {
            return Err(ws::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let rc = unsafe {
            ws::wc_HKDF_Extract(typ, salt_ptr, salt_size,
                key.as_ptr(), key_size, out.as_mut_ptr())
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
    /// * `key`: Key to use for KDF (typically output of `HKDF::extract()`).
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
    /// use wolfssl::wolfcrypt::hmac::{HMAC,HKDF};
    /// use wolfssl_sys as ws;
    /// let ikm = b"MyPassword0";
    /// let salt = b"12345678ABCDEFGH";
    /// let mut extract_out = [0u8; ws::WC_SHA256_DIGEST_SIZE as usize];
    /// HKDF::extract(HMAC::TYPE_SHA256, Some(salt), ikm, &mut extract_out).expect("Error with extract()");
    /// let info = b"0";
    /// let mut expand_out = [0u8; 16];
    /// HKDF::expand(HMAC::TYPE_SHA256, &extract_out, Some(info), &mut expand_out).expect("Error with expand()");
    /// ```
    pub fn expand(typ: i32, key: &[u8], info: Option<&[u8]>, out: &mut [u8]) -> Result<(), i32> {
        let key_size = key.len() as u32;
        let mut info_ptr = core::ptr::null();
        let mut info_size = 0u32;
        if let Some(info) = info {
            info_ptr = info.as_ptr();
            info_size = info.len() as u32;
        }
        let out_size = out.len() as u32;
        let rc = unsafe {
            ws::wc_HKDF_Expand(typ, key.as_ptr(), key_size,
                info_ptr, info_size, out.as_mut_ptr(), out_size)
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
    /// This one-shot function is a combination of `extract()` and `expand()`.
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
    /// use wolfssl::wolfcrypt::hmac::{HMAC,HKDF};
    /// let ikm = b"MyPassword0";
    /// let salt = b"12345678ABCDEFGH";
    /// let info = b"0";
    /// let mut out = [0u8; 16];
    /// HKDF::hkdf(HMAC::TYPE_SHA256, ikm, Some(salt), Some(info), &mut out).expect("Error with hkdf()");
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
            ws::wc_HKDF(typ, key.as_ptr(), key_size, salt_ptr, salt_size,
                info_ptr, info_size, out.as_mut_ptr(), out_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}
