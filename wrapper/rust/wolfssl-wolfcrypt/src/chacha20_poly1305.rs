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
This module provides a Rust wrapper for the wolfCrypt library's
ChaCha20-Poly1305 functionality.
*/

#![cfg(chacha20_poly1305)]

use crate::sys;
use std::mem::MaybeUninit;

pub struct ChaCha20Poly1305 {
    wc_ccp: sys::ChaChaPoly_Aead,
}

impl ChaCha20Poly1305 {
    pub const KEYSIZE: usize = sys::CHACHA20_POLY1305_AEAD_KEYSIZE as usize;
    pub const IV_SIZE: usize = sys::CHACHA20_POLY1305_AEAD_IV_SIZE as usize;
    pub const AUTH_TAG_SIZE: usize = sys::CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE as usize;

    /// Decrypt an input message from `ciphertext` using the ChaCha20 stream
    /// cipher into the `plaintext` output buffer. It also performs Poly-1305
    /// authentication, comparing the given `auth_tag` to an authentication
    /// generated with the `aad` (additional authentication data). If Err is
    /// returned, the output data, `plaintext` is undefined. However, callers
    /// must unconditionally zeroize the output buffer to guard against
    /// leakage of cleartext data.
    ///
    /// # Parameters
    ///
    /// * `key`: Encryption key (must be 32 bytes).
    /// * `iv`: Initialization Vector (must be 12 bytes).
    /// * `aad`: Additional authenticated data (can be any length).
    /// * `ciphertext`: Input buffer containing encrypted cipher text.
    /// * `auth_tag`: Input buffer containing authentication tag (must be 16
    ///   bytes).
    /// * `plaintext`: Output buffer containing decrypted plain text.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    pub fn decrypt(key: &[u8], iv: &[u8], aad: &[u8], ciphertext: &[u8],
        auth_tag: &[u8], plaintext: &mut [u8]) -> Result<(), i32> {
        if key.len() != Self::KEYSIZE {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        if iv.len() != Self::IV_SIZE {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        if auth_tag.len() != Self::AUTH_TAG_SIZE {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let aad_size = aad.len() as u32;
        let ciphertext_size = ciphertext.len() as u32;
        let rc = unsafe {
            sys::wc_ChaCha20Poly1305_Decrypt(key.as_ptr(), iv.as_ptr(),
                aad.as_ptr(), aad_size, ciphertext.as_ptr(),
                ciphertext_size, auth_tag.as_ptr(), plaintext.as_mut_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Encrypt an input message from `plaintext` using the ChaCha20 stream
    /// cipher into the `ciphertext` output buffer performing Poly-1305
    /// authentication on the cipher text and storing the generated
    /// authentication tag in the `auth_tag` output buffer.
    ///
    /// # Parameters
    ///
    /// * `key`: Encryption key (must be 32 bytes).
    /// * `iv`: Initialization Vector (must be 12 bytes).
    /// * `aad`: Additional authenticated data (can be any length).
    /// * `plaintext`: Input plain text to encrypt.
    /// * `ciphertext`: Output buffer for encrypted cipher text.
    /// * `auth_tag`: Output buffer for authentication tag (must be 16 bytes).
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    pub fn encrypt(key: &[u8], iv: &[u8], aad: &[u8], plaintext: &[u8],
        ciphertext: &mut [u8], auth_tag: &mut [u8]) -> Result<(), i32> {
        if key.len() != Self::KEYSIZE {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        if iv.len() != Self::IV_SIZE {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        if auth_tag.len() != Self::AUTH_TAG_SIZE {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let aad_size = aad.len() as u32;
        let plaintext_size = plaintext.len() as u32;
        let rc = unsafe {
            sys::wc_ChaCha20Poly1305_Encrypt(key.as_ptr(), iv.as_ptr(),
                aad.as_ptr(), aad_size, plaintext.as_ptr(), plaintext_size,
                ciphertext.as_mut_ptr(), auth_tag.as_mut_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Create a new ChaCha20Poly1305 instance.
    ///
    /// # Parameters
    ///
    /// * `key`: Encryption key (must be 32 bytes).
    /// * `iv`: Initialization Vector (must be 12 bytes).
    /// * `encrypt`: Whether the instance will be used to encrypt (true) or
    ///   decrypt (false).
    ///
    /// Returns either Ok(chacha20poly1305) on success or Err(e) containing the
    /// wolfSSL library error code value.
    pub fn new(key: &[u8], iv: &[u8], encrypt: bool) -> Result<Self, i32> {
        if key.len() != Self::KEYSIZE {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        if iv.len() != Self::IV_SIZE {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let mut wc_ccp: MaybeUninit<sys::ChaChaPoly_Aead> = MaybeUninit::uninit();
        let rc = unsafe {
            sys::wc_ChaCha20Poly1305_Init(wc_ccp.as_mut_ptr(), key.as_ptr(),
                iv.as_ptr(), if encrypt {1} else {0})
        };
        if rc != 0 {
            return Err(rc);
        }
        let wc_ccp = unsafe { wc_ccp.assume_init() };
        let chacha20poly1305 = ChaCha20Poly1305 { wc_ccp };
        Ok(chacha20poly1305)
    }

    /// Update AAD (additional authenticated data).
    ///
    /// This function should be called before `update_data()`.
    ///
    /// # Parameters
    ///
    /// * `aad`: Additional authenticated data.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    pub fn update_aad(&mut self, aad: &[u8]) -> Result<(), i32> {
        let aad_size = aad.len() as u32;
        let rc = unsafe {
            sys::wc_ChaCha20Poly1305_UpdateAad(&mut self.wc_ccp,
                aad.as_ptr(), aad_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Update data (add additional input data to decrypt or encrypt).
    ///
    /// This function can be called multiple times. If AAD is used, the
    /// `update_aad()` function must be called before this function. The
    /// `finalize()` function should be called after adding all input data to
    /// finalize the operation and compute the authentication tag.
    ///
    /// # Parameters
    ///
    /// * `din`: Additional input data to decrypt or encrypt.
    /// * `dout`: Buffer in which to store output data (must be the same length
    ///   as the input buffer).
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    pub fn update_data(&mut self, din: &[u8], dout: &mut [u8]) -> Result<(), i32> {
        if din.len() != dout.len() {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let din_size = din.len() as u32;
        let rc = unsafe {
            sys::wc_ChaCha20Poly1305_UpdateData(&mut self.wc_ccp,
                din.as_ptr(), dout.as_mut_ptr(), din_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Finalize the decrypt/encrypt operation.
    ///
    /// This function consumes the `ChaCha20Poly1305` instance. The
    /// `update_data()` function must be called before calling this function to
    /// add all input data.
    ///
    /// # Parameters
    ///
    /// * `auth_tag`: Output buffer for authentication tag (must be 16 bytes).
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    pub fn finalize(mut self, auth_tag: &mut [u8]) -> Result<(), i32> {
        if auth_tag.len() != Self::AUTH_TAG_SIZE {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let rc = unsafe {
            sys::wc_ChaCha20Poly1305_Final(&mut self.wc_ccp,
                auth_tag.as_mut_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}
