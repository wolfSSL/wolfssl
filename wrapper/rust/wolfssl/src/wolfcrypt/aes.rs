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
This module provides a Rust wrapper for the wolfCrypt library's Advanced
Encryption Standard (AES) functionality.
*/

#![cfg(aes)]

use crate::sys;
use std::mem::{size_of, MaybeUninit};

/// AES Cipher Block Chaining (CBC) mode.
///
/// # Example
/// ```rust
/// #[cfg(aes_cbc)]
/// {
/// use wolfssl::wolfcrypt::aes::CBC;
/// let mut cbc = CBC::new().expect("Failed to create CBC");
/// let key: &[u8; 16] = b"0123456789abcdef";
/// let iv: &[u8; 16] = b"1234567890abcdef";
/// let msg: [u8; 16] = [
///     0x6e, 0x6f, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74,
///     0x68, 0x65, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x20,
/// ];
/// let expected_cipher: [u8; 16] = [
///     0x95, 0x94, 0x92, 0x57, 0x5f, 0x42, 0x81, 0x53,
///     0x2c, 0xcc, 0x9d, 0x46, 0x77, 0xa2, 0x33, 0xcb
/// ];
/// cbc.init_encrypt(key, iv).expect("Error with init_encrypt()");
/// let mut cipher: [u8; 16] = [0; 16];
/// cbc.encrypt(&msg, &mut cipher).expect("Error with encrypt()");
/// assert_eq!(&cipher, &expected_cipher);
/// let mut plain_out = [0; 16];
/// cbc.init_decrypt(key, iv).expect("Error with init_decrypt()");
/// cbc.decrypt(&cipher, &mut plain_out).expect("Error with decrypt()");
/// assert_eq!(&plain_out, &msg);
/// }
/// ```
#[cfg(aes_cbc)]
pub struct CBC {
    ws_aes: sys::Aes,
}
#[cfg(aes_cbc)]
impl CBC {
    /// Create a new `CBC` instance.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(CBC) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn new() -> Result<Self, i32> {
        Self::new_ex(None, None)
    }

    /// Create a new `CBC` instance with optional heap and device ID.
    ///
    /// # Parameters
    ///
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(CBC) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn new_ex(heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let ws_aes = new_ws_aes(heap, dev_id)?;
        let cbc = CBC {ws_aes};
        Ok(cbc)
    }

    fn init(&mut self, key: &[u8], iv: &[u8], dir: i32) -> Result<(), i32> {
        let key_ptr = key.as_ptr() as *const u8;
        let key_size = key.len() as u32;
        let iv_ptr = iv.as_ptr() as *const u8;
        if iv.len() as u32 != sys::WC_AES_BLOCK_SIZE {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesSetKey(&mut self.ws_aes, key_ptr, key_size, iv_ptr, dir)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Initialize a CBC instance for encryption.
    ///
    /// This method must be called before calling `encrypt()`.
    ///
    /// # Parameters
    ///
    /// * `key`: A slice containing the encryption key to use. The key must be
    /// 16, 24, or 32 bytes in length.
    /// * `iv`: A slice containing the initialization vector (IV) to use. The
    /// IV must be 16 bytes in length.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn init_encrypt(&mut self, key: &[u8], iv: &[u8]) -> Result<(), i32> {
        return self.init(key, iv, sys::AES_ENCRYPTION as i32);
    }

    /// Initialize a CBC instance for decryption.
    ///
    /// This method must be called before calling `decrypt()`.
    ///
    /// # Parameters
    ///
    /// * `key`: A slice containing the decryption key to use. The key must be
    /// 16, 24, or 32 bytes in length.
    /// * `iv`: A slice containing the initialization vector (IV) to use. The
    /// IV must be 16 bytes in length.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn init_decrypt(&mut self, key: &[u8], iv: &[u8]) -> Result<(), i32> {
        return self.init(key, iv, sys::AES_DECRYPTION as i32);
    }

    /// Encrypt data.
    ///
    /// The `init_encrypt()` method must be called before calling this method.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to encrypt. The size of the data must be a multiple of
    /// 16 bytes.
    /// * `dout`: Buffer in which to store the encrypted data. The size of
    /// the buffer must match that of the `din` buffer.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn encrypt<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesCbcEncrypt(&mut self.ws_aes, out_ptr, in_ptr, in_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Decrypt data.
    ///
    /// The `init_decrypt()` method must be called before calling this method.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to decrypt. The size of the data must be a multiple of
    /// 16 bytes.
    /// * `dout`: Buffer in which to store the decrypted data. The size of
    /// the data must match that of the `din` slice.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn decrypt<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesCbcDecrypt(&mut self.ws_aes, out_ptr, in_ptr, in_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}
#[cfg(aes_cbc)]
impl Drop for CBC {
    /// Safely free the wolfSSL resources.
    fn drop(&mut self) {
        unsafe { sys::wc_AesFree(&mut self.ws_aes); }
    }
}

/// AES Counter with CBC-MAC (CCM) mode.
///
/// # Example
/// ```rust
/// #[cfg(aes_ccm)]
/// {
/// use wolfssl::wolfcrypt::aes::CCM;
/// let key: [u8; 16] = [
///     0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
///     0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf
/// ];
/// let nonce: [u8; 13] = [
///     0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0xa0,
///     0xa1, 0xa2, 0xa3, 0xa4, 0xa5 ];
/// let plaintext: [u8; 23] = [
///     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
///     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
///     0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e
/// ];
/// let auth_data: [u8; 8] = [
///     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
/// ];
/// let expected_ciphertext: [u8; 23] = [
///     0x58, 0x8c, 0x97, 0x9a, 0x61, 0xc6, 0x63, 0xd2,
///     0xf0, 0x66, 0xd0, 0xc2, 0xc0, 0xf9, 0x89, 0x80,
///     0x6d, 0x5f, 0x6b, 0x61, 0xda, 0xc3, 0x84
/// ];
/// let expected_auth_tag: [u8; 8] = [
///     0x17, 0xe8, 0xd1, 0x2c, 0xfd, 0xf9, 0x26, 0xe0
/// ];
///
/// let mut ccm = CCM::new().expect("Failed to create CCM");
/// ccm.init(&key).expect("Error with init()");
/// let mut auth_tag_out: [u8; 8] = [0; 8];
/// let mut cipher_out: [u8; 23] = [0; 23];
/// ccm.encrypt(&plaintext, &mut cipher_out,
///     &nonce, &auth_data, &mut auth_tag_out).expect("Error with encrypt()");
/// assert_eq!(cipher_out, expected_ciphertext);
/// assert_eq!(auth_tag_out, expected_auth_tag);
/// ccm.init(&key).expect("Error with init()");
/// let mut plain_out: [u8; 23] = [0; 23];
/// ccm.decrypt(&cipher_out, &mut plain_out,
///     &nonce, &auth_data, &auth_tag_out).expect("Error with decrypt()");
/// assert_eq!(plain_out, plaintext);
/// }
/// ```
#[cfg(aes_ccm)]
pub struct CCM {
    ws_aes: sys::Aes,
}
#[cfg(aes_ccm)]
impl CCM {
    /// Create a new `CCM` instance.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(CCM) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn new() -> Result<Self, i32> {
        Self::new_ex(None, None)
    }

    /// Create a new `CCM` instance with optional heap and device ID.
    ///
    /// # Parameters
    ///
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(CCM) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn new_ex(heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let ws_aes = new_ws_aes(heap, dev_id)?;
        let ccm = CCM {ws_aes};
        Ok(ccm)
    }

    /// Initialize a CCM instance for encryption or decryption.
    ///
    /// This method must be called before calling `encrypt()` or `decrypt()`.
    ///
    /// # Parameters
    ///
    /// * `key`: A slice containing the encryption key to use. The key must be
    /// 16, 24, or 32 bytes in length.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn init(&mut self, key: &[u8]) -> Result<(), i32> {
        let key_ptr = key.as_ptr() as *const u8;
        let key_size = key.len() as u32;
        let rc = unsafe {
            sys::wc_AesCcmSetKey(&mut self.ws_aes, key_ptr, key_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Encrypt data.
    ///
    /// The `init()` method must be called before calling this method.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to encrypt.
    /// * `dout`: Buffer in which to store the encrypted data. The size of
    /// the buffer must match that of the `din` buffer.
    /// * `nonce`: Nonce (number used once).
    /// * `auth`: Authentication data input.
    /// * `auth_tag`: Buffer in which to store the authentication tag.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn encrypt<I,O,N,A>(&mut self, din: &[I], dout: &mut [O], nonce: &[N], auth: &[A], auth_tag: &mut [A]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        let nonce_ptr = nonce.as_ptr() as *const u8;
        let nonce_size = (nonce.len() * size_of::<O>()) as u32;
        let auth_ptr = auth.as_ptr() as *const u8;
        let auth_size = (auth.len() * size_of::<O>()) as u32;
        let auth_tag_ptr = auth_tag.as_ptr() as *mut u8;
        let auth_tag_size = (auth_tag.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesCcmEncrypt(&mut self.ws_aes, out_ptr,
                in_ptr, in_size,
                nonce_ptr, nonce_size,
                auth_tag_ptr, auth_tag_size,
                auth_ptr, auth_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Decrypt data.
    ///
    /// The `init()` method must be called before calling this method.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to decrypt.
    /// * `dout`: Buffer in which to store the decrypted data. The size of
    /// the buffer must match that of the `din` buffer.
    /// * `nonce`: Nonce (number used once).
    /// * `auth`: Authentication data input.
    /// * `auth_tag`: Authentication tag input to verify.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn decrypt<I,O,N,A>(&mut self, din: &[I], dout: &mut [O], nonce: &[N], auth: &[A], auth_tag: &[A]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        let nonce_ptr = nonce.as_ptr() as *const u8;
        let nonce_size = (nonce.len() * size_of::<O>()) as u32;
        let auth_ptr = auth.as_ptr() as *const u8;
        let auth_size = (auth.len() * size_of::<O>()) as u32;
        let auth_tag_ptr = auth_tag.as_ptr() as *const u8;
        let auth_tag_size = (auth_tag.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesCcmDecrypt(&mut self.ws_aes, out_ptr,
                in_ptr, in_size,
                nonce_ptr, nonce_size,
                auth_tag_ptr, auth_tag_size,
                auth_ptr, auth_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}
#[cfg(aes_ccm)]
impl Drop for CCM {
    /// Safely free the wolfSSL resources.
    fn drop(&mut self) {
        unsafe { sys::wc_AesFree(&mut self.ws_aes); }
    }
}

/// AES Cipher FeedBack (CFB) mode.
///
/// # Example
/// ```rust
/// #[cfg(aes_cfb)]
/// {
/// use wolfssl::wolfcrypt::aes::CFB;
/// let mut cfb = CFB::new().expect("Failed to create CFB");
/// let key: [u8; 16] = [
///     0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
///     0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
/// ];
/// let iv: [u8; 16] = [
///     0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
///     0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
/// ];
/// let msg: [u8; 48] = [
///     0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
///     0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
///     0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
///     0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
///     0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,
///     0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef
/// ];
/// let cipher: [u8; 48] = [
///     0x3b,0x3f,0xd9,0x2e,0xb7,0x2d,0xad,0x20,
///     0x33,0x34,0x49,0xf8,0xe8,0x3c,0xfb,0x4a,
///     0xc8,0xa6,0x45,0x37,0xa0,0xb3,0xa9,0x3f,
///     0xcd,0xe3,0xcd,0xad,0x9f,0x1c,0xe5,0x8b,
///     0x26,0x75,0x1f,0x67,0xa3,0xcb,0xb1,0x40,
///     0xb1,0x80,0x8c,0xf1,0x87,0xa4,0xf4,0xdf
/// ];
/// cfb.init(&key, &iv).expect("Error with init()");
/// let mut outbuf: [u8; 48] = [0; 48];
/// cfb.encrypt(&msg[0..32], &mut outbuf[0..32]).expect("Error with encrypt()");
/// cfb.encrypt(&msg[32..48], &mut outbuf[32..48]).expect("Error with encrypt()");
/// assert_eq!(outbuf, cipher);
/// cfb.init(&key, &iv).expect("Error with init()");
/// let mut plain: [u8; 48] = [0; 48];
/// #[cfg(aes_decrypt)]
/// {
/// cfb.decrypt(&outbuf, &mut plain).expect("Error with decrypt()");
/// assert_eq!(plain, msg);
/// }
/// }
/// ```
#[cfg(aes_cfb)]
pub struct CFB {
    ws_aes: sys::Aes,
}
#[cfg(aes_cfb)]
impl CFB {
    /// Create a new `CFB` instance.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(CFB) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn new() -> Result<Self, i32> {
        Self::new_ex(None, None)
    }

    /// Create a new `CFB` instance with optional heap and device ID.
    ///
    /// # Parameters
    ///
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(CFB) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn new_ex(heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let ws_aes = new_ws_aes(heap, dev_id)?;
        let cfb = CFB {ws_aes};
        Ok(cfb)
    }

    /// Initialize a CFB instance for encryption or decryption.
    ///
    /// This method must be called before calling `encrypt()`, `encrypt1()`,
    /// `encrypt8()`, `decrypt()`, `decrypt1()`, or `decrypt8()`.
    ///
    /// # Parameters
    ///
    /// * `key`: A slice containing the encryption key to use. The key must be
    /// 16, 24, or 32 bytes in length.
    /// * `iv`: A slice containing the initialization vector (IV) to use. The
    /// IV must be 16 bytes in length.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn init(&mut self, key: &[u8], iv: &[u8]) -> Result<(), i32> {
        let key_ptr = key.as_ptr() as *const u8;
        let key_size = key.len() as u32;
        let iv_ptr = iv.as_ptr() as *const u8;
        if iv.len() as u32 != sys::WC_AES_BLOCK_SIZE {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesSetKey(&mut self.ws_aes, key_ptr, key_size,
                iv_ptr, sys::AES_ENCRYPTION as i32)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Encrypt data in full-block CFB mode.
    ///
    /// The `init()` method must be called before calling this method.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to encrypt.
    /// * `dout`: Buffer in which to store the encrypted data. The size of
    /// the buffer must match that of the `din` buffer.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn encrypt<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesCfbEncrypt(&mut self.ws_aes, out_ptr, in_ptr, in_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Encrypt data in 1-bit CFB mode.
    ///
    /// The `init()` method must be called before calling this method.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to encrypt.
    /// * `dout`: Buffer in which to store the encrypted data. The size of
    /// the buffer must match that of the `din` buffer.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn encrypt1<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesCfb1Encrypt(&mut self.ws_aes, out_ptr, in_ptr, in_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Encrypt data in 8-bit CFB mode.
    ///
    /// The `init()` method must be called before calling this method.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to encrypt.
    /// * `dout`: Buffer in which to store the encrypted data. The size of
    /// the buffer must match that of the `din` buffer.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn encrypt8<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesCfb8Encrypt(&mut self.ws_aes, out_ptr, in_ptr, in_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Decrypt data in full-block CFB mode.
    ///
    /// The `init()` method must be called before calling this method.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to decrypt.
    /// * `dout`: Buffer in which to store the decrypted data. The size of
    /// the buffer must match that of the `din` buffer.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    #[cfg(aes_decrypt)]
    pub fn decrypt<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesCfbDecrypt(&mut self.ws_aes, out_ptr, in_ptr, in_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Decrypt data in 1-bit CFB mode.
    ///
    /// The `init()` method must be called before calling this method.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to decrypt.
    /// * `dout`: Buffer in which to store the decrypted data. The size of
    /// the buffer must match that of the `din` buffer.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    #[cfg(aes_decrypt)]
    pub fn decrypt1<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesCfb1Decrypt(&mut self.ws_aes, out_ptr, in_ptr, in_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Decrypt data in 8-bit CFB mode.
    ///
    /// The `init()` method must be called before calling this method.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to decrypt.
    /// * `dout`: Buffer in which to store the decrypted data. The size of
    /// the buffer must match that of the `din` buffer.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    #[cfg(aes_decrypt)]
    pub fn decrypt8<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesCfb8Decrypt(&mut self.ws_aes, out_ptr, in_ptr, in_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}
#[cfg(aes_cfb)]
impl Drop for CFB {
    /// Safely free the wolfSSL resources.
    fn drop(&mut self) {
        unsafe { sys::wc_AesFree(&mut self.ws_aes); }
    }
}

/// AES Counter (CTR) mode.
///
/// # Example
/// ```rust
/// #[cfg(aes_ctr)]
/// {
/// use wolfssl::wolfcrypt::aes::CTR;
/// let iv: [u8; 16] = [
///     0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,
///     0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff
/// ];
/// let msg: [u8; 64] = [
///     0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
///     0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
///     0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
///     0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
///     0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,
///     0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
///     0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,
///     0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10
/// ];
/// let key: [u8; 16] = [
///     0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
///     0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
/// ];
/// let cipher: [u8; 64] = [
///     0x87,0x4d,0x61,0x91,0xb6,0x20,0xe3,0x26,
///     0x1b,0xef,0x68,0x64,0x99,0x0d,0xb6,0xce,
///     0x98,0x06,0xf6,0x6b,0x79,0x70,0xfd,0xff,
///     0x86,0x17,0x18,0x7b,0xb9,0xff,0xfd,0xff,
///     0x5a,0xe4,0xdf,0x3e,0xdb,0xd5,0xd3,0x5e,
///     0x5b,0x4f,0x09,0x02,0x0d,0xb0,0x3e,0xab,
///     0x1e,0x03,0x1d,0xda,0x2f,0xbe,0x03,0xd1,
///     0x79,0x21,0x70,0xa0,0xf3,0x00,0x9c,0xee
/// ];
/// let mut ctr = CTR::new().expect("Failed to create CTR");
/// ctr.init(&key, &iv).expect("Error with init()");
/// let mut outbuf: [u8; 64] = [0; 64];
/// ctr.encrypt(&msg, &mut outbuf).expect("Error with encrypt()");
/// assert_eq!(outbuf, cipher);
/// ctr.init(&key, &iv).expect("Error with init()");
/// let mut plain: [u8; 64] = [0; 64];
/// ctr.decrypt(&outbuf, &mut plain).expect("Error with decrypt()");
/// assert_eq!(plain, msg);
/// }
/// ```
#[cfg(aes_ctr)]
pub struct CTR {
    ws_aes: sys::Aes,
}
#[cfg(aes_ctr)]
impl CTR {
    /// Create a new `CTR` instance.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(CTR) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn new() -> Result<Self, i32> {
        Self::new_ex(None, None)
    }

    /// Create a new `CTR` instance with optional heap and device ID.
    ///
    /// # Parameters
    ///
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(CTR) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn new_ex(heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let ws_aes = new_ws_aes(heap, dev_id)?;
        let ctr = CTR {ws_aes};
        Ok(ctr)
    }

    /// Initialize a CTR instance for encryption or decryption.
    ///
    /// This method must be called before calling `encrypt()` or `decrypt()`.
    ///
    /// # Parameters
    ///
    /// * `key`: A slice containing the encryption key to use. The key must be
    /// 16, 24, or 32 bytes in length.
    /// * `iv`: A slice containing the initialization vector (IV) to use. The
    /// IV must be 16 bytes in length.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn init(&mut self, key: &[u8], iv: &[u8]) -> Result<(), i32> {
        let key_ptr = key.as_ptr() as *const u8;
        let key_size = key.len() as u32;
        let iv_ptr = iv.as_ptr() as *const u8;
        if iv.len() as u32 != sys::WC_AES_BLOCK_SIZE {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesSetKeyDirect(&mut self.ws_aes, key_ptr, key_size,
                iv_ptr, sys::AES_ENCRYPTION as i32)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    fn encrypt_decrypt<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesCtrEncrypt(&mut self.ws_aes, out_ptr, in_ptr, in_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Encrypt data.
    ///
    /// The `init()` method must be called before calling this method.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to encrypt.
    /// * `dout`: Buffer in which to store the encrypted data. The size of
    /// the buffer must match that of the `din` buffer.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn encrypt<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        return self.encrypt_decrypt(din, dout);
    }

    /// Decrypt data.
    ///
    /// The `init()` method must be called before calling this method.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to decrypt.
    /// * `dout`: Buffer in which to store the decrypted data. The size of
    /// the buffer must match that of the `din` buffer.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn decrypt<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        return self.encrypt_decrypt(din, dout);
    }
}
#[cfg(aes_ctr)]
impl Drop for CTR {
    /// Safely free the wolfSSL resources.
    fn drop(&mut self) {
        unsafe { sys::wc_AesFree(&mut self.ws_aes); }
    }
}

/// AES Encrypt-Then-Authenticate-Then-Translate (EAX) mode.
///
/// # Example
/// ```rust
/// #[cfg(aes_eax)]
/// {
/// use wolfssl::wolfcrypt::aes::EAX;
/// let key: [u8; 16] = [
///     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
///     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
/// ];
/// let nonce: [u8; 16] = [
///     0x3c, 0x8c, 0xc2, 0x97, 0x0a, 0x00, 0x8f, 0x75,
///     0xcc, 0x5b, 0xea, 0xe2, 0x84, 0x72, 0x58, 0xc2
/// ];
/// let auth: &[u8] = &[];
/// let msg: [u8; 32] = [
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
///     0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11
/// ];
/// let expected_cipher: [u8; 32] = [
///     0x3c, 0x44, 0x1f, 0x32, 0xce, 0x07, 0x82, 0x23,
///     0x64, 0xd7, 0xa2, 0x99, 0x0e, 0x50, 0xbb, 0x13,
///     0xd7, 0xb0, 0x2a, 0x26, 0x96, 0x9e, 0x4a, 0x93,
///     0x7e, 0x5e, 0x90, 0x73, 0xb0, 0xd9, 0xc9, 0x68
/// ];
/// let expected_auth_tag: [u8; 16] = [
///     0xdb, 0x90, 0xbd, 0xb3, 0xda, 0x3d, 0x00, 0xaf,
///     0xd0, 0xfc, 0x6a, 0x83, 0x55, 0x1d, 0xa9, 0x5e
/// ];
/// let mut cipher: [u8; 32] = [0; 32];
/// let mut auth_tag: [u8; 16] = [0; 16];
/// EAX::encrypt(&msg, &mut cipher, &key, &nonce, auth, &mut auth_tag).expect("Error with encrypt()");
/// assert_eq!(cipher, expected_cipher);
/// assert_eq!(auth_tag, expected_auth_tag);
/// let mut plain: [u8; 32] = [0; 32];
/// EAX::decrypt(&cipher, &mut plain, &key, &nonce, auth, &auth_tag).expect("Error with decrypt()");
/// assert_eq!(plain, msg);
/// }
/// ```
#[cfg(aes_eax)]
pub struct EAX {
}
#[cfg(aes_eax)]
impl EAX {
    /// Encrypt data.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to encrypt.
    /// * `dout`: Buffer in which to store the encrypted data. The size of
    /// the buffer must match that of the `din` buffer.
    /// * `key`: Encryption key to use. The key size must be 16, 24, or 32
    /// bytes.
    /// * `nonce`: Nonce (number used once).
    /// * `auth`: Authentication data input.
    /// * `auth_tag`: Buffer in which to store the authentication tag.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn encrypt<I,O>(din: &[I], dout: &mut [O], key: &[u8], nonce: &[u8],
            auth: &[u8], auth_tag: &mut [u8]) -> Result<(), i32> {
        let key_ptr = key.as_ptr() as *const u8;
        let key_size = key.len() as u32;
        let nonce_ptr = nonce.as_ptr() as *const u8;
        let nonce_size = nonce.len() as u32;
        let auth_ptr = auth.as_ptr() as *const u8;
        let auth_size = auth.len() as u32;
        let auth_tag_ptr = auth_tag.as_ptr() as *mut u8;
        let auth_tag_size = auth_tag.len() as u32;
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = din.len() as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = dout.len() as u32;
        if in_size != out_size {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesEaxEncryptAuth(key_ptr, key_size, out_ptr,
                in_ptr, in_size, nonce_ptr, nonce_size,
                auth_tag_ptr, auth_tag_size,
                auth_ptr, auth_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Decrypt data.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to decrypt.
    /// * `dout`: Buffer in which to store the decrypted data. The size of
    /// the buffer must match that of the `din` buffer.
    /// * `key`: Decryption key to use. The key size must be 16, 24, or 32
    /// bytes.
    /// * `nonce`: Nonce (number used once).
    /// * `auth`: Authentication data input.
    /// * `auth_tag`: Authentication tag input to verify.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn decrypt<I,O>(din: &[I], dout: &mut [O], key: &[u8], nonce: &[u8],
            auth: &[u8], auth_tag: &[u8]) -> Result<(), i32> {
        let key_ptr = key.as_ptr() as *const u8;
        let key_size = key.len() as u32;
        let nonce_ptr = nonce.as_ptr() as *const u8;
        let nonce_size = nonce.len() as u32;
        let auth_ptr = auth.as_ptr() as *const u8;
        let auth_size = auth.len() as u32;
        let auth_tag_ptr = auth_tag.as_ptr() as *const u8;
        let auth_tag_size = auth_tag.len() as u32;
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = din.len() as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = dout.len() as u32;
        if in_size != out_size {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesEaxDecryptAuth(key_ptr, key_size, out_ptr,
                in_ptr, in_size, nonce_ptr, nonce_size,
                auth_tag_ptr, auth_tag_size,
                auth_ptr, auth_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}

/// AES Electronic CodeBook (ECB) mode.
///
/// # Example
/// ```rust
/// #[cfg(aes_ecb)]
/// {
/// use wolfssl::wolfcrypt::aes::ECB;
/// let mut ecb = ECB::new().expect("Failed to create ECB");
/// let key_128: &[u8; 16] = b"0123456789abcdef";
/// let msg: [u8; 16] = [
///     0x6e, 0x6f, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74,
///     0x68, 0x65, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x20
/// ];
/// let verify_ecb_128: [u8; 16] = [
///     0xd0, 0xc9, 0xd9, 0xc9, 0x40, 0xe8, 0x97, 0xb6,
///     0xc8, 0x8c, 0x33, 0x3b, 0xb5, 0x8f, 0x85, 0xd1
/// ];
/// ecb.init_encrypt(key_128).expect("Error with init_encrypt()");
/// let mut outbuf: [u8; 16] = [0; 16];
/// ecb.encrypt(&msg, &mut outbuf).expect("Error with encrypt()");
/// assert_eq!(&outbuf, &verify_ecb_128);
/// outbuf = [0; 16];
/// ecb.init_decrypt(key_128).expect("Error with init_decrypt()");
/// ecb.decrypt(&verify_ecb_128, &mut outbuf).expect("Error with decrypt()");
/// assert_eq!(&outbuf, &msg);
/// }
/// ```
#[cfg(aes_ecb)]
pub struct ECB {
    ws_aes: sys::Aes,
}
#[cfg(aes_ecb)]
impl ECB {
    /// Create a new `ECB` instance.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(ECB) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn new() -> Result<Self, i32> {
        Self::new_ex(None, None)
    }

    /// Create a new `ECB` instance with optional heap and device ID.
    ///
    /// # Parameters
    ///
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(ECB) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn new_ex(heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let ws_aes = new_ws_aes(heap, dev_id)?;
        let ecb = ECB {ws_aes};
        Ok(ecb)
    }

    fn init(&mut self, key: &[u8], dir: i32) -> Result<(), i32> {
        let key_ptr = key.as_ptr() as *const u8;
        let key_size = key.len() as u32;
        let rc = unsafe {
            sys::wc_AesSetKey(&mut self.ws_aes, key_ptr, key_size,
                core::ptr::null(), dir)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Initialize a ECB instance for encryption.
    ///
    /// This method must be called before calling `encrypt()`.
    ///
    /// # Parameters
    ///
    /// * `key`: A slice containing the encryption key to use. The key must be
    /// 16, 24, or 32 bytes in length.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn init_encrypt(&mut self, key: &[u8]) -> Result<(), i32> {
        return self.init(key, sys::AES_ENCRYPTION as i32);
    }

    /// Initialize a ECB instance for decryption.
    ///
    /// This method must be called before calling `decrypt()`.
    ///
    /// # Parameters
    ///
    /// * `key`: A slice containing the decryption key to use. The key must be
    /// 16, 24, or 32 bytes in length.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn init_decrypt(&mut self, key: &[u8]) -> Result<(), i32> {
        return self.init(key, sys::AES_DECRYPTION as i32);
    }

    /// Encrypt data.
    ///
    /// The `init_encrypt()` method must be called before calling this method.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to encrypt. The size of the data must be a multiple of
    /// 16 bytes.
    /// * `dout`: Buffer in which to store the encrypted data. The size of
    /// the buffer must match that of the `din` buffer.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn encrypt<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesEcbEncrypt(&mut self.ws_aes, out_ptr, in_ptr, in_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Decrypt data.
    ///
    /// The `init_decrypt()` method must be called before calling this method.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to decrypt. The size of the data must be a multiple of
    /// 16 bytes.
    /// * `dout`: Buffer in which to store the decrypted data. The size of
    /// the buffer must match that of the `din` buffer.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn decrypt<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesEcbDecrypt(&mut self.ws_aes, out_ptr, in_ptr, in_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}
#[cfg(aes_ecb)]
impl Drop for ECB {
    /// Safely free the wolfSSL resources.
    fn drop(&mut self) {
        unsafe { sys::wc_AesFree(&mut self.ws_aes); }
    }
}

/// AES Galois/Counter Mode (GCM) mode (one shot functionality).
///
/// This struct provides one-shot encryption and decryption functionality.
/// For streaming/chunking functionality, see the `GCMStream` struct instead.
///
/// # Example
/// ```rust
/// #[cfg(aes_gcm)]
/// {
/// use wolfssl::wolfcrypt::aes::GCM;
/// let key: [u8; 16] = [
///     0x29, 0x8e, 0xfa, 0x1c, 0xcf, 0x29, 0xcf, 0x62,
///     0xae, 0x68, 0x24, 0xbf, 0xc1, 0x95, 0x57, 0xfc
/// ];
/// let iv: [u8; 12] = [
///     0x6f, 0x58, 0xa9, 0x3f, 0xe1, 0xd2, 0x07, 0xfa,
///     0xe4, 0xed, 0x2f, 0x6d
/// ];
/// let plain: [u8; 32] = [
///     0xcc, 0x38, 0xbc, 0xcd, 0x6b, 0xc5, 0x36, 0xad,
///     0x91, 0x9b, 0x13, 0x95, 0xf5, 0xd6, 0x38, 0x01,
///     0xf9, 0x9f, 0x80, 0x68, 0xd6, 0x5c, 0xa5, 0xac,
///     0x63, 0x87, 0x2d, 0xaf, 0x16, 0xb9, 0x39, 0x01
/// ];
/// let auth: [u8; 16] = [
///     0x02, 0x1f, 0xaf, 0xd2, 0x38, 0x46, 0x39, 0x73,
///     0xff, 0xe8, 0x02, 0x56, 0xe5, 0xb1, 0xc6, 0xb1
/// ];
/// let expected_cipher: [u8; 32] = [
///     0xdf, 0xce, 0x4e, 0x9c, 0xd2, 0x91, 0x10, 0x3d,
///     0x7f, 0xe4, 0xe6, 0x33, 0x51, 0xd9, 0xe7, 0x9d,
///     0x3d, 0xfd, 0x39, 0x1e, 0x32, 0x67, 0x10, 0x46,
///     0x58, 0x21, 0x2d, 0xa9, 0x65, 0x21, 0xb7, 0xdb
/// ];
/// let expected_auth_tag: [u8; 16] = [
///     0x54, 0x24, 0x65, 0xef, 0x59, 0x93, 0x16, 0xf7,
///     0x3a, 0x7a, 0x56, 0x05, 0x09, 0xa2, 0xd9, 0xf2
/// ];
/// let mut gcm = GCM::new().expect("Failed to create GCM");
/// gcm.init(&key).expect("Error with init()");
/// let mut cipher: [u8; 32] = [0; 32];
/// let mut auth_tag: [u8; 16] = [0; 16];
/// gcm.encrypt(&plain, &mut cipher, &iv, &auth, &mut auth_tag).expect("Error with encrypt()");
/// assert_eq!(cipher, expected_cipher);
/// assert_eq!(auth_tag, expected_auth_tag);
/// let mut plain_out: [u8; 32] = [0; 32];
/// gcm.decrypt(&cipher, &mut plain_out, &iv, &auth, &auth_tag).expect("Error with decrypt()");
/// assert_eq!(plain_out, plain);
/// }
/// ```
#[cfg(aes_gcm)]
pub struct GCM {
    ws_aes: sys::Aes,
}
#[cfg(aes_gcm)]
impl GCM {
    /// Create a new `GCM` instance.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(GCM) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn new() -> Result<Self, i32> {
        Self::new_ex(None, None)
    }

    /// Create a new `GCM` instance with optional heap and device ID.
    ///
    /// # Parameters
    ///
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(GCM) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn new_ex(heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let ws_aes = new_ws_aes(heap, dev_id)?;
        let gcm = GCM {ws_aes};
        Ok(gcm)
    }

    /// Initialize a GCM instance for encryption or decryption.
    ///
    /// This method must be called before calling `encrypt()` or `decrypt()`.
    ///
    /// # Parameters
    ///
    /// * `key`: A slice containing the encryption key to use. The key must be
    /// 16, 24, or 32 bytes in length.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn init(&mut self, key: &[u8]) -> Result<(), i32> {
        let key_ptr = key.as_ptr() as *const u8;
        let key_size = key.len() as u32;
        let rc = unsafe {
            sys::wc_AesGcmSetKey(&mut self.ws_aes, key_ptr, key_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Encrypt data.
    ///
    /// The `init()` method must be called before calling this method.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to encrypt.
    /// * `dout`: Buffer in which to store the encrypted data. The size of
    /// the buffer must match that of the `din` buffer.
    /// * `iv`: Initialization vector to use for the encryption operation.
    /// * `auth`: Authentication data input.
    /// * `auth_tag`: Buffer in which to store the authentication tag.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn encrypt<I,O>(&mut self, din: &[I], dout: &mut [O], iv: &[u8],
            auth: &[u8], auth_tag: &mut [u8]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        let iv_ptr = iv.as_ptr() as *const u8;
        let iv_size = iv.len() as u32;
        let auth_ptr = auth.as_ptr() as *const u8;
        let auth_size = auth.len() as u32;
        let auth_tag_ptr = auth_tag.as_ptr() as *mut u8;
        let auth_tag_size = auth_tag.len() as u32;
        if in_size != out_size {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesGcmEncrypt(&mut self.ws_aes, out_ptr,
                in_ptr, in_size,
                iv_ptr, iv_size,
                auth_tag_ptr, auth_tag_size,
                auth_ptr, auth_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Decrypt data.
    ///
    /// The `init()` method must be called before calling this method.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to decrypt.
    /// * `dout`: Buffer in which to store the decrypted data. The size of
    /// the buffer must match that of the `din` buffer.
    /// * `iv`: Initialization vector to use for the decryption operation.
    /// * `auth`: Authentication data input.
    /// * `auth_tag`: Authentication tag input to verify.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn decrypt<I,O>(&mut self, din: &[I], dout: &mut [O], iv: &[u8],
            auth: &[u8], auth_tag: &[u8]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        let iv_ptr = iv.as_ptr() as *const u8;
        let iv_size = iv.len() as u32;
        let auth_ptr = auth.as_ptr() as *const u8;
        let auth_size = auth.len() as u32;
        let auth_tag_ptr = auth_tag.as_ptr() as *const u8;
        let auth_tag_size = auth_tag.len() as u32;
        if in_size != out_size {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesGcmDecrypt(&mut self.ws_aes, out_ptr,
                in_ptr, in_size,
                iv_ptr, iv_size,
                auth_tag_ptr, auth_tag_size,
                auth_ptr, auth_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}
#[cfg(aes_gcm)]
impl Drop for GCM {
    /// Safely free the wolfSSL resources.
    fn drop(&mut self) {
        unsafe { sys::wc_AesFree(&mut self.ws_aes); }
    }
}

/// AES Galois/Counter Mode (GCM) mode (streaming functionality).
///
/// This struct provides streaming/chunking encryption and decryption
/// functionality. For one-shot functionality, see the `GCM` struct instead.
///
/// # Example
/// ```rust
/// #[cfg(aes_gcm_stream)]
/// {
/// use wolfssl::wolfcrypt::aes::GCMStream;
/// let plain: [u8; 60] = [
///     0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
///     0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
///     0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
///     0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
///     0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
///     0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
///     0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
///     0xba, 0x63, 0x7b, 0x39
/// ];
/// let auth: [u8; 20] = [
///     0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
///     0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
///     0xab, 0xad, 0xda, 0xd2
/// ];
/// let key: [u8; 32] = [
///     0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
///     0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
///     0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
///     0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
/// ];
/// let iv: [u8; 12] = [
///     0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
///     0xde, 0xca, 0xf8, 0x88
/// ];
/// let expected_cipher: [u8; 60] = [
///     0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07,
///     0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
///     0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
///     0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
///     0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
///     0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
///     0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
///     0xbc, 0xc9, 0xf6, 0x62
/// ];
/// let expected_auth_tag: [u8; 16] = [
///     0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68,
///     0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55, 0x1b
/// ];
/// let mut gcmstream = GCMStream::new().expect("Failed to create GCMStream");
/// for chunk_size in 1..=auth.len() {
///     gcmstream.init(&key, &iv).expect("Error with init()");
///     let mut cipher: [u8; 60] = [0; 60];
///     let mut i = 0;
///     while i < auth.len() {
///         let mut end = i + chunk_size;
///         if end > auth.len() {
///             end = auth.len()
///         }
///         gcmstream.encrypt_update(&plain[0..0], &mut cipher[0..0], &auth[i..end]).expect("Error with encrypt_update()");
///         i += chunk_size;
///     }
///     i = 0;
///     while i < plain.len() {
///         let mut end = i + chunk_size;
///         if end > plain.len() {
///             end = plain.len()
///         }
///         gcmstream.encrypt_update(&plain[i..end], &mut cipher[i..end], &auth[0..0]).expect("Error with encrypt_update()");
///         i += chunk_size;
///     }
///     let mut auth_tag: [u8; 16] = [0; 16];
///     gcmstream.encrypt_final(&mut auth_tag).expect("Error with encrypt_final()");
///     assert_eq!(cipher, expected_cipher);
///     assert_eq!(auth_tag, expected_auth_tag);
/// }
/// }
/// ```
#[cfg(aes_gcm_stream)]
pub struct GCMStream {
    ws_aes: sys::Aes,
}
#[cfg(aes_gcm_stream)]
impl GCMStream {
    /// Create a new `GCMStream` instance.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(GCMStream) on success or an Err containing the
    /// wolfSSL library return code on failure.
    pub fn new() -> Result<Self, i32> {
        Self::new_ex(None, None)
    }

    /// Create a new `GCMStream` instance with heap and device ID.
    ///
    /// # Parameters
    ///
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(GCMStream) on success or an Err containing the
    /// wolfSSL library return code on failure.
    pub fn new_ex(heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let ws_aes = new_ws_aes(heap, dev_id)?;
        let gcmstream = GCMStream {ws_aes};
        Ok(gcmstream)
    }

    /// Initialize a GCMStream instance for encryption or decryption.
    ///
    /// This method must be called before calling `encrypt_update()`,
    /// `encrypt_final()`, `decrypt_update()`, or `decrypt_final()`.
    ///
    /// # Parameters
    ///
    /// * `key`: A slice containing the encryption key to use. The key must be
    /// 16, 24, or 32 bytes in length.
    /// * `iv`: A slice containing the initialization vector (IV) to use.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn init(&mut self, key: &[u8], iv: &[u8]) -> Result<(), i32> {
        let key_ptr = key.as_ptr() as *const u8;
        let key_size = key.len() as u32;
        let iv_ptr = iv.as_ptr() as *const u8;
        let iv_size = iv.len() as u32;
        let rc = unsafe {
            sys::wc_AesGcmInit(&mut self.ws_aes, key_ptr, key_size, iv_ptr, iv_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Add a chunk of data to encrypt or authentication data.
    ///
    /// All authentication data must be passed in to update before the
    /// plaintext to encrypt. The last part of the authentication data can be
    /// passed in with the same call as the first part of the plaintext data.
    ///
    /// The `init()` method must be called before calling this method.
    /// The `encrypt_final()` method must be called to finalize the encryption
    /// operation and retrieve the calculated authentication tag.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to encrypt.
    /// * `dout`: Buffer in which to store the encrypted data. The size of
    /// the buffer must match that of the `din` buffer.
    /// * `auth`: Authentication data input.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn encrypt_update<I,O>(&mut self, din: &[I], dout: &mut [O],
            auth: &[u8]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        let auth_ptr = auth.as_ptr() as *const u8;
        let auth_size = auth.len() as u32;
        if in_size != out_size {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesGcmEncryptUpdate(&mut self.ws_aes, out_ptr,
                in_ptr, in_size,
                auth_ptr, auth_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Finalize encryption.
    ///
    /// The `init()` method must be called before calling this method.
    /// The `encrypt_update()` method must be called one or more times before
    /// calling this method to supply authentication data and plaintext input
    /// for encryption.
    ///
    /// # Parameters
    ///
    /// * `auth_tag`: Buffer in which to store the authentication tag.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn encrypt_final(&mut self, auth_tag: &mut [u8]) -> Result<(), i32> {
        let auth_tag_ptr = auth_tag.as_ptr() as *mut u8;
        let auth_tag_size = auth_tag.len() as u32;
        let rc = unsafe {
            sys::wc_AesGcmEncryptFinal(&mut self.ws_aes, auth_tag_ptr, auth_tag_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Add a chunk of data to decrypt or authentication data.
    ///
    /// All authentication data must be passed in to update before the
    /// ciphertext to decrypt. The last part of the authentication data can be
    /// passed in with the same call as the first part of the ciphertext data.
    ///
    /// The `init()` method must be called before calling this method.
    /// The `decrypt_final()` method must be called to finalize the decryption
    /// operation and verify the authentication tag.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to encrypt.
    /// * `dout`: Buffer in which to store the decrypted data. The size of
    /// the buffer must match that of the `din` buffer.
    /// * `auth`: Authentication data input.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn decrypt_update<I,O>(&mut self, din: &[I], dout: &mut [O],
            auth: &[u8]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        let auth_ptr = auth.as_ptr() as *const u8;
        let auth_size = auth.len() as u32;
        if in_size != out_size {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesGcmDecryptUpdate(&mut self.ws_aes, out_ptr,
                in_ptr, in_size,
                auth_ptr, auth_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Finalize decryption.
    ///
    /// The `init()` method must be called before calling this method.
    /// The `decrypt_update()` method must be called one or more times before
    /// calling this method to supply authentication data and ciphertext input
    /// for decryption.
    ///
    /// # Parameters
    ///
    /// * `auth_tag`: Authentication tag input to verify.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn decrypt_final(&mut self, auth_tag: &[u8]) -> Result<(), i32> {
        let auth_tag_ptr = auth_tag.as_ptr() as *const u8;
        let auth_tag_size = auth_tag.len() as u32;
        let rc = unsafe {
            sys::wc_AesGcmDecryptFinal(&mut self.ws_aes, auth_tag_ptr, auth_tag_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}
#[cfg(aes_gcm_stream)]
impl Drop for GCMStream {
    /// Safely free the wolfSSL resources.
    fn drop(&mut self) {
        unsafe { sys::wc_AesFree(&mut self.ws_aes); }
    }
}

/// AES Output FeedBack (OFB) mode.
///
/// # Example
/// ```rust
/// #[cfg(aes_ofb)]
/// {
/// use wolfssl::wolfcrypt::aes::OFB;
/// let key: [u8; 32] = [
///     0xc4,0xc7,0xfa,0xd6,0x53,0x5c,0xb8,0x71,
///     0x4a,0x5c,0x40,0x77,0x9a,0x8b,0xa1,0xd2,
///     0x53,0x3e,0x23,0xb4,0xb2,0x58,0x73,0x2a,
///     0x5b,0x78,0x01,0xf4,0xe3,0x71,0xa7,0x94
/// ];
/// let iv: [u8; 16] = [
///     0x5e,0xb9,0x33,0x13,0xb8,0x71,0xff,0x16,
///     0xb9,0x8a,0x9b,0xcb,0x43,0x33,0x0d,0x6f
/// ];
/// let plain: [u8; 48] = [
///     0x6d,0x0b,0xb0,0x79,0x63,0x84,0x71,0xe9,
///     0x39,0xd4,0x53,0x14,0x86,0xc1,0x4c,0x25,
///     0x9a,0xee,0xc6,0xf3,0xc0,0x0d,0xfd,0xd6,
///     0xc0,0x50,0xa8,0xba,0xa8,0x20,0xdb,0x71,
///     0xcc,0x12,0x2c,0x4e,0x0c,0x17,0x15,0xef,
///     0x55,0xf3,0x99,0x5a,0x6b,0xf0,0x2a,0x4c
/// ];
/// let expected_cipher: [u8; 48] = [
///     0x0f,0x54,0x61,0x71,0x59,0xd0,0x3f,0xfc,
///     0x1b,0xfa,0xfb,0x60,0x29,0x30,0xd7,0x00,
///     0xf4,0xa4,0xa8,0xe6,0xdd,0x93,0x94,0x46,
///     0x64,0xd2,0x19,0xc4,0xc5,0x4d,0xde,0x1b,
///     0x04,0x53,0xe1,0x73,0xf5,0x18,0x74,0xae,
///     0xfd,0x64,0xa2,0xe1,0xe2,0x76,0x13,0xb0
/// ];
/// let mut ofb = OFB::new().expect("Failed to create OFB");
/// ofb.init(&key, &iv).expect("Error with init()");
/// let mut cipher: [u8; 48] = [0; 48];
/// ofb.encrypt(&plain, &mut cipher).expect("Error with encrypt()");
/// assert_eq!(cipher, expected_cipher);
/// ofb.init(&key, &iv).expect("Error with init()");
/// let mut plain_out: [u8; 48] = [0; 48];
/// #[cfg(aes_decrypt)]
/// {
/// ofb.decrypt(&cipher, &mut plain_out).expect("Error with decrypt()");
/// assert_eq!(plain_out, plain);
/// }
/// }
/// ```
#[cfg(aes_ofb)]
pub struct OFB {
    ws_aes: sys::Aes,
}
#[cfg(aes_ofb)]
impl OFB {
    /// Create a new `OFB` instance.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(OFB) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn new() -> Result<Self, i32> {
        Self::new_ex(None, None)
    }

    /// Create a new `OFB` instance with optional heap and device ID.
    ///
    /// # Parameters
    ///
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(OFB) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn new_ex(heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let ws_aes = new_ws_aes(heap, dev_id)?;
        let ofb = OFB {ws_aes};
        Ok(ofb)
    }

    /// Initialize a OFB instance for encryption or decryption.
    ///
    /// This method must be called before calling `encrypt()` or `decrypt()`.
    ///
    /// # Parameters
    ///
    /// * `key`: A slice containing the encryption key to use. The key must be
    /// 16, 24, or 32 bytes in length.
    /// * `iv`: A slice containing the initialization vector (IV) to use. The
    /// IV must be 16 bytes in length.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn init(&mut self, key: &[u8], iv: &[u8]) -> Result<(), i32> {
        let key_ptr = key.as_ptr() as *const u8;
        let key_size = key.len() as u32;
        let iv_ptr = iv.as_ptr() as *const u8;
        if iv.len() as u32 != sys::WC_AES_BLOCK_SIZE {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesSetKey(&mut self.ws_aes, key_ptr, key_size, iv_ptr,
                sys::AES_ENCRYPTION as i32)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Encrypt data.
    ///
    /// The `init()` method must be called before calling this method.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to encrypt.
    /// * `dout`: Buffer in which to store the encrypted data. The size of
    /// the buffer must match that of the `din` buffer.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn encrypt<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesOfbEncrypt(&mut self.ws_aes, out_ptr, in_ptr, in_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Decrypt data.
    ///
    /// The `init()` method must be called before calling this method.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to decrypt.
    /// * `dout`: Buffer in which to store the decrypted data. The size of
    /// the buffer must match that of the `din` buffer.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    #[cfg(aes_decrypt)]
    pub fn decrypt<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesOfbDecrypt(&mut self.ws_aes, out_ptr, in_ptr, in_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}
#[cfg(aes_ofb)]
impl Drop for OFB {
    /// Safely free the wolfSSL resources.
    fn drop(&mut self) {
        unsafe { sys::wc_AesFree(&mut self.ws_aes); }
    }
}

/// AES XEX-based Tweaked-Codebook Mode With Ciphertext Stealing (XTS) support
/// (one shot functionality).
///
/// This struct provides one-shot encryption and decryption functionality.
/// For streaming/chunking functionality, see the `XTSStream` struct instead.
///
/// # Example
/// ```rust
/// #[cfg(aes_xts)]
/// {
/// use wolfssl::wolfcrypt::aes::XTS;
/// let key: [u8; 32] = [
///     0xa1, 0xb9, 0x0c, 0xba, 0x3f, 0x06, 0xac, 0x35,
///     0x3b, 0x2c, 0x34, 0x38, 0x76, 0x08, 0x17, 0x62,
///     0x09, 0x09, 0x23, 0x02, 0x6e, 0x91, 0x77, 0x18,
///     0x15, 0xf2, 0x9d, 0xab, 0x01, 0x93, 0x2f, 0x2f
/// ];
/// let tweak: [u8; 16] = [
///     0x4f, 0xae, 0xf7, 0x11, 0x7c, 0xda, 0x59, 0xc6,
///     0x6e, 0x4b, 0x92, 0x01, 0x3e, 0x76, 0x8a, 0xd5
/// ];
/// let plain: [u8; 16] = [
///     0xeb, 0xab, 0xce, 0x95, 0xb1, 0x4d, 0x3c, 0x8d,
///     0x6f, 0xb3, 0x50, 0x39, 0x07, 0x90, 0x31, 0x1c
/// ];
/// let expected_cipher: [u8; 16] = [
///     0x77, 0x8a, 0xe8, 0xb4, 0x3c, 0xb9, 0x8d, 0x5a,
///     0x82, 0x50, 0x81, 0xd5, 0xbe, 0x47, 0x1c, 0x63
/// ];
/// let partial: [u8; 24] = [
///     0xeb, 0xab, 0xce, 0x95, 0xb1, 0x4d, 0x3c, 0x8d,
///     0x6f, 0xb3, 0x50, 0x39, 0x07, 0x90, 0x31, 0x1c,
///     0x6e, 0x4b, 0x92, 0x01, 0x3e, 0x76, 0x8a, 0xd5
/// ];
/// let expected_partial_cipher: [u8; 24] = [
///     0x2b, 0xf7, 0x2c, 0xf3, 0xeb, 0x85, 0xef, 0x7b,
///     0x0b, 0x76, 0xa0, 0xaa, 0xf3, 0x3f, 0x25, 0x8b,
///     0x77, 0x8a, 0xe8, 0xb4, 0x3c, 0xb9, 0x8d, 0x5a
/// ];
///
/// let mut xts = XTS::new().expect("Failed to create XTS");
/// xts.init_encrypt(&key).expect("Error with init_encrypt()");
/// let mut cipher: [u8; 16] = [0; 16];
/// xts.encrypt(&plain, &mut cipher, &tweak).expect("Error with encrypt()");
/// assert_eq!(cipher, expected_cipher);
/// xts.init_decrypt(&key).expect("Error with init_decrypt()");
/// let mut plain_out: [u8; 16] = [0; 16];
/// xts.decrypt(&cipher, &mut plain_out, &tweak).expect("Error with decrypt()");
/// assert_eq!(plain_out, plain);
///
/// xts.init_encrypt(&key).expect("Error with init_encrypt()");
/// let mut partial_cipher: [u8; 24] = [0; 24];
/// xts.encrypt(&partial, &mut partial_cipher, &tweak).expect("Error with encrypt()");
/// assert_eq!(partial_cipher, expected_partial_cipher);
/// xts.init_decrypt(&key).expect("Error with init_decrypt()");
/// let mut partial_out: [u8; 24] = [0; 24];
/// xts.decrypt(&partial_cipher, &mut partial_out, &tweak).expect("Error with decrypt()");
/// assert_eq!(partial_out, partial);
/// }
/// ```
#[cfg(aes_xts)]
pub struct XTS {
    ws_xtsaes: sys::XtsAes,
}
#[cfg(aes_xts)]
impl XTS {
    /// Create a new `XTS` instance.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(XTS) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn new() -> Result<Self, i32> {
        Self::new_ex(None, None)
    }

    /// Create a new `XTS` instance with optional heap and device ID.
    ///
    /// # Parameters
    ///
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(XTS) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn new_ex(heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let ws_xtsaes = new_ws_xtsaes(heap, dev_id)?;
        let xts = XTS {ws_xtsaes};
        Ok(xts)
    }

    fn init(&mut self, key: &[u8], dir: i32) -> Result<(), i32> {
        let key_ptr = key.as_ptr() as *const u8;
        let key_size = key.len() as u32;
        let rc = unsafe {
            sys::wc_AesXtsSetKeyNoInit(&mut self.ws_xtsaes, key_ptr, key_size,
                dir)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Initialize a XTS instance for encryption.
    ///
    /// This method must be called before calling any encryption methods.
    ///
    /// # Parameters
    ///
    /// * `key`: A slice containing the encryption key to use. The key must be
    /// 16, 24, or 32 bytes in length.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn init_encrypt(&mut self, key: &[u8]) -> Result<(), i32> {
        return self.init(key, sys::AES_ENCRYPTION as i32);
    }

    /// Initialize a XTS instance for decryption.
    ///
    /// This method must be called before calling any decryption methods.
    ///
    /// # Parameters
    ///
    /// * `key`: A slice containing the decryption key to use. The key must be
    /// 16, 24, or 32 bytes in length.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn init_decrypt(&mut self, key: &[u8]) -> Result<(), i32> {
        return self.init(key, sys::AES_DECRYPTION as i32);
    }

    /// Encrypt data.
    ///
    /// The `init_encrypt()` method must be called before calling this method.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to encrypt.
    /// * `dout`: Buffer in which to store the encrypted data. The size of
    /// the buffer must match that of the `din` buffer.
    /// * `tweak`: Tweak value to use for the encryption operation.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn encrypt<I,O>(&mut self, din: &[I], dout: &mut [O], tweak: &[u8]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        let tweak_ptr = tweak.as_ptr() as *const u8;
        let tweak_size = tweak.len() as u32;
        if in_size != out_size {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesXtsEncrypt(&mut self.ws_xtsaes, out_ptr,
                in_ptr, in_size,
                tweak_ptr, tweak_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Encrypt a sector of data.
    ///
    /// The `init_encrypt()` method must be called before calling this method.
    ///
    /// This method is the same as `encrypt()` except that a sector number is
    /// taken instead of a tweak buffer. Internally the sector number is
    /// expanded into the tweak value to use.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to encrypt.
    /// * `dout`: Buffer in which to store the encrypted data. The size of
    /// the buffer must match that of the `din` buffer.
    /// * `sector`: Sector number to use for encryption operation. This value
    /// is expanded into a tweak value.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn encrypt_sector<I,O>(&mut self, din: &[I], dout: &mut [O], sector: u64) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesXtsEncryptSector(&mut self.ws_xtsaes, out_ptr,
                in_ptr, in_size, sector)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Encrypt consecutive sectors of data.
    ///
    /// The `init_encrypt()` method must be called before calling this method.
    ///
    /// This method is the same as `encrypt_sector()` except that the sector
    /// number is automatically incremented every `sector_size` bytes.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to encrypt.
    /// * `dout`: Buffer in which to store the encrypted data. The size of
    /// the buffer must match that of the `din` buffer.
    /// * `sector`: Sector number to use for encryption operation. This value
    /// is expanded into a tweak value.
    /// * `sector_size`: Sector size. The `sector` value is internally
    /// incremented every `sector_size` bytes.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn encrypt_consecutive_sectors<I,O>(&mut self, din: &[I], dout: &mut [O],
            sector: u64, sector_size: u32) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesXtsEncryptConsecutiveSectors(&mut self.ws_xtsaes, out_ptr,
                in_ptr, in_size, sector, sector_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Decrypt data.
    ///
    /// The `init_decrypt()` method must be called before calling this method.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to decrypt.
    /// * `dout`: Buffer in which to store the decrypted data. The size of
    /// the buffer must match that of the `din` buffer.
    /// * `tweak`: Tweak value to use for the decryption operation.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn decrypt<I,O>(&mut self, din: &[I], dout: &mut [O], tweak: &[u8]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        let tweak_ptr = tweak.as_ptr() as *const u8;
        let tweak_size = tweak.len() as u32;
        if in_size != out_size {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesXtsDecrypt(&mut self.ws_xtsaes, out_ptr,
                in_ptr, in_size,
                tweak_ptr, tweak_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Decrypt a sector of data.
    ///
    /// The `init_decrypt()` method must be called before calling this method.
    ///
    /// This method is the same as `decrypt()` except that a sector number is
    /// taken instead of a tweak buffer. Internally the sector number is
    /// expanded into the tweak value to use.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to decrypt.
    /// * `dout`: Buffer in which to store the decrypted data. The size of
    /// the buffer must match that of the `din` buffer.
    /// * `sector`: Sector number to use for decryption operation. This value
    /// is expanded into a tweak value.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn decrypt_sector<I,O>(&mut self, din: &[I], dout: &mut [O], sector: u64) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesXtsDecryptSector(&mut self.ws_xtsaes, out_ptr,
                in_ptr, in_size, sector)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Decrypt consecutive sectors of data.
    ///
    /// The `init_decrypt()` method must be called before calling this method.
    ///
    /// This method is the same as `decrypt_sector()` except that the sector
    /// number is automatically incremented every `sector_size` bytes.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to decrypt.
    /// * `dout`: Buffer in which to store the decrypted data. The size of
    /// the buffer must match that of the `din` buffer.
    /// * `sector`: Sector number to use for decryption operation. This value
    /// is expanded into a tweak value.
    /// * `sector_size`: Sector size. The `sector` value is internally
    /// incremented every `sector_size` bytes.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn decrypt_consecutive_sectors<I,O>(&mut self, din: &[I], dout: &mut [O],
            sector: u64, sector_size: u32) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesXtsDecryptConsecutiveSectors(&mut self.ws_xtsaes, out_ptr,
                in_ptr, in_size, sector, sector_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}
#[cfg(aes_xts)]
impl Drop for XTS {
    /// Safely free the wolfSSL resources.
    fn drop(&mut self) {
        unsafe { sys::wc_AesXtsFree(&mut self.ws_xtsaes); }
    }
}

/// AES XEX-based Tweaked-Codebook Mode With Ciphertext Stealing (XTS) support
/// (streaming functionality).
///
/// This struct provides streaming/chunking encryption and decryption
/// functionality. For one-shot functionality, see the `XTS` struct instead.
///
/// # Example
/// ```rust
/// #[cfg(aes_xts_stream)]
/// {
/// use wolfssl::wolfcrypt::aes::XTSStream;
/// let keys: [u8; 32] = [
///     0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
///     0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
///     0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
///     0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
/// ];
/// let tweak: [u8; 16] = [
///     0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
///     0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
/// ];
/// let plain: [u8; 40] = [
///     0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
///     0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
///     0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
///     0x20, 0xff, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
///     0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20
/// ];
/// let expected_cipher: [u8; 40] = [
///     0xA2, 0x07, 0x47, 0x76, 0x3F, 0xEC, 0x0C, 0x23,
///     0x1B, 0xD0, 0xBD, 0x46, 0x9A, 0x27, 0x38, 0x12,
///     0x95, 0x02, 0x3D, 0x5D, 0xC6, 0x94, 0x51, 0x36,
///     0xA0, 0x85, 0xD2, 0x69, 0x6E, 0x87, 0x0A, 0xBF,
///     0xB5, 0x5A, 0xDD, 0xCB, 0x80, 0xE0, 0xFC, 0xCD
/// ];
///
/// let mut xtsstream = XTSStream::new().expect("Failed to create XTSStream");
/// xtsstream.init_encrypt(&keys, &tweak).expect("Error with init_encrypt()");
/// let mut cipher: [u8; 40] = [0; 40];
/// xtsstream.encrypt_update(&plain[0..16], &mut cipher[0..16]).expect("Error with encrypt_update()");
/// xtsstream.encrypt_final(&plain[16..40], &mut cipher[16..40]).expect("Error with encrypt_final()");
/// assert_eq!(cipher, expected_cipher);
///
/// xtsstream.init_decrypt(&keys, &tweak).expect("Error with init_decrypt()");
/// let mut plain_out: [u8; 40] = [0; 40];
/// xtsstream.decrypt_update(&cipher[0..16], &mut plain_out[0..16]).expect("Error with decrypt_update()");
/// xtsstream.decrypt_final(&cipher[16..40], &mut plain_out[16..40]).expect("Error with decrypt_final()");
/// assert_eq!(plain_out, plain);
/// }
/// ```
#[cfg(aes_xts_stream)]
pub struct XTSStream {
    ws_xtsaes: sys::XtsAes,
    ws_xtsaesstreamdata: sys::XtsAesStreamData,
}
#[cfg(aes_xts_stream)]
impl XTSStream {
    /// Create a new `XTSStream` instance.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(XTSStream) on success or an Err containing the
    /// wolfSSL library return code on failure.
    pub fn new() -> Result<Self, i32> {
        Self::new_ex(None, None)
    }

    /// Create a new `XTSStream` instance with optional heap and device ID.
    ///
    /// # Parameters
    ///
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(XTSStream) on success or an Err containing the
    /// wolfSSL library return code on failure.
    pub fn new_ex(heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let ws_xtsaes = new_ws_xtsaes(heap, dev_id)?;
        let ws_xtsaesstreamdata: MaybeUninit<sys::XtsAesStreamData> = MaybeUninit::uninit();
        let ws_xtsaesstreamdata = unsafe { ws_xtsaesstreamdata.assume_init() };
        let xtsstream = XTSStream {ws_xtsaes, ws_xtsaesstreamdata};
        Ok(xtsstream)
    }

    /// Initialize a XTSStream instance for encryption.
    ///
    /// This method must be called before calling `encrypt_update()`.
    ///
    /// # Parameters
    ///
    /// * `key`: A slice containing the encryption key to use. The key must be
    /// 16, 24, or 32 bytes in length.
    /// * `tweak`: Tweak value to use for the encryption operation.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn init_encrypt(&mut self, key: &[u8], tweak: &[u8]) -> Result<(), i32> {
        let key_ptr = key.as_ptr() as *const u8;
        let key_size = key.len() as u32;
        let rc = unsafe {
            sys::wc_AesXtsSetKeyNoInit(&mut self.ws_xtsaes, key_ptr, key_size,
                sys::AES_ENCRYPTION as i32)
        };
        if rc != 0 {
            return Err(rc);
        }
        let tweak_ptr = tweak.as_ptr() as *const u8;
        let tweak_size = tweak.len() as u32;
        let rc = unsafe {
            sys::wc_AesXtsEncryptInit(&mut self.ws_xtsaes, tweak_ptr, tweak_size,
                &mut self.ws_xtsaesstreamdata)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Initialize a XTSStream instance for decryption.
    ///
    /// This method must be called before calling `decrypt_update()`.
    ///
    /// # Parameters
    ///
    /// * `key`: A slice containing the decryption key to use. The key must be
    /// 16, 24, or 32 bytes in length.
    /// * `tweak`: Tweak value to use for the decryption operation.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn init_decrypt(&mut self, key: &[u8], tweak: &[u8]) -> Result<(), i32> {
        let key_ptr = key.as_ptr() as *const u8;
        let key_size = key.len() as u32;
        let rc = unsafe {
            sys::wc_AesXtsSetKeyNoInit(&mut self.ws_xtsaes, key_ptr, key_size,
                sys::AES_DECRYPTION as i32)
        };
        if rc != 0 {
            return Err(rc);
        }
        let tweak_ptr = tweak.as_ptr() as *const u8;
        let tweak_size = tweak.len() as u32;
        let rc = unsafe {
            sys::wc_AesXtsDecryptInit(&mut self.ws_xtsaes, tweak_ptr, tweak_size,
                &mut self.ws_xtsaesstreamdata)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Add a chunk of data to encrypt.
    ///
    /// The `init_encrypt()` method must be called before calling this method.
    /// The `encrypt_final()` method must be called to finalize the encryption
    /// operation.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to encrypt. The size of the data must be a multiple of
    /// 16 bytes. A final chunk of data that is not a multiple of 16 bytes can
    /// be passed in to `encrypt_final()`.
    /// * `dout`: Buffer in which to store the encrypted data. The size of
    /// the buffer must match that of the `din` buffer.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn encrypt_update<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesXtsEncryptUpdate(&mut self.ws_xtsaes, out_ptr,
                in_ptr, in_size, &mut self.ws_xtsaesstreamdata)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Encrypt the final chunk of data.
    ///
    /// The `init_encrypt()` method must be called before calling this method.
    /// The `encrypt_update()` method may be called prior to this to encrypt
    /// blocks of data in chunks.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to encrypt. The size of the data must be 0 or at least
    /// 16 bytes. It does not need to be a multiple of 16 bytes.
    /// * `dout`: Buffer in which to store the encrypted data. The size of
    /// the buffer must match that of the `din` buffer.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn encrypt_final<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesXtsEncryptFinal(&mut self.ws_xtsaes, out_ptr,
                in_ptr, in_size, &mut self.ws_xtsaesstreamdata)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Add a chunk of data to decrypt.
    ///
    /// The `init_decrypt()` method must be called before calling this method.
    /// The `decrypt_final()` method must be called to finalize the decryption
    /// operation.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to decrypt. The size of the data must be a multiple of
    /// 16 bytes. A final chunk of data that is not a multiple of 16 bytes can
    /// be passed in to `decrypt_final()`.
    /// * `dout`: Buffer in which to store the decrypted data. The size of
    /// the buffer must match that of the `din` buffer.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn decrypt_update<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesXtsDecryptUpdate(&mut self.ws_xtsaes, out_ptr,
                in_ptr, in_size, &mut self.ws_xtsaesstreamdata)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Decrypt the final chunk of data.
    ///
    /// The `init_decrypt()` method must be called before calling this method.
    /// The `decrypt_update()` method may be called prior to this to decrypt
    /// blocks of data in chunks.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to decrypt. The size of the data must be 0 or at least
    /// 16 bytes. It does not need to be a multiple of 16 bytes.
    /// * `dout`: Buffer in which to store the decrypted data. The size of
    /// the buffer must match that of the `din` buffer.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn decrypt_final<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            sys::wc_AesXtsDecryptFinal(&mut self.ws_xtsaes, out_ptr,
                in_ptr, in_size, &mut self.ws_xtsaesstreamdata)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}
#[cfg(aes_xts_stream)]
impl Drop for XTSStream {
    /// Safely free the wolfSSL resources.
    fn drop(&mut self) {
        unsafe { sys::wc_AesXtsFree(&mut self.ws_xtsaes); }
    }
}

fn new_ws_aes(heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<sys::Aes, i32> {
    let heap = match heap {
        Some(heap) => heap,
        None => core::ptr::null_mut(),
    };
    let dev_id = match dev_id {
        Some(dev_id) => dev_id,
        None => sys::INVALID_DEVID,
    };
    let mut ws_aes: MaybeUninit<sys::Aes> = MaybeUninit::uninit();
    let rc = unsafe {
        sys::wc_AesInit(ws_aes.as_mut_ptr(), heap, dev_id)
    };
    if rc != 0 {
        return Err(rc);
    }
    let ws_aes = unsafe { ws_aes.assume_init() };
    Ok(ws_aes)
}

#[cfg(any(aes_xts, aes_xts_stream))]
fn new_ws_xtsaes(heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<sys::XtsAes, i32> {
    let heap = match heap {
        Some(heap) => heap,
        None => core::ptr::null_mut(),
    };
    let dev_id = match dev_id {
        Some(dev_id) => dev_id,
        None => sys::INVALID_DEVID,
    };
    let mut ws_xtsaes: MaybeUninit<sys::XtsAes> = MaybeUninit::uninit();
    let rc = unsafe {
        sys::wc_AesXtsInit(ws_xtsaes.as_mut_ptr(), heap, dev_id)
    };
    if rc != 0 {
        return Err(rc);
    }
    let ws_xtsaes = unsafe { ws_xtsaes.assume_init() };
    Ok(ws_xtsaes)
}
