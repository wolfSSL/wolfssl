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
This module provides a Rust wrapper for the wolfCrypt library's RSA
functionality.

The primary component is the `RSA` struct, which manages the lifecycle of a
wolfSSL `RsaKey` object. It ensures proper initialization and deallocation.

# Examples

```rust
use std::fs;
use wolfssl::wolfcrypt::random::RNG;
use wolfssl::wolfcrypt::rsa::RSA;

let mut rng = RNG::new().expect("Error creating RNG");
let key_path = "../../../certs/client-keyPub.der";
let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
let mut rsa = RSA::new_public_from_der(&der).expect("Error with new_public_from_der()");
rsa.set_rng(&mut rng).expect("Error with set_rng()");
let plain: &[u8] = b"Test message";
let mut enc: [u8; 512] = [0; 512];
let enc_len = rsa.public_encrypt(plain, &mut enc, &mut rng).expect("Error with public_encrypt()");
assert!(enc_len > 0 && enc_len <= 512);

let key_path = "../../../certs/client-key.der";
let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
let mut rsa = RSA::new_from_der(&der).expect("Error with new_from_der()");
rsa.set_rng(&mut rng).expect("Error with set_rng()");
let mut plain_out: [u8; 512] = [0; 512];
let dec_len = rsa.private_decrypt(&enc[0..enc_len], &mut plain_out).expect("Error with private_decrypt()");
assert!(dec_len as usize == plain.len());
assert_eq!(plain_out[0..dec_len], *plain);
```
*/

#![cfg(rsa)]

use crate::sys;
use crate::wolfcrypt::random::RNG;
use std::mem::{MaybeUninit};

/// The `RSA` struct manages the lifecycle of a wolfSSL `RsaKey` object.
///
/// It ensures proper initialization and deallocation.
///
/// An instance can be created with `new_from_der()`, `new_public_from_der()`,
/// or `generate()`.
pub struct RSA {
    wc_rsakey: sys::RsaKey,
}

impl RSA {
    // Hash type constants used for PSS sign and verify methods.
    pub const HASH_TYPE_NONE       : u32 = sys::wc_HashType_WC_HASH_TYPE_NONE;
    pub const HASH_TYPE_MD2        : u32 = sys::wc_HashType_WC_HASH_TYPE_MD2;
    pub const HASH_TYPE_MD4        : u32 = sys::wc_HashType_WC_HASH_TYPE_MD4;
    pub const HASH_TYPE_MD5        : u32 = sys::wc_HashType_WC_HASH_TYPE_MD5;
    #[cfg(sha)]
    pub const HASH_TYPE_SHA        : u32 = sys::wc_HashType_WC_HASH_TYPE_SHA;
    #[cfg(sha256)]
    pub const HASH_TYPE_SHA224     : u32 = sys::wc_HashType_WC_HASH_TYPE_SHA224;
    #[cfg(sha256)]
    pub const HASH_TYPE_SHA256     : u32 = sys::wc_HashType_WC_HASH_TYPE_SHA256;
    #[cfg(sha512)]
    pub const HASH_TYPE_SHA384     : u32 = sys::wc_HashType_WC_HASH_TYPE_SHA384;
    #[cfg(sha512)]
    pub const HASH_TYPE_SHA512     : u32 = sys::wc_HashType_WC_HASH_TYPE_SHA512;
    pub const HASH_TYPE_MD5_SHA    : u32 = sys::wc_HashType_WC_HASH_TYPE_MD5_SHA;
    #[cfg(sha3)]
    pub const HASH_TYPE_SHA3_224   : u32 = sys::wc_HashType_WC_HASH_TYPE_SHA3_224;
    #[cfg(sha3)]
    pub const HASH_TYPE_SHA3_256   : u32 = sys::wc_HashType_WC_HASH_TYPE_SHA3_256;
    #[cfg(sha3)]
    pub const HASH_TYPE_SHA3_384   : u32 = sys::wc_HashType_WC_HASH_TYPE_SHA3_384;
    #[cfg(sha3)]
    pub const HASH_TYPE_SHA3_512   : u32 = sys::wc_HashType_WC_HASH_TYPE_SHA3_512;
    pub const HASH_TYPE_BLAKE2B    : u32 = sys::wc_HashType_WC_HASH_TYPE_BLAKE2B;
    pub const HASH_TYPE_BLAKE2S    : u32 = sys::wc_HashType_WC_HASH_TYPE_BLAKE2S;
    pub const HASH_TYPE_SHA512_224 : u32 = sys::wc_HashType_WC_HASH_TYPE_SHA512_224;
    pub const HASH_TYPE_SHA512_256 : u32 = sys::wc_HashType_WC_HASH_TYPE_SHA512_256;
    #[cfg(shake128)]
    pub const HASH_TYPE_SHAKE128   : u32 = sys::wc_HashType_WC_HASH_TYPE_SHAKE128;
    #[cfg(shake256)]
    pub const HASH_TYPE_SHAKE256   : u32 = sys::wc_HashType_WC_HASH_TYPE_SHAKE256;

    // Mask generation function (MGF) constants used for PSS sign and verify methods.
    pub const MGF1NONE       : i32 = sys::WC_MGF1NONE as i32;
    pub const MGF1SHA1       : i32 = sys::WC_MGF1SHA1 as i32;
    pub const MGF1SHA224     : i32 = sys::WC_MGF1SHA224 as i32;
    pub const MGF1SHA256     : i32 = sys::WC_MGF1SHA256 as i32;
    pub const MGF1SHA384     : i32 = sys::WC_MGF1SHA384 as i32;
    pub const MGF1SHA512     : i32 = sys::WC_MGF1SHA512 as i32;
    pub const MGF1SHA512_224 : i32 = sys::WC_MGF1SHA512_224 as i32;
    pub const MGF1SHA512_256 : i32 = sys::WC_MGF1SHA512_256 as i32;

    // Type constants used for `rsa_direct()`.
    pub const PUBLIC_ENCRYPT : i32 = sys::RSA_PUBLIC_ENCRYPT;
    pub const PUBLIC_DECRYPT : i32 = sys::RSA_PUBLIC_DECRYPT;
    pub const PRIVATE_ENCRYPT : i32 = sys::RSA_PRIVATE_ENCRYPT;
    pub const PRIVATE_DECRYPT : i32 = sys::RSA_PRIVATE_DECRYPT;

    /// Load a public and private RSA keypair from DER-encoded buffer.
    ///
    /// # Parameters
    ///
    /// * `der`: DER-encoded input buffer.
    ///
    /// # Returns
    ///
    /// Returns either Ok(RSA) containing the RSA struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::fs;
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::rsa::RSA;
    ///
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let key_path = "../../../certs/client-keyPub.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut rsa = RSA::new_public_from_der(&der).expect("Error with new_public_from_der()");
    /// rsa.set_rng(&mut rng).expect("Error with set_rng()");
    /// let plain: &[u8] = b"Test message";
    /// let mut enc: [u8; 512] = [0; 512];
    /// let enc_len = rsa.public_encrypt(plain, &mut enc, &mut rng).expect("Error with public_encrypt()");
    /// assert!(enc_len > 0 && enc_len <= 512);
    ///
    /// let key_path = "../../../certs/client-key.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut rsa = RSA::new_from_der(&der).expect("Error with new_from_der()");
    /// rsa.set_rng(&mut rng).expect("Error with set_rng()");
    /// let mut plain_out: [u8; 512] = [0; 512];
    /// let dec_len = rsa.private_decrypt(&enc[0..enc_len], &mut plain_out).expect("Error with private_decrypt()");
    /// assert!(dec_len as usize == plain.len());
    /// assert_eq!(plain_out[0..dec_len], *plain);
    /// ```
    pub fn new_from_der(der: &[u8]) -> Result<Self, i32> {
        Self::new_from_der_ex(der, None, None)
    }

    /// Load a public and private RSA keypair from DER-encoded buffer with
    /// optional heap and device ID.
    ///
    /// # Parameters
    ///
    /// * `der`: DER-encoded input buffer.
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(RSA) containing the RSA struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::fs;
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::rsa::RSA;
    ///
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let key_path = "../../../certs/client-keyPub.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut rsa = RSA::new_public_from_der(&der).expect("Error with new_public_from_der()");
    /// rsa.set_rng(&mut rng).expect("Error with set_rng()");
    /// let plain: &[u8] = b"Test message";
    /// let mut enc: [u8; 512] = [0; 512];
    /// let enc_len = rsa.public_encrypt(plain, &mut enc, &mut rng).expect("Error with public_encrypt()");
    /// assert!(enc_len > 0 && enc_len <= 512);
    ///
    /// let key_path = "../../../certs/client-key.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut rsa = RSA::new_from_der_ex(&der, None, None).expect("Error with new_from_der_ex()");
    /// rsa.set_rng(&mut rng).expect("Error with set_rng()");
    /// let mut plain_out: [u8; 512] = [0; 512];
    /// let dec_len = rsa.private_decrypt(&enc[0..enc_len], &mut plain_out).expect("Error with private_decrypt()");
    /// assert!(dec_len as usize == plain.len());
    /// assert_eq!(plain_out[0..dec_len], *plain);
    /// ```
    pub fn new_from_der_ex(der: &[u8], heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let mut wc_rsakey: MaybeUninit<sys::RsaKey> = MaybeUninit::uninit();
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_InitRsaKey_ex(wc_rsakey.as_mut_ptr(), heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        let mut wc_rsakey = unsafe { wc_rsakey.assume_init() };
        let der_ptr = der.as_ptr() as *const u8;
        let der_size = der.len() as u32;
        let mut idx: u32 = 0;
        let rc = unsafe {
            sys::wc_RsaPrivateKeyDecode(der_ptr, &mut idx, &mut wc_rsakey, der_size)
        };
        if rc != 0 {
            unsafe { sys::wc_FreeRsaKey(&mut wc_rsakey); }
            return Err(rc);
        }
        let rsa = RSA { wc_rsakey };
        Ok(rsa)
    }

    /// Load a public RSA key from DER-encoded buffer.
    ///
    /// # Parameters
    ///
    /// * `der`: DER-encoded input buffer.
    ///
    /// # Returns
    ///
    /// Returns either Ok(RSA) containing the RSA struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::fs;
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::rsa::RSA;
    ///
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let key_path = "../../../certs/client-keyPub.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut rsa = RSA::new_public_from_der(&der).expect("Error with new_public_from_der()");
    /// rsa.set_rng(&mut rng).expect("Error with set_rng()");
    /// let plain: &[u8] = b"Test message";
    /// let mut enc: [u8; 512] = [0; 512];
    /// let enc_len = rsa.public_encrypt(plain, &mut enc, &mut rng).expect("Error with public_encrypt()");
    /// assert!(enc_len > 0 && enc_len <= 512);
    ///
    /// let key_path = "../../../certs/client-key.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut rsa = RSA::new_from_der(&der).expect("Error with new_from_der()");
    /// rsa.set_rng(&mut rng).expect("Error with set_rng()");
    /// let mut plain_out: [u8; 512] = [0; 512];
    /// let dec_len = rsa.private_decrypt(&enc[0..enc_len], &mut plain_out).expect("Error with private_decrypt()");
    /// assert!(dec_len as usize == plain.len());
    /// assert_eq!(plain_out[0..dec_len], *plain);
    /// ```
    pub fn new_public_from_der(der: &[u8]) -> Result<Self, i32> {
        Self::new_public_from_der_ex(der, None, None)
    }

    /// Load a public RSA key from DER-encoded buffer with optional heap and
    /// device ID.
    ///
    /// # Parameters
    ///
    /// * `der`: DER-encoded input buffer.
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(RSA) containing the RSA struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::fs;
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::rsa::RSA;
    ///
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let key_path = "../../../certs/client-keyPub.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut rsa = RSA::new_public_from_der_ex(&der, None, None).expect("Error with new_public_from_der_ex()");
    /// rsa.set_rng(&mut rng).expect("Error with set_rng()");
    /// let plain: &[u8] = b"Test message";
    /// let mut enc: [u8; 512] = [0; 512];
    /// let enc_len = rsa.public_encrypt(plain, &mut enc, &mut rng).expect("Error with public_encrypt()");
    /// assert!(enc_len > 0 && enc_len <= 512);
    ///
    /// let key_path = "../../../certs/client-key.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut rsa = RSA::new_from_der(&der).expect("Error with new_from_der()");
    /// rsa.set_rng(&mut rng).expect("Error with set_rng()");
    /// let mut plain_out: [u8; 512] = [0; 512];
    /// let dec_len = rsa.private_decrypt(&enc[0..enc_len], &mut plain_out).expect("Error with private_decrypt()");
    /// assert!(dec_len as usize == plain.len());
    /// assert_eq!(plain_out[0..dec_len], *plain);
    /// ```
    pub fn new_public_from_der_ex(der: &[u8], heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let mut wc_rsakey: MaybeUninit<sys::RsaKey> = MaybeUninit::uninit();
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_InitRsaKey_ex(wc_rsakey.as_mut_ptr(), heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        let mut wc_rsakey = unsafe { wc_rsakey.assume_init() };
        let der_ptr = der.as_ptr() as *const u8;
        let der_size = der.len() as u32;
        let mut idx: u32 = 0;
        let rc = unsafe {
            sys::wc_RsaPublicKeyDecode(der_ptr, &mut idx, &mut wc_rsakey, der_size)
        };
        if rc != 0 {
            unsafe { sys::wc_FreeRsaKey(&mut wc_rsakey); }
            return Err(rc);
        }
        let rsa = RSA { wc_rsakey };
        Ok(rsa)
    }

    /// Generate a new RSA key using the given size and exponent.
    ///
    /// This function generates an RSA private key of length size (in bits) and
    /// given exponent (e). It then returns the RSA structure instance so that
    /// it may be used for encryption or signing operations. A secure number to
    /// use for e is 65537. size is required to be greater than or equal to
    /// RSA_MIN_SIZE and less than or equal to RSA_MAX_SIZE. For this function
    /// to be available, the option WOLFSSL_KEY_GEN must be enabled at compile
    /// time. This can be accomplished with --enable-keygen if using
    /// `./configure`.
    ///
    /// # Parameters
    ///
    /// * `size`: Desired key length in bits.
    /// * `e`: Exponent parameter to use for generating the key. A secure
    ///   choice is 65537.
    /// * `rng`: Reference to a `RNG` struct to use for random number
    ///   generation while making the key.
    ///
    /// # Returns
    ///
    /// Returns either Ok(RSA) containing the RSA struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(rsa_keygen)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::rsa::RSA;
    ///
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut rsa = RSA::generate(2048, 65537, &mut rng).expect("Error with generate()");
    /// rsa.check().expect("Error with check()");
    /// let encrypt_size = rsa.get_encrypt_size().expect("Error with get_encrypt_size()");
    /// assert_eq!(encrypt_size, 256);
    /// }
    /// ```
    #[cfg(rsa_keygen)]
    pub fn generate(size: i32, e: i64, rng: &mut RNG) -> Result<Self, i32> {
        Self::generate_ex(size, e, rng, None, None)
    }

    /// Generate a new RSA key using the given size and exponent with optional
    /// heap and device ID.
    ///
    /// This function generates an RSA private key of length size (in bits) and
    /// given exponent (e). It then returns the RSA structure instance so that
    /// it may be used for encryption or signing operations. A secure number to
    /// use for e is 65537. size is required to be greater than or equal to
    /// RSA_MIN_SIZE and less than or equal to RSA_MAX_SIZE. For this function
    /// to be available, the option WOLFSSL_KEY_GEN must be enabled at compile
    /// time. This can be accomplished with --enable-keygen if using
    /// `./configure`.
    ///
    /// # Parameters
    ///
    /// * `size`: Desired key length in bits.
    /// * `e`: Exponent parameter to use for generating the key. A secure
    ///   choice is 65537.
    /// * `rng`: Reference to a `RNG` struct to use for random number
    ///   generation while making the key.
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(RSA) containing the RSA struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(rsa_keygen)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::rsa::RSA;
    ///
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut rsa = RSA::generate_ex(2048, 65537, &mut rng, None, None).expect("Error with generate_ex()");
    /// rsa.check().expect("Error with check()");
    /// let encrypt_size = rsa.get_encrypt_size().expect("Error with get_encrypt_size()");
    /// assert_eq!(encrypt_size, 256);
    /// }
    /// ```
    #[cfg(rsa_keygen)]
    pub fn generate_ex(size: i32, e: i64, rng: &mut RNG, heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let mut wc_rsakey: MaybeUninit<sys::RsaKey> = MaybeUninit::uninit();
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_InitRsaKey_ex(wc_rsakey.as_mut_ptr(), heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        let mut wc_rsakey = unsafe { wc_rsakey.assume_init() };
        let rc = unsafe {
            sys::wc_MakeRsaKey(&mut wc_rsakey, size, e, &mut rng.wc_rng)
        };
        if rc != 0 {
            unsafe { sys::wc_FreeRsaKey(&mut wc_rsakey); }
            return Err(rc);
        }
        let rsa = RSA { wc_rsakey };
        Ok(rsa)
    }

    /// Export public and private RSA parameters from an RSA key.
    ///
    /// # Parameters
    ///
    /// * `e`: Slice in which to hold `e` key parameter.
    /// * `e_size`: Output holding the number of bytes written to `e`.
    /// * `n`: Slice in which to hold `n` key parameter.
    /// * `n_size`: Output holding the number of bytes written to `n`.
    /// * `d`: Slice in which to hold `d` key parameter.
    /// * `d_size`: Output holding the number of bytes written to `d`.
    /// * `p`: Slice in which to hold `p` key parameter.
    /// * `p_size`: Output holding the number of bytes written to `p`.
    /// * `q`: Slice in which to hold `q` key parameter.
    /// * `q_size`: Output holding the number of bytes written to `q`.
    ///
    /// # Returns
    ///
    /// Returns Ok(()) on success or Err(e) containing the wolfSSL library
    /// error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(rsa_keygen)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::rsa::RSA;
    ///
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut rsa = RSA::generate(2048, 65537, &mut rng).expect("Error with generate()");
    /// let mut e: [u8; 256] = [0; 256];
    /// let mut e_size: u32 = 0;
    /// let mut n: [u8; 256] = [0; 256];
    /// let mut n_size: u32 = 0;
    /// let mut d: [u8; 256] = [0; 256];
    /// let mut d_size: u32 = 0;
    /// let mut p: [u8; 256] = [0; 256];
    /// let mut p_size: u32 = 0;
    /// let mut q: [u8; 256] = [0; 256];
    /// let mut q_size: u32 = 0;
    /// rsa.export_key(&mut e, &mut e_size, &mut n, &mut n_size,
    ///     &mut d, &mut d_size, &mut p, &mut p_size, &mut q, &mut q_size).expect("Error with export_key()");
    /// }
    /// ```
    pub fn export_key(&mut self,
            e: &mut [u8], e_size: &mut u32,
            n: &mut [u8], n_size: &mut u32,
            d: &mut [u8], d_size: &mut u32,
            p: &mut [u8], p_size: &mut u32,
            q: &mut [u8], q_size: &mut u32) -> Result<(), i32> {
        let e_ptr = e.as_ptr() as *mut u8;
        *e_size = e.len() as u32;
        let n_ptr = n.as_ptr() as *mut u8;
        *n_size = n.len() as u32;
        let d_ptr = d.as_ptr() as *mut u8;
        *d_size = d.len() as u32;
        let p_ptr = p.as_ptr() as *mut u8;
        *p_size = p.len() as u32;
        let q_ptr = q.as_ptr() as *mut u8;
        *q_size = q.len() as u32;
        let rc = unsafe {
            sys::wc_RsaExportKey(&mut self.wc_rsakey, e_ptr, e_size,
                n_ptr, n_size, d_ptr, d_size, p_ptr, p_size, q_ptr, q_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Export public RSA parameters from an RSA key.
    ///
    /// # Parameters
    ///
    /// * `e`: Slice in which to hold `e` key parameter.
    /// * `e_size`: Output holding the number of bytes written to `e`.
    /// * `n`: Slice in which to hold `n` key parameter.
    /// * `n_size`: Output holding the number of bytes written to `n`.
    ///
    /// # Returns
    ///
    /// Returns Ok(()) on success or Err(e) containing the wolfSSL library
    /// error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(rsa_keygen)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::rsa::RSA;
    ///
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut rsa = RSA::generate(2048, 65537, &mut rng).expect("Error with generate()");
    /// let mut e: [u8; 256] = [0; 256];
    /// let mut e_size: u32 = 0;
    /// let mut n: [u8; 256] = [0; 256];
    /// let mut n_size: u32 = 0;
    /// rsa.export_public_key(&mut e, &mut e_size, &mut n, &mut n_size).expect("Error with export_public_key()");
    /// }
    /// ```
    pub fn export_public_key(&mut self,
            e: &mut [u8], e_size: &mut u32,
            n: &mut [u8], n_size: &mut u32) -> Result<(), i32> {
        let e_ptr = e.as_ptr() as *mut u8;
        *e_size = e.len() as u32;
        let n_ptr = n.as_ptr() as *mut u8;
        *n_size = n.len() as u32;
        let rc = unsafe {
            sys::wc_RsaFlattenPublicKey(&mut self.wc_rsakey, e_ptr, e_size,
                n_ptr, n_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Get the encryption size for the RSA key.
    ///
    /// # Returns
    ///
    /// Returns Ok(size) on success or Err(e) containing the wolfSSL library
    /// error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(rsa_keygen)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::rsa::RSA;
    ///
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut rsa = RSA::generate(2048, 65537, &mut rng).expect("Error with generate()");
    /// let encrypt_size = rsa.get_encrypt_size().expect("Error with get_encrypt_size()");
    /// assert_eq!(encrypt_size, 256);
    /// }
    /// ```
    pub fn get_encrypt_size(&self) -> Result<usize, i32> {
        let rc = unsafe { sys::wc_RsaEncryptSize(&self.wc_rsakey) };
        if rc < 0 {
            return Err(rc);
        }
        Ok(rc as usize)
    }

    /// Check the RSA key.
    ///
    /// # Returns
    ///
    /// Returns Ok(()) on success or Err(e) containing the wolfSSL library
    /// error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(rsa_keygen)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::rsa::RSA;
    ///
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut rsa = RSA::generate(2048, 65537, &mut rng).expect("Error with generate()");
    /// rsa.check().expect("Error with check()");
    /// }
    /// ```
    pub fn check(&mut self) -> Result<(), i32> {
        let rc = unsafe { sys::wc_CheckRsaKey(&mut self.wc_rsakey) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Encrypt data using an RSA public key.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to encrypt.
    /// * `dout`: Buffer in which to store encrypted data.
    /// * `rng`: Reference to a `RNG` struct to use for random number
    ///   generation while encrypting.
    ///
    /// # Returns
    ///
    /// Returns Ok(size) on success or Err(e) containing the wolfSSL library
    /// error code value.
    /// The size returned specifies the number of bytes written to the `dout`
    /// buffer.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::fs;
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::rsa::RSA;
    ///
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let key_path = "../../../certs/client-keyPub.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut rsa = RSA::new_public_from_der(&der).expect("Error with new_public_from_der()");
    /// rsa.set_rng(&mut rng).expect("Error with set_rng()");
    /// let plain: &[u8] = b"Test message";
    /// let mut enc: [u8; 512] = [0; 512];
    /// let enc_len = rsa.public_encrypt(plain, &mut enc, &mut rng).expect("Error with public_encrypt()");
    /// assert!(enc_len > 0 && enc_len <= 512);
    ///
    /// let key_path = "../../../certs/client-key.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut rsa = RSA::new_from_der(&der).expect("Error with new_from_der()");
    /// rsa.set_rng(&mut rng).expect("Error with set_rng()");
    /// let mut plain_out: [u8; 512] = [0; 512];
    /// let dec_len = rsa.private_decrypt(&enc[0..enc_len], &mut plain_out).expect("Error with private_decrypt()");
    /// assert!(dec_len as usize == plain.len());
    /// assert_eq!(plain_out[0..dec_len], *plain);
    /// ```
    pub fn public_encrypt(&mut self, din: &[u8], dout: &mut [u8], rng: &mut RNG) -> Result<usize, i32> {
        let din_ptr = din.as_ptr() as *const u8;
        let din_size = din.len() as u32;
        let dout_ptr = dout.as_ptr() as *mut u8;
        let dout_size = dout.len() as u32;
        let rc = unsafe {
            sys::wc_RsaPublicEncrypt(din_ptr, din_size, dout_ptr, dout_size,
                &mut self.wc_rsakey, &mut rng.wc_rng)
        };
        if rc < 0 {
            return Err(rc);
        }
        Ok(rc as usize)
    }

    /// Decrypt data using an RSA private key.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to decrypt.
    /// * `dout`: Buffer in which to store decrypted data.
    ///
    /// # Returns
    ///
    /// Returns Ok(size) on success or Err(e) containing the wolfSSL library
    /// error code value.
    /// The size returned specifies the number of bytes written to the `dout`
    /// buffer.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::fs;
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::rsa::RSA;
    ///
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let key_path = "../../../certs/client-keyPub.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut rsa = RSA::new_public_from_der(&der).expect("Error with new_public_from_der()");
    /// rsa.set_rng(&mut rng).expect("Error with set_rng()");
    /// let plain: &[u8] = b"Test message";
    /// let mut enc: [u8; 512] = [0; 512];
    /// let enc_len = rsa.public_encrypt(plain, &mut enc, &mut rng).expect("Error with public_encrypt()");
    /// assert!(enc_len > 0 && enc_len <= 512);
    ///
    /// let key_path = "../../../certs/client-key.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut rsa = RSA::new_from_der(&der).expect("Error with new_from_der()");
    /// rsa.set_rng(&mut rng).expect("Error with set_rng()");
    /// let mut plain_out: [u8; 512] = [0; 512];
    /// let dec_len = rsa.private_decrypt(&enc[0..enc_len], &mut plain_out).expect("Error with private_decrypt()");
    /// assert!(dec_len as usize == plain.len());
    /// assert_eq!(plain_out[0..dec_len], *plain);
    /// ```
    pub fn private_decrypt(&mut self, din: &[u8], dout: &mut [u8]) -> Result<usize, i32> {
        let din_ptr = din.as_ptr() as *const u8;
        let din_size = din.len() as u32;
        let dout_ptr = dout.as_ptr() as *mut u8;
        let dout_size = dout.len() as u32;
        let rc = unsafe {
            sys::wc_RsaPrivateDecrypt(din_ptr, din_size, dout_ptr, dout_size,
                &mut self.wc_rsakey)
        };
        if rc < 0 {
            return Err(rc);
        }
        Ok(rc as usize)
    }

    /// Sign the provided data with the private key using RSA-PSS signature
    /// scheme.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to sign.
    /// * `dout`: Buffer in which to store output signature.
    /// * `hash_algo`: Hash algorithm type to use, one of RSA::HASH_TYPE_*.
    /// * `mgf`: Mask generation function to use, one of RSA::MGF*.
    /// * `rng`: Reference to a `RNG` struct to use for random number
    ///   generation while signing.
    ///
    /// # Returns
    ///
    /// Returns Ok(size) on success or Err(e) containing the wolfSSL library
    /// error code value.
    /// The size returned specifies the number of bytes written to the `dout`
    /// buffer.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::fs;
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::rsa::RSA;
    ///
    /// let mut rng = RNG::new().expect("Error creating RNG");
    ///
    /// let key_path = "../../../certs/client-key.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut rsa = RSA::new_from_der(&der).expect("Error with new_from_der()");
    /// let msg: &[u8] = b"This is the string to be signed!";
    /// let mut signature: [u8; 512] = [0; 512];
    /// let sig_len = rsa.pss_sign(msg, &mut signature, RSA::HASH_TYPE_SHA256, RSA::MGF1SHA256, &mut rng).expect("Error with pss_sign()");
    /// assert!(sig_len > 0 && sig_len <= 512);
    ///
    /// let key_path = "../../../certs/client-keyPub.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut rsa = RSA::new_public_from_der(&der).expect("Error with new_public_from_der()");
    /// rsa.set_rng(&mut rng).expect("Error with set_rng()");
    /// let signature = &signature[0..sig_len];
    /// let mut verify_out: [u8; 512] = [0; 512];
    /// let verify_out_size = rsa.pss_verify(signature, &mut verify_out, RSA::HASH_TYPE_SHA256, RSA::MGF1SHA256).expect("Error with pss_verify()");
    /// let verify_out = &verify_out[0..verify_out_size];
    /// rsa.pss_check_padding(msg, verify_out, RSA::HASH_TYPE_SHA256).expect("Error with pss_check_padding()");
    ///
    /// let mut verify_out: [u8; 512] = [0; 512];
    /// rsa.pss_verify_check(signature, &mut verify_out, msg, RSA::HASH_TYPE_SHA256, RSA::MGF1SHA256).expect("Error with pss_verify_check()");
    /// ```
    pub fn pss_sign(&mut self, din: &[u8], dout: &mut [u8], hash_algo: u32, mgf: i32, rng: &mut RNG) -> Result<usize, i32> {
        let din_ptr = din.as_ptr() as *const u8;
        let din_size = din.len() as u32;
        let dout_ptr = dout.as_ptr() as *mut u8;
        let dout_size = dout.len() as u32;
        let rc = unsafe {
            sys::wc_RsaPSS_Sign(din_ptr, din_size, dout_ptr, dout_size,
                hash_algo, mgf, &mut self.wc_rsakey, &mut rng.wc_rng)
        };
        if rc < 0 {
            return Err(rc);
        }
        Ok(rc as usize)
    }

    /// Check the PSS data to ensure the signature matches.
    ///
    /// `set_rng()` must be called previously when wolfSSL is built with
    /// WC_RSA_BLINDING option enabled.
    ///
    /// # Parameters
    ///
    /// * `din`: Hash of data being verified.
    /// * `sig`: Buffer holding PSS data (output from `pss_verify()`).
    /// * `hash_algo`: Hash algorithm type to use, one of RSA::HASH_TYPE_*.
    ///
    /// # Returns
    ///
    /// Returns Ok(()) on success or Err(e) containing the wolfSSL library
    /// error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::fs;
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::rsa::RSA;
    ///
    /// let mut rng = RNG::new().expect("Error creating RNG");
    ///
    /// let key_path = "../../../certs/client-key.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut rsa = RSA::new_from_der(&der).expect("Error with new_from_der()");
    /// let msg: &[u8] = b"This is the string to be signed!";
    /// let mut signature: [u8; 512] = [0; 512];
    /// let sig_len = rsa.pss_sign(msg, &mut signature, RSA::HASH_TYPE_SHA256, RSA::MGF1SHA256, &mut rng).expect("Error with pss_sign()");
    /// assert!(sig_len > 0 && sig_len <= 512);
    ///
    /// let key_path = "../../../certs/client-keyPub.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut rsa = RSA::new_public_from_der(&der).expect("Error with new_public_from_der()");
    /// rsa.set_rng(&mut rng).expect("Error with set_rng()");
    /// let signature = &signature[0..sig_len];
    /// let mut verify_out: [u8; 512] = [0; 512];
    /// let verify_out_size = rsa.pss_verify(signature, &mut verify_out, RSA::HASH_TYPE_SHA256, RSA::MGF1SHA256).expect("Error with pss_verify()");
    /// let verify_out = &verify_out[0..verify_out_size];
    /// rsa.pss_check_padding(msg, verify_out, RSA::HASH_TYPE_SHA256).expect("Error with pss_check_padding()");
    ///
    /// let mut verify_out: [u8; 512] = [0; 512];
    /// rsa.pss_verify_check(signature, &mut verify_out, msg, RSA::HASH_TYPE_SHA256, RSA::MGF1SHA256).expect("Error with pss_verify_check()");
    /// ```
    pub fn pss_check_padding(&mut self, din: &[u8], sig: &[u8], hash_algo: u32) -> Result<(), i32> {
        let din_ptr = din.as_ptr() as *const u8;
        let din_size = din.len() as u32;
        let sig_ptr = sig.as_ptr() as *const u8;
        let sig_size = sig.len() as u32;
        let rc = unsafe {
            sys::wc_RsaPSS_CheckPadding(din_ptr, din_size, sig_ptr, sig_size,
                hash_algo)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Decrypt input signature to verify that the message was signed by key.
    ///
    /// `set_rng()` must be called previously when wolfSSL is built with
    /// WC_RSA_BLINDING option enabled.
    ///
    /// # Parameters
    ///
    /// * `din`: Input data to decrypt.
    /// * `dout`: Buffer in which to store decrypted data.
    /// * `hash_algo`: Hash algorithm type to use, one of RSA::HASH_TYPE_*.
    /// * `mgf`: Mask generation function to use, one of RSA::MGF*.
    ///
    /// # Returns
    ///
    /// Returns Ok(size) on success or Err(e) containing the wolfSSL library
    /// error code value.
    /// The size returned specifies the number of bytes written to the `dout`
    /// buffer.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::fs;
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::rsa::RSA;
    ///
    /// let mut rng = RNG::new().expect("Error creating RNG");
    ///
    /// let key_path = "../../../certs/client-key.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut rsa = RSA::new_from_der(&der).expect("Error with new_from_der()");
    /// let msg: &[u8] = b"This is the string to be signed!";
    /// let mut signature: [u8; 512] = [0; 512];
    /// let sig_len = rsa.pss_sign(msg, &mut signature, RSA::HASH_TYPE_SHA256, RSA::MGF1SHA256, &mut rng).expect("Error with pss_sign()");
    /// assert!(sig_len > 0 && sig_len <= 512);
    ///
    /// let key_path = "../../../certs/client-keyPub.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut rsa = RSA::new_public_from_der(&der).expect("Error with new_public_from_der()");
    /// rsa.set_rng(&mut rng).expect("Error with set_rng()");
    /// let signature = &signature[0..sig_len];
    /// let mut verify_out: [u8; 512] = [0; 512];
    /// let verify_out_size = rsa.pss_verify(signature, &mut verify_out, RSA::HASH_TYPE_SHA256, RSA::MGF1SHA256).expect("Error with pss_verify()");
    /// let verify_out = &verify_out[0..verify_out_size];
    /// rsa.pss_check_padding(msg, verify_out, RSA::HASH_TYPE_SHA256).expect("Error with pss_check_padding()");
    ///
    /// let mut verify_out: [u8; 512] = [0; 512];
    /// rsa.pss_verify_check(signature, &mut verify_out, msg, RSA::HASH_TYPE_SHA256, RSA::MGF1SHA256).expect("Error with pss_verify_check()");
    /// ```
    pub fn pss_verify(&mut self, din: &[u8], dout: &mut [u8], hash_algo: u32, mgf: i32) -> Result<usize, i32> {
        let din_ptr = din.as_ptr() as *const u8;
        let din_size = din.len() as u32;
        let dout_ptr = dout.as_ptr() as *mut u8;
        let dout_size = dout.len() as u32;
        let rc = unsafe {
            sys::wc_RsaPSS_Verify(din_ptr, din_size, dout_ptr, dout_size,
                hash_algo, mgf, &mut self.wc_rsakey)
        };
        if rc < 0 {
            return Err(rc);
        }
        Ok(rc as usize)
    }

    /// Verify the message signed with RSA-PSS.
    ///
    /// This method combines the functionality of `pss_verify()` and
    /// `pss_check_padding()`.
    ///
    /// `set_rng()` must be called previously when wolfSSL is built with
    /// WC_RSA_BLINDING option enabled.
    ///
    /// # Parameters
    ///
    /// * `din`: Input data to decrypt.
    /// * `dout`: Buffer in which to store decrypted data.
    /// * `digest`: Hash of data being verified.
    /// * `hash_algo`: Hash algorithm type to use, one of RSA::HASH_TYPE_*.
    /// * `mgf`: Mask generation function to use, one of RSA::MGF*.
    ///
    /// # Returns
    ///
    /// Returns Ok(size) on success or Err(e) containing the wolfSSL library
    /// error code value.
    /// The size returned specifies the number of bytes written to the `dout`
    /// buffer.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::fs;
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::rsa::RSA;
    ///
    /// let mut rng = RNG::new().expect("Error creating RNG");
    ///
    /// let key_path = "../../../certs/client-key.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut rsa = RSA::new_from_der(&der).expect("Error with new_from_der()");
    /// let msg: &[u8] = b"This is the string to be signed!";
    /// let mut signature: [u8; 512] = [0; 512];
    /// let sig_len = rsa.pss_sign(msg, &mut signature, RSA::HASH_TYPE_SHA256, RSA::MGF1SHA256, &mut rng).expect("Error with pss_sign()");
    /// assert!(sig_len > 0 && sig_len <= 512);
    ///
    /// let key_path = "../../../certs/client-keyPub.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut rsa = RSA::new_public_from_der(&der).expect("Error with new_public_from_der()");
    /// rsa.set_rng(&mut rng).expect("Error with set_rng()");
    /// let signature = &signature[0..sig_len];
    /// let mut verify_out: [u8; 512] = [0; 512];
    /// let verify_out_size = rsa.pss_verify(signature, &mut verify_out, RSA::HASH_TYPE_SHA256, RSA::MGF1SHA256).expect("Error with pss_verify()");
    /// let verify_out = &verify_out[0..verify_out_size];
    /// rsa.pss_check_padding(msg, verify_out, RSA::HASH_TYPE_SHA256).expect("Error with pss_check_padding()");
    ///
    /// let mut verify_out: [u8; 512] = [0; 512];
    /// rsa.pss_verify_check(signature, &mut verify_out, msg, RSA::HASH_TYPE_SHA256, RSA::MGF1SHA256).expect("Error with pss_verify_check()");
    /// ```
    pub fn pss_verify_check(&mut self, din: &[u8], dout: &mut [u8], digest: &[u8], hash_algo: u32, mgf: i32) -> Result<usize, i32> {
        let din_ptr = din.as_ptr() as *const u8;
        let din_size = din.len() as u32;
        let dout_ptr = dout.as_ptr() as *mut u8;
        let dout_size = dout.len() as u32;
        let digest_ptr = digest.as_ptr() as *const u8;
        let digest_size = digest.len() as u32;
        let rc = unsafe {
            sys::wc_RsaPSS_VerifyCheck(din_ptr, din_size, dout_ptr, dout_size,
                digest_ptr, digest_size, hash_algo, mgf, &mut self.wc_rsakey)
        };
        if rc < 0 {
            return Err(rc);
        }
        Ok(rc as usize)
    }

    /// Perform the RSA operation directly with no padding.
    ///
    /// The input size must match key size. Typically this is used when padding
    /// is already done on the RSA input.
    ///
    /// # Parameters
    ///
    /// * `din`: Input data to encrypt/decrypt.
    /// * `dout`: Buffer in which to store output.
    /// * `typ`: Operation type, one of `RSA::PUBLIC_ENCRYPT`,
    ///   `RSA::PUBLIC_DECRYPT`, `RSA::PRIVATE_ENCRYPT`, `RSA::PRIVATE_DECRYPT`.
    /// * `rng`: Reference to a `RNG` struct to use for random number
    ///   generation while signing.
    ///
    /// # Returns
    ///
    /// Returns Ok(size) on success or Err(e) containing the wolfSSL library
    /// error code value.
    /// The size returned specifies the number of bytes written to the `dout`
    /// buffer.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(rsa_direct)]
    /// {
    /// use std::fs;
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::rsa::RSA;
    ///
    /// let mut rng = RNG::new().expect("Error creating RNG");
    ///
    /// let key_path = "../../../certs/client-key.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut rsa = RSA::new_from_der(&der).expect("Error with new_from_der()");
    /// let msg = b"A rsa_direct() test input string";
    /// let mut plain = [0u8; 256];
    /// plain[..msg.len()].copy_from_slice(msg);
    /// let mut enc = [0u8; 256];
    /// let enc_len = rsa.rsa_direct(&plain, &mut enc, RSA::PRIVATE_ENCRYPT, &mut rng).expect("Error with rsa_direct()");
    /// assert_eq!(enc_len, 256);
    /// let mut plain_out = [0u8; 256];
    /// let dec_len = rsa.rsa_direct(&enc, &mut plain_out, RSA::PUBLIC_DECRYPT, &mut rng).expect("Error with rsa_direct()");
    /// assert_eq!(dec_len, 256);
    /// assert_eq!(plain_out, plain);
    /// }
    /// ```
    #[cfg(rsa_direct)]
    pub fn rsa_direct(&mut self, din: &[u8], dout: &mut [u8], typ: i32, rng: &mut RNG) -> Result<usize, i32> {
        let din_ptr = din.as_ptr() as *const u8;
        let din_size = din.len() as u32;
        let dout_ptr = dout.as_ptr() as *mut u8;
        let mut dout_size = dout.len() as u32;
        let rc = unsafe {
            sys::wc_RsaDirect(din_ptr, din_size, dout_ptr, &mut dout_size,
                &mut self.wc_rsakey, typ, &mut rng.wc_rng)
        };
        if rc < 0 {
            return Err(rc);
        }
        Ok(dout_size as usize)
    }

    /// Associates a `RNG` instance with this `RSA` instance.
    ///
    /// This is necessary when wolfSSL is built with the `WC_RSA_BLINDING`
    /// build option enabled.
    ///
    /// # Parameters
    ///
    /// * `rng`: The `RNG` struct instance to associate with this `RSA`
    ///   instance. The `RNG` struct should not be moved in memory after
    ///   calling this method.
    ///
    /// # Returns
    ///
    /// Returns Ok(()) on success or Err(e) containing the wolfSSL library
    /// error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::fs;
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::rsa::RSA;
    ///
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let key_path = "../../../certs/client-keyPub.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut rsa = RSA::new_public_from_der(&der).expect("Error with new_public_from_der()");
    /// rsa.set_rng(&mut rng).expect("Error with set_rng()");
    /// let plain: &[u8] = b"Test message";
    /// let mut enc: [u8; 512] = [0; 512];
    /// let enc_len = rsa.public_encrypt(plain, &mut enc, &mut rng).expect("Error with public_encrypt()");
    /// assert!(enc_len > 0 && enc_len <= 512);

    /// let key_path = "../../../certs/client-key.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut rsa = RSA::new_from_der(&der).expect("Error with new_from_der()");
    /// rsa.set_rng(&mut rng).expect("Error with set_rng()");
    /// let mut plain_out: [u8; 512] = [0; 512];
    /// let dec_len = rsa.private_decrypt(&enc[0..enc_len], &mut plain_out).expect("Error with private_decrypt()");
    /// assert!(dec_len as usize == plain.len());
    /// assert_eq!(plain_out[0..dec_len], *plain);
    /// ```
    pub fn set_rng(&mut self, rng: &mut RNG) -> Result<(), i32> {
        let rc = unsafe {
            sys::wc_RsaSetRNG(&mut self.wc_rsakey, &mut rng.wc_rng)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Sign the provided data with the private key.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to sign.
    /// * `dout`: Buffer in which to store output signature.
    /// * `rng`: Reference to a `RNG` struct to use for random number
    ///   generation while signing.
    ///
    /// # Returns
    ///
    /// Returns Ok(size) on success or Err(e) containing the wolfSSL library
    /// error code value.
    /// The size returned specifies the number of bytes written to the `dout`
    /// buffer.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::fs;
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::rsa::RSA;
    ///
    /// let mut rng = RNG::new().expect("Error creating RNG");
    ///
    /// let key_path = "../../../certs/client-key.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut rsa = RSA::new_from_der(&der).expect("Error with new_from_der()");
    /// let msg: &[u8] = b"This is the string to be signed!";
    /// let mut signature: [u8; 512] = [0; 512];
    /// let sig_len = rsa.ssl_sign(msg, &mut signature, &mut rng).expect("Error with ssl_sign()");
    /// assert!(sig_len > 0 && sig_len <= 512);
    ///
    /// let key_path = "../../../certs/client-keyPub.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut rsa = RSA::new_public_from_der(&der).expect("Error with new_public_from_der()");
    /// rsa.set_rng(&mut rng).expect("Error with set_rng()");
    /// let signature = &signature[0..sig_len];
    /// let mut verify_out: [u8; 512] = [0; 512];
    /// let verify_out_size = rsa.ssl_verify(signature, &mut verify_out).expect("Error with ssl_verify()");
    /// assert!(verify_out_size > 0 && verify_out_size <= 512);
    /// ```
    pub fn ssl_sign(&mut self, din: &[u8], dout: &mut [u8], rng: &mut RNG) -> Result<usize, i32> {
        let din_ptr = din.as_ptr() as *const u8;
        let din_size = din.len() as u32;
        let dout_ptr = dout.as_ptr() as *mut u8;
        let dout_size = dout.len() as u32;
        let rc = unsafe {
            sys::wc_RsaSSL_Sign(din_ptr, din_size, dout_ptr, dout_size,
                &mut self.wc_rsakey, &mut rng.wc_rng)
        };
        if rc < 0 {
            return Err(rc);
        }
        Ok(rc as usize)
    }

    /// Decrypt input signature to verify that the message was signed by key.
    ///
    /// `set_rng()` must be called previously when wolfSSL is built with
    /// WC_RSA_BLINDING option enabled.
    ///
    /// # Parameters
    ///
    /// * `din`: Input data to decrypt.
    /// * `dout`: Buffer in which to store decrypted data.
    ///
    /// # Returns
    ///
    /// Returns Ok(size) on success or Err(e) containing the wolfSSL library
    /// error code value.
    /// The size returned specifies the number of bytes written to the `dout`
    /// buffer.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::fs;
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::rsa::RSA;
    ///
    /// let mut rng = RNG::new().expect("Error creating RNG");
    ///
    /// let key_path = "../../../certs/client-key.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut rsa = RSA::new_from_der(&der).expect("Error with new_from_der()");
    /// let msg: &[u8] = b"This is the string to be signed!";
    /// let mut signature: [u8; 512] = [0; 512];
    /// let sig_len = rsa.ssl_sign(msg, &mut signature, &mut rng).expect("Error with ssl_sign()");
    /// assert!(sig_len > 0 && sig_len <= 512);
    ///
    /// let key_path = "../../../certs/client-keyPub.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut rsa = RSA::new_public_from_der(&der).expect("Error with new_public_from_der()");
    /// rsa.set_rng(&mut rng).expect("Error with set_rng()");
    /// let signature = &signature[0..sig_len];
    /// let mut verify_out: [u8; 512] = [0; 512];
    /// let verify_out_size = rsa.ssl_verify(signature, &mut verify_out).expect("Error with ssl_verify()");
    /// assert!(verify_out_size > 0 && verify_out_size <= 512);
    /// ```
    pub fn ssl_verify(&mut self, din: &[u8], dout: &mut [u8]) -> Result<usize, i32> {
        let din_ptr = din.as_ptr() as *const u8;
        let din_size = din.len() as u32;
        let dout_ptr = dout.as_ptr() as *mut u8;
        let dout_size = dout.len() as u32;
        let rc = unsafe {
            sys::wc_RsaSSL_Verify(din_ptr, din_size, dout_ptr, dout_size,
                &mut self.wc_rsakey)
        };
        if rc < 0 {
            return Err(rc);
        }
        Ok(rc as usize)
    }
}

impl Drop for RSA {
    /// Safely free the underlying wolfSSL RSA context.
    ///
    /// This calls the `wc_FreeRsaKey` wolfssl library function.
    ///
    /// The Rust Drop trait guarantees that this method is called when the RSA
    /// struct goes out of scope, automatically cleaning up resources and
    /// preventing memory leaks.
    fn drop(&mut self) {
        unsafe { sys::wc_FreeRsaKey(&mut self.wc_rsakey); }
    }
}
