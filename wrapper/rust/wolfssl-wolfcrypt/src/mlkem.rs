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

/*!
This module provides a Rust wrapper for the wolfCrypt library's ML-KEM
(Module-Lattice-Based Key-Encapsulation Mechanism) post-quantum key
encapsulation functionality.

The primary component is the [`MlKem`] struct, which manages the lifecycle of
a wolfSSL `MlKemKey` object. It ensures proper initialization and deallocation.

Three security parameter sets are supported, selected via the type argument at
construction time:

| Constant              | NIST Security Level |
|-----------------------|---------------------|
| [`MlKem::TYPE_512`]   | 1 (ML-KEM-512)      |
| [`MlKem::TYPE_768`]   | 3 (ML-KEM-768)      |
| [`MlKem::TYPE_1024`]  | 5 (ML-KEM-1024)     |

# Examples

```rust
#[cfg(all(mlkem, random))]
{
use wolfssl_wolfcrypt::random::RNG;
use wolfssl_wolfcrypt::mlkem::MlKem;
let mut rng = RNG::new().expect("RNG creation failed");
let mut alice = MlKem::generate(MlKem::TYPE_768, &mut rng)
    .expect("Key generation failed");
let ct_size = alice.cipher_text_size().expect("cipher_text_size failed");
let ss_size = alice.shared_secret_size().expect("shared_secret_size failed");
let mut ct = vec![0u8; ct_size];
let mut ss_alice = vec![0u8; ss_size];
alice.encapsulate(&mut ct, &mut ss_alice, &mut rng)
    .expect("Encapsulation failed");
let mut ss_bob = vec![0u8; ss_size];
alice.decapsulate(&mut ss_bob, &ct)
    .expect("Decapsulation failed");
assert_eq!(ss_alice, ss_bob);
}
```
*/

#![cfg(mlkem)]

use crate::sys;
#[cfg(random)]
use crate::random::RNG;

/// Rust wrapper for a wolfSSL `MlKemKey` object.
///
/// Manages the lifecycle of the underlying heap-allocated key, including
/// initialization and deallocation via the [`Drop`] trait.
///
/// An instance is created with [`MlKem::generate()`],
/// [`MlKem::generate_with_random()`], or [`MlKem::new()`].
pub struct MlKem {
    ws_key: *mut sys::MlKemKey,
}

impl MlKem {
    /// ML-KEM-512 key type (NIST Security Level 1).
    pub const TYPE_512: i32 = sys::WC_ML_KEM_512 as i32;
    /// ML-KEM-768 key type (NIST Security Level 3).
    pub const TYPE_768: i32 = sys::WC_ML_KEM_768 as i32;
    /// ML-KEM-1024 key type (NIST Security Level 5).
    pub const TYPE_1024: i32 = sys::WC_ML_KEM_1024 as i32;

    /// Symmetric data size in bytes (`WC_ML_KEM_SYM_SZ` = 32).
    pub const SYM_SIZE: usize = sys::WC_ML_KEM_SYM_SZ as usize;
    /// Shared secret size in bytes (`WC_ML_KEM_SS_SZ` = 32).
    pub const SHARED_SECRET_SIZE: usize = sys::WC_ML_KEM_SS_SZ as usize;
    /// Random bytes required for key generation (`WC_ML_KEM_MAKEKEY_RAND_SZ` = 64).
    pub const MAKEKEY_RAND_SIZE: usize = sys::WC_ML_KEM_MAKEKEY_RAND_SZ as usize;
    /// Random bytes required for encapsulation (`WC_ML_KEM_ENC_RAND_SZ` = 32).
    pub const ENC_RAND_SIZE: usize = sys::WC_ML_KEM_ENC_RAND_SZ as usize;

    /// Generate a new ML-KEM key pair using a random number generator.
    ///
    /// # Parameters
    ///
    /// * `key_type`: Key type. One of [`MlKem::TYPE_512`], [`MlKem::TYPE_768`],
    ///   or [`MlKem::TYPE_1024`].
    /// * `rng`: `RNG` instance to use for random number generation.
    ///
    /// # Returns
    ///
    /// Returns either Ok(MlKem) containing the key instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(mlkem, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::mlkem::MlKem;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let key = MlKem::generate(MlKem::TYPE_768, &mut rng)
    ///     .expect("Error with generate()");
    /// }
    /// ```
    #[cfg(random)]
    pub fn generate(key_type: i32, rng: &mut RNG) -> Result<Self, i32> {
        Self::generate_ex(key_type, rng, None, None)
    }

    /// Generate a new ML-KEM key pair with optional heap hint and device ID.
    ///
    /// # Parameters
    ///
    /// * `key_type`: Key type. One of [`MlKem::TYPE_512`], [`MlKem::TYPE_768`],
    ///   or [`MlKem::TYPE_1024`].
    /// * `rng`: `RNG` instance to use for random number generation.
    /// * `heap`: Optional heap hint.
    /// * `dev_id`: Optional device ID for crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(MlKem) containing the key instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(mlkem, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::mlkem::MlKem;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let key = MlKem::generate_ex(MlKem::TYPE_768, &mut rng, None, None)
    ///     .expect("Error with generate_ex()");
    /// }
    /// ```
    #[cfg(random)]
    pub fn generate_ex(
        key_type: i32,
        rng: &mut RNG,
        heap: Option<*mut core::ffi::c_void>,
        dev_id: Option<i32>,
    ) -> Result<Self, i32> {
        let key = Self::new_ex(key_type, heap, dev_id)?;
        let rc = unsafe { sys::wc_MlKemKey_MakeKey(key.ws_key, &mut rng.wc_rng) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(key)
    }

    /// Generate an ML-KEM key pair from caller-supplied random bytes.
    ///
    /// Produces the same key pair for a given `(key_type, rand)` pair, enabling
    /// deterministic key generation. The `rand` buffer must be exactly
    /// [`MlKem::MAKEKEY_RAND_SIZE`] (64) bytes.
    ///
    /// # Parameters
    ///
    /// * `key_type`: Key type. One of [`MlKem::TYPE_512`], [`MlKem::TYPE_768`],
    ///   or [`MlKem::TYPE_1024`].
    /// * `rand`: Random bytes. Must be `MAKEKEY_RAND_SIZE` (64) bytes.
    ///
    /// # Returns
    ///
    /// Returns either Ok(MlKem) containing the key instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(mlkem)]
    /// {
    /// use wolfssl_wolfcrypt::mlkem::MlKem;
    /// let rand = [0x42u8; 64];
    /// let key = MlKem::generate_with_random(MlKem::TYPE_768, &rand)
    ///     .expect("Error with generate_with_random()");
    /// }
    /// ```
    pub fn generate_with_random(key_type: i32, rand: &[u8]) -> Result<Self, i32> {
        Self::generate_with_random_ex(key_type, rand, None, None)
    }

    /// Generate an ML-KEM key pair from caller-supplied random bytes with
    /// optional heap hint and device ID.
    ///
    /// # Parameters
    ///
    /// * `key_type`: Key type. One of [`MlKem::TYPE_512`], [`MlKem::TYPE_768`],
    ///   or [`MlKem::TYPE_1024`].
    /// * `rand`: Random bytes. Must be `MAKEKEY_RAND_SIZE` (64) bytes.
    /// * `heap`: Optional heap hint.
    /// * `dev_id`: Optional device ID for crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(MlKem) containing the key instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(mlkem)]
    /// {
    /// use wolfssl_wolfcrypt::mlkem::MlKem;
    /// let rand = [0x42u8; 64];
    /// let key = MlKem::generate_with_random_ex(MlKem::TYPE_768, &rand, None, None)
    ///     .expect("Error with generate_with_random_ex()");
    /// }
    /// ```
    pub fn generate_with_random_ex(
        key_type: i32,
        rand: &[u8],
        heap: Option<*mut core::ffi::c_void>,
        dev_id: Option<i32>,
    ) -> Result<Self, i32> {
        if rand.len() != Self::MAKEKEY_RAND_SIZE {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let key = Self::new_ex(key_type, heap, dev_id)?;
        let rc = unsafe {
            sys::wc_MlKemKey_MakeKeyWithRandom(
                key.ws_key,
                rand.as_ptr(),
                rand.len() as core::ffi::c_int,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(key)
    }

    /// Create and initialize a new ML-KEM key instance without generating key
    /// material.
    ///
    /// Key material can be loaded afterwards using [`MlKem::decode_public_key()`]
    /// or [`MlKem::decode_private_key()`].
    ///
    /// # Parameters
    ///
    /// * `key_type`: Key type. One of [`MlKem::TYPE_512`], [`MlKem::TYPE_768`],
    ///   or [`MlKem::TYPE_1024`].
    ///
    /// # Returns
    ///
    /// Returns either Ok(MlKem) containing the key instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(mlkem)]
    /// {
    /// use wolfssl_wolfcrypt::mlkem::MlKem;
    /// let key = MlKem::new(MlKem::TYPE_768).expect("Error with new()");
    /// }
    /// ```
    pub fn new(key_type: i32) -> Result<Self, i32> {
        Self::new_ex(key_type, None, None)
    }

    /// Create and initialize a new ML-KEM key instance with optional heap hint
    /// and device ID.
    ///
    /// # Parameters
    ///
    /// * `key_type`: Key type. One of [`MlKem::TYPE_512`], [`MlKem::TYPE_768`],
    ///   or [`MlKem::TYPE_1024`].
    /// * `heap`: Optional heap hint.
    /// * `dev_id`: Optional device ID for crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(MlKem) containing the key instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(mlkem)]
    /// {
    /// use wolfssl_wolfcrypt::mlkem::MlKem;
    /// let key = MlKem::new_ex(MlKem::TYPE_768, None, None).expect("Error with new_ex()");
    /// }
    /// ```
    pub fn new_ex(
        key_type: i32,
        heap: Option<*mut core::ffi::c_void>,
        dev_id: Option<i32>,
    ) -> Result<Self, i32> {
        let heap = match heap {
            Some(h) => h,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(id) => id,
            None => sys::INVALID_DEVID,
        };
        let ws_key = unsafe { sys::wc_MlKemKey_New(key_type, heap, dev_id) };
        if ws_key.is_null() {
            return Err(sys::wolfCrypt_ErrorCodes_MEMORY_E);
        }
        Ok(MlKem { ws_key })
    }

    /// Get the cipher text size in bytes for this key's type.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) or Err(e) containing the wolfSSL library error
    /// code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(mlkem)]
    /// {
    /// use wolfssl_wolfcrypt::mlkem::MlKem;
    /// let mut key = MlKem::new(MlKem::TYPE_768).expect("Error with new()");
    /// let ct_size = key.cipher_text_size().expect("Error with cipher_text_size()");
    /// assert!(ct_size > 0);
    /// }
    /// ```
    pub fn cipher_text_size(&self) -> Result<usize, i32> {
        let mut len = 0u32;
        let rc = unsafe { sys::wc_MlKemKey_CipherTextSize(self.ws_key, &mut len) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(len as usize)
    }

    /// Get the shared secret size in bytes for this key's type.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) or Err(e) containing the wolfSSL library error
    /// code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(mlkem)]
    /// {
    /// use wolfssl_wolfcrypt::mlkem::MlKem;
    /// let mut key = MlKem::new(MlKem::TYPE_768).expect("Error with new()");
    /// let ss_size = key.shared_secret_size().expect("Error with shared_secret_size()");
    /// assert_eq!(ss_size, MlKem::SHARED_SECRET_SIZE);
    /// }
    /// ```
    pub fn shared_secret_size(&self) -> Result<usize, i32> {
        let mut len = 0u32;
        let rc = unsafe { sys::wc_MlKemKey_SharedSecretSize(self.ws_key, &mut len) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(len as usize)
    }

    /// Get the private key size in bytes for this key's type.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) or Err(e) containing the wolfSSL library error
    /// code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(mlkem)]
    /// {
    /// use wolfssl_wolfcrypt::mlkem::MlKem;
    /// let mut key = MlKem::new(MlKem::TYPE_768).expect("Error with new()");
    /// let priv_size = key.private_key_size().expect("Error with private_key_size()");
    /// assert!(priv_size > 0);
    /// }
    /// ```
    pub fn private_key_size(&self) -> Result<usize, i32> {
        let mut len = 0u32;
        let rc = unsafe { sys::wc_MlKemKey_PrivateKeySize(self.ws_key, &mut len) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(len as usize)
    }

    /// Get the public key size in bytes for this key's type.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) or Err(e) containing the wolfSSL library error
    /// code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(mlkem)]
    /// {
    /// use wolfssl_wolfcrypt::mlkem::MlKem;
    /// let mut key = MlKem::new(MlKem::TYPE_768).expect("Error with new()");
    /// let pub_size = key.public_key_size().expect("Error with public_key_size()");
    /// assert!(pub_size > 0);
    /// }
    /// ```
    pub fn public_key_size(&self) -> Result<usize, i32> {
        let mut len = 0u32;
        let rc = unsafe { sys::wc_MlKemKey_PublicKeySize(self.ws_key, &mut len) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(len as usize)
    }

    /// Encapsulate: generate a shared secret and cipher text using this
    /// public key and an RNG.
    ///
    /// The `ct` buffer must be exactly `cipher_text_size()` bytes.
    /// The `ss` buffer must be exactly `shared_secret_size()` bytes.
    ///
    /// # Parameters
    ///
    /// * `ct`: Output buffer for the cipher text.
    /// * `ss`: Output buffer for the shared secret.
    /// * `rng`: `RNG` instance for random number generation.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(mlkem, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::mlkem::MlKem;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = MlKem::generate(MlKem::TYPE_768, &mut rng)
    ///     .expect("Error with generate()");
    /// let ct_size = key.cipher_text_size().unwrap();
    /// let ss_size = key.shared_secret_size().unwrap();
    /// let mut ct = vec![0u8; ct_size];
    /// let mut ss = vec![0u8; ss_size];
    /// key.encapsulate(&mut ct, &mut ss, &mut rng)
    ///     .expect("Error with encapsulate()");
    /// }
    /// ```
    #[cfg(random)]
    pub fn encapsulate(
        &mut self,
        ct: &mut [u8],
        ss: &mut [u8],
        rng: &mut RNG,
    ) -> Result<(), i32> {
        // Verify the cipher text length is as expected based on the parameter
        // set (key type) in use.
        let expected_ct_size = self.cipher_text_size()?;
        if ct.len() != expected_ct_size {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        // Verify the shared secret length is as expected.
        if ss.len() != Self::SHARED_SECRET_SIZE {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let rc = unsafe {
            sys::wc_MlKemKey_Encapsulate(
                self.ws_key,
                ct.as_mut_ptr(),
                ss.as_mut_ptr(),
                &mut rng.wc_rng,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Encapsulate using caller-supplied random bytes instead of an RNG.
    ///
    /// Produces the same cipher text and shared secret for a given
    /// `(public_key, rand)` pair, enabling deterministic encapsulation.
    /// The `rand` buffer must be exactly [`MlKem::ENC_RAND_SIZE`] (32) bytes.
    ///
    /// # Parameters
    ///
    /// * `ct`: Output buffer for the cipher text.
    /// * `ss`: Output buffer for the shared secret.
    /// * `rand`: Caller-supplied random bytes. Must be `ENC_RAND_SIZE` (32) bytes.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(mlkem)]
    /// {
    /// use wolfssl_wolfcrypt::mlkem::MlKem;
    /// let key_rand = [0x42u8; 64];
    /// let enc_rand = [0x55u8; 32];
    /// let mut key = MlKem::generate_with_random(MlKem::TYPE_768, &key_rand)
    ///     .expect("Error with generate_with_random()");
    /// let ct_size = key.cipher_text_size().unwrap();
    /// let ss_size = key.shared_secret_size().unwrap();
    /// let mut ct = vec![0u8; ct_size];
    /// let mut ss = vec![0u8; ss_size];
    /// key.encapsulate_with_random(&mut ct, &mut ss, &enc_rand)
    ///     .expect("Error with encapsulate_with_random()");
    /// }
    /// ```
    pub fn encapsulate_with_random(
        &mut self,
        ct: &mut [u8],
        ss: &mut [u8],
        rand: &[u8],
    ) -> Result<(), i32> {
        if rand.len() != Self::ENC_RAND_SIZE {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        // Verify the cipher text length is as expected based on the parameter
        // set (key type) in use.
        let expected_ct_size = self.cipher_text_size()?;
        if ct.len() != expected_ct_size {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        // Verify the shared secret length is as expected.
        if ss.len() != Self::SHARED_SECRET_SIZE {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let rc = unsafe {
            sys::wc_MlKemKey_EncapsulateWithRandom(
                self.ws_key,
                ct.as_mut_ptr(),
                ss.as_mut_ptr(),
                rand.as_ptr(),
                rand.len() as core::ffi::c_int,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Decapsulate: recover the shared secret from a cipher text using this
    /// private key.
    ///
    /// The `ss` buffer must be exactly `shared_secret_size()` bytes.
    /// The `ct` length is validated against the expected cipher text size for
    /// the key type by the C library.
    ///
    /// # Parameters
    ///
    /// * `ss`: Output buffer for the shared secret.
    /// * `ct`: Cipher text produced by [`MlKem::encapsulate()`] or
    ///   [`MlKem::encapsulate_with_random()`].
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(mlkem, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::mlkem::MlKem;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = MlKem::generate(MlKem::TYPE_768, &mut rng)
    ///     .expect("Error with generate()");
    /// let ct_size = key.cipher_text_size().unwrap();
    /// let ss_size = key.shared_secret_size().unwrap();
    /// let mut ct = vec![0u8; ct_size];
    /// let mut ss_enc = vec![0u8; ss_size];
    /// key.encapsulate(&mut ct, &mut ss_enc, &mut rng)
    ///     .expect("Error with encapsulate()");
    /// let mut ss_dec = vec![0u8; ss_size];
    /// key.decapsulate(&mut ss_dec, &ct)
    ///     .expect("Error with decapsulate()");
    /// assert_eq!(ss_enc, ss_dec);
    /// }
    /// ```
    pub fn decapsulate(&mut self, ss: &mut [u8], ct: &[u8]) -> Result<(), i32> {
        // Verify the shared secret length is as expected.
        if ss.len() != Self::SHARED_SECRET_SIZE {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let rc = unsafe {
            sys::wc_MlKemKey_Decapsulate(
                self.ws_key,
                ss.as_mut_ptr(),
                ct.as_ptr(),
                ct.len() as u32,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Encode (export) the public key to a byte buffer.
    ///
    /// The `out` buffer must be exactly `public_key_size()` bytes.
    ///
    /// # Parameters
    ///
    /// * `out`: Output buffer to receive the encoded public key.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(mlkem, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::mlkem::MlKem;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = MlKem::generate(MlKem::TYPE_768, &mut rng)
    ///     .expect("Error with generate()");
    /// let pub_size = key.public_key_size().unwrap();
    /// let mut pub_buf = vec![0u8; pub_size];
    /// let written = key.encode_public_key(&mut pub_buf)
    ///     .expect("Error with encode_public_key()");
    /// assert_eq!(written, pub_size);
    /// }
    /// ```
    pub fn encode_public_key(&self, out: &mut [u8]) -> Result<usize, i32> {
        let rc = unsafe {
            sys::wc_MlKemKey_EncodePublicKey(self.ws_key, out.as_mut_ptr(), out.len() as u32)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(out.len())
    }

    /// Encode (export) the private key to a byte buffer.
    ///
    /// The `out` buffer must be exactly `private_key_size()` bytes.
    ///
    /// # Parameters
    ///
    /// * `out`: Output buffer to receive the encoded private key.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(mlkem, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::mlkem::MlKem;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = MlKem::generate(MlKem::TYPE_768, &mut rng)
    ///     .expect("Error with generate()");
    /// let priv_size = key.private_key_size().unwrap();
    /// let mut priv_buf = vec![0u8; priv_size];
    /// let written = key.encode_private_key(&mut priv_buf)
    ///     .expect("Error with encode_private_key()");
    /// assert_eq!(written, priv_size);
    /// }
    /// ```
    pub fn encode_private_key(&self, out: &mut [u8]) -> Result<usize, i32> {
        let rc = unsafe {
            sys::wc_MlKemKey_EncodePrivateKey(self.ws_key, out.as_mut_ptr(), out.len() as u32)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(out.len())
    }

    /// Decode (import) a public key from a byte buffer.
    ///
    /// # Parameters
    ///
    /// * `data`: Input buffer containing the encoded public key.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(mlkem, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::mlkem::MlKem;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = MlKem::generate(MlKem::TYPE_768, &mut rng)
    ///     .expect("Error with generate()");
    /// let pub_size = key.public_key_size().unwrap();
    /// let mut pub_buf = vec![0u8; pub_size];
    /// key.encode_public_key(&mut pub_buf).expect("Error with encode_public_key()");
    /// let mut key2 = MlKem::new(MlKem::TYPE_768).expect("Error with new()");
    /// key2.decode_public_key(&pub_buf).expect("Error with decode_public_key()");
    /// }
    /// ```
    pub fn decode_public_key(&mut self, data: &[u8]) -> Result<(), i32> {
        let rc = unsafe {
            sys::wc_MlKemKey_DecodePublicKey(self.ws_key, data.as_ptr(), data.len() as u32)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Decode (import) a private key from a byte buffer.
    ///
    /// # Parameters
    ///
    /// * `data`: Input buffer containing the encoded private key.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(mlkem, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::mlkem::MlKem;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = MlKem::generate(MlKem::TYPE_768, &mut rng)
    ///     .expect("Error with generate()");
    /// let priv_size = key.private_key_size().unwrap();
    /// let mut priv_buf = vec![0u8; priv_size];
    /// key.encode_private_key(&mut priv_buf).expect("Error with encode_private_key()");
    /// let mut key2 = MlKem::new(MlKem::TYPE_768).expect("Error with new()");
    /// key2.decode_private_key(&priv_buf).expect("Error with decode_private_key()");
    /// }
    /// ```
    pub fn decode_private_key(&mut self, data: &[u8]) -> Result<(), i32> {
        let rc = unsafe {
            sys::wc_MlKemKey_DecodePrivateKey(self.ws_key, data.as_ptr(), data.len() as u32)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}

impl Drop for MlKem {
    /// Safely free the underlying wolfSSL ML-KEM key context.
    ///
    /// This calls `wc_MlKemKey_Delete()`. The Rust Drop trait guarantees this
    /// is called when the `MlKem` struct goes out of scope.
    fn drop(&mut self) {
        unsafe {
            sys::wc_MlKemKey_Delete(self.ws_key, core::ptr::null_mut());
        }
    }
}
