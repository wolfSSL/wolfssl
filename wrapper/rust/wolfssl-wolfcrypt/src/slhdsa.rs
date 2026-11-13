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
This module provides a Rust wrapper for the wolfCrypt library's SLH-DSA
post-quantum digital signature functionality.

The primary component is the [`SlhDsa`] struct, which manages the lifecycle
of a wolfSSL `SlhDsaKey` object. It ensures proper initialization and
deallocation.

Twelve security parameter sets are supported, set via
[`SlhDsa::new()`], [`SlhDsa::new_ex()`], [`SlhDsa::generate()`] or [`SlhDsa::generate_ex()`]:

| Constant        | Level | NIST PQC Level |
|-----------------|-------|----------------|
| [`SlhDsa::SHA2_128S`] | 1 | 1 (SLH-DSA-SHA2-128s) |
| [`SlhDsa::SHA2_128F`] | 1 | 1 (SLH-DSA-SHA2-128f) |
| [`SlhDsa::SHA2_192S`] | 3 | 3 (SLH-DSA-SHA2-192s) |
| [`SlhDsa::SHA2_192F`] | 3 | 3 (SLH-DSA-SHA2-192f) |
| [`SlhDsa::SHA2_256S`] | 5 | 5 (SLH-DSA-SHA2-256s) |
| [`SlhDsa::SHA2_256F`] | 5 | 5 (SLH-DSA-SHA2-1256f) |
| [`SlhDsa::SHAKE_128S`] | 1 | 1 (SLH-DSA-SHAKE-128s) |
| [`SlhDsa::SHAKE_128F`] | 1 | 1 (SLH-DSA-SHAKE-128f) |
| [`SlhDsa::SHAKE_192S`] | 3 | 3 (SLH-DSA-SHAKE-192s) |
| [`SlhDsa::SHAKE_192F`] | 3 | 3 (SLH-DSA-SHAKE-192f) |
| [`SlhDsa::SHAKE_256S`] | 5 | 5 (SLH-DSA-SHAKE-256s) |
| [`SlhDsa::SHAKE_256F`] | 5 | 5 (SLH-DSA-SHAKE-1256f) |

# Examples

```rust
#[cfg(all(slhdsa, slhdsa_verify, random))]
{
use wolfssl_wolfcrypt::random::RNG;
use wolfssl_wolfcrypt::slhdsa::SlhDsa;
let mut rng = RNG::new().expect("RNG creation failed");
let mut key = SlhDsa::generate(SlhDsa::SHAKE_128S, &mut rng)
    .expect("Key generation failed");
let message = b"Hello, SLH-DSA!";
let mut sig = vec![0u8; key.sig_size().expect("sig_size failed")];
let sig_len = key.sign_msg(message, &mut sig, &mut rng)
    .expect("Signing failed");
let valid = key.verify_msg(&sig[..sig_len], message)
    .expect("Verification failed");
assert!(valid);
}
```
*/

#![cfg(slhdsa)]

#[cfg(all(random, slhdsa_sign))]
use crate::random::RNG;
use crate::sys;
use core::ffi::c_uint;
use core::mem::MaybeUninit;

/// Rust wrapper for a wolfSSL `SlhDsaKey` object.
///
/// Manages the lifecycle of the underlying key, including initialization and
/// deallocation via the [`Drop`] trait.
///
/// An instance is created with [`SlhDsa::generate()`],
/// [`SlhDsa::generate_ex()`], [`SlhDsa::new()`] or [`SlhDsa::new_ex()`].
pub struct SlhDsa {
    ws_key: sys::SlhDsaKey,
}

impl SlhDsa {
    /// SLH-DSA-SHA2-128s security parameter set (NIST Level 1).
    #[cfg(slhdsa_sha2)]
    pub const SHA2_128S: u8 = sys::SlhDsaParam_SLHDSA_SHA2_128S as u8;
    /// SLH-DSA-SHA2-128f security parameter set (NIST Level 1).
    #[cfg(slhdsa_sha2)]
    pub const SHA2_128F: u8 = sys::SlhDsaParam_SLHDSA_SHA2_128F as u8;
    /// SLH-DSA-SHA2-192s security parameter set (NIST Level 3).
    #[cfg(slhdsa_sha2)]
    pub const SHA2_192S: u8 = sys::SlhDsaParam_SLHDSA_SHA2_192S as u8;
    /// SLH-DSA-SHA2-192f security parameter set (NIST Level 3).
    #[cfg(slhdsa_sha2)]
    pub const SHA2_192F: u8 = sys::SlhDsaParam_SLHDSA_SHA2_192F as u8;
    /// SLH-DSA-SHA2-256s security parameter set (NIST Level 5).
    #[cfg(slhdsa_sha2)]
    pub const SHA2_256S: u8 = sys::SlhDsaParam_SLHDSA_SHA2_256S as u8;
    /// SLH-DSA-SHA2-256f security parameter set (NIST Level 5).
    #[cfg(slhdsa_sha2)]
    pub const SHA2_256F: u8 = sys::SlhDsaParam_SLHDSA_SHA2_256F as u8;
    /// SLH-DSA-SHAKE-128s security parameter set (NIST Level 1).
    pub const SHAKE_128S: u8 = sys::SlhDsaParam_SLHDSA_SHAKE128S as u8;
    /// SLH-DSA-SHAKE-128f security parameter set (NIST Level 1).
    pub const SHAKE_128F: u8 = sys::SlhDsaParam_SLHDSA_SHAKE128F as u8;
    /// SLH-DSA-SHAKE-192s security parameter set (NIST Level 3).
    pub const SHAKE_192S: u8 = sys::SlhDsaParam_SLHDSA_SHAKE192S as u8;
    /// SLH-DSA-SHAKE-192f security parameter set (NIST Level 3).
    pub const SHAKE_192F: u8 = sys::SlhDsaParam_SLHDSA_SHAKE192F as u8;
    /// SLH-DSA-SHAKE-256s security parameter set (NIST Level 5).
    pub const SHAKE_256S: u8 = sys::SlhDsaParam_SLHDSA_SHAKE256S as u8;
    /// SLH-DSA-SHAKE-256f security parameter set (NIST Level 5).
    pub const SHAKE_256F: u8 = sys::SlhDsaParam_SLHDSA_SHAKE256F as u8;
    /// Private (secret) key size in bytes for SLH-DSA-SHA2-128s.
    #[cfg(slhdsa_sha2)]
    pub const SHA2_128S_PRV_KEY_SIZE: usize = sys::WC_SLHDSA_SHA2_128S_PRIV_LEN as usize;
    /// Private (secret) key size in bytes for SLH-DSA-SHA2-128f.
    #[cfg(slhdsa_sha2)]
    pub const SHA2_128F_PRV_KEY_SIZE: usize = sys::WC_SLHDSA_SHA2_128F_PRIV_LEN as usize;
    /// Private (secret) key size in bytes for SLH-DSA-SHA2-192s.
    #[cfg(slhdsa_sha2)]
    pub const SHA2_192S_PRV_KEY_SIZE: usize = sys::WC_SLHDSA_SHA2_192S_PRIV_LEN as usize;
    /// Private (secret) key size in bytes for SLH-DSA-SHA2-192f.
    #[cfg(slhdsa_sha2)]
    pub const SHA2_192F_PRV_KEY_SIZE: usize = sys::WC_SLHDSA_SHA2_192F_PRIV_LEN as usize;
    /// Private (secret) key size in bytes for SLH-DSA-SHA2-256s.
    #[cfg(slhdsa_sha2)]
    pub const SHA2_256S_PRV_KEY_SIZE: usize = sys::WC_SLHDSA_SHA2_256S_PRIV_LEN as usize;
    /// Private (secret) key size in bytes for SLH-DSA-SHA2-256f.
    #[cfg(slhdsa_sha2)]
    pub const SHA2_256F_PRV_KEY_SIZE: usize = sys::WC_SLHDSA_SHA2_256F_PRIV_LEN as usize;
    /// Private (secret) key size in bytes for SLH-DSA-SHAKE-128s.
    pub const SHAKE_128S_PRV_KEY_SIZE: usize = sys::WC_SLHDSA_SHAKE128S_PRIV_LEN as usize;
    /// Private (secret) key size in bytes for SLH-DSA-SHAKE-128f.
    pub const SHAKE_128F_PRV_KEY_SIZE: usize = sys::WC_SLHDSA_SHAKE128F_PRIV_LEN as usize;
    /// Private (secret) key size in bytes for SLH-DSA-SHAKE-192s.
    pub const SHAKE_192S_PRV_KEY_SIZE: usize = sys::WC_SLHDSA_SHAKE192S_PRIV_LEN as usize;
    /// Private (secret) key size in bytes for SLH-DSA-SHAKE-192f.
    pub const SHAKE_192F_PRV_KEY_SIZE: usize = sys::WC_SLHDSA_SHAKE192F_PRIV_LEN as usize;
    /// Private (secret) key size in bytes for SLH-DSA-SHAKE-256s.
    pub const SHAKE_256S_PRV_KEY_SIZE: usize = sys::WC_SLHDSA_SHAKE256S_PRIV_LEN as usize;
    /// Private (secret) key size in bytes for SLH-DSA-SHAKE-256f.
    pub const SHAKE_256F_PRV_KEY_SIZE: usize = sys::WC_SLHDSA_SHAKE256F_PRIV_LEN as usize;
    /// Signature size in bytes for SLH-DSA-SHA2-128s.
    #[cfg(slhdsa_sha2)]
    pub const SHA2_128S_SIG_SIZE: usize = sys::WC_SLHDSA_SHA2_128S_SIG_LEN as usize;
    /// Signature size in bytes for SLH-DSA-SHA2-128f.
    #[cfg(slhdsa_sha2)]
    pub const SHA2_128F_SIG_SIZE: usize = sys::WC_SLHDSA_SHA2_128F_SIG_LEN as usize;
    /// Signature size in bytes for SLH-DSA-SHA2-192s.
    #[cfg(slhdsa_sha2)]
    pub const SHA2_192S_SIG_SIZE: usize = sys::WC_SLHDSA_SHA2_192S_SIG_LEN as usize;
    /// Signature size in bytes for SLH-DSA-SHA2-192f.
    #[cfg(slhdsa_sha2)]
    pub const SHA2_192F_SIG_SIZE: usize = sys::WC_SLHDSA_SHA2_192F_SIG_LEN as usize;
    /// Signature size in bytes for SLH-DSA-SHA2-256s.
    #[cfg(slhdsa_sha2)]
    pub const SHA2_256S_SIG_SIZE: usize = sys::WC_SLHDSA_SHA2_256S_SIG_LEN as usize;
    /// Signature size in bytes for SLH-DSA-SHA2-256f.
    #[cfg(slhdsa_sha2)]
    pub const SHA2_256F_SIG_SIZE: usize = sys::WC_SLHDSA_SHA2_256F_SIG_LEN as usize;
    /// Signature size in bytes for SLH-DSA-SHAKE-128s.
    pub const SHAKE_128S_SIG_SIZE: usize = sys::WC_SLHDSA_SHAKE128S_SIG_LEN as usize;
    /// Signature size in bytes for SLH-DSA-SHAKE-128f.
    pub const SHAKE_128F_SIG_SIZE: usize = sys::WC_SLHDSA_SHAKE128F_SIG_LEN as usize;
    /// Signature size in bytes for SLH-DSA-SHAKE-192s.
    pub const SHAKE_192S_SIG_SIZE: usize = sys::WC_SLHDSA_SHAKE192S_SIG_LEN as usize;
    /// Signature size in bytes for SLH-DSA-SHAKE-192f.
    pub const SHAKE_192F_SIG_SIZE: usize = sys::WC_SLHDSA_SHAKE192F_SIG_LEN as usize;
    /// Signature size in bytes for SLH-DSA-SHAKE-256s.
    pub const SHAKE_256S_SIG_SIZE: usize = sys::WC_SLHDSA_SHAKE256S_SIG_LEN as usize;
    /// Signature size in bytes for SLH-DSA-SHAKE-256f.
    pub const SHAKE_256F_SIG_SIZE: usize = sys::WC_SLHDSA_SHAKE256F_SIG_LEN as usize;
    /// Public key size in bytes for SLH-DSA-SHA2-128s.
    #[cfg(slhdsa_sha2)]
    pub const SHA2_128S_PUB_KEY_SIZE: usize = sys::WC_SLHDSA_SHA2_128S_PUB_LEN as usize;
    /// Public key size in bytes for SLH-DSA-SHA2-128f.
    #[cfg(slhdsa_sha2)]
    pub const SHA2_128F_PUB_KEY_SIZE: usize = sys::WC_SLHDSA_SHA2_128F_PUB_LEN as usize;
    /// Public key size in bytes for SLH-DSA-SHA2-192s.
    #[cfg(slhdsa_sha2)]
    pub const SHA2_192S_PUB_KEY_SIZE: usize = sys::WC_SLHDSA_SHA2_192S_PUB_LEN as usize;
    /// Public key size in bytes for SLH-DSA-SHA2-192f.
    #[cfg(slhdsa_sha2)]
    pub const SHA2_192F_PUB_KEY_SIZE: usize = sys::WC_SLHDSA_SHA2_192F_PUB_LEN as usize;
    /// Public key size in bytes for SLH-DSA-SHA2-256s.
    #[cfg(slhdsa_sha2)]
    pub const SHA2_256S_PUB_KEY_SIZE: usize = sys::WC_SLHDSA_SHA2_256S_PUB_LEN as usize;
    /// Public key size in bytes for SLH-DSA-SHA2-256f.
    #[cfg(slhdsa_sha2)]
    pub const SHA2_256F_PUB_KEY_SIZE: usize = sys::WC_SLHDSA_SHA2_256F_PUB_LEN as usize;
    /// Public key size in bytes for SLH-DSA-SHAKE-128s.
    pub const SHAKE_128S_PUB_KEY_SIZE: usize = sys::WC_SLHDSA_SHAKE128S_PUB_LEN as usize;
    /// Public key size in bytes for SLH-DSA-SHAKE-128f.
    pub const SHAKE_128F_PUB_KEY_SIZE: usize = sys::WC_SLHDSA_SHAKE128F_PUB_LEN as usize;
    /// Public key size in bytes for SLH-DSA-SHAKE-192s.
    pub const SHAKE_192S_PUB_KEY_SIZE: usize = sys::WC_SLHDSA_SHAKE192S_PUB_LEN as usize;
    /// Public key size in bytes for SLH-DSA-SHAKE-192f.
    pub const SHAKE_192F_PUB_KEY_SIZE: usize = sys::WC_SLHDSA_SHAKE192F_PUB_LEN as usize;
    /// Public key size in bytes for SLH-DSA-SHAKE-256s.
    pub const SHAKE_256S_PUB_KEY_SIZE: usize = sys::WC_SLHDSA_SHAKE256S_PUB_LEN as usize;
    /// Public key size in bytes for SLH-DSA-SHAKE-256f.
    pub const SHAKE_256F_PUB_KEY_SIZE: usize = sys::WC_SLHDSA_SHAKE256F_PUB_LEN as usize;

    /// Create and initialize a new SLH-DSA key instance without a key.
    ///
    /// The key material can be set afterwards using one of the import functions.
    ///
    /// # Parameters
    ///
    /// * `param`: Security parameter set.
    ///
    /// # Returns
    ///
    /// Returns either Ok(SlhDsa) containing the key instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(slhdsa)]
    /// {
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let key = SlhDsa::new(SlhDsa::SHAKE_128S).expect("Error with new()");
    /// }
    /// ```
    pub fn new(param: u8) -> Result<Self, i32> {
        Self::new_ex(param, None, None)
    }

    /// Create and initialize a new SLH-DSA key instance with optional heap
    /// hint and device ID.
    ///
    /// # Parameters
    ///
    /// * `param`: Security parameter set.
    /// * `heap`: Optional heap hint.
    /// * `dev_id`: Optional device ID for crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(SlhDsa) containing the key instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(slhdsa)]
    /// {
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let key = SlhDsa::new_ex(SlhDsa::SHAKE_128S, None, None).expect("Error with new_ex()");
    /// }
    /// ```
    pub fn new_ex(
        param: u8,
        heap: Option<*mut core::ffi::c_void>,
        dev_id: Option<i32>,
    ) -> Result<Self, i32> {
        let mut ws_key: MaybeUninit<sys::SlhDsaKey> = MaybeUninit::uninit();
        let heap = heap.unwrap_or_else(|| core::ptr::null_mut());
        let dev_id = dev_id.unwrap_or_else(|| sys::INVALID_DEVID);
        let rc =
            unsafe { sys::wc_SlhDsaKey_Init(ws_key.as_mut_ptr(), param as c_uint, heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        let ws_key = unsafe { ws_key.assume_init() };
        Ok(SlhDsa { ws_key })
    }

    /// Generate a new SLH-DSA key pair using a random number generator.
    ///
    /// # Parameters
    ///
    /// * `param`: Security parameter set.
    /// * `rng`: `RNG` instance to use for random number generation.
    ///
    /// # Returns
    ///
    /// Returns either Ok(SlhDsa) containing the key instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(slhdsa, slhdsa_sign, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let key = SlhDsa::generate(SlhDsa::SHAKE_128S, &mut rng)
    ///     .expect("Error with generate()");
    /// }
    /// ```
    #[cfg(all(slhdsa_sign, random))]
    pub fn generate(param: u8, rng: &mut RNG) -> Result<Self, i32> {
        Self::generate_ex(param, rng, None, None)
    }

    /// Generate a new SLH-DSA key pair with optional heap hint and device ID.
    ///
    /// # Parameters
    ///
    /// * `param`: Security parameter set.
    /// * `rng`: `RNG` instance to use for random number generation.
    /// * `heap`: Optional heap hint.
    /// * `dev_id`: Optional device ID for crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(SlhDsa) containing the key instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(slhdsa, slhdsa_sign, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let key = SlhDsa::generate_ex(SlhDsa::SHAKE_128S, &mut rng, None, None)
    ///     .expect("Error with generate_ex()");
    /// }
    /// ```
    #[cfg(all(slhdsa_sign, random))]
    pub fn generate_ex(
        param: u8,
        rng: &mut RNG,
        heap: Option<*mut core::ffi::c_void>,
        dev_id: Option<i32>,
    ) -> Result<Self, i32> {
        let mut key = Self::new_ex(param, heap, dev_id)?;
        let rc = unsafe { sys::wc_SlhDsaKey_MakeKey(&mut key.ws_key, rng.wc_rng) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(key)
    }

    /// Get the private (secret) key size in bytes for the current parameter set.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the private key size or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(slhdsa, slhdsa_sign, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = SlhDsa::generate(SlhDsa::SHAKE_128S, &mut rng)
    ///     .expect("Error with generate()");
    /// let sz = key.priv_size().expect("Error with priv_size()");
    /// assert_eq!(sz, SlhDsa::SHAKE_128S_PRV_KEY_SIZE);
    /// }
    /// ```
    pub fn priv_size(&mut self) -> Result<usize, i32> {
        let rc = unsafe { sys::wc_SlhDsaKey_PrivateSize(&mut self.ws_key) };
        if rc < 0 {
            return Err(rc);
        }
        Ok(rc as usize)
    }

    /// Get the public key size in bytes for the current parameter set.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the private key size or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(slhdsa, slhdsa_sign, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = SlhDsa::generate(SlhDsa::SHAKE_128S, &mut rng)
    ///     .expect("Error with generate()");
    /// let sz = key.pub_size().expect("Error with size()");
    /// assert_eq!(sz, SlhDsa::SHAKE_128S_PUB_KEY_SIZE);
    /// }
    /// ```
    pub fn pub_size(&mut self) -> Result<usize, i32> {
        let rc = unsafe { sys::wc_SlhDsaKey_PublicSize(&mut self.ws_key) };
        if rc < 0 {
            return Err(rc);
        }
        Ok(rc as usize)
    }

    /// Get the signature size in bytes for the current parameter set.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the private key size or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(slhdsa, slhdsa_sign, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = SlhDsa::generate(SlhDsa::SHAKE_128S, &mut rng)
    ///     .expect("Error with generate()");
    /// let sz = key.sig_size().expect("Error with size()");
    /// assert_eq!(sz, SlhDsa::SHAKE_128S_SIG_SIZE);
    /// }
    /// ```
    pub fn sig_size(&mut self) -> Result<usize, i32> {
        let rc = unsafe { sys::wc_SlhDsaKey_SigSize(&mut self.ws_key) };
        if rc < 0 {
            return Err(rc);
        }
        Ok(rc as usize)
    }

    /// Check that the key pair is valid (public key matches private key).
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(slhdsa, slhdsa_sign, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = SlhDsa::generate(SlhDsa::SHAKE_128S, &mut rng)
    ///     .expect("Error with generate()");
    /// key.check_key().expect("Error with check_key()");
    /// }
    /// ```
    #[cfg(slhdsa_sign)]
    pub fn check_key(&mut self) -> Result<(), i32> {
        let rc = unsafe { sys::wc_SlhDsaKey_CheckKey(&mut self.ws_key) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Import a public key from a raw byte buffer.
    ///
    /// # Parameters
    ///
    /// * `public`: Input buffer containing the raw public key bytes.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(slhdsa, slhdsa_sign, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = SlhDsa::generate(SlhDsa::SHAKE_128S, &mut rng)
    ///     .expect("Error with generate()");
    /// let mut pub_buf = vec![0u8; key.pub_size().unwrap()];
    /// key.export_public(&mut pub_buf).expect("Error with export_public()");
    /// let mut key2 = SlhDsa::new(SlhDsa::SHAKE_128S).expect("Error with new()");
    /// key2.import_public(&pub_buf).expect("Error with import_public()");
    /// }
    /// ```
    pub fn import_public(&mut self, public: &[u8]) -> Result<(), i32> {
        let public_size = crate::buffer_len_to_u32(public.len())?;
        let rc = unsafe {
            sys::wc_SlhDsaKey_ImportPublic(&mut self.ws_key, public.as_ptr(), public_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Import a private (secret) key from a raw byte buffer.
    ///
    /// The buffer should contain the raw private key bytes only
    ///
    /// # Parameters
    ///
    /// * `private`: Input buffer containing the raw private key bytes.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(slhdsa, slhdsa_sign, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = SlhDsa::generate(SlhDsa::SHAKE_128S, &mut rng)
    ///     .expect("Error with generate()");
    /// let mut priv_buf = vec![0u8; key.priv_size().unwrap()];
    /// key.export_private(&mut priv_buf).expect("Error with export_private()");
    /// let mut key2 = SlhDsa::new(SlhDsa::SHAKE_128S).expect("Error with new()");
    /// key2.import_private(&priv_buf).expect("Error with import_private()");
    /// }
    /// ```
    #[cfg(slhdsa_sign)]
    pub fn import_private(&mut self, private: &[u8]) -> Result<(), i32> {
        let private_size = crate::buffer_len_to_u32(private.len())?;
        let rc = unsafe {
            sys::wc_SlhDsaKey_ImportPrivate(&mut self.ws_key, private.as_ptr(), private_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Export the public key to a raw byte buffer.
    ///
    /// # Parameters
    ///
    /// * `public`: Output buffer to receive the public key. Must be at least
    ///   `pub_size()` bytes.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(slhdsa, slhdsa_import, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = SlhDsa::generate(SlhDsa::SHAKE_128S, &mut rng)
    ///     .expect("Error with generate()");
    /// let mut pub_buf = vec![0u8; key.pub_size().unwrap()];
    /// let written = key.export_public(&mut pub_buf).expect("Error with export_public()");
    /// assert_eq!(written, SlhDsa::SHAKE_128S_PUB_KEY_SIZE);
    /// }
    /// ```
    pub fn export_public(&mut self, public: &mut [u8]) -> Result<usize, i32> {
        let mut public_size = crate::buffer_len_to_u32(public.len())?;
        let rc = unsafe {
            sys::wc_SlhDsaKey_ExportPublic(&mut self.ws_key, public.as_mut_ptr(), &mut public_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(public_size as usize)
    }

    /// Export the private (secret) key to a raw byte buffer.
    ///
    /// # Parameters
    ///
    /// * `private`: Output buffer to receive the private key. Must be at
    ///   least `priv_size()` bytes.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(slhdsa, slhdsa_sign, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = SlhDsa::generate(SlhDsa::SHAKE_128S, &mut rng)
    ///     .expect("Error with generate()");
    /// let mut priv_buf = vec![0u8; key.priv_size().unwrap()];
    /// let written = key.export_private(&mut priv_buf).expect("Error with export_private()");
    /// assert_eq!(written, SlhDsa::SHAKE_128S_PRV_KEY_SIZE);
    /// }
    /// ```
    #[cfg(slhdsa_sign)]
    pub fn export_private(&mut self, private: &mut [u8]) -> Result<usize, i32> {
        let mut private_size = crate::buffer_len_to_u32(private.len())?;
        let rc = unsafe {
            sys::wc_SlhDsaKey_ExportPrivate(
                &mut self.ws_key,
                private.as_mut_ptr(),
                &mut private_size,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(private_size as usize)
    }

    /// Sign a message and write the signature to `sig`.
    ///
    /// # Parameters
    ///
    /// * `msg`: Message to sign.
    /// * `sig`: Output buffer to hold the signature. Must be at least
    ///   `sig_size()` bytes.
    /// * `rng`: RNG instance for hedged signing. For deterministic signing,
    ///   use [`SlhDsa::sign_msg_deterministic()`] instead.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to `sig`
    /// on success or Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(slhdsa, slhdsa_sign, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = SlhDsa::generate(SlhDsa::SHAKE_128S, &mut rng)
    ///     .expect("Error with generate()");
    /// let message = b"Hello, SLH-DSA!";
    /// let mut sig = vec![0u8; key.sig_size().unwrap()];
    /// let sig_len = key.sign_msg(message, &mut sig, &mut rng)
    ///     .expect("Error with sign_msg()");
    /// assert_eq!(sig_len, SlhDsa::SHAKE_128S_SIG_SIZE);
    /// }
    /// ```
    #[cfg(all(slhdsa_sign, random))]
    pub fn sign_msg(&mut self, msg: &[u8], sig: &mut [u8], rng: &RNG) -> Result<usize, i32> {
        let msg_len = crate::buffer_len_to_u32(msg.len())?;
        let mut sig_len = crate::buffer_len_to_u32(sig.len())?;
        let rc = unsafe {
            sys::wc_SlhDsaKey_Sign(
                &mut self.ws_key,
                core::ptr::null(),
                0,
                msg.as_ptr(),
                msg_len,
                sig.as_mut_ptr(),
                &mut sig_len,
                rng.wc_rng,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(sig_len as usize)
    }

    /// Sign a message with a context string and write the signature to `sig`.
    ///
    /// # Parameters
    ///
    /// * `ctx`: Context string (at most 255 bytes).
    /// * `msg`: Message to sign.
    /// * `sig`: Output buffer to hold the signature. Must be at least
    ///   `sig_size()` bytes.
    /// * `rng`: RNG instance for hedged signing. For deterministic signing,
    ///   use [`SlhDsa::sign_ctx_msg_deterministic()`] instead.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to `sig`
    /// on success or Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(slhdsa, slhdsa_sign, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = SlhDsa::generate(SlhDsa::SHAKE_128S, &mut rng)
    ///     .expect("Error with generate()");
    /// let message = b"Hello, SLH-DSA!";
    /// let ctx = b"my context";
    /// let mut sig = vec![0u8; key.sig_size().unwrap()];
    /// let sig_len = key.sign_ctx_msg(ctx, message, &mut sig, &mut rng)
    ///     .expect("Error with sign_ctx_msg()");
    /// assert_eq!(sig_len, SlhDsa::SHAKE_128S_SIG_SIZE);
    /// }
    /// ```
    #[cfg(all(slhdsa_sign, random))]
    pub fn sign_ctx_msg(
        &mut self,
        ctx: &[u8],
        msg: &[u8],
        sig: &mut [u8],
        rng: &RNG,
    ) -> Result<usize, i32> {
        if ctx.len() > 255 {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let ctx_len = ctx.len() as u8;
        let msg_len = crate::buffer_len_to_u32(msg.len())?;
        let mut sig_len = crate::buffer_len_to_u32(sig.len())?;
        let rc = unsafe {
            sys::wc_SlhDsaKey_Sign(
                &mut self.ws_key,
                ctx.as_ptr(),
                ctx_len,
                msg.as_ptr(),
                msg_len,
                sig.as_mut_ptr(),
                &mut sig_len,
                rng.wc_rng,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(sig_len as usize)
    }

    /// Sign a message deterministically instead of using RNG.
    ///
    /// # Parameters
    ///
    /// * `msg`: Message to sign.
    /// * `sig`: Output buffer to hold the signature.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to `sig`
    /// on success or Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(slhdsa, slhdsa_sign, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = SlhDsa::generate(SlhDsa::SHAKE_128S, &mut rng)
    ///     .expect("Error with generate()");
    /// let message = b"Hello, SLH-DSA!";
    /// let mut sig = vec![0u8; key.sig_size().unwrap()];
    /// let sig_len = key.sign_msg_deterministic(message, &mut sig)
    ///     .expect("Error with sign_msg_deterministic()");
    /// assert_eq!(sig_len, SlhDsa::SHAKE_128S_SIG_SIZE);
    /// }
    /// ```
    #[cfg(all(slhdsa_sign))]
    pub fn sign_msg_deterministic(&mut self, msg: &[u8], sig: &mut [u8]) -> Result<usize, i32> {
        let msg_len = crate::buffer_len_to_u32(msg.len())?;
        let mut sig_len = crate::buffer_len_to_u32(sig.len())?;
        let rc = unsafe {
            sys::wc_SlhDsaKey_SignDeterministic(
                &mut self.ws_key,
                core::ptr::null(),
                0,
                msg.as_ptr(),
                msg_len,
                sig.as_mut_ptr(),
                &mut sig_len,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(sig_len as usize)
    }

    /// Sign a message with a context string deterministically instead of using RNG.
    ///
    /// # Parameters
    ///
    /// * `ctx`: Context string (at most 255 bytes).
    /// * `msg`: Message to sign.
    /// * `sig`: Output buffer to hold the signature.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to `sig`
    /// on success or Err(e) containing the wolfSSL library error code value.
    ///
    /// ```rust
    /// #[cfg(all(slhdsa, slhdsa_sign, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = SlhDsa::generate(SlhDsa::SHAKE_128S, &mut rng)
    ///     .expect("Error with generate()");
    /// let message = b"Hello, SLH-DSA!";
    /// let ctx = b"my context";
    /// let mut sig = vec![0u8; key.sig_size().unwrap()];
    /// let sig_len = key.sign_ctx_msg_deterministic(ctx, message, &mut sig)
    ///     .expect("Error with sign_ctx_msg_deterministic()");
    /// assert_eq!(sig_len, SlhDsa::SHAKE_128S_SIG_SIZE);
    /// }
    /// ```
    #[cfg(all(slhdsa_sign))]
    pub fn sign_ctx_msg_deterministic(
        &mut self,
        ctx: &[u8],
        msg: &[u8],
        sig: &mut [u8],
    ) -> Result<usize, i32> {
        if ctx.len() > 255 {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let ctx_len = ctx.len() as u8;
        let msg_len = crate::buffer_len_to_u32(msg.len())?;
        let mut sig_len = crate::buffer_len_to_u32(sig.len())?;
        let rc = unsafe {
            sys::wc_SlhDsaKey_SignDeterministic(
                &mut self.ws_key,
                ctx.as_ptr(),
                ctx_len,
                msg.as_ptr(),
                msg_len,
                sig.as_mut_ptr(),
                &mut sig_len,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(sig_len as usize)
    }

    /// Verify a message signature.
    ///
    /// # Parameters
    ///
    /// * `sig`: Signature to verify.
    /// * `msg`: Message the signature was created over.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) if the signature is valid, or Err(e) containing
    /// the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(slhdsa, slhdsa_sign, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = SlhDsa::generate(SlhDsa::SHAKE_128S, &mut rng)
    ///     .expect("Error with generate()");
    /// let message = b"Hello, SLH-DSA!";
    /// let mut sig = vec![0u8; key.sig_size().unwrap()];
    /// let sig_len = key.sign_msg(message, &mut sig, &mut rng)
    ///     .expect("Error with sign_msg()");
    /// let valid = key.verify_msg(&sig[..sig_len], message);
    /// assert!(valid.is_ok());
    /// }
    /// ```
    pub fn verify_msg(&mut self, sig: &[u8], msg: &[u8]) -> Result<(), i32> {
        let sig_len = crate::buffer_len_to_u32(sig.len())?;
        let msg_len = crate::buffer_len_to_u32(msg.len())?;
        let rc = unsafe {
            sys::wc_SlhDsaKey_Verify(
                &mut self.ws_key,
                core::ptr::null(),
                0,
                msg.as_ptr(),
                msg_len,
                sig.as_ptr(),
                sig_len,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Verify a message signature with a context string.
    ///
    /// # Parameters
    ///
    /// * `sig`: Signature to verify.
    /// * `ctx`: Context string used when signing.
    /// * `msg`: Message the signature was created over.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) if the signature is valid, or Err(e) containing
    /// the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(slhdsa, slhdsa_sign, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = SlhDsa::generate(SlhDsa::SHAKE_128S, &mut rng)
    ///     .expect("Error with generate()");
    /// let message = b"Hello, SLH-DSA!";
    /// let ctx = b"my context";
    /// let mut sig = vec![0u8; key.sig_size().unwrap()];
    /// let sig_len = key.sign_ctx_msg(ctx, message, &mut sig, &mut rng)
    ///     .expect("Error with sign_ctx_msg()");
    /// let valid = key.verify_ctx_msg(&sig[..sig_len], ctx, message);
    /// assert!(valid.is_ok());
    /// }
    /// ```
    pub fn verify_ctx_msg(&mut self, sig: &[u8], ctx: &[u8], msg: &[u8]) -> Result<(), i32> {
        if ctx.len() > 255 {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let sig_len = crate::buffer_len_to_u32(sig.len())?;
        let ctx_len = ctx.len() as u8;
        let msg_len = crate::buffer_len_to_u32(msg.len())?;
        let rc = unsafe {
            sys::wc_SlhDsaKey_Verify(
                &mut self.ws_key,
                ctx.as_ptr(),
                ctx_len,
                msg.as_ptr(),
                msg_len,
                sig.as_ptr(),
                sig_len,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    fn zeroize(&mut self) {
        unsafe {
            crate::zeroize_raw(&mut self.ws_key);
        }
    }
}

impl Drop for SlhDsa {
    /// Safely free the underlying wolfSSL SLH-DSA key context.
    ///
    /// This calls `wc_SlhDsaKey_Free()`. The Rust Drop trait guarantees this
    /// is called when the `SlhDsa` struct goes out of scope.
    fn drop(&mut self) {
        unsafe {
            sys::wc_SlhDsaKey_Free(&mut self.ws_key);
        }
        self.zeroize();
    }
}
