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
This module provides a Rust wrapper for the wolfCrypt library's ML-DSA
(Dilithium) post-quantum digital signature functionality.

The primary component is the [`Dilithium`] struct, which manages the lifecycle
of a wolfSSL `dilithium_key` object. It ensures proper initialization and
deallocation.

Three security parameter sets are supported, selected via
[`Dilithium::set_level()`]:

| Constant        | Level | NIST PQC Level |
|-----------------|-------|----------------|
| [`Dilithium::LEVEL_44`] | 2 | 2 (ML-DSA-44) |
| [`Dilithium::LEVEL_65`] | 3 | 3 (ML-DSA-65) |
| [`Dilithium::LEVEL_87`] | 5 | 5 (ML-DSA-87) |

# Examples

```rust
#[cfg(all(dilithium, dilithium_make_key, dilithium_sign, dilithium_verify, random))]
{
use wolfssl_wolfcrypt::random::RNG;
use wolfssl_wolfcrypt::dilithium::Dilithium;
let mut rng = RNG::new().expect("RNG creation failed");
let mut key = Dilithium::generate(Dilithium::LEVEL_44, &mut rng)
    .expect("Key generation failed");
let message = b"Hello, ML-DSA!";
let mut sig = vec![0u8; key.sig_size().expect("sig_size failed")];
let sig_len = key.sign_msg(message, &mut sig, &mut rng)
    .expect("Signing failed");
let valid = key.verify_msg(&sig[..sig_len], message)
    .expect("Verification failed");
assert!(valid);
}
```
*/

#![cfg(dilithium)]

use crate::sys;
#[cfg(all(random, any(dilithium_make_key, dilithium_sign)))]
use crate::random::RNG;
use core::mem::MaybeUninit;

/// Rust wrapper for a wolfSSL `dilithium_key` object.
///
/// Manages the lifecycle of the underlying key, including initialization and
/// deallocation via the [`Drop`] trait.
///
/// An instance is created with [`Dilithium::generate()`],
/// [`Dilithium::generate_from_seed()`], or [`Dilithium::new()`].
pub struct Dilithium {
    ws_key: sys::dilithium_key,
}

impl Dilithium {
    /// ML-DSA-44 security parameter set (NIST Level 2).
    pub const LEVEL_44: u8 = sys::WC_ML_DSA_44 as u8;
    /// ML-DSA-65 security parameter set (NIST Level 3).
    pub const LEVEL_65: u8 = sys::WC_ML_DSA_65 as u8;
    /// ML-DSA-87 security parameter set (NIST Level 5).
    pub const LEVEL_87: u8 = sys::WC_ML_DSA_87 as u8;

    /// Required size in bytes of the seed passed to
    /// [`Dilithium::generate_from_seed()`] (`DILITHIUM_SEED_SZ`).
    #[cfg(dilithium_make_key_seed_sz)]
    pub const DILITHIUM_SEED_SZ: usize = sys::DILITHIUM_SEED_SZ as usize;

    /// Required size in bytes of the seed passed to signing-with-seed
    /// functions such as [`Dilithium::sign_msg_with_seed()`]
    /// (`DILITHIUM_RND_SZ`).
    #[cfg(dilithium_rnd_sz)]
    pub const SIGN_SEED_SIZE: usize = sys::DILITHIUM_RND_SZ as usize;

    /// Private (secret) key size in bytes for ML-DSA-44.
    #[cfg(dilithium_level2)]
    pub const LEVEL2_KEY_SIZE: usize = sys::DILITHIUM_LEVEL2_KEY_SIZE as usize;
    /// Signature size in bytes for ML-DSA-44.
    #[cfg(dilithium_level2)]
    pub const LEVEL2_SIG_SIZE: usize = sys::DILITHIUM_LEVEL2_SIG_SIZE as usize;
    /// Public key size in bytes for ML-DSA-44.
    #[cfg(dilithium_level2)]
    pub const LEVEL2_PUB_KEY_SIZE: usize = sys::DILITHIUM_LEVEL2_PUB_KEY_SIZE as usize;
    /// Combined private-plus-public key size in bytes for ML-DSA-44.
    #[cfg(dilithium_level2)]
    pub const LEVEL2_PRV_KEY_SIZE: usize =
        sys::DILITHIUM_LEVEL2_PUB_KEY_SIZE as usize + sys::DILITHIUM_LEVEL2_KEY_SIZE as usize;

    /// Private (secret) key size in bytes for ML-DSA-65.
    #[cfg(dilithium_level3)]
    pub const LEVEL3_KEY_SIZE: usize = sys::DILITHIUM_LEVEL3_KEY_SIZE as usize;
    /// Signature size in bytes for ML-DSA-65.
    #[cfg(dilithium_level3)]
    pub const LEVEL3_SIG_SIZE: usize = sys::DILITHIUM_LEVEL3_SIG_SIZE as usize;
    /// Public key size in bytes for ML-DSA-65.
    #[cfg(dilithium_level3)]
    pub const LEVEL3_PUB_KEY_SIZE: usize = sys::DILITHIUM_LEVEL3_PUB_KEY_SIZE as usize;
    /// Combined private-plus-public key size in bytes for ML-DSA-65.
    #[cfg(dilithium_level3)]
    pub const LEVEL3_PRV_KEY_SIZE: usize =
        sys::DILITHIUM_LEVEL3_PUB_KEY_SIZE as usize + sys::DILITHIUM_LEVEL3_KEY_SIZE as usize;

    /// Private (secret) key size in bytes for ML-DSA-87.
    #[cfg(dilithium_level5)]
    pub const LEVEL5_KEY_SIZE: usize = sys::DILITHIUM_LEVEL5_KEY_SIZE as usize;
    /// Signature size in bytes for ML-DSA-87.
    #[cfg(dilithium_level5)]
    pub const LEVEL5_SIG_SIZE: usize = sys::DILITHIUM_LEVEL5_SIG_SIZE as usize;
    /// Public key size in bytes for ML-DSA-87.
    #[cfg(dilithium_level5)]
    pub const LEVEL5_PUB_KEY_SIZE: usize = sys::DILITHIUM_LEVEL5_PUB_KEY_SIZE as usize;
    /// Combined private-plus-public key size in bytes for ML-DSA-87.
    #[cfg(dilithium_level5)]
    pub const LEVEL5_PRV_KEY_SIZE: usize =
        sys::DILITHIUM_LEVEL5_PUB_KEY_SIZE as usize + sys::DILITHIUM_LEVEL5_KEY_SIZE as usize;

    /// Generate a new Dilithium key pair using a random number generator.
    ///
    /// # Parameters
    ///
    /// * `level`: Security parameter set. One of [`Dilithium::LEVEL_44`],
    ///   [`Dilithium::LEVEL_65`], or [`Dilithium::LEVEL_87`].
    /// * `rng`: `RNG` instance to use for random number generation.
    ///
    /// # Returns
    ///
    /// Returns either Ok(Dilithium) containing the key instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(dilithium, dilithium_make_key, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::dilithium::Dilithium;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let key = Dilithium::generate(Dilithium::LEVEL_44, &mut rng)
    ///     .expect("Error with generate()");
    /// }
    /// ```
    #[cfg(all(dilithium_make_key, random))]
    pub fn generate(level: u8, rng: &mut RNG) -> Result<Self, i32> {
        Self::generate_ex(level, rng, None, None)
    }

    /// Generate a new Dilithium key pair with optional heap hint and device ID.
    ///
    /// # Parameters
    ///
    /// * `level`: Security parameter set. One of [`Dilithium::LEVEL_44`],
    ///   [`Dilithium::LEVEL_65`], or [`Dilithium::LEVEL_87`].
    /// * `rng`: `RNG` instance to use for random number generation.
    /// * `heap`: Optional heap hint.
    /// * `dev_id`: Optional device ID for crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(Dilithium) containing the key instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(dilithium, dilithium_make_key, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::dilithium::Dilithium;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let key = Dilithium::generate_ex(Dilithium::LEVEL_44, &mut rng, None, None)
    ///     .expect("Error with generate_ex()");
    /// }
    /// ```
    #[cfg(all(dilithium_make_key, random))]
    pub fn generate_ex(
        level: u8,
        rng: &mut RNG,
        heap: Option<*mut core::ffi::c_void>,
        dev_id: Option<i32>,
    ) -> Result<Self, i32> {
        let mut key = Self::new_ex(heap, dev_id)?;
        let rc = unsafe { sys::wc_dilithium_set_level(&mut key.ws_key, level) };
        if rc != 0 {
            return Err(rc);
        }
        let rc = unsafe { sys::wc_dilithium_make_key(&mut key.ws_key, &mut rng.wc_rng) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(key)
    }

    /// Generate a Dilithium key pair from a fixed seed.
    ///
    /// Produces the same key pair for a given `(level, seed)` pair, enabling
    /// deterministic key generation.
    ///
    /// # Parameters
    ///
    /// * `level`: Security parameter set. One of [`Dilithium::LEVEL_44`],
    ///   [`Dilithium::LEVEL_65`], or [`Dilithium::LEVEL_87`].
    /// * `seed`: Seed bytes. Must be `DILITHIUM_SEED_SZ` (32) bytes.
    ///
    /// # Returns
    ///
    /// Returns either Ok(Dilithium) containing the key instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(dilithium, dilithium_make_key_from_seed))]
    /// {
    /// use wolfssl_wolfcrypt::dilithium::Dilithium;
    /// let seed = [0x42u8; 32];
    /// let key = Dilithium::generate_from_seed(Dilithium::LEVEL_44, &seed)
    ///     .expect("Error with generate_from_seed()");
    /// }
    /// ```
    #[cfg(dilithium_make_key_from_seed)]
    pub fn generate_from_seed(level: u8, seed: &[u8]) -> Result<Self, i32> {
        Self::generate_from_seed_ex(level, seed, None, None)
    }

    /// Generate a Dilithium key pair from a fixed seed with optional heap hint
    /// and device ID.
    ///
    /// # Parameters
    ///
    /// * `level`: Security parameter set. One of [`Dilithium::LEVEL_44`],
    ///   [`Dilithium::LEVEL_65`], or [`Dilithium::LEVEL_87`].
    /// * `seed`: Seed bytes. Must be `DILITHIUM_SEED_SZ` (32) bytes.
    /// * `heap`: Optional heap hint.
    /// * `dev_id`: Optional device ID for crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(Dilithium) containing the key instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(dilithium, dilithium_make_key_from_seed))]
    /// {
    /// use wolfssl_wolfcrypt::dilithium::Dilithium;
    /// let seed = [0x42u8; 32];
    /// let key = Dilithium::generate_from_seed_ex(Dilithium::LEVEL_44, &seed, None, None)
    ///     .expect("Error with generate_from_seed_ex()");
    /// }
    /// ```
    #[cfg(dilithium_make_key_from_seed)]
    pub fn generate_from_seed_ex(
        level: u8,
        seed: &[u8],
        heap: Option<*mut core::ffi::c_void>,
        dev_id: Option<i32>,
    ) -> Result<Self, i32> {
        #[cfg(dilithium_make_key_seed_sz)]
        if seed.len() != Self::DILITHIUM_SEED_SZ {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let mut key = Self::new_ex(heap, dev_id)?;
        let rc = unsafe { sys::wc_dilithium_set_level(&mut key.ws_key, level) };
        if rc != 0 {
            return Err(rc);
        }
        let rc = unsafe {
            sys::wc_dilithium_make_key_from_seed(&mut key.ws_key, seed.as_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(key)
    }

    /// Create and initialize a new Dilithium key instance without a key.
    ///
    /// The security level and key material can be set afterwards using
    /// [`Dilithium::set_level()`] and one of the import functions.
    ///
    /// # Returns
    ///
    /// Returns either Ok(Dilithium) containing the key instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(dilithium)]
    /// {
    /// use wolfssl_wolfcrypt::dilithium::Dilithium;
    /// let key = Dilithium::new().expect("Error with new()");
    /// }
    /// ```
    pub fn new() -> Result<Self, i32> {
        Self::new_ex(None, None)
    }

    /// Create and initialize a new Dilithium key instance with optional heap
    /// hint and device ID.
    ///
    /// # Parameters
    ///
    /// * `heap`: Optional heap hint.
    /// * `dev_id`: Optional device ID for crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(Dilithium) containing the key instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(dilithium)]
    /// {
    /// use wolfssl_wolfcrypt::dilithium::Dilithium;
    /// let key = Dilithium::new_ex(None, None).expect("Error with new_ex()");
    /// }
    /// ```
    pub fn new_ex(
        heap: Option<*mut core::ffi::c_void>,
        dev_id: Option<i32>,
    ) -> Result<Self, i32> {
        let mut ws_key: MaybeUninit<sys::dilithium_key> = MaybeUninit::uninit();
        let heap = match heap {
            Some(h) => h,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(id) => id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_dilithium_init_ex(ws_key.as_mut_ptr(), heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        let ws_key = unsafe { ws_key.assume_init() };
        Ok(Dilithium { ws_key })
    }

    /// Set the security parameter level for this key.
    ///
    /// Must be called before generating or importing key material. Use one of
    /// the level constants: [`Dilithium::LEVEL_44`], [`Dilithium::LEVEL_65`],
    /// or [`Dilithium::LEVEL_87`].
    ///
    /// # Parameters
    ///
    /// * `level`: Security level (2 = ML-DSA-44, 3 = ML-DSA-65, 5 = ML-DSA-87).
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(dilithium)]
    /// {
    /// use wolfssl_wolfcrypt::dilithium::Dilithium;
    /// let mut key = Dilithium::new().expect("Error with new()");
    /// key.set_level(Dilithium::LEVEL_65).expect("Error with set_level()");
    /// }
    /// ```
    pub fn set_level(&mut self, level: u8) -> Result<(), i32> {
        let rc = unsafe { sys::wc_dilithium_set_level(&mut self.ws_key, level) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Get the security parameter level of this key.
    ///
    /// # Returns
    ///
    /// Returns either Ok(level) containing the current security level or
    /// Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(dilithium)]
    /// {
    /// use wolfssl_wolfcrypt::dilithium::Dilithium;
    /// let mut key = Dilithium::new().expect("Error with new()");
    /// key.set_level(Dilithium::LEVEL_87).expect("Error with set_level()");
    /// let level = key.get_level().expect("Error with get_level()");
    /// assert_eq!(level, Dilithium::LEVEL_87);
    /// }
    /// ```
    pub fn get_level(&mut self) -> Result<u8, i32> {
        let mut level = 0u8;
        let rc = unsafe { sys::wc_dilithium_get_level(&mut self.ws_key, &mut level) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(level)
    }

    /// Get the private (secret) key size in bytes for the current level.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the private key size or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(dilithium, dilithium_make_key, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::dilithium::Dilithium;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = Dilithium::generate(Dilithium::LEVEL_44, &mut rng)
    ///     .expect("Error with generate()");
    /// let sz = key.size().expect("Error with size()");
    /// assert_eq!(sz, Dilithium::LEVEL2_KEY_SIZE);
    /// }
    /// ```
    pub fn size(&mut self) -> Result<usize, i32> {
        let rc = unsafe { sys::wc_dilithium_size(&mut self.ws_key) };
        if rc < 0 {
            return Err(rc);
        }
        Ok(rc as usize)
    }

    /// Get the combined private-plus-public key size in bytes for the current
    /// level.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) or Err(e) containing the wolfSSL library error
    /// code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(dilithium, dilithium_make_key, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::dilithium::Dilithium;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = Dilithium::generate(Dilithium::LEVEL_44, &mut rng)
    ///     .expect("Error with generate()");
    /// let sz = key.priv_size().expect("Error with priv_size()");
    /// assert_eq!(sz, Dilithium::LEVEL2_PRV_KEY_SIZE);
    /// }
    /// ```
    pub fn priv_size(&mut self) -> Result<usize, i32> {
        let rc = unsafe { sys::wc_dilithium_priv_size(&mut self.ws_key) };
        if rc < 0 {
            return Err(rc);
        }
        Ok(rc as usize)
    }

    /// Get the public key size in bytes for the current level.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) or Err(e) containing the wolfSSL library error
    /// code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(dilithium, dilithium_make_key, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::dilithium::Dilithium;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = Dilithium::generate(Dilithium::LEVEL_44, &mut rng)
    ///     .expect("Error with generate()");
    /// let sz = key.pub_size().expect("Error with pub_size()");
    /// assert_eq!(sz, Dilithium::LEVEL2_PUB_KEY_SIZE);
    /// }
    /// ```
    pub fn pub_size(&mut self) -> Result<usize, i32> {
        let rc = unsafe { sys::wc_dilithium_pub_size(&mut self.ws_key) };
        if rc < 0 {
            return Err(rc);
        }
        Ok(rc as usize)
    }

    /// Get the signature size in bytes for the current level.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) or Err(e) containing the wolfSSL library error
    /// code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(dilithium, dilithium_make_key, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::dilithium::Dilithium;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = Dilithium::generate(Dilithium::LEVEL_44, &mut rng)
    ///     .expect("Error with generate()");
    /// let sz = key.sig_size().expect("Error with sig_size()");
    /// assert_eq!(sz, Dilithium::LEVEL2_SIG_SIZE);
    /// }
    /// ```
    pub fn sig_size(&mut self) -> Result<usize, i32> {
        let rc = unsafe { sys::wc_dilithium_sig_size(&mut self.ws_key) };
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
    /// #[cfg(all(dilithium, dilithium_make_key, dilithium_check_key, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::dilithium::Dilithium;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = Dilithium::generate(Dilithium::LEVEL_44, &mut rng)
    ///     .expect("Error with generate()");
    /// key.check_key().expect("Error with check_key()");
    /// }
    /// ```
    #[cfg(dilithium_check_key)]
    pub fn check_key(&mut self) -> Result<(), i32> {
        let rc = unsafe { sys::wc_dilithium_check_key(&mut self.ws_key) };
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
    /// #[cfg(all(dilithium, dilithium_make_key, dilithium_import, dilithium_export, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::dilithium::Dilithium;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = Dilithium::generate(Dilithium::LEVEL_44, &mut rng)
    ///     .expect("Error with generate()");
    /// let mut pub_buf = vec![0u8; key.pub_size().unwrap()];
    /// key.export_public(&mut pub_buf).expect("Error with export_public()");
    /// let mut key2 = Dilithium::new().expect("Error with new()");
    /// key2.set_level(Dilithium::LEVEL_44).expect("Error with set_level()");
    /// key2.import_public(&pub_buf).expect("Error with import_public()");
    /// }
    /// ```
    #[cfg(dilithium_import)]
    pub fn import_public(&mut self, public: &[u8]) -> Result<(), i32> {
        let public_size = public.len() as u32;
        let rc = unsafe {
            sys::wc_dilithium_import_public(public.as_ptr(), public_size, &mut self.ws_key)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Import a private (secret) key from a raw byte buffer.
    ///
    /// The buffer should contain the raw private key bytes only
    /// (size = `LEVEL*_KEY_SIZE`).
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
    /// #[cfg(all(dilithium, dilithium_make_key, dilithium_import, dilithium_export, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::dilithium::Dilithium;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = Dilithium::generate(Dilithium::LEVEL_44, &mut rng)
    ///     .expect("Error with generate()");
    /// let mut priv_buf = vec![0u8; key.size().unwrap()];
    /// key.export_private(&mut priv_buf).expect("Error with export_private()");
    /// let mut key2 = Dilithium::new().expect("Error with new()");
    /// key2.set_level(Dilithium::LEVEL_44).expect("Error with set_level()");
    /// key2.import_private(&priv_buf).expect("Error with import_private()");
    /// }
    /// ```
    #[cfg(dilithium_import)]
    pub fn import_private(&mut self, private: &[u8]) -> Result<(), i32> {
        let private_size = private.len() as u32;
        let rc = unsafe {
            sys::wc_dilithium_import_private(private.as_ptr(), private_size, &mut self.ws_key)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Import both private and public key material from raw byte buffers.
    ///
    /// # Parameters
    ///
    /// * `private`: Input buffer containing the raw private key bytes.
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
    /// #[cfg(all(dilithium, dilithium_make_key, dilithium_import, dilithium_export, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::dilithium::Dilithium;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = Dilithium::generate(Dilithium::LEVEL_44, &mut rng)
    ///     .expect("Error with generate()");
    /// let mut priv_buf = vec![0u8; key.size().unwrap()];
    /// let mut pub_buf = vec![0u8; key.pub_size().unwrap()];
    /// key.export_key(&mut priv_buf, &mut pub_buf).expect("Error with export_key()");
    /// let mut key2 = Dilithium::new().expect("Error with new()");
    /// key2.set_level(Dilithium::LEVEL_44).expect("Error with set_level()");
    /// key2.import_key(&priv_buf, &pub_buf).expect("Error with import_key()");
    /// }
    /// ```
    #[cfg(dilithium_import)]
    pub fn import_key(&mut self, private: &[u8], public: &[u8]) -> Result<(), i32> {
        let private_size = private.len() as u32;
        let public_size = public.len() as u32;
        let rc = unsafe {
            sys::wc_dilithium_import_key(
                private.as_ptr(), private_size,
                public.as_ptr(), public_size,
                &mut self.ws_key,
            )
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
    /// #[cfg(all(dilithium, dilithium_make_key, dilithium_export, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::dilithium::Dilithium;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = Dilithium::generate(Dilithium::LEVEL_44, &mut rng)
    ///     .expect("Error with generate()");
    /// let mut pub_buf = vec![0u8; key.pub_size().unwrap()];
    /// let written = key.export_public(&mut pub_buf).expect("Error with export_public()");
    /// assert_eq!(written, Dilithium::LEVEL2_PUB_KEY_SIZE);
    /// }
    /// ```
    #[cfg(dilithium_export)]
    pub fn export_public(&mut self, public: &mut [u8]) -> Result<usize, i32> {
        let mut public_size = public.len() as u32;
        let rc = unsafe {
            sys::wc_dilithium_export_public(&mut self.ws_key, public.as_mut_ptr(), &mut public_size)
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
    ///   least `size()` bytes.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(dilithium, dilithium_make_key, dilithium_export, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::dilithium::Dilithium;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = Dilithium::generate(Dilithium::LEVEL_44, &mut rng)
    ///     .expect("Error with generate()");
    /// let mut priv_buf = vec![0u8; key.size().unwrap()];
    /// let written = key.export_private(&mut priv_buf).expect("Error with export_private()");
    /// assert_eq!(written, Dilithium::LEVEL2_KEY_SIZE);
    /// }
    /// ```
    #[cfg(dilithium_export)]
    pub fn export_private(&mut self, private: &mut [u8]) -> Result<usize, i32> {
        let mut private_size = private.len() as u32;
        let rc = unsafe {
            sys::wc_dilithium_export_private(
                &mut self.ws_key, private.as_mut_ptr(), &mut private_size,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(private_size as usize)
    }

    /// Export both private and public key material to separate raw byte
    /// buffers.
    ///
    /// # Parameters
    ///
    /// * `private`: Output buffer for the private key. Must be at least
    ///   `size()` bytes.
    /// * `public`: Output buffer for the public key. Must be at least
    ///   `pub_size()` bytes.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(dilithium, dilithium_make_key, dilithium_export, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::dilithium::Dilithium;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = Dilithium::generate(Dilithium::LEVEL_44, &mut rng)
    ///     .expect("Error with generate()");
    /// let mut priv_buf = vec![0u8; key.size().unwrap()];
    /// let mut pub_buf = vec![0u8; key.pub_size().unwrap()];
    /// key.export_key(&mut priv_buf, &mut pub_buf).expect("Error with export_key()");
    /// }
    /// ```
    #[cfg(dilithium_export)]
    pub fn export_key(&mut self, private: &mut [u8], public: &mut [u8]) -> Result<(), i32> {
        let mut private_size = private.len() as u32;
        let mut public_size = public.len() as u32;
        let rc = unsafe {
            sys::wc_dilithium_export_key(
                &mut self.ws_key,
                private.as_mut_ptr(), &mut private_size,
                public.as_mut_ptr(), &mut public_size,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Sign a message and write the signature to `sig`.
    ///
    /// # Parameters
    ///
    /// * `msg`: Message to sign.
    /// * `sig`: Output buffer to hold the signature. Must be at least
    ///   `sig_size()` bytes.
    /// * `rng`: RNG instance for hedged signing. For deterministic signing,
    ///   use [`Dilithium::sign_msg_with_seed()`] instead.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to `sig`
    /// on success or Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(dilithium, dilithium_make_key, dilithium_sign, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::dilithium::Dilithium;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = Dilithium::generate(Dilithium::LEVEL_44, &mut rng)
    ///     .expect("Error with generate()");
    /// let message = b"Hello, ML-DSA!";
    /// let mut sig = vec![0u8; key.sig_size().unwrap()];
    /// let sig_len = key.sign_msg(message, &mut sig, &mut rng)
    ///     .expect("Error with sign_msg()");
    /// assert_eq!(sig_len, Dilithium::LEVEL2_SIG_SIZE);
    /// }
    /// ```
    #[cfg(all(dilithium_sign, random))]
    pub fn sign_msg(
        &mut self,
        msg: &[u8],
        sig: &mut [u8],
        rng: &mut RNG,
    ) -> Result<usize, i32> {
        let msg_len = msg.len() as u32;
        let mut sig_len = sig.len() as u32;
        let rc = unsafe {
            sys::wc_dilithium_sign_msg(
                msg.as_ptr(), msg_len,
                sig.as_mut_ptr(), &mut sig_len,
                &mut self.ws_key,
                &mut rng.wc_rng,
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
    ///   use [`Dilithium::sign_ctx_msg_with_seed()`] instead.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to `sig`
    /// on success or Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(dilithium, dilithium_make_key, dilithium_sign, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::dilithium::Dilithium;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = Dilithium::generate(Dilithium::LEVEL_44, &mut rng)
    ///     .expect("Error with generate()");
    /// let message = b"Hello, ML-DSA!";
    /// let ctx = b"my context";
    /// let mut sig = vec![0u8; key.sig_size().unwrap()];
    /// key.sign_ctx_msg(ctx, message, &mut sig, &mut rng)
    ///     .expect("Error with sign_ctx_msg()");
    /// }
    /// ```
    #[cfg(all(dilithium_sign, random))]
    pub fn sign_ctx_msg(
        &mut self,
        ctx: &[u8],
        msg: &[u8],
        sig: &mut [u8],
        rng: &mut RNG,
    ) -> Result<usize, i32> {
        if ctx.len() > 255 {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let ctx_len = ctx.len() as u8;
        let msg_len = msg.len() as u32;
        let mut sig_len = sig.len() as u32;
        let rc = unsafe {
            sys::wc_dilithium_sign_ctx_msg(
                ctx.as_ptr(), ctx_len,
                msg.as_ptr(), msg_len,
                sig.as_mut_ptr(), &mut sig_len,
                &mut self.ws_key,
                &mut rng.wc_rng,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(sig_len as usize)
    }

    /// Sign a pre-hashed message with a context string.
    ///
    /// This is the HashML-DSA variant: the message is supplied as a hash
    /// digest along with the hash algorithm identifier.
    ///
    /// # Parameters
    ///
    /// * `ctx`: Context string (at most 255 bytes).
    /// * `hash_alg`: Hash algorithm identifier (e.g. `WC_HASH_TYPE_SHA256`).
    /// * `hash`: Hash digest of the message to sign.
    /// * `sig`: Output buffer to hold the signature. Must be at least
    ///   `sig_size()` bytes.
    /// * `rng`: RNG instance for hedged signing. For deterministic signing,
    ///   use [`Dilithium::sign_ctx_hash_with_seed()`] instead.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to `sig`
    /// on success or Err(e) containing the wolfSSL library error code value.
    #[cfg(all(dilithium_sign, random))]
    pub fn sign_ctx_hash(
        &mut self,
        ctx: &[u8],
        hash_alg: i32,
        hash: &[u8],
        sig: &mut [u8],
        rng: &mut RNG,
    ) -> Result<usize, i32> {
        if ctx.len() > 255 {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let ctx_len = ctx.len() as u8;
        let hash_len = hash.len() as u32;
        let mut sig_len = sig.len() as u32;
        let rc = unsafe {
            sys::wc_dilithium_sign_ctx_hash(
                ctx.as_ptr(), ctx_len,
                hash_alg,
                hash.as_ptr(), hash_len,
                sig.as_mut_ptr(), &mut sig_len,
                &mut self.ws_key,
                &mut rng.wc_rng,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(sig_len as usize)
    }

    /// Sign a message using a fixed random seed instead of an RNG.
    ///
    /// Produces a deterministic signature for a given `(key, msg, seed)`
    /// triple.
    ///
    /// # Parameters
    ///
    /// * `msg`: Message to sign.
    /// * `sig`: Output buffer to hold the signature.
    /// * `seed`: Random seed bytes (`DILITHIUM_RND_SZ` = 32 bytes).
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to `sig`
    /// on success or Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(dilithium, dilithium_make_key_from_seed, dilithium_sign_with_seed))]
    /// {
    /// use wolfssl_wolfcrypt::dilithium::Dilithium;
    /// let key_seed = [0x42u8; 32];
    /// let mut key = Dilithium::generate_from_seed(Dilithium::LEVEL_44, &key_seed)
    ///     .expect("Error with generate_from_seed()");
    /// let message = b"Hello, ML-DSA!";
    /// let sign_seed = [0x55u8; 32];
    /// let mut sig = vec![0u8; key.sig_size().unwrap()];
    /// key.sign_msg_with_seed(message, &mut sig, &sign_seed)
    ///     .expect("Error with sign_msg_with_seed()");
    /// }
    /// ```
    #[cfg(dilithium_sign_with_seed)]
    pub fn sign_msg_with_seed(
        &mut self,
        msg: &[u8],
        sig: &mut [u8],
        seed: &[u8],
    ) -> Result<usize, i32> {
        #[cfg(dilithium_rnd_sz)]
        if seed.len() != sys::DILITHIUM_RND_SZ as usize {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let msg_len = msg.len() as u32;
        let mut sig_len = sig.len() as u32;
        let rc = unsafe {
            sys::wc_dilithium_sign_msg_with_seed(
                msg.as_ptr(), msg_len,
                sig.as_mut_ptr(), &mut sig_len,
                &mut self.ws_key,
                seed.as_ptr(),
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(sig_len as usize)
    }

    /// Sign a message with a context string using a fixed random seed.
    ///
    /// # Parameters
    ///
    /// * `ctx`: Context string (at most 255 bytes).
    /// * `msg`: Message to sign.
    /// * `sig`: Output buffer to hold the signature.
    /// * `seed`: Random seed bytes (`DILITHIUM_RND_SZ` = 32 bytes).
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to `sig`
    /// on success or Err(e) containing the wolfSSL library error code value.
    #[cfg(dilithium_sign_with_seed)]
    pub fn sign_ctx_msg_with_seed(
        &mut self,
        ctx: &[u8],
        msg: &[u8],
        sig: &mut [u8],
        seed: &[u8],
    ) -> Result<usize, i32> {
        if ctx.len() > 255 {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        #[cfg(dilithium_rnd_sz)]
        if seed.len() != sys::DILITHIUM_RND_SZ as usize {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let ctx_len = ctx.len() as u8;
        let msg_len = msg.len() as u32;
        let mut sig_len = sig.len() as u32;
        let rc = unsafe {
            sys::wc_dilithium_sign_ctx_msg_with_seed(
                ctx.as_ptr(), ctx_len,
                msg.as_ptr(), msg_len,
                sig.as_mut_ptr(), &mut sig_len,
                &mut self.ws_key,
                seed.as_ptr(),
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(sig_len as usize)
    }

    /// Sign a pre-hashed message with a context string using a fixed random
    /// seed.
    ///
    /// # Parameters
    ///
    /// * `ctx`: Context string (at most 255 bytes).
    /// * `hash_alg`: Hash algorithm identifier (e.g. `WC_HASH_TYPE_SHA256`).
    /// * `hash`: Hash digest of the message to sign.
    /// * `sig`: Output buffer to hold the signature.
    /// * `seed`: Random seed bytes (`DILITHIUM_RND_SZ` = 32 bytes).
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to `sig`
    /// on success or Err(e) containing the wolfSSL library error code value.
    #[cfg(dilithium_sign_with_seed)]
    pub fn sign_ctx_hash_with_seed(
        &mut self,
        ctx: &[u8],
        hash_alg: i32,
        hash: &[u8],
        sig: &mut [u8],
        seed: &[u8],
    ) -> Result<usize, i32> {
        if ctx.len() > 255 {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        #[cfg(dilithium_rnd_sz)]
        if seed.len() != sys::DILITHIUM_RND_SZ as usize {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let ctx_len = ctx.len() as u8;
        let hash_len = hash.len() as u32;
        let mut sig_len = sig.len() as u32;
        let rc = unsafe {
            sys::wc_dilithium_sign_ctx_hash_with_seed(
                ctx.as_ptr(), ctx_len,
                hash_alg,
                hash.as_ptr(), hash_len,
                sig.as_mut_ptr(), &mut sig_len,
                &mut self.ws_key,
                seed.as_ptr(),
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
    /// Returns either Ok(true) if the signature is valid, Ok(false) if it is
    /// invalid, or Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(dilithium, dilithium_make_key, dilithium_sign, dilithium_verify, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::dilithium::Dilithium;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = Dilithium::generate(Dilithium::LEVEL_44, &mut rng)
    ///     .expect("Error with generate()");
    /// let message = b"Hello, ML-DSA!";
    /// let mut sig = vec![0u8; key.sig_size().unwrap()];
    /// let sig_len = key.sign_msg(message, &mut sig, &mut rng)
    ///     .expect("Error with sign_msg()");
    /// let valid = key.verify_msg(&sig[..sig_len], message)
    ///     .expect("Error with verify_msg()");
    /// assert!(valid);
    /// }
    /// ```
    #[cfg(dilithium_verify)]
    pub fn verify_msg(&mut self, sig: &[u8], msg: &[u8]) -> Result<bool, i32> {
        let sig_len = sig.len() as u32;
        let msg_len = msg.len() as u32;
        let mut res = 0i32;
        let rc = unsafe {
            sys::wc_dilithium_verify_msg(
                sig.as_ptr(), sig_len,
                msg.as_ptr(), msg_len,
                &mut res,
                &mut self.ws_key,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(res == 1)
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
    /// Returns either Ok(true) if the signature is valid, Ok(false) if it is
    /// invalid, or Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(dilithium, dilithium_make_key, dilithium_sign, dilithium_verify, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::dilithium::Dilithium;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = Dilithium::generate(Dilithium::LEVEL_44, &mut rng)
    ///     .expect("Error with generate()");
    /// let message = b"Hello, ML-DSA!";
    /// let ctx = b"my context";
    /// let mut sig = vec![0u8; key.sig_size().unwrap()];
    /// let sig_len = key.sign_ctx_msg(ctx, message, &mut sig, &mut rng)
    ///     .expect("Error with sign_ctx_msg()");
    /// let valid = key.verify_ctx_msg(&sig[..sig_len], ctx, message)
    ///     .expect("Error with verify_ctx_msg()");
    /// assert!(valid);
    /// }
    /// ```
    #[cfg(dilithium_verify)]
    pub fn verify_ctx_msg(&mut self, sig: &[u8], ctx: &[u8], msg: &[u8]) -> Result<bool, i32> {
        if ctx.len() > 255 {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let sig_len = sig.len() as u32;
        let ctx_len = ctx.len() as u32;
        let msg_len = msg.len() as u32;
        let mut res = 0i32;
        let rc = unsafe {
            sys::wc_dilithium_verify_ctx_msg(
                sig.as_ptr(), sig_len,
                ctx.as_ptr(), ctx_len,
                msg.as_ptr(), msg_len,
                &mut res,
                &mut self.ws_key,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(res == 1)
    }

    /// Verify a pre-hashed message signature with a context string.
    ///
    /// This is the HashML-DSA variant: the message is supplied as a hash
    /// digest along with the hash algorithm identifier.
    ///
    /// # Parameters
    ///
    /// * `sig`: Signature to verify.
    /// * `ctx`: Context string used when signing.
    /// * `hash_alg`: Hash algorithm identifier (e.g. `WC_HASH_TYPE_SHA256`).
    /// * `hash`: Hash digest of the message to verify.
    ///
    /// # Returns
    ///
    /// Returns either Ok(true) if the signature is valid, Ok(false) if it is
    /// invalid, or Err(e) containing the wolfSSL library error code value.
    #[cfg(dilithium_verify)]
    pub fn verify_ctx_hash(
        &mut self,
        sig: &[u8],
        ctx: &[u8],
        hash_alg: i32,
        hash: &[u8],
    ) -> Result<bool, i32> {
        if ctx.len() > 255 {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let sig_len = sig.len() as u32;
        let ctx_len = ctx.len() as u32;
        let hash_len = hash.len() as u32;
        let mut res = 0i32;
        let rc = unsafe {
            sys::wc_dilithium_verify_ctx_hash(
                sig.as_ptr(), sig_len,
                ctx.as_ptr(), ctx_len,
                hash_alg,
                hash.as_ptr(), hash_len,
                &mut res,
                &mut self.ws_key,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(res == 1)
    }
}

impl Drop for Dilithium {
    /// Safely free the underlying wolfSSL Dilithium key context.
    ///
    /// This calls `wc_dilithium_free()`. The Rust Drop trait guarantees this
    /// is called when the `Dilithium` struct goes out of scope.
    fn drop(&mut self) {
        unsafe { sys::wc_dilithium_free(&mut self.ws_key); }
    }
}
