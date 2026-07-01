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
post-quantum digital signature functionality.

The primary component is the [`MlDsa`] struct, which manages the lifecycle
of a wolfSSL `wc_MlDsaKey` object. It ensures proper initialization and
deallocation.

Three security parameter sets are supported, selected via
[`MlDsa::set_level()`]:

| Constant        | Level | NIST PQC Level |
|-----------------|-------|----------------|
| [`MlDsa::LEVEL_44`] | 2 | 2 (ML-DSA-44) |
| [`MlDsa::LEVEL_65`] | 3 | 3 (ML-DSA-65) |
| [`MlDsa::LEVEL_87`] | 5 | 5 (ML-DSA-87) |

# Examples

```rust
#[cfg(all(mldsa, mldsa_make_key, mldsa_sign, mldsa_verify, random))]
{
use wolfssl_wolfcrypt::random::RNG;
use wolfssl_wolfcrypt::mldsa::MlDsa;
let mut rng = RNG::new().expect("RNG creation failed");
let mut key = MlDsa::generate(MlDsa::LEVEL_44, &mut rng)
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

#![cfg(mldsa)]

use crate::sys;
#[cfg(all(random, any(mldsa_make_key, mldsa_sign)))]
use crate::random::RNG;
use core::mem::MaybeUninit;

/// Rust wrapper for a wolfSSL `wc_MlDsaKey` object.
///
/// Manages the lifecycle of the underlying key, including initialization and
/// deallocation via the [`Drop`] trait.
///
/// An instance is created with [`MlDsa::generate()`],
/// [`MlDsa::generate_from_seed()`], or [`MlDsa::new()`].
pub struct MlDsa {
    ws_key: sys::wc_MlDsaKey,
}

impl MlDsa {
    /// ML-DSA-44 security parameter set (NIST Level 2).
    pub const LEVEL_44: u8 = sys::WC_ML_DSA_44 as u8;
    /// ML-DSA-65 security parameter set (NIST Level 3).
    pub const LEVEL_65: u8 = sys::WC_ML_DSA_65 as u8;
    /// ML-DSA-87 security parameter set (NIST Level 5).
    pub const LEVEL_87: u8 = sys::WC_ML_DSA_87 as u8;

    /// Required size in bytes of the seed passed to
    /// [`MlDsa::generate_from_seed()`] (`MLDSA_SEED_SZ`).
    pub const MLDSA_SEED_SZ: usize = sys::MLDSA_SEED_SZ as usize;

    /// Required size in bytes of the seed passed to signing-with-seed
    /// functions such as [`MlDsa::sign_msg_with_seed()`]
    /// (`MLDSA_RND_SZ`).
    pub const SIGN_SEED_SIZE: usize = sys::MLDSA_RND_SZ as usize;

    /// Private (secret) key size in bytes for ML-DSA-44.
    #[cfg(mldsa_level2)]
    pub const LEVEL2_KEY_SIZE: usize = sys::WC_MLDSA_44_KEY_SIZE as usize;
    /// Signature size in bytes for ML-DSA-44.
    #[cfg(mldsa_level2)]
    pub const LEVEL2_SIG_SIZE: usize = sys::WC_MLDSA_44_SIG_SIZE as usize;
    /// Public key size in bytes for ML-DSA-44.
    #[cfg(mldsa_level2)]
    pub const LEVEL2_PUB_KEY_SIZE: usize = sys::WC_MLDSA_44_PUB_KEY_SIZE as usize;
    /// Combined private-plus-public key size in bytes for ML-DSA-44.
    #[cfg(mldsa_level2)]
    pub const LEVEL2_PRV_KEY_SIZE: usize =
        sys::WC_MLDSA_44_PUB_KEY_SIZE as usize + sys::WC_MLDSA_44_KEY_SIZE as usize;

    /// Private (secret) key size in bytes for ML-DSA-65.
    #[cfg(mldsa_level3)]
    pub const LEVEL3_KEY_SIZE: usize = sys::WC_MLDSA_65_KEY_SIZE as usize;
    /// Signature size in bytes for ML-DSA-65.
    #[cfg(mldsa_level3)]
    pub const LEVEL3_SIG_SIZE: usize = sys::WC_MLDSA_65_SIG_SIZE as usize;
    /// Public key size in bytes for ML-DSA-65.
    #[cfg(mldsa_level3)]
    pub const LEVEL3_PUB_KEY_SIZE: usize = sys::WC_MLDSA_65_PUB_KEY_SIZE as usize;
    /// Combined private-plus-public key size in bytes for ML-DSA-65.
    #[cfg(mldsa_level3)]
    pub const LEVEL3_PRV_KEY_SIZE: usize =
        sys::WC_MLDSA_65_PUB_KEY_SIZE as usize + sys::WC_MLDSA_65_KEY_SIZE as usize;

    /// Private (secret) key size in bytes for ML-DSA-87.
    #[cfg(mldsa_level5)]
    pub const LEVEL5_KEY_SIZE: usize = sys::WC_MLDSA_87_KEY_SIZE as usize;
    /// Signature size in bytes for ML-DSA-87.
    #[cfg(mldsa_level5)]
    pub const LEVEL5_SIG_SIZE: usize = sys::WC_MLDSA_87_SIG_SIZE as usize;
    /// Public key size in bytes for ML-DSA-87.
    #[cfg(mldsa_level5)]
    pub const LEVEL5_PUB_KEY_SIZE: usize = sys::WC_MLDSA_87_PUB_KEY_SIZE as usize;
    /// Combined private-plus-public key size in bytes for ML-DSA-87.
    #[cfg(mldsa_level5)]
    pub const LEVEL5_PRV_KEY_SIZE: usize =
        sys::WC_MLDSA_87_PUB_KEY_SIZE as usize + sys::WC_MLDSA_87_KEY_SIZE as usize;

    /// Generate a new ML-DSA key pair using a random number generator.
    ///
    /// # Parameters
    ///
    /// * `level`: Security parameter set. One of [`MlDsa::LEVEL_44`],
    ///   [`MlDsa::LEVEL_65`], or [`MlDsa::LEVEL_87`].
    /// * `rng`: `RNG` instance to use for random number generation.
    ///
    /// # Returns
    ///
    /// Returns either Ok(MlDsa) containing the key instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(mldsa, mldsa_make_key, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::mldsa::MlDsa;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let key = MlDsa::generate(MlDsa::LEVEL_44, &mut rng)
    ///     .expect("Error with generate()");
    /// }
    /// ```
    #[cfg(all(mldsa_make_key, random))]
    pub fn generate(level: u8, rng: &RNG) -> Result<Self, i32> {
        Self::generate_ex(level, rng, None, None)
    }

    /// Generate a new ML-DSA key pair with optional heap hint and device ID.
    ///
    /// # Parameters
    ///
    /// * `level`: Security parameter set. One of [`MlDsa::LEVEL_44`],
    ///   [`MlDsa::LEVEL_65`], or [`MlDsa::LEVEL_87`].
    /// * `rng`: `RNG` instance to use for random number generation.
    /// * `heap`: Optional heap hint.
    /// * `dev_id`: Optional device ID for crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(MlDsa) containing the key instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(mldsa, mldsa_make_key, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::mldsa::MlDsa;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let key = MlDsa::generate_ex(MlDsa::LEVEL_44, &mut rng, None, None)
    ///     .expect("Error with generate_ex()");
    /// }
    /// ```
    #[cfg(all(mldsa_make_key, random))]
    pub fn generate_ex(
        level: u8,
        rng: &RNG,
        heap: Option<*mut core::ffi::c_void>,
        dev_id: Option<i32>,
    ) -> Result<Self, i32> {
        let mut key = Self::new_ex(heap, dev_id)?;
        let rc = unsafe { sys::wc_MlDsaKey_SetParams(&mut key.ws_key, level) };
        if rc != 0 {
            return Err(rc);
        }
        let rc = unsafe { sys::wc_MlDsaKey_MakeKey(&mut key.ws_key, rng.wc_rng) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(key)
    }

    /// Generate an ML-DSA key pair from a fixed seed.
    ///
    /// Produces the same key pair for a given `(level, seed)` pair, enabling
    /// deterministic key generation.
    ///
    /// # Parameters
    ///
    /// * `level`: Security parameter set. One of [`MlDsa::LEVEL_44`],
    ///   [`MlDsa::LEVEL_65`], or [`MlDsa::LEVEL_87`].
    /// * `seed`: Seed bytes. Must be `MLDSA_SEED_SZ` (32) bytes.
    ///
    /// # Returns
    ///
    /// Returns either Ok(MlDsa) containing the key instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(mldsa, mldsa_make_key_from_seed))]
    /// {
    /// use wolfssl_wolfcrypt::mldsa::MlDsa;
    /// let seed = [0x42u8; 32];
    /// let key = MlDsa::generate_from_seed(MlDsa::LEVEL_44, &seed)
    ///     .expect("Error with generate_from_seed()");
    /// }
    /// ```
    #[cfg(mldsa_make_key_from_seed)]
    pub fn generate_from_seed(level: u8, seed: &[u8]) -> Result<Self, i32> {
        Self::generate_from_seed_ex(level, seed, None, None)
    }

    /// Generate an ML-DSA key pair from a fixed seed with optional heap hint
    /// and device ID.
    ///
    /// # Parameters
    ///
    /// * `level`: Security parameter set. One of [`MlDsa::LEVEL_44`],
    ///   [`MlDsa::LEVEL_65`], or [`MlDsa::LEVEL_87`].
    /// * `seed`: Seed bytes. Must be `MLDSA_SEED_SZ` (32) bytes.
    /// * `heap`: Optional heap hint.
    /// * `dev_id`: Optional device ID for crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(MlDsa) containing the key instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(mldsa, mldsa_make_key_from_seed))]
    /// {
    /// use wolfssl_wolfcrypt::mldsa::MlDsa;
    /// let seed = [0x42u8; 32];
    /// let key = MlDsa::generate_from_seed_ex(MlDsa::LEVEL_44, &seed, None, None)
    ///     .expect("Error with generate_from_seed_ex()");
    /// }
    /// ```
    #[cfg(mldsa_make_key_from_seed)]
    pub fn generate_from_seed_ex(
        level: u8,
        seed: &[u8],
        heap: Option<*mut core::ffi::c_void>,
        dev_id: Option<i32>,
    ) -> Result<Self, i32> {
        if seed.len() != Self::MLDSA_SEED_SZ {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let mut key = Self::new_ex(heap, dev_id)?;
        let rc = unsafe { sys::wc_MlDsaKey_SetParams(&mut key.ws_key, level) };
        if rc != 0 {
            return Err(rc);
        }
        let rc = unsafe {
            sys::wc_MlDsaKey_MakeKeyFromSeed(&mut key.ws_key, seed.as_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(key)
    }

    /// Create and initialize a new ML-DSA key instance without a key.
    ///
    /// The security level and key material can be set afterwards using
    /// [`MlDsa::set_level()`] and one of the import functions.
    ///
    /// # Returns
    ///
    /// Returns either Ok(MlDsa) containing the key instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(mldsa)]
    /// {
    /// use wolfssl_wolfcrypt::mldsa::MlDsa;
    /// let key = MlDsa::new().expect("Error with new()");
    /// }
    /// ```
    pub fn new() -> Result<Self, i32> {
        Self::new_ex(None, None)
    }

    /// Create and initialize a new ML-DSA key instance with optional heap
    /// hint and device ID.
    ///
    /// # Parameters
    ///
    /// * `heap`: Optional heap hint.
    /// * `dev_id`: Optional device ID for crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(MlDsa) containing the key instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(mldsa)]
    /// {
    /// use wolfssl_wolfcrypt::mldsa::MlDsa;
    /// let key = MlDsa::new_ex(None, None).expect("Error with new_ex()");
    /// }
    /// ```
    pub fn new_ex(
        heap: Option<*mut core::ffi::c_void>,
        dev_id: Option<i32>,
    ) -> Result<Self, i32> {
        let mut ws_key: MaybeUninit<sys::wc_MlDsaKey> = MaybeUninit::uninit();
        let heap = match heap {
            Some(h) => h,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(id) => id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_MlDsaKey_Init(ws_key.as_mut_ptr(), heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        let ws_key = unsafe { ws_key.assume_init() };
        Ok(MlDsa { ws_key })
    }

    /// Set the security parameter level for this key.
    ///
    /// Must be called before generating or importing key material. Use one of
    /// the level constants: [`MlDsa::LEVEL_44`], [`MlDsa::LEVEL_65`],
    /// or [`MlDsa::LEVEL_87`].
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
    /// #[cfg(mldsa)]
    /// {
    /// use wolfssl_wolfcrypt::mldsa::MlDsa;
    /// let mut key = MlDsa::new().expect("Error with new()");
    /// key.set_level(MlDsa::LEVEL_65).expect("Error with set_level()");
    /// }
    /// ```
    pub fn set_level(&mut self, level: u8) -> Result<(), i32> {
        let rc = unsafe { sys::wc_MlDsaKey_SetParams(&mut self.ws_key, level) };
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
    /// #[cfg(mldsa)]
    /// {
    /// use wolfssl_wolfcrypt::mldsa::MlDsa;
    /// let mut key = MlDsa::new().expect("Error with new()");
    /// key.set_level(MlDsa::LEVEL_87).expect("Error with set_level()");
    /// let level = key.get_level().expect("Error with get_level()");
    /// assert_eq!(level, MlDsa::LEVEL_87);
    /// }
    /// ```
    pub fn get_level(&mut self) -> Result<u8, i32> {
        let mut level = 0u8;
        let rc = unsafe { sys::wc_MlDsaKey_GetParams(&mut self.ws_key, &mut level) };
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
    /// #[cfg(all(mldsa, mldsa_make_key, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::mldsa::MlDsa;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = MlDsa::generate(MlDsa::LEVEL_44, &mut rng)
    ///     .expect("Error with generate()");
    /// let sz = key.size().expect("Error with size()");
    /// assert_eq!(sz, MlDsa::LEVEL2_KEY_SIZE);
    /// }
    /// ```
    pub fn size(&mut self) -> Result<usize, i32> {
        let rc = unsafe { sys::wc_MlDsaKey_Size(&mut self.ws_key) };
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
    /// #[cfg(all(mldsa, mldsa_make_key, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::mldsa::MlDsa;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = MlDsa::generate(MlDsa::LEVEL_44, &mut rng)
    ///     .expect("Error with generate()");
    /// let sz = key.priv_size().expect("Error with priv_size()");
    /// assert_eq!(sz, MlDsa::LEVEL2_PRV_KEY_SIZE);
    /// }
    /// ```
    pub fn priv_size(&mut self) -> Result<usize, i32> {
        let rc = unsafe { sys::wc_MlDsaKey_PrivSize(&mut self.ws_key) };
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
    /// #[cfg(all(mldsa, mldsa_make_key, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::mldsa::MlDsa;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = MlDsa::generate(MlDsa::LEVEL_44, &mut rng)
    ///     .expect("Error with generate()");
    /// let sz = key.pub_size().expect("Error with pub_size()");
    /// assert_eq!(sz, MlDsa::LEVEL2_PUB_KEY_SIZE);
    /// }
    /// ```
    pub fn pub_size(&mut self) -> Result<usize, i32> {
        let rc = unsafe { sys::wc_MlDsaKey_PubSize(&mut self.ws_key) };
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
    /// #[cfg(all(mldsa, mldsa_make_key, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::mldsa::MlDsa;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = MlDsa::generate(MlDsa::LEVEL_44, &mut rng)
    ///     .expect("Error with generate()");
    /// let sz = key.sig_size().expect("Error with sig_size()");
    /// assert_eq!(sz, MlDsa::LEVEL2_SIG_SIZE);
    /// }
    /// ```
    pub fn sig_size(&mut self) -> Result<usize, i32> {
        let rc = unsafe { sys::wc_MlDsaKey_SigSize(&mut self.ws_key) };
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
    /// #[cfg(all(mldsa, mldsa_make_key, mldsa_check_key, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::mldsa::MlDsa;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = MlDsa::generate(MlDsa::LEVEL_44, &mut rng)
    ///     .expect("Error with generate()");
    /// key.check_key().expect("Error with check_key()");
    /// }
    /// ```
    #[cfg(mldsa_check_key)]
    pub fn check_key(&mut self) -> Result<(), i32> {
        let rc = unsafe { sys::wc_MlDsaKey_CheckKey(&mut self.ws_key) };
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
    /// #[cfg(all(mldsa, mldsa_make_key, mldsa_import, mldsa_export, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::mldsa::MlDsa;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = MlDsa::generate(MlDsa::LEVEL_44, &mut rng)
    ///     .expect("Error with generate()");
    /// let mut pub_buf = vec![0u8; key.pub_size().unwrap()];
    /// key.export_public(&mut pub_buf).expect("Error with export_public()");
    /// let mut key2 = MlDsa::new().expect("Error with new()");
    /// key2.set_level(MlDsa::LEVEL_44).expect("Error with set_level()");
    /// key2.import_public(&pub_buf).expect("Error with import_public()");
    /// }
    /// ```
    #[cfg(mldsa_import)]
    pub fn import_public(&mut self, public: &[u8]) -> Result<(), i32> {
        let public_size = crate::buffer_len_to_u32(public.len())?;
        let rc = unsafe {
            sys::wc_MlDsaKey_ImportPubRaw(&mut self.ws_key, public.as_ptr(), public_size)
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
    /// #[cfg(all(mldsa, mldsa_make_key, mldsa_import, mldsa_export, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::mldsa::MlDsa;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = MlDsa::generate(MlDsa::LEVEL_44, &mut rng)
    ///     .expect("Error with generate()");
    /// let mut priv_buf = vec![0u8; key.size().unwrap()];
    /// key.export_private(&mut priv_buf).expect("Error with export_private()");
    /// let mut key2 = MlDsa::new().expect("Error with new()");
    /// key2.set_level(MlDsa::LEVEL_44).expect("Error with set_level()");
    /// key2.import_private(&priv_buf).expect("Error with import_private()");
    /// }
    /// ```
    #[cfg(mldsa_import)]
    pub fn import_private(&mut self, private: &[u8]) -> Result<(), i32> {
        let private_size = crate::buffer_len_to_u32(private.len())?;
        let rc = unsafe {
            sys::wc_MlDsaKey_ImportPrivRaw(&mut self.ws_key, private.as_ptr(), private_size)
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
    /// #[cfg(all(mldsa, mldsa_make_key, mldsa_import, mldsa_export, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::mldsa::MlDsa;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = MlDsa::generate(MlDsa::LEVEL_44, &mut rng)
    ///     .expect("Error with generate()");
    /// let mut priv_buf = vec![0u8; key.size().unwrap()];
    /// let mut pub_buf = vec![0u8; key.pub_size().unwrap()];
    /// key.export_key(&mut priv_buf, &mut pub_buf).expect("Error with export_key()");
    /// let mut key2 = MlDsa::new().expect("Error with new()");
    /// key2.set_level(MlDsa::LEVEL_44).expect("Error with set_level()");
    /// key2.import_key(&priv_buf, &pub_buf).expect("Error with import_key()");
    /// }
    /// ```
    #[cfg(mldsa_import)]
    pub fn import_key(&mut self, private: &[u8], public: &[u8]) -> Result<(), i32> {
        let private_size = crate::buffer_len_to_u32(private.len())?;
        let public_size = crate::buffer_len_to_u32(public.len())?;
        let rc = unsafe {
            sys::wc_MlDsaKey_ImportKey(
                &mut self.ws_key,
                private.as_ptr(), private_size,
                public.as_ptr(), public_size,
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
    /// #[cfg(all(mldsa, mldsa_make_key, mldsa_export, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::mldsa::MlDsa;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = MlDsa::generate(MlDsa::LEVEL_44, &mut rng)
    ///     .expect("Error with generate()");
    /// let mut pub_buf = vec![0u8; key.pub_size().unwrap()];
    /// let written = key.export_public(&mut pub_buf).expect("Error with export_public()");
    /// assert_eq!(written, MlDsa::LEVEL2_PUB_KEY_SIZE);
    /// }
    /// ```
    #[cfg(mldsa_export)]
    pub fn export_public(&mut self, public: &mut [u8]) -> Result<usize, i32> {
        let mut public_size = crate::buffer_len_to_u32(public.len())?;
        let rc = unsafe {
            sys::wc_MlDsaKey_ExportPubRaw(&mut self.ws_key, public.as_mut_ptr(), &mut public_size)
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
    /// #[cfg(all(mldsa, mldsa_make_key, mldsa_export, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::mldsa::MlDsa;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = MlDsa::generate(MlDsa::LEVEL_44, &mut rng)
    ///     .expect("Error with generate()");
    /// let mut priv_buf = vec![0u8; key.size().unwrap()];
    /// let written = key.export_private(&mut priv_buf).expect("Error with export_private()");
    /// assert_eq!(written, MlDsa::LEVEL2_KEY_SIZE);
    /// }
    /// ```
    #[cfg(mldsa_export)]
    pub fn export_private(&mut self, private: &mut [u8]) -> Result<usize, i32> {
        let mut private_size = crate::buffer_len_to_u32(private.len())?;
        let rc = unsafe {
            sys::wc_MlDsaKey_ExportPrivRaw(
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
    /// #[cfg(all(mldsa, mldsa_make_key, mldsa_export, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::mldsa::MlDsa;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = MlDsa::generate(MlDsa::LEVEL_44, &mut rng)
    ///     .expect("Error with generate()");
    /// let mut priv_buf = vec![0u8; key.size().unwrap()];
    /// let mut pub_buf = vec![0u8; key.pub_size().unwrap()];
    /// key.export_key(&mut priv_buf, &mut pub_buf).expect("Error with export_key()");
    /// }
    /// ```
    #[cfg(mldsa_export)]
    pub fn export_key(&mut self, private: &mut [u8], public: &mut [u8]) -> Result<(), i32> {
        let mut private_size = crate::buffer_len_to_u32(private.len())?;
        let mut public_size = crate::buffer_len_to_u32(public.len())?;
        let rc = unsafe {
            sys::wc_MlDsaKey_ExportKey(
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
    ///   use [`MlDsa::sign_msg_with_seed()`] instead.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to `sig`
    /// on success or Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(mldsa, mldsa_make_key, mldsa_sign, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::mldsa::MlDsa;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = MlDsa::generate(MlDsa::LEVEL_44, &mut rng)
    ///     .expect("Error with generate()");
    /// let message = b"Hello, ML-DSA!";
    /// let mut sig = vec![0u8; key.sig_size().unwrap()];
    /// let sig_len = key.sign_msg(message, &mut sig, &mut rng)
    ///     .expect("Error with sign_msg()");
    /// assert_eq!(sig_len, MlDsa::LEVEL2_SIG_SIZE);
    /// }
    /// ```
    #[cfg(all(mldsa_sign, random))]
    pub fn sign_msg(
        &mut self,
        msg: &[u8],
        sig: &mut [u8],
        rng: &RNG,
    ) -> Result<usize, i32> {
        let msg_len = crate::buffer_len_to_u32(msg.len())?;
        let mut sig_len = crate::buffer_len_to_u32(sig.len())?;
        let rc = unsafe {
            sys::wc_MlDsaKey_SignCtx(
                &mut self.ws_key,
                core::ptr::null(), 0,
                sig.as_mut_ptr(), &mut sig_len,
                msg.as_ptr(), msg_len,
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
    ///   use [`MlDsa::sign_ctx_msg_with_seed()`] instead.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to `sig`
    /// on success or Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(mldsa, mldsa_make_key, mldsa_sign, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::mldsa::MlDsa;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = MlDsa::generate(MlDsa::LEVEL_44, &mut rng)
    ///     .expect("Error with generate()");
    /// let message = b"Hello, ML-DSA!";
    /// let ctx = b"my context";
    /// let mut sig = vec![0u8; key.sig_size().unwrap()];
    /// key.sign_ctx_msg(ctx, message, &mut sig, &mut rng)
    ///     .expect("Error with sign_ctx_msg()");
    /// }
    /// ```
    #[cfg(all(mldsa_sign, random))]
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
            sys::wc_MlDsaKey_SignCtx(
                &mut self.ws_key,
                ctx.as_ptr(), ctx_len,
                sig.as_mut_ptr(), &mut sig_len,
                msg.as_ptr(), msg_len,
                rng.wc_rng,
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
    ///   use [`MlDsa::sign_ctx_hash_with_seed()`] instead.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to `sig`
    /// on success or Err(e) containing the wolfSSL library error code value.
    #[cfg(all(mldsa_sign, random))]
    pub fn sign_ctx_hash(
        &mut self,
        ctx: &[u8],
        hash_alg: i32,
        hash: &[u8],
        sig: &mut [u8],
        rng: &RNG,
    ) -> Result<usize, i32> {
        if ctx.len() > 255 {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let ctx_len = ctx.len() as u8;
        let hash_len = crate::buffer_len_to_u32(hash.len())?;
        let mut sig_len = crate::buffer_len_to_u32(sig.len())?;
        let rc = unsafe {
            sys::wc_MlDsaKey_SignCtxHash(
                &mut self.ws_key,
                ctx.as_ptr(), ctx_len,
                sig.as_mut_ptr(), &mut sig_len,
                hash.as_ptr(), hash_len,
                hash_alg,
                rng.wc_rng,
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
    /// * `seed`: Random seed bytes (`MLDSA_RND_SZ` = 32 bytes).
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to `sig`
    /// on success or Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(mldsa, mldsa_make_key_from_seed, mldsa_sign_with_seed))]
    /// {
    /// use wolfssl_wolfcrypt::mldsa::MlDsa;
    /// let key_seed = [0x42u8; 32];
    /// let mut key = MlDsa::generate_from_seed(MlDsa::LEVEL_44, &key_seed)
    ///     .expect("Error with generate_from_seed()");
    /// let message = b"Hello, ML-DSA!";
    /// let sign_seed = [0x55u8; 32];
    /// let mut sig = vec![0u8; key.sig_size().unwrap()];
    /// key.sign_msg_with_seed(message, &mut sig, &sign_seed)
    ///     .expect("Error with sign_msg_with_seed()");
    /// }
    /// ```
    #[cfg(mldsa_sign_with_seed)]
    pub fn sign_msg_with_seed(
        &mut self,
        msg: &[u8],
        sig: &mut [u8],
        seed: &[u8],
    ) -> Result<usize, i32> {
        if seed.len() != sys::MLDSA_RND_SZ as usize {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let msg_len = crate::buffer_len_to_u32(msg.len())?;
        let mut sig_len = crate::buffer_len_to_u32(sig.len())?;
        let rc = unsafe {
            sys::wc_MlDsaKey_SignCtxWithSeed(
                &mut self.ws_key,
                core::ptr::null(), 0,
                sig.as_mut_ptr(), &mut sig_len,
                msg.as_ptr(), msg_len,
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
    /// * `seed`: Random seed bytes (`MLDSA_RND_SZ` = 32 bytes).
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to `sig`
    /// on success or Err(e) containing the wolfSSL library error code value.
    #[cfg(mldsa_sign_with_seed)]
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
        if seed.len() != sys::MLDSA_RND_SZ as usize {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let ctx_len = ctx.len() as u8;
        let msg_len = crate::buffer_len_to_u32(msg.len())?;
        let mut sig_len = crate::buffer_len_to_u32(sig.len())?;
        let rc = unsafe {
            sys::wc_MlDsaKey_SignCtxWithSeed(
                &mut self.ws_key,
                ctx.as_ptr(), ctx_len,
                sig.as_mut_ptr(), &mut sig_len,
                msg.as_ptr(), msg_len,
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
    /// * `seed`: Random seed bytes (`MLDSA_RND_SZ` = 32 bytes).
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to `sig`
    /// on success or Err(e) containing the wolfSSL library error code value.
    #[cfg(mldsa_sign_with_seed)]
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
        if seed.len() != sys::MLDSA_RND_SZ as usize {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let ctx_len = ctx.len() as u8;
        let hash_len = crate::buffer_len_to_u32(hash.len())?;
        let mut sig_len = crate::buffer_len_to_u32(sig.len())?;
        let rc = unsafe {
            sys::wc_MlDsaKey_SignCtxHashWithSeed(
                &mut self.ws_key,
                ctx.as_ptr(), ctx_len,
                sig.as_mut_ptr(), &mut sig_len,
                hash.as_ptr(), hash_len,
                hash_alg,
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
    /// #[cfg(all(mldsa, mldsa_make_key, mldsa_sign, mldsa_verify, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::mldsa::MlDsa;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = MlDsa::generate(MlDsa::LEVEL_44, &mut rng)
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
    #[cfg(mldsa_verify)]
    pub fn verify_msg(&mut self, sig: &[u8], msg: &[u8]) -> Result<bool, i32> {
        let sig_len = crate::buffer_len_to_u32(sig.len())?;
        let msg_len = crate::buffer_len_to_u32(msg.len())?;
        let mut res = 0i32;
        let rc = unsafe {
            sys::wc_MlDsaKey_VerifyCtx(
                &mut self.ws_key,
                sig.as_ptr(), sig_len,
                core::ptr::null(), 0,
                msg.as_ptr(), msg_len,
                &mut res,
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
    /// #[cfg(all(mldsa, mldsa_make_key, mldsa_sign, mldsa_verify, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::mldsa::MlDsa;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = MlDsa::generate(MlDsa::LEVEL_44, &mut rng)
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
    #[cfg(mldsa_verify)]
    pub fn verify_ctx_msg(&mut self, sig: &[u8], ctx: &[u8], msg: &[u8]) -> Result<bool, i32> {
        if ctx.len() > 255 {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let sig_len = crate::buffer_len_to_u32(sig.len())?;
        let ctx_len = ctx.len() as u8;
        let msg_len = crate::buffer_len_to_u32(msg.len())?;
        let mut res = 0i32;
        let rc = unsafe {
            sys::wc_MlDsaKey_VerifyCtx(
                &mut self.ws_key,
                sig.as_ptr(), sig_len,
                ctx.as_ptr(), ctx_len,
                msg.as_ptr(), msg_len,
                &mut res,
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
    #[cfg(mldsa_verify)]
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
        let sig_len = crate::buffer_len_to_u32(sig.len())?;
        let ctx_len = ctx.len() as u8;
        let hash_len = crate::buffer_len_to_u32(hash.len())?;
        let mut res = 0i32;
        let rc = unsafe {
            sys::wc_MlDsaKey_VerifyCtxHash(
                &mut self.ws_key,
                sig.as_ptr(), sig_len,
                ctx.as_ptr(), ctx_len,
                hash.as_ptr(), hash_len,
                hash_alg,
                &mut res,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(res == 1)
    }
}

impl MlDsa {
    fn zeroize(&mut self) {
        unsafe { crate::zeroize_raw(&mut self.ws_key); }
    }
}

impl Drop for MlDsa {
    /// Safely free the underlying wolfSSL ML-DSA key context.
    ///
    /// This calls `wc_MlDsaKey_Free()`. The Rust Drop trait guarantees this
    /// is called when the `MlDsa` struct goes out of scope.
    fn drop(&mut self) {
        unsafe { sys::wc_MlDsaKey_Free(&mut self.ws_key); }
        self.zeroize();
    }
}
