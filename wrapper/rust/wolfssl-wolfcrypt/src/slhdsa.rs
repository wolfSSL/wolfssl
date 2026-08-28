/*
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Boston, MA 02110-1335, USA
 */

/*!
This module provides a Rust wrapper for the wolfCrypt library's SLH-DSA
post-quantum digital signature functionality.

The primary component is the [`SlhDsa`] struct, which manages the lifecycle
of a wolfSSL `SlhDsaKey` object. It ensures proper initialization and
deallocation.

The SHAKE parameter sets are selected using the associated constants on
[`SlhDsa`]. SHA2 parameter sets are also available when the wolfCrypt build
enables the SLH-DSA SHA2 option.

# Examples

```rust
#[cfg(all(slhdsa, slhdsa_make_key, slhdsa_sign, slhdsa_verify, random))]
{
use wolfssl_wolfcrypt::random::RNG;
use wolfssl_wolfcrypt::slhdsa::SlhDsa;
let rng = RNG::new().expect("RNG creation failed");
let mut key = SlhDsa::generate(SlhDsa::SHAKE128S, &rng)
    .expect("Key generation failed");
let message = b"Hello, SLH-DSA!";
let mut sig = vec![0u8; key.sig_size().expect("sig_size failed")];
let sig_len = key.sign_msg(message, &mut sig, &rng)
    .expect("Signing failed");
let valid = key.verify_msg(&sig[..sig_len], message)
    .expect("Verification failed");
assert!(valid);
}
```
*/

#![cfg(slhdsa)]

#[cfg(all(random, slhdsa_make_key))]
use crate::random::RNG;
use crate::sys;
use core::mem::MaybeUninit;

/// Rust wrapper for a wolfSSL `SlhDsaKey` object.
///
/// Manages the lifecycle of the underlying key, including initialization and
/// deallocation via the [`Drop`] trait.
pub struct SlhDsa {
    ws_key: sys::SlhDsaKey,
}

impl SlhDsa {
    /// SLH-DSA-SHAKE-128s parameter set.
    #[cfg(slhdsa_shake)]
    pub const SHAKE128S: i32 = sys::SlhDsaParam_SLHDSA_SHAKE128S as i32;
    /// SLH-DSA-SHAKE-128f parameter set.
    #[cfg(slhdsa_shake)]
    pub const SHAKE128F: i32 = sys::SlhDsaParam_SLHDSA_SHAKE128F as i32;
    /// SLH-DSA-SHAKE-192s parameter set.
    #[cfg(slhdsa_shake)]
    pub const SHAKE192S: i32 = sys::SlhDsaParam_SLHDSA_SHAKE192S as i32;
    /// SLH-DSA-SHAKE-192f parameter set.
    #[cfg(slhdsa_shake)]
    pub const SHAKE192F: i32 = sys::SlhDsaParam_SLHDSA_SHAKE192F as i32;
    /// SLH-DSA-SHAKE-256s parameter set.
    #[cfg(slhdsa_shake)]
    pub const SHAKE256S: i32 = sys::SlhDsaParam_SLHDSA_SHAKE256S as i32;
    /// SLH-DSA-SHAKE-256f parameter set.
    #[cfg(slhdsa_shake)]
    pub const SHAKE256F: i32 = sys::SlhDsaParam_SLHDSA_SHAKE256F as i32;

    /// SLH-DSA-SHA2-128s parameter set.
    #[cfg(slhdsa_sha2)]
    pub const SHA2_128S: i32 = sys::SlhDsaParam_SLHDSA_SHA2_128S as i32;
    /// SLH-DSA-SHA2-128f parameter set.
    #[cfg(slhdsa_sha2)]
    pub const SHA2_128F: i32 = sys::SlhDsaParam_SLHDSA_SHA2_128F as i32;
    /// SLH-DSA-SHA2-192s parameter set.
    #[cfg(slhdsa_sha2)]
    pub const SHA2_192S: i32 = sys::SlhDsaParam_SLHDSA_SHA2_192S as i32;
    /// SLH-DSA-SHA2-192f parameter set.
    #[cfg(slhdsa_sha2)]
    pub const SHA2_192F: i32 = sys::SlhDsaParam_SLHDSA_SHA2_192F as i32;
    /// SLH-DSA-SHA2-256s parameter set.
    #[cfg(slhdsa_sha2)]
    pub const SHA2_256S: i32 = sys::SlhDsaParam_SLHDSA_SHA2_256S as i32;
    /// SLH-DSA-SHA2-256f parameter set.
    #[cfg(slhdsa_sha2)]
    pub const SHA2_256F: i32 = sys::SlhDsaParam_SLHDSA_SHA2_256F as i32;

    /// Generate a new SLH-DSA key pair using a random number generator.
    ///
    /// # Parameters
    ///
    /// * `param`: SLH-DSA parameter set, such as [`SlhDsa::SHAKE128S`].
    /// * `rng`: `RNG` instance to use for random number generation.
    ///
    /// # Returns
    ///
    /// Returns either `Ok(SlhDsa)` containing the key instance or `Err(e)`
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(slhdsa, slhdsa_make_key, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let rng = RNG::new().expect("Error creating RNG");
    /// let key = SlhDsa::generate(SlhDsa::SHAKE128S, &rng)
    ///     .expect("Error with generate()");
    /// }
    /// ```
    #[cfg(all(slhdsa_make_key, random))]
    pub fn generate(param: i32, rng: &RNG) -> Result<Self, i32> {
        Self::generate_ex(param, rng, None, None)
    }

    /// Generate a new SLH-DSA key pair with optional heap hint and device ID.
    ///
    /// # Parameters
    ///
    /// * `param`: SLH-DSA parameter set.
    /// * `rng`: `RNG` instance to use for random number generation.
    /// * `heap`: Optional heap hint.
    /// * `dev_id`: Optional device ID for crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either `Ok(SlhDsa)` containing the key instance or `Err(e)`
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(slhdsa, slhdsa_make_key, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let rng = RNG::new().expect("Error creating RNG");
    /// let key = SlhDsa::generate_ex(SlhDsa::SHAKE128S, &rng, None, None)
    ///     .expect("Error with generate_ex()");
    /// }
    /// ```
    #[cfg(all(slhdsa_make_key, random))]
    pub fn generate_ex(
        param: i32,
        rng: &RNG,
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

    /// Create and initialize a new SLH-DSA key instance without key material.
    ///
    /// Key material can be added later with [`SlhDsa::import_public()`].
    ///
    /// # Parameters
    ///
    /// * `param`: SLH-DSA parameter set.
    ///
    /// # Returns
    ///
    /// Returns either `Ok(SlhDsa)` or `Err(e)` with the wolfSSL error code.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(slhdsa)]
    /// {
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let key = SlhDsa::new(SlhDsa::SHAKE128S).expect("Error with new()");
    /// }
    /// ```
    pub fn new(param: i32) -> Result<Self, i32> {
        Self::new_ex(param, None, None)
    }

    /// Create and initialize a new SLH-DSA key with optional heap hint and
    /// device ID.
    ///
    /// # Parameters
    ///
    /// * `param`: SLH-DSA parameter set.
    /// * `heap`: Optional heap hint.
    /// * `dev_id`: Optional device ID for crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either `Ok(SlhDsa)` or `Err(e)` with the wolfSSL error code.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(slhdsa)]
    /// {
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let key = SlhDsa::new_ex(SlhDsa::SHAKE128S, None, None)
    ///     .expect("Error with new_ex()");
    /// }
    /// ```
    pub fn new_ex(
        param: i32,
        heap: Option<*mut core::ffi::c_void>,
        dev_id: Option<i32>,
    ) -> Result<Self, i32> {
        let mut ws_key: MaybeUninit<sys::SlhDsaKey> = MaybeUninit::uninit();
        let heap = heap.unwrap_or(core::ptr::null_mut());
        let dev_id = dev_id.unwrap_or(sys::INVALID_DEVID);
        let rc = unsafe { sys::wc_SlhDsaKey_Init(ws_key.as_mut_ptr(), param as _, heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(Self {
            ws_key: unsafe { ws_key.assume_init() },
        })
    }

    /// Get the private key size in bytes for the configured parameter set.
    ///
    /// # Returns
    ///
    /// Returns `Ok(size)` with the private key size in bytes, or `Err(e)`.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(slhdsa)]
    /// {
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let mut key = SlhDsa::new(SlhDsa::SHAKE128S).expect("Error with new()");
    /// assert!(key.priv_size().expect("Error with priv_size()") > 0);
    /// }
    /// ```
    pub fn priv_size(&mut self) -> Result<usize, i32> {
        let rc = unsafe { sys::wc_SlhDsaKey_PrivateSize(&mut self.ws_key) };
        if rc < 0 { Err(rc) } else { Ok(rc as usize) }
    }

    /// Get the public key size in bytes for the configured parameter set.
    ///
    /// # Returns
    ///
    /// Returns `Ok(size)` with the public key size in bytes, or `Err(e)`.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(slhdsa)]
    /// {
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let mut key = SlhDsa::new(SlhDsa::SHAKE128S).expect("Error with new()");
    /// assert!(key.pub_size().expect("Error with pub_size()") > 0);
    /// }
    /// ```
    pub fn pub_size(&mut self) -> Result<usize, i32> {
        let rc = unsafe { sys::wc_SlhDsaKey_PublicSize(&mut self.ws_key) };
        if rc < 0 { Err(rc) } else { Ok(rc as usize) }
    }

    /// Get the signature size in bytes for the configured parameter set.
    ///
    /// # Returns
    ///
    /// Returns `Ok(size)` with the signature size in bytes, or `Err(e)`.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(slhdsa)]
    /// {
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let mut key = SlhDsa::new(SlhDsa::SHAKE128S).expect("Error with new()");
    /// assert!(key.sig_size().expect("Error with sig_size()") > 0);
    /// }
    /// ```
    pub fn sig_size(&mut self) -> Result<usize, i32> {
        let rc = unsafe { sys::wc_SlhDsaKey_SigSize(&mut self.ws_key) };
        if rc < 0 { Err(rc) } else { Ok(rc as usize) }
    }

    /// Check that the private and public key material forms a valid key pair.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` when the key pair is valid, or `Err(e)` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(slhdsa, slhdsa_make_key, slhdsa_check_key, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let rng = RNG::new().expect("Error creating RNG");
    /// let mut key = SlhDsa::generate(SlhDsa::SHAKE128S, &rng)
    ///     .expect("Error with generate()");
    /// key.check_key().expect("Error with check_key()");
    /// }
    /// ```
    #[cfg(slhdsa_check_key)]
    pub fn check_key(&mut self) -> Result<(), i32> {
        let rc = unsafe { sys::wc_SlhDsaKey_CheckKey(&mut self.ws_key) };
        if rc != 0 { Err(rc) } else { Ok(()) }
    }

    /// Import a raw public key.
    ///
    /// # Parameters
    ///
    /// * `public`: Input buffer containing the raw public key bytes.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success or `Err(e)` with the wolfSSL error code.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(slhdsa, slhdsa_make_key, slhdsa_import, slhdsa_export, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let rng = RNG::new().expect("Error creating RNG");
    /// let mut source = SlhDsa::generate(SlhDsa::SHAKE128S, &rng).unwrap();
    /// let mut public = vec![0u8; source.pub_size().unwrap()];
    /// source.export_public(&mut public).unwrap();
    /// let mut imported = SlhDsa::new(SlhDsa::SHAKE128S).unwrap();
    /// imported.import_public(&public).unwrap();
    /// }
    /// ```
    #[cfg(slhdsa_import)]
    pub fn import_public(&mut self, public: &[u8]) -> Result<(), i32> {
        let public_size = crate::buffer_len_to_u32(public.len())?;
        let rc = unsafe {
            sys::wc_SlhDsaKey_ImportPublic(&mut self.ws_key, public.as_ptr(), public_size)
        };
        if rc != 0 { Err(rc) } else { Ok(()) }
    }

    /// Export the raw public key into `out`, returning the number of bytes
    /// written.
    ///
    /// # Parameters
    ///
    /// * `out`: Output buffer for the raw public key.
    ///
    /// # Returns
    ///
    /// Returns `Ok(size)` with the number of bytes written, or `Err(e)`.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(slhdsa, slhdsa_make_key, slhdsa_export, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let rng = RNG::new().unwrap();
    /// let mut key = SlhDsa::generate(SlhDsa::SHAKE128S, &rng).unwrap();
    /// let mut public = vec![0u8; key.pub_size().unwrap()];
    /// let written = key.export_public(&mut public).unwrap();
    /// assert_eq!(written, public.len());
    /// }
    /// ```
    #[cfg(slhdsa_export)]
    pub fn export_public(&mut self, out: &mut [u8]) -> Result<usize, i32> {
        let mut out_len = crate::buffer_len_to_u32(out.len())?;
        let rc = unsafe {
            sys::wc_SlhDsaKey_ExportPublic(&mut self.ws_key, out.as_mut_ptr(), &mut out_len)
        };
        if rc != 0 {
            Err(rc)
        } else {
            Ok(out_len as usize)
        }
    }

    /// Import raw private key material.
    ///
    /// # Parameters
    ///
    /// * `private`: Input buffer containing the raw private key bytes.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success or `Err(e)` with the wolfSSL error code.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(slhdsa, slhdsa_make_key, slhdsa_import_private, slhdsa_export_private, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let rng = RNG::new().unwrap();
    /// let mut source = SlhDsa::generate(SlhDsa::SHAKE128S, &rng).unwrap();
    /// let mut private = vec![0u8; source.priv_size().unwrap()];
    /// source.export_private(&mut private).unwrap();
    /// let mut imported = SlhDsa::new(SlhDsa::SHAKE128S).unwrap();
    /// imported.import_private(&private).unwrap();
    /// }
    /// ```
    #[cfg(slhdsa_import_private)]
    pub fn import_private(&mut self, private: &[u8]) -> Result<(), i32> {
        let private_len = crate::buffer_len_to_u32(private.len())?;
        let rc = unsafe {
            sys::wc_SlhDsaKey_ImportPrivate(&mut self.ws_key, private.as_ptr(), private_len)
        };
        if rc != 0 { Err(rc) } else { Ok(()) }
    }

    /// Export raw private key material, returning the number of bytes written.
    ///
    /// # Parameters
    ///
    /// * `out`: Output buffer for the raw private key.
    ///
    /// # Returns
    ///
    /// Returns `Ok(size)` with the number of bytes written, or `Err(e)`.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(slhdsa, slhdsa_make_key, slhdsa_export_private, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let rng = RNG::new().unwrap();
    /// let mut key = SlhDsa::generate(SlhDsa::SHAKE128S, &rng).unwrap();
    /// let mut private = vec![0u8; key.priv_size().unwrap()];
    /// let written = key.export_private(&mut private).unwrap();
    /// assert_eq!(written, private.len());
    /// }
    /// ```
    #[cfg(slhdsa_export_private)]
    pub fn export_private(&mut self, out: &mut [u8]) -> Result<usize, i32> {
        let mut out_len = crate::buffer_len_to_u32(out.len())?;
        let rc = unsafe {
            sys::wc_SlhDsaKey_ExportPrivate(&mut self.ws_key, out.as_mut_ptr(), &mut out_len)
        };
        if rc != 0 {
            Err(rc)
        } else {
            Ok(out_len as usize)
        }
    }

    /// Return the private key size for a parameter set without initializing a key.
    ///
    /// # Parameters
    ///
    /// * `param`: SLH-DSA parameter set.
    ///
    /// # Returns
    ///
    /// Returns `Ok(size)` with the private key size in bytes, or `Err(e)`.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(slhdsa, slhdsa_private_size_from_param))]
    /// {
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let size = SlhDsa::priv_size_from_param(SlhDsa::SHAKE128S).unwrap();
    /// assert!(size > 0);
    /// }
    /// ```
    #[cfg(slhdsa_private_size_from_param)]
    pub fn priv_size_from_param(param: i32) -> Result<usize, i32> {
        let rc = unsafe { sys::wc_SlhDsaKey_PrivateSizeFromParam(param as _) };
        if rc < 0 { Err(rc) } else { Ok(rc as usize) }
    }

    /// Return the public key size for a parameter set without initializing a key.
    ///
    /// # Parameters
    ///
    /// * `param`: SLH-DSA parameter set.
    ///
    /// # Returns
    ///
    /// Returns `Ok(size)` with the public key size in bytes, or `Err(e)`.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(slhdsa, slhdsa_public_size_from_param))]
    /// {
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let size = SlhDsa::pub_size_from_param(SlhDsa::SHAKE128S).unwrap();
    /// assert!(size > 0);
    /// }
    /// ```
    #[cfg(slhdsa_public_size_from_param)]
    pub fn pub_size_from_param(param: i32) -> Result<usize, i32> {
        let rc = unsafe { sys::wc_SlhDsaKey_PublicSizeFromParam(param as _) };
        if rc < 0 { Err(rc) } else { Ok(rc as usize) }
    }

    /// Return the signature size for a parameter set without initializing a key.
    ///
    /// # Parameters
    ///
    /// * `param`: SLH-DSA parameter set.
    ///
    /// # Returns
    ///
    /// Returns `Ok(size)` with the signature size in bytes, or `Err(e)`.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(slhdsa, slhdsa_sig_size_from_param))]
    /// {
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let size = SlhDsa::sig_size_from_param(SlhDsa::SHAKE128S).unwrap();
    /// assert!(size > 0);
    /// }
    /// ```
    #[cfg(slhdsa_sig_size_from_param)]
    pub fn sig_size_from_param(param: i32) -> Result<usize, i32> {
        let rc = unsafe { sys::wc_SlhDsaKey_SigSizeFromParam(param as _) };
        if rc < 0 { Err(rc) } else { Ok(rc as usize) }
    }

    fn context_len(ctx: &[u8]) -> Result<u8, i32> {
        if ctx.len() > 255 {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        Ok(ctx.len() as u8)
    }

    /// Sign a message with a context string using an RNG.
    ///
    /// This is the context-bearing counterpart to [`SlhDsa::sign_msg`].
    ///
    /// # Parameters
    ///
    /// * `ctx`: Context string, at most 255 bytes.
    /// * `message`: Message bytes to sign.
    /// * `out`: Output buffer for the signature.
    /// * `rng`: RNG instance for signing randomness.
    ///
    /// # Returns
    ///
    /// Returns `Ok(size)` with the number of bytes written, or `Err(e)`.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(slhdsa, slhdsa_make_key, slhdsa_sign, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let rng = RNG::new().unwrap();
    /// let mut key = SlhDsa::generate(SlhDsa::SHAKE128S, &rng).unwrap();
    /// let mut sig = vec![0u8; key.sig_size().unwrap()];
    /// let written = key.sign_ctx_msg(b"context", b"message", &mut sig, &rng).unwrap();
    /// assert_eq!(written, sig.len());
    /// }
    /// ```
    #[cfg(all(slhdsa_sign, random))]
    pub fn sign_ctx_msg(
        &mut self,
        ctx: &[u8],
        message: &[u8],
        out: &mut [u8],
        rng: &RNG,
    ) -> Result<usize, i32> {
        let ctx_len = Self::context_len(ctx)?;
        let message_len = crate::buffer_len_to_u32(message.len())?;
        let mut signature_len = crate::buffer_len_to_u32(out.len())?;
        let rc = unsafe {
            sys::wc_SlhDsaKey_Sign(
                &mut self.ws_key,
                ctx.as_ptr(),
                ctx_len,
                message.as_ptr(),
                message_len,
                out.as_mut_ptr(),
                &mut signature_len,
                rng.wc_rng,
            )
        };
        if rc != 0 {
            Err(rc)
        } else {
            Ok(signature_len as usize)
        }
    }

    /// Sign a pre-hashed message with a context string using an RNG.
    ///
    /// # Parameters
    ///
    /// * `ctx`: Context string, at most 255 bytes.
    /// * `hash_alg`: Hash algorithm identifier.
    /// * `hash`: Message digest to sign.
    /// * `out`: Output buffer for the signature.
    /// * `rng`: RNG instance for signing randomness.
    ///
    /// # Returns
    ///
    /// Returns `Ok(size)` with the number of bytes written, or `Err(e)`.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(slhdsa, slhdsa_make_key, slhdsa_sign_hash, random))]
    /// {
    /// use wolfssl_wolfcrypt::hmac::HMAC;
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let rng = RNG::new().unwrap();
    /// let mut key = SlhDsa::generate(SlhDsa::SHAKE128S, &rng).unwrap();
    /// let digest = [0u8; 32];
    /// let mut sig = vec![0u8; key.sig_size().unwrap()];
    /// key.sign_ctx_hash(b"context", HMAC::TYPE_SHA256, &digest, &mut sig, &rng).unwrap();
    /// }
    /// ```
    #[cfg(all(slhdsa_sign_hash, random))]
    pub fn sign_ctx_hash(
        &mut self,
        ctx: &[u8],
        hash_alg: i32,
        hash: &[u8],
        out: &mut [u8],
        rng: &RNG,
    ) -> Result<usize, i32> {
        let ctx_len = Self::context_len(ctx)?;
        let hash_len = crate::buffer_len_to_u32(hash.len())?;
        let mut signature_len = crate::buffer_len_to_u32(out.len())?;
        let rc = unsafe {
            sys::wc_SlhDsaKey_SignHash(
                &mut self.ws_key,
                ctx.as_ptr(),
                ctx_len,
                hash.as_ptr(),
                hash_len,
                hash_alg as _,
                out.as_mut_ptr(),
                &mut signature_len,
                rng.wc_rng,
            )
        };
        if rc != 0 {
            Err(rc)
        } else {
            Ok(signature_len as usize)
        }
    }

    /// Sign a message deterministically.
    ///
    /// SLH-DSA derives the deterministic signing randomness from the key and
    /// message; unlike ML-DSA, this operation does not take a seed argument.
    ///
    /// # Parameters
    ///
    /// * `message`: Message bytes to sign.
    /// * `out`: Output buffer for the signature.
    ///
    /// # Returns
    ///
    /// Returns `Ok(size)` with the number of bytes written, or `Err(e)`.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(slhdsa, slhdsa_make_key, slhdsa_sign_deterministic, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let rng = RNG::new().unwrap();
    /// let mut key = SlhDsa::generate(SlhDsa::SHAKE128S, &rng).unwrap();
    /// let mut sig = vec![0u8; key.sig_size().unwrap()];
    /// key.sign_msg_deterministic(b"message", &mut sig).unwrap();
    /// }
    /// ```
    #[cfg(slhdsa_sign_deterministic)]
    pub fn sign_msg_deterministic(&mut self, message: &[u8], out: &mut [u8]) -> Result<usize, i32> {
        self.sign_ctx_msg_deterministic(&[], message, out)
    }

    /// Sign a message with a context string deterministically.
    ///
    /// # Parameters
    ///
    /// * `ctx`: Context string, at most 255 bytes.
    /// * `message`: Message bytes to sign.
    /// * `out`: Output buffer for the signature.
    ///
    /// # Returns
    ///
    /// Returns `Ok(size)` with the number of bytes written, or `Err(e)`.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(slhdsa, slhdsa_make_key, slhdsa_sign_deterministic, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let rng = RNG::new().unwrap();
    /// let mut key = SlhDsa::generate(SlhDsa::SHAKE128S, &rng).unwrap();
    /// let mut sig = vec![0u8; key.sig_size().unwrap()];
    /// key.sign_ctx_msg_deterministic(b"context", b"message", &mut sig).unwrap();
    /// }
    /// ```
    #[cfg(slhdsa_sign_deterministic)]
    pub fn sign_ctx_msg_deterministic(
        &mut self,
        ctx: &[u8],
        message: &[u8],
        out: &mut [u8],
    ) -> Result<usize, i32> {
        let ctx_len = Self::context_len(ctx)?;
        let message_len = crate::buffer_len_to_u32(message.len())?;
        let mut signature_len = crate::buffer_len_to_u32(out.len())?;
        let rc = unsafe {
            sys::wc_SlhDsaKey_SignDeterministic(
                &mut self.ws_key,
                ctx.as_ptr(),
                ctx_len,
                message.as_ptr(),
                message_len,
                out.as_mut_ptr(),
                &mut signature_len,
            )
        };
        if rc != 0 {
            Err(rc)
        } else {
            Ok(signature_len as usize)
        }
    }

    /// Sign a message using a random number generator.
    ///
    /// The wrapper uses an empty context, matching the wolfCrypt API's
    /// default message-signing form.
    ///
    /// # Parameters
    ///
    /// * `message`: Message bytes to sign.
    /// * `out`: Output buffer for the signature.
    /// * `rng`: `RNG` instance to use for signing randomness.
    ///
    /// # Returns
    ///
    /// Returns the number of signature bytes written.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(slhdsa, slhdsa_make_key, slhdsa_sign, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let rng = RNG::new().unwrap();
    /// let mut key = SlhDsa::generate(SlhDsa::SHAKE128S, &rng).unwrap();
    /// let mut sig = vec![0u8; key.sig_size().unwrap()];
    /// let written = key.sign_msg(b"message", &mut sig, &rng).unwrap();
    /// assert_eq!(written, sig.len());
    /// }
    /// ```
    #[cfg(all(slhdsa_sign, random))]
    pub fn sign_msg(&mut self, message: &[u8], out: &mut [u8], rng: &RNG) -> Result<usize, i32> {
        let message_len = crate::buffer_len_to_u32(message.len())?;
        let mut signature_len = crate::buffer_len_to_u32(out.len())?;
        let rc = unsafe {
            sys::wc_SlhDsaKey_Sign(
                &mut self.ws_key,
                core::ptr::null(),
                0,
                message.as_ptr(),
                message_len,
                out.as_mut_ptr(),
                &mut signature_len,
                rng.wc_rng,
            )
        };
        if rc != 0 {
            Err(rc)
        } else {
            Ok(signature_len as usize)
        }
    }

    /// Verify a signature over a message.
    ///
    /// Returns `Ok(true)` for a valid signature and `Ok(false)` for an
    /// invalid signature. WolfCrypt errors are returned as `Err(e)`.
    ///
    /// # Parameters
    ///
    /// * `signature`: Signature to verify.
    /// * `message`: Message the signature was created over.
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if valid, `Ok(false)` if invalid, or `Err(e)`.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(slhdsa, slhdsa_make_key, slhdsa_sign, slhdsa_verify, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let rng = RNG::new().unwrap();
    /// let mut key = SlhDsa::generate(SlhDsa::SHAKE128S, &rng).unwrap();
    /// let mut sig = vec![0u8; key.sig_size().unwrap()];
    /// let len = key.sign_msg(b"message", &mut sig, &rng).unwrap();
    /// assert!(key.verify_msg(&sig[..len], b"message").unwrap());
    /// }
    /// ```
    #[cfg(slhdsa_verify)]
    pub fn verify_msg(&mut self, signature: &[u8], message: &[u8]) -> Result<bool, i32> {
        let message_len = crate::buffer_len_to_u32(message.len())?;
        let signature_len = crate::buffer_len_to_u32(signature.len())?;
        let rc = unsafe {
            sys::wc_SlhDsaKey_Verify(
                &mut self.ws_key,
                core::ptr::null(),
                0,
                message.as_ptr(),
                message_len,
                signature.as_ptr(),
                signature_len,
            )
        };
        if rc == 0 {
            Ok(true)
        } else if rc == sys::wolfCrypt_ErrorCodes_SIG_VERIFY_E {
            Ok(false)
        } else {
            Err(rc)
        }
    }

    /// Verify a message signature with a context string.
    ///
    /// # Parameters
    ///
    /// * `signature`: Signature to verify.
    /// * `ctx`: Context string used when signing, at most 255 bytes.
    /// * `message`: Message the signature was created over.
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if valid, `Ok(false)` if invalid, or `Err(e)`.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(slhdsa, slhdsa_make_key, slhdsa_sign, slhdsa_verify, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let rng = RNG::new().unwrap();
    /// let mut key = SlhDsa::generate(SlhDsa::SHAKE128S, &rng).unwrap();
    /// let mut sig = vec![0u8; key.sig_size().unwrap()];
    /// let len = key.sign_ctx_msg(b"context", b"message", &mut sig, &rng).unwrap();
    /// assert!(key.verify_ctx_msg(&sig[..len], b"context", b"message").unwrap());
    /// }
    /// ```
    #[cfg(slhdsa_verify)]
    pub fn verify_ctx_msg(
        &mut self,
        signature: &[u8],
        ctx: &[u8],
        message: &[u8],
    ) -> Result<bool, i32> {
        let ctx_len = Self::context_len(ctx)?;
        let message_len = crate::buffer_len_to_u32(message.len())?;
        let signature_len = crate::buffer_len_to_u32(signature.len())?;
        let rc = unsafe {
            sys::wc_SlhDsaKey_Verify(
                &mut self.ws_key,
                ctx.as_ptr(),
                ctx_len,
                message.as_ptr(),
                message_len,
                signature.as_ptr(),
                signature_len,
            )
        };
        if rc == 0 {
            Ok(true)
        } else if rc == sys::wolfCrypt_ErrorCodes_SIG_VERIFY_E {
            Ok(false)
        } else {
            Err(rc)
        }
    }

    /// Verify a pre-hashed message signature with a context string.
    ///
    /// # Parameters
    ///
    /// * `signature`: Signature to verify.
    /// * `ctx`: Context string used when signing, at most 255 bytes.
    /// * `hash_alg`: Hash algorithm identifier.
    /// * `hash`: Message digest to verify.
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if valid, `Ok(false)` if invalid, or `Err(e)`.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(slhdsa, slhdsa_make_key, slhdsa_sign_hash, slhdsa_verify_hash, random))]
    /// {
    /// use wolfssl_wolfcrypt::hmac::HMAC;
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::slhdsa::SlhDsa;
    /// let rng = RNG::new().unwrap();
    /// let mut key = SlhDsa::generate(SlhDsa::SHAKE128S, &rng).unwrap();
    /// let digest = [0u8; 32];
    /// let mut sig = vec![0u8; key.sig_size().unwrap()];
    /// let len = key.sign_ctx_hash(b"context", HMAC::TYPE_SHA256, &digest, &mut sig, &rng).unwrap();
    /// assert!(key.verify_ctx_hash(&sig[..len], b"context", HMAC::TYPE_SHA256, &digest).unwrap());
    /// }
    /// ```
    #[cfg(slhdsa_verify_hash)]
    pub fn verify_ctx_hash(
        &mut self,
        signature: &[u8],
        ctx: &[u8],
        hash_alg: i32,
        hash: &[u8],
    ) -> Result<bool, i32> {
        let ctx_len = Self::context_len(ctx)?;
        let hash_len = crate::buffer_len_to_u32(hash.len())?;
        let signature_len = crate::buffer_len_to_u32(signature.len())?;
        let rc = unsafe {
            sys::wc_SlhDsaKey_VerifyHash(
                &mut self.ws_key,
                ctx.as_ptr(),
                ctx_len,
                hash.as_ptr(),
                hash_len,
                hash_alg as _,
                signature.as_ptr(),
                signature_len,
            )
        };
        if rc == 0 {
            Ok(true)
        } else if rc == sys::wolfCrypt_ErrorCodes_SIG_VERIFY_E {
            Ok(false)
        } else {
            Err(rc)
        }
    }
}

impl Drop for SlhDsa {
    fn drop(&mut self) {
        unsafe {
            sys::wc_SlhDsaKey_Free(&mut self.ws_key);
        }
    }
}
