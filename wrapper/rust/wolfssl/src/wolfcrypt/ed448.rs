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
This module provides a Rust wrapper for the wolfCrypt library's EdDSA Curve
448 (Ed448) functionality.
*/

#![cfg(ed448)]

use crate::sys;
use crate::wolfcrypt::random::RNG;
use std::mem::MaybeUninit;

/// The `Ed448` struct manages the lifecycle of a wolfSSL `ed448_key`
/// object.
///
/// It ensures proper initialization and deallocation.
///
/// An instance can be created with `generate()` or `new()`.
pub struct Ed448 {
    ws_key: sys::ed448_key,
}

impl Ed448 {
    /** Size of private key only. */
    pub const KEY_SIZE: usize = sys::ED448_KEY_SIZE as usize;
    /** Size of signature. */
    pub const SIG_SIZE: usize = sys::ED448_SIG_SIZE as usize;
    /** Compressed public key size. */
    pub const PUB_KEY_SIZE: usize = sys::ED448_PUB_KEY_SIZE as usize;
    /** Size of both private and public key. */
    pub const PRV_KEY_SIZE: usize = sys::ED448_PRV_KEY_SIZE as usize;

    pub const ED448: u8 = sys::Ed448 as u8;
    pub const ED448PH: u8 = sys::Ed448ph as u8;

    /// Generate a new Ed448 key.
    ///
    /// # Parameters
    ///
    /// * `rng`: `RNG` instance to use for random number generation.
    ///
    /// # Returns
    ///
    /// Returns either Ok(ed448) containing the Ed448 struct instance or
    /// Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ed448::Ed448;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let ed = Ed448::generate(&mut rng).expect("Error with generate()");
    /// ```
    pub fn generate(rng: &mut RNG) -> Result<Self, i32> {
        Self::generate_ex(rng, None, None)
    }

    /// Generate a new Ed448 key with optional heap and device ID.
    ///
    /// # Parameters
    ///
    /// * `rng`: `RNG` instance to use for random number generation.
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(ed448) containing the Ed448 struct instance or
    /// Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ed448::Ed448;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let ed = Ed448::generate_ex(&mut rng, None, None).expect("Error with generate_ex()");
    /// ```
    pub fn generate_ex(rng: &mut RNG, heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let mut ws_key: MaybeUninit<sys::ed448_key> = MaybeUninit::uninit();
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_ed448_init_ex(ws_key.as_mut_ptr(), heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        let ws_key = unsafe { ws_key.assume_init() };
        let mut ed448 = Ed448 { ws_key };
        let rc = unsafe {
            sys::wc_ed448_make_key(&mut rng.wc_rng,
                sys::ED448_KEY_SIZE as i32, &mut ed448.ws_key)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(ed448)
    }

    /// Create and initialize a new Ed448 instance.
    ///
    /// A key will not be present but can be imported with one of the import
    /// functions.
    ///
    /// # Returns
    ///
    /// Returns either Ok(ed448) containing the Ed448 struct instance or
    /// Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::ed448::Ed448;
    /// let ed = Ed448::new().expect("Error with new()");
    /// ```
    pub fn new() -> Result<Self, i32> {
        Self::new_ex(None, None)
    }

    /// Create and initialize a new Ed448 instance with optional heap and
    /// device ID.
    ///
    /// A key will not be present but can be imported with one of the import
    /// functions.
    ///
    /// # Parameters
    ///
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(ed448) containing the Ed448 struct instance or
    /// Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::ed448::Ed448;
    /// let ed = Ed448::new_ex(None, None).expect("Error with new()");
    /// ```
    pub fn new_ex(heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let mut ws_key: MaybeUninit<sys::ed448_key> = MaybeUninit::uninit();
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_ed448_init_ex(ws_key.as_mut_ptr(), heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        let ws_key = unsafe { ws_key.assume_init() };
        let ed448 = Ed448 { ws_key };
        Ok(ed448)
    }

    /// Check the public key is valid.
    ///
    /// When a private key is present, check that the calculated public key
    /// matches it. When a private key is not present, check that Y is in range
    /// and an X is able to be calculated.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ed448::Ed448;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut ed = Ed448::generate(&mut rng).expect("Error with generate()");
    /// ed.check_key().expect("Error with check_key()");
    /// ```
    pub fn check_key(&mut self) -> Result<(), i32> {
        let rc = unsafe { sys::wc_ed448_check_key(&mut self.ws_key) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Export private and public key to separate buffers.
    ///
    /// # Parameters
    ///
    /// * `private`: Output buffer in which to store the public/private key
    ///   pair. The length should be PRV_KEY_SIZE.
    /// * `public`: Output buffer in which to store the public key. The length
    ///   should be PUB_KEY_SIZE.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ed448_export)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ed448::Ed448;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut ed = Ed448::generate(&mut rng).expect("Error with generate()");
    /// let mut private = [0u8; Ed448::PRV_KEY_SIZE];
    /// let mut public = [0u8; Ed448::PUB_KEY_SIZE];
    /// ed.export_key(&mut private, &mut public).expect("Error with export_key()");
    /// }
    /// ```
    #[cfg(ed448_export)]
    pub fn export_key(&self, private: &mut [u8], public: &mut [u8]) -> Result<(), i32> {
        let mut private_size = private.len() as u32;
        let mut public_size = public.len() as u32;
        let rc = unsafe {
            sys::wc_ed448_export_key(&self.ws_key,
                private.as_mut_ptr(), &mut private_size,
                public.as_mut_ptr(), &mut public_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Export public key to buffer.
    ///
    /// # Parameters
    ///
    /// * `public`: Output buffer in which to store the public key. The length
    ///   should be PUB_KEY_SIZE.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ed448_export)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ed448::Ed448;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut ed = Ed448::generate(&mut rng).expect("Error with generate()");
    /// let mut public = [0u8; Ed448::PUB_KEY_SIZE];
    /// ed.export_public(&mut public).expect("Error with export_public()");
    /// }
    /// ```
    #[cfg(ed448_export)]
    pub fn export_public(&self, public: &mut [u8]) -> Result<(), i32> {
        let mut public_size = public.len() as u32;
        let rc = unsafe {
            sys::wc_ed448_export_public(&self.ws_key, public.as_mut_ptr(),
                &mut public_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Export public/private key pair to buffer.
    ///
    /// # Parameters
    ///
    /// * `keyout`: Output buffer in which to store the key pair. The length
    ///   should be PRV_KEY_SIZE.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ed448_export)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ed448::Ed448;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut ed = Ed448::generate(&mut rng).expect("Error with generate()");
    /// let mut private = [0u8; Ed448::PRV_KEY_SIZE];
    /// ed.export_private(&mut private).expect("Error with export_private()");
    /// }
    /// ```
    #[cfg(ed448_export)]
    pub fn export_private(&self, keyout: &mut [u8]) -> Result<(), i32> {
        let mut keyout_size = keyout.len() as u32;
        let rc = unsafe {
            sys::wc_ed448_export_private(&self.ws_key, keyout.as_mut_ptr(),
                &mut keyout_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Export private key only to buffer.
    ///
    /// # Parameters
    ///
    /// * `private`: Output buffer in which to store the private key. The
    ///   length should be KEY_SIZE.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ed448_export)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ed448::Ed448;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut ed = Ed448::generate(&mut rng).expect("Error with generate()");
    /// let mut private_only = [0u8; Ed448::KEY_SIZE];
    /// ed.export_private_only(&mut private_only).expect("Error with export_private_only()");
    /// }
    /// ```
    #[cfg(ed448_export)]
    pub fn export_private_only(&self, private: &mut [u8]) -> Result<(), i32> {
        let mut private_size = private.len() as u32;
        let rc = unsafe {
            sys::wc_ed448_export_private_only(&self.ws_key,
                private.as_mut_ptr(), &mut private_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Import a public Ed448 key from buffer.
    ///
    /// This function handles either compressed or uncompressed keys.
    /// The public key is checked that it matches the private key if one is
    /// already present.
    ///
    /// # Parameters
    ///
    /// * `public`: Input buffer containing public key.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ed448_import)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ed448::Ed448;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut ed = Ed448::generate(&mut rng).expect("Error with generate()");
    /// let mut private = [0u8; Ed448::PRV_KEY_SIZE];
    /// let mut public = [0u8; Ed448::PUB_KEY_SIZE];
    /// ed.export_key(&mut private, &mut public).expect("Error with export_key()");
    /// let mut ed = Ed448::new().expect("Error with new()");
    /// ed.import_public(&public).expect("Error with import_public()");
    /// }
    /// ```
    #[cfg(ed448_import)]
    pub fn import_public(&mut self, public: &[u8]) -> Result<(), i32> {
        let public_size = public.len() as u32;
        let rc = unsafe {
            sys::wc_ed448_import_public(public.as_ptr(), public_size, &mut self.ws_key)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Import a public Ed448 key from buffer with trusted flag.
    ///
    /// This function handles either compressed or uncompressed keys.
    /// The public key is checked that it matches the private key if one is
    /// already present and trusted is false.
    ///
    /// # Parameters
    ///
    /// * `public`: Input buffer containing public key.
    /// * `trusted`: Whether the public key buffer is trusted.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ed448_import)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ed448::Ed448;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut ed = Ed448::generate(&mut rng).expect("Error with generate()");
    /// let mut private = [0u8; Ed448::PRV_KEY_SIZE];
    /// let mut public = [0u8; Ed448::PUB_KEY_SIZE];
    /// ed.export_key(&mut private, &mut public).expect("Error with export_key()");
    /// let mut ed = Ed448::new().expect("Error with new()");
    /// ed.import_public_ex(&public, false).expect("Error with import_public_ex()");
    /// }
    /// ```
    #[cfg(ed448_import)]
    pub fn import_public_ex(&mut self, public: &[u8], trusted: bool) -> Result<(), i32> {
        let public_size = public.len() as u32;
        let rc = unsafe {
            sys::wc_ed448_import_public_ex(public.as_ptr(), public_size,
                &mut self.ws_key, if trusted {1} else {0})
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Import private Ed448 key only from buffer.
    ///
    /// # Parameters
    ///
    /// * `private`: Input buffer containing private key.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ed448_import)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ed448::Ed448;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut ed = Ed448::generate(&mut rng).expect("Error with generate()");
    /// let mut private_only = [0u8; Ed448::KEY_SIZE];
    /// ed.export_private_only(&mut private_only).expect("Error with export_private_only()");
    /// let mut ed = Ed448::new().expect("Error with new()");
    /// ed.import_private_only(&private_only).expect("Error with import_private_only()");
    /// }
    /// ```
    #[cfg(ed448_import)]
    pub fn import_private_only(&mut self, private: &[u8]) -> Result<(), i32> {
        let private_size = private.len() as u32;
        let rc = unsafe {
            sys::wc_ed448_import_private_only(private.as_ptr(), private_size,
                &mut self.ws_key)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Import public/private Ed448 key pair from buffers.
    ///
    /// This functions handles either compressed or uncompressed keys.
    /// The public key is assumed to be untrusted and is checked against the
    /// private key.
    ///
    /// # Parameters
    ///
    /// * `private`: Input buffer containing private key.
    /// * `public`: Optional input buffer containing public key.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ed448_import)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ed448::Ed448;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut ed = Ed448::generate(&mut rng).expect("Error with generate()");
    /// let mut private = [0u8; Ed448::PRV_KEY_SIZE];
    /// let mut public = [0u8; Ed448::PUB_KEY_SIZE];
    /// ed.export_key(&mut private, &mut public).expect("Error with export_key()");
    /// let mut ed = Ed448::new().expect("Error with new()");
    /// ed.import_private_key(&private, Some(&public)).expect("Error with import_private_key()");
    /// }
    /// ```
    #[cfg(ed448_import)]
    pub fn import_private_key(&mut self, private: &[u8], public: Option<&[u8]>) -> Result<(), i32> {
        let private_size = private.len() as u32;
        let mut public_ptr: *const u8 = core::ptr::null();
        let mut public_size = 0u32;
        if let Some(public) = public {
            public_ptr = public.as_ptr();
            public_size = public.len() as u32;
        }
        let rc = unsafe {
            sys::wc_ed448_import_private_key(private.as_ptr(), private_size,
                public_ptr, public_size, &mut self.ws_key)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Import public/private Ed448 key pair from buffers with trusted flag.
    ///
    /// This functions handles either compressed or uncompressed keys.
    /// The public is checked against private key if not trusted.
    ///
    /// # Parameters
    ///
    /// * `private`: Input buffer containing private key.
    /// * `public`: Optional input buffer containing private key.
    /// * `trusted`: Whether the public key buffer is trusted.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ed448_import)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ed448::Ed448;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut ed = Ed448::generate(&mut rng).expect("Error with generate()");
    /// let mut private = [0u8; Ed448::PRV_KEY_SIZE];
    /// let mut public = [0u8; Ed448::PUB_KEY_SIZE];
    /// ed.export_key(&mut private, &mut public).expect("Error with export_key()");
    /// let mut ed = Ed448::new().expect("Error with new()");
    /// ed.import_private_key_ex(&private, Some(&public), false).expect("Error with import_private_key_ex()");
    /// }
    /// ```
    #[cfg(ed448_import)]
    pub fn import_private_key_ex(&mut self, private: &[u8], public: Option<&[u8]>, trusted: bool) -> Result<(), i32> {
        let private_size = private.len() as u32;
        let mut public_ptr: *const u8 = core::ptr::null();
        let mut public_size = 0u32;
        if let Some(public) = public {
            public_ptr = public.as_ptr();
            public_size = public.len() as u32;
        }
        let rc = unsafe {
            sys::wc_ed448_import_private_key_ex(private.as_ptr(), private_size,
                public_ptr, public_size, &mut self.ws_key, if trusted {1} else {0})
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Generate the Ed448 public key from the private key stored in the
    /// Ed448 object.
    ///
    /// The public key is written to the pubkey output buffer.
    ///
    /// # Parameters
    ///
    /// * `pubkey`: Output buffer in which to store the public key.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ed448::Ed448;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let ed = Ed448::generate(&mut rng).expect("Error with generate()");
    /// let mut private = [0u8; Ed448::KEY_SIZE];
    /// ed.export_private_only(&mut private).expect("Error with export_private_only()");
    /// let mut ed = Ed448::new().expect("Error with new()");
    /// ed.import_private_only(&private).expect("Error with import_private_only()");
    /// let mut public = [0u8; Ed448::KEY_SIZE];
    /// ed.make_public(&mut public).expect("Error with make_public()");
    /// ```
    pub fn make_public(&mut self, pubkey: &mut [u8]) -> Result<(), i32> {
        let pubkey_size = pubkey.len() as u32;
        let rc = unsafe {
            sys::wc_ed448_make_public(&mut self.ws_key,
                pubkey.as_mut_ptr(), pubkey_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Sign a message with optional context using Ed448 key.
    ///
    /// The context is part of the data signed.
    ///
    /// # Parameters
    ///
    /// * `message`: Message to sign.
    /// * `context`: Optional buffer containing context for which message is being signed.
    /// * `signature`: Output buffer to hold signature.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to
    /// signature on success or Err(e) containing the wolfSSL library error
    /// code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ed448_sign)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ed448::Ed448;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut ed = Ed448::generate(&mut rng).expect("Error with generate()");
    /// let message = [0x42u8, 33, 55, 66];
    /// let context = b"context";
    /// let mut signature = [0u8; Ed448::SIG_SIZE];
    /// ed.sign_msg(&message, Some(context), &mut signature).expect("Error with sign_msg()");
    /// }
    /// ```
    #[cfg(ed448_sign)]
    pub fn sign_msg(&mut self, message: &[u8], context: Option<&[u8]>, signature: &mut [u8]) -> Result<usize, i32> {
        let message_size = message.len() as u32;
        let mut context_ptr: *const u8 = core::ptr::null();
        let mut context_size = 0u8;
        if let Some(context) = context {
            context_ptr = context.as_ptr();
            context_size = context.len() as u8;
        }
        let mut signature_size = signature.len() as u32;
        let rc = unsafe {
            sys::wc_ed448_sign_msg(message.as_ptr(), message_size,
                signature.as_mut_ptr(), &mut signature_size, &mut self.ws_key,
                context_ptr, context_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(signature_size as usize)
    }

    /// Sign a message digest with optional context using Ed448 key.
    ///
    /// The context is part of the data signed.
    /// The message is pre-hashed before signature calculation.
    ///
    /// # Parameters
    ///
    /// * `hash`: Message digest to sign.
    /// * `context`: Optional buffer containing context for which hash is being signed.
    /// * `signature`: Output buffer to hold signature.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to
    /// signature on success or Err(e) containing the wolfSSL library error
    /// code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ed448_sign)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ed448::Ed448;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut ed = Ed448::generate(&mut rng).expect("Error with generate()");
    /// let hash = [
    ///     0xddu8,0xaf,0x35,0xa1,0x93,0x61,0x7a,0xba,
    ///     0xcc,0x41,0x73,0x49,0xae,0x20,0x41,0x31,
    ///     0x12,0xe6,0xfa,0x4e,0x89,0xa9,0x7e,0xa2,
    ///     0x0a,0x9e,0xee,0xe6,0x4b,0x55,0xd3,0x9a,
    ///     0x21,0x92,0x99,0x2a,0x27,0x4f,0xc1,0xa8,
    ///     0x36,0xba,0x3c,0x23,0xa3,0xfe,0xeb,0xbd,
    ///     0x45,0x4d,0x44,0x23,0x64,0x3c,0xe8,0x0e,
    ///     0x2a,0x9a,0xc9,0x4f,0xa5,0x4c,0xa4,0x9f
    /// ];
    /// let context = b"context";
    /// let mut signature = [0u8; Ed448::SIG_SIZE];
    /// ed.sign_hash_ph(&hash, Some(context), &mut signature).expect("Error with sign_hash_ph()");
    /// }
    /// ```
    #[cfg(ed448_sign)]
    pub fn sign_hash_ph(&mut self, hash: &[u8], context: Option<&[u8]>, signature: &mut [u8]) -> Result<usize, i32> {
        let hash_size = hash.len() as u32;
        let mut context_ptr: *const u8 = core::ptr::null();
        let mut context_size = 0u8;
        if let Some(context) = context {
            context_ptr = context.as_ptr();
            context_size = context.len() as u8;
        }
        let mut signature_size = signature.len() as u32;
        let rc = unsafe {
            sys::wc_ed448ph_sign_hash(hash.as_ptr(), hash_size,
                signature.as_mut_ptr(), &mut signature_size, &mut self.ws_key,
                context_ptr, context_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(signature_size as usize)
    }

    /// Sign a message with optional context using Ed448 key.
    ///
    /// The context is part of the data signed.
    /// The message is pre-hashed before signature calculation.
    ///
    /// # Parameters
    ///
    /// * `message`: Message digest to sign.
    /// * `context`: Optional buffer containing context for which message is being signed.
    /// * `signature`: Output buffer to hold signature.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to
    /// signature on success or Err(e) containing the wolfSSL library error
    /// code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ed448_sign)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ed448::Ed448;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut ed = Ed448::generate(&mut rng).expect("Error with generate()");
    /// let message = [0x42u8, 33, 55, 66];
    /// let context = b"context";
    /// let mut signature = [0u8; Ed448::SIG_SIZE];
    /// ed.sign_msg_ph(&message, Some(context), &mut signature).expect("Error with sign_msg_ph()");
    /// }
    /// ```
    #[cfg(ed448_sign)]
    pub fn sign_msg_ph(&mut self, message: &[u8], context: Option<&[u8]>, signature: &mut [u8]) -> Result<usize, i32> {
        let message_size = message.len() as u32;
        let mut context_ptr: *const u8 = core::ptr::null();
        let mut context_size = 0u8;
        if let Some(context) = context {
            context_ptr = context.as_ptr();
            context_size = context.len() as u8;
        }
        let mut signature_size = signature.len() as u32;
        let rc = unsafe {
            sys::wc_ed448ph_sign_msg(message.as_ptr(), message_size,
                signature.as_mut_ptr(), &mut signature_size, &mut self.ws_key,
                context_ptr, context_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(signature_size as usize)
    }

    /// Sign input data with optional context using Ed448 key.
    ///
    /// If provided, the context is part of the data signed.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to sign.
    /// * `context`: Optional buffer containing context for which `din` is being signed.
    /// * `typ`: One of `Ed448::ED448` or `Ed448::ED448PH`.
    /// * `signature`: Output buffer to hold signature.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to
    /// signature on success or Err(e) containing the wolfSSL library error
    /// code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ed448_sign)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ed448::Ed448;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut ed = Ed448::generate(&mut rng).expect("Error with generate()");
    /// let message = [0x42u8, 33, 55, 66];
    /// let context = b"context";
    /// let mut signature = [0u8; Ed448::SIG_SIZE];
    /// ed.sign_msg_ex(&message, Some(context), Ed448::ED448, &mut signature).expect("Error with sign_msg_ex()");
    /// }
    /// ```
    #[cfg(ed448_sign)]
    pub fn sign_msg_ex(&mut self, din: &[u8], context: Option<&[u8]>, typ: u8, signature: &mut [u8]) -> Result<usize, i32> {
        let din_size = din.len() as u32;
        let mut context_ptr: *const u8 = core::ptr::null();
        let mut context_size = 0u8;
        if let Some(context) = context {
            context_ptr = context.as_ptr();
            context_size = context.len() as u8;
        }
        let mut signature_size = signature.len() as u32;
        let rc = unsafe {
            sys::wc_ed448_sign_msg_ex(din.as_ptr(), din_size,
                signature.as_mut_ptr(), &mut signature_size, &mut self.ws_key,
                typ, context_ptr, context_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(signature_size as usize)
    }

    /// Verify the Ed448 signature of a message and optional context to ensure authenticity.
    ///
    /// The context is included as part of the data verified.
    ///
    /// # Parameters
    ///
    /// * `signature`: Signature to verify.
    /// * `message`: Message to verify the signature of.
    /// * `context`: Optional buffer containing context for which the message was signed.
    ///
    /// # Returns
    ///
    /// Returns either Ok(valid) containing whether the signature is valid or
    /// Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ed448_verify)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ed448::Ed448;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut ed = Ed448::generate(&mut rng).expect("Error with generate()");
    /// let message = b"Hello!";
    /// let context = b"context";
    /// let mut signature = [0u8; Ed448::SIG_SIZE];
    /// ed.sign_msg(message, Some(context), &mut signature).expect("Error with sign_msg()");
    /// let signature_valid = ed.verify_msg(&signature, message, Some(context)).expect("Error with verify_msg()");
    /// assert!(signature_valid);
    /// }
    /// ```
    #[cfg(ed448_verify)]
    pub fn verify_msg(&mut self, signature: &[u8], message: &[u8], context: Option<&[u8]>) -> Result<bool, i32> {
        let signature_size = signature.len() as u32;
        let message_size = message.len() as u32;
        let mut context_ptr: *const u8 = core::ptr::null();
        let mut context_size = 0u8;
        if let Some(context) = context {
            context_ptr = context.as_ptr();
            context_size = context.len() as u8;
        }
        let mut res = 0i32;
        let rc = unsafe {
            sys::wc_ed448_verify_msg(signature.as_ptr(), signature_size,
                message.as_ptr(), message_size, &mut res, &mut self.ws_key,
                context_ptr, context_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(res == 1)
    }

    /// Verify the Ed448 signature of a message digest and optional context to ensure authenticity.
    ///
    /// The context is included as part of the data verified.
    /// The hash algorithm used to create message digest must be SHA-512.
    /// The message is pre-hashed before verification.
    ///
    /// # Parameters
    ///
    /// * `signature`: Signature to verify.
    /// * `hash`: Message to verify the signature of.
    /// * `context`: Optional buffer containing context for which the hash was signed.
    ///
    /// # Returns
    ///
    /// Returns either Ok(valid) containing whether the signature is valid or
    /// Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ed448_verify)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ed448::Ed448;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut ed = Ed448::generate(&mut rng).expect("Error with generate()");
    /// let hash = [
    ///     0xddu8,0xaf,0x35,0xa1,0x93,0x61,0x7a,0xba,
    ///     0xcc,0x41,0x73,0x49,0xae,0x20,0x41,0x31,
    ///     0x12,0xe6,0xfa,0x4e,0x89,0xa9,0x7e,0xa2,
    ///     0x0a,0x9e,0xee,0xe6,0x4b,0x55,0xd3,0x9a,
    ///     0x21,0x92,0x99,0x2a,0x27,0x4f,0xc1,0xa8,
    ///     0x36,0xba,0x3c,0x23,0xa3,0xfe,0xeb,0xbd,
    ///     0x45,0x4d,0x44,0x23,0x64,0x3c,0xe8,0x0e,
    ///     0x2a,0x9a,0xc9,0x4f,0xa5,0x4c,0xa4,0x9f
    /// ];
    /// let context = b"context";
    /// let mut signature = [0u8; Ed448::SIG_SIZE];
    /// ed.sign_hash_ph(&hash, Some(context), &mut signature).expect("Error with sign_hash_ph()");
    /// let signature_valid = ed.verify_hash_ph(&signature, &hash, Some(context)).expect("Error with verify_hash_ph()");
    /// assert!(signature_valid);
    /// }
    /// ```
    #[cfg(ed448_verify)]
    pub fn verify_hash_ph(&mut self, signature: &[u8], hash: &[u8], context: Option<&[u8]>) -> Result<bool, i32> {
        let signature_size = signature.len() as u32;
        let hash_size = hash.len() as u32;
        let mut context_ptr: *const u8 = core::ptr::null();
        let mut context_size = 0u8;
        if let Some(context) = context {
            context_ptr = context.as_ptr();
            context_size = context.len() as u8;
        }
        let mut res = 0i32;
        let rc = unsafe {
            sys::wc_ed448ph_verify_hash(signature.as_ptr(), signature_size,
                hash.as_ptr(), hash_size, &mut res, &mut self.ws_key,
                context_ptr, context_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(res == 1)
    }

    /// Verify the Ed448 signature of a message and optional context to ensure authenticity.
    ///
    /// The context is included as part of the data verified.
    /// The message is pre-hashed before verification.
    ///
    /// # Parameters
    ///
    /// * `signature`: Signature to verify.
    /// * `message`: Message to verify the signature of.
    /// * `context`: Optional buffer containing context for which the message was signed.
    ///
    /// # Returns
    ///
    /// Returns either Ok(valid) containing whether the signature is valid or
    /// Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ed448_verify)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ed448::Ed448;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut ed = Ed448::generate(&mut rng).expect("Error with generate()");
    /// let message = [0x42u8, 33, 55, 66];
    /// let context = b"context";
    /// let mut signature = [0u8; Ed448::SIG_SIZE];
    /// ed.sign_msg_ph(&message, Some(context), &mut signature).expect("Error with sign_msg_ph()");
    /// let signature_valid = ed.verify_msg_ph(&signature, &message, Some(context)).expect("Error with verify_msg_ph()");
    /// assert!(signature_valid);
    /// }
    /// ```
    #[cfg(ed448_verify)]
    pub fn verify_msg_ph(&mut self, signature: &[u8], message: &[u8], context: Option<&[u8]>) -> Result<bool, i32> {
        let signature_size = signature.len() as u32;
        let message_size = message.len() as u32;
        let mut context_ptr: *const u8 = core::ptr::null();
        let mut context_size = 0u8;
        if let Some(context) = context {
            context_ptr = context.as_ptr();
            context_size = context.len() as u8;
        }
        let mut res = 0i32;
        let rc = unsafe {
            sys::wc_ed448ph_verify_msg(signature.as_ptr(), signature_size,
                message.as_ptr(), message_size, &mut res, &mut self.ws_key,
                context_ptr, context_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(res == 1)
    }

    /// Verify the Ed448 signature of a message and optional context to ensure authenticity.
    ///
    /// The context is included as part of the data verified.
    ///
    /// # Parameters
    ///
    /// * `signature`: Signature to verify.
    /// * `din`: Message to verify the signature of.
    /// * `context`: Optional buffer containing context for which the input data was signed.
    /// * `typ`: One of `Ed448::ED448` or `Ed448::ED448PH`.
    ///
    /// # Returns
    ///
    /// Returns either Ok(valid) containing whether the signature is valid or
    /// Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ed448_verify)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ed448::Ed448;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut ed = Ed448::generate(&mut rng).expect("Error with generate()");
    /// let message = [0x42u8, 33, 55, 66];
    /// let context = b"context";
    /// let mut signature = [0u8; Ed448::SIG_SIZE];
    /// ed.sign_msg_ex(&message, Some(context), Ed448::ED448, &mut signature).expect("Error with sign_msg_ex()");
    /// let signature_valid = ed.verify_msg_ex(&signature, &message, Some(context), Ed448::ED448).expect("Error with verify_msg_ex()");
    /// assert!(signature_valid);
    /// }
    /// ```
    #[cfg(ed448_verify)]
    pub fn verify_msg_ex(&mut self, signature: &[u8], din: &[u8], context: Option<&[u8]>, typ: u8) -> Result<bool, i32> {
        let signature_size = signature.len() as u32;
        let din_size = din.len() as u32;
        let mut context_ptr: *const u8 = core::ptr::null();
        let mut context_size = 0u8;
        if let Some(context) = context {
            context_ptr = context.as_ptr();
            context_size = context.len() as u8;
        }
        let mut res = 0i32;
        let rc = unsafe {
            sys::wc_ed448_verify_msg_ex(signature.as_ptr(), signature_size,
                din.as_ptr(), din_size, &mut res, &mut self.ws_key, typ,
                context_ptr, context_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(res == 1)
    }

    /// Initialize Ed448 key to perform streaming verification.
    ///
    /// # Parameters
    ///
    /// * `signature`: Signature to verify.
    /// * `context`: Optional buffer containing context for which the input data was signed.
    /// * `typ`: One of `Ed448::ED448` or `Ed448::ED448PH`.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ed448_streaming_verify)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ed448::Ed448;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut ed = Ed448::generate(&mut rng).expect("Error with generate()");
    /// let message = [0x42u8, 33, 55, 66];
    /// let context = [0x42u8, 1, 2, 3];
    /// let mut signature = [0u8; Ed448::SIG_SIZE];
    /// ed.sign_msg(&message, Some(&context), &mut signature).expect("Error with sign_msg()");
    /// ed.verify_msg_init(&signature, Some(&context), Ed448::ED448).expect("Error with verify_msg_init()");
    /// ed.verify_msg_update(&message[0..2]).expect("Error with verify_msg_update()");
    /// ed.verify_msg_update(&message[2..4]).expect("Error with verify_msg_update()");
    /// let signature_valid = ed.verify_msg_final(&signature).expect("Error with verify_msg_final()");
    /// assert!(signature_valid);
    /// }
    /// ```
    #[cfg(ed448_streaming_verify)]
    pub fn verify_msg_init(&mut self, signature: &[u8], context: Option<&[u8]>, typ: u8) -> Result<(), i32> {
        let signature_size = signature.len() as u32;
        let mut context_ptr: *const u8 = core::ptr::null();
        let mut context_size = 0u8;
        if let Some(context) = context {
            context_ptr = context.as_ptr();
            context_size = context.len() as u8;
        }
        let rc = unsafe {
            sys::wc_ed448_verify_msg_init(signature.as_ptr(), signature_size,
                &mut self.ws_key, typ, context_ptr, context_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Add input data to Ed448 streaming verification.
    ///
    /// # Parameters
    ///
    /// * `din`: Segment of message to verify the signature of.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ed448_streaming_verify)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ed448::Ed448;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut ed = Ed448::generate(&mut rng).expect("Error with generate()");
    /// let message = [0x42u8, 33, 55, 66];
    /// let context = [0x42u8, 1, 2, 3];
    /// let mut signature = [0u8; Ed448::SIG_SIZE];
    /// ed.sign_msg(&message, Some(&context), &mut signature).expect("Error with sign_msg()");
    /// ed.verify_msg_init(&signature, Some(&context), Ed448::ED448).expect("Error with verify_msg_init()");
    /// ed.verify_msg_update(&message[0..2]).expect("Error with verify_msg_update()");
    /// ed.verify_msg_update(&message[2..4]).expect("Error with verify_msg_update()");
    /// let signature_valid = ed.verify_msg_final(&signature).expect("Error with verify_msg_final()");
    /// assert!(signature_valid);
    /// }
    /// ```
    #[cfg(ed448_streaming_verify)]
    pub fn verify_msg_update(&mut self, din: &[u8]) -> Result<(), i32> {
        let din_size = din.len() as u32;
        let rc = unsafe {
            sys::wc_ed448_verify_msg_update(din.as_ptr(), din_size,
                &mut self.ws_key)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Finalize Ed448 streaming verification.
    ///
    /// # Parameters
    ///
    /// * `signature`: Signature to verify.
    ///
    /// # Returns
    ///
    /// Returns either Ok(valid) containing whether the signature is valid or
    /// Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ed448_streaming_verify)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ed448::Ed448;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut ed = Ed448::generate(&mut rng).expect("Error with generate()");
    /// let message = [0x42u8, 33, 55, 66];
    /// let context = [0x42u8, 1, 2, 3];
    /// let mut signature = [0u8; Ed448::SIG_SIZE];
    /// ed.sign_msg(&message, Some(&context), &mut signature).expect("Error with sign_msg()");
    /// ed.verify_msg_init(&signature, Some(&context), Ed448::ED448).expect("Error with verify_msg_init()");
    /// ed.verify_msg_update(&message[0..2]).expect("Error with verify_msg_update()");
    /// ed.verify_msg_update(&message[2..4]).expect("Error with verify_msg_update()");
    /// let signature_valid = ed.verify_msg_final(&signature).expect("Error with verify_msg_final()");
    /// assert!(signature_valid);
    /// }
    /// ```
    #[cfg(ed448_streaming_verify)]
    pub fn verify_msg_final(&mut self, signature: &[u8]) -> Result<bool, i32> {
        let signature_size = signature.len() as u32;
        let mut res = 0i32;
        let rc = unsafe {
            sys::wc_ed448_verify_msg_final(signature.as_ptr(), signature_size,
                &mut res, &mut self.ws_key)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(res == 1)
    }

    /// Get the size of an Ed448 key (57 bytes).
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the key size or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ed448::Ed448;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let ed = Ed448::generate(&mut rng).expect("Error with generate()");
    /// let key_size = ed.size().expect("Error with size()");
    /// assert_eq!(key_size, Ed448::KEY_SIZE);
    /// ```
    pub fn size(&self) -> Result<usize, i32> {
        let rc = unsafe { sys::wc_ed448_size(&self.ws_key) };
        if rc < 0 {
            return Err(rc);
        }
        Ok(rc as usize)
    }

    /// Get the size of a private (including public) Ed448 key (114 bytes).
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the key size or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ed448::Ed448;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let ed = Ed448::generate(&mut rng).expect("Error with generate()");
    /// let priv_size = ed.priv_size().expect("Error with priv_size()");
    /// assert_eq!(priv_size, Ed448::PRV_KEY_SIZE);
    /// ```
    pub fn priv_size(&self) -> Result<usize, i32> {
        let rc = unsafe { sys::wc_ed448_priv_size(&self.ws_key) };
        if rc < 0 {
            return Err(rc);
        }
        Ok(rc as usize)
    }

    /// Get the size of a public Ed448 key (57 bytes).
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the key size or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ed448::Ed448;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let ed = Ed448::generate(&mut rng).expect("Error with generate()");
    /// let pub_size = ed.pub_size().expect("Error with pub_size()");
    /// assert_eq!(pub_size, Ed448::PUB_KEY_SIZE);
    /// ```
    pub fn pub_size(&self) -> Result<usize, i32> {
        let rc = unsafe { sys::wc_ed448_pub_size(&self.ws_key) };
        if rc < 0 {
            return Err(rc);
        }
        Ok(rc as usize)
    }

    /// Get the size of a Ed448 signature (114 bytes).
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the key size or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ed448::Ed448;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let ed = Ed448::generate(&mut rng).expect("Error with generate()");
    /// let sig_size = ed.sig_size().expect("Error with sig_size()");
    /// assert_eq!(sig_size, Ed448::SIG_SIZE);
    /// ```
    pub fn sig_size(&self) -> Result<usize, i32> {
        let rc = unsafe { sys::wc_ed448_sig_size(&self.ws_key) };
        if rc < 0 {
            return Err(rc);
        }
        Ok(rc as usize)
    }
}

impl Drop for Ed448 {
    /// Safely free the wolfSSL resources.
    fn drop(&mut self) {
        unsafe { sys::wc_ed448_free(&mut self.ws_key); }
    }
}
