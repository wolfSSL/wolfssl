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
This module provides a Rust wrapper for the wolfCrypt library's Curve25519
functionality.
*/

#![cfg(curve25519)]

#[cfg(random)]
use crate::random::RNG;
use crate::sys;
use core::mem::MaybeUninit;

pub struct Curve25519Key {
    wc_key: sys::curve25519_key,
}

impl Curve25519Key {
    /// Curve 25519 key size (32 bytes).
    pub const KEYSIZE: usize = sys::CURVE25519_KEYSIZE as usize;

    /// Check that a public key buffer holds a valid Curve25519 key value
    /// given the endian ordering.
    ///
    /// # Parameters
    ///
    /// * `big_endian`: True for big-endian, false for little-endian.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    pub fn check_public(public: &[u8], big_endian: bool) -> Result<(), i32> {
        let public_size = public.len() as u32;
        let endian = if big_endian {sys::EC25519_BIG_ENDIAN} else {sys::EC25519_LITTLE_ENDIAN};
        let rc = unsafe {
            sys::wc_curve25519_check_public(public.as_ptr(), public_size,
                endian as i32)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Generate a new private key.
    ///
    /// # Parameters
    ///
    /// * `rng`: Random number generator struct to use for blinding operation.
    ///
    /// # Returns
    ///
    /// Returns either Ok(curve25519key) on success or Err(e) containing the
    /// wolfSSL library error code value.
    #[cfg(random)]
    pub fn generate(rng: &mut RNG) -> Result<Self, i32> {
        let mut wc_key: MaybeUninit<sys::curve25519_key> = MaybeUninit::uninit();
        let rc = unsafe {
            sys::wc_curve25519_init(wc_key.as_mut_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        let wc_key = unsafe { wc_key.assume_init() };
        let mut curve25519key = Curve25519Key { wc_key };
        let rc = unsafe {
            sys::wc_curve25519_make_key(&mut rng.wc_rng, Self::KEYSIZE as i32,
                &mut curve25519key.wc_key)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(curve25519key)
    }

    /// Generate a new private key as a bare vector.
    ///
    /// # Parameters
    ///
    /// * `rng`: Random number generator struct to use for blinding operation.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    #[cfg(random)]
    pub fn generate_priv(rng: &mut RNG, out: &mut [u8]) -> Result<(), i32> {
        if out.len() != Self::KEYSIZE {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let rc = unsafe {
            sys::wc_curve25519_make_priv(&mut rng.wc_rng, Self::KEYSIZE as i32, out.as_mut_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Import a Curve25519 private key only (big-endian only).
    ///
    /// # Parameters
    ///
    /// * `private`: Buffer containing the Curve25519 private key.
    ///
    /// # Returns
    ///
    /// Returns either Ok(curve25519key) on success or Err(e) containing the
    /// wolfSSL library error code value.
    pub fn import_private(private: &[u8]) -> Result<Self, i32> {
        let mut wc_key: MaybeUninit<sys::curve25519_key> = MaybeUninit::uninit();
        let rc = unsafe {
            sys::wc_curve25519_init(wc_key.as_mut_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        let wc_key = unsafe { wc_key.assume_init() };
        let mut curve25519key = Curve25519Key { wc_key };
        let private_size = private.len() as u32;
        let rc = unsafe {
            sys::wc_curve25519_import_private(private.as_ptr(), private_size,
                &mut curve25519key.wc_key)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(curve25519key)
    }

    /// Import a Curve25519 private key only (big or little endian).
    ///
    /// # Parameters
    ///
    /// * `private`: Buffer containing the Curve25519 private key.
    /// * `big_endian`: True for big-endian, false for little-endian.
    ///
    /// # Returns
    ///
    /// Returns either Ok(curve25519key) on success or Err(e) containing the
    /// wolfSSL library error code value.
    pub fn import_private_ex(private: &[u8], big_endian: bool) -> Result<Self, i32> {
        let mut wc_key: MaybeUninit<sys::curve25519_key> = MaybeUninit::uninit();
        let rc = unsafe {
            sys::wc_curve25519_init(wc_key.as_mut_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        let wc_key = unsafe { wc_key.assume_init() };
        let mut curve25519key = Curve25519Key { wc_key };
        let private_size = private.len() as u32;
        let endian = if big_endian {sys::EC25519_BIG_ENDIAN} else {sys::EC25519_LITTLE_ENDIAN};
        let rc = unsafe {
            sys::wc_curve25519_import_private_ex(private.as_ptr(),
                private_size, &mut curve25519key.wc_key, endian as i32)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(curve25519key)
    }

    /// Import a Curve25519 public/private key pair (big-endian only).
    ///
    /// # Parameters
    ///
    /// * `private`: Buffer containing the Curve25519 private key.
    /// * `public`: Buffer containing the Curve25519 public key.
    ///
    /// # Returns
    ///
    /// Returns either Ok(curve25519key) on success or Err(e) containing the
    /// wolfSSL library error code value.
    pub fn import_private_raw(private: &[u8], public: &[u8]) -> Result<Self, i32> {
        let mut wc_key: MaybeUninit<sys::curve25519_key> = MaybeUninit::uninit();
        let rc = unsafe {
            sys::wc_curve25519_init(wc_key.as_mut_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        let wc_key = unsafe { wc_key.assume_init() };
        let mut curve25519key = Curve25519Key { wc_key };
        let private_size = private.len() as u32;
        let public_size = public.len() as u32;
        let rc = unsafe {
            sys::wc_curve25519_import_private_raw(private.as_ptr(),
                private_size, public.as_ptr(), public_size,
                &mut curve25519key.wc_key)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(curve25519key)
    }

    /// Import a Curve25519 public/private key pair (big or little endian).
    ///
    /// # Parameters
    ///
    /// * `private`: Buffer containing the Curve25519 private key.
    /// * `public`: Buffer containing the Curve25519 public key.
    /// * `big_endian`: True for big-endian, false for little-endian.
    ///
    /// # Returns
    ///
    /// Returns either Ok(curve25519key) on success or Err(e) containing the
    /// wolfSSL library error code value.
    pub fn import_private_raw_ex(private: &[u8], public: &[u8], big_endian: bool) -> Result<Self, i32> {
        let mut wc_key: MaybeUninit<sys::curve25519_key> = MaybeUninit::uninit();
        let rc = unsafe {
            sys::wc_curve25519_init(wc_key.as_mut_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        let wc_key = unsafe { wc_key.assume_init() };
        let mut curve25519key = Curve25519Key { wc_key };
        let private_size = private.len() as u32;
        let public_size = public.len() as u32;
        let endian = if big_endian {sys::EC25519_BIG_ENDIAN} else {sys::EC25519_LITTLE_ENDIAN};
        let rc = unsafe {
            sys::wc_curve25519_import_private_raw_ex(private.as_ptr(),
                private_size, public.as_ptr(), public_size,
                &mut curve25519key.wc_key, endian as i32)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(curve25519key)
    }

    /// Import a Curve25519 public key (big-endian only).
    ///
    /// # Parameters
    ///
    /// * `public`: Buffer containing the Curve25519 public key.
    ///
    /// # Returns
    ///
    /// Returns either Ok(curve25519key) on success or Err(e) containing the
    /// wolfSSL library error code value.
    pub fn import_public(public: &[u8]) -> Result<Self, i32> {
        let mut wc_key: MaybeUninit<sys::curve25519_key> = MaybeUninit::uninit();
        let rc = unsafe {
            sys::wc_curve25519_init(wc_key.as_mut_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        let wc_key = unsafe { wc_key.assume_init() };
        let mut curve25519key = Curve25519Key { wc_key };
        let public_size = public.len() as u32;
        let rc = unsafe {
            sys::wc_curve25519_import_public(public.as_ptr(), public_size,
                &mut curve25519key.wc_key)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(curve25519key)
    }

    /// Import a Curve25519 public key (big or little endian).
    ///
    /// # Parameters
    ///
    /// * `public`: Buffer containing the Curve25519 public key.
    /// * `big_endian`: True for big-endian, false for little-endian.
    ///
    /// # Returns
    ///
    /// Returns either Ok(curve25519key) on success or Err(e) containing the
    /// wolfSSL library error code value.
    pub fn import_public_ex(public: &[u8], big_endian: bool) -> Result<Self, i32> {
        let mut wc_key: MaybeUninit<sys::curve25519_key> = MaybeUninit::uninit();
        let rc = unsafe {
            sys::wc_curve25519_init(wc_key.as_mut_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        let wc_key = unsafe { wc_key.assume_init() };
        let mut curve25519key = Curve25519Key { wc_key };
        let public_size = public.len() as u32;
        let endian = if big_endian {sys::EC25519_BIG_ENDIAN} else {sys::EC25519_LITTLE_ENDIAN};
        let rc = unsafe {
            sys::wc_curve25519_import_public_ex(public.as_ptr(), public_size,
                &mut curve25519key.wc_key, endian as i32)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(curve25519key)
    }

    /// Compute the public key from an existing private key using bare vectors.
    ///
    /// # Parameters
    ///
    /// * `private`: Private key (input).
    /// * `public`: Buffer in which to store the computed public key.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    pub fn make_pub(private: &[u8], public: &mut [u8]) -> Result<(), i32> {
        let private_size = private.len() as i32;
        let public_size = public.len() as i32;
        let rc = unsafe {
            sys::wc_curve25519_make_pub(public_size, public.as_mut_ptr(),
                private_size, private.as_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Compute the public key from an existing private key using bare vectors
    /// with blinding.
    ///
    /// # Parameters
    ///
    /// * `private`: Private key (input).
    /// * `public`: Buffer in which to store the computed public key.
    /// * `rng`: Random number generator struct to use for blinding operation.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    #[cfg(all(curve25519_blinding, random))]
    pub fn make_pub_blind(private: &[u8], public: &mut [u8], rng: &mut RNG) -> Result<(), i32> {
        let private_size = private.len() as i32;
        let public_size = public.len() as i32;
        let rc = unsafe {
            sys::wc_curve25519_make_pub_blind(public_size, public.as_mut_ptr(),
                private_size, private.as_ptr(), &mut rng.wc_rng)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Compute the public key from an existing private key with supplied
    /// basepoint, using bare vectors.
    ///
    /// # Parameters
    ///
    /// * `private`: Private key (input).
    /// * `public`: Buffer in which to store the computed public key.
    /// * `basepoint`: Basepoint value to use.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    pub fn make_pub_generic(private: &[u8], public: &mut [u8], basepoint: &[u8]) -> Result<(), i32> {
        let private_size = private.len() as i32;
        let public_size = public.len() as i32;
        let basepoint_size = basepoint.len() as i32;
        let rc = unsafe {
            sys::wc_curve25519_generic(public_size, public.as_mut_ptr(),
                private_size, private.as_ptr(), basepoint_size, basepoint.as_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Compute the public key from an existing private key with supplied
    /// basepoint, using bare vectors.
    ///
    /// # Parameters
    ///
    /// * `private`: Private key (input).
    /// * `public`: Buffer in which to store the computed public key.
    /// * `basepoint`: Basepoint value to use.
    /// * `rng`: Random number generator struct to use for blinding operation.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    #[cfg(all(curve25519_blinding, random))]
    pub fn make_pub_generic_blind(private: &[u8], public: &mut [u8], basepoint: &[u8], rng: &mut RNG) -> Result<(), i32> {
        let private_size = private.len() as i32;
        let public_size = public.len() as i32;
        let basepoint_size = basepoint.len() as i32;
        let rc = unsafe {
            sys::wc_curve25519_generic_blind(public_size, public.as_mut_ptr(),
                private_size, private.as_ptr(), basepoint_size, basepoint.as_ptr(),
                &mut rng.wc_rng)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Compute a shared secret key given a secret private key and a received
    /// public key. It stores the generated secret key in the buffer out and
    /// returns the generated key size. Only supports big endian.
    ///
    /// # Parameters
    ///
    /// * `private_key`: Curve25519Key struct holding the user's private key.
    /// * `public_key`: Curve25519Key struct holding the received public key.
    /// * `out`: Output buffer in which to store the generated secret key.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to `out`
    /// on success or Err(e) containing the wolfSSL library error code value.
    pub fn shared_secret(private_key: &mut Curve25519Key, public_key: &mut Curve25519Key, out: &mut [u8]) -> Result<usize, i32> {
        let mut outlen = out.len() as u32;
        let rc = unsafe {
            sys::wc_curve25519_shared_secret(&mut private_key.wc_key,
                &mut public_key.wc_key, out.as_mut_ptr(), &mut outlen)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(outlen as usize)
    }

    /// Associates a `RNG` instance with this `Curve25519Key` instance.
    ///
    /// This is necessary when generating a shared secret if wolfSSL is built
    /// with the `WOLFSSL_CURVE25519_BLINDING` build option enabled.
    ///
    /// # Parameters
    ///
    /// * `rng`: The `RNG` struct instance to associate with this
    ///   `Curve25519Key` instance. The `RNG` struct should not be moved in
    ///   memory after calling this method.
    ///
    /// # Returns
    ///
    /// Returns Ok(()) on success or Err(e) containing the wolfSSL library
    /// error code value.
    #[cfg(all(curve25519_blinding, random))]
    pub fn set_rng(&mut self, rng: &mut RNG) -> Result<(), i32> {
        let rc = unsafe {
            sys::wc_curve25519_set_rng(&mut self.wc_key, &mut rng.wc_rng)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Compute a shared secret key given a secret private key and a received
    /// public key. It stores the generated secret key in the buffer out and
    /// returns the generated key size. Supports big or little endian.
    ///
    /// # Parameters
    ///
    /// * `private_key`: Curve25519Key struct holding the user's private key.
    /// * `public_key`: Curve25519Key struct holding the received public key.
    /// * `out`: Output buffer in which to store the generated secret key.
    /// * `big_endian`: True for big-endian, false for little-endian.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to `out`
    /// on success or Err(e) containing the wolfSSL library error code value.
    pub fn shared_secret_ex(private_key: &mut Curve25519Key, public_key: &mut Curve25519Key, out: &mut [u8], big_endian: bool) -> Result<usize, i32> {
        let mut outlen = out.len() as u32;
        let endian = if big_endian {sys::EC25519_BIG_ENDIAN} else {sys::EC25519_LITTLE_ENDIAN};
        let rc = unsafe {
            sys::wc_curve25519_shared_secret_ex(&mut private_key.wc_key,
                &mut public_key.wc_key, out.as_mut_ptr(), &mut outlen, endian as i32)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(outlen as usize)
    }

    /// Export public and private keys from Curve25519Key struct to raw buffers
    /// (big-endian only).
    ///
    /// # Parameters
    ///
    /// * `private`: Buffer in which to store the raw private key.
    /// * `public`: Buffer in which to store the raw public key.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    pub fn export_key_raw(&mut self, private: &mut [u8], public: &mut [u8]) -> Result<(), i32> {
        let mut private_size = private.len() as u32;
        let mut public_size = public.len() as u32;
        let rc = unsafe {
            sys::wc_curve25519_export_key_raw(&mut self.wc_key,
                private.as_mut_ptr(), &mut private_size,
                public.as_mut_ptr(), &mut public_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Export public and private keys from Curve25519Key struct to raw buffers
    /// (big or little endian).
    ///
    /// # Parameters
    ///
    /// * `private`: Buffer in which to store the raw private key.
    /// * `public`: Buffer in which to store the raw public key.
    /// * `big_endian`: True for big-endian, false for little-endian.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    pub fn export_key_raw_ex(&mut self, private: &mut [u8], public: &mut [u8], big_endian: bool) -> Result<(), i32> {
        let mut private_size = private.len() as u32;
        let mut public_size = public.len() as u32;
        let endian = if big_endian {sys::EC25519_BIG_ENDIAN} else {sys::EC25519_LITTLE_ENDIAN};
        let rc = unsafe {
            sys::wc_curve25519_export_key_raw_ex(&mut self.wc_key,
                private.as_mut_ptr(), &mut private_size,
                public.as_mut_ptr(), &mut public_size, endian as i32)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Export private key from Curve25519Key struct to a raw buffer
    /// (big-endian only).
    ///
    /// # Parameters
    ///
    /// * `out`: Buffer in which to store the raw private key.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to `out`
    /// on success or Err(e) containing the wolfSSL library error code value.
    pub fn export_private_raw(&mut self, out: &mut [u8]) -> Result<usize, i32> {
        let mut outlen = out.len() as u32;
        let rc = unsafe {
            sys::wc_curve25519_export_private_raw(&mut self.wc_key,
                out.as_mut_ptr(), &mut outlen)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(outlen as usize)
    }

    /// Export private key from Curve25519Key struct to a raw buffer
    /// (big or little endian).
    ///
    /// # Parameters
    ///
    /// * `out`: Buffer in which to store the raw private key.
    /// * `big_endian`: True for big-endian, false for little-endian.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to `out`
    /// on success or Err(e) containing the wolfSSL library error code value.
    pub fn export_private_raw_ex(&mut self, out: &mut [u8], big_endian: bool) -> Result<usize, i32> {
        let mut outlen = out.len() as u32;
        let endian = if big_endian {sys::EC25519_BIG_ENDIAN} else {sys::EC25519_LITTLE_ENDIAN};
        let rc = unsafe {
            sys::wc_curve25519_export_private_raw_ex(&mut self.wc_key,
                out.as_mut_ptr(), &mut outlen, endian as i32)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(outlen as usize)
    }

    /// Export public key from Curve25519Key struct to a raw buffer
    /// (big-endian only).
    ///
    /// # Parameters
    ///
    /// * `out`: Buffer in which to store the raw public key.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to `out`
    /// on success or Err(e) containing the wolfSSL library error code value.
    pub fn export_public(&mut self, out: &mut [u8]) -> Result<usize, i32> {
        let mut outlen = out.len() as u32;
        let rc = unsafe {
            sys::wc_curve25519_export_public(&mut self.wc_key,
                out.as_mut_ptr(), &mut outlen)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(outlen as usize)
    }

    /// Export public key from Curve25519Key struct to a raw buffer
    /// (big or little endian).
    ///
    /// # Parameters
    ///
    /// * `out`: Buffer in which to store the raw public key.
    /// * `big_endian`: True for big-endian, false for little-endian.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to `out`
    /// on success or Err(e) containing the wolfSSL library error code value.
    pub fn export_public_ex(&mut self, out: &mut [u8], big_endian: bool) -> Result<usize, i32> {
        let mut outlen = out.len() as u32;
        let endian = if big_endian {sys::EC25519_BIG_ENDIAN} else {sys::EC25519_LITTLE_ENDIAN};
        let rc = unsafe {
            sys::wc_curve25519_export_public_ex(&mut self.wc_key,
                out.as_mut_ptr(), &mut outlen, endian as i32)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(outlen as usize)
    }
}

impl Drop for Curve25519Key {
    /// Safely free the underlying wolfSSL Curve25519Key context.
    ///
    /// This calls the `wc_curve25519_free` wolfssl library function.
    ///
    /// The Rust Drop trait guarantees that this method is called when the
    /// struct goes out of scope, automatically cleaning up resources and
    /// preventing memory leaks.
    fn drop(&mut self) {
        unsafe { sys::wc_curve25519_free(&mut self.wc_key); }
    }
}
