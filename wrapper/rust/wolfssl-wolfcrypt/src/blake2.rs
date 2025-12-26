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
This module provides a Rust wrapper for the wolfCrypt library's BLAKE2
functionality.
*/

use crate::sys;
use std::mem::MaybeUninit;

/// Context for BLAKE2b computation.
#[cfg(blake2b)]
pub struct BLAKE2b {
    wc_blake2b: sys::Blake2b,
}

#[cfg(blake2b)]
impl BLAKE2b {
    /// Build a new BLAKE2b instance.
    ///
    /// # Parameters
    ///
    /// * `digest_size`: Length of the blake 2 digest to implement.
    ///
    /// # Returns
    ///
    /// Returns either Ok(blake2b) containing the BLAKE2b struct instance or
    /// Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl_wolfcrypt::blake2::BLAKE2b;
    /// let blake2b = BLAKE2b::new(64).expect("Error with new()");
    /// ```
    pub fn new(digest_size: usize) -> Result<Self, i32> {
        let digest_size = digest_size as u32;
        let mut wc_blake2b: MaybeUninit<sys::Blake2b> = MaybeUninit::uninit();
        let rc = unsafe {
            sys::wc_InitBlake2b(wc_blake2b.as_mut_ptr(), digest_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        let wc_blake2b = unsafe { wc_blake2b.assume_init() };
        let blake2b = BLAKE2b { wc_blake2b };
        Ok(blake2b)
    }

    /// Build a new BLAKE2b instance.
    ///
    /// # Parameters
    ///
    /// * `digest_size`: Length of the blake 2 digest to implement.
    /// * `key`: Key to use for BLAKE2b operation.
    ///
    /// # Returns
    ///
    /// Returns either Ok(blake2b) containing the BLAKE2b struct instance or
    /// Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl_wolfcrypt::blake2::BLAKE2b;
    /// let key = [42u8; 32];
    /// let blake2b = BLAKE2b::new_with_key(64, &key).expect("Error with new()");
    /// ```
    pub fn new_with_key(digest_size: usize, key: &[u8]) -> Result<Self, i32> {
        let digest_size = digest_size as u32;
        let mut wc_blake2b: MaybeUninit<sys::Blake2b> = MaybeUninit::uninit();
        let key_size = key.len() as u32;
        let rc = unsafe {
            sys::wc_InitBlake2b_WithKey(wc_blake2b.as_mut_ptr(), digest_size,
                key.as_ptr(), key_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        let wc_blake2b = unsafe { wc_blake2b.assume_init() };
        let blake2b = BLAKE2b { wc_blake2b };
        Ok(blake2b)
    }

    /// Update the BLAKE2b hash with the input data.
    ///
    /// This method may be called several times and then the finalize()
    /// method should be called to retrieve the final hash.
    ///
    /// # Parameters
    ///
    /// * `data`: Input data to hash.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl_wolfcrypt::blake2::BLAKE2b;
    /// let mut blake2b = BLAKE2b::new(64).expect("Error with new()");
    /// blake2b.update(&[0u8; 16]).expect("Error with update()");
    /// ```
    pub fn update(&mut self, data: &[u8]) -> Result<(), i32> {
        let data_size = data.len() as u32;
        let rc = unsafe {
            sys::wc_Blake2bUpdate(&mut self.wc_blake2b, data.as_ptr(), data_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Compute and retrieve the final BLAKE2b hash value.
    ///
    /// # Parameters
    ///
    /// * `hash`: Output buffer in which to store the computed BLAKE2b hash
    ///   value. It can be any length.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl_wolfcrypt::blake2::BLAKE2b;
    /// let mut blake2b = BLAKE2b::new(64).expect("Error with new()");
    /// blake2b.update(&[0u8; 16]).expect("Error with update()");
    /// let mut hash = [0u8; 64];
    /// blake2b.finalize(&mut hash).expect("Error with finalize()");
    /// ```
    pub fn finalize(&mut self, hash: &mut [u8]) -> Result<(), i32> {
        let hash_size = hash.len() as u32;
        let rc = unsafe {
            sys::wc_Blake2bFinal(&mut self.wc_blake2b, hash.as_mut_ptr(), hash_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}

/// Context for BLAKE2s computation.
#[cfg(blake2s)]
pub struct BLAKE2s {
    wc_blake2s: sys::Blake2s,
}

#[cfg(blake2s)]
impl BLAKE2s {
    /// Build a new BLAKE2s instance.
    ///
    /// # Parameters
    ///
    /// * `digest_size`: Length of the blake 2 digest to implement.
    ///
    /// # Returns
    ///
    /// Returns either Ok(blake2s) containing the BLAKE2s struct instance or
    /// Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl_wolfcrypt::blake2::BLAKE2s;
    /// let blake2s = BLAKE2s::new(32).expect("Error with new()");
    /// ```
    pub fn new(digest_size: usize) -> Result<Self, i32> {
        let digest_size = digest_size as u32;
        let mut wc_blake2s: MaybeUninit<sys::Blake2s> = MaybeUninit::uninit();
        let rc = unsafe {
            sys::wc_InitBlake2s(wc_blake2s.as_mut_ptr(), digest_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        let wc_blake2s = unsafe { wc_blake2s.assume_init() };
        let blake2s = BLAKE2s { wc_blake2s };
        Ok(blake2s)
    }

    /// Build a new BLAKE2s instance.
    ///
    /// # Parameters
    ///
    /// * `digest_size`: Length of the blake 2 digest to implement.
    /// * `key`: Key to use for BLAKE2s operation.
    ///
    /// # Returns
    ///
    /// Returns either Ok(blake2s) containing the BLAKE2s struct instance or
    /// Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl_wolfcrypt::blake2::BLAKE2s;
    /// let key = [42u8; 32];
    /// let blake2s = BLAKE2s::new_with_key(32, &key).expect("Error with new()");
    /// ```
    pub fn new_with_key(digest_size: usize, key: &[u8]) -> Result<Self, i32> {
        let digest_size = digest_size as u32;
        let mut wc_blake2s: MaybeUninit<sys::Blake2s> = MaybeUninit::uninit();
        let key_size = key.len() as u32;
        let rc = unsafe {
            sys::wc_InitBlake2s_WithKey(wc_blake2s.as_mut_ptr(), digest_size,
                key.as_ptr(), key_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        let wc_blake2s = unsafe { wc_blake2s.assume_init() };
        let blake2s = BLAKE2s { wc_blake2s };
        Ok(blake2s)
    }

    /// Update the BLAKE2s hash with the input data.
    ///
    /// This method may be called several times and then the finalize()
    /// method should be called to retrieve the final hash.
    ///
    /// # Parameters
    ///
    /// * `data`: Input data to hash.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl_wolfcrypt::blake2::BLAKE2s;
    /// let mut blake2s = BLAKE2s::new(32).expect("Error with new()");
    /// blake2s.update(&[0u8; 16]).expect("Error with update()");
    /// ```
    pub fn update(&mut self, data: &[u8]) -> Result<(), i32> {
        let data_size = data.len() as u32;
        let rc = unsafe {
            sys::wc_Blake2sUpdate(&mut self.wc_blake2s, data.as_ptr(), data_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Compute and retrieve the final BLAKE2s hash value.
    ///
    /// # Parameters
    ///
    /// * `hash`: Output buffer in which to store the computed BLAKE2s hash
    ///   value. It can be any length.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl_wolfcrypt::blake2::BLAKE2s;
    /// let mut blake2s = BLAKE2s::new(32).expect("Error with new()");
    /// blake2s.update(&[0u8; 16]).expect("Error with update()");
    /// let mut hash = [0u8; 64];
    /// blake2s.finalize(&mut hash).expect("Error with finalize()");
    /// ```
    pub fn finalize(&mut self, hash: &mut [u8]) -> Result<(), i32> {
        let hash_size = hash.len() as u32;
        let rc = unsafe {
            sys::wc_Blake2sFinal(&mut self.wc_blake2s, hash.as_mut_ptr(), hash_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}
