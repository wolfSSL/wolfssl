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
This module provides a Rust wrapper for the wolfCrypt library's random number
generator (RNG).

The primary component is the `RNG` struct, which manages the lifecycle of a
wolfSSL `WC_RNG` object. It ensures proper initialization and deallocation.

# Examples

```rust
use wolfssl::wolfcrypt::random::RNG;

fn main() {
    // Create a RNG instance.
    let mut rng = RNG::new().expect("Failed to create RNG");

    // Generate a single random byte value.
    let byte = rng.generate_byte().expect("Failed to generate a single byte");

    // Generate a random block.
    let mut buffer = [0u32; 8];
    rng.generate_block(&mut buffer).expect("Failed to generate a block");
}
```
*/

use crate::sys;
use std::mem::{size_of, MaybeUninit};

/// A cryptographically secure random number generator based on the wolfSSL
/// library.
///
/// This struct wraps the wolfssl `WC_RNG` type, providing a high-level API
/// for generating random bytes and blocks of data. The `Drop` implementation
/// ensures that the underlying wolfSSL RNG context is correctly freed when the
/// `RNG` struct goes out of scope, preventing memory leaks.
pub struct RNG {
    pub(crate) wc_rng: sys::WC_RNG,
}

impl RNG {
    /// Initialize a new `RNG` instance.
    ///
    /// This function wraps the wolfssl library function `wc_InitRng`, which
    /// performs the necessary initialization for the RNG context.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(RNG) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn new() -> Result<Self, i32> {
        RNG::new_ex(None, None)
    }

    /// Initialize a new `RNG` instance with optional heap and device ID.
    ///
    /// This function wraps the wolfssl library function `wc_InitRng`, which
    /// performs the necessary initialization for the RNG context.
    ///
    /// # Parameters
    ///
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(RNG) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn new_ex(heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let mut rng: MaybeUninit<RNG> = MaybeUninit::uninit();
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe {
            sys::wc_InitRng_ex(&mut (*rng.as_mut_ptr()).wc_rng, heap, dev_id)
        };
        if rc == 0 {
            let rng = unsafe { rng.assume_init() };
            Ok(rng)
        } else {
            Err(rc)
        }
    }

    /// Initialize a new `RNG` instance and provide a nonce input.
    ///
    /// This function wraps the wolfssl library function `wc_InitRngNonce`,
    /// which performs the necessary initialization for the RNG context and
    /// accepts a nonce input buffer.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(RNG) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn new_with_nonce<T>(nonce: &mut [T]) -> Result<Self, i32> {
        RNG::new_with_nonce_ex(nonce, None, None)
    }

    /// Initialize a new `RNG` instance and provide a nonce input.
    ///
    /// This function wraps the wolfssl library function `wc_InitRngNonce`,
    /// which performs the necessary initialization for the RNG context and
    /// accepts a nonce input buffer.
    ///
    /// # Parameters
    ///
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(RNG) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn new_with_nonce_ex<T>(nonce: &mut [T], heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let ptr = nonce.as_mut_ptr() as *mut u8;
        let size: u32 = (nonce.len() * size_of::<T>()) as u32;
        let mut rng: MaybeUninit<RNG> = MaybeUninit::uninit();
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe {
            sys::wc_InitRngNonce_ex(&mut (*rng.as_mut_ptr()).wc_rng, ptr, size, heap, dev_id)
        };
        if rc == 0 {
            let rng = unsafe { rng.assume_init() };
            Ok(rng)
        } else {
            Err(rc)
        }
    }

    /// Generate a single cryptographically secure random byte.
    ///
    /// This method calls the `wc_RNG_GenerateByte` wolfSSL library function to
    /// retrieve a random byte from the underlying wolfSSL RNG context.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok(u8)` containing the random byte on success or
    /// an `Err` with the wolfssl library return code on failure.
    pub fn generate_byte(&mut self) -> Result<u8, i32> {
        let mut b: u8 = 0;
        let rc = unsafe { sys::wc_RNG_GenerateByte(&mut self.wc_rng, &mut b) };
        if rc == 0 {
            Ok(b)
        } else {
            Err(rc)
        }
    }

    /// Fill a mutable slice with cryptographically secure random data.
    ///
    /// This is a generic function that can fill a slice of any type `T` with
    /// random bytes. It calculates the total size of the slice in bytes and
    /// calls the underlying `wc_RNG_GenerateBlock` wolfssl library function.
    ///
    /// # Parameters
    ///
    /// * `buf`: A mutable slice of any type `T` to be filled with random data.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok(())` on success or an `Err` with the wolfssl
    /// library return code on failure.
    pub fn generate_block<T>(&mut self, buf: &mut [T]) -> Result<(), i32> {
        let ptr = buf.as_mut_ptr() as *mut u8;
        let size: u32 = (buf.len() * size_of::<T>()) as u32;
        let rc = unsafe { sys::wc_RNG_GenerateBlock(&mut self.wc_rng, ptr, size) };
        if rc == 0 {
            Ok(())
        } else {
            Err(rc)
        }
    }
}

impl Drop for RNG {
    /// Safely free the underlying wolfSSL RNG context.
    ///
    /// This calls the `wc_FreeRng` wolfssl library function.
    ///
    /// The Rust Drop trait guarantees that this method is called when the RNG
    /// struct goes out of scope, automatically cleaning up resources and
    /// preventing memory leaks.
    fn drop(&mut self) {
        unsafe { sys::wc_FreeRng(&mut self.wc_rng); }
    }
}
