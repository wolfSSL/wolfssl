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
This module provides a Rust wrapper for the wolfCrypt library's random number
generator (RNG).

The primary component is the `RNG` struct, which manages the lifecycle of a
wolfSSL `WC_RNG` object. It ensures proper initialization and deallocation.

# Examples

```rust
use wolfssl_wolfcrypt::random::RNG;

// Create a RNG instance.
let rng = RNG::new().expect("Failed to create RNG");

// Generate a single random byte value.
let byte = rng.generate_byte().expect("Failed to generate a single byte");

// Generate a random block.
let mut buffer = [0u32; 8];
rng.generate_block(&mut buffer).expect("Failed to generate a block");
```
*/

#![cfg(random)]

use crate::sys;
use core::mem::size_of_val;
use num_traits::PrimInt;

/// A cryptographically secure random number generator based on the wolfSSL
/// library.
///
/// This struct wraps a pointer to a wolfssl `WC_RNG` allocated on the C heap,
/// providing a high-level API for generating random bytes and blocks of data.
/// The `Drop` implementation ensures that the underlying wolfSSL RNG context is
/// correctly freed when the `RNG` struct goes out of scope, preventing memory
/// leaks.
///
/// All generation methods take `&self`. The actual mutation of the DRBG state
/// happens through the raw pointer in the C library; the `RNG` struct itself
/// is logically immutable after construction.
pub struct RNG {
    pub(crate) wc_rng: *mut sys::WC_RNG,
}

// Safety: the only field of `RNG` is a non-null pointer to a `WC_RNG` that
// lives on the C heap and is never reassigned after construction. Moving the
// struct between threads is sound.
unsafe impl Send for RNG {}

// Note: `RNG` is intentionally not `Sync`. The underlying C `WC_RNG` state is
// mutated by every call to a generation routine, with no internal locking.
// Callers that need cross-thread sharing of a single RNG struct must implement
// their own locking.

/// Storage for an RNG that a consumer (e.g. `RSA`, `ECC`) has been bound to
/// via `set_rng`. The consumer keeps the `RngHandle` alive for as long as the
/// C struct holds its pointer, ensuring the `WC_RNG` outlives the consumer.
pub(crate) enum RngHandle {
    Owned(RNG),
    #[cfg(feature = "alloc")]
    Shared(alloc::rc::Rc<RNG>),
}

impl RNG {
    /// Initialize a new `RNG` instance.
    ///
    /// This function wraps the wolfssl library function `wc_rng_new_ex`, which
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
    /// This function wraps the wolfssl library function `wc_rng_new_ex`, which
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
    pub fn new_ex(heap: Option<*mut core::ffi::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        #[cfg(fips)]
        {
            let rc = unsafe {
                sys::wc_SetSeed_Cb_fips(Some(sys::wc_GenerateSeed))
            };
            if rc != 0 {
                return Err(rc);
            }
        }
        let mut wc_rng: *mut sys::WC_RNG = core::ptr::null_mut();
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe {
            rng_new_ex(&mut wc_rng, core::ptr::null_mut(), 0, heap, dev_id)
        };
        if rc == 0 {
            Ok(RNG {wc_rng})
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
    pub fn new_with_nonce<T: PrimInt>(nonce: &mut [T]) -> Result<Self, i32> {
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
    pub fn new_with_nonce_ex<T: PrimInt>(nonce: &mut [T], heap: Option<*mut core::ffi::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        #[cfg(fips)]
        {
            let rc = unsafe {
                sys::wc_SetSeed_Cb_fips(Some(sys::wc_GenerateSeed))
            };
            if rc != 0 {
                return Err(rc);
            }
        }
        let ptr = nonce.as_mut_ptr() as *mut u8;
        let size = crate::buffer_len_to_u32(size_of_val(nonce))?;
        let mut wc_rng: *mut sys::WC_RNG = core::ptr::null_mut();
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe {
            rng_new_ex(&mut wc_rng, ptr, size, heap, dev_id)
        };
        if rc == 0 {
            Ok(RNG {wc_rng})
        } else {
            Err(rc)
        }
    }

    /// Create and test functionality of DRBG.
    ///
    /// # Parameters
    ///
    /// * `nonce`: Optional nonce to use to initialize DRBG.
    /// * `seed_a`: Buffer containing seed data (required).
    /// * `seed_b`: Optional buffer containing more seed data. If present and
    ///   not empty, the DRBG will be reseeded.
    /// * `output`: Output buffer.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #![cfg(random_hashdrbg)]
    /// use wolfssl_wolfcrypt::random::RNG;
    /// let nonce = [99u8, 88, 77, 66];
    /// let seed_a = [42u8, 33, 55, 88];
    /// let seed_b = [45u8, 10, 20, 30];
    /// let mut output = [0u8; 128];
    /// RNG::health_test(Some(&nonce), &seed_a, Some(&seed_b), &mut output).expect("Error with health_test()");
    /// ```
    #[cfg(random_hashdrbg)]
    pub fn health_test(nonce: Option<&[u8]>, seed_a: &[u8], seed_b: Option<&[u8]>, output: &mut [u8]) -> Result<(), i32> {
        Self::health_test_ex(nonce, seed_a, seed_b, output, None, None)
    }

    /// Create and test functionality of DRBG with optional heap and device ID.
    ///
    /// # Parameters
    ///
    /// * `nonce`: Optional nonce to use to initialize DRBG.
    /// * `seed_a`: Buffer containing seed data (required).
    /// * `seed_b`: Optional buffer containing more seed data. If present and
    ///   not empty, the DRBG will be reseeded.
    /// * `output`: Output buffer.
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #![cfg(random_hashdrbg)]
    /// use wolfssl_wolfcrypt::random::RNG;
    /// let nonce = [99u8, 88, 77, 66];
    /// let seed_a = [42u8, 33, 55, 88];
    /// let seed_b = [45u8, 10, 20, 30];
    /// let mut output = [0u8; 128];
    /// RNG::health_test_ex(Some(&nonce), &seed_a, Some(&seed_b), &mut output, None, None).expect("Error with health_test_ex()");
    /// ```
    #[cfg(random_hashdrbg)]
    pub fn health_test_ex(nonce: Option<&[u8]>, seed_a: &[u8], seed_b: Option<&[u8]>, output: &mut [u8], heap: Option<*mut core::ffi::c_void>, dev_id: Option<i32>) -> Result<(), i32> {
        let mut nonce_ptr = core::ptr::null();
        let mut nonce_size = 0u32;
        if let Some(nonce) = nonce {
            nonce_ptr = nonce.as_ptr();
            nonce_size = crate::buffer_len_to_u32(nonce.len())?;
        }
        let seed_a_size = crate::buffer_len_to_u32(seed_a.len())?;
        let mut seed_b_ptr = core::ptr::null();
        let mut seed_b_size = 0u32;
        if let Some(seed_b) = seed_b {
            seed_b_ptr = seed_b.as_ptr();
            seed_b_size = crate::buffer_len_to_u32(seed_b.len())?;
        }
        let output_size = crate::buffer_len_to_u32(output.len())?;
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe {
            sys::wc_RNG_HealthTest_ex(if seed_b_size > 0 {1} else {0},
                nonce_ptr, nonce_size,
                seed_a.as_ptr(), seed_a_size,
                seed_b_ptr, seed_b_size,
                output.as_mut_ptr(), output_size,
                heap, dev_id)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Test a seed.
    ///
    /// # Parameters
    ///
    /// * `seed`: Buffer containing seed data.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #![cfg(random_hashdrbg)]
    /// use wolfssl_wolfcrypt::random::RNG;
    /// let seed = [42u8, 33, 55, 88];
    /// RNG::test_seed(&seed).expect("Error with test_seed()");
    /// ```
    #[cfg(random_hashdrbg)]
    pub fn test_seed(seed: &[u8]) -> Result<(), i32> {
        let seed_size = crate::buffer_len_to_u32(seed.len())?;
        let rc = unsafe { sys::wc_RNG_TestSeed(seed.as_ptr(), seed_size) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
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
    pub fn generate_byte(&self) -> Result<u8, i32> {
        let mut b: u8 = 0;
        let rc = unsafe { sys::wc_RNG_GenerateByte(self.wc_rng, &mut b) };
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
    /// A single DRBG generate request is limited to `RNG_MAX_BLOCK_LEN` bytes
    /// (the SP 800-90A per-request maximum). Larger buffers are filled with
    /// multiple consecutive requests of at most that size each.
    ///
    /// # Parameters
    ///
    /// * `buf`: A mutable slice of any type `T` to be filled with random data.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok(())` on success or an `Err` with the wolfssl
    /// library return code on failure. On failure the buffer may have been
    /// partially filled and its contents must not be used.
    pub fn generate_block<T: PrimInt>(&self, buf: &mut [T]) -> Result<(), i32> {
        let len = size_of_val(buf);
        // SAFETY: PrimInt types are plain integers with no padding bytes and
        // for which every bit pattern is valid, so viewing the slice as bytes
        // and overwriting them is sound.
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, len)
        };
        for chunk in bytes.chunks_mut(sys::RNG_MAX_BLOCK_LEN as usize) {
            let size = crate::buffer_len_to_u32(chunk.len())?;
            let rc = unsafe {
                sys::wc_RNG_GenerateBlock(self.wc_rng, chunk.as_mut_ptr(), size)
            };
            if rc != 0 {
                return Err(rc);
            }
        }
        Ok(())
    }

    /// Reseed random number generator.
    ///
    /// # Parameters
    ///
    /// * `seed`: Buffer with new seed data.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #![cfg(random_hashdrbg)]
    /// use wolfssl_wolfcrypt::random::RNG;
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let seed = [1u8, 2, 3, 4];
    /// rng.reseed(&seed).expect("Error with reseed()");
    /// ```
    #[cfg(all(random_hashdrbg, not(fips_v5_2_3)))]
    pub fn reseed(&self, seed: &[u8]) -> Result<(), i32> {
        let seed_size = crate::buffer_len_to_u32(seed.len())?;
        let rc = unsafe {
            sys::wc_RNG_DRBG_Reseed(self.wc_rng, seed.as_ptr(), seed_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}

/// The error type returned by the `rand_core` trait implementations for
/// [`RNG`].
///
/// It carries the wolfSSL library error code of the failed
/// `wc_RNG_GenerateBlock()` call, so that entropy, reseed and hardware
/// failures are reported to the caller instead of terminating the process.
#[cfg(any(feature = "rand_core", feature = "rand_core_0_9"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RngError(i32);

#[cfg(any(feature = "rand_core", feature = "rand_core_0_9"))]
impl RngError {
    /// Return the wolfSSL library error code that caused the failure.
    pub fn code(&self) -> i32 {
        self.0
    }
}

#[cfg(any(feature = "rand_core", feature = "rand_core_0_9"))]
impl core::fmt::Display for RngError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "wolfSSL RNG failure (error code {})", self.0)
    }
}

#[cfg(any(feature = "rand_core", feature = "rand_core_0_9"))]
impl core::error::Error for RngError {}

#[cfg(any(feature = "rand_core", feature = "rand_core_0_9"))]
impl From<RngError> for i32 {
    fn from(err: RngError) -> i32 {
        err.0
    }
}

/// Implement `rand_core::TryRng` for `RNG`, allowing it to be used anywhere
/// a standard Rust RNG is expected.
///
/// The wolfSSL RNG is genuinely fallible: a failure of the entropy source, of
/// a reseed or of the underlying hardware is reported to the caller as an
/// [`RngError`] carrying the wolfSSL error code, which is the contract
/// consumers of the fallible `TryRng` trait expect.
///
/// Because `Error` is not `Infallible`, the blanket impls of the infallible
/// `rand_core::Rng` and `rand_core::CryptoRng` traits do not apply to `RNG`.
/// Callers who need those traits, or who prefer a panic on RNG failure, can
/// wrap the RNG in the `rand_core::UnwrapErr` adapter:
///
/// ```rust
/// #![cfg(feature = "rand_core")]
/// use rand_core::{Rng, UnwrapErr};
/// use wolfssl_wolfcrypt::random::RNG;
///
/// let mut rng = UnwrapErr(RNG::new().expect("Failed to create RNG"));
/// let mut buf = [0u8; 32];
/// // Panics on RNG failure.
/// rng.fill_bytes(&mut buf);
/// ```
#[cfg(feature = "rand_core")]
impl rand_core::TryRng for RNG {
    type Error = RngError;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        rand_core::utils::next_word_via_fill(self)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        rand_core::utils::next_word_via_fill(self)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.generate_block(dest).map_err(RngError)
    }
}

/// Mark `RNG` as a cryptographically secure random number generator.
#[cfg(feature = "rand_core")]
impl rand_core::TryCryptoRng for RNG {}

/// Implement `rand_core` 0.9's `TryRngCore` for `RNG`, for callers still on
/// the `rand` 0.9 ecosystem.
///
/// This mirrors the `rand_core` 0.10 `TryRng` implementation, failures are
/// returned as an [`RngError`]. Wrap the RNG in the 0.9 `UnwrapErr` adapter
/// to get the infallible `RngCore` and `CryptoRng` traits, which panic on RNG
/// failure.
///
/// ```rust
/// #![cfg(feature = "rand_core_0_9")]
/// use rand_core_0_9::{RngCore, UnwrapErr};
/// use wolfssl_wolfcrypt::random::RNG;
///
/// let mut rng = UnwrapErr(RNG::new().expect("Failed to create RNG"));
/// let mut buf = [0u8; 32];
/// // Panics on RNG failure.
/// rng.fill_bytes(&mut buf);
/// ```
#[cfg(feature = "rand_core_0_9")]
impl rand_core_0_9::TryRngCore for RNG {
    type Error = RngError;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        self.generate_block(&mut buf).map_err(RngError)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        self.generate_block(&mut buf).map_err(RngError)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.generate_block(dest).map_err(RngError)
    }
}

/// Mark `RNG` as a cryptographically secure random number generator for
/// `rand_core` 0.9.
#[cfg(feature = "rand_core_0_9")]
impl rand_core_0_9::TryCryptoRng for RNG {}

/// `wc_rng_new_ex()`, or on libraries without it (FIPS v5) the older
/// `wc_rng_new()`, which takes no device ID, so any device ID is refused there.
///
/// # Safety
///
/// Same as `wc_rng_new_ex()`.
unsafe fn rng_new_ex(rng: &mut *mut sys::WC_RNG, nonce: *mut u8,
        nonce_size: u32, heap: *mut core::ffi::c_void, dev_id: i32) -> i32 {
    #[cfg(rng_new_ex)]
    {
        unsafe { sys::wc_rng_new_ex(rng, nonce, nonce_size, heap, dev_id) }
    }
    #[cfg(not(rng_new_ex))]
    {
        if dev_id != sys::INVALID_DEVID {
            return sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG;
        }
        *rng = unsafe { sys::wc_rng_new(nonce, nonce_size, heap) };
        if rng.is_null() {
            sys::wolfCrypt_ErrorCodes_RNG_FAILURE_E
        } else {
            0
        }
    }
}

impl Drop for RNG {
    /// Safely free the underlying wolfSSL RNG context.
    ///
    /// This calls the `wc_rng_free` wolfssl library function, which frees the
    /// C-heap-allocated `WC_RNG` object.
    ///
    /// The Rust Drop trait guarantees that this method is called when the RNG
    /// struct goes out of scope, automatically cleaning up resources and
    /// preventing memory leaks.
    fn drop(&mut self) {
        unsafe { sys::wc_rng_free(self.wc_rng); }
    }
}
