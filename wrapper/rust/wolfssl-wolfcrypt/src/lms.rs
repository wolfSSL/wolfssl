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
This module provides a Rust wrapper for the wolfCrypt library's LMS/HSS
(Leighton-Micali Signature / Hierarchical Signature System) post-quantum
hash-based signature functionality (RFC 8554).

The primary component is the [`Lms`] struct, which manages the lifecycle of
a wolfSSL `LmsKey` object. It ensures proper initialization and deallocation.

LMS/HSS signatures are controlled by three parameters:

| Parameter    | Valid Values          | Effect                          |
|--------------|-----------------------|---------------------------------|
| `levels`     | 1..8                  | Number of Merkle tree levels    |
| `height`     | 5, 10, 15, 20, 25     | Height of each Merkle tree      |
| `winternitz` | 1, 2, 4, 8            | Bits per Winternitz chain step  |

The total number of available signatures is `2^(levels * height)`.
Larger `winternitz` values reduce signature size at the cost of slower
key generation and signing.

Predefined parameter sets are available as `Lms::PARM_*` constants
(e.g., `Lms::PARM_L1_H5_W4`), or parameters can be set directly via
[`Lms::set_parameters()`].

Signing requires private key I/O callbacks to persist the evolving private
key state. Register callbacks with [`Lms::set_write_cb()`] and
[`Lms::set_read_cb()`] before calling [`Lms::make_key()`] or
[`Lms::reload()`]. These methods are absent when wolfCrypt is built with
`WOLFSSL_LMS_VERIFY_ONLY`.

# Examples

```rust,no_run
#[cfg(all(lms, lms_make_key, random))]
{
use wolfssl_wolfcrypt::random::RNG;
use wolfssl_wolfcrypt::lms::Lms;
use wolfssl_wolfcrypt::sys;

let mut rng = RNG::new().expect("RNG creation failed");
let mut key = Lms::new().expect("Lms::new() failed");

// Use a small, fast parameter set for demonstration.
key.set_parm(Lms::PARM_L1_H5_W8).expect("set_parm failed");

// The private key I/O callbacks must be registered before making a key.
// (Omitted here for brevity; see set_write_cb / set_read_cb.)

let sig_len = key.get_sig_len().expect("get_sig_len failed");
let pub_len = key.get_pub_len().expect("get_pub_len failed");
let mut sig = vec![0u8; sig_len];
let mut pub_buf = vec![0u8; pub_len];

key.make_key(&mut rng).expect("make_key failed");
key.sign(b"hello", &mut sig).expect("sign failed");
key.export_pub_raw(&mut pub_buf).expect("export_pub_raw failed");

let mut vkey = Lms::new().expect("Lms::new() for verify failed");
vkey.set_parm(Lms::PARM_L1_H5_W8).expect("set_parm failed");
vkey.import_pub_raw(&pub_buf).expect("import_pub_raw failed");
vkey.verify(&sig, b"hello").expect("verify failed");
}
```
*/

#![cfg(lms)]

use crate::sys;
use core::mem::MaybeUninit;
#[cfg(all(lms_make_key, random))]
use crate::random::RNG;

/// Rust wrapper for a wolfSSL `LmsKey` object (LMS/HSS, RFC 8554).
///
/// Manages the lifecycle of the underlying key, including initialization and
/// deallocation via the [`Drop`] trait.
///
/// An instance is created with [`Lms::new()`] or [`Lms::new_ex()`].
/// Parameters must be set with [`Lms::set_parm()`] or
/// [`Lms::set_parameters()`] before generating or importing a key.
///
/// When `WOLFSSL_LMS_VERIFY_ONLY` is **not** set, private-key callbacks must
/// be registered (see [`Lms::set_write_cb()`] and [`Lms::set_read_cb()`])
/// before calling [`Lms::make_key()`] or [`Lms::reload()`].
pub struct Lms {
    ws_key: sys::LmsKey,
}

#[cfg(lms_sha256_256)]
impl Lms {
    pub const PARM_NONE: u32 = sys::wc_LmsParm_WC_LMS_PARM_NONE;
    pub const PARM_L1_H5_W1: u32 = sys::wc_LmsParm_WC_LMS_PARM_L1_H5_W1;
    pub const PARM_L1_H5_W2: u32 = sys::wc_LmsParm_WC_LMS_PARM_L1_H5_W2;
    pub const PARM_L1_H5_W4: u32 = sys::wc_LmsParm_WC_LMS_PARM_L1_H5_W4;
    pub const PARM_L1_H5_W8: u32 = sys::wc_LmsParm_WC_LMS_PARM_L1_H5_W8;
    pub const PARM_L1_H10_W2: u32 = sys::wc_LmsParm_WC_LMS_PARM_L1_H10_W2;
    pub const PARM_L1_H10_W4: u32 = sys::wc_LmsParm_WC_LMS_PARM_L1_H10_W4;
    pub const PARM_L1_H10_W8: u32 = sys::wc_LmsParm_WC_LMS_PARM_L1_H10_W8;
    pub const PARM_L1_H15_W2: u32 = sys::wc_LmsParm_WC_LMS_PARM_L1_H15_W2;
    pub const PARM_L1_H15_W4: u32 = sys::wc_LmsParm_WC_LMS_PARM_L1_H15_W4;
    pub const PARM_L1_H15_W8: u32 = sys::wc_LmsParm_WC_LMS_PARM_L1_H15_W8;
    pub const PARM_L1_H20_W2: u32 = sys::wc_LmsParm_WC_LMS_PARM_L1_H20_W2;
    pub const PARM_L1_H20_W4: u32 = sys::wc_LmsParm_WC_LMS_PARM_L1_H20_W4;
    pub const PARM_L1_H20_W8: u32 = sys::wc_LmsParm_WC_LMS_PARM_L1_H20_W8;
    pub const PARM_L2_H5_W2: u32 = sys::wc_LmsParm_WC_LMS_PARM_L2_H5_W2;
    pub const PARM_L2_H5_W4: u32 = sys::wc_LmsParm_WC_LMS_PARM_L2_H5_W4;
    pub const PARM_L2_H5_W8: u32 = sys::wc_LmsParm_WC_LMS_PARM_L2_H5_W8;
    pub const PARM_L2_H10_W2: u32 = sys::wc_LmsParm_WC_LMS_PARM_L2_H10_W2;
    pub const PARM_L2_H10_W4: u32 = sys::wc_LmsParm_WC_LMS_PARM_L2_H10_W4;
    pub const PARM_L2_H10_W8: u32 = sys::wc_LmsParm_WC_LMS_PARM_L2_H10_W8;
    pub const PARM_L2_H15_W2: u32 = sys::wc_LmsParm_WC_LMS_PARM_L2_H15_W2;
    pub const PARM_L2_H15_W4: u32 = sys::wc_LmsParm_WC_LMS_PARM_L2_H15_W4;
    pub const PARM_L2_H15_W8: u32 = sys::wc_LmsParm_WC_LMS_PARM_L2_H15_W8;
    pub const PARM_L2_H20_W2: u32 = sys::wc_LmsParm_WC_LMS_PARM_L2_H20_W2;
    pub const PARM_L2_H20_W4: u32 = sys::wc_LmsParm_WC_LMS_PARM_L2_H20_W4;
    pub const PARM_L2_H20_W8: u32 = sys::wc_LmsParm_WC_LMS_PARM_L2_H20_W8;
    pub const PARM_L3_H5_W2: u32 = sys::wc_LmsParm_WC_LMS_PARM_L3_H5_W2;
    pub const PARM_L3_H5_W4: u32 = sys::wc_LmsParm_WC_LMS_PARM_L3_H5_W4;
    pub const PARM_L3_H5_W8: u32 = sys::wc_LmsParm_WC_LMS_PARM_L3_H5_W8;
    pub const PARM_L3_H10_W4: u32 = sys::wc_LmsParm_WC_LMS_PARM_L3_H10_W4;
    pub const PARM_L3_H10_W8: u32 = sys::wc_LmsParm_WC_LMS_PARM_L3_H10_W8;
    pub const PARM_L4_H5_W2: u32 = sys::wc_LmsParm_WC_LMS_PARM_L4_H5_W2;
    pub const PARM_L4_H5_W4: u32 = sys::wc_LmsParm_WC_LMS_PARM_L4_H5_W4;
    pub const PARM_L4_H5_W8: u32 = sys::wc_LmsParm_WC_LMS_PARM_L4_H5_W8;
    pub const PARM_L4_H10_W4: u32 = sys::wc_LmsParm_WC_LMS_PARM_L4_H10_W4;
    pub const PARM_L4_H10_W8: u32 = sys::wc_LmsParm_WC_LMS_PARM_L4_H10_W8;
}

#[cfg(lms_sha256_192)]
impl Lms {
    pub const PARM_SHA256_192_L1_H5_W1 : u32 = sys::wc_LmsParm_WC_LMS_PARM_SHA256_192_L1_H5_W1;
    pub const PARM_SHA256_192_L1_H5_W2 : u32 = sys::wc_LmsParm_WC_LMS_PARM_SHA256_192_L1_H5_W2;
    pub const PARM_SHA256_192_L1_H5_W4 : u32 = sys::wc_LmsParm_WC_LMS_PARM_SHA256_192_L1_H5_W4;
    pub const PARM_SHA256_192_L1_H5_W8 : u32 = sys::wc_LmsParm_WC_LMS_PARM_SHA256_192_L1_H5_W8;
    pub const PARM_SHA256_192_L1_H10_W2: u32 = sys::wc_LmsParm_WC_LMS_PARM_SHA256_192_L1_H10_W2;
    pub const PARM_SHA256_192_L1_H10_W4: u32 = sys::wc_LmsParm_WC_LMS_PARM_SHA256_192_L1_H10_W4;
    pub const PARM_SHA256_192_L1_H10_W8: u32 = sys::wc_LmsParm_WC_LMS_PARM_SHA256_192_L1_H10_W8;
    pub const PARM_SHA256_192_L1_H15_W2: u32 = sys::wc_LmsParm_WC_LMS_PARM_SHA256_192_L1_H15_W2;
    pub const PARM_SHA256_192_L1_H15_W4: u32 = sys::wc_LmsParm_WC_LMS_PARM_SHA256_192_L1_H15_W4;
    pub const PARM_SHA256_192_L1_H20_W2: u32 = sys::wc_LmsParm_WC_LMS_PARM_SHA256_192_L1_H20_W2;
    pub const PARM_SHA256_192_L1_H20_W4: u32 = sys::wc_LmsParm_WC_LMS_PARM_SHA256_192_L1_H20_W4;
    pub const PARM_SHA256_192_L1_H20_W8: u32 = sys::wc_LmsParm_WC_LMS_PARM_SHA256_192_L1_H20_W8;
    pub const PARM_SHA256_192_L2_H10_W2: u32 = sys::wc_LmsParm_WC_LMS_PARM_SHA256_192_L2_H10_W2;
    pub const PARM_SHA256_192_L2_H10_W4: u32 = sys::wc_LmsParm_WC_LMS_PARM_SHA256_192_L2_H10_W4;
    pub const PARM_SHA256_192_L2_H10_W8: u32 = sys::wc_LmsParm_WC_LMS_PARM_SHA256_192_L2_H10_W8;
    pub const PARM_SHA256_192_L3_H5_W2 : u32 = sys::wc_LmsParm_WC_LMS_PARM_SHA256_192_L3_H5_W2;
    pub const PARM_SHA256_192_L3_H5_W4 : u32 = sys::wc_LmsParm_WC_LMS_PARM_SHA256_192_L3_H5_W4;
    pub const PARM_SHA256_192_L3_H5_W8 : u32 = sys::wc_LmsParm_WC_LMS_PARM_SHA256_192_L3_H5_W8;
    pub const PARM_SHA256_192_L3_H10_W4: u32 = sys::wc_LmsParm_WC_LMS_PARM_SHA256_192_L3_H10_W4;
    pub const PARM_SHA256_192_L4_H5_W8 : u32 = sys::wc_LmsParm_WC_LMS_PARM_SHA256_192_L4_H5_W8;
}

impl Lms {
    /// Length of the LMS Key ID (`WC_LMS_I_LEN` = 16 bytes).
    pub const KEY_ID_LEN: usize = sys::WC_LMS_I_LEN as usize;

    /// Create and initialize a new `Lms` key instance.
    ///
    /// # Returns
    ///
    /// Returns either Ok(Lms) containing the key instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(lms)]
    /// {
    /// use wolfssl_wolfcrypt::lms::Lms;
    /// let key = Lms::new().expect("Error with Lms::new()");
    /// }
    /// ```
    pub fn new() -> Result<Self, i32> {
        Self::new_ex(None, None)
    }

    /// Create and initialize a new `Lms` key instance with optional heap hint
    /// and device ID.
    ///
    /// # Parameters
    ///
    /// * `heap`: Optional heap hint.
    /// * `dev_id`: Optional device ID for crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(Lms) containing the key instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(lms)]
    /// {
    /// use wolfssl_wolfcrypt::lms::Lms;
    /// let key = Lms::new_ex(None, None).expect("Error with Lms::new_ex()");
    /// }
    /// ```
    pub fn new_ex(
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
        let mut ws_key: MaybeUninit<sys::LmsKey> = MaybeUninit::uninit();
        let rc = unsafe { sys::wc_LmsKey_Init(ws_key.as_mut_ptr(), heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        let ws_key = unsafe { ws_key.assume_init() };
        let lms = Lms { ws_key };
        Ok(lms)
    }

    /// Set parameters using a predefined `wc_LmsParm` parameter set.
    ///
    /// Use `Lms::PARM_*` constants for the `parm` value (e.g.,
    /// `Lms::PARM_L1_H5_W8`).
    ///
    /// # Parameters
    ///
    /// * `parm`: A `Lms::PARM_*` value identifying the parameter set.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(lms)]
    /// {
    /// use wolfssl_wolfcrypt::lms::Lms;
    /// let mut key = Lms::new().expect("Error with Lms::new()");
    /// key.set_parm(Lms::PARM_L1_H5_W8).expect("Error with set_parm()");
    /// }
    /// ```
    pub fn set_parm(&mut self, parm: u32) -> Result<(), i32> {
        let rc = unsafe { sys::wc_LmsKey_SetLmsParm(&mut self.ws_key, parm) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Set LMS/HSS parameters directly by levels, height, and Winternitz factor.
    ///
    /// # Parameters
    ///
    /// * `levels`: Number of Merkle tree levels (1..8).
    /// * `height`: Height of each Merkle tree (5, 10, 15, 20, or 25).
    /// * `winternitz`: Winternitz factor (1, 2, 4, or 8).
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(lms)]
    /// {
    /// use wolfssl_wolfcrypt::lms::Lms;
    /// let mut key = Lms::new().expect("Error with Lms::new()");
    /// key.set_parameters(1, 5, 8).expect("Error with set_parameters()");
    /// }
    /// ```
    pub fn set_parameters(&mut self, levels: i32, height: i32, winternitz: i32) -> Result<(), i32> {
        let rc = unsafe {
            sys::wc_LmsKey_SetParameters(&mut self.ws_key, levels, height, winternitz)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Get the current LMS/HSS parameter values.
    ///
    /// # Returns
    ///
    /// Returns either Ok((levels, height, winternitz)) on success or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(lms)]
    /// {
    /// use wolfssl_wolfcrypt::lms::Lms;
    /// let mut key = Lms::new().expect("Error with Lms::new()");
    /// key.set_parameters(1, 5, 8).expect("Error with set_parameters()");
    /// let (levels, height, winternitz) = key.get_parameters()
    ///     .expect("Error with get_parameters()");
    /// assert_eq!((levels, height, winternitz), (1, 5, 8));
    /// }
    /// ```
    pub fn get_parameters(&self) -> Result<(i32, i32, i32), i32> {
        let mut levels = 0i32;
        let mut height = 0i32;
        let mut winternitz = 0i32;
        let rc = unsafe {
            sys::wc_LmsKey_GetParameters(
                &self.ws_key,
                &mut levels,
                &mut height,
                &mut winternitz,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok((levels, height, winternitz))
    }

    /// Register a callback to write (persist) the private key.
    ///
    /// The callback is called by [`Lms::make_key()`] and [`Lms::sign()`]
    /// whenever the private key state must be saved to non-volatile storage.
    ///
    /// # Parameters
    ///
    /// * `write_cb`: Callback function of type
    ///   `wc_lms_write_private_key_cb`.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    #[cfg(lms_make_key)]
    pub fn set_write_cb(&mut self, write_cb: sys::wc_lms_write_private_key_cb) -> Result<(), i32> {
        let rc = unsafe { sys::wc_LmsKey_SetWriteCb(&mut self.ws_key, write_cb) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Register a callback to read (restore) the private key.
    ///
    /// The callback is called by [`Lms::reload()`] and [`Lms::sign()`]
    /// whenever the private key must be read from non-volatile storage.
    ///
    /// # Parameters
    ///
    /// * `read_cb`: Callback function of type `wc_lms_read_private_key_cb`.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    #[cfg(lms_make_key)]
    pub fn set_read_cb(&mut self, read_cb: sys::wc_lms_read_private_key_cb) -> Result<(), i32> {
        let rc = unsafe { sys::wc_LmsKey_SetReadCb(&mut self.ws_key, read_cb) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Set the context pointer passed to the private key I/O callbacks.
    ///
    /// # Parameters
    ///
    /// * `context`: An arbitrary pointer passed unchanged to the write and
    ///   read callbacks.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Safety
    ///
    /// The caller must ensure `context` remains valid for as long as the key
    /// may invoke the registered write or read callbacks (i.e., across calls
    /// to [`Lms::make_key()`], [`Lms::reload()`], and [`Lms::sign()`]).
    #[cfg(lms_make_key)]
    pub unsafe fn set_context(&mut self, context: *mut core::ffi::c_void) -> Result<(), i32> {
        let rc = unsafe { sys::wc_LmsKey_SetContext(&mut self.ws_key, context) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Generate a new LMS/HSS key pair using an RNG.
    ///
    /// Parameters must be set with [`Lms::set_parm()`] or
    /// [`Lms::set_parameters()`] and private key callbacks must be
    /// registered with [`Lms::set_write_cb()`] and [`Lms::set_read_cb()`]
    /// before calling this function.
    ///
    /// # Parameters
    ///
    /// * `rng`: `RNG` instance to use for random number generation.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(lms, lms_make_key, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::lms::Lms;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = Lms::new().expect("Error with Lms::new()");
    /// key.set_parm(Lms::PARM_L1_H5_W8).expect("Error with set_parm()");
    /// // Register write/read callbacks before calling make_key().
    /// // key.make_key(&mut rng).expect("Error with make_key()");
    /// }
    /// ```
    #[cfg(all(lms_make_key, random))]
    pub fn make_key(&mut self, rng: &mut RNG) -> Result<(), i32> {
        let rc = unsafe { sys::wc_LmsKey_MakeKey(&mut self.ws_key, &mut rng.wc_rng) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Reload a previously generated LMS/HSS key from non-volatile storage.
    ///
    /// The read callback registered with [`Lms::set_read_cb()`] is called
    /// to restore the private key state. Parameters must have been set and
    /// the read callback registered before calling this function.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    #[cfg(lms_make_key)]
    pub fn reload(&mut self) -> Result<(), i32> {
        let rc = unsafe { sys::wc_LmsKey_Reload(&mut self.ws_key) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Get the encoded private key length in bytes.
    ///
    /// # Returns
    ///
    /// Returns either Ok(length) on success or Err(e) containing the wolfSSL
    /// library error code value.
    #[cfg(lms_make_key)]
    pub fn get_priv_len(&self) -> Result<usize, i32> {
        let mut len = 0u32;
        let rc = unsafe { sys::wc_LmsKey_GetPrivLen(&self.ws_key, &mut len) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(len as usize)
    }

    /// Sign a message with this LMS/HSS private key.
    ///
    /// The `sig` buffer must be at least `get_sig_len()` bytes. The write
    /// callback is invoked to persist the updated private key state after
    /// signing.
    ///
    /// # Parameters
    ///
    /// * `msg`: Message bytes to sign.
    /// * `sig`: Output buffer for the signature. Must be at least
    ///   `get_sig_len()` bytes.
    ///
    /// # Returns
    ///
    /// Returns either Ok(sig_len) containing the number of bytes written to
    /// `sig` on success, or Err(e) containing the wolfSSL library error code.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(lms, lms_make_key, random))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::lms::Lms;
    /// let mut rng = RNG::new().expect("Error creating RNG");
    /// let mut key = Lms::new().expect("Error with Lms::new()");
    /// key.set_parm(Lms::PARM_L1_H5_W8).expect("Error with set_parm()");
    /// // Register callbacks and make key first (omitted for brevity).
    /// // let sig_len = key.get_sig_len().unwrap();
    /// // let mut sig = vec![0u8; sig_len];
    /// // let written = key.sign(b"hello", &mut sig).expect("Error with sign()");
    /// // assert_eq!(written, sig_len);
    /// }
    /// ```
    #[cfg(lms_make_key)]
    pub fn sign(&mut self, msg: &[u8], sig: &mut [u8]) -> Result<usize, i32> {
        // wc_LmsKey_Sign treats sigSz as write-only: it writes sig_len bytes
        // to sig without reading or checking *sigSz beforehand. Validate here.
        let expected_sig_len = self.get_sig_len()?;
        if sig.len() < expected_sig_len {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let mut sig_sz = sig.len() as u32;
        let rc = unsafe {
            sys::wc_LmsKey_Sign(
                &mut self.ws_key,
                sig.as_mut_ptr(),
                &mut sig_sz,
                msg.as_ptr(),
                msg.len() as core::ffi::c_int,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(sig_sz as usize)
    }

    /// Return the number of signatures remaining for this key.
    ///
    /// Returns `Ok(true)` if at least one signature remains, `Ok(false)` if
    /// exhausted, or `Err(e)` on error. This is a conservative check only.
    ///
    /// # Returns
    ///
    /// Returns either Ok(count) on success or Err(e) containing the wolfSSL
    /// library error code value.
    #[cfg(lms_make_key)]
    pub fn sigs_left(&mut self) -> Result<bool, i32> {
        let rc = unsafe { sys::wc_LmsKey_SigsLeft(&mut self.ws_key) };
        if rc < 0 {
            return Err(rc);
        }
        Ok(rc != 0)
    }

    /// Get the signature length in bytes for this key's parameters.
    ///
    /// # Returns
    ///
    /// Returns either Ok(length) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(lms)]
    /// {
    /// use wolfssl_wolfcrypt::lms::Lms;
    /// let mut key = Lms::new().expect("Error with Lms::new()");
    /// key.set_parm(Lms::PARM_L1_H5_W8).expect("Error with set_parm()");
    /// let sig_len = key.get_sig_len().expect("Error with get_sig_len()");
    /// assert!(sig_len > 0);
    /// }
    /// ```
    pub fn get_sig_len(&self) -> Result<usize, i32> {
        let mut len = 0u32;
        let rc = unsafe { sys::wc_LmsKey_GetSigLen(&self.ws_key, &mut len) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(len as usize)
    }

    /// Get the public key length in bytes for this key's parameters.
    ///
    /// # Returns
    ///
    /// Returns either Ok(length) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(lms)]
    /// {
    /// use wolfssl_wolfcrypt::lms::Lms;
    /// let mut key = Lms::new().expect("Error with Lms::new()");
    /// key.set_parm(Lms::PARM_L1_H5_W8).expect("Error with set_parm()");
    /// let pub_len = key.get_pub_len().expect("Error with get_pub_len()");
    /// assert!(pub_len > 0);
    /// }
    /// ```
    pub fn get_pub_len(&self) -> Result<usize, i32> {
        let mut len = 0u32;
        let rc = unsafe { sys::wc_LmsKey_GetPubLen(&self.ws_key, &mut len) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(len as usize)
    }

    /// Copy the public key from `src` into this key instance.
    ///
    /// Both keys must have matching parameters. After a successful call,
    /// this key can be used for verification.
    ///
    /// # Parameters
    ///
    /// * `src`: Source key to copy the public portion from.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    pub fn export_pub_from(&mut self, src: &Lms) -> Result<(), i32> {
        let rc = unsafe {
            sys::wc_LmsKey_ExportPub(&mut self.ws_key, &src.ws_key)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Export the raw public key bytes into `out`.
    ///
    /// The `out` buffer must be at least `get_pub_len()` bytes.
    ///
    /// # Parameters
    ///
    /// * `out`: Output buffer for the raw public key. Must be at least
    ///   `get_pub_len()` bytes.
    ///
    /// # Returns
    ///
    /// Returns either Ok(length) containing the number of bytes written on
    /// success, or Err(e) containing the wolfSSL library error code.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(lms, lms_make_key, random))]
    /// {
    /// use wolfssl_wolfcrypt::lms::Lms;
    /// let mut key = Lms::new().expect("Error with Lms::new()");
    /// key.set_parm(Lms::PARM_L1_H5_W8).expect("Error with set_parm()");
    /// // After make_key():
    /// // let pub_len = key.get_pub_len().unwrap();
    /// // let mut pub_buf = vec![0u8; pub_len];
    /// // let written = key.export_pub_raw(&mut pub_buf).unwrap();
    /// }
    /// ```
    pub fn export_pub_raw(&self, out: &mut [u8]) -> Result<usize, i32> {
        let mut out_len = out.len() as u32;
        let rc = unsafe {
            sys::wc_LmsKey_ExportPubRaw(&self.ws_key, out.as_mut_ptr(), &mut out_len)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(out_len as usize)
    }

    /// Import a raw public key from `data` into this key instance.
    ///
    /// Parameters **must** be set with [`Lms::set_parm()`] or
    /// [`Lms::set_parameters()`] before calling this function, and the
    /// length of `data` must match `get_pub_len()`. After a successful
    /// import the key can be used for verification.
    ///
    /// # Parameters
    ///
    /// * `data`: Buffer containing the raw public key bytes.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let mut key = Lms::new().expect("Error with Lms::new()");
    /// key.set_parm(Lms::PARM_L1_H5_W8).expect("set_parm failed");
    /// key.import_pub_raw(&pub_buf).expect("Error with import_pub_raw()");
    /// ```
    pub fn import_pub_raw(&mut self, data: &[u8]) -> Result<(), i32> {
        let rc = unsafe {
            sys::wc_LmsKey_ImportPubRaw(&mut self.ws_key, data.as_ptr(), data.len() as u32)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Verify an LMS/HSS signature over a message.
    ///
    /// The key must have a public key loaded (via [`Lms::make_key()`],
    /// [`Lms::reload()`], or [`Lms::import_pub_raw()`]).
    ///
    /// # Parameters
    ///
    /// * `sig`: Signature bytes to verify.
    /// * `msg`: Message bytes that were signed.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) if the signature is valid, or Err(e) containing
    /// the wolfSSL library error code value (including a verification failure
    /// code).
    pub fn verify(&mut self, sig: &[u8], msg: &[u8]) -> Result<(), i32> {
        // wc_lms.c validates sigSz, but ext_lms.c passes sigSz through to
        // hss_validate_signature without checking it. Validate here for both.
        let expected_sig_len = self.get_sig_len()?;
        if sig.len() != expected_sig_len {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let rc = unsafe {
            sys::wc_LmsKey_Verify(
                &mut self.ws_key,
                sig.as_ptr(),
                sig.len() as u32,
                msg.as_ptr(),
                msg.len() as core::ffi::c_int,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Get the Key ID (I value) for this LMS/HSS key.
    ///
    /// Returns a slice pointing into the key's internal storage.
    ///
    /// # Returns
    ///
    /// Returns either Ok(&[u8]) containing the key ID on success, or Err(e)
    /// containing the wolfSSL library error code value.
    pub fn get_kid(&mut self) -> Result<&[u8], i32> {
        let mut kid_ptr: *const u8 = core::ptr::null();
        let mut kid_sz: u32 = 0;
        let rc = unsafe {
            sys::wc_LmsKey_GetKid(&mut self.ws_key, &mut kid_ptr, &mut kid_sz)
        };
        if rc != 0 {
            return Err(rc);
        }
        let slice = unsafe { core::slice::from_raw_parts(kid_ptr, kid_sz as usize) };
        Ok(slice)
    }
}

impl Drop for Lms {
    /// Safely free the underlying wolfSSL LMS/HSS key context.
    ///
    /// This calls `wc_LmsKey_Free()`. The Rust Drop trait guarantees this
    /// is called when the `Lms` struct goes out of scope.
    fn drop(&mut self) {
        unsafe {
            sys::wc_LmsKey_Free(&mut self.ws_key);
        }
    }
}
