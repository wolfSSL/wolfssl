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
This module provides a Rust wrapper for the wolfCrypt library's Secure Hash
Algorithm (SHA) functionality.
*/

use crate::sys;
use std::mem::MaybeUninit;

/// Context for SHA-1 computation.
#[cfg(sha)]
pub struct SHA {
    wc_sha: sys::wc_Sha,
}

#[cfg(sha)]
impl SHA {
    /// SHA-1 digest size in bytes.
    pub const DIGEST_SIZE: usize = sys::WC_SHA_DIGEST_SIZE as usize;

    /// Build a new SHA instance.
    ///
    /// # Returns
    ///
    /// Returns either Ok(sha) containing the SHA struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA;
    /// let sha = SHA::new().expect("Error with new()");
    /// ```
    pub fn new() -> Result<Self, i32> {
        Self::new_ex(None, None)
    }

    /// Build a new SHA instance with optional heap and device ID.
    ///
    /// # Parameters
    ///
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(sha) containing the SHA struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA;
    /// let sha = SHA::new_ex(None, None).expect("Error with new_ex()");
    /// ```
    pub fn new_ex(heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let mut wc_sha: MaybeUninit<sys::wc_Sha> = MaybeUninit::uninit();
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_InitSha_ex(wc_sha.as_mut_ptr(), heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        let wc_sha = unsafe { wc_sha.assume_init() };
        let sha = SHA { wc_sha };
        Ok(sha)
    }

    /// Reinitialize a SHA instance for a new hash calculation.
    ///
    /// This does not need to be called after `new()`, but should be called
    /// after a hash calculation to prepare for a new calculation.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA;
    /// let mut sha = SHA::new().expect("Error with new()");
    /// sha.init().expect("Error with init()");
    /// ```
    pub fn init(&mut self) -> Result<(), i32> {
        self.init_ex(None, None)
    }

    /// Reinitialize a SHA instance for a new hash calculation with optional
    /// heap and device ID.
    ///
    /// This does not need to be called after `new()`, but should be called
    /// after a hash calculation to prepare for a new calculation.
    ///
    /// # Parameters
    ///
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
    /// use wolfssl::wolfcrypt::sha::SHA;
    /// let mut sha = SHA::new().expect("Error with new()");
    /// sha.init_ex(None, None).expect("Error with init_ex()");
    /// ```
    pub fn init_ex(&mut self, heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<(), i32> {
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_InitSha_ex(&mut self.wc_sha, heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Update the SHA calculation by feeding in more input data.
    ///
    /// # Parameters
    ///
    /// * `data`: Input data.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA;
    /// let mut sha = SHA::new().expect("Error with new()");
    /// sha.update(b"input").expect("Error with update()");
    /// ```
    pub fn update(&mut self, data: &[u8]) -> Result<(), i32> {
        let data_size = data.len() as u32;
        let rc = unsafe {
            sys::wc_ShaUpdate(&mut self.wc_sha, data.as_ptr(), data_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Finalize the SHA calculation and retrieve the calculated hash.
    ///
    /// # Parameters
    ///
    /// * `hash`: Buffer in which to store the calculated hash. The length
    ///   should be SHA::DIGEST_SIZE.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA;
    /// let mut sha = SHA::new().expect("Error with new()");
    /// sha.update(b"input").expect("Error with update()");
    /// let mut hash = [0u8; SHA::DIGEST_SIZE];
    /// sha.finalize(&mut hash).expect("Error with finalize()");
    /// ```
    pub fn finalize(&mut self, hash: &mut [u8]) -> Result<(), i32> {
        if hash.len() != Self::DIGEST_SIZE {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let rc = unsafe {
            sys::wc_ShaFinal(&mut self.wc_sha, hash.as_mut_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}

#[cfg(sha)]
impl Drop for SHA {
    /// Safely free the underlying wolfSSL SHA context.
    ///
    /// This calls the `wc_ShaFree` wolfssl library function.
    ///
    /// The Rust Drop trait guarantees that this method is called when the SHA
    /// struct goes out of scope, automatically cleaning up resources and
    /// preventing memory leaks.
    fn drop(&mut self) {
        unsafe { sys::wc_ShaFree(&mut self.wc_sha); }
    }
}

/// Context for SHA-224 (SHA-2) computation.
#[cfg(sha256)]
pub struct SHA224 {
    wc_sha224: sys::wc_Sha224,
}

#[cfg(sha256)]
impl SHA224 {
    /// SHA-224 digest size in bytes.
    pub const DIGEST_SIZE: usize = sys::WC_SHA224_DIGEST_SIZE as usize;

    /// Build a new SHA224 instance.
    ///
    /// # Returns
    ///
    /// Returns either Ok(sha) containing the SHA224 struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA224;
    /// let sha = SHA224::new().expect("Error with new()");
    /// ```
    pub fn new() -> Result<Self, i32> {
        Self::new_ex(None, None)
    }

    /// Build a new SHA224 instance with optional heap and device ID.
    ///
    /// # Parameters
    ///
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(sha) containing the SHA224 struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA224;
    /// let sha = SHA224::new_ex(None, None).expect("Error with new_ex()");
    /// ```
    pub fn new_ex(heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let mut wc_sha224: MaybeUninit<sys::wc_Sha224> = MaybeUninit::uninit();
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_InitSha224_ex(wc_sha224.as_mut_ptr(), heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        let wc_sha224 = unsafe { wc_sha224.assume_init() };
        let sha224 = SHA224 { wc_sha224 };
        Ok(sha224)
    }

    /// Reinitialize a SHA224 instance for a new hash calculation.
    ///
    /// This does not need to be called after `new()`, but should be called
    /// after a hash calculation to prepare for a new calculation.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA224;
    /// let mut sha = SHA224::new().expect("Error with new()");
    /// sha.init().expect("Error with init()");
    /// ```
    pub fn init(&mut self) -> Result<(), i32> {
        self.init_ex(None, None)
    }

    /// Reinitialize a SHA224 instance for a new hash calculation with optional
    /// heap and device ID.
    ///
    /// This does not need to be called after `new()`, but should be called
    /// after a hash calculation to prepare for a new calculation.
    ///
    /// # Parameters
    ///
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
    /// use wolfssl::wolfcrypt::sha::SHA224;
    /// let mut sha = SHA224::new().expect("Error with new()");
    /// sha.init_ex(None, None).expect("Error with init_ex()");
    /// ```
    pub fn init_ex(&mut self, heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<(), i32> {
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_InitSha224_ex(&mut self.wc_sha224, heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Update the SHA-224 calculation by feeding in more input data.
    ///
    /// # Parameters
    ///
    /// * `data`: Input data.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA224;
    /// let mut sha = SHA224::new().expect("Error with new()");
    /// sha.update(b"input").expect("Error with update()");
    /// ```
    pub fn update(&mut self, data: &[u8]) -> Result<(), i32> {
        let data_size = data.len() as u32;
        let rc = unsafe {
            sys::wc_Sha224Update(&mut self.wc_sha224, data.as_ptr(), data_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Finalize the SHA-224 calculation and retrieve the calculated hash.
    ///
    /// # Parameters
    ///
    /// * `hash`: Buffer in which to store the calculated hash. The length
    ///   should be SHA224::DIGEST_SIZE.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA224;
    /// let mut sha = SHA224::new().expect("Error with new()");
    /// sha.update(b"input").expect("Error with update()");
    /// let mut hash = [0u8; SHA224::DIGEST_SIZE];
    /// sha.finalize(&mut hash).expect("Error with finalize()");
    /// ```
    pub fn finalize(&mut self, hash: &mut [u8]) -> Result<(), i32> {
        if hash.len() != Self::DIGEST_SIZE {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let rc = unsafe {
            sys::wc_Sha224Final(&mut self.wc_sha224, hash.as_mut_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}

#[cfg(sha256)]
impl Drop for SHA224 {
    /// Safely free the underlying wolfSSL SHA224 context.
    ///
    /// This calls the `wc_Sha224Free` wolfssl library function.
    ///
    /// The Rust Drop trait guarantees that this method is called when the
    /// SHA224 struct goes out of scope, automatically cleaning up resources
    /// and preventing memory leaks.
    fn drop(&mut self) {
        unsafe { sys::wc_Sha224Free(&mut self.wc_sha224); }
    }
}

/// Context for SHA-256 (SHA-2) computation.
#[cfg(sha256)]
pub struct SHA256 {
    wc_sha256: sys::wc_Sha256,
}

#[cfg(sha256)]
impl SHA256 {
    /// SHA-256 digest size in bytes.
    pub const DIGEST_SIZE: usize = sys::WC_SHA256_DIGEST_SIZE as usize;

    /// Build a new SHA256 instance.
    ///
    /// # Returns
    ///
    /// Returns either Ok(sha) containing the SHA256 struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA256;
    /// let sha = SHA256::new().expect("Error with new()");
    /// ```
    pub fn new() -> Result<Self, i32> {
        Self::new_ex(None, None)
    }

    /// Build a new SHA256 instance with optional heap and device ID.
    ///
    /// # Parameters
    ///
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(sha) containing the SHA256 struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA256;
    /// let sha = SHA256::new_ex(None, None).expect("Error with new_ex()");
    /// ```
    pub fn new_ex(heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let mut wc_sha256: MaybeUninit<sys::wc_Sha256> = MaybeUninit::uninit();
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_InitSha256_ex(wc_sha256.as_mut_ptr(), heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        let wc_sha256 = unsafe { wc_sha256.assume_init() };
        let sha256 = SHA256 { wc_sha256 };
        Ok(sha256)
    }

    /// Reinitialize a SHA256 instance for a new hash calculation.
    ///
    /// This does not need to be called after `new()`, but should be called
    /// after a hash calculation to prepare for a new calculation.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA256;
    /// let mut sha = SHA256::new().expect("Error with new()");
    /// sha.init().expect("Error with init()");
    /// ```
    pub fn init(&mut self) -> Result<(), i32> {
        self.init_ex(None, None)
    }

    /// Reinitialize a SHA256 instance for a new hash calculation with optional
    /// heap and device ID.
    ///
    /// This does not need to be called after `new()`, but should be called
    /// after a hash calculation to prepare for a new calculation.
    ///
    /// # Parameters
    ///
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
    /// use wolfssl::wolfcrypt::sha::SHA256;
    /// let mut sha = SHA256::new().expect("Error with new()");
    /// sha.init_ex(None, None).expect("Error with init_ex()");
    /// ```
    pub fn init_ex(&mut self, heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<(), i32> {
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_InitSha256_ex(&mut self.wc_sha256, heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Update the SHA-256 calculation by feeding in more input data.
    ///
    /// # Parameters
    ///
    /// * `data`: Input data.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA256;
    /// let mut sha = SHA256::new().expect("Error with new()");
    /// sha.update(b"input").expect("Error with update()");
    /// ```
    pub fn update(&mut self, data: &[u8]) -> Result<(), i32> {
        let data_size = data.len() as u32;
        let rc = unsafe {
            sys::wc_Sha256Update(&mut self.wc_sha256, data.as_ptr(), data_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Finalize the SHA-256 calculation and retrieve the calculated hash.
    ///
    /// # Parameters
    ///
    /// * `hash`: Buffer in which to store the calculated hash. The length
    ///   should be SHA256::DIGEST_SIZE.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA256;
    /// let mut sha = SHA256::new().expect("Error with new()");
    /// sha.update(b"input").expect("Error with update()");
    /// let mut hash = [0u8; SHA256::DIGEST_SIZE];
    /// sha.finalize(&mut hash).expect("Error with finalize()");
    /// ```
    pub fn finalize(&mut self, hash: &mut [u8]) -> Result<(), i32> {
        if hash.len() != Self::DIGEST_SIZE {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let rc = unsafe {
            sys::wc_Sha256Final(&mut self.wc_sha256, hash.as_mut_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}

#[cfg(sha256)]
impl Drop for SHA256 {
    /// Safely free the underlying wolfSSL SHA256 context.
    ///
    /// This calls the `wc_Sha256Free` wolfssl library function.
    ///
    /// The Rust Drop trait guarantees that this method is called when the
    /// SHA256 struct goes out of scope, automatically cleaning up resources
    /// and preventing memory leaks.
    fn drop(&mut self) {
        unsafe { sys::wc_Sha256Free(&mut self.wc_sha256); }
    }
}

/// Context for SHA-384 (SHA-2) computation.
#[cfg(sha512)]
pub struct SHA384 {
    wc_sha384: sys::wc_Sha384,
}

#[cfg(sha512)]
impl SHA384 {
    /// SHA-384 digest size in bytes.
    pub const DIGEST_SIZE: usize = sys::WC_SHA384_DIGEST_SIZE as usize;

    /// Build a new SHA384 instance.
    ///
    /// # Returns
    ///
    /// Returns either Ok(sha) containing the SHA384 struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA384;
    /// let sha = SHA384::new().expect("Error with new()");
    /// ```
    pub fn new() -> Result<Self, i32> {
        Self::new_ex(None, None)
    }

    /// Build a new SHA384 instance with optional heap and device ID.
    ///
    /// # Parameters
    ///
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(sha) containing the SHA384 struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA384;
    /// let sha = SHA384::new_ex(None, None).expect("Error with new_ex()");
    /// ```
    pub fn new_ex(heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let mut wc_sha384: MaybeUninit<sys::wc_Sha384> = MaybeUninit::uninit();
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_InitSha384_ex(wc_sha384.as_mut_ptr(), heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        let wc_sha384 = unsafe { wc_sha384.assume_init() };
        let sha384 = SHA384 { wc_sha384 };
        Ok(sha384)
    }

    /// Reinitialize a SHA384 instance for a new hash calculation.
    ///
    /// This does not need to be called after `new()`, but should be called
    /// after a hash calculation to prepare for a new calculation.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA384;
    /// let mut sha = SHA384::new().expect("Error with new()");
    /// sha.init().expect("Error with init()");
    /// ```
    pub fn init(&mut self) -> Result<(), i32> {
        self.init_ex(None, None)
    }

    /// Reinitialize a SHA384 instance for a new hash calculation with optional
    /// heap and device ID.
    ///
    /// This does not need to be called after `new()`, but should be called
    /// after a hash calculation to prepare for a new calculation.
    ///
    /// # Parameters
    ///
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
    /// use wolfssl::wolfcrypt::sha::SHA384;
    /// let mut sha = SHA384::new().expect("Error with new()");
    /// sha.init_ex(None, None).expect("Error with init_ex()");
    /// ```
    pub fn init_ex(&mut self, heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<(), i32> {
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_InitSha384_ex(&mut self.wc_sha384, heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Update the SHA-384 calculation by feeding in more input data.
    ///
    /// # Parameters
    ///
    /// * `data`: Input data.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA384;
    /// let mut sha = SHA384::new().expect("Error with new()");
    /// sha.update(b"input").expect("Error with update()");
    /// ```
    pub fn update(&mut self, data: &[u8]) -> Result<(), i32> {
        let data_size = data.len() as u32;
        let rc = unsafe {
            sys::wc_Sha384Update(&mut self.wc_sha384, data.as_ptr(), data_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Finalize the SHA-384 calculation and retrieve the calculated hash.
    ///
    /// # Parameters
    ///
    /// * `hash`: Buffer in which to store the calculated hash. The length
    ///   should be SHA384::DIGEST_SIZE.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA384;
    /// let mut sha = SHA384::new().expect("Error with new()");
    /// sha.update(b"input").expect("Error with update()");
    /// let mut hash = [0u8; SHA384::DIGEST_SIZE];
    /// sha.finalize(&mut hash).expect("Error with finalize()");
    /// ```
    pub fn finalize(&mut self, hash: &mut [u8]) -> Result<(), i32> {
        if hash.len() != Self::DIGEST_SIZE {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let rc = unsafe {
            sys::wc_Sha384Final(&mut self.wc_sha384, hash.as_mut_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}

#[cfg(sha512)]
impl Drop for SHA384 {
    /// Safely free the underlying wolfSSL SHA384 context.
    ///
    /// This calls the `wc_Sha384Free` wolfssl library function.
    ///
    /// The Rust Drop trait guarantees that this method is called when the
    /// SHA384 struct goes out of scope, automatically cleaning up resources
    /// and preventing memory leaks.
    fn drop(&mut self) {
        unsafe { sys::wc_Sha384Free(&mut self.wc_sha384); }
    }
}

/// Context for SHA-512 (SHA-2) computation.
#[cfg(sha512)]
pub struct SHA512 {
    wc_sha512: sys::wc_Sha512,
}

#[cfg(sha512)]
impl SHA512 {
    /// SHA-512 digest size in bytes.
    pub const DIGEST_SIZE: usize = sys::WC_SHA512_DIGEST_SIZE as usize;

    /// Build a new SHA512 instance.
    ///
    /// # Returns
    ///
    /// Returns either Ok(sha) containing the SHA512 struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA512;
    /// let sha = SHA512::new().expect("Error with new()");
    /// ```
    pub fn new() -> Result<Self, i32> {
        Self::new_ex(None, None)
    }

    /// Build a new SHA512 instance with optional heap and device ID.
    ///
    /// # Parameters
    ///
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(sha) containing the SHA512 struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA512;
    /// let sha = SHA512::new_ex(None, None).expect("Error with new_ex()");
    /// ```
    pub fn new_ex(heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let mut wc_sha512: MaybeUninit<sys::wc_Sha512> = MaybeUninit::uninit();
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_InitSha512_ex(wc_sha512.as_mut_ptr(), heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        let wc_sha512 = unsafe { wc_sha512.assume_init() };
        let sha512 = SHA512 { wc_sha512 };
        Ok(sha512)
    }

    /// Reinitialize a SHA512 instance for a new hash calculation.
    ///
    /// This does not need to be called after `new()`, but should be called
    /// after a hash calculation to prepare for a new calculation.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA512;
    /// let mut sha = SHA512::new().expect("Error with new()");
    /// sha.init().expect("Error with init()");
    /// ```
    pub fn init(&mut self) -> Result<(), i32> {
        self.init_ex(None, None)
    }

    /// Reinitialize a SHA512 instance for a new hash calculation with optional
    /// heap and device ID.
    ///
    /// This does not need to be called after `new()`, but should be called
    /// after a hash calculation to prepare for a new calculation.
    ///
    /// # Parameters
    ///
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
    /// use wolfssl::wolfcrypt::sha::SHA512;
    /// let mut sha = SHA512::new().expect("Error with new()");
    /// sha.init_ex(None, None).expect("Error with init_ex()");
    /// ```
    pub fn init_ex(&mut self, heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<(), i32> {
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_InitSha512_ex(&mut self.wc_sha512, heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Update the SHA-512 calculation by feeding in more input data.
    ///
    /// # Parameters
    ///
    /// * `data`: Input data.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA512;
    /// let mut sha = SHA512::new().expect("Error with new()");
    /// sha.update(b"input").expect("Error with update()");
    /// ```
    pub fn update(&mut self, data: &[u8]) -> Result<(), i32> {
        let data_size = data.len() as u32;
        let rc = unsafe {
            sys::wc_Sha512Update(&mut self.wc_sha512, data.as_ptr(), data_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Finalize the SHA-512 calculation and retrieve the calculated hash.
    ///
    /// # Parameters
    ///
    /// * `hash`: Buffer in which to store the calculated hash. The length
    ///   should be SHA512::DIGEST_SIZE.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA512;
    /// let mut sha = SHA512::new().expect("Error with new()");
    /// sha.update(b"input").expect("Error with update()");
    /// let mut hash = [0u8; SHA512::DIGEST_SIZE];
    /// sha.finalize(&mut hash).expect("Error with finalize()");
    /// ```
    pub fn finalize(&mut self, hash: &mut [u8]) -> Result<(), i32> {
        if hash.len() != Self::DIGEST_SIZE {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let rc = unsafe {
            sys::wc_Sha512Final(&mut self.wc_sha512, hash.as_mut_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}

#[cfg(sha512)]
impl Drop for SHA512 {
    /// Safely free the underlying wolfSSL SHA512 context.
    ///
    /// This calls the `wc_Sha512Free` wolfssl library function.
    ///
    /// The Rust Drop trait guarantees that this method is called when the
    /// SHA512 struct goes out of scope, automatically cleaning up resources
    /// and preventing memory leaks.
    fn drop(&mut self) {
        unsafe { sys::wc_Sha512Free(&mut self.wc_sha512); }
    }
}

/// Context for SHA3-224 computation.
#[cfg(sha3)]
pub struct SHA3_224 {
    wc_sha3: sys::wc_Sha3,
}

#[cfg(sha3)]
impl SHA3_224 {
    /// SHA3-224 digest size in bytes.
    pub const DIGEST_SIZE: usize = sys::WC_SHA3_224_DIGEST_SIZE as usize;

    /// Build a new SHA3_224 instance.
    ///
    /// # Returns
    ///
    /// Returns either Ok(sha) containing the SHA3_224 struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA3_224;
    /// let sha = SHA3_224::new().expect("Error with new()");
    /// ```
    pub fn new() -> Result<Self, i32> {
        Self::new_ex(None, None)
    }

    /// Build a new SHA3_224 instance with optional heap and device ID.
    ///
    /// # Parameters
    ///
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(sha) containing the SHA3_224 struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA3_224;
    /// let sha = SHA3_224::new_ex(None, None).expect("Error with new_ex()");
    /// ```
    pub fn new_ex(heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let mut wc_sha3: MaybeUninit<sys::wc_Sha3> = MaybeUninit::uninit();
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_InitSha3_224(wc_sha3.as_mut_ptr(), heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        let wc_sha3 = unsafe { wc_sha3.assume_init() };
        let sha3_224 = SHA3_224 { wc_sha3 };
        Ok(sha3_224)
    }

    /// Reinitialize a SHA3_224 instance for a new hash calculation.
    ///
    /// This does not need to be called after `new()`, but should be called
    /// after a hash calculation to prepare for a new calculation.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA3_224;
    /// let mut sha = SHA3_224::new().expect("Error with new()");
    /// sha.init().expect("Error with init()");
    /// ```
    pub fn init(&mut self) -> Result<(), i32> {
        self.init_ex(None, None)
    }

    /// Reinitialize a SHA3_224 instance for a new hash calculation with
    /// optional heap and device ID.
    ///
    /// This does not need to be called after `new()`, but should be called
    /// after a hash calculation to prepare for a new calculation.
    ///
    /// # Parameters
    ///
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
    /// use wolfssl::wolfcrypt::sha::SHA3_224;
    /// let mut sha = SHA3_224::new().expect("Error with new()");
    /// sha.init_ex(None, None).expect("Error with init_ex()");
    /// ```
    pub fn init_ex(&mut self, heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<(), i32> {
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_InitSha3_224(&mut self.wc_sha3, heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Update the SHA3-224 calculation by feeding in more input data.
    ///
    /// # Parameters
    ///
    /// * `data`: Input data.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA3_224;
    /// let mut sha = SHA3_224::new().expect("Error with new()");
    /// sha.update(b"input").expect("Error with update()");
    /// ```
    pub fn update(&mut self, data: &[u8]) -> Result<(), i32> {
        let data_size = data.len() as u32;
        let rc = unsafe {
            sys::wc_Sha3_224_Update(&mut self.wc_sha3, data.as_ptr(), data_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Finalize the SHA3-224 calculation and retrieve the calculated hash.
    ///
    /// # Parameters
    ///
    /// * `hash`: Buffer in which to store the calculated hash. The length
    ///   should be SHA3_224::DIGEST_SIZE.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA3_224;
    /// let mut sha = SHA3_224::new().expect("Error with new()");
    /// sha.update(b"input").expect("Error with update()");
    /// let mut hash = [0u8; SHA3_224::DIGEST_SIZE];
    /// sha.finalize(&mut hash).expect("Error with finalize()");
    /// ```
    pub fn finalize(&mut self, hash: &mut [u8]) -> Result<(), i32> {
        if hash.len() != Self::DIGEST_SIZE {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let rc = unsafe {
            sys::wc_Sha3_224_Final(&mut self.wc_sha3, hash.as_mut_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}

#[cfg(sha3)]
impl Drop for SHA3_224 {
    /// Safely free the underlying wolfSSL SHA3_224 context.
    ///
    /// This calls the `wc_Sha3_224_Free` wolfssl library function.
    ///
    /// The Rust Drop trait guarantees that this method is called when the
    /// SHA3_224 struct goes out of scope, automatically cleaning up resources
    /// and preventing memory leaks.
    fn drop(&mut self) {
        unsafe { sys::wc_Sha3_224_Free(&mut self.wc_sha3); }
    }
}

/// Context for SHA3-256 computation.
#[cfg(sha3)]
pub struct SHA3_256 {
    wc_sha3: sys::wc_Sha3,
}

#[cfg(sha3)]
impl SHA3_256 {
    /// SHA3-256 digest size in bytes.
    pub const DIGEST_SIZE: usize = sys::WC_SHA3_256_DIGEST_SIZE as usize;

    /// Build a new SHA3_256 instance.
    ///
    /// # Returns
    ///
    /// Returns either Ok(sha) containing the SHA3_256 struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA3_256;
    /// let sha = SHA3_256::new().expect("Error with new()");
    /// ```
    pub fn new() -> Result<Self, i32> {
        Self::new_ex(None, None)
    }

    /// Build a new SHA3_256 instance with optional heap and device ID.
    ///
    /// # Parameters
    ///
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(sha) containing the SHA3_256 struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA3_256;
    /// let sha = SHA3_256::new_ex(None, None).expect("Error with new_ex()");
    /// ```
    pub fn new_ex(heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let mut wc_sha3: MaybeUninit<sys::wc_Sha3> = MaybeUninit::uninit();
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_InitSha3_256(wc_sha3.as_mut_ptr(), heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        let wc_sha3 = unsafe { wc_sha3.assume_init() };
        let sha3_256 = SHA3_256 { wc_sha3 };
        Ok(sha3_256)
    }

    /// Reinitialize a SHA3_256 instance for a new hash calculation.
    ///
    /// This does not need to be called after `new()`, but should be called
    /// after a hash calculation to prepare for a new calculation.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA3_256;
    /// let mut sha = SHA3_256::new().expect("Error with new()");
    /// sha.init().expect("Error with init()");
    /// ```
    pub fn init(&mut self) -> Result<(), i32> {
        self.init_ex(None, None)
    }

    /// Reinitialize a SHA3_256 instance for a new hash calculation with
    /// optional heap and device ID.
    ///
    /// This does not need to be called after `new()`, but should be called
    /// after a hash calculation to prepare for a new calculation.
    ///
    /// # Parameters
    ///
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
    /// use wolfssl::wolfcrypt::sha::SHA3_256;
    /// let mut sha = SHA3_256::new().expect("Error with new()");
    /// sha.init_ex(None, None).expect("Error with init_ex()");
    /// ```
    pub fn init_ex(&mut self, heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<(), i32> {
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_InitSha3_256(&mut self.wc_sha3, heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Update the SHA3-256 calculation by feeding in more input data.
    ///
    /// # Parameters
    ///
    /// * `data`: Input data.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA3_256;
    /// let mut sha = SHA3_256::new().expect("Error with new()");
    /// sha.update(b"input").expect("Error with update()");
    /// ```
    pub fn update(&mut self, data: &[u8]) -> Result<(), i32> {
        let data_size = data.len() as u32;
        let rc = unsafe {
            sys::wc_Sha3_256_Update(&mut self.wc_sha3, data.as_ptr(), data_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Finalize the SHA3-256 calculation and retrieve the calculated hash.
    ///
    /// # Parameters
    ///
    /// * `hash`: Buffer in which to store the calculated hash. The length
    ///   should be SHA3_256::DIGEST_SIZE.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA3_256;
    /// let mut sha = SHA3_256::new().expect("Error with new()");
    /// sha.update(b"input").expect("Error with update()");
    /// let mut hash = [0u8; SHA3_256::DIGEST_SIZE];
    /// sha.finalize(&mut hash).expect("Error with finalize()");
    /// ```
    pub fn finalize(&mut self, hash: &mut [u8]) -> Result<(), i32> {
        if hash.len() != Self::DIGEST_SIZE {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let rc = unsafe {
            sys::wc_Sha3_256_Final(&mut self.wc_sha3, hash.as_mut_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}

#[cfg(sha3)]
impl Drop for SHA3_256 {
    /// Safely free the underlying wolfSSL SHA3_256 context.
    ///
    /// This calls the `wc_Sha3_256_Free` wolfssl library function.
    ///
    /// The Rust Drop trait guarantees that this method is called when the
    /// SHA3_256 struct goes out of scope, automatically cleaning up resources
    /// and preventing memory leaks.
    fn drop(&mut self) {
        unsafe { sys::wc_Sha3_256_Free(&mut self.wc_sha3); }
    }
}

/// Context for SHA3-384 computation.
#[cfg(sha3)]
pub struct SHA3_384 {
    wc_sha3: sys::wc_Sha3,
}

#[cfg(sha3)]
impl SHA3_384 {
    /// SHA3-384 digest size in bytes.
    pub const DIGEST_SIZE: usize = sys::WC_SHA3_384_DIGEST_SIZE as usize;

    /// Build a new SHA3_384 instance.
    ///
    /// # Returns
    ///
    /// Returns either Ok(sha) containing the SHA3_384 struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA3_384;
    /// let sha = SHA3_384::new().expect("Error with new()");
    /// ```
    pub fn new() -> Result<Self, i32> {
        Self::new_ex(None, None)
    }

    /// Build a new SHA3_384 instance with optional heap and device ID.
    ///
    /// # Parameters
    ///
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(sha) containing the SHA3_384 struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA3_384;
    /// let sha = SHA3_384::new_ex(None, None).expect("Error with new_ex()");
    /// ```
    pub fn new_ex(heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let mut wc_sha3: MaybeUninit<sys::wc_Sha3> = MaybeUninit::uninit();
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_InitSha3_384(wc_sha3.as_mut_ptr(), heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        let wc_sha3 = unsafe { wc_sha3.assume_init() };
        let sha3_384 = SHA3_384 { wc_sha3 };
        Ok(sha3_384)
    }

    /// Reinitialize a SHA3_384 instance for a new hash calculation.
    ///
    /// This does not need to be called after `new()`, but should be called
    /// after a hash calculation to prepare for a new calculation.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA3_384;
    /// let mut sha = SHA3_384::new().expect("Error with new()");
    /// sha.init().expect("Error with init()");
    /// ```
    pub fn init(&mut self) -> Result<(), i32> {
        self.init_ex(None, None)
    }

    /// Reinitialize a SHA3_384 instance for a new hash calculation with
    /// optional heap and device ID.
    ///
    /// This does not need to be called after `new()`, but should be called
    /// after a hash calculation to prepare for a new calculation.
    ///
    /// # Parameters
    ///
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
    /// use wolfssl::wolfcrypt::sha::SHA3_384;
    /// let mut sha = SHA3_384::new().expect("Error with new()");
    /// sha.init_ex(None, None).expect("Error with init_ex()");
    /// ```
    pub fn init_ex(&mut self, heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<(), i32> {
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_InitSha3_384(&mut self.wc_sha3, heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Update the SHA3-384 calculation by feeding in more input data.
    ///
    /// # Parameters
    ///
    /// * `data`: Input data.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA3_384;
    /// let mut sha = SHA3_384::new().expect("Error with new()");
    /// sha.update(b"input").expect("Error with update()");
    /// ```
    pub fn update(&mut self, data: &[u8]) -> Result<(), i32> {
        let data_size = data.len() as u32;
        let rc = unsafe {
            sys::wc_Sha3_384_Update(&mut self.wc_sha3, data.as_ptr(), data_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Finalize the SHA3-384 calculation and retrieve the calculated hash.
    ///
    /// # Parameters
    ///
    /// * `hash`: Buffer in which to store the calculated hash. The length
    ///   should be SHA3_384::DIGEST_SIZE.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA3_384;
    /// let mut sha = SHA3_384::new().expect("Error with new()");
    /// sha.update(b"input").expect("Error with update()");
    /// let mut hash = [0u8; SHA3_384::DIGEST_SIZE];
    /// sha.finalize(&mut hash).expect("Error with finalize()");
    /// ```
    pub fn finalize(&mut self, hash: &mut [u8]) -> Result<(), i32> {
        if hash.len() != Self::DIGEST_SIZE {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let rc = unsafe {
            sys::wc_Sha3_384_Final(&mut self.wc_sha3, hash.as_mut_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}

#[cfg(sha3)]
impl Drop for SHA3_384 {
    /// Safely free the underlying wolfSSL SHA3_384 context.
    ///
    /// This calls the `wc_Sha3_384_Free` wolfssl library function.
    ///
    /// The Rust Drop trait guarantees that this method is called when the
    /// SHA3_384 struct goes out of scope, automatically cleaning up resources
    /// and preventing memory leaks.
    fn drop(&mut self) {
        unsafe { sys::wc_Sha3_384_Free(&mut self.wc_sha3); }
    }
}

/// Context for SHA3-512 computation.
#[cfg(sha3)]
pub struct SHA3_512 {
    wc_sha3: sys::wc_Sha3,
}

#[cfg(sha3)]
impl SHA3_512 {
    /// SHA3-512 digest size in bytes.
    pub const DIGEST_SIZE: usize = sys::WC_SHA3_512_DIGEST_SIZE as usize;

    /// Build a new SHA3_512 instance.
    ///
    /// # Returns
    ///
    /// Returns either Ok(sha) containing the SHA3_512 struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA3_512;
    /// let sha = SHA3_512::new().expect("Error with new()");
    /// ```
    pub fn new() -> Result<Self, i32> {
        Self::new_ex(None, None)
    }

    /// Build a new SHA3_512 instance with optional heap and device ID.
    ///
    /// # Parameters
    ///
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(sha) containing the SHA3_512 struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA3_512;
    /// let sha = SHA3_512::new_ex(None, None).expect("Error with new_ex()");
    /// ```
    pub fn new_ex(heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let mut wc_sha3: MaybeUninit<sys::wc_Sha3> = MaybeUninit::uninit();
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_InitSha3_512(wc_sha3.as_mut_ptr(), heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        let wc_sha3 = unsafe { wc_sha3.assume_init() };
        let sha3_512 = SHA3_512 { wc_sha3 };
        Ok(sha3_512)
    }

    /// Reinitialize a SHA3_512 instance for a new hash calculation.
    ///
    /// This does not need to be called after `new()`, but should be called
    /// after a hash calculation to prepare for a new calculation.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA3_512;
    /// let mut sha = SHA3_512::new().expect("Error with new()");
    /// sha.init().expect("Error with init()");
    /// ```
    pub fn init(&mut self) -> Result<(), i32> {
        self.init_ex(None, None)
    }

    /// Reinitialize a SHA3_512 instance for a new hash calculation with
    /// optional heap and device ID.
    ///
    /// This does not need to be called after `new()`, but should be called
    /// after a hash calculation to prepare for a new calculation.
    ///
    /// # Parameters
    ///
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
    /// use wolfssl::wolfcrypt::sha::SHA3_512;
    /// let mut sha = SHA3_512::new().expect("Error with new()");
    /// sha.init_ex(None, None).expect("Error with init_ex()");
    /// ```
    pub fn init_ex(&mut self, heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<(), i32> {
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_InitSha3_512(&mut self.wc_sha3, heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Update the SHA3-512 calculation by feeding in more input data.
    ///
    /// # Parameters
    ///
    /// * `data`: Input data.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA3_512;
    /// let mut sha = SHA3_512::new().expect("Error with new()");
    /// sha.update(b"input").expect("Error with update()");
    /// ```
    pub fn update(&mut self, data: &[u8]) -> Result<(), i32> {
        let data_size = data.len() as u32;
        let rc = unsafe {
            sys::wc_Sha3_512_Update(&mut self.wc_sha3, data.as_ptr(), data_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Finalize the SHA3-512 calculation and retrieve the calculated hash.
    ///
    /// # Parameters
    ///
    /// * `hash`: Buffer in which to store the calculated hash. The length
    ///   should be SHA3_512::DIGEST_SIZE.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHA3_512;
    /// let mut sha = SHA3_512::new().expect("Error with new()");
    /// sha.update(b"input").expect("Error with update()");
    /// let mut hash = [0u8; SHA3_512::DIGEST_SIZE];
    /// sha.finalize(&mut hash).expect("Error with finalize()");
    /// ```
    pub fn finalize(&mut self, hash: &mut [u8]) -> Result<(), i32> {
        if hash.len() != Self::DIGEST_SIZE {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let rc = unsafe {
            sys::wc_Sha3_512_Final(&mut self.wc_sha3, hash.as_mut_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}

#[cfg(sha3)]
impl Drop for SHA3_512 {
    /// Safely free the underlying wolfSSL SHA3_512 context.
    ///
    /// This calls the `wc_Sha3_512_Free` wolfssl library function.
    ///
    /// The Rust Drop trait guarantees that this method is called when the
    /// SHA3_512 struct goes out of scope, automatically cleaning up resources
    /// and preventing memory leaks.
    fn drop(&mut self) {
        unsafe { sys::wc_Sha3_512_Free(&mut self.wc_sha3); }
    }
}

/// Context for SHAKE128 (SHA-3) computation.
#[cfg(shake128)]
pub struct SHAKE128 {
    wc_shake: sys::wc_Shake,
}

#[cfg(shake128)]
impl SHAKE128 {
    /// Squeeze block size.
    pub const SQUEEZE_BLOCK_SIZE: usize = sys::WC_SHA3_128_BLOCK_SIZE as usize;

    /// Build a new SHAKE128 instance.
    ///
    /// # Returns
    ///
    /// Returns either Ok(sha) containing the SHAKE128 struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHAKE128;
    /// let sha = SHAKE128::new().expect("Error with new()");
    /// ```
    pub fn new() -> Result<Self, i32> {
        Self::new_ex(None, None)
    }

    /// Build a new SHAKE128 instance with optional heap and device ID.
    ///
    /// # Parameters
    ///
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(sha) containing the SHAKE128 struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHAKE128;
    /// let sha = SHAKE128::new_ex(None, None).expect("Error with new_ex()");
    /// ```
    pub fn new_ex(heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let mut wc_shake: MaybeUninit<sys::wc_Shake> = MaybeUninit::uninit();
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe {
            sys::wc_InitShake128(wc_shake.as_mut_ptr(), heap, dev_id)
        };
        if rc != 0 {
            return Err(rc);
        }
        let wc_shake = unsafe { wc_shake.assume_init() };
        let shake128 = SHAKE128 { wc_shake };
        Ok(shake128)
    }

    /// Reinitialize a SHAKE128 instance for a new hash calculation.
    ///
    /// This does not need to be called after `new()`, but should be called
    /// after a hash calculation to prepare for a new calculation.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHAKE128;
    /// let mut sha = SHAKE128::new().expect("Error with new()");
    /// sha.init().expect("Error with init()");
    /// ```
    pub fn init(&mut self) -> Result<(), i32> {
        self.init_ex(None, None)
    }

    /// Reinitialize a SHAKE128 instance for a new hash calculation with
    /// optional heap and device ID.
    ///
    /// This does not need to be called after `new()`, but should be called
    /// after a hash calculation to prepare for a new calculation.
    ///
    /// # Parameters
    ///
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
    /// use wolfssl::wolfcrypt::sha::SHAKE128;
    /// let mut sha = SHAKE128::new().expect("Error with new()");
    /// sha.init_ex(None, None).expect("Error with init_ex()");
    /// ```
    pub fn init_ex(&mut self, heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<(), i32> {
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe {
            sys::wc_InitShake128(&mut self.wc_shake, heap, dev_id)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Update the SHAKE128 calculation by feeding in more input data.
    ///
    /// # Parameters
    ///
    /// * `data`: Input data.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHAKE128;
    /// let mut sha = SHAKE128::new().expect("Error with new()");
    /// sha.update(b"input").expect("Error with update()");
    /// ```
    pub fn update(&mut self, data: &[u8]) -> Result<(), i32> {
        let data_size = data.len() as u32;
        let rc = unsafe {
            sys::wc_Shake128_Update(&mut self.wc_shake, data.as_ptr(), data_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Finalize the SHAKE128 calculation and retrieve the calculated hash.
    ///
    /// # Parameters
    ///
    /// * `hash`: Buffer in which to store the calculated hash.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHAKE128;
    /// let mut sha = SHAKE128::new().expect("Error with new()");
    /// sha.update(b"input").expect("Error with update()");
    /// let mut hash = [0u8; 32];
    /// sha.finalize(&mut hash).expect("Error with finalize()");
    /// ```
    pub fn finalize(&mut self, hash: &mut [u8]) -> Result<(), i32> {
        let hash_size = hash.len() as u32;
        let rc = unsafe {
            sys::wc_Shake128_Final(&mut self.wc_shake, hash.as_mut_ptr(), hash_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Absorb the provided byte array. Cannot be called incrementally.
    ///
    /// # Parameters
    ///
    /// * `data`: Data buffer to absorb.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHAKE128;
    /// let mut sha = SHAKE128::new().expect("Error with new()");
    /// sha.absorb(b"input").expect("Error with absorb()");
    /// ```
    pub fn absorb(&mut self, data: &[u8]) -> Result<(), i32> {
        let data_size = data.len() as u32;
        let rc = unsafe {
            sys::wc_Shake128_Absorb(&mut self.wc_shake, data.as_ptr(), data_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Squeeze out more blocks of data.
    ///
    /// This function can be called inrementally.
    ///
    /// # Parameters
    ///
    /// * `dout`: Output buffer.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHAKE128;
    /// let mut sha = SHAKE128::new().expect("Error with new()");
    /// sha.absorb(b"input").expect("Error with absorb()");
    /// let mut buffer = [0u8; 2 * SHAKE128::SQUEEZE_BLOCK_SIZE];
    /// sha.squeeze_blocks(&mut buffer).expect("Error with squeeze_blocks()");
    /// ```
    pub fn squeeze_blocks(&mut self, dout: &mut [u8]) -> Result<(), i32> {
        let dout_size = dout.len() as u32;
        if dout_size % (Self::SQUEEZE_BLOCK_SIZE as u32) != 0 {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let n_blocks = (dout_size / (Self::SQUEEZE_BLOCK_SIZE as u32)) as u32;
        let rc = unsafe {
            sys::wc_Shake128_SqueezeBlocks(&mut self.wc_shake, dout.as_mut_ptr(), n_blocks)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}

#[cfg(shake128)]
impl Drop for SHAKE128 {
    /// Safely free the underlying wolfSSL SHAKE128 context.
    ///
    /// This calls the `wc_Shake128_Free` wolfssl library function.
    ///
    /// The Rust Drop trait guarantees that this method is called when the
    /// SHAKE128 struct goes out of scope, automatically cleaning up resources
    /// and preventing memory leaks.
    fn drop(&mut self) {
        unsafe { sys::wc_Shake128_Free(&mut self.wc_shake); }
    }
}

/// Context for SHAKE256 (SHA-3) computation.
#[cfg(shake256)]
pub struct SHAKE256 {
    wc_shake: sys::wc_Shake,
}

#[cfg(shake256)]
impl SHAKE256 {
    /// Squeeze block size.
    pub const SQUEEZE_BLOCK_SIZE: usize = sys::WC_SHA3_256_BLOCK_SIZE as usize;

    /// Build a new SHAKE256 instance.
    ///
    /// # Returns
    ///
    /// Returns either Ok(sha) containing the SHAKE256 struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHAKE256;
    /// let sha = SHAKE256::new().expect("Error with new()");
    /// ```
    pub fn new() -> Result<Self, i32> {
        Self::new_ex(None, None)
    }

    /// Build a new SHAKE256 instance with optional heap and device ID.
    ///
    /// # Parameters
    ///
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(sha) containing the SHAKE256 struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHAKE256;
    /// let sha = SHAKE256::new_ex(None, None).expect("Error with new_ex()");
    /// ```
    pub fn new_ex(heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let mut wc_shake: MaybeUninit<sys::wc_Shake> = MaybeUninit::uninit();
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe {
            sys::wc_InitShake256(wc_shake.as_mut_ptr(), heap, dev_id)
        };
        if rc != 0 {
            return Err(rc);
        }
        let wc_shake = unsafe { wc_shake.assume_init() };
        let shake256 = SHAKE256 { wc_shake };
        Ok(shake256)
    }

    /// Reinitialize a SHAKE256 instance for a new hash calculation.
    ///
    /// This does not need to be called after `new()`, but should be called
    /// after a hash calculation to prepare for a new calculation.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHAKE256;
    /// let mut sha = SHAKE256::new().expect("Error with new()");
    /// sha.init().expect("Error with init()");
    /// ```
    pub fn init(&mut self) -> Result<(), i32> {
        self.init_ex(None, None)
    }

    /// Reinitialize a SHAKE256 instance for a new hash calculation with
    /// optional heap and device ID.
    ///
    /// This does not need to be called after `new()`, but should be called
    /// after a hash calculation to prepare for a new calculation.
    ///
    /// # Parameters
    ///
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
    /// use wolfssl::wolfcrypt::sha::SHAKE256;
    /// let mut sha = SHAKE256::new().expect("Error with new()");
    /// sha.init_ex(None, None).expect("Error with init_ex()");
    /// ```
    pub fn init_ex(&mut self, heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<(), i32> {
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe {
            sys::wc_InitShake256(&mut self.wc_shake, heap, dev_id)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Update the SHAKE256 calculation by feeding in more input data.
    ///
    /// # Parameters
    ///
    /// * `data`: Input data.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHAKE256;
    /// let mut sha = SHAKE256::new().expect("Error with new()");
    /// sha.update(b"input").expect("Error with update()");
    /// ```
    pub fn update(&mut self, data: &[u8]) -> Result<(), i32> {
        let data_size = data.len() as u32;
        let rc = unsafe {
            sys::wc_Shake256_Update(&mut self.wc_shake, data.as_ptr(), data_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Finalize the SHAKE256 calculation and retrieve the calculated hash.
    ///
    /// # Parameters
    ///
    /// * `hash`: Buffer in which to store the calculated hash.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHAKE256;
    /// let mut sha = SHAKE256::new().expect("Error with new()");
    /// sha.update(b"input").expect("Error with update()");
    /// let mut hash = [0u8; 32];
    /// sha.finalize(&mut hash).expect("Error with finalize()");
    /// ```
    pub fn finalize(&mut self, hash: &mut [u8]) -> Result<(), i32> {
        let hash_size = hash.len() as u32;
        let rc = unsafe {
            sys::wc_Shake256_Final(&mut self.wc_shake, hash.as_mut_ptr(), hash_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Absorb the provided byte array. Cannot be called incrementally.
    ///
    /// # Parameters
    ///
    /// * `data`: Data buffer to absorb.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHAKE256;
    /// let mut sha = SHAKE256::new().expect("Error with new()");
    /// sha.absorb(b"input").expect("Error with absorb()");
    /// ```
    pub fn absorb(&mut self, data: &[u8]) -> Result<(), i32> {
        let data_size = data.len() as u32;
        let rc = unsafe {
            sys::wc_Shake256_Absorb(&mut self.wc_shake, data.as_ptr(), data_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Squeeze out more blocks of data.
    ///
    /// This function can be called inrementally.
    ///
    /// # Parameters
    ///
    /// * `dout`: Output buffer.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::sha::SHAKE256;
    /// let mut sha = SHAKE256::new().expect("Error with new()");
    /// sha.absorb(b"input").expect("Error with absorb()");
    /// let mut buffer = [0u8; 2 * SHAKE256::SQUEEZE_BLOCK_SIZE];
    /// sha.squeeze_blocks(&mut buffer).expect("Error with squeeze_blocks()");
    /// ```
    pub fn squeeze_blocks(&mut self, dout: &mut [u8]) -> Result<(), i32> {
        let dout_size = dout.len() as u32;
        if dout_size % (Self::SQUEEZE_BLOCK_SIZE as u32) != 0 {
            return Err(sys::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let n_blocks = (dout_size / (Self::SQUEEZE_BLOCK_SIZE as u32)) as u32;
        let rc = unsafe {
            sys::wc_Shake256_SqueezeBlocks(&mut self.wc_shake, dout.as_mut_ptr(), n_blocks)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}

#[cfg(shake256)]
impl Drop for SHAKE256 {
    /// Safely free the underlying wolfSSL SHAKE256 context.
    ///
    /// This calls the `wc_Shake256_Free` wolfssl library function.
    ///
    /// The Rust Drop trait guarantees that this method is called when the
    /// SHAKE256 struct goes out of scope, automatically cleaning up resources
    /// and preventing memory leaks.
    fn drop(&mut self) {
        unsafe { sys::wc_Shake256_Free(&mut self.wc_shake); }
    }
}
