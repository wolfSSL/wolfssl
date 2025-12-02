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
This module provides a Rust wrapper for the wolfCrypt library's Cipher-based
Message Authentication Code (CMAC) functionality.
*/

#![cfg(cmac)]

use crate::sys;
use std::mem::MaybeUninit;

/// The `CMAC` struct manages the lifecycle of a wolfSSL `Cmac` object.
///
/// It ensures proper initialization and deallocation.
///
/// An instance can be created with `new()`.
pub struct CMAC {
    ws_cmac: sys::Cmac,
}
impl CMAC {
    /// One-shot CMAC generation function.
    ///
    /// # Parameters
    ///
    /// * `key`: Key to use for CMAC generation.
    /// * `data`: CMAC input data.
    /// * `dout`: Output buffer where CMAC is written.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(aes)]
    /// {
    /// use wolfssl::wolfcrypt::cmac::CMAC;
    /// let key = [
    ///     0x2bu8, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    ///     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    /// ];
    /// let message = [
    ///     0x6bu8, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    ///     0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    /// ];
    /// let mut generate_out = [0u8; 16];
    /// CMAC::generate(&key, &message, &mut generate_out).expect("Error with generate()");
    /// }
    /// ```
    #[cfg(aes)]
    pub fn generate(key: &[u8], data: &[u8], dout: &mut [u8]) -> Result<(), i32> {
        let key_size = key.len() as u32;
        let data_size = data.len() as u32;
        let mut dout_size = dout.len() as u32;
        let rc = unsafe {
            sys::wc_AesCmacGenerate(dout.as_mut_ptr(), &mut dout_size,
                data.as_ptr(), data_size,
                key.as_ptr(), key_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Create a new CMAC object using the given key.
    ///
    /// # Parameters
    ///
    /// * `key`: Key to use for CMAC generation.
    ///
    /// # Returns
    ///
    /// Returns either Ok(cmac) containing the CMAC struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::cmac::CMAC;
    /// let key = [
    ///     0x2bu8, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    ///     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    /// ];
    /// let mut cmac = CMAC::new(&key).expect("Error with new()");
    /// ```
    pub fn new(key: &[u8]) -> Result<Self, i32> {
        Self::new_ex(key, None, None)
    }

    /// Create a new CMAC object using the given key with optional heap and
    /// device ID.
    ///
    /// # Parameters
    ///
    /// * `key`: Key to use for CMAC generation.
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(cmac) containing the CMAC struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::cmac::CMAC;
    /// let key = [
    ///     0x2bu8, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    ///     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    /// ];
    /// let mut cmac = CMAC::new_ex(&key, None, None).expect("Error with new_ex()");
    /// ```
    pub fn new_ex(key: &[u8], heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let key_size = key.len() as u32;
        let mut ws_cmac: MaybeUninit<sys::Cmac> = MaybeUninit::uninit();
        let typ = sys::CmacType_WC_CMAC_AES as i32;
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe {
            sys::wc_InitCmac_ex(ws_cmac.as_mut_ptr(), key.as_ptr(), key_size,
                typ, core::ptr::null_mut(), heap, dev_id)
        };
        if rc != 0 {
            return Err(rc);
        }
        let ws_cmac = unsafe { ws_cmac.assume_init() };
        let cmac = CMAC { ws_cmac };
        Ok(cmac)
    }

    /// One-shot CMAC verification function.
    ///
    /// # Parameters
    ///
    /// * `key`: Key to use for CMAC generation.
    /// * `data`: CMAC input data.
    /// * `check`: CMAC value to compare to.
    ///
    /// # Returns
    ///
    /// Returns either Ok(valid) (with valid indicating if the CMAC passed in
    /// is correct or not) on success or Err(e) containing the wolfSSL library
    /// error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(aes)]
    /// {
    /// use wolfssl::wolfcrypt::cmac::CMAC;
    /// let key = [
    ///     0x2bu8, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    ///     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    /// ];
    /// let message = [
    ///     0x6bu8, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    ///     0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    /// ];
    /// let mut generate_out = [0u8; 16];
    /// CMAC::generate(&key, &message, &mut generate_out).expect("Error with generate()");
    /// let valid = CMAC::verify(&key, &message, &generate_out).expect("Error with verify()");
    /// assert!(valid);
    /// }
    /// ```
    #[cfg(aes)]
    pub fn verify(key: &[u8], data: &[u8], check: &[u8]) -> Result<bool, i32> {
        let key_size = key.len() as u32;
        let data_size = data.len() as u32;
        let check_size = check.len() as u32;
        let rc = unsafe {
            sys::wc_AesCmacVerify(check.as_ptr(), check_size,
                data.as_ptr(), data_size,
                key.as_ptr(), key_size)
        };
        if rc < 0 {
            return Err(rc);
        }
        Ok(rc == 0)
    }

    /// One-shot CMAC generation function (with heap and device ID).
    ///
    /// # Parameters
    ///
    /// * `key`: Key to use for CMAC generation.
    /// * `data`: CMAC input data.
    /// * `dout`: Output buffer where CMAC is written.
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
    /// #[cfg(aes)]
    /// {
    /// use wolfssl::wolfcrypt::cmac::CMAC;
    /// let key = [
    ///     0x2bu8, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    ///     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    /// ];
    /// let message = [
    ///     0x6bu8, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    ///     0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    /// ];
    /// let mut generate_out = [0u8; 16];
    /// let mut cmac = CMAC::new(&key).expect("Error with new()");
    /// cmac.generate_ex(&key, &message, &mut generate_out, None, None).expect("Error with generate_ex()");
    /// }
    /// ```
    #[cfg(aes)]
    pub fn generate_ex(&mut self, key: &[u8], data: &[u8], dout: &mut [u8], heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<(), i32> {
        let key_size = key.len() as u32;
        let data_size = data.len() as u32;
        let mut dout_size = dout.len() as u32;
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe {
            sys::wc_AesCmacGenerate_ex(&mut self.ws_cmac,
                dout.as_mut_ptr(), &mut dout_size,
                data.as_ptr(), data_size,
                key.as_ptr(), key_size, heap, dev_id)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Add CMAC input data.
    ///
    /// # Parameters
    ///
    /// * `data`: CMAC input data.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::cmac::CMAC;
    /// let key = [
    ///     0x2bu8, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    ///     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    /// ];
    /// let message = [
    ///     0x6bu8, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    ///     0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    /// ];
    /// let mut cmac = CMAC::new(&key).expect("Error with new()");
    /// cmac.update(&message).expect("Error with update()");
    /// ```
    pub fn update(&mut self, data: &[u8]) -> Result<(), i32> {
        let data_size = data.len() as u32;
        let rc = unsafe {
            sys::wc_CmacUpdate(&mut self.ws_cmac, data.as_ptr(), data_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Generate the final Cipher-based Message Authentication Code result.
    ///
    /// This function consumes the `CMAC` object since no further operations
    /// can be performed with it.
    ///
    /// # Parameters
    ///
    /// * `dout`: Output buffer where CMAC is written.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::cmac::CMAC;
    /// let key = [
    ///     0x2bu8, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    ///     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    /// ];
    /// let message = [
    ///     0x6bu8, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    ///     0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    /// ];
    /// let mut cmac = CMAC::new(&key).expect("Error with new()");
    /// cmac.update(&message).expect("Error with update()");
    /// let mut finalize_out = [0u8; 16];
    /// cmac.finalize(&mut finalize_out).expect("Error with finalize()");
    /// ```
    pub fn finalize(mut self, dout: &mut [u8]) -> Result<(), i32> {
        let mut dout_size = dout.len() as u32;
        let rc = unsafe {
            sys::wc_CmacFinalNoFree(&mut self.ws_cmac,
                dout.as_mut_ptr(), &mut dout_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// One-shot CMAC verification function (with optional heap and device ID).
    ///
    /// # Parameters
    ///
    /// * `key`: Key to use for CMAC generation.
    /// * `data`: CMAC input data.
    /// * `check`: CMAC value to compare to.
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(valid) (with valid indicating if the CMAC passed in
    /// is correct or not) on success or Err(e) containing the wolfSSL library
    /// error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(aes)]
    /// {
    /// use wolfssl::wolfcrypt::cmac::CMAC;
    /// let key = [
    ///     0x2bu8, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    ///     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    /// ];
    /// let message = [
    ///     0x6bu8, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    ///     0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    /// ];
    /// let mut generate_out = [0u8; 16];
    /// CMAC::generate(&key, &message, &mut generate_out).expect("Error with generate()");
    /// let mut cmac = CMAC::new(&key).expect("Error with new()");
    /// let valid = cmac.verify_ex(&key, &message, &generate_out, None, None).expect("Error with verify_ex()");
    /// assert!(valid);
    /// }
    /// ```
    #[cfg(aes)]
    pub fn verify_ex(&mut self, key: &[u8], data: &[u8], check: &[u8], heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<bool, i32> {
        let key_size = key.len() as u32;
        let data_size = data.len() as u32;
        let check_size = check.len() as u32;
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe {
            sys::wc_AesCmacVerify_ex(&mut self.ws_cmac,
                check.as_ptr(), check_size,
                data.as_ptr(), data_size,
                key.as_ptr(), key_size, heap, dev_id)
        };
        if rc < 0 {
            return Err(rc);
        }
        Ok(rc == 0)
    }
}
impl Drop for CMAC {
    /// Safely free the wolfSSL resources.
    fn drop(&mut self) {
        unsafe { sys::wc_CmacFree(&mut self.ws_cmac); }
    }
}
