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
This module provides a Rust wrapper for the wolfCrypt library's ECC
functionality.

The primary component is the `ECC` struct, which manages the lifecycle of a
wolfSSL `ecc_key` object. It ensures proper initialization and deallocation.
*/

#![cfg(ecc)]

use crate::sys;
use crate::wolfcrypt::random::RNG;
use std::mem::{MaybeUninit};

/// Rust wrapper for wolfSSL `ecc_point` object.
pub struct ECCPoint {
    wc_ecc_point: *mut sys::ecc_point,
    heap: *mut std::os::raw::c_void,
}

impl ECCPoint {
    /// Import an ECCPoint from a DER-formatted buffer.
    ///
    /// # Parameters
    ///
    /// * `din`: DER-formatted buffer.
    /// * `curve_id`: Curve ID, e.g. ECC::SECP256R1.
    /// * `heap`: Optional heap hint.
    ///
    /// # Returns
    ///
    /// Returns either Ok(ECCPoint) containing the ECCPoint struct instance or
    /// Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ecc_import)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::{ECC,ECCPoint};
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let curve_id = ECC::SECP256R1;
    /// let curve_size = ECC::get_curve_size_from_id(curve_id).expect("Error with get_curve_size_from_id()");
    /// let mut ecc = ECC::generate_ex(curve_size, &mut rng, curve_id, None, None).expect("Error with generate()");
    /// let ecc_point = ecc.make_pub_to_point(Some(&mut rng), None).expect("Error with make_pub_to_point()");
    /// let mut der = [0u8; 128];
    /// let size = ecc_point.export_der(&mut der, curve_id).expect("Error with export_der()");
    /// ECCPoint::import_der(&der[0..size], curve_id, None).expect("Error with import_der()");
    /// }
    /// ```
    #[cfg(ecc_import)]
    pub fn import_der(din: &[u8], curve_id: i32, heap: Option<*mut std::os::raw::c_void>) -> Result<Self, i32> {
        let curve_idx = unsafe { sys::wc_ecc_get_curve_idx(curve_id) };
        if curve_idx < 0 {
            return Err(curve_idx);
        }
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let wc_ecc_point = unsafe { sys::wc_ecc_new_point_h(heap) };
        if wc_ecc_point.is_null() {
            return Err(sys::wolfCrypt_ErrorCodes_MEMORY_E);
        }
        let eccpoint = ECCPoint { wc_ecc_point, heap };
        let din_size = din.len() as u32;
        let rc = unsafe {
            sys::wc_ecc_import_point_der(din.as_ptr(), din_size, curve_idx,
                eccpoint.wc_ecc_point)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(eccpoint)
    }

    /// Import an ECCPoint from a DER-formatted buffer.
    ///
    /// # Parameters
    ///
    /// * `din`: DER-formatted buffer.
    /// * `curve_id`: Curve ID, e.g. ECC::SECP256R1.
    /// * `short_key_size`: if shortKeySize != 0 then key size is always
    ///   (din.len() - 1) / 2.
    /// * `heap`: Optional heap hint.
    ///
    /// # Returns
    ///
    /// Returns either Ok(ECCPoint) containing the ECCPoint struct instance or
    /// Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(ecc_import, ecc_export, ecc_comp_key))]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::{ECC,ECCPoint};
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let curve_id = ECC::SECP256R1;
    /// let curve_size = ECC::get_curve_size_from_id(curve_id).expect("Error with get_curve_size_from_id()");
    /// let mut ecc = ECC::generate_ex(curve_size, &mut rng, curve_id, None, None).expect("Error with generate()");
    /// let ecc_point = ecc.make_pub_to_point(Some(&mut rng), None).expect("Error with make_pub_to_point()");
    /// let mut der = [0u8; 128];
    /// let size = ecc_point.export_der_compressed(&mut der, curve_id).expect("Error with export_der_compressed()");
    /// ECCPoint::import_der_ex(&der[0..size], curve_id, 1, None).expect("Error with import_der_ex()");
    /// }
    /// ```
    #[cfg(ecc_import)]
    pub fn import_der_ex(din: &[u8], curve_id: i32, short_key_size: i32, heap: Option<*mut std::os::raw::c_void>) -> Result<Self, i32> {
        let curve_idx = unsafe { sys::wc_ecc_get_curve_idx(curve_id) };
        if curve_idx < 0 {
            return Err(curve_idx);
        }
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let wc_ecc_point = unsafe { sys::wc_ecc_new_point_h(heap) };
        if wc_ecc_point.is_null() {
            return Err(sys::wolfCrypt_ErrorCodes_MEMORY_E);
        }
        let eccpoint = ECCPoint { wc_ecc_point, heap };
        let din_size = din.len() as u32;
        let rc = unsafe {
            sys::wc_ecc_import_point_der_ex(din.as_ptr(), din_size, curve_idx,
                wc_ecc_point, short_key_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(eccpoint)
    }

    /// Export an ECCPoint in DER format.
    ///
    /// # Parameters
    ///
    /// * `dout`: Output buffer.
    /// * `curve_id`: Curve ID, e.g. ECC::SECP256R1.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to
    /// `dout` or Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ecc_export)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::{ECC,ECCPoint};
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let curve_id = ECC::SECP256R1;
    /// let curve_size = ECC::get_curve_size_from_id(curve_id).expect("Error with get_curve_size_from_id()");
    /// let mut ecc = ECC::generate_ex(curve_size, &mut rng, curve_id, None, None).expect("Error with generate()");
    /// let ecc_point = ecc.make_pub_to_point(Some(&mut rng), None).expect("Error with make_pub_to_point()");
    /// let mut der = [0u8; 128];
    /// let size = ecc_point.export_der(&mut der, curve_id).expect("Error with export_der()");
    /// assert!(size > 0 && size <= der.len());
    /// ECCPoint::import_der(&der[0..size], curve_id, None).expect("Error with import_der()");
    /// }
    /// ```
    #[cfg(ecc_export)]
    pub fn export_der(&self, dout: &mut [u8], curve_id: i32) -> Result<usize, i32> {
        let curve_idx = unsafe { sys::wc_ecc_get_curve_idx(curve_id) };
        if curve_idx < 0 {
            return Err(curve_idx);
        }
        let mut dout_size = dout.len() as u32;
        let rc = unsafe {
            sys::wc_ecc_export_point_der(curve_idx, self.wc_ecc_point,
                dout.as_mut_ptr(), &mut dout_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(dout_size as usize)
    }

    /// Export an ECCPoint in compressed DER format.
    ///
    /// # Parameters
    ///
    /// * `dout`: Output buffer.
    /// * `curve_id`: Curve ID, e.g. ECC::SECP256R1.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to
    /// `dout` or Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(ecc_export, ecc_comp_key))]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::{ECC,ECCPoint};
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let curve_id = ECC::SECP256R1;
    /// let curve_size = ECC::get_curve_size_from_id(curve_id).expect("Error with get_curve_size_from_id()");
    /// let mut ecc = ECC::generate_ex(curve_size, &mut rng, curve_id, None, None).expect("Error with generate()");
    /// let ecc_point = ecc.make_pub_to_point(Some(&mut rng), None).expect("Error with make_pub_to_point()");
    /// let mut der = [0u8; 128];
    /// let size = ecc_point.export_der_compressed(&mut der, curve_id).expect("Error with export_der_compressed()");
    /// ECCPoint::import_der_ex(&der[0..size], curve_id, 1, None).expect("Error with import_der_ex()");
    /// }
    /// ```
    #[cfg(all(ecc_export, ecc_comp_key))]
    pub fn export_der_compressed(&self, dout: &mut [u8], curve_id: i32) -> Result<usize, i32> {
        let curve_idx = unsafe { sys::wc_ecc_get_curve_idx(curve_id) };
        if curve_idx < 0 {
            return Err(curve_idx);
        }
        let mut dout_size = dout.len() as u32;
        let rc = unsafe {
            sys::wc_ecc_export_point_der_ex(curve_idx, self.wc_ecc_point,
                dout.as_mut_ptr(), &mut dout_size, 1)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(dout_size as usize)
    }

    /// Zeroize the ECCPoint.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let mut ecc = ECC::generate(32, &mut rng, None, None).expect("Error with generate()");
    /// let mut ecc_point = ecc.make_pub_to_point(Some(&mut rng), None).expect("Error with make_pub_to_point()");
    /// ecc_point.forcezero();
    /// ```
    pub fn forcezero(&mut self) {
        unsafe { sys::wc_ecc_forcezero_point(self.wc_ecc_point) };
    }
}

impl Drop for ECCPoint {
    /// Safely free the underlying wolfSSL ecc_point context.
    ///
    /// This calls the `wc_ecc_del_point_h()` wolfssl library function.
    ///
    /// The Rust Drop trait guarantees that this method is called when the
    /// ECCPoint struct instance goes out of scope, automatically cleaning up
    /// resources and preventing memory leaks.
    fn drop(&mut self) {
        unsafe { sys::wc_ecc_del_point_h(self.wc_ecc_point, self.heap); }
    }
}

/// The `ECC` struct manages the lifecycle of a wolfSSL `ecc_key` object.
///
/// It ensures proper initialization and deallocation.
///
/// An instance can be created with `generate()`, `import_x963()`,
/// `import_x963_ex()`, `import_private_key()`, `import_private_key_ex()`,
/// `import_raw()`, or `import_raw_ex()`.
pub struct ECC {
    wc_ecc_key: sys::ecc_key,
}

impl ECC {
    pub const CURVE_INVALID: i32 = sys::ecc_curve_ids_ECC_CURVE_INVALID;
    pub const CURVE_DEF: i32 = sys::ecc_curve_ids_ECC_CURVE_DEF;
    pub const SECP192R1: i32 = sys::ecc_curve_ids_ECC_SECP192R1;
    pub const PRIME192V2: i32 = sys::ecc_curve_ids_ECC_PRIME192V2;
    pub const PRIME192V3: i32 = sys::ecc_curve_ids_ECC_PRIME192V3;
    pub const PRIME239V1: i32 = sys::ecc_curve_ids_ECC_PRIME239V1;
    pub const PRIME239V2: i32 = sys::ecc_curve_ids_ECC_PRIME239V2;
    pub const PRIME239V3: i32 = sys::ecc_curve_ids_ECC_PRIME239V3;
    pub const SECP256R1: i32 = sys::ecc_curve_ids_ECC_SECP256R1;
    pub const SECP112R1: i32 = sys::ecc_curve_ids_ECC_SECP112R1;
    pub const SECP112R2: i32 = sys::ecc_curve_ids_ECC_SECP112R2;
    pub const SECP128R1: i32 = sys::ecc_curve_ids_ECC_SECP128R1;
    pub const SECP128R2: i32 = sys::ecc_curve_ids_ECC_SECP128R2;
    pub const SECP160R1: i32 = sys::ecc_curve_ids_ECC_SECP160R1;
    pub const SECP160R2: i32 = sys::ecc_curve_ids_ECC_SECP160R2;
    pub const SECP224R1: i32 = sys::ecc_curve_ids_ECC_SECP224R1;
    pub const SECP384R1: i32 = sys::ecc_curve_ids_ECC_SECP384R1;
    pub const SECP521R1: i32 = sys::ecc_curve_ids_ECC_SECP521R1;
    pub const SECP160K1: i32 = sys::ecc_curve_ids_ECC_SECP160K1;
    pub const SECP192K1: i32 = sys::ecc_curve_ids_ECC_SECP192K1;
    pub const SECP224K1: i32 = sys::ecc_curve_ids_ECC_SECP224K1;
    pub const SECP256K1: i32 = sys::ecc_curve_ids_ECC_SECP256K1;
    pub const BRAINPOOLP160R1: i32 = sys::ecc_curve_ids_ECC_BRAINPOOLP160R1;
    pub const BRAINPOOLP192R1: i32 = sys::ecc_curve_ids_ECC_BRAINPOOLP192R1;
    pub const BRAINPOOLP224R1: i32 = sys::ecc_curve_ids_ECC_BRAINPOOLP224R1;
    pub const BRAINPOOLP256R1: i32 = sys::ecc_curve_ids_ECC_BRAINPOOLP256R1;
    pub const BRAINPOOLP320R1: i32 = sys::ecc_curve_ids_ECC_BRAINPOOLP320R1;
    pub const BRAINPOOLP384R1: i32 = sys::ecc_curve_ids_ECC_BRAINPOOLP384R1;
    pub const BRAINPOOLP512R1: i32 = sys::ecc_curve_ids_ECC_BRAINPOOLP512R1;
    pub const SM2P256V1: i32 = sys::ecc_curve_ids_ECC_SM2P256V1;
    #[cfg(ecc_curve_25519)]
    pub const X25519: i32 = sys::ecc_curve_ids_ECC_X25519;
    #[cfg(ecc_curve_448)]
    pub const X448: i32 = sys::ecc_curve_ids_ECC_X448;
    #[cfg(ecc_curve_sakke)]
    pub const SAKKE_1: i32 = sys::ecc_curve_ids_ECC_SAKKE_1;
    #[cfg(ecc_custom_curves)]
    pub const CURVE_CUSTOM: i32 = sys::ecc_curve_ids_ECC_CURVE_CUSTOM;
    pub const CURVE_MAX: i32 = sys::ecc_curve_ids_ECC_CURVE_MAX;

    pub const FLAG_NONE: i32 = sys::WC_ECC_FLAG_NONE as i32;
    pub const FLAG_COFACTOR: i32 = sys::WC_ECC_FLAG_COFACTOR as i32;
    pub const FLAG_DEC_SIGN: i32 = sys::WC_ECC_FLAG_DEC_SIGN as i32;

    /// Generate a new ECC key with the given size.
    ///
    /// # Parameters
    ///
    /// * `size`: Desired key length in bytes.
    /// * `rng`: Reference to a `RNG` struct to use for random number
    ///   generation while making the key.
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(ECC) containing the ECC struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let mut ecc = ECC::generate(32, &mut rng, None, None).expect("Error with generate()");
    /// ecc.check().expect("Error with check()");
    /// ```
    pub fn generate(size: i32, rng: &mut RNG, heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let mut wc_ecc_key: MaybeUninit<sys::ecc_key> = MaybeUninit::uninit();
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_ecc_init_ex(wc_ecc_key.as_mut_ptr(), heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        let mut wc_ecc_key = unsafe { wc_ecc_key.assume_init() };
        let rc = unsafe {
            sys::wc_ecc_make_key(&mut rng.wc_rng, size, &mut wc_ecc_key)
        };
        if rc != 0 {
            unsafe { sys::wc_ecc_free(&mut wc_ecc_key); }
            return Err(rc);
        }
        let ecc = ECC { wc_ecc_key };
        Ok(ecc)
    }

    /// Generate a new ECC key with the given size and curve.
    ///
    /// # Parameters
    ///
    /// * `size`: Desired key length in bytes.
    /// * `rng`: Reference to a `RNG` struct to use for random number
    ///   generation while making the key.
    /// * `curve_id`: Curve ID, e.g. ECC::SECP256R1.
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(ECC) containing the ECC struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let curve_id = ECC::SECP256R1;
    /// let curve_size = ECC::get_curve_size_from_id(curve_id).expect("Error with get_curve_size_from_id()");
    /// let mut ecc = ECC::generate_ex(curve_size, &mut rng, curve_id, None, None).expect("Error with generate_ex()");
    /// ecc.check().expect("Error with check()");
    /// ```
    pub fn generate_ex(size: i32, rng: &mut RNG, curve_id: i32, heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let mut wc_ecc_key: MaybeUninit<sys::ecc_key> = MaybeUninit::uninit();
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_ecc_init_ex(wc_ecc_key.as_mut_ptr(), heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        let mut wc_ecc_key = unsafe { wc_ecc_key.assume_init() };
        let rc = unsafe {
            sys::wc_ecc_make_key_ex(&mut rng.wc_rng, size, &mut wc_ecc_key, curve_id)
        };
        if rc != 0 {
            unsafe { sys::wc_ecc_free(&mut wc_ecc_key); }
            return Err(rc);
        }
        let ecc = ECC { wc_ecc_key };
        Ok(ecc)
    }

    /// Generate a new ECC key with the given size, curve, and flags.
    ///
    /// # Parameters
    ///
    /// * `size`: Desired key length in bytes.
    /// * `rng`: Reference to a `RNG` struct to use for random number
    ///   generation while making the key.
    /// * `curve_id`: Curve ID, e.g. ECC::SECP256R1.
    /// * `flags`: Flags for making the key.
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(ECC) containing the ECC struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let curve_id = ECC::SECP256R1;
    /// let curve_size = ECC::get_curve_size_from_id(curve_id).expect("Error with get_curve_size_from_id()");
    /// let mut ecc = ECC::generate_ex2(curve_size, &mut rng, curve_id, ECC::FLAG_COFACTOR, None, None).expect("Error with generate_ex2()");
    /// ecc.check().expect("Error with check()");
    /// ```
    pub fn generate_ex2(size: i32, rng: &mut RNG, curve_id: i32, flags: i32, heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let mut wc_ecc_key: MaybeUninit<sys::ecc_key> = MaybeUninit::uninit();
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_ecc_init_ex(wc_ecc_key.as_mut_ptr(), heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        let mut wc_ecc_key = unsafe { wc_ecc_key.assume_init() };
        let rc = unsafe {
            sys::wc_ecc_make_key_ex2(&mut rng.wc_rng, size, &mut wc_ecc_key, curve_id, flags)
        };
        if rc != 0 {
            unsafe { sys::wc_ecc_free(&mut wc_ecc_key); }
            return Err(rc);
        }
        let ecc = ECC { wc_ecc_key };
        Ok(ecc)
    }

    /// Get the curve size corresponding to the given curve ID.
    ///
    /// # Parameters
    ///
    /// * `curve_id`: Curve ID, e.g. ECC::SECP256R1.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the curve size or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let curve_id = ECC::SECP256R1;
    /// let curve_size = ECC::get_curve_size_from_id(curve_id).expect("Error with get_curve_size_from_id()");
    /// let mut ecc = ECC::generate_ex(curve_size, &mut rng, curve_id, None, None).expect("Error with generate()");
    /// ecc.check().expect("Error with check()");
    /// ```
    pub fn get_curve_size_from_id(curve_id: i32) -> Result<i32, i32> {
        let rc = unsafe { sys::wc_ecc_get_curve_size_from_id(curve_id) };
        if rc < 0 {
            return Err(rc);
        }
        Ok(rc)
    }

    /// Import public and private ECC key pair from DER input buffer.
    ///
    /// # Parameters
    ///
    /// * `der`: DER buffer containing the ECC public and private key pair.
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(ECC) containing the ECC struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// use std::fs;
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let key_path = "../../../certs/ecc-client-key.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut ecc = ECC::import_der(&der, None, None).expect("Error with import_der()");
    /// ```
    pub fn import_der(der: &[u8], heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let mut wc_ecc_key: MaybeUninit<sys::ecc_key> = MaybeUninit::uninit();
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_ecc_init_ex(wc_ecc_key.as_mut_ptr(), heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        let mut wc_ecc_key = unsafe { wc_ecc_key.assume_init() };
        let mut idx = 0u32;
        let der_size = der.len() as u32;
        let rc = unsafe {
            sys::wc_EccPrivateKeyDecode(der.as_ptr(), &mut idx, &mut wc_ecc_key, der_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        let ecc = ECC { wc_ecc_key };
        Ok(ecc)
    }

    /// Import public ECC key from DER input buffer.
    ///
    /// # Parameters
    ///
    /// * `der`: DER buffer containing the ECC public key.
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(ECC) containing the ECC struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// use std::fs;
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let key_path = "../../../certs/ecc-client-key.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut ecc = ECC::import_der(&der, None, None).expect("Error with import_der()");
    /// let hash = [0x42u8; 32];
    /// let mut signature = [0u8; 128];
    /// let signature_length = ecc.sign_hash(&hash, &mut signature, &mut rng).expect("Error with sign_hash()");
    /// assert!(signature_length > 0 && signature_length <= signature.len());
    /// let signature = &mut signature[0..signature_length];
    /// let key_path = "../../../certs/ecc-client-keyPub.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut ecc = ECC::import_public_der(&der, None, None).expect("Error with import_public_der()");
    /// ```
    pub fn import_public_der(der: &[u8], heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let mut wc_ecc_key: MaybeUninit<sys::ecc_key> = MaybeUninit::uninit();
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_ecc_init_ex(wc_ecc_key.as_mut_ptr(), heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        let mut wc_ecc_key = unsafe { wc_ecc_key.assume_init() };
        let mut idx = 0u32;
        let der_size = der.len() as u32;
        let rc = unsafe {
            sys::wc_EccPublicKeyDecode(der.as_ptr(), &mut idx, &mut wc_ecc_key, der_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        let ecc = ECC { wc_ecc_key };
        Ok(ecc)
    }

    /// Import a public/private ECC key pair from a buffer containing the raw
    /// private key and a second buffer containing the ANSI X9.63 formatted
    /// public key. This function handles both compressed and uncompressed
    /// keys as long as wolfSSL is built with the HAVE_COMP_KEY build option
    /// enabled.
    ///
    /// # Parameters
    ///
    /// * `priv_buf`: Buffer containing the raw private key.
    /// * `pub_buf`: Buffer containing the ANSI X9.63 formatted public key.
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(ECC) containing the ECC struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ecc_import)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let mut ecc = ECC::generate(32, &mut rng, None, None).expect("Error with generate()");
    /// let hash = [0x42u8; 32];
    /// let mut signature = [0u8; 128];
    /// let signature_length = ecc.sign_hash(&hash, &mut signature, &mut rng).expect("Error with sign_hash()");
    /// let signature = &signature[0..signature_length];
    /// let mut d = [0u8; 32];
    /// let d_size = ecc.export_private(&mut d).expect("Error with export_private()");
    /// let mut x963 = [0u8; 128];
    /// let x963_size = ecc.export_x963(&mut x963).expect("Error with export_x963()");
    /// let x963 = &x963[0..x963_size];
    /// let mut ecc2 = ECC::import_private_key(&d, x963, None, None).expect("Error with import_private_key()");
    /// let valid = ecc2.verify_hash(&signature, &hash).expect("Error with verify_hash()");
    /// assert_eq!(valid, true);
    /// }
    /// ```
    #[cfg(ecc_import)]
    pub fn import_private_key(priv_buf: &[u8], pub_buf: &[u8], heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let mut wc_ecc_key: MaybeUninit<sys::ecc_key> = MaybeUninit::uninit();
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_ecc_init_ex(wc_ecc_key.as_mut_ptr(), heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        let mut wc_ecc_key = unsafe { wc_ecc_key.assume_init() };
        let priv_size = priv_buf.len() as u32;
        let pub_size = pub_buf.len() as u32;
        let rc = unsafe {
            sys::wc_ecc_import_private_key(priv_buf.as_ptr(), priv_size,
                pub_buf.as_ptr(), pub_size, &mut wc_ecc_key)
        };
        if rc != 0 {
            return Err(rc);
        }
        let ecc = ECC { wc_ecc_key };
        Ok(ecc)
    }

    /// Import a public/private ECC key pair from a buffer containing the raw
    /// private key and a second buffer containing the ANSI X9.63 formatted
    /// public key. This function handles both compressed and uncompressed
    /// keys as long as wolfSSL is built with the HAVE_COMP_KEY build option
    /// enabled. This function allows the curve ID to be explicitly specified.
    ///
    /// # Parameters
    ///
    /// * `priv_buf`: Buffer containing the raw private key.
    /// * `pub_buf`: Buffer containing the ANSI X9.63 formatted public key.
    /// * `curve_id`: Curve ID, e.g. ECC::SECP256R1.
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(ECC) containing the ECC struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ecc_import)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let curve_id = ECC::SECP256R1;
    /// let curve_size = ECC::get_curve_size_from_id(curve_id).expect("Error with get_curve_size_from_id()");
    /// let mut ecc = ECC::generate_ex(curve_size, &mut rng, curve_id, None, None).expect("Error with generate_ex()");
    /// let hash = [0x42u8; 32];
    /// let mut signature = [0u8; 128];
    /// let signature_length = ecc.sign_hash(&hash, &mut signature, &mut rng).expect("Error with sign_hash()");
    /// let signature = &signature[0..signature_length];
    /// let mut d = [0u8; 32];
    /// let d_size = ecc.export_private(&mut d).expect("Error with export_private()");
    /// let mut x963 = [0u8; 128];
    /// let x963_size = ecc.export_x963(&mut x963).expect("Error with export_x963()");
    /// let x963 = &x963[0..x963_size];
    /// let mut ecc2 = ECC::import_private_key_ex(&d, x963, curve_id, None, None).expect("Error with import_private_key_ex()");
    /// let valid = ecc2.verify_hash(&signature, &hash).expect("Error with verify_hash()");
    /// assert_eq!(valid, true);
    /// }
    /// ```
    #[cfg(ecc_import)]
    pub fn import_private_key_ex(priv_buf: &[u8], pub_buf: &[u8], curve_id: i32, heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let mut wc_ecc_key: MaybeUninit<sys::ecc_key> = MaybeUninit::uninit();
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_ecc_init_ex(wc_ecc_key.as_mut_ptr(), heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        let mut wc_ecc_key = unsafe { wc_ecc_key.assume_init() };
        let priv_size = priv_buf.len() as u32;
        let pub_size = pub_buf.len() as u32;
        let rc = unsafe {
            sys::wc_ecc_import_private_key_ex(priv_buf.as_ptr(), priv_size,
                pub_buf.as_ptr(), pub_size, &mut wc_ecc_key, curve_id)
        };
        if rc != 0 {
            return Err(rc);
        }
        let ecc = ECC { wc_ecc_key };
        Ok(ecc)
    }

    /// Import raw ECC key from components in hexadecimal ASCII string format
    /// with curve name specified.
    ///
    /// # Parameters
    ///
    /// * `qx`: X component of public key as null terminated ASCII hex string.
    /// * `qy`: Y component of public key as null terminated ASCII hex string.
    /// * `d`: Private key as null terminated ASCII hex string.
    /// * `curve_name`: Null terminated ASCII string containing the curve name.
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(ECC) containing the ECC struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ecc_import)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// let qx = b"7a4e287890a1a47ad3457e52f2f76a83ce46cbc947616d0cbaa82323818a793d\0";
    /// let qy = b"eec4084f5b29ebf29c44cce3b3059610922f8b30ea6e8811742ac7238fe87308\0";
    /// let d  = b"8c14b793cb19137e323a6d2e2a870bca2e7a493ec1153b3a95feb8a4873f8d08\0";
    /// ECC::import_raw(qx, qy, d, b"SECP256R1\0", None, None).expect("Error with import_raw()");
    /// }
    /// ```
    #[cfg(ecc_import)]
    pub fn import_raw(qx: &[u8], qy: &[u8], d: &[u8], curve_name: &[u8], heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let mut wc_ecc_key: MaybeUninit<sys::ecc_key> = MaybeUninit::uninit();
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_ecc_init_ex(wc_ecc_key.as_mut_ptr(), heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        let mut wc_ecc_key = unsafe { wc_ecc_key.assume_init() };
        let qx_ptr = qx.as_ptr() as *const i8;
        let qy_ptr = qy.as_ptr() as *const i8;
        let d_ptr = d.as_ptr() as *const i8;
        let curve_name_ptr = curve_name.as_ptr() as *const i8;
        let rc = unsafe {
            sys::wc_ecc_import_raw(&mut wc_ecc_key, qx_ptr, qy_ptr, d_ptr,
                curve_name_ptr)
        };
        if rc != 0 {
            return Err(rc);
        }
        let ecc = ECC { wc_ecc_key };
        Ok(ecc)
    }

    /// Import raw ECC key from components in hexadecimal ASCII string format
    /// with curve ID specified.
    ///
    /// # Parameters
    ///
    /// * `qx`: X component of public key as null terminated ASCII hex string.
    /// * `qy`: Y component of public key as null terminated ASCII hex string.
    /// * `d`: Private key as null terminated ASCII hex string.
    /// * `curve_id`: Curve ID, e.g. ECC::SECP256R1.
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(ECC) containing the ECC struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ecc_import)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// let qx = b"7a4e287890a1a47ad3457e52f2f76a83ce46cbc947616d0cbaa82323818a793d\0";
    /// let qy = b"eec4084f5b29ebf29c44cce3b3059610922f8b30ea6e8811742ac7238fe87308\0";
    /// let d  = b"8c14b793cb19137e323a6d2e2a870bca2e7a493ec1153b3a95feb8a4873f8d08\0";
    /// ECC::import_raw_ex(qx, qy, d, ECC::SECP256R1, None, None).expect("Error with import_raw_ex()");
    /// }
    /// ```
    #[cfg(ecc_import)]
    pub fn import_raw_ex(qx: &[u8], qy: &[u8], d: &[u8], curve_id: i32, heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let mut wc_ecc_key: MaybeUninit<sys::ecc_key> = MaybeUninit::uninit();
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_ecc_init_ex(wc_ecc_key.as_mut_ptr(), heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        let mut wc_ecc_key = unsafe { wc_ecc_key.assume_init() };
        let qx_ptr = qx.as_ptr() as *const i8;
        let qy_ptr = qy.as_ptr() as *const i8;
        let d_ptr = d.as_ptr() as *const i8;
        let rc = unsafe {
            sys::wc_ecc_import_raw_ex(&mut wc_ecc_key, qx_ptr, qy_ptr, d_ptr,
                curve_id)
        };
        if rc != 0 {
            return Err(rc);
        }
        let ecc = ECC { wc_ecc_key };
        Ok(ecc)
    }

    /// Import raw ECC key from components in binary unsigned integer format
    /// with curve ID specified.
    ///
    /// # Parameters
    ///
    /// * `qx`: X component of public key in binary unsigned integer format.
    /// * `qy`: Y component of public key in binary unsigned integer format.
    /// * `d`: Private key in binary unsigned integer format.
    /// * `curve_id`: Curve ID, e.g. ECC::SECP256R1.
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(ECC) containing the ECC struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ecc_import)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let curve_id = ECC::SECP256R1;
    /// let curve_size = ECC::get_curve_size_from_id(curve_id).expect("Error with get_curve_size_from_id()");
    /// let mut ecc = ECC::generate_ex(curve_size, &mut rng, curve_id, None, None).expect("Error with generate()");
    /// let mut qx = [0u8; 32];
    /// let mut qx_len = 0u32;
    /// let mut qy = [0u8; 32];
    /// let mut qy_len = 0u32;
    /// let mut d = [0u8; 32];
    /// let mut d_len = 0u32;
    /// ecc.export_ex(&mut qx, &mut qx_len, &mut qy, &mut qy_len, &mut d, &mut d_len, false).expect("Error with export_ex()");
    /// let mut ecc2 = ECC::import_unsigned(&qx, &qy, &d, curve_id, None, None).expect("Error with import_unsigned()");
    /// }
    /// ```
    #[cfg(ecc_import)]
    pub fn import_unsigned(qx: &[u8], qy: &[u8], d: &[u8], curve_id: i32, heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<Self, i32> {
        let mut wc_ecc_key: MaybeUninit<sys::ecc_key> = MaybeUninit::uninit();
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_ecc_init_ex(wc_ecc_key.as_mut_ptr(), heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        let mut wc_ecc_key = unsafe { wc_ecc_key.assume_init() };
        let rc = unsafe {
            sys::wc_ecc_import_unsigned(&mut wc_ecc_key, qx.as_ptr(), qy.as_ptr(),
                d.as_ptr(), curve_id)
        };
        if rc != 0 {
            return Err(rc);
        }
        let ecc = ECC { wc_ecc_key };
        Ok(ecc)
    }

    /// Import a public ECC key from the given buffer containing the key stored
    /// in ANSI X9.63 format. This function handles both compressed and
    /// uncompressed keys, as long as compressed keys are enabled at compile
    /// time with the HAVE_COMP_KEY build option.
    ///
    /// # Parameters
    ///
    /// * `din`: Buffer containing the ECC key encoded in ANSI X9.63 format.
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(ECC) containing the ECC struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ecc_import)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let mut ecc = ECC::generate(32, &mut rng, None, None).expect("Error with generate()");
    /// let mut x963 = [0u8; 128];
    /// let x963_size = ecc.export_x963(&mut x963).expect("Error with export_x963()");
    /// let x963 = &x963[0..x963_size];
    /// let _ecc2 = ECC::import_x963(x963, None, None).expect("Error with import_x963()");
    /// }
    /// ```
    #[cfg(ecc_import)]
    pub fn import_x963(din: &[u8], heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<ECC, i32> {
        let din_size = din.len() as u32;
        let mut wc_ecc_key: MaybeUninit<sys::ecc_key> = MaybeUninit::uninit();
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_ecc_init_ex(wc_ecc_key.as_mut_ptr(), heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        let mut wc_ecc_key = unsafe { wc_ecc_key.assume_init() };
        let rc = unsafe {
            sys::wc_ecc_import_x963(din.as_ptr(), din_size, &mut wc_ecc_key)
        };
        if rc != 0 {
            unsafe { sys::wc_ecc_free(&mut wc_ecc_key); }
            return Err(rc);
        }
        let ecc = ECC { wc_ecc_key };
        Ok(ecc)
    }

    /// Import a public ECC key from the given buffer containing the key stored
    /// in ANSI X9.63 format. This function handles both compressed and
    /// uncompressed keys, as long as compressed keys are enabled at compile
    /// time with the HAVE_COMP_KEY build option.
    ///
    /// This function allows specifying the ECC curve ID to use.
    ///
    /// # Parameters
    ///
    /// * `din`: Buffer containing the ECC key encoded in ANSI X9.63 format.
    /// * `curve_id`: Curve ID, e.g. ECC::SECP256R1.
    /// * `heap`: Optional heap hint.
    /// * `dev_id` Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(ECC) containing the ECC struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ecc_import)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let curve_id = ECC::SECP256R1;
    /// let curve_size = ECC::get_curve_size_from_id(curve_id).expect("Error with get_curve_size_from_id()");
    /// let mut ecc = ECC::generate_ex(curve_size, &mut rng, curve_id, None, None).expect("Error with generate_ex()");
    /// let mut x963 = [0u8; 128];
    /// let x963_size = ecc.export_x963(&mut x963).expect("Error with export_x963()");
    /// let x963 = &x963[0..x963_size];
    /// let _ecc2 = ECC::import_x963_ex(x963, curve_id, None, None).expect("Error with import_x963_ex()");
    /// }
    /// ```
    #[cfg(ecc_import)]
    pub fn import_x963_ex(din: &[u8], curve_id: i32, heap: Option<*mut std::os::raw::c_void>, dev_id: Option<i32>) -> Result<ECC, i32> {
        let din_size = din.len() as u32;
        let mut wc_ecc_key: MaybeUninit<sys::ecc_key> = MaybeUninit::uninit();
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let dev_id = match dev_id {
            Some(dev_id) => dev_id,
            None => sys::INVALID_DEVID,
        };
        let rc = unsafe { sys::wc_ecc_init_ex(wc_ecc_key.as_mut_ptr(), heap, dev_id) };
        if rc != 0 {
            return Err(rc);
        }
        let mut wc_ecc_key = unsafe { wc_ecc_key.assume_init() };
        let rc = unsafe {
            sys::wc_ecc_import_x963_ex(din.as_ptr(), din_size, &mut wc_ecc_key, curve_id)
        };
        if rc != 0 {
            unsafe { sys::wc_ecc_free(&mut wc_ecc_key); }
            return Err(rc);
        }
        let ecc = ECC { wc_ecc_key };
        Ok(ecc)
    }

    /// Convert the R and S portions (as hexadecimal ASCII strings) of an ECC
    /// signature into a DER-encoded ECDSA signature.
    ///
    /// # Parameters
    ///
    /// * `r`: R component of ECC signature as a null-terminated hexadecimal
    ///   ASCII string.
    /// * `s`: S component of ECC signature as a null-terminated hexadecimal
    ///   ASCII string.
    /// * `dout`: Buffer in which to store the output ECDSA signature.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to
    /// `dout` or Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::fs;
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// fn bytes_to_asciiz_hex_string(bytes: &[u8]) -> String {
    ///     let mut hex_string = String::with_capacity(bytes.len() * 2 + 1);
    ///     for byte in bytes {
    ///         hex_string.push_str(&format!("{:02X}", byte));
    ///     }
    ///     hex_string.push('\0');
    ///     hex_string
    /// }
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let key_path = "../../../certs/ecc-client-key.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut ecc = ECC::import_der(&der, None, None).expect("Error with import_der()");
    /// let hash = [0x42u8; 32];
    /// let mut signature = [0u8; 128];
    /// let signature_length = ecc.sign_hash(&hash, &mut signature, &mut rng).expect("Error with sign_hash()");
    /// let signature = &mut signature[0..signature_length];
    /// let mut r = [0u8; 32];
    /// let mut r_size = 0u32;
    /// let mut s = [0u8; 32];
    /// let mut s_size = 0u32;
    /// ECC::sig_to_rs(signature, &mut r, &mut r_size, &mut s, &mut s_size).expect("Error with sig_to_rs()");
    /// let r = &r[0..r_size as usize];
    /// let s = &s[0..s_size as usize];
    /// let r_hex_string = bytes_to_asciiz_hex_string(r);
    /// let s_hex_string = bytes_to_asciiz_hex_string(s);
    /// let mut sig_out = [0u8; 128];
    /// let sig_out_size = ECC::rs_hex_to_sig(&r_hex_string[0..r_hex_string.len()].as_bytes(), &s_hex_string[0..s_hex_string.len()].as_bytes(), &mut sig_out).expect("Error with rs_hex_to_sig()");
    /// assert_eq!(*signature, *&sig_out[0..sig_out_size]);
    /// ```
    pub fn rs_hex_to_sig(r: &[u8], s: &[u8], dout: &mut [u8]) -> Result<usize, i32> {
        let mut dout_size = dout.len() as u32;
        let r_ptr = r.as_ptr() as *const i8;
        let s_ptr = s.as_ptr() as *const i8;
        let rc = unsafe {
            sys::wc_ecc_rs_to_sig(r_ptr, s_ptr, dout.as_mut_ptr(),
                &mut dout_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(dout_size as usize)
    }

    /// Convert the R and S portions (as binary unsigned integers) of an ECC
    /// signature into a DER-encoded ECDSA signature.
    ///
    /// # Parameters
    ///
    /// * `r`: R component of ECC signature as a binary unsigned integer.
    /// * `s`: S component of ECC signature as a binary unsigned integer.
    /// * `dout`: Buffer in which to store the output ECDSA signature.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to
    /// `dout` or Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::fs;
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let key_path = "../../../certs/ecc-client-key.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut ecc = ECC::import_der(&der, None, None).expect("Error with import_der()");
    /// let hash = [0x42u8; 32];
    /// let mut signature = [0u8; 128];
    /// let signature_length = ecc.sign_hash(&hash, &mut signature, &mut rng).expect("Error with sign_hash()");
    /// let signature = &mut signature[0..signature_length];
    /// let mut r = [0u8; 32];
    /// let mut r_size = 0u32;
    /// let mut s = [0u8; 32];
    /// let mut s_size = 0u32;
    /// ECC::sig_to_rs(signature, &mut r, &mut r_size, &mut s, &mut s_size).expect("Error with sig_to_rs()");
    /// let r = &r[0..r_size as usize];
    /// let s = &s[0..s_size as usize];
    /// let mut sig_out = [0u8; 128];
    /// let sig_out_size = ECC::rs_bin_to_sig(r, s, &mut sig_out).expect("Error with rs_bin_to_sig()");
    /// assert_eq!(*signature, *&sig_out[0..sig_out_size]);
    /// ```
    pub fn rs_bin_to_sig(r: &[u8], s: &[u8], dout: &mut [u8]) -> Result<usize, i32> {
        let r_size = r.len() as u32;
        let s_size = s.len() as u32;
        let mut dout_size = dout.len() as u32;
        let rc = unsafe {
            sys::wc_ecc_rs_raw_to_sig(r.as_ptr(), r_size, s.as_ptr(), s_size,
                dout.as_mut_ptr(), &mut dout_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(dout_size as usize)
    }

    /// Convert ECDSA signature to R and S components.
    ///
    /// # Parameters
    ///
    /// * `sig`: ECDSA signature.
    /// * `r`: Output buffer for R component.
    /// * `r_size`: Number of bytes written to `r` buffer.
    /// * `s`: Output buffer for S component.
    /// * `s_size`: Number of bytes written to `s` buffer.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::fs;
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let key_path = "../../../certs/ecc-client-key.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut ecc = ECC::import_der(&der, None, None).expect("Error with import_der()");
    /// let hash = [0x42u8; 32];
    /// let mut signature = [0u8; 128];
    /// let signature_length = ecc.sign_hash(&hash, &mut signature, &mut rng).expect("Error with sign_hash()");
    /// let signature = &mut signature[0..signature_length];
    /// let mut r = [0u8; 32];
    /// let mut r_size = 0u32;
    /// let mut s = [0u8; 32];
    /// let mut s_size = 0u32;
    /// ECC::sig_to_rs(signature, &mut r, &mut r_size, &mut s, &mut s_size).expect("Error with sig_to_rs()");
    /// let r = &r[0..r_size as usize];
    /// let s = &s[0..s_size as usize];
    /// let mut sig_out = [0u8; 128];
    /// let sig_out_size = ECC::rs_bin_to_sig(r, s, &mut sig_out).expect("Error with rs_bin_to_sig()");
    /// assert_eq!(*signature, *&sig_out[0..sig_out_size]);
    /// ```
    pub fn sig_to_rs(sig: &[u8], r: &mut [u8], r_size: &mut u32, s: &mut [u8], s_size: &mut u32) -> Result<(), i32> {
        let sig_len = sig.len() as u32;
        *r_size = r.len() as u32;
        *s_size = s.len() as u32;
        let rc = unsafe {
            sys::wc_ecc_sig_to_rs(sig.as_ptr(), sig_len,
                r.as_mut_ptr(), r_size, s.as_mut_ptr(), s_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Perform basic sanity checks on the ECC key.
    ///
    /// # Returns
    ///
    /// Returns either Ok(ECC) containing the ECC struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let mut ecc = ECC::generate(32, &mut rng, None, None).expect("Error with generate()");
    /// ecc.check().expect("Error with check()");
    /// ```
    pub fn check(&mut self) -> Result<(), i32> {
        let rc = unsafe { sys::wc_ecc_check_key(&mut self.wc_ecc_key) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Export ECC key components in binary unsigned integer format.
    ///
    /// # Parameters
    ///
    /// * `qx`: Buffer in which to store public X component.
    /// * `qx_len`: Output parameter storing number of bytes written to `qx`.
    /// * `qy`: Buffer in which to store public Y component.
    /// * `qy_len`: Output parameter storing number of bytes written to `qy`.
    /// * `d`: Buffer in which to store private component.
    /// * `d_len`: Output parameter storing number of bytes written to `d`.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) or Err(e) containing the wolfSSL library error
    /// code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ecc_import)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let mut ecc = ECC::generate(32, &mut rng, None, None).expect("Error with generate()");
    /// let mut qx = [0u8; 32];
    /// let mut qx_len = 0u32;
    /// let mut qy = [0u8; 32];
    /// let mut qy_len = 0u32;
    /// let mut d = [0u8; 32];
    /// let mut d_len = 0u32;
    /// ecc.export(&mut qx, &mut qx_len, &mut qy, &mut qy_len, &mut d, &mut d_len).expect("Error with export()");
    /// }
    /// ```
    #[cfg(ecc_import)]
    pub fn export(&mut self, qx: &mut [u8], qx_len: &mut u32,
            qy: &mut [u8], qy_len: &mut u32, d: &mut [u8], d_len: &mut u32) -> Result<(), i32> {
        *qx_len = qx.len() as u32;
        *qy_len = qy.len() as u32;
        *d_len = d.len() as u32;
        let rc = unsafe {
            sys::wc_ecc_export_private_raw(&mut self.wc_ecc_key,
                qx.as_mut_ptr(), qx_len,
                qy.as_mut_ptr(), qy_len,
                d.as_mut_ptr(), d_len)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Export ECC key components as either ASCII hexadecimal strings or
    /// in binary unsigned integer format.
    ///
    /// # Parameters
    ///
    /// * `qx`: Buffer in which to store public X component.
    /// * `qx_len`: Output parameter storing number of bytes written to `qx`.
    /// * `qy`: Buffer in which to store public Y component.
    /// * `qy_len`: Output parameter storing number of bytes written to `qy`.
    /// * `d`: Buffer in which to store private component.
    /// * `d_len`: Output parameter storing number of bytes written to `d`.
    /// * `hex`: true to output in ASCII hexadecimal string, false to output
    ///   as binary data.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) or Err(e) containing the wolfSSL library error
    /// code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ecc_import)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let mut ecc = ECC::generate(32, &mut rng, None, None).expect("Error with generate()");
    /// let mut qx = [0u8; 32];
    /// let mut qx_len = 0u32;
    /// let mut qy = [0u8; 32];
    /// let mut qy_len = 0u32;
    /// let mut d = [0u8; 32];
    /// let mut d_len = 0u32;
    /// ecc.export_ex(&mut qx, &mut qx_len, &mut qy, &mut qy_len, &mut d, &mut d_len, false).expect("Error with export_ex()");
    /// }
    /// ```
    #[cfg(ecc_import)]
    pub fn export_ex(&mut self, qx: &mut [u8], qx_len: &mut u32,
            qy: &mut [u8], qy_len: &mut u32, d: &mut [u8], d_len: &mut u32,
            hex: bool) -> Result<(), i32> {
        *qx_len = qx.len() as u32;
        *qy_len = qy.len() as u32;
        *d_len = d.len() as u32;
        let enc_type =
            if hex {
                sys::WC_TYPE_HEX_STR as i32
            } else {
                sys::WC_TYPE_UNSIGNED_BIN as i32
            };
        let rc = unsafe {
            sys::wc_ecc_export_ex(&mut self.wc_ecc_key,
                qx.as_mut_ptr(), qx_len,
                qy.as_mut_ptr(), qy_len,
                d.as_mut_ptr(), d_len,
                enc_type)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Export private component from ECC key in binary unsigned integer form.
    ///
    /// # Parameters
    ///
    /// * `d`: Buffer in which to store private component.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to `d`
    /// or Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ecc_export)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let mut ecc = ECC::generate(32, &mut rng, None, None).expect("Error with generate()");
    /// let mut d = [0u8; 32];
    /// let d_size = ecc.export_private(&mut d).expect("Error with export_private()");
    /// assert_eq!(d_size, 32);
    /// }
    /// ```
    #[cfg(ecc_export)]
    pub fn export_private(&mut self, d: &mut [u8]) -> Result<usize, i32> {
        let mut d_size = d.len() as u32;
        let rc = unsafe {
            sys::wc_ecc_export_private_only(&mut self.wc_ecc_key,
                d.as_mut_ptr(), &mut d_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(d_size as usize)
    }

    /// Export public ECC key components in binary unsigned integer format.
    ///
    /// # Parameters
    ///
    /// * `qx`: Buffer in which to store public X component.
    /// * `qx_len`: Output parameter storing number of bytes written to `qx`.
    /// * `qy`: Buffer in which to store public Y component.
    /// * `qy_len`: Output parameter storing number of bytes written to `qy`.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) or Err(e) containing the wolfSSL library error
    /// code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ecc_export)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let mut ecc = ECC::generate(32, &mut rng, None, None).expect("Error with generate()");
    /// let mut qx = [0u8; 32];
    /// let mut qx_len = 0u32;
    /// let mut qy = [0u8; 32];
    /// let mut qy_len = 0u32;
    /// ecc.export_public(&mut qx, &mut qx_len, &mut qy, &mut qy_len).expect("Error with export_public()");
    /// }
    /// ```
    #[cfg(ecc_export)]
    pub fn export_public(&mut self, qx: &mut [u8], qx_len: &mut u32,
            qy: &mut [u8], qy_len: &mut u32) -> Result<(), i32> {
        *qx_len = qx.len() as u32;
        *qy_len = qy.len() as u32;
        let rc = unsafe {
            sys::wc_ecc_export_public_raw(&mut self.wc_ecc_key,
                qx.as_mut_ptr(), qx_len,
                qy.as_mut_ptr(), qy_len)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Export public key in ANSI X9.63 format.
    ///
    /// # Parameters
    ///
    /// * `dout`: Buffer to contain the output.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to
    /// `dout` or Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ecc_export)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let mut ecc = ECC::generate(32, &mut rng, None, None).expect("Error with generate()");
    /// let mut x963 = [0u8; 128];
    /// let _x963_size = ecc.export_x963(&mut x963).expect("Error with export_x963()");
    /// }
    /// ```
    #[cfg(ecc_export)]
    pub fn export_x963(&mut self, dout: &mut [u8]) -> Result<usize, i32> {
        let mut out_len: u32 = dout.len() as u32;
        let rc = unsafe {
            sys::wc_ecc_export_x963(&mut self.wc_ecc_key, dout.as_mut_ptr(), &mut out_len)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(out_len as usize)
    }

    /// Export public key in ANSI X9.63 compressed format.
    ///
    /// # Parameters
    ///
    /// * `dout`: Buffer to contain the output.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to
    /// `dout` or Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(ecc_export, ecc_comp_key))]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let mut ecc = ECC::generate(32, &mut rng, None, None).expect("Error with generate()");
    /// let mut x963 = [0u8; 128];
    /// let _x963_size = ecc.export_x963_compressed(&mut x963).expect("Error with export_x963_compressed()");
    /// }
    /// ```
    #[cfg(all(ecc_export, ecc_comp_key))]
    pub fn export_x963_compressed(&mut self, dout: &mut [u8]) -> Result<usize, i32> {
        let mut out_len: u32 = dout.len() as u32;
        let rc = unsafe {
            sys::wc_ecc_export_x963_ex(&mut self.wc_ecc_key, dout.as_mut_ptr(), &mut out_len, 1)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(out_len as usize)
    }

    /// Compute the public component from this key private component.
    ///
    /// # Parameters
    ///
    /// * `rng`: RNG struct used to blind the private key value used in the
    ///   computation.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) or Err(e) containing the wolfSSL library error
    /// code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::fs;
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let key_path = "../../../certs/ecc-client-key.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut ecc = ECC::import_der(&der, None, None).expect("Error with import_der()");
    /// ecc.make_pub(Some(&mut rng)).expect("Error with make_pub()");
    /// ```
    pub fn make_pub(&mut self, rng: Option<&mut RNG>) -> Result<(), i32> {
        let rng_ptr = match rng {
            Some(rng) => &mut rng.wc_rng,
            None => core::ptr::null_mut(),
        };
        let rc = unsafe {
            sys::wc_ecc_make_pub_ex(&mut self.wc_ecc_key, core::ptr::null_mut(), rng_ptr)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Compute the public component from this key private component.
    ///
    /// # Parameters
    ///
    /// * `rng`: RNG struct used to blind the private key value used in the
    ///   computation.
    /// * `heap`: Optional heap hint.
    ///
    /// # Returns
    ///
    /// Returns either Ok(ECCPoint) containing the public component ECCPoint
    /// or Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::fs;
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let key_path = "../../../certs/ecc-client-key.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut ecc = ECC::import_der(&der, None, None).expect("Error with import_der()");
    /// ecc.make_pub_to_point(Some(&mut rng), None).expect("Error with make_pub_to_point()");
    /// ```
    pub fn make_pub_to_point(&mut self, rng: Option<&mut RNG>, heap: Option<*mut std::os::raw::c_void>) -> Result<ECCPoint, i32> {
        let rng_ptr = match rng {
            Some(rng) => &mut rng.wc_rng,
            None => core::ptr::null_mut(),
        };
        let heap = match heap {
            Some(heap) => heap,
            None => core::ptr::null_mut(),
        };
        let wc_ecc_point = unsafe { sys::wc_ecc_new_point_h(heap) };
        if wc_ecc_point.is_null() {
            return Err(sys::wolfCrypt_ErrorCodes_MEMORY_E);
        }
        let ecc_point = ECCPoint { wc_ecc_point, heap };
        let rc = unsafe {
            sys::wc_ecc_make_pub_ex(&mut self.wc_ecc_key, wc_ecc_point, rng_ptr)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(ecc_point)
    }

    /// Associates a `RNG` instance with this `ECC` instance.
    ///
    /// This is necessary when wolfSSL is built with the `ECC_TIMING_RESISTANT`
    /// build option enabled.
    ///
    /// # Parameters
    ///
    /// * `rng`: The `RNG` struct instance to associate with this `ECC`
    ///   instance. The `RNG` struct should not be moved in memory after
    ///   calling this method.
    ///
    /// # Returns
    ///
    /// Returns Ok(()) on success or Err(e) containing the wolfSSL library
    /// error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let mut ecc = ECC::generate(32, &mut rng, None, None).expect("Error with generate()");
    /// ecc.set_rng(&mut rng).expect("Error with set_rng()");
    /// ```
    pub fn set_rng(&mut self, rng: &mut RNG) -> Result<(), i32> {
        let rc = unsafe {
            sys::wc_ecc_set_rng(&mut self.wc_ecc_key, &mut rng.wc_rng)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Compute the ECDH shared secret using this key's private component
    /// and the peer public key.
    ///
    /// # Parameters
    ///
    /// * `peer`: `ECC` public key.
    /// * `dout`: Buffer in which to store the computed secret value.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to
    /// `dout` or Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ecc_dh)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let mut ecc0 = ECC::generate(32, &mut rng, None, None).expect("Error with generate()");
    /// let mut ecc1 = ECC::generate(32, &mut rng, None, None).expect("Error with generate()");
    /// let mut ss0 = [0u8; 128];
    /// let mut ss1 = [0u8; 128];
    /// ecc0.set_rng(&mut rng).expect("Error with set_rng()");
    /// ecc1.set_rng(&mut rng).expect("Error with set_rng()");
    /// let ss0_size = ecc0.shared_secret(&mut ecc1, &mut ss0).expect("Error with shared_secret()");
    /// let ss1_size = ecc1.shared_secret(&mut ecc0, &mut ss1).expect("Error with shared_secret()");
    /// assert_eq!(ss0_size, ss1_size);
    /// let ss0 = &ss0[0..ss0_size];
    /// let ss1 = &ss1[0..ss1_size];
    /// assert_eq!(*ss0, *ss1);
    /// }
    /// ```
    #[cfg(ecc_dh)]
    pub fn shared_secret(&mut self, peer_key: &mut ECC, dout: &mut [u8]) -> Result<usize, i32> {
        let mut out_len = dout.len() as u32;
        let rc = unsafe {
            sys::wc_ecc_shared_secret(&mut self.wc_ecc_key,
                &mut peer_key.wc_ecc_key, dout.as_mut_ptr(), &mut out_len)
        };
        if rc < 0 {
            return Err(rc);
        }
        Ok(out_len as usize)
    }

    /// Compute the ECDH shared secret using this key's private component
    /// and the peer public point.
    ///
    /// # Parameters
    ///
    /// * `peer`: `ECCPoint` struct holding the public components of the peer
    ///   ECC key.
    /// * `dout`: Buffer in which to store the computed secret value.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to
    /// `dout` or Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ecc_dh)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let mut ecc0 = ECC::generate(32, &mut rng, None, None).expect("Error with generate()");
    /// let mut ecc1 = ECC::generate(32, &mut rng, None, None).expect("Error with generate()");
    /// let ecc1_point = ecc1.make_pub_to_point(None, None).expect("Error with make_pub_to_point()");
    /// let mut ss0 = [0u8; 128];
    /// let mut ss1 = [0u8; 128];
    /// ecc0.set_rng(&mut rng).expect("Error with set_rng()");
    /// ecc1.set_rng(&mut rng).expect("Error with set_rng()");
    /// let ss0_size = ecc0.shared_secret_ex(&ecc1_point, &mut ss0).expect("Error with shared_secret_ex()");
    /// let ss1_size = ecc1.shared_secret(&mut ecc0, &mut ss1).expect("Error with shared_secret()");
    /// assert_eq!(ss0_size, ss1_size);
    /// let ss0 = &ss0[0..ss0_size];
    /// let ss1 = &ss1[0..ss1_size];
    /// assert_eq!(*ss0, *ss1);
    /// }
    /// ```
    #[cfg(ecc_dh)]
    pub fn shared_secret_ex(&mut self, peer: &ECCPoint, dout: &mut [u8]) -> Result<usize, i32> {
        let mut out_len = dout.len() as u32;
        let rc = unsafe {
            sys::wc_ecc_shared_secret_ex(&mut self.wc_ecc_key,
                peer.wc_ecc_point, dout.as_mut_ptr(), &mut out_len)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(out_len as usize)
    }

    /// Sign a message digest using the ECC key.
    ///
    /// # Parameters
    ///
    /// * `din`: Message digest to sign.
    /// * `dout`: Buffer in which to store the signature.
    /// * `rng`: RNG struct to use for random number generation during signing.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to
    /// `dout` or Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ecc_sign)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let mut ecc = ECC::generate(32, &mut rng, None, None).expect("Error with generate()");
    /// let hash = [0x42u8; 32];
    /// let mut signature = [0u8; 128];
    /// let signature_length = ecc.sign_hash(&hash, &mut signature, &mut rng).expect("Error with sign_hash()");
    /// let signature = &mut signature[0..signature_length];
    /// let valid = ecc.verify_hash(&signature, &hash).expect("Error with verify_hash()");
    /// assert_eq!(valid, true);
    /// }
    /// ```
    #[cfg(ecc_sign)]
    pub fn sign_hash(&mut self, din: &[u8], dout: &mut [u8], rng: &mut RNG) -> Result<usize, i32> {
        let din_size = din.len() as u32;
        let mut dout_size = dout.len() as u32;
        let rc = unsafe {
            sys::wc_ecc_sign_hash(din.as_ptr(), din_size, dout.as_mut_ptr(),
                &mut dout_size, &mut rng.wc_rng, &mut self.wc_ecc_key)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(dout_size as usize)
    }

    /// Verify the ECC signature of a hash.
    ///
    /// # Parameters
    ///
    /// * `sig`: ECC signature.
    /// * `hash`: Message digest.
    ///
    /// # Returns
    ///
    /// Returns either Ok(valid) containing a flag for whether the signature is
    /// valid or Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(ecc_verify)]
    /// {
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let mut ecc = ECC::generate(32, &mut rng, None, None).expect("Error with generate()");
    /// let hash = [0x42u8; 32];
    /// let mut signature = [0u8; 128];
    /// let signature_length = ecc.sign_hash(&hash, &mut signature, &mut rng).expect("Error with sign_hash()");
    /// let signature = &mut signature[0..signature_length];
    /// let valid = ecc.verify_hash(&signature, &hash).expect("Error with verify_hash()");
    /// assert_eq!(valid, true);
    /// }
    /// ```
    #[cfg(ecc_verify)]
    pub fn verify_hash(&mut self, sig: &[u8], hash: &[u8]) -> Result<bool, i32> {
        let mut res: i32 = 0;
        let sig_len = sig.len() as u32;
        let hash_len = hash.len() as u32;
        let rc = unsafe {
            sys::wc_ecc_verify_hash(sig.as_ptr(), sig_len,
                hash.as_ptr(), hash_len, &mut res, &mut self.wc_ecc_key)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(res != 0)
    }
}

impl Drop for ECC {
    /// Safely free the underlying wolfSSL ECC context.
    ///
    /// This calls the `wc_ecc_key_free()` wolfssl library function.
    ///
    /// The Rust Drop trait guarantees that this method is called when the ECC
    /// struct goes out of scope, automatically cleaning up resources and
    /// preventing memory leaks.
    fn drop(&mut self) {
        unsafe { sys::wc_ecc_free(&mut self.wc_ecc_key); }
    }
}
