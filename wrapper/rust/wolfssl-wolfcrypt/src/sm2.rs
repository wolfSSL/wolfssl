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
This module provides a Rust wrapper for wolfCrypt SM2 functionality.
*/

#![cfg(sm2)]

use crate::ecc::ECC;
#[cfg(random)]
use crate::random::RNG;
use crate::sys;

/// An SM2 key backed by a wolfCrypt ECC key.
pub struct SM2 {
    key: ECC,
}

impl SM2 {
    /// SM2 key size in bytes.
    pub const KEY_SIZE: usize = sys::SM2_KEY_SIZE as usize;

    /// Default SM2 certificate signature identity.
    pub const CERT_SIG_ID: &'static [u8] = b"1234567812345678";

    /// wolfCrypt hash type identifier for SM3.
    pub const HASH_TYPE_SM3: u32 = sys::wc_HashType_WC_HASH_TYPE_SM3;

    /// No ECC operation flags.
    pub const FLAG_NONE: i32 = ECC::FLAG_NONE;

    /// Enable the ECC cofactor flag.
    pub const FLAG_COFACTOR: i32 = ECC::FLAG_COFACTOR;

    /// Enable the ECC decrypt/sign flag.
    pub const FLAG_DEC_SIGN: i32 = ECC::FLAG_DEC_SIGN;

    /// Generate a new SM2 key using the supplied random number generator.
    #[cfg(random)]
    pub fn generate(rng: &RNG, flags: i32) -> Result<Self, i32> {
        let key = ECC::new()?;
        let rc = unsafe { sys::wc_ecc_sm2_make_key(rng.wc_rng, key.wc_ecc_key, flags) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(Self { key })
    }

    /// Derive a shared secret into the caller-supplied output buffer.
    #[cfg(sm2_dh)]
    pub fn shared_secret(&mut self, peer: &mut SM2, out: &mut [u8]) -> Result<usize, i32> {
        let mut out_len = crate::buffer_len_to_u32(out.len())?;
        let rc = unsafe {
            sys::wc_ecc_sm2_shared_secret(
                self.key.wc_ecc_key,
                peer.key.wc_ecc_key,
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(out_len as usize)
    }

    /// Create an SM2 digest for an identity and message.
    #[cfg(sm2_digest)]
    pub fn create_digest(
        &mut self,
        id: &[u8],
        message: &[u8],
        hash_type: u32,
        out: &mut [u8],
    ) -> Result<(), i32> {
        let id_len = u16::try_from(id.len()).map_err(|_| sys::wolfCrypt_ErrorCodes_BUFFER_E)?;
        let message_len = crate::buffer_len_to_i32(message.len())?;
        let out_len = crate::buffer_len_to_i32(out.len())?;
        let rc = unsafe {
            sys::wc_ecc_sm2_create_digest(
                id.as_ptr(),
                id_len,
                message.as_ptr(),
                message_len,
                hash_type as sys::wc_HashType,
                out.as_mut_ptr(),
                out_len,
                self.key.wc_ecc_key,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Sign a hash with this SM2 key and return the DER signature length.
    #[cfg(all(sm2_sign, random))]
    pub fn sign_hash(
        &mut self,
        hash: &[u8],
        signature: &mut [u8],
        rng: &RNG,
    ) -> Result<usize, i32> {
        let hash_len = crate::buffer_len_to_u32(hash.len())?;
        let mut signature_len = crate::buffer_len_to_u32(signature.len())?;
        let rc = unsafe {
            sys::wc_ecc_sm2_sign_hash(
                hash.as_ptr(),
                hash_len,
                signature.as_mut_ptr(),
                &mut signature_len,
                rng.wc_rng,
                self.key.wc_ecc_key,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(signature_len as usize)
    }

    /// Verify a DER-encoded SM2 signature against a hash.
    #[cfg(sm2_verify)]
    pub fn verify_hash(&mut self, signature: &[u8], hash: &[u8]) -> Result<bool, i32> {
        let signature_len = crate::buffer_len_to_u32(signature.len())?;
        let hash_len = crate::buffer_len_to_u32(hash.len())?;
        let mut valid = 0;
        let rc = unsafe {
            sys::wc_ecc_sm2_verify_hash(
                signature.as_ptr(),
                signature_len,
                hash.as_ptr(),
                hash_len,
                &mut valid,
                self.key.wc_ecc_key,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(valid != 0)
    }
}
