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
ECDSA trait impls for the RustCrypto `signature` crate.

Provides per-curve wrapper types (`P256SigningKey`, `P256VerifyingKey`,
`P256Signature`, etc.) over the inherent [`crate::ecc::ECC`] wrapper. Each
curve pairs with its canonical hash algorithm (P-256 with SHA-256, P-384 with
SHA-384, P-521 with SHA-512) and produces fixed-size `r‖s` signatures
matching the conventions used by the RustCrypto `ecdsa` crate.

Signing and verifying use the high-level `wc_SignatureGenerate` /
`wc_SignatureVerify` wolfCrypt entry points, which hash the raw message
internally and emit/consume DER-encoded ECDSA signatures; the wrapper
converts between DER and fixed `r‖s` via `wc_ecc_sig_to_rs` and
`wc_ecc_rs_raw_to_sig`.
*/

#![cfg(all(feature = "signature", ecc, ecc_sign, ecc_verify, ecc_import, ecc_export, ecc_curve_ids, random))]

use core::ffi::c_void;
use core::mem::size_of;

use signature::{Error, Keypair, SignatureEncoding, SignerMut, Verifier};

use crate::ecc::ECC;
use crate::random::RNG;
use crate::sys;

/// Build a fixed `r‖s` signature buffer from DER bytes produced by wolfCrypt.
fn der_to_rs<const SIG_SIZE: usize, const FIELD_SIZE: usize>(
    der: &[u8],
) -> Result<[u8; SIG_SIZE], Error> {
    debug_assert_eq!(SIG_SIZE, 2 * FIELD_SIZE);
    let mut r_buf = [0u8; FIELD_SIZE];
    let mut s_buf = [0u8; FIELD_SIZE];
    let mut r_len = FIELD_SIZE as u32;
    let mut s_len = FIELD_SIZE as u32;
    let rc = unsafe {
        sys::wc_ecc_sig_to_rs(
            der.as_ptr(), der.len() as u32,
            r_buf.as_mut_ptr(), &mut r_len,
            s_buf.as_mut_ptr(), &mut s_len,
        )
    };
    if rc != 0 {
        return Err(Error::new());
    }
    let r_len = r_len as usize;
    let s_len = s_len as usize;
    if r_len > FIELD_SIZE || s_len > FIELD_SIZE {
        return Err(Error::new());
    }
    let mut out = [0u8; SIG_SIZE];
    out[FIELD_SIZE - r_len..FIELD_SIZE].copy_from_slice(&r_buf[..r_len]);
    out[SIG_SIZE - s_len..SIG_SIZE].copy_from_slice(&s_buf[..s_len]);
    Ok(out)
}

/// Build a DER signature from fixed `r‖s` bytes.
fn rs_to_der<const FIELD_SIZE: usize>(
    rs: &[u8],
    der_out: &mut [u8],
) -> Result<usize, Error> {
    if rs.len() != 2 * FIELD_SIZE {
        return Err(Error::new());
    }
    let (r, s) = rs.split_at(FIELD_SIZE);
    let mut der_len = der_out.len() as u32;
    let rc = unsafe {
        sys::wc_ecc_rs_raw_to_sig(
            r.as_ptr(), FIELD_SIZE as u32,
            s.as_ptr(), FIELD_SIZE as u32,
            der_out.as_mut_ptr(), &mut der_len,
        )
    };
    if rc != 0 {
        return Err(Error::new());
    }
    Ok(der_len as usize)
}

macro_rules! define_ecdsa_curve {
    (
        $(#[$meta:meta])*
        ($signing_key:ident, $verifying_key:ident, $signature:ident),
        field_size = $field_size:literal,
        sig_size = $sig_size:literal,
        x963_size = $x963_size:literal,
        der_max = $der_max:literal,
        curve_id = $curve_id:expr,
        hash_type = $hash_type:expr,
        hash_cfg = $hash_cfg:meta $(,)?
    ) => {
        /// Fixed-size ECDSA signature in `r‖s` form.
        $(#[$meta])*
        #[cfg($hash_cfg)]
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct $signature([u8; $sig_size]);

        #[cfg($hash_cfg)]
        impl $signature {
            /// Size in bytes of the fixed `r‖s` encoding.
            pub const BYTE_SIZE: usize = $sig_size;

            /// Construct a signature from raw `r‖s` bytes.
            pub const fn from_bytes(bytes: [u8; $sig_size]) -> Self {
                Self(bytes)
            }

            /// Return the raw `r‖s` bytes.
            pub const fn to_bytes(&self) -> [u8; $sig_size] {
                self.0
            }
        }

        #[cfg($hash_cfg)]
        impl AsRef<[u8]> for $signature {
            fn as_ref(&self) -> &[u8] { &self.0 }
        }

        #[cfg($hash_cfg)]
        impl TryFrom<&[u8]> for $signature {
            type Error = Error;
            fn try_from(bytes: &[u8]) -> Result<Self, Error> {
                let arr: [u8; $sig_size] = bytes.try_into().map_err(|_| Error::new())?;
                Ok(Self(arr))
            }
        }

        #[cfg($hash_cfg)]
        impl From<$signature> for [u8; $sig_size] {
            fn from(sig: $signature) -> Self { sig.0 }
        }

        #[cfg($hash_cfg)]
        impl SignatureEncoding for $signature {
            type Repr = [u8; $sig_size];
        }

        /// ECDSA signing key (private key + owned RNG + cached public key).
        $(#[$meta])*
        #[cfg($hash_cfg)]
        pub struct $signing_key {
            inner: ECC,
            rng: RNG,
            pub_bytes: [u8; $x963_size],
        }

        #[cfg($hash_cfg)]
        impl $signing_key {
            /// Byte length of the uncompressed X9.63 public key encoding.
            pub const PUB_KEY_SIZE: usize = $x963_size;

            /// Private-scalar byte length (`d`, curve field size).
            pub const SCALAR_SIZE: usize = $field_size;

            /// Generate a fresh signing key using the provided RNG.
            pub fn generate(mut rng: RNG) -> Result<Self, i32> {
                let ecc = ECC::generate_ex(
                    $field_size as i32,
                    &mut rng,
                    $curve_id,
                    None, None,
                )?;
                Self::from_ecc(ecc, rng)
            }

            /// Import a signing key from unsigned big-endian public
            /// coordinates `qx`, `qy` and private scalar `d`, each of exactly
            /// the curve's field size in bytes.
            pub fn import_unsigned(
                qx: &[u8; $field_size],
                qy: &[u8; $field_size],
                d: &[u8; $field_size],
                rng: RNG,
            ) -> Result<Self, i32> {
                let ecc = ECC::import_unsigned(qx, qy, d, $curve_id, None, None)?;
                Self::from_ecc(ecc, rng)
            }

            /// Import a signing key from an uncompressed X9.63 public key
            /// (leading `0x04` byte + `x‖y`) and a matching unsigned
            /// big-endian private scalar `d`.
            pub fn import_x963(
                public_x963: &[u8; $x963_size],
                d: &[u8; $field_size],
                rng: RNG,
            ) -> Result<Self, i32> {
                let ecc = ECC::import_private_key_ex(
                    d, public_x963, $curve_id, None, None,
                )?;
                Self::from_ecc(ecc, rng)
            }

            /// Borrow the inner [`ECC`] key for operations not covered by the
            /// signature traits.
            pub fn as_ecc(&self) -> &ECC { &self.inner }

            /// Consume the signing key and return its `ECC` and `RNG` parts.
            pub fn into_parts(self) -> (ECC, RNG) {
                (self.inner, self.rng)
            }

            /// Helper that caches the X9.63 public key bytes from an already
            /// populated [`ECC`] and pairs it with the given `rng`.
            fn from_ecc(mut ecc: ECC, rng: RNG) -> Result<Self, i32> {
                let mut pub_bytes = [0u8; $x963_size];
                let written = ecc.export_x963(&mut pub_bytes)?;
                if written != $x963_size {
                    return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
                }
                Ok(Self { inner: ecc, rng, pub_bytes })
            }
        }

        #[cfg($hash_cfg)]
        impl Keypair for $signing_key {
            type VerifyingKey = $verifying_key;
            fn verifying_key(&self) -> $verifying_key {
                $verifying_key { pub_bytes: self.pub_bytes }
            }
        }

        #[cfg($hash_cfg)]
        impl SignerMut<$signature> for $signing_key {
            fn try_sign(&mut self, msg: &[u8]) -> Result<$signature, Error> {
                let mut der = [0u8; $der_max];
                let mut der_len: u32 = der.len() as u32;
                let msg_len: u32 = msg.len().try_into().map_err(|_| Error::new())?;
                let rc = unsafe {
                    sys::wc_SignatureGenerate(
                        $hash_type,
                        sys::wc_SignatureType_WC_SIGNATURE_TYPE_ECC,
                        msg.as_ptr(), msg_len,
                        der.as_mut_ptr(), &mut der_len,
                        &mut self.inner.wc_ecc_key as *mut _ as *mut c_void,
                        size_of::<sys::ecc_key>() as u32,
                        &mut self.rng.wc_rng,
                    )
                };
                if rc != 0 {
                    return Err(Error::new());
                }
                let rs = der_to_rs::<$sig_size, $field_size>(&der[..der_len as usize])?;
                Ok($signature(rs))
            }
        }

        /// ECDSA verifying key. Owns the uncompressed X9.63 public key bytes
        /// and instantiates a short-lived [`ECC`] on each verification.
        $(#[$meta])*
        #[cfg($hash_cfg)]
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct $verifying_key {
            pub_bytes: [u8; $x963_size],
        }

        #[cfg($hash_cfg)]
        impl $verifying_key {
            /// Byte length of the uncompressed X9.63 public key encoding.
            pub const BYTE_SIZE: usize = $x963_size;

            /// Construct a verifying key from its uncompressed X9.63 bytes.
            ///
            /// The buffer must start with `0x04` followed by `x‖y` (each
            /// `FIELD_SIZE` bytes).
            pub const fn from_bytes(bytes: [u8; $x963_size]) -> Self {
                Self { pub_bytes: bytes }
            }

            /// Return the uncompressed X9.63 public key bytes.
            pub const fn to_bytes(&self) -> [u8; $x963_size] {
                self.pub_bytes
            }
        }

        #[cfg($hash_cfg)]
        impl AsRef<[u8]> for $verifying_key {
            fn as_ref(&self) -> &[u8] { &self.pub_bytes }
        }

        #[cfg($hash_cfg)]
        impl TryFrom<&[u8]> for $verifying_key {
            type Error = Error;
            fn try_from(bytes: &[u8]) -> Result<Self, Error> {
                let arr: [u8; $x963_size] =
                    bytes.try_into().map_err(|_| Error::new())?;
                Ok(Self { pub_bytes: arr })
            }
        }

        #[cfg($hash_cfg)]
        impl Verifier<$signature> for $verifying_key {
            fn verify(&self, msg: &[u8], sig: &$signature) -> Result<(), Error> {
                let mut der = [0u8; $der_max];
                let der_len = rs_to_der::<$field_size>(&sig.0, &mut der)?;
                let mut key = ECC::import_x963_ex(&self.pub_bytes, $curve_id, None, None)
                    .map_err(|_| Error::new())?;
                let msg_len: u32 = msg.len().try_into().map_err(|_| Error::new())?;
                let rc = unsafe {
                    sys::wc_SignatureVerify(
                        $hash_type,
                        sys::wc_SignatureType_WC_SIGNATURE_TYPE_ECC,
                        msg.as_ptr(), msg_len,
                        der.as_ptr(), der_len as u32,
                        &mut key.wc_ecc_key as *mut _ as *mut c_void,
                        size_of::<sys::ecc_key>() as u32,
                    )
                };
                if rc != 0 {
                    return Err(Error::new());
                }
                Ok(())
            }
        }
    };
}

define_ecdsa_curve! {
    /// NIST P-256 (secp256r1) paired with SHA-256.
    (P256SigningKey, P256VerifyingKey, P256Signature),
    field_size = 32,
    sig_size = 64,
    x963_size = 65,
    der_max = 72,
    curve_id = sys::ecc_curve_ids_ECC_SECP256R1,
    hash_type = sys::wc_HashType_WC_HASH_TYPE_SHA256,
    hash_cfg = sha256,
}

define_ecdsa_curve! {
    /// NIST P-384 (secp384r1) paired with SHA-384.
    (P384SigningKey, P384VerifyingKey, P384Signature),
    field_size = 48,
    sig_size = 96,
    x963_size = 97,
    der_max = 104,
    curve_id = sys::ecc_curve_ids_ECC_SECP384R1,
    hash_type = sys::wc_HashType_WC_HASH_TYPE_SHA384,
    hash_cfg = sha384,
}

define_ecdsa_curve! {
    /// NIST P-521 (secp521r1) paired with SHA-512.
    (P521SigningKey, P521VerifyingKey, P521Signature),
    field_size = 66,
    sig_size = 132,
    x963_size = 133,
    der_max = 141,
    curve_id = sys::ecc_curve_ids_ECC_SECP521R1,
    hash_type = sys::wc_HashType_WC_HASH_TYPE_SHA512,
    hash_cfg = sha512,
}
