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
RSA PKCS#1 v1.5 trait impls for the RustCrypto `signature` crate.

Provides fixed-size const-generic wrapper types over [`crate::rsa::RSA`] so
RSA PKCS#1 v1.5 signing/verifying fits cleanly into `no_std` without `alloc`:

- [`SigningKey<H, N>`] / [`VerifyingKey<H, N>`] — `H` is a [`Hash`] marker
  selecting the digest algorithm, `N` is the modulus size in bytes (e.g.
  `256` for RSA-2048).
- [`Signature<N>`] — fixed-size `[u8; N]` wrapper implementing
  [`signature::SignatureEncoding`].

Signing and verifying delegate to `wc_SignatureGenerate` and
`wc_SignatureVerify` with `WC_SIGNATURE_TYPE_RSA_W_ENC`, which hash the raw
message and apply the PKCS#1 v1.5 DigestInfo encoding internally.
*/

#![cfg(all(feature = "signature", rsa, random))]

use core::ffi::c_void;
use core::marker::PhantomData;
use core::mem::size_of;

use signature::{Error, Keypair, SignatureEncoding, SignerMut, Verifier};

use crate::random::RNG;
use crate::rsa::RSA;
use crate::sys;

mod private {
    pub trait Sealed {}
}

/// Marker trait selecting the digest algorithm used by PKCS#1 v1.5 DigestInfo
/// encoding.
pub trait Hash: private::Sealed {
    /// wolfCrypt hash algorithm identifier.
    const HASH_TYPE: u32;
}

/// SHA-256 digest selection for PKCS#1 v1.5.
#[cfg(sha256)]
pub enum Sha256 {}
#[cfg(sha256)]
impl private::Sealed for Sha256 {}
#[cfg(sha256)]
impl Hash for Sha256 {
    const HASH_TYPE: u32 = sys::wc_HashType_WC_HASH_TYPE_SHA256;
}

/// SHA-384 digest selection for PKCS#1 v1.5.
#[cfg(sha384)]
pub enum Sha384 {}
#[cfg(sha384)]
impl private::Sealed for Sha384 {}
#[cfg(sha384)]
impl Hash for Sha384 {
    const HASH_TYPE: u32 = sys::wc_HashType_WC_HASH_TYPE_SHA384;
}

/// SHA-512 digest selection for PKCS#1 v1.5.
#[cfg(sha512)]
pub enum Sha512 {}
#[cfg(sha512)]
impl private::Sealed for Sha512 {}
#[cfg(sha512)]
impl Hash for Sha512 {
    const HASH_TYPE: u32 = sys::wc_HashType_WC_HASH_TYPE_SHA512;
}

/// Fixed-size RSA PKCS#1 v1.5 signature. `N` is the modulus size in bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signature<const N: usize>([u8; N]);

impl<const N: usize> Signature<N> {
    /// Construct a signature from its raw bytes.
    pub const fn from_bytes(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Return the raw signature bytes.
    pub const fn to_bytes(&self) -> [u8; N] {
        self.0
    }
}

impl<const N: usize> AsRef<[u8]> for Signature<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> TryFrom<&[u8]> for Signature<N> {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        let arr: [u8; N] = bytes.try_into().map_err(|_| Error::new())?;
        Ok(Self(arr))
    }
}

impl<const N: usize> From<Signature<N>> for [u8; N] {
    fn from(sig: Signature<N>) -> Self {
        sig.0
    }
}

impl<const N: usize> SignatureEncoding for Signature<N> {
    type Repr = [u8; N];
}

fn check_modulus_size(rsa: &RSA, expected: usize) -> Result<(), i32> {
    let actual = rsa.get_encrypt_size()?;
    if actual != expected {
        return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
    }
    Ok(())
}

/// RSA PKCS#1 v1.5 signing key.
///
/// `H` selects the hash used in DigestInfo encoding; `N` is the expected
/// modulus size in bytes (e.g. `256` for RSA-2048, `384` for RSA-3072).
pub struct SigningKey<H: Hash, const N: usize> {
    inner: RSA,
    rng: RNG,
    _hash: PhantomData<H>,
}

impl<H: Hash, const N: usize> SigningKey<H, N> {
    /// Generate a fresh `N * 8`-bit RSA key with public exponent 65537.
    #[cfg(rsa_keygen)]
    pub fn generate(mut rng: RNG) -> Result<Self, i32> {
        let bits: i32 = (N * 8).try_into().map_err(|_| sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG)?;
        let rsa = RSA::generate(bits, 65537, &mut rng)?;
        Ok(Self { inner: rsa, rng, _hash: PhantomData })
    }

    /// Adopt an existing [`RSA`] key, verifying that its modulus size in
    /// bytes matches `N`.
    pub fn from_rsa(rsa: RSA, rng: RNG) -> Result<Self, i32> {
        check_modulus_size(&rsa, N)?;
        Ok(Self { inner: rsa, rng, _hash: PhantomData })
    }

    /// Borrow the inner [`RSA`] key.
    pub fn as_rsa(&self) -> &RSA {
        &self.inner
    }

    /// Consume the signing key and return its `RSA` and `RNG` parts.
    pub fn into_parts(self) -> (RSA, RNG) {
        (self.inner, self.rng)
    }
}

impl<H: Hash, const N: usize> SignerMut<Signature<N>> for SigningKey<H, N> {
    fn try_sign(&mut self, msg: &[u8]) -> Result<Signature<N>, Error> {
        let mut sig = [0u8; N];
        let mut sig_len: u32 = N as u32;
        let msg_len: u32 = msg.len().try_into().map_err(|_| Error::new())?;
        let rc = unsafe {
            sys::wc_SignatureGenerate(
                H::HASH_TYPE,
                sys::wc_SignatureType_WC_SIGNATURE_TYPE_RSA_W_ENC,
                msg.as_ptr(), msg_len,
                sig.as_mut_ptr(), &mut sig_len,
                &mut self.inner.wc_rsakey as *mut _ as *mut c_void,
                size_of::<sys::RsaKey>() as u32,
                &mut self.rng.wc_rng,
            )
        };
        if rc != 0 || sig_len as usize != N {
            return Err(Error::new());
        }
        Ok(Signature(sig))
    }
}

/// Maximum number of bytes that the E exponent can use. An error is returned
/// if longer exponent byte arrays are provided.
const MAX_E_LEN: usize = 8;

/// RSA PKCS#1 v1.5 verifying key.
///
/// Owns a copy of the public key as raw `(n, e)` bytes and instantiates a
/// short-lived [`RSA`] on each verification. `H` selects the hash algorithm
/// used in DigestInfo encoding; `N` is the modulus size in bytes.
pub struct VerifyingKey<H: Hash, const N: usize> {
    n: [u8; N],
    e: [u8; MAX_E_LEN],
    e_len: u8,
    _hash: PhantomData<H>,
}

// Manual impls avoid requiring `H: Clone`/`Copy`/etc. — `H` is a marker
// (uninhabited enum) that only appears inside `PhantomData`.
impl<H: Hash, const N: usize> Clone for VerifyingKey<H, N> {
    fn clone(&self) -> Self { *self }
}
impl<H: Hash, const N: usize> Copy for VerifyingKey<H, N> {}
impl<H: Hash, const N: usize> core::fmt::Debug for VerifyingKey<H, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerifyingKey")
            .field("n", &&self.n[..])
            .field("e", &self.exponent())
            .finish()
    }
}
impl<H: Hash, const N: usize> PartialEq for VerifyingKey<H, N> {
    fn eq(&self, other: &Self) -> bool {
        self.n == other.n && self.exponent() == other.exponent()
    }
}
impl<H: Hash, const N: usize> Eq for VerifyingKey<H, N> {}

impl<H: Hash, const N: usize> VerifyingKey<H, N> {
    /// Construct a verifying key from raw big-endian modulus (`n`) and
    /// public exponent (`e`) bytes.
    pub fn from_components(n: &[u8], e: &[u8]) -> Result<Self, Error> {
        if n.len() != N || e.is_empty() || e.len() > MAX_E_LEN {
            return Err(Error::new());
        }
        let mut n_arr = [0u8; N];
        n_arr.copy_from_slice(n);
        let mut e_arr = [0u8; MAX_E_LEN];
        e_arr[..e.len()].copy_from_slice(e);
        Ok(Self {
            n: n_arr,
            e: e_arr,
            e_len: e.len() as u8,
            _hash: PhantomData,
        })
    }

    /// Adopt an existing [`RSA`] public key, verifying its modulus size in
    /// bytes matches `N`.
    pub fn from_rsa(rsa: RSA) -> Result<Self, i32> {
        check_modulus_size(&rsa, N)?;
        let mut n = [0u8; N];
        let mut e = [0u8; MAX_E_LEN];
        let mut n_len: u32 = n.len() as u32;
        let mut e_len: u32 = e.len() as u32;
        let rc = unsafe {
            sys::wc_RsaFlattenPublicKey(
                &rsa.wc_rsakey,
                e.as_mut_ptr(), &mut e_len,
                n.as_mut_ptr(), &mut n_len,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        if (n_len as usize) != N || e_len == 0 || (e_len as usize) > MAX_E_LEN {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        Ok(Self {
            n,
            e,
            e_len: e_len as u8,
            _hash: PhantomData,
        })
    }

    /// Construct a verifying key from a DER-encoded `SubjectPublicKeyInfo`
    /// / PKCS#1 public key.
    pub fn from_public_der(der: &[u8]) -> Result<Self, i32> {
        let rsa = RSA::new_public_from_der(der)?;
        Self::from_rsa(rsa)
    }

    /// Return the raw modulus bytes.
    pub const fn modulus(&self) -> &[u8; N] {
        &self.n
    }

    /// Return the raw public exponent bytes.
    pub fn exponent(&self) -> &[u8] {
        &self.e[..self.e_len as usize]
    }
}

impl<H: Hash, const N: usize> Verifier<Signature<N>> for VerifyingKey<H, N> {
    fn verify(&self, msg: &[u8], signature: &Signature<N>) -> Result<(), Error> {
        let msg_len: u32 = msg.len().try_into().map_err(|_| Error::new())?;
        let mut rsa = RSA::new_public_from_raw(&self.n, self.exponent())
            .map_err(|_| Error::new())?;
        let rc = unsafe {
            sys::wc_SignatureVerify(
                H::HASH_TYPE,
                sys::wc_SignatureType_WC_SIGNATURE_TYPE_RSA_W_ENC,
                msg.as_ptr(), msg_len,
                signature.0.as_ptr(), N as u32,
                &mut rsa.wc_rsakey as *mut _ as *mut c_void,
                size_of::<sys::RsaKey>() as u32,
            )
        };
        if rc != 0 {
            return Err(Error::new());
        }
        Ok(())
    }
}

impl<H: Hash, const N: usize> Keypair for SigningKey<H, N> {
    type VerifyingKey = VerifyingKey<H, N>;
    fn verifying_key(&self) -> VerifyingKey<H, N> {
        let mut n = [0u8; N];
        let mut e = [0u8; MAX_E_LEN];
        let mut n_len: u32 = n.len() as u32;
        let mut e_len: u32 = e.len() as u32;
        let rc = unsafe {
            sys::wc_RsaFlattenPublicKey(
                &self.inner.wc_rsakey,
                e.as_mut_ptr(), &mut e_len,
                n.as_mut_ptr(), &mut n_len,
            )
        };
        if rc != 0 {
            panic!("wc_RsaFlattenPublicKey failed: {rc}");
        }
        if (n_len as usize) != N || e_len == 0 || (e_len as usize) > MAX_E_LEN {
            panic!("wc_RsaFlattenPublicKey returned unexpected lengths: e_len: {e_len}, n_len: {n_len}");
        }
        VerifyingKey {
            n,
            e,
            e_len: e_len as u8,
            _hash: PhantomData,
        }
    }
}
