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
RSA OAEP (PKCS#1 v2.2) encryption / decryption with const-generic wrapper
types over [`crate::rsa::RSA`].

This module mirrors the style of [`crate::rsa_pkcs1v15`]: a [`Hash`] marker
selects the digest algorithm used by OAEP and its MGF1, and `N` is the
modulus size in bytes (e.g. `256` for RSA-2048, `384` for RSA-3072).

- [`EncryptingKey<H, N>`] / [`DecryptingKey<H, N>`] — RSA public/private key
  wrappers parameterised by the OAEP hash and modulus size.
- [`Ciphertext<N>`] — fixed-size `[u8; N]` ciphertext wrapper.

# RustCrypto traits

The widely-used encryption / decryption traits in the RustCrypto ecosystem
(`rsa::traits::RandomizedEncryptor`, `rsa::traits::Decryptor`) live in the
`rsa` crate and are sealed, so external crates cannot implement them. This
module therefore provides only the natural inherent-method API, matching the
shape of those traits without claiming conformance.

# Example

```rust
#[cfg(all(random, sha256, rsa_keygen, rsa_oaep))]
{
use wolfssl_wolfcrypt::random::RNG;
use wolfssl_wolfcrypt::rsa_oaep::{Sha256, EncryptingKey, DecryptingKey};

let pad_rng = RNG::new().expect("RNG");
let mut dk: DecryptingKey<Sha256, 256> = DecryptingKey::generate(RNG::new().expect("RNG")).expect("dk");
let ek: EncryptingKey<Sha256, 256> = dk.encrypting_key().expect("ek");

let msg = b"hello, OAEP";
let ct = ek.encrypt(&pad_rng, msg).expect("encrypt");
let mut buf = [0u8; 256];
let n = dk.decrypt(&ct, &mut buf).expect("decrypt");
assert_eq!(&buf[..n], msg);
}
```
*/

#![cfg(all(rsa, rsa_oaep))]

use core::marker::PhantomData;

use crate::rsa::RSA;
use crate::sys;
#[cfg(random)]
use crate::random::RNG;

mod private {
    pub trait Sealed {}
}

/// Marker trait selecting the digest algorithm used by OAEP (both the label
/// hash and the MGF1 hash).
pub trait Hash: private::Sealed {
    /// wolfCrypt hash algorithm identifier (one of `WC_HASH_TYPE_*`).
    const HASH_TYPE: u32;
    /// wolfCrypt MGF1 identifier matching `HASH_TYPE`.
    const MGF: i32;
}

/// SHA-1 digest selection for OAEP / MGF1.
///
/// SHA-1 is included for interoperability only and is **not recommended** for
/// new designs.
#[cfg(sha)]
pub enum Sha1 {}
#[cfg(sha)]
impl private::Sealed for Sha1 {}
#[cfg(sha)]
impl Hash for Sha1 {
    const HASH_TYPE: u32 = sys::wc_HashType_WC_HASH_TYPE_SHA;
    const MGF: i32 = sys::WC_MGF1SHA1 as i32;
}

/// SHA-224 digest selection for OAEP / MGF1.
#[cfg(sha224)]
pub enum Sha224 {}
#[cfg(sha224)]
impl private::Sealed for Sha224 {}
#[cfg(sha224)]
impl Hash for Sha224 {
    const HASH_TYPE: u32 = sys::wc_HashType_WC_HASH_TYPE_SHA224;
    const MGF: i32 = sys::WC_MGF1SHA224 as i32;
}

/// SHA-256 digest selection for OAEP / MGF1.
#[cfg(sha256)]
pub enum Sha256 {}
#[cfg(sha256)]
impl private::Sealed for Sha256 {}
#[cfg(sha256)]
impl Hash for Sha256 {
    const HASH_TYPE: u32 = sys::wc_HashType_WC_HASH_TYPE_SHA256;
    const MGF: i32 = sys::WC_MGF1SHA256 as i32;
}

/// SHA-384 digest selection for OAEP / MGF1.
#[cfg(sha384)]
pub enum Sha384 {}
#[cfg(sha384)]
impl private::Sealed for Sha384 {}
#[cfg(sha384)]
impl Hash for Sha384 {
    const HASH_TYPE: u32 = sys::wc_HashType_WC_HASH_TYPE_SHA384;
    const MGF: i32 = sys::WC_MGF1SHA384 as i32;
}

/// SHA-512 digest selection for OAEP / MGF1.
#[cfg(sha512)]
pub enum Sha512 {}
#[cfg(sha512)]
impl private::Sealed for Sha512 {}
#[cfg(sha512)]
impl Hash for Sha512 {
    const HASH_TYPE: u32 = sys::wc_HashType_WC_HASH_TYPE_SHA512;
    const MGF: i32 = sys::WC_MGF1SHA512 as i32;
}

/// Fixed-size RSAES-OAEP ciphertext. `N` is the modulus size in bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ciphertext<const N: usize>([u8; N]);

impl<const N: usize> Ciphertext<N> {
    /// Construct a ciphertext from its raw bytes.
    pub const fn from_bytes(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Return the raw ciphertext bytes.
    pub const fn to_bytes(&self) -> [u8; N] {
        self.0
    }
}

impl<const N: usize> AsRef<[u8]> for Ciphertext<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> TryFrom<&[u8]> for Ciphertext<N> {
    type Error = i32;
    fn try_from(bytes: &[u8]) -> Result<Self, i32> {
        let arr: [u8; N] = bytes.try_into()
            .map_err(|_| sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG)?;
        Ok(Self(arr))
    }
}

impl<const N: usize> From<Ciphertext<N>> for [u8; N] {
    fn from(ct: Ciphertext<N>) -> Self {
        ct.0
    }
}

fn check_modulus_size(rsa: &RSA, expected: usize) -> Result<(), i32> {
    let actual = rsa.get_encrypt_size()?;
    if actual != expected {
        return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
    }
    Ok(())
}

/// Maximum number of bytes that the public exponent `e` can occupy.
const MAX_E_LEN: usize = 8;

/// RSA OAEP encrypting (public) key.
///
/// Owns a copy of the public key as raw `(n, e)` bytes and instantiates a
/// short-lived [`RSA`] on each encryption. `H` selects the OAEP hash; `N` is
/// the modulus size in bytes.
pub struct EncryptingKey<H: Hash, const N: usize> {
    n: [u8; N],
    e: [u8; MAX_E_LEN],
    e_len: u8,
    _hash: PhantomData<H>,
}

impl<H: Hash, const N: usize> Clone for EncryptingKey<H, N> {
    fn clone(&self) -> Self { *self }
}
impl<H: Hash, const N: usize> Copy for EncryptingKey<H, N> {}
impl<H: Hash, const N: usize> core::fmt::Debug for EncryptingKey<H, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EncryptingKey")
            .field("n", &&self.n[..])
            .field("e", &self.exponent())
            .finish()
    }
}
impl<H: Hash, const N: usize> PartialEq for EncryptingKey<H, N> {
    fn eq(&self, other: &Self) -> bool {
        self.n == other.n && self.exponent() == other.exponent()
    }
}
impl<H: Hash, const N: usize> Eq for EncryptingKey<H, N> {}

impl<H: Hash, const N: usize> EncryptingKey<H, N> {
    /// Construct an encrypting key from raw big-endian modulus (`n`) and
    /// public exponent (`e`) bytes.
    pub fn from_components(n: &[u8], e: &[u8]) -> Result<Self, i32> {
        if n.len() != N || e.is_empty() || e.len() > MAX_E_LEN {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
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

    /// Adopt the public part of an existing [`RSA`] key, verifying its
    /// modulus size in bytes matches `N`.
    pub fn from_rsa(rsa: &RSA) -> Result<Self, i32> {
        check_modulus_size(rsa, N)?;
        let mut n = [0u8; N];
        let mut e = [0u8; MAX_E_LEN];
        let mut n_len: u32 = n.len() as u32;
        let mut e_len: u32 = e.len() as u32;
        #[cfg(rsa_const_api)]
        let key = &rsa.wc_rsakey;
        // SAFETY: older wolfSSL declared the first arg as non-const, but the
        // function only reads from the key (newer versions declare it const).
        #[cfg(not(rsa_const_api))]
        let key = core::ptr::addr_of!(rsa.wc_rsakey) as *mut sys::RsaKey;
        let rc = unsafe {
            sys::wc_RsaFlattenPublicKey(
                key,
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

    /// Construct an encrypting key from a DER-encoded `SubjectPublicKeyInfo`
    /// / PKCS#1 public key.
    pub fn from_public_der(der: &[u8]) -> Result<Self, i32> {
        let rsa = RSA::new_public_from_der(der)?;
        Self::from_rsa(&rsa)
    }

    /// Return the raw modulus bytes.
    pub const fn modulus(&self) -> &[u8; N] {
        &self.n
    }

    /// Return the raw public exponent bytes.
    pub fn exponent(&self) -> &[u8] {
        &self.e[..self.e_len as usize]
    }

    /// Encrypt `msg` with RSAES-OAEP, returning the fixed-size ciphertext.
    #[cfg(random)]
    pub fn encrypt(&self, rng: &RNG, msg: &[u8]) -> Result<Ciphertext<N>, i32> {
        self.encrypt_inner(rng, msg, None)
    }

    /// Encrypt `msg` with RSAES-OAEP using an associated `label`, returning
    /// the fixed-size ciphertext.
    #[cfg(random)]
    pub fn encrypt_with_label(&self, rng: &RNG, msg: &[u8], label: &[u8]) -> Result<Ciphertext<N>, i32> {
        self.encrypt_inner(rng, msg, Some(label))
    }

    #[cfg(random)]
    fn encrypt_inner(&self, rng: &RNG, msg: &[u8], label: Option<&[u8]>) -> Result<Ciphertext<N>, i32> {
        let mut rsa = RSA::new_public_from_raw(&self.n, self.exponent())?;
        let mut out = [0u8; N];
        let len = rsa.public_encrypt_oaep_ex(msg, &mut out, H::HASH_TYPE, H::MGF, label, rng)?;
        if len != N {
            return Err(sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        Ok(Ciphertext(out))
    }
}

/// RSA OAEP decrypting (private) key.
///
/// `H` selects the OAEP hash; `N` is the expected modulus size in bytes
/// (e.g. `256` for RSA-2048, `384` for RSA-3072).
pub struct DecryptingKey<H: Hash, const N: usize> {
    inner: RSA,
    _hash: PhantomData<H>,
}

impl<H: Hash, const N: usize> DecryptingKey<H, N> {
    /// Generate a fresh `N * 8`-bit RSA key with public exponent 65537. The
    /// `rng` is consumed and bound to the key for blinding during decryption.
    #[cfg(all(random, rsa_keygen))]
    pub fn generate(rng: RNG) -> Result<Self, i32> {
        let bits: i32 = (N * 8).try_into().map_err(|_| sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG)?;
        let mut rsa = RSA::generate(bits, 65537, &rng)?;
        rsa.set_rng(rng)?;
        Ok(Self { inner: rsa, _hash: PhantomData })
    }

    /// Adopt an existing [`RSA`] key, verifying its modulus size in bytes
    /// matches `N`. The `rng` is consumed and bound to the key for blinding
    /// during decryption.
    #[cfg(random)]
    pub fn from_rsa(rsa: RSA, rng: RNG) -> Result<Self, i32> {
        check_modulus_size(&rsa, N)?;
        let mut rsa = rsa;
        rsa.set_rng(rng)?;
        Ok(Self { inner: rsa, _hash: PhantomData })
    }

    /// Construct a decrypting key from a DER-encoded PKCS#1 private key. The
    /// `rng` is consumed and bound to the key for blinding during decryption.
    #[cfg(random)]
    pub fn from_private_der(der: &[u8], rng: RNG) -> Result<Self, i32> {
        let rsa = RSA::new_from_der(der)?;
        Self::from_rsa(rsa, rng)
    }

    /// Borrow the inner [`RSA`] key.
    pub fn as_rsa(&self) -> &RSA {
        &self.inner
    }

    /// Consume the decrypting key and return its inner [`RSA`].
    pub fn into_rsa(self) -> RSA {
        self.inner
    }

    /// Derive the matching [`EncryptingKey`] from this decrypting key.
    pub fn encrypting_key(&self) -> Result<EncryptingKey<H, N>, i32> {
        EncryptingKey::from_rsa(&self.inner)
    }

    /// Decrypt `ciphertext` and write the recovered plaintext into `out`,
    /// returning the plaintext length.
    pub fn decrypt(&mut self, ciphertext: &Ciphertext<N>, out: &mut [u8]) -> Result<usize, i32> {
        self.decrypt_inner(ciphertext, out, None)
    }

    /// Decrypt `ciphertext` with an associated `label` and write the
    /// recovered plaintext into `out`, returning the plaintext length.
    pub fn decrypt_with_label(&mut self, ciphertext: &Ciphertext<N>, out: &mut [u8], label: &[u8]) -> Result<usize, i32> {
        self.decrypt_inner(ciphertext, out, Some(label))
    }

    fn decrypt_inner(&mut self, ciphertext: &Ciphertext<N>, out: &mut [u8], label: Option<&[u8]>) -> Result<usize, i32> {
        self.inner.private_decrypt_oaep_ex(&ciphertext.0, out, H::HASH_TYPE, H::MGF, label)
    }
}
