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
RustCrypto `password-hash` trait implementations for wolfCrypt PBKDF2.

This module provides [`Pbkdf2`], a type that implements the
[`PasswordHasher`] and [`CustomizedPasswordHasher`] traits from the
`password-hash` crate, backed by the wolfCrypt PBKDF2 implementation.
The blanket [`PasswordVerifier`] implementation is also available,
allowing verification of existing password hashes.

Password hashes are represented in the
[PHC string format](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md):

```text
$pbkdf2-sha256$i=600000$<salt>$<hash>
```

# Supported algorithms

| Algorithm ID    | Hash function |
|-----------------|---------------|
| `pbkdf2-sha256` | HMAC-SHA-256  |
| `pbkdf2-sha384` | HMAC-SHA-384  |
| `pbkdf2-sha512` | HMAC-SHA-512  |

[`PasswordHasher`]: password_hash::PasswordHasher
[`CustomizedPasswordHasher`]: password_hash::CustomizedPasswordHasher
[`PasswordVerifier`]: password_hash::PasswordVerifier
*/

#![cfg(all(feature = "password-hash", hmac, kdf_pbkdf2))]

use password_hash::phc::{Ident, Output, ParamsString, PasswordHash, Salt};
use password_hash::{CustomizedPasswordHasher, Error, Result, Version};

use crate::hmac::HMAC;
use crate::kdf;

const PBKDF2_SHA256_IDENT: Ident = Ident::new_unwrap("pbkdf2-sha256");
const PBKDF2_SHA384_IDENT: Ident = Ident::new_unwrap("pbkdf2-sha384");
const PBKDF2_SHA512_IDENT: Ident = Ident::new_unwrap("pbkdf2-sha512");

/// Minimum number of PBKDF2 rounds.
pub const MIN_ROUNDS: u32 = 1_000;

/// Default number of PBKDF2 rounds (OWASP recommendation for SHA-256).
pub const DEFAULT_ROUNDS: u32 = 600_000;

/// Default output length in bytes.
pub const DEFAULT_OUTPUT_LEN: usize = 32;

/// PBKDF2 algorithm variant.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub enum Algorithm {
    /// PBKDF2 with HMAC-SHA-256.
    #[default]
    Pbkdf2Sha256,
    /// PBKDF2 with HMAC-SHA-384.
    Pbkdf2Sha384,
    /// PBKDF2 with HMAC-SHA-512.
    Pbkdf2Sha512,
}

impl Algorithm {
    /// Get the PHC string format identifier for this algorithm.
    pub fn ident(self) -> Ident {
        match self {
            Algorithm::Pbkdf2Sha256 => PBKDF2_SHA256_IDENT,
            Algorithm::Pbkdf2Sha384 => PBKDF2_SHA384_IDENT,
            Algorithm::Pbkdf2Sha512 => PBKDF2_SHA512_IDENT,
        }
    }

    fn hmac_type(self) -> i32 {
        match self {
            Algorithm::Pbkdf2Sha256 => HMAC::TYPE_SHA256,
            Algorithm::Pbkdf2Sha384 => HMAC::TYPE_SHA384,
            Algorithm::Pbkdf2Sha512 => HMAC::TYPE_SHA512,
        }
    }
}

impl TryFrom<Ident> for Algorithm {
    type Error = Error;

    fn try_from(ident: Ident) -> Result<Self> {
        if ident == PBKDF2_SHA256_IDENT {
            Ok(Algorithm::Pbkdf2Sha256)
        } else if ident == PBKDF2_SHA384_IDENT {
            Ok(Algorithm::Pbkdf2Sha384)
        } else if ident == PBKDF2_SHA512_IDENT {
            Ok(Algorithm::Pbkdf2Sha512)
        } else {
            Err(Error::Algorithm)
        }
    }
}

/// PBKDF2 parameters.
#[derive(Clone, Debug)]
pub struct Params {
    /// Number of iterations (rounds).
    pub rounds: u32,
    /// Desired output hash length in bytes.
    pub output_len: usize,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            rounds: DEFAULT_ROUNDS,
            output_len: DEFAULT_OUTPUT_LEN,
        }
    }
}

impl TryFrom<&PasswordHash> for Params {
    type Error = Error;

    fn try_from(hash: &PasswordHash) -> Result<Self> {
        let rounds = hash
            .params
            .get_decimal("i")
            .ok_or(Error::ParamInvalid { name: "i" })?;

        if rounds < MIN_ROUNDS {
            return Err(Error::ParamInvalid { name: "i" });
        }

        let output_len = if let Some(ref h) = hash.hash {
            h.len()
        } else if let Some(l) = hash.params.get_decimal("l") {
            l as usize
        } else {
            return Err(Error::ParamInvalid { name: "l" });
        };

        Ok(Params { rounds, output_len })
    }
}

/// PBKDF2 password hasher backed by wolfCrypt.
///
/// Implements the [`PasswordHasher`](password_hash::PasswordHasher) and
/// [`CustomizedPasswordHasher`] traits. A blanket
/// [`PasswordVerifier`](password_hash::PasswordVerifier) implementation is
/// provided by the `password-hash` crate.
///
/// # Example
///
/// ```rust
/// #[cfg(all(hmac, kdf_pbkdf2))]
/// {
/// use password_hash::PasswordHasher;
/// use wolfssl_wolfcrypt::pbkdf2_password_hash::Pbkdf2;
///
/// let hasher = Pbkdf2::default();
/// let salt = b"0123456789abcdef"; // 16 bytes
/// let hash = hasher.hash_password_with_salt(b"password", salt)
///     .expect("hashing failed");
/// }
/// ```
#[derive(Clone, Debug, Default)]
pub struct Pbkdf2 {
    /// Algorithm to use for hashing.
    pub algorithm: Algorithm,
    /// Default parameters.
    pub params: Params,
}

impl password_hash::PasswordHasher<PasswordHash> for Pbkdf2 {
    fn hash_password_with_salt(&self, password: &[u8], salt: &[u8]) -> Result<PasswordHash> {
        self.hash_password_customized(password, salt, None, None, self.params.clone())
    }
}

impl password_hash::CustomizedPasswordHasher<PasswordHash> for Pbkdf2 {
    type Params = Params;

    fn hash_password_customized(
        &self,
        password: &[u8],
        salt: &[u8],
        algorithm: Option<&str>,
        version: Option<Version>,
        params: Params,
    ) -> Result<PasswordHash> {
        if version.is_some() {
            return Err(Error::Version);
        }

        let algorithm = match algorithm {
            Some(s) => {
                let ident = Ident::new(s).map_err(|_| Error::Algorithm)?;
                Algorithm::try_from(ident)?
            }
            None => self.algorithm,
        };

        if params.rounds < MIN_ROUNDS {
            return Err(Error::ParamInvalid { name: "i" });
        }

        let iterations = i32::try_from(params.rounds)
            .map_err(|_| Error::ParamInvalid { name: "i" })?;

        let salt = Salt::new(salt)?;

        let mut out_buf = [0u8; Output::MAX_LENGTH];
        let out_slice = &mut out_buf[..params.output_len];
        kdf::pbkdf2(password, salt.as_ref(), iterations, algorithm.hmac_type(), out_slice)
            .map_err(|_| Error::Crypto)?;
        let output = Output::new(out_slice)?;

        let mut phc_params = ParamsString::new();
        phc_params.add_decimal("i", params.rounds)?;

        Ok(PasswordHash {
            algorithm: algorithm.ident(),
            version: None,
            params: phc_params,
            salt: Some(salt),
            hash: Some(output),
        })
    }
}
