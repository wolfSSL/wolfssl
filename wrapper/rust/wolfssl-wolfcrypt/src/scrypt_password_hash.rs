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
RustCrypto `password-hash` trait implementations for wolfCrypt scrypt.

This module provides [`Scrypt`], a type that implements the
[`PasswordHasher`] and [`CustomizedPasswordHasher`] traits from the
`password-hash` crate, backed by the wolfCrypt scrypt implementation. The
blanket [`PasswordVerifier`] implementation is also available, allowing
verification of existing password hashes.

Password hashes are represented in the
[PHC string format](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md):

```text
$scrypt$ln=<log_n>,r=<r>,p=<p>$<salt>$<hash>
```

This is the same encoding used by the RustCrypto `scrypt` crate.

[`PasswordHasher`]: password_hash::PasswordHasher
[`CustomizedPasswordHasher`]: password_hash::CustomizedPasswordHasher
[`PasswordVerifier`]: password_hash::PasswordVerifier
*/

#![cfg(all(feature = "password-hash", kdf_scrypt))]

use password_hash::phc::{Ident, Output, ParamsString, PasswordHash, Salt};
use password_hash::{CustomizedPasswordHasher, Error, Result, Version};

use crate::kdf;

const SCRYPT_IDENT: Ident = Ident::new_unwrap("scrypt");

/// Recommended `log_n` (cost) parameter.
pub const RECOMMENDED_LOG_N: u8 = 17;

/// Recommended `r` (block size) parameter.
pub const RECOMMENDED_R: u32 = 8;

/// Recommended `p` (parallelism) parameter.
pub const RECOMMENDED_P: u32 = 1;

/// Default output length in bytes.
pub const DEFAULT_OUTPUT_LEN: usize = 32;

/// scrypt parameters.
#[derive(Clone, Debug)]
pub struct Params {
    /// `log_n` (cost): log base 2 of the iteration count. Iterations =
    /// `1 << log_n`.
    pub log_n: u8,
    /// `r`: block size in 128-byte octets.
    pub r: u32,
    /// `p`: parallelism factor.
    pub p: u32,
    /// Desired output hash length in bytes.
    pub output_len: usize,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            log_n: RECOMMENDED_LOG_N,
            r: RECOMMENDED_R,
            p: RECOMMENDED_P,
            output_len: DEFAULT_OUTPUT_LEN,
        }
    }
}

impl Params {
    /// Validate the parameters against wolfCrypt's accepted ranges.
    fn validate(&self) -> Result<()> {
        if self.r == 0 || self.r > 8 {
            return Err(Error::ParamInvalid { name: "r" });
        }
        if self.p == 0 {
            return Err(Error::ParamInvalid { name: "p" });
        }

        // wolfCrypt: cost < 128 * r / 8.
        let log_n_cutoff = (128u32 * self.r) / 8;
        if self.log_n == 0 || u32::from(self.log_n) >= log_n_cutoff {
            return Err(Error::ParamInvalid { name: "ln" });
        }
        if self.output_len == 0 || self.output_len > Output::MAX_LENGTH {
            return Err(Error::ParamInvalid { name: "l" });
        }

        // wolfCrypt additionally validates that (1 << cost) * (128 * r) fits in a 32-bit word.
        let max_n = u32::MAX / (128 * self.r);
        let n = 1u32
            .checked_shl(self.log_n as u32)
            .ok_or(Error::ParamInvalid { name: "ln" })?;
        if n > max_n {
            return Err(Error::ParamInvalid { name: "ln" });
        }

        // wolfCrypt: limit p to avoid 32-bit overflow in internal buffer sizing.
        let max_p1 = (u32::MAX / 4) / self.r;
        let max_p2 = u32::MAX / (128 * self.r);
        let max_p = max_p1.min(max_p2);
        if self.p > max_p {
            return Err(Error::ParamInvalid { name: "p" });
        }
        Ok(())
    }
}

impl TryFrom<&PasswordHash> for Params {
    type Error = Error;

    fn try_from(hash: &PasswordHash) -> Result<Self> {
        let log_n = hash
            .params
            .get_decimal("ln")
            .ok_or(Error::ParamInvalid { name: "ln" })?;
        let log_n = u8::try_from(log_n)
            .map_err(|_| Error::ParamInvalid { name: "ln" })?;

        let r = hash
            .params
            .get_decimal("r")
            .ok_or(Error::ParamInvalid { name: "r" })?;

        let p = hash
            .params
            .get_decimal("p")
            .ok_or(Error::ParamInvalid { name: "p" })?;

        let output_len = if let Some(ref h) = hash.hash {
            h.len()
        } else if let Some(l) = hash.params.get_decimal("l") &&
                0 < l && (l as usize) <= Output::MAX_LENGTH {
            l as usize
        } else {
            return Err(Error::ParamInvalid { name: "l" });
        };

        let params = Params { log_n, r, p, output_len };
        params.validate()?;
        Ok(params)
    }
}

/// scrypt password hasher backed by wolfCrypt.
///
/// Implements the [`PasswordHasher`](password_hash::PasswordHasher) and
/// [`CustomizedPasswordHasher`] traits. A blanket
/// [`PasswordVerifier`](password_hash::PasswordVerifier) implementation is
/// provided by the `password-hash` crate.
///
/// # Example
///
/// ```rust
/// #[cfg(kdf_scrypt)]
/// {
/// use password_hash::PasswordHasher;
/// use wolfssl_wolfcrypt::scrypt_password_hash::{Params, Scrypt};
///
/// // Use smaller parameters in the doc test to keep it fast.
/// let hasher = Scrypt {
///     params: Params { log_n: 10, r: 8, p: 1, output_len: 32 },
/// };
/// let salt = b"0123456789abcdef"; // 16 bytes
/// let hash = hasher.hash_password_with_salt(b"password", salt)
///     .expect("hashing failed");
/// }
/// ```
#[derive(Clone, Debug, Default)]
pub struct Scrypt {
    /// Default parameters.
    pub params: Params,
}

impl password_hash::PasswordHasher<PasswordHash> for Scrypt {
    fn hash_password_with_salt(&self, password: &[u8], salt: &[u8]) -> Result<PasswordHash> {
        self.hash_password_customized(password, salt, None, None, self.params.clone())
    }
}

impl CustomizedPasswordHasher<PasswordHash> for Scrypt {
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

        if let Some(s) = algorithm {
            let ident = Ident::new(s).map_err(|_| Error::Algorithm)?;
            if ident != SCRYPT_IDENT {
                return Err(Error::Algorithm);
            }
        }

        params.validate()?;

        let block_size = i32::try_from(params.r)
            .map_err(|_| Error::ParamInvalid { name: "r" })?;
        let parallel = i32::try_from(params.p)
            .map_err(|_| Error::ParamInvalid { name: "p" })?;

        let salt = Salt::new(salt)?;

        let mut out_buf = [0u8; Output::MAX_LENGTH];
        let out_slice = &mut out_buf[..params.output_len];
        kdf::scrypt(password, salt.as_ref(), i32::from(params.log_n),
                block_size, parallel, out_slice)
            .map_err(|_| Error::Crypto)?;
        let output = Output::new(out_slice)?;

        let mut phc_params = ParamsString::new();
        phc_params.add_decimal("ln", u32::from(params.log_n))?;
        phc_params.add_decimal("r", params.r)?;
        phc_params.add_decimal("p", params.p)?;

        Ok(PasswordHash {
            algorithm: SCRYPT_IDENT,
            version: None,
            params: phc_params,
            salt: Some(salt),
            hash: Some(output),
        })
    }
}
