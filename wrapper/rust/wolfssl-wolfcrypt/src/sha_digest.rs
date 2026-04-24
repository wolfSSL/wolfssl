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
RustCrypto `digest` trait implementations for the wolfCrypt SHA-family hash
types.

This module provides implementations of the traits from the `digest` crate
(`HashMarker`, `OutputSizeUser`, `BlockSizeUser`, `Update`, `Reset`,
`FixedOutput`, and `FixedOutputReset`) for the fixed-output hash types
defined in [`crate::sha`]. With these implementations the `digest::Digest`
trait becomes available via its blanket implementation, allowing these
hashers to be used anywhere a RustCrypto `Digest` is accepted.

Any failure returned by the underlying wolfCrypt call in a trait method will
result in a panic, matching the infallible signatures required by the
RustCrypto traits.
*/

use digest::consts::{
    U20, U28, U32, U48, U64, U72, U104, U128, U136, U144,
};

macro_rules! impl_digest_traits {
    (
        $(#[$attr:meta])*
        $ty:path, out = $output:ty, block = $block:ty
    ) => {
        $(#[$attr])*
        impl Default for $ty {
            fn default() -> Self {
                <$ty>::new().expect("wolfCrypt hash init failed")
            }
        }

        $(#[$attr])*
        impl digest::HashMarker for $ty {}

        $(#[$attr])*
        impl digest::OutputSizeUser for $ty {
            type OutputSize = $output;
        }

        $(#[$attr])*
        impl digest::block_api::BlockSizeUser for $ty {
            type BlockSize = $block;
        }

        $(#[$attr])*
        impl digest::Update for $ty {
            fn update(&mut self, data: &[u8]) {
                <$ty>::update(self, data).expect("wolfCrypt hash update failed");
            }
        }

        $(#[$attr])*
        impl digest::Reset for $ty {
            fn reset(&mut self) {
                <$ty>::init(self).expect("wolfCrypt hash init failed");
            }
        }

        $(#[$attr])*
        impl digest::FixedOutput for $ty {
            fn finalize_into(mut self, out: &mut digest::Output<Self>) {
                <$ty>::finalize(&mut self, out.as_mut_slice())
                    .expect("wolfCrypt hash finalize failed");
            }
        }

        $(#[$attr])*
        impl digest::FixedOutputReset for $ty {
            fn finalize_into_reset(&mut self, out: &mut digest::Output<Self>) {
                <$ty>::finalize(self, out.as_mut_slice())
                    .expect("wolfCrypt hash finalize failed");
                <$ty>::init(self).expect("wolfCrypt hash init failed");
            }
        }
    };
}

impl_digest_traits! {
    #[cfg(sha)]
    crate::sha::SHA, out = U20, block = U64
}

impl_digest_traits! {
    #[cfg(sha224)]
    crate::sha::SHA224, out = U28, block = U64
}

impl_digest_traits! {
    #[cfg(sha256)]
    crate::sha::SHA256, out = U32, block = U64
}

impl_digest_traits! {
    #[cfg(sha384)]
    crate::sha::SHA384, out = U48, block = U128
}

impl_digest_traits! {
    #[cfg(sha512)]
    crate::sha::SHA512, out = U64, block = U128
}

impl_digest_traits! {
    #[cfg(sha3)]
    crate::sha::SHA3_224, out = U28, block = U144
}

impl_digest_traits! {
    #[cfg(sha3)]
    crate::sha::SHA3_256, out = U32, block = U136
}

impl_digest_traits! {
    #[cfg(sha3)]
    crate::sha::SHA3_384, out = U48, block = U104
}

impl_digest_traits! {
    #[cfg(sha3)]
    crate::sha::SHA3_512, out = U64, block = U72
}
