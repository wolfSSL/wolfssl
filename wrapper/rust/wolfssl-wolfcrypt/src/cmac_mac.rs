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
RustCrypto `digest::Mac` trait implementations for the wolfCrypt CMAC types.

This module provides typed AES-CMAC wrappers with implementations of the
traits from the `digest` crate (`MacMarker`, `KeyInit`, `Update`,
`FixedOutput`) for each AES key size (128, 192, 256). With these
implementations the `digest::Mac` trait becomes available via its blanket
implementation, allowing these CMAC types to be used anywhere a RustCrypto
`Mac` is accepted.

Any failure returned by the underlying wolfCrypt call in a trait method will
result in a panic, matching the infallible signatures required by the
RustCrypto traits.
*/

use digest::consts::{U16, U24, U32};

macro_rules! impl_cmac_mac {
    (
        $(#[$attr:meta])*
        $name:ident, key = $key_size:ty
    ) => {
        $(#[$attr])*
        pub struct $name {
            cmac: crate::cmac::CMAC,
        }

        $(#[$attr])*
        impl digest::MacMarker for $name {}

        $(#[$attr])*
        impl digest::OutputSizeUser for $name {
            type OutputSize = U16;
        }

        $(#[$attr])*
        impl digest::common::KeySizeUser for $name {
            type KeySize = $key_size;
        }

        $(#[$attr])*
        impl digest::KeyInit for $name {
            fn new(key: &digest::Key<Self>) -> Self {
                Self {
                    cmac: crate::cmac::CMAC::new(key.as_slice())
                        .expect("wolfCrypt CMAC init failed"),
                }
            }
        }

        $(#[$attr])*
        impl digest::Update for $name {
            fn update(&mut self, data: &[u8]) {
                crate::cmac::CMAC::update(&mut self.cmac, data)
                    .expect("wolfCrypt CMAC update failed");
            }
        }

        $(#[$attr])*
        impl digest::FixedOutput for $name {
            fn finalize_into(self, out: &mut digest::Output<Self>) {
                self.cmac.finalize(out.as_mut_slice())
                    .expect("wolfCrypt CMAC finalize failed");
            }
        }
    };
}

impl_cmac_mac! {
    CmacAes128, key = U16
}

impl_cmac_mac! {
    CmacAes192, key = U24
}

impl_cmac_mac! {
    CmacAes256, key = U32
}
