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
RustCrypto `kem` trait implementations for the wolfCrypt ML-KEM types.

Provides [`kem::Kem`] marker types and associated encapsulation/decapsulation
key types for ML-KEM-512, ML-KEM-768, and ML-KEM-1024:

| Marker          | Encapsulation key               | Decapsulation key               |
|-----------------|---------------------------------|---------------------------------|
| [`MlKem512`]    | [`MlKem512EncapsulationKey`]    | [`MlKem512DecapsulationKey`]    |
| [`MlKem768`]    | [`MlKem768EncapsulationKey`]    | [`MlKem768DecapsulationKey`]    |
| [`MlKem1024`]   | [`MlKem1024EncapsulationKey`]   | [`MlKem1024DecapsulationKey`]   |

Each encapsulation key implements [`kem::Encapsulate`] (with
[`kem::TryKeyInit`] and [`kem::KeyExport`] for key serialization).

Each decapsulation key implements [`kem::Decapsulate`] and
[`kem::Generate`] (for key generation from a [`rand_core::CryptoRng`]).

Key generation and encapsulation bridge a caller-supplied
[`rand_core::CryptoRng`] to wolfCrypt's deterministic APIs by extracting the
required random bytes from the RNG.

# Examples

```rust
#[cfg(all(mlkem, random, feature = "kem", feature = "rand_core"))]
{
use kem::{Kem, Encapsulate, Decapsulate};
use kem::Generate;
use wolfssl_wolfcrypt::random::RNG;
use wolfssl_wolfcrypt::mlkem_kem::*;

let mut rng = RNG::new().expect("RNG creation failed");

let (dk, ek) = MlKem768::generate_keypair_from_rng(&mut rng);
let (ct, k_send) = ek.encapsulate_with_rng(&mut rng);
let k_recv = dk.decapsulate(&ct);
assert_eq!(k_send, k_recv);
}
```
*/

#![cfg(all(feature = "kem", mlkem))]

use kem::common::array::Array;
use kem::common::typenum::{U32, U768, U800};
use hybrid_array::sizes::{U1088, U1184, U1568, U1632, U2400, U3168};

macro_rules! impl_mlkem_kem {
    (
        kem = $kem:ident,
        ek = $ek:ident,
        dk = $dk:ident,
        pk_typenum = $pk_tn:ty,
        sk_typenum = $sk_tn:ty,
        ct_typenum = $ct_tn:ty,
        pk_len = $pk_len:expr,
        sk_len = $sk_len:expr,
        ct_len = $ct_len:expr,
        key_type = $key_type:expr $(,)?
    ) => {
        /// ML-KEM parameter set marker implementing [`kem::Kem`].
        #[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $kem;

        impl kem::Kem for $kem {
            type DecapsulationKey = $dk;
            type EncapsulationKey = $ek;
            type SharedKeySize = U32;
            type CiphertextSize = $ct_tn;
        }

        /// ML-KEM encapsulation (public) key implementing [`kem::Encapsulate`].
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $ek {
            pk: Array<u8, $pk_tn>,
        }

        impl kem::KeySizeUser for $ek {
            type KeySize = $pk_tn;
        }

        impl kem::TryKeyInit for $ek {
            fn new(key: &kem::Key<Self>) -> Result<Self, kem::InvalidKey> {
                let mut wc_key = crate::mlkem::MlKem::new($key_type)
                    .map_err(|_| kem::InvalidKey)?;
                wc_key.decode_public_key(key.as_ref())
                    .map_err(|_| kem::InvalidKey)?;
                Ok(Self { pk: key.clone() })
            }
        }

        impl kem::KeyExport for $ek {
            fn to_bytes(&self) -> kem::Key<Self> {
                self.pk.clone()
            }
        }

        impl kem::Encapsulate for $ek {
            type Kem = $kem;

            fn encapsulate_with_rng<R: kem::common::rand_core::CryptoRng + ?Sized>(
                &self,
                rng: &mut R,
            ) -> (kem::Ciphertext<$kem>, kem::SharedKey<$kem>) {
                let mut rand = [0u8; crate::mlkem::MlKem::ENC_RAND_SIZE];
                rng.fill_bytes(&mut rand);

                let mut wc_key = crate::mlkem::MlKem::new($key_type)
                    .expect("MlKem::new failed");
                wc_key.decode_public_key(self.pk.as_ref())
                    .expect("decode_public_key failed");

                let mut ct = [0u8; $ct_len];
                let mut ss = [0u8; crate::mlkem::MlKem::SHARED_SECRET_SIZE];
                wc_key.encapsulate_with_random(&mut ct, &mut ss, &rand)
                    .expect("encapsulate_with_random failed");

                (ct.into(), ss.into())
            }
        }

        /// ML-KEM decapsulation (private) key implementing [`kem::Decapsulate`].
        ///
        /// The private key bytes are securely zeroized on drop.
        pub struct $dk {
            sk: Array<u8, $sk_tn>,
            ek: $ek,
        }

        impl kem::Decapsulator for $dk {
            type Kem = $kem;

            fn encapsulation_key(&self) -> &$ek {
                &self.ek
            }
        }

        impl kem::Decapsulate for $dk {
            fn decapsulate(
                &self,
                ct: &kem::Ciphertext<$kem>,
            ) -> kem::SharedKey<$kem> {
                let mut wc_key = crate::mlkem::MlKem::new($key_type)
                    .expect("MlKem::new failed");
                wc_key.decode_private_key(self.sk.as_ref())
                    .expect("decode_private_key failed");

                let mut ss = [0u8; crate::mlkem::MlKem::SHARED_SECRET_SIZE];
                wc_key.decapsulate(&mut ss, ct.as_ref())
                    .expect("decapsulate failed");

                ss.into()
            }
        }

        impl kem::Generate for $dk {
            fn try_generate_from_rng<R: kem::common::rand_core::TryCryptoRng + ?Sized>(
                rng: &mut R,
            ) -> Result<Self, R::Error> {
                let mut rand = [0u8; crate::mlkem::MlKem::MAKEKEY_RAND_SIZE];
                rng.try_fill_bytes(&mut rand)?;

                let wc_key = crate::mlkem::MlKem::generate_with_random(
                    $key_type, &rand,
                ).expect("generate_with_random failed");

                let mut pk = [0u8; $pk_len];
                let mut sk = [0u8; $sk_len];
                wc_key.encode_public_key(&mut pk)
                    .expect("encode_public_key failed");
                wc_key.encode_private_key(&mut sk)
                    .expect("encode_private_key failed");

                Ok(Self {
                    sk: sk.into(),
                    ek: $ek { pk: pk.into() },
                })
            }
        }

        impl Drop for $dk {
            fn drop(&mut self) {
                use zeroize::Zeroize;
                let sk_bytes: &mut [u8] = self.sk.as_mut();
                sk_bytes.zeroize();
            }
        }
    };
}

impl_mlkem_kem! {
    kem = MlKem512,
    ek = MlKem512EncapsulationKey,
    dk = MlKem512DecapsulationKey,
    pk_typenum = U800,
    sk_typenum = U1632,
    ct_typenum = U768,
    pk_len = 800,
    sk_len = 1632,
    ct_len = 768,
    key_type = crate::mlkem::MlKem::TYPE_512,
}

impl_mlkem_kem! {
    kem = MlKem768,
    ek = MlKem768EncapsulationKey,
    dk = MlKem768DecapsulationKey,
    pk_typenum = U1184,
    sk_typenum = U2400,
    ct_typenum = U1088,
    pk_len = 1184,
    sk_len = 2400,
    ct_len = 1088,
    key_type = crate::mlkem::MlKem::TYPE_768,
}

impl_mlkem_kem! {
    kem = MlKem1024,
    ek = MlKem1024EncapsulationKey,
    dk = MlKem1024DecapsulationKey,
    pk_typenum = U1568,
    sk_typenum = U3168,
    ct_typenum = U1568,
    pk_len = 1568,
    sk_len = 3168,
    ct_len = 1568,
    key_type = crate::mlkem::MlKem::TYPE_1024,
}
