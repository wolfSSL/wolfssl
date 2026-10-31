/* ecjpake.h
 *
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
    \file wolfssl/wolfcrypt/ecjpake.h
*/

/* EC-JPAKE password authenticated key exchange (RFC 8236 Section 3) with
 * Schnorr NIZK proofs (RFC 8235 Section 3), profiled and encoded as in
 * draft-cragie-tls-ecjpake-01: P-256, SHA-256, fixed "client"/"server"
 * identities and the TLS ECJPAKEKeyKP wire structures. */

#ifndef WOLFCRYPT_ECJPAKE_H
#define WOLFCRYPT_ECJPAKE_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFCRYPT_HAVE_ECJPAKE

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>

#if !defined(HAVE_ECC) || defined(NO_SHA256)
    #error "EC-JPAKE requires ECC and SHA-256"
#endif
#if defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_NO_ECC_SW)
    #error "EC-JPAKE requires generic ECC point arithmetic"
#endif

#ifdef __cplusplus
    extern "C" {
#endif

/* Size of a P-256 field element / scalar in bytes. */
#define WC_ECJPAKE_FIELD_SZ     32
/* SEC1 uncompressed point: 0x04 || x || y */
#define WC_ECJPAKE_POINT_SZ     (1 + 2 * WC_ECJPAKE_FIELD_SZ)
/* ECJPAKEKeyKP: ECPoint X, ECPoint V, opaque r<1..2^8-1> */
#define WC_ECJPAKE_KKP_SZ       (2 * (1 + WC_ECJPAKE_POINT_SZ) + \
                                 1 + WC_ECJPAKE_FIELD_SZ)
/* ECParameters: named_curve, NamedCurve */
#define WC_ECJPAKE_ECPARAMS_SZ  3

/* Encoded size of a round one message (ECJPAKEKeyKPPairList). */
#define WC_ECJPAKE_ROUND1_SZ    (2 * WC_ECJPAKE_KKP_SZ)
/* Maximum encoded size of a round two message. */
#define WC_ECJPAKE_ROUND2_SZ    (WC_ECJPAKE_ECPARAMS_SZ + WC_ECJPAKE_KKP_SZ)
/* Size of the derived premaster secret. */
#define WC_ECJPAKE_SECRET_SZ    WC_SHA256_DIGEST_SIZE

enum {
    WC_ECJPAKE_CLIENT = 0,
    WC_ECJPAKE_SERVER = 1
};

typedef struct EcJpake {
    int        role;
    int        curveIdx;
    word32     flags;
    void*      heap;
    mp_digit   mp;              /* Montgomery setup value for prime */
    mp_int     prime;
    mp_int     a;
    mp_int     order;
    mp_int     s;               /* password scalar, then x2*s once keys set */
    mp_int     xm2;             /* own second round one private key */
    ecc_point* Xm1;             /* own round one public keys */
    ecc_point* Xm2;
    ecc_point* Xp1;             /* peer round one public keys */
    ecc_point* Xp2;
    ecc_point* Xp;              /* peer round two public key */
} EcJpake;

WOLFSSL_API int  wc_EcJpakeInit(EcJpake* jp, int role, int curveId,
                                const byte* secret, word32 secretSz,
                                void* heap);
WOLFSSL_API void wc_EcJpakeFree(EcJpake* jp);

WOLFSSL_API int  wc_EcJpakeWriteRound1(EcJpake* jp, WC_RNG* rng, byte* out,
                                       word32* outSz);
WOLFSSL_API int  wc_EcJpakeReadRound1(EcJpake* jp, const byte* in,
                                      word32 inSz);
WOLFSSL_API int  wc_EcJpakeWriteRound2(EcJpake* jp, WC_RNG* rng, byte* out,
                                       word32* outSz);
WOLFSSL_API int  wc_EcJpakeReadRound2(EcJpake* jp, const byte* in,
                                      word32 inSz);
WOLFSSL_API int  wc_EcJpakeDeriveSecret(EcJpake* jp, WC_RNG* rng, byte* out,
                                        word32* outSz);

/* Loads fixed round one private keys in place of WriteRound1, for known
 * answer tests only. */
WOLFSSL_TEST_VIS int wc_EcJpakeSetRound1Keys(EcJpake* jp, WC_RNG* rng,
                                             const byte* x1, word32 x1Sz,
                                             const byte* x2, word32 x2Sz);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFCRYPT_HAVE_ECJPAKE */
#endif /* WOLFCRYPT_ECJPAKE_H */
