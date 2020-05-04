/* renesas_sce_ra6m3g.h
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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

#ifndef WOLFSSL_RENESAS_RA6M3G_SCE_H
#define WOLFSSL_RENESAS_RA6M3G_SCE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn.h>

/* Renesas RA6M3G Secure Cryptogrpahy Engine (SCE) drivers for wolfCrypt */

/* General */
WOLFSSL_LOCAL int wc_RA6_SCE_init(void);

/* TRNG */
WOLFSSL_LOCAL int wc_RA6_GenerateSeed(byte* output, word32 sz);

/* SHA-2 */
WOLFSSL_LOCAL int wc_RA6_Sha256Transform(wc_Sha256*, const byte*);

/* AES */
#define AES_SCE_ENCRYPT (1) /* op for ECB/CBC */
#define AES_SCE_DECRYPT (2) /* op for ECB/CBC */
WOLFSSL_LOCAL int wc_RA6_AesEcb(Aes* aes, byte* out, const byte* in, word32 sz,
        int op);

/* ECC */
#if defined(HAVE_ECC) && !defined(NO_RSA)
WOLFSSL_LOCAL int wc_RA6_EccGenerateKey(ecc_key* key);
WOLFSSL_LOCAL int wc_RA6_EccGenerateSign(ecc_key* key, const byte* hash,
                               const word32 hashlen, mp_int* r, mp_int* s);
WOLFSSL_LOCAL int wc_RA6_EccVerifySign(ecc_key* key, mp_int* r, mp_int* s,
                             const byte* hash, const word32 hashlen, int* res);
WOLFSSL_LOCAL int wc_RA6_EccMulmod(mp_int* k, ecc_point *G, ecc_point *R,
                            mp_int* a, mp_int* b, mp_int* modulus, int map);
#endif

/* RSA */
#if !defined(NO_RSA)
WOLFSSL_LOCAL int wc_RA6_RsaGenerateKey(RsaKey* rsa, long e, int size);
WOLFSSL_LOCAL int wc_RA6_RsaFunction(const byte* in, word32 inLen, byte* out,
        word32* outLen, int rsa_type, RsaKey* key, WC_RNG* rng, byte pad_value);
#endif /* !NO_RSA */

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_RA6M3G_SCE_H */
