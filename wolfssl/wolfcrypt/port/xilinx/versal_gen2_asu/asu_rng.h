/* asu_rng.h
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

/* ASU TRNG entropy for the wolfSSL crypto callback. Seeds the wolfCrypt Hash
 * DRBG from the ASU true random number generator. */

#ifndef WOLFSSL_VERSAL_GEN2_ASU_RNG_H
#define WOLFSSL_VERSAL_GEN2_ASU_RNG_H

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_VERSAL_GEN2_ASU_TRNG

#include <wolfssl/wolfcrypt/cryptocb.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Single entry point for the ASU TRNG. The crypto callback dispatcher routes
 * both random number operations here and this handler decides which it is: seed
 * a DRBG (WC_ALGO_TYPE_SEED, fills info->seed) or serve random blocks
 * (WC_ALGO_TYPE_RNG, fills info->rng). The ASU TRNG returns at most one strength
 * block (32 bytes) per call, so larger requests are filled over several ASU
 * transactions. Returns 0 on success, CRYPTOCB_UNAVAILABLE for an unsupported
 * operation, or a negative error. */
WOLFSSL_LOCAL int wc_AsuRng(wc_CryptoInfo* info);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_VERSAL_GEN2_ASU_TRNG */

#endif /* WOLFSSL_VERSAL_GEN2_ASU_RNG_H */
