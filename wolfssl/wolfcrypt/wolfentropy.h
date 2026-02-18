/* wolfentropy.h
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

#ifndef WOLFENTROPY_H
#define WOLFENTROPY_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef HAVE_ENTROPY_MEMUSE

#if defined(ENTROPY_SCALE_FACTOR) && FIPS_VERSION3_GE(5,2,4) && \
    FIPS_VERSION3_NE(6,0,0)
    #error "ENTROPY_SCALE_FACTOR defined elsewhere than wolfEntropy.h"
#endif

#if FIPS_VERSION3_GE(5,2,4) && FIPS_VERSION3_NE(6,0,0)
    /* Do not allow default fallback to /dev/urandom when in FIPS mode that
     * supports ESV */
    #define ENTROPY_MEMUSE_FORCE_FAILURE
#endif

#ifndef ENTROPY_SCALE_FACTOR
    /* The entropy scale factor should be the whole number inverse of the
     * minimum bits of entropy per bit of NDRNG output. */
    /* Full strength, conditioned entropy is requested of MemUse Entropy. */
    #if defined(HAVE_FIPS) && defined(HAVE_FIPS_VERSION) && \
        (HAVE_FIPS_VERSION >= 2)
        #define ENTROPY_SCALE_FACTOR (4)
    #else
        #define ENTROPY_SCALE_FACTOR (1)
    #endif
#endif

#ifdef __cplusplus
    extern "C" {
#endif

/* Maximum entropy bits that can be produced. */
#define MAX_ENTROPY_BITS    256

/* For generating data for assessment. */
WOLFSSL_API int wc_Entropy_GetRawEntropy(unsigned char* raw, int cnt);
WOLFSSL_API int wc_Entropy_Get(int bits, unsigned char* entropy, word32 len);
WOLFSSL_API int wc_Entropy_OnDemandTest(void);

WOLFSSL_LOCAL int Entropy_Init(void);
WOLFSSL_LOCAL void Entropy_Final(void);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* HAVE_ENTROPY_MEMUSE */
#endif /* WOLFENTROPY_H */
