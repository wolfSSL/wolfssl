/* altera_fcs_rng.c
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

/* SDM true random number generator.
 *
 * Measured cost is roughly 400 us per request regardless of size, so this is
 * used as a seed source for wolfCrypt's DRBG rather than as a bulk generator.
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if defined(WOLFSSL_ALTERA_FCS) && defined(WOLFSSL_ALTERA_FCS_RNG)

#include <wolfssl/wolfcrypt/port/altera/altera_fcs.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#include <libfcs.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* Arbitrary non-zero identifier tagging our requests within the session. */
#ifndef WOLFSSL_ALTERA_FCS_CTX_ID
    #define WOLFSSL_ALTERA_FCS_CTX_ID 0x574F4C46
#endif

/* Largest single random request; the SDM rejects oversized asks, so longer
 * outputs are filled in chunks. */
#define WC_ALTERA_FCS_RNG_CHUNK 256

static int wc_AlteraFcs_RngGenerate(byte* out, word32 sz)
{
    void*  session = NULL;
    word32 done = 0;
    int    ret;

    if (out == NULL) {
        return BAD_FUNC_ARG;
    }
    if (sz == 0) {
        return 0;
    }

    ret = wc_AlteraFcs_SessionAcquire(&session);
    if (ret != 0) {
        return CRYPTOCB_UNAVAILABLE;
    }

    while (ret == 0 && done < sz) {
        word32 chunk = sz - done;

        if (chunk > WC_ALTERA_FCS_RNG_CHUNK) {
            chunk = WC_ALTERA_FCS_RNG_CHUNK;
        }

        ret = fcs_random_number_ext((FCS_OSAL_UUID*)session,
                                    WOLFSSL_ALTERA_FCS_CTX_ID,
                                    (FCS_OSAL_CHAR*)(out + done),
                                    (FCS_OSAL_U32)chunk);
        if (ret != 0) {
            (void)wc_AlteraFcs_MapError(ret);
            ret = CRYPTOCB_UNAVAILABLE;
        }
        else {
            done += chunk;
        }
    }

    wc_AlteraFcs_SessionRelease();

    if (ret != 0) {
        ForceZero(out, sz);
    }
    else {
        wc_AlteraFcs_TestHwMark(WC_ALTERA_FCS_TEST_HW_RNG);
    }
    return ret;
}

int wc_AlteraFcs_Rng(wc_CryptoInfo* info)
{
    int ret = CRYPTOCB_UNAVAILABLE;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    /* The TRNG serves seeding, and generation is left to the DRBG it seeded:
     * a mailbox round trip per generate request is roughly 225 times slower
     * than the DRBG for no entropy benefit. Raw TRNG output for every request
     * is available by building with WOLFSSL_ALTERA_FCS_RAW_RNG. */
    if (info->algo_type == WC_ALGO_TYPE_SEED) {
        ret = wc_AlteraFcs_RngGenerate(info->seed.seed, info->seed.sz);
    }
#ifdef WOLFSSL_ALTERA_FCS_RAW_RNG
    else if (info->algo_type == WC_ALGO_TYPE_RNG) {
        ret = wc_AlteraFcs_RngGenerate(info->rng.out, info->rng.sz);
    }
#endif

    return ret;
}

#endif /* WOLFSSL_ALTERA_FCS && WOLFSSL_ALTERA_FCS_RNG */
