/* test_wolfentropy.c
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

#include <tests/unit.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/types.h>
#ifdef HAVE_ENTROPY_MEMUSE
    #include <wolfssl/wolfcrypt/wolfentropy.h>
    #include <wolfssl/wolfcrypt/sha3.h>
#endif
#include <tests/api/api.h>
#include <tests/api/test_wolfentropy.h>

/* Public MC/DC coverage for wolfcrypt/src/wolfentropy.c (SP800-90B MemUse
 * jitter entropy source). Only the exported surface is reachable from
 * tests/api: wc_Entropy_GetRawEntropy(), wc_Entropy_Get() and
 * wc_Entropy_OnDemandTest(). The file-static SP800-90B health tests
 * (Repetition/Proportion/Startup) and the MemUse index math are driven in the
 * tests/unit-mcdc white-box (test_wolfentropy_whitebox.c). The module is
 * gated by HAVE_ENTROPY_MEMUSE so every body auto-skips when it is compiled
 * out. wolfCrypt_Init() (unit.test setup) already ran Entropy_Init(), so the
 * SHA3 conditioner and mutex are ready before these calls. */

/* Raw-entropy assessment API: argument checks plus a valid collection. */
int test_wc_Entropy_GetRawEntropy(void)
{
    EXPECT_DECLS;
#ifdef HAVE_ENTROPY_MEMUSE
    byte raw[64];

    XMEMSET(raw, 0, sizeof(raw));

    /* "raw == NULL || cnt <= 0": drive each operand alone. */
    ExpectIntEQ(wc_Entropy_GetRawEntropy(NULL, (int)sizeof(raw)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                 /* raw NULL */
    ExpectIntEQ(wc_Entropy_GetRawEntropy(raw, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                 /* cnt == 0 */
    ExpectIntEQ(wc_Entropy_GetRawEntropy(raw, -1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                 /* cnt < 0 */

    /* Valid: collect a bounded amount of raw jitter noise. */
    ExpectIntEQ(wc_Entropy_GetRawEntropy(raw, (int)sizeof(raw)), 0);
#endif /* HAVE_ENTROPY_MEMUSE */
    return EXPECT_RESULT();
}

/* On-demand SP800-90B startup health test (Repetition + Adaptive
 * Proportion over >= 1024 + 512 fresh samples). */
int test_wc_Entropy_OnDemandTest(void)
{
    EXPECT_DECLS;
#ifdef HAVE_ENTROPY_MEMUSE
    ExpectIntEQ(wc_Entropy_OnDemandTest(), 0);
    /* Idempotent: a second run must also pass. */
    ExpectIntEQ(wc_Entropy_OnDemandTest(), 0);
#endif /* HAVE_ENTROPY_MEMUSE */
    return EXPECT_RESULT();
}

/* wc_Entropy_Get()'s argument guard is a three-operand compound:
 *   "bits <= 0 || bits > MAX_ENTROPY_BITS || (entropy == NULL && len > 0)"
 * Drive each operand's independence pair. */
int test_wc_EntropyDecisionCoverage(void)
{
    EXPECT_DECLS;
#ifdef HAVE_ENTROPY_MEMUSE
    byte entropy[WC_SHA3_256_DIGEST_SIZE]; /* 32 bytes */

    XMEMSET(entropy, 0, sizeof(entropy));

    /* bits <= 0 (1st operand true). */
    ExpectIntEQ(wc_Entropy_Get(0, entropy, sizeof(entropy)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Entropy_Get(-8, entropy, sizeof(entropy)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* bits > MAX_ENTROPY_BITS (2nd operand true, 1st false). */
    ExpectIntEQ(wc_Entropy_Get(MAX_ENTROPY_BITS + 1, entropy, sizeof(entropy)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* entropy == NULL && len > 0 (3rd operand true, first two false). */
    ExpectIntEQ(wc_Entropy_Get(MAX_ENTROPY_BITS, NULL, sizeof(entropy)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* entropy == NULL but len == 0 -> 3rd operand false (independence for the
     * "len > 0" sub-operand): accepted, the generate loop never runs. */
    ExpectIntEQ(wc_Entropy_Get(MAX_ENTROPY_BITS, NULL, 0), 0);

    /* All operands false: a real collection. */
    ExpectIntEQ(wc_Entropy_Get(MAX_ENTROPY_BITS, entropy, sizeof(entropy)), 0);
#endif /* HAVE_ENTROPY_MEMUSE */
    return EXPECT_RESULT();
}

/* Positive-path feature coverage: exercise wc_Entropy_Get()'s output loop
 * with sizes that straddle the SHA3-256 block (WC_SHA3_256_DIGEST_SIZE = 32),
 * driving the "len < entropy_len" clamp on both sides and multiple loop
 * iterations, at a couple of entropy strengths. */
int test_wc_EntropyFeatureCoverage(void)
{
    EXPECT_DECLS;
#ifdef HAVE_ENTROPY_MEMUSE
    byte out[96];
    word32 sizes[] = { 1, 16, 32, 33, 64, 96 };
    word32 i;

    for (i = 0; i < (word32)(sizeof(sizes) / sizeof(sizes[0])); i++) {
        XMEMSET(out, 0, sizeof(out));
        ExpectIntEQ(wc_Entropy_Get(MAX_ENTROPY_BITS, out, sizes[i]), 0);
    }

    /* A lower strength (fewer noise samples per output). */
    XMEMSET(out, 0, sizeof(out));
    ExpectIntEQ(wc_Entropy_Get(128, out, 32), 0);
#endif /* HAVE_ENTROPY_MEMUSE */
    return EXPECT_RESULT();
}
