/* test_compress.c
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

/* After <tests/unit.h>: that header establishes wolfSSL's feature-test
 * macros, and a libc header pulled in ahead of it fixes glibc's exposure
 * before they are seen -- under -std=c89 that leaves POSIX types the rest of
 * the suite needs undeclared. Every other file in tests/api/ starts with
 * <tests/unit.h> for the same reason. INT_MAX is used below. */
#include <limits.h>

#ifdef HAVE_LIBZ
    #include <wolfssl/wolfcrypt/compress.h>
#endif
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <tests/api/api.h>
#include <tests/api/test_compress.h>

/*
 * MC/DC decision coverage for the zlib wrapper (wolfcrypt/src/compress.c).
 * compress_test() in testwolfcrypt exercises the round trips; this drives the
 * argument guards, each operand flipped independently:
 *   - "out == NULL || in == NULL" in wc_Compress_ex, wc_DeCompress_ex and
 *     wc_DeCompressDynamic;
 *   - "inSz == 0 || inSz > INT_MAX/2" in wc_DeCompressDynamic, the cap that
 *     keeps the buffer doubling from overflowing.
 */
int test_wc_CompressDecisionCoverage(void)
{
    EXPECT_DECLS;
#ifdef HAVE_LIBZ
    static const byte sample[] =
        "wolfSSL compress decision coverage sample text, repeated enough to "
        "actually compress: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    byte  packed[512];
    byte  plain[512];
    byte* dynOut = NULL;
    int   packedSz;

    XMEMSET(packed, 0, sizeof(packed));
    XMEMSET(plain, 0, sizeof(plain));

    /* wc_Compress_ex "out == NULL || in == NULL" */
    ExpectIntEQ(wc_Compress_ex(NULL, sizeof(packed), sample, sizeof(sample),
        0, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Compress_ex(packed, sizeof(packed), NULL, sizeof(sample),
        0, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* both operands false: a real compression, whose output feeds the
     * decompression guards below. */
    ExpectIntGT(packedSz = wc_Compress(packed, sizeof(packed), sample,
        sizeof(sample), 0), 0);

    /* wc_DeCompress_ex "out == NULL || in == NULL" */
    ExpectIntEQ(wc_DeCompress_ex(NULL, sizeof(plain), packed, sizeof(packed),
        0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DeCompress_ex(plain, sizeof(plain), NULL, sizeof(packed),
        0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    if (EXPECT_SUCCESS() && packedSz > 0) {
        ExpectIntEQ(wc_DeCompress(plain, sizeof(plain), packed,
            (word32)packedSz), (int)sizeof(sample));
        ExpectIntEQ(XMEMCMP(plain, sample, sizeof(sample)), 0);
    }

    /* wc_DeCompressDynamic "out == NULL || in == NULL" */
    ExpectIntEQ(wc_DeCompressDynamic(NULL, 1, DYNAMIC_TYPE_TMP_BUFFER, packed,
        (word32)packedSz, 0, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DeCompressDynamic(&dynOut, 1, DYNAMIC_TYPE_TMP_BUFFER, NULL,
        (word32)packedSz, 0, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* wc_DeCompressDynamic "inSz == 0 || inSz > INT_MAX/2", one operand true
     * per call, then both false on the working round trip. */
    ExpectIntEQ(wc_DeCompressDynamic(&dynOut, 1, DYNAMIC_TYPE_TMP_BUFFER,
        packed, 0, 0, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DeCompressDynamic(&dynOut, 1, DYNAMIC_TYPE_TMP_BUFFER,
        packed, (word32)(INT_MAX / 2) + 1, 0, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    if (EXPECT_SUCCESS() && packedSz > 0) {
        ExpectIntEQ(wc_DeCompressDynamic(&dynOut, 4, DYNAMIC_TYPE_TMP_BUFFER,
            packed, (word32)packedSz, 0, NULL),
            (int)sizeof(sample));
        ExpectNotNull(dynOut);
        if (dynOut != NULL) {
            ExpectIntEQ(XMEMCMP(dynOut, sample, sizeof(sample)), 0);
            XFREE(dynOut, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            dynOut = NULL;
        }
    }
#endif /* HAVE_LIBZ */
    return EXPECT_RESULT();
}
