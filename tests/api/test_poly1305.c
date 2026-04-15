/* test_poly1305.c
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

#include <wolfssl/wolfcrypt/poly1305.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_poly1305.h>

/*
 * unit test for wc_Poly1305SetKey()
 */
int test_wc_Poly1305SetKey(void)
{
    EXPECT_DECLS;
#ifdef HAVE_POLY1305
    Poly1305    ctx;
    const byte  key[] =
    {
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
    };
    word32 keySz = (word32)(sizeof(key)/sizeof(byte));

    ExpectIntEQ(wc_Poly1305SetKey(&ctx, key, keySz), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_Poly1305SetKey(NULL, key,keySz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Poly1305SetKey(&ctx, NULL, keySz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Poly1305SetKey(&ctx, key, 18),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    return EXPECT_RESULT();
} /* END test_wc_Poly1305_SetKey() */

/*
 * Unit test for wc_Poly1305Update and wc_Poly1305Final.
 * Uses RFC 8439 2.5.2 test vector.
 */
int test_wc_Poly1305UpdateFinal(void)
{
    EXPECT_DECLS;
#ifdef HAVE_POLY1305
    /* RFC 8439 2.5.2 test vector */
    const byte key[] = {
        0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,
        0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
        0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,
        0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b
    };
    /* "Cryptographic Forum Research Group" */
    const byte msg[] = {
        0x43,0x72,0x79,0x70,0x74,0x6f,0x67,0x72,
        0x61,0x70,0x68,0x69,0x63,0x20,0x46,0x6f,
        0x72,0x75,0x6d,0x20,0x52,0x65,0x73,0x65,
        0x61,0x72,0x63,0x68,0x20,0x47,0x72,0x6f,
        0x75,0x70
    };
    const byte expected[] = {
        0xa8,0x06,0x1d,0xc1,0x30,0x51,0x36,0xc6,
        0xc2,0x2b,0x8b,0xaf,0x0c,0x01,0x27,0xa9
    };
    Poly1305 ctx;
    byte tag[WC_POLY1305_MAC_SZ];

    /* Single update */
    ExpectIntEQ(wc_Poly1305SetKey(&ctx, key, sizeof(key)), 0);
    ExpectIntEQ(wc_Poly1305Update(&ctx, msg, sizeof(msg)), 0);
    ExpectIntEQ(wc_Poly1305Final(&ctx, tag), 0);
    ExpectBufEQ(tag, expected, sizeof(expected));

    /* Multi-chunk update produces the same result */
    ExpectIntEQ(wc_Poly1305SetKey(&ctx, key, sizeof(key)), 0);
    ExpectIntEQ(wc_Poly1305Update(&ctx, msg, 16), 0);
    ExpectIntEQ(wc_Poly1305Update(&ctx, msg + 16, sizeof(msg) - 16), 0);
    ExpectIntEQ(wc_Poly1305Final(&ctx, tag), 0);
    ExpectBufEQ(tag, expected, sizeof(expected));

    /* Bad args */
    ExpectIntEQ(wc_Poly1305Update(NULL, msg, sizeof(msg)),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Poly1305Final(NULL, tag),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Poly1305Final(&ctx, NULL),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    return EXPECT_RESULT();
} /* END test_wc_Poly1305UpdateFinal */

/*
 * Unit test for wc_Poly1305_MAC.
 * Uses RFC 7539 2.8.2 test vector.
 */
int test_wc_Poly1305_MAC(void)
{
    EXPECT_DECLS;
#ifdef HAVE_POLY1305
    const byte key[] = {
        0x7b,0xac,0x2b,0x25,0x2d,0xb4,0x47,0xaf,
        0x09,0xb6,0x7a,0x55,0xa4,0xe9,0x55,0x84,
        0x0a,0xe1,0xd6,0x73,0x10,0x75,0xd9,0xeb,
        0x2a,0x93,0x75,0x78,0x3e,0xd5,0x53,0xff
    };
    const byte aad[] = {
        0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,
        0xc4,0xc5,0xc6,0xc7
    };
    const byte input[] = {
        0xd3,0x1a,0x8d,0x34,0x64,0x8e,0x60,0xdb,
        0x7b,0x86,0xaf,0xbc,0x53,0xef,0x7e,0xc2,
        0xa4,0xad,0xed,0x51,0x29,0x6e,0x08,0xfe,
        0xa9,0xe2,0xb5,0xa7,0x36,0xee,0x62,0xd6,
        0x3d,0xbe,0xa4,0x5e,0x8c,0xa9,0x67,0x12,
        0x82,0xfa,0xfb,0x69,0xda,0x92,0x72,0x8b,
        0x1a,0x71,0xde,0x0a,0x9e,0x06,0x0b,0x29,
        0x05,0xd6,0xa5,0xb6,0x7e,0xcd,0x3b,0x36,
        0x92,0xdd,0xbd,0x7f,0x2d,0x77,0x8b,0x8c,
        0x98,0x03,0xae,0xe3,0x28,0x09,0x1b,0x58,
        0xfa,0xb3,0x24,0xe4,0xfa,0xd6,0x75,0x94,
        0x55,0x85,0x80,0x8b,0x48,0x31,0xd7,0xbc,
        0x3f,0xf4,0xde,0xf0,0x8e,0x4b,0x7a,0x9d,
        0xe5,0x76,0xd2,0x65,0x86,0xce,0xc6,0x4b,
        0x61,0x16
    };
    const byte expected[] = {
        0x1a,0xe1,0x0b,0x59,0x4f,0x09,0xe2,0x6a,
        0x7e,0x90,0x2e,0xcb,0xd0,0x60,0x06,0x91
    };
    Poly1305 ctx;
    byte tag[WC_POLY1305_MAC_SZ];

    ExpectIntEQ(wc_Poly1305SetKey(&ctx, key, sizeof(key)), 0);
    ExpectIntEQ(wc_Poly1305_MAC(&ctx, aad, sizeof(aad),
                                 input, sizeof(input),
                                 tag, sizeof(tag)), 0);
    ExpectBufEQ(tag, expected, sizeof(expected));

    /* Bad args */
    ExpectIntEQ(wc_Poly1305_MAC(NULL, aad, sizeof(aad),
                                 input, sizeof(input), tag, sizeof(tag)),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Poly1305_MAC(&ctx, aad, sizeof(aad),
                                 NULL, sizeof(input), tag, sizeof(tag)),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Poly1305_MAC(&ctx, aad, sizeof(aad),
                                 input, sizeof(input), NULL, sizeof(tag)),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* tagSz too small */
    ExpectIntEQ(wc_Poly1305_MAC(&ctx, aad, sizeof(aad),
                                 input, sizeof(input),
                                 tag, WC_POLY1305_MAC_SZ - 1),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* non-NULL additional with addSz > 0 but additional == NULL */
    ExpectIntEQ(wc_Poly1305_MAC(&ctx, NULL, 1,
                                 input, sizeof(input), tag, sizeof(tag)),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    return EXPECT_RESULT();
} /* END test_wc_Poly1305_MAC */

/*
 * Unit test for wc_Poly1305_Pad and wc_Poly1305_EncodeSizes /
 * wc_Poly1305_EncodeSizes64.
 * These are exercised via wc_Poly1305_MAC in normal use; test them directly
 * by verifying the tag changes when data is artificially padded/encoded.
 */
int test_wc_Poly1305_PadEncodeSizes(void)
{
    EXPECT_DECLS;
#ifdef HAVE_POLY1305
    const byte key[] = {
        0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,
        0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
        0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,
        0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b
    };
    const byte data[] = { 0x01, 0x02, 0x03, 0x04, 0x05 }; /* 5 bytes */
    Poly1305 ctx;
    byte tag1[WC_POLY1305_MAC_SZ];
    byte tag2[WC_POLY1305_MAC_SZ];

    /* Build tag1: data + manual Pad + EncodeSizes(5, 5) */
    ExpectIntEQ(wc_Poly1305SetKey(&ctx, key, sizeof(key)), 0);
    ExpectIntEQ(wc_Poly1305Update(&ctx, data, sizeof(data)), 0);
    ExpectIntEQ(wc_Poly1305_Pad(&ctx, sizeof(data)), 0);
    ExpectIntEQ(wc_Poly1305_EncodeSizes(&ctx,
                                        (word32)sizeof(data),
                                        (word32)sizeof(data)), 0);
    ExpectIntEQ(wc_Poly1305Final(&ctx, tag1), 0);

    /* Build tag2 same way - must match */
    ExpectIntEQ(wc_Poly1305SetKey(&ctx, key, sizeof(key)), 0);
    ExpectIntEQ(wc_Poly1305Update(&ctx, data, sizeof(data)), 0);
    ExpectIntEQ(wc_Poly1305_Pad(&ctx, sizeof(data)), 0);
    ExpectIntEQ(wc_Poly1305_EncodeSizes(&ctx,
                                        (word32)sizeof(data),
                                        (word32)sizeof(data)), 0);
    ExpectIntEQ(wc_Poly1305Final(&ctx, tag2), 0);
    ExpectBufEQ(tag1, tag2, sizeof(tag1));

    /* Omitting the pad must produce a different tag */
    ExpectIntEQ(wc_Poly1305SetKey(&ctx, key, sizeof(key)), 0);
    ExpectIntEQ(wc_Poly1305Update(&ctx, data, sizeof(data)), 0);
    /* intentionally skip Pad */
    ExpectIntEQ(wc_Poly1305_EncodeSizes(&ctx,
                                        (word32)sizeof(data),
                                        (word32)sizeof(data)), 0);
    ExpectIntEQ(wc_Poly1305Final(&ctx, tag2), 0);
    /* tags must differ */
    ExpectIntNE(XMEMCMP(tag1, tag2, sizeof(tag1)), 0);

#ifdef WORD64_AVAILABLE
    /* wc_Poly1305_EncodeSizes64: same data as 64-bit sizes, same result */
    ExpectIntEQ(wc_Poly1305SetKey(&ctx, key, sizeof(key)), 0);
    ExpectIntEQ(wc_Poly1305Update(&ctx, data, sizeof(data)), 0);
    ExpectIntEQ(wc_Poly1305_Pad(&ctx, sizeof(data)), 0);
    ExpectIntEQ(wc_Poly1305_EncodeSizes64(&ctx,
                                          (word64)sizeof(data),
                                          (word64)sizeof(data)), 0);
    ExpectIntEQ(wc_Poly1305Final(&ctx, tag2), 0);
    ExpectBufEQ(tag1, tag2, sizeof(tag1));
#endif

    /* Pad lenToPad == 0 is a no-op */
    ExpectIntEQ(wc_Poly1305SetKey(&ctx, key, sizeof(key)), 0);
    ExpectIntEQ(wc_Poly1305_Pad(&ctx, 0), 0);

    /* Bad args */
    ExpectIntEQ(wc_Poly1305_Pad(NULL, 1),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Poly1305_EncodeSizes(NULL, 1, 1),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifdef WORD64_AVAILABLE
    ExpectIntEQ(wc_Poly1305_EncodeSizes64(NULL, 1, 1),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
#endif
    return EXPECT_RESULT();
} /* END test_wc_Poly1305_PadEncodeSizes */

int test_wc_Poly1305BadArgCoverage(void)
{
    EXPECT_DECLS;
#ifdef HAVE_POLY1305
    Poly1305 ctx;
    byte tag[WC_POLY1305_MAC_SZ];
    byte mac[WC_POLY1305_MAC_SZ];
    byte buf[32];
    const byte key[32] = {
        0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,
        0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
        0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,
        0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b
    };

    XMEMSET(buf, 0x42, sizeof(buf));
    XMEMSET(tag, 0, sizeof(tag));

    ExpectIntEQ(wc_Poly1305SetKey(NULL, key, 32),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Poly1305SetKey(&ctx, NULL, 32),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Poly1305SetKey(&ctx, key, 16),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Poly1305SetKey(&ctx, key, 64),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_Poly1305Final(NULL, mac),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Poly1305SetKey(&ctx, key, 32), 0);
    ExpectIntEQ(wc_Poly1305Final(&ctx, NULL),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_Poly1305Update(NULL, buf, 16),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Poly1305SetKey(&ctx, key, 32), 0);
    ExpectIntEQ(wc_Poly1305Update(&ctx, NULL, 1),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Poly1305Update(&ctx, NULL, 0), 0);

    ExpectIntEQ(wc_Poly1305_MAC(NULL, NULL, 0, buf, 16, tag, WC_POLY1305_MAC_SZ),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Poly1305SetKey(&ctx, key, 32), 0);
    ExpectIntEQ(wc_Poly1305_MAC(&ctx, NULL, 0, NULL, 1, tag, WC_POLY1305_MAC_SZ),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Poly1305SetKey(&ctx, key, 32), 0);
    ExpectIntEQ(wc_Poly1305_MAC(&ctx, NULL, 0, buf, 16, NULL, WC_POLY1305_MAC_SZ),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Poly1305SetKey(&ctx, key, 32), 0);
    ExpectIntEQ(wc_Poly1305_MAC(&ctx, NULL, 0, buf, 16, tag, 8),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Poly1305SetKey(&ctx, key, 32), 0);
    ExpectIntEQ(wc_Poly1305_MAC(&ctx, NULL, 1, buf, 16, tag, WC_POLY1305_MAC_SZ),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    return EXPECT_RESULT();
}

int test_wc_Poly1305DecisionCoverage(void)
{
    EXPECT_DECLS;
#ifdef HAVE_POLY1305
    Poly1305 ctx;
    byte tag[WC_POLY1305_MAC_SZ];
    const byte key[32] = {
        0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,
        0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
        0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,
        0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b
    };
    const byte msg[] = {
        0x43,0x72,0x79,0x70,0x74,0x6f,0x67,0x72,
        0x61,0x70,0x68,0x69,0x63,0x20,0x46,0x6f,
        0x72,0x75,0x6d,0x20,0x52,0x65,0x73,0x65,
        0x61,0x72,0x63,0x68,0x20,0x47,0x72,0x6f,
        0x75,0x70
    };
    const byte expectedTag[WC_POLY1305_MAC_SZ] = {
        0xa8,0x06,0x1d,0xc1,0x30,0x51,0x36,0xc6,
        0xc2,0x2b,0x8b,0xaf,0x0c,0x01,0x27,0xa9
    };

    ExpectIntEQ(wc_Poly1305SetKey(&ctx, key, 32), 0);
    ExpectIntEQ(wc_Poly1305Update(&ctx, NULL, 0), 0);
    ExpectIntEQ(wc_Poly1305Update(&ctx, msg, 7), 0);
    ExpectIntEQ(wc_Poly1305Update(&ctx, msg + 7, (word32)(sizeof(msg) - 7)), 0);
    ExpectIntEQ(wc_Poly1305Final(&ctx, tag), 0);
    ExpectBufEQ(tag, expectedTag, WC_POLY1305_MAC_SZ);

    ExpectIntEQ(wc_Poly1305SetKey(&ctx, key, 32), 0);
    ExpectIntEQ(wc_Poly1305Update(&ctx, msg, 16), 0);
    ExpectIntEQ(wc_Poly1305Update(&ctx, msg + 16, (word32)(sizeof(msg) - 16)), 0);
    XMEMSET(tag, 0, sizeof(tag));
    ExpectIntEQ(wc_Poly1305Final(&ctx, tag), 0);

    ExpectIntEQ(wc_Poly1305SetKey(&ctx, key, 32), 0);
    ExpectIntEQ(wc_Poly1305_Pad(&ctx, 0), 0);
    ExpectIntEQ(wc_Poly1305_Pad(&ctx, 16), 0);
    ExpectIntEQ(wc_Poly1305_Pad(&ctx, 17), 0);
    ExpectIntEQ(wc_Poly1305_Pad(&ctx, 1), 0);

    ExpectIntEQ(wc_Poly1305SetKey(&ctx, key, 32), 0);
    XMEMSET(tag, 0, sizeof(tag));
    ExpectIntEQ(wc_Poly1305_MAC(&ctx, NULL, 0, msg, (word32)sizeof(msg),
                                 tag, WC_POLY1305_MAC_SZ), 0);

    {
        const byte aad[12] = {
            0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7
        };
        ExpectIntEQ(wc_Poly1305SetKey(&ctx, key, 32), 0);
        XMEMSET(tag, 0, sizeof(tag));
        ExpectIntEQ(wc_Poly1305_MAC(&ctx, aad, (word32)sizeof(aad),
                                     msg, (word32)sizeof(msg),
                                     tag, WC_POLY1305_MAC_SZ), 0);
    }
#endif
    return EXPECT_RESULT();
}

int test_wc_Poly1305FeatureCoverage(void)
{
    EXPECT_DECLS;
#ifdef HAVE_POLY1305
    Poly1305 ctx;
    byte tag[WC_POLY1305_MAC_SZ];
    byte tag2[WC_POLY1305_MAC_SZ];
    const byte key[32] = {
        0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,
        0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
        0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,
        0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b
    };
    const byte msg[] = {
        0x43,0x72,0x79,0x70,0x74,0x6f,0x67,0x72,
        0x61,0x70,0x68,0x69,0x63,0x20,0x46,0x6f,
        0x72,0x75,0x6d,0x20,0x52,0x65,0x73,0x65,
        0x61,0x72,0x63,0x68,0x20,0x47,0x72,0x6f,
        0x75,0x70
    };
    const byte expectedTag[WC_POLY1305_MAC_SZ] = {
        0xa8,0x06,0x1d,0xc1,0x30,0x51,0x36,0xc6,
        0xc2,0x2b,0x8b,0xaf,0x0c,0x01,0x27,0xa9
    };

    ExpectIntEQ(wc_Poly1305SetKey(&ctx, key, 32), 0);
    ExpectIntEQ(wc_Poly1305Update(&ctx, msg, (word32)sizeof(msg)), 0);
    XMEMSET(tag, 0, sizeof(tag));
    ExpectIntEQ(wc_Poly1305Final(&ctx, tag), 0);
    ExpectBufEQ(tag, expectedTag, WC_POLY1305_MAC_SZ);

    ExpectIntEQ(wc_Poly1305SetKey(&ctx, key, 32), 0);
    ExpectIntEQ(wc_Poly1305Update(&ctx, msg, 0), 0);
    ExpectIntEQ(wc_Poly1305Update(&ctx, msg, (word32)sizeof(msg)), 0);
    XMEMSET(tag2, 0, sizeof(tag2));
    ExpectIntEQ(wc_Poly1305Final(&ctx, tag2), 0);
    ExpectBufEQ(tag2, tag, WC_POLY1305_MAC_SZ);

    {
        word32 i;
        ExpectIntEQ(wc_Poly1305SetKey(&ctx, key, 32), 0);
        for (i = 0; i < (word32)sizeof(msg); i++) {
            ExpectIntEQ(wc_Poly1305Update(&ctx, msg + i, 1), 0);
        }
        XMEMSET(tag2, 0, sizeof(tag2));
        ExpectIntEQ(wc_Poly1305Final(&ctx, tag2), 0);
        ExpectBufEQ(tag2, tag, WC_POLY1305_MAC_SZ);
    }

    {
        byte data32[32];
        XMEMSET(data32, 0xab, sizeof(data32));
        ExpectIntEQ(wc_Poly1305SetKey(&ctx, key, 32), 0);
        ExpectIntEQ(wc_Poly1305Update(&ctx, data32, 16), 0);
        ExpectIntEQ(wc_Poly1305Update(&ctx, data32 + 16, 16), 0);
        XMEMSET(tag2, 0, sizeof(tag2));
        ExpectIntEQ(wc_Poly1305Final(&ctx, tag2), 0);
    }

    {
        byte data33[33];
        XMEMSET(data33, 0xcd, sizeof(data33));
        ExpectIntEQ(wc_Poly1305SetKey(&ctx, key, 32), 0);
        ExpectIntEQ(wc_Poly1305Update(&ctx, data33, (word32)sizeof(data33)), 0);
        XMEMSET(tag2, 0, sizeof(tag2));
        ExpectIntEQ(wc_Poly1305Final(&ctx, tag2), 0);
    }

    {
        byte aad16[16];
        XMEMSET(aad16, 0xee, sizeof(aad16));
        ExpectIntEQ(wc_Poly1305SetKey(&ctx, key, 32), 0);
        XMEMSET(tag2, 0, sizeof(tag2));
        ExpectIntEQ(wc_Poly1305_MAC(&ctx, aad16, 16,
                                     msg, (word32)sizeof(msg),
                                     tag2, WC_POLY1305_MAC_SZ), 0);
    }

    {
        byte aad17[17];
        XMEMSET(aad17, 0xff, sizeof(aad17));
        ExpectIntEQ(wc_Poly1305SetKey(&ctx, key, 32), 0);
        XMEMSET(tag2, 0, sizeof(tag2));
        ExpectIntEQ(wc_Poly1305_MAC(&ctx, aad17, 17,
                                     msg, (word32)sizeof(msg),
                                     tag2, WC_POLY1305_MAC_SZ), 0);
    }

    {
        byte aad1[1] = { 0xAA };
        ExpectIntEQ(wc_Poly1305SetKey(&ctx, key, 32), 0);
        XMEMSET(tag2, 0, sizeof(tag2));
        ExpectIntEQ(wc_Poly1305_MAC(&ctx, aad1, 1,
                                     msg, (word32)sizeof(msg),
                                     tag2, WC_POLY1305_MAC_SZ), 0);
    }

    ExpectIntEQ(wc_Poly1305_EncodeSizes(NULL, 12, 34),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_Poly1305SetKey(&ctx, key, 32), 0);
    ExpectIntEQ(wc_Poly1305_EncodeSizes(&ctx, 12, (word32)sizeof(msg)), 0);

    {
        byte emptyBuf[1] = { 0 };
        ExpectIntEQ(wc_Poly1305SetKey(&ctx, key, 32), 0);
        XMEMSET(tag2, 0, sizeof(tag2));
        ExpectIntEQ(wc_Poly1305_MAC(&ctx, NULL, 0,
                                     emptyBuf, 0,
                                     tag2, WC_POLY1305_MAC_SZ), 0);
    }
#endif
    return EXPECT_RESULT();
}
