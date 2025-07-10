/* test_chacha.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#include <wolfssl/wolfcrypt/chacha.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_chacha.h>

/*
 * Testing wc_Chacha_SetKey() and wc_Chacha_SetIV()
 */
int test_wc_Chacha_SetKey(void)
{
    EXPECT_DECLS;
#ifdef HAVE_CHACHA
    ChaCha     ctx;
    const byte key[] = {
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
    };
    word32 keySz = (word32)(sizeof(key)/sizeof(byte));
    byte       cipher[128];

    XMEMSET(cipher, 0, sizeof(cipher));
    ExpectIntEQ(wc_Chacha_SetKey(&ctx, key, keySz), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_Chacha_SetKey(NULL, key, keySz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Chacha_SetKey(&ctx, key, 18), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_Chacha_SetIV(&ctx, cipher, 0), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_Chacha_SetIV(NULL, cipher, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    return EXPECT_RESULT();
} /* END test_wc_Chacha_SetKey */

/*
 * Testing wc_Chacha_Process()
 */
int test_wc_Chacha_Process(void)
{
    EXPECT_DECLS;
#ifdef HAVE_CHACHA
    ChaCha      enc, dec;
    byte        cipher[128];
    byte        plain[128];
    const byte  key[] =
    {
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
    };
    const char* input = "Everybody gets Friday off.";
    word32      keySz = sizeof(key)/sizeof(byte);
    unsigned long int inlen = XSTRLEN(input);

    /* Initialize stack variables. */
    XMEMSET(cipher, 0, 128);
    XMEMSET(plain, 0, 128);

    ExpectIntEQ(wc_Chacha_SetKey(&enc, key, keySz), 0);
    ExpectIntEQ(wc_Chacha_SetKey(&dec, key, keySz), 0);
    ExpectIntEQ(wc_Chacha_SetIV(&enc, cipher, 0), 0);
    ExpectIntEQ(wc_Chacha_SetIV(&dec, cipher, 0), 0);

    ExpectIntEQ(wc_Chacha_Process(&enc, cipher, (byte*)input, (word32)inlen),
        0);
    ExpectIntEQ(wc_Chacha_Process(&dec, plain, cipher, (word32)inlen), 0);
    ExpectIntEQ(XMEMCMP(input, plain, inlen), 0);

#if !defined(USE_INTEL_CHACHA_SPEEDUP) && !defined(WOLFSSL_ARMASM)
    /* test checking and using leftovers, currently just in C code */
    ExpectIntEQ(wc_Chacha_SetIV(&enc, cipher, 0), 0);
    ExpectIntEQ(wc_Chacha_SetIV(&dec, cipher, 0), 0);

    ExpectIntEQ(wc_Chacha_Process(&enc, cipher, (byte*)input,
        (word32)inlen - 2), 0);
    ExpectIntEQ(wc_Chacha_Process(&enc, cipher + (inlen - 2),
        (byte*)input + (inlen - 2), 2), 0);
    ExpectIntEQ(wc_Chacha_Process(&dec, plain, (byte*)cipher,
        (word32)inlen - 2), 0);
    ExpectIntEQ(wc_Chacha_Process(&dec, cipher + (inlen - 2),
        (byte*)input + (inlen - 2), 2), 0);
    ExpectIntEQ(XMEMCMP(input, plain, inlen), 0);

    /* check edge cases with counter increment */
    {
        /* expected results collected from wolfSSL 4.3.0 encrypted in one call*/
        const byte expected[] = {
            0x54,0xB1,0xE2,0xD4,0xA2,0x4D,0x52,0x5F,
            0x42,0x04,0x89,0x7C,0x6E,0x2D,0xFC,0x2D,
            0x10,0x25,0xB6,0x92,0x71,0xD5,0xC3,0x20,
            0xE3,0x0E,0xEC,0xF4,0xD8,0x10,0x70,0x29,
            0x2D,0x4C,0x2A,0x56,0x21,0xE1,0xC7,0x37,
            0x0B,0x86,0xF5,0x02,0x8C,0xB8,0xB8,0x38,
            0x41,0xFD,0xDF,0xD9,0xC3,0xE6,0xC8,0x88,
            0x06,0x82,0xD4,0x80,0x6A,0x50,0x69,0xD5,
            0xB9,0xB0,0x2F,0x44,0x36,0x5D,0xDA,0x5E,
            0xDE,0xF6,0xF5,0xFC,0x44,0xDC,0x07,0x51,
            0xA7,0x32,0x42,0xDB,0xCC,0xBD,0xE2,0xE5,
            0x0B,0xB1,0x14,0xFF,0x12,0x80,0x16,0x43,
            0xE7,0x40,0xD5,0xEA,0xC7,0x3F,0x69,0x07,
            0x64,0xD4,0x86,0x6C,0xE2,0x1F,0x8F,0x6E,
            0x35,0x41,0xE7,0xD3,0xB5,0x5D,0xD6,0xD4,
            0x9F,0x00,0xA9,0xAE,0x3D,0x28,0xA5,0x37,
            0x80,0x3D,0x11,0x25,0xE2,0xB6,0x99,0xD9,
            0x9B,0x98,0xE9,0x37,0xB9,0xF8,0xA0,0x04,
            0xDF,0x13,0x49,0x3F,0x19,0x6A,0x45,0x06,
            0x21,0xB4,0xC7,0x3B,0x49,0x45,0xB4,0xC8,
            0x03,0x5B,0x43,0x89,0xBD,0xB3,0x96,0x4B,
            0x17,0x6F,0x85,0xC6,0xCF,0xA6,0x05,0x35,
            0x1E,0x25,0x03,0xBB,0x55,0x0A,0xD5,0x54,
            0x41,0xEA,0xEB,0x50,0x40,0x1B,0x43,0x19,
            0x59,0x1B,0x0E,0x12,0x3E,0xA2,0x71,0xC3,
            0x1A,0xA7,0x11,0x50,0x43,0x9D,0x56,0x3B,
            0x63,0x2F,0x63,0xF1,0x8D,0xAE,0xF3,0x23,
            0xFA,0x1E,0xD8,0x6A,0xE1,0xB2,0x4B,0xF3,
            0xB9,0x13,0x7A,0x72,0x2B,0x6D,0xCC,0x41,
            0x1C,0x69,0x7C,0xCD,0x43,0x6F,0xE4,0xE2,
            0x38,0x99,0xFB,0xC3,0x38,0x92,0x62,0x35,
            0xC0,0x1D,0x60,0xE4,0x4B,0xDD,0x0C,0x14
        };
        const byte iv2[] = {
            0x9D,0xED,0xE7,0x0F,0xEC,0x81,0x51,0xD9,
            0x77,0x39,0x71,0xA6,0x21,0xDF,0xB8,0x93
        };
        byte input2[256];
        int i;

        for (i = 0; i < 256; i++)
            input2[i] = (byte)i;

        ExpectIntEQ(wc_Chacha_SetIV(&enc, iv2, 0), 0);

        ExpectIntEQ(wc_Chacha_Process(&enc, cipher, input2, 64), 0);
        ExpectIntEQ(XMEMCMP(expected, cipher, 64), 0);

        ExpectIntEQ(wc_Chacha_Process(&enc, cipher, input2 + 64, 128), 0);
        ExpectIntEQ(XMEMCMP(expected + 64, cipher, 128), 0);

        /* partial */
        ExpectIntEQ(wc_Chacha_Process(&enc, cipher, input2 + 192, 32), 0);
        ExpectIntEQ(XMEMCMP(expected + 192, cipher, 32), 0);

        ExpectIntEQ(wc_Chacha_Process(&enc, cipher, input2 + 224, 32), 0);
        ExpectIntEQ(XMEMCMP(expected + 224, cipher, 32), 0);
    }
#endif

    /* Test bad args. */
    ExpectIntEQ(wc_Chacha_Process(NULL, cipher, (byte*)input, (word32)inlen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    return EXPECT_RESULT();
} /* END test_wc_Chacha_Process */

