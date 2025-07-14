/* test_random.c
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

#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_random.h>


int test_wc_InitRng(void)
{
    EXPECT_DECLS;
#ifndef WC_NO_RNG
    WC_RNG rng[1];

    (void)rng;

    /* Bad parameter. */
    ExpectIntEQ(wc_InitRng(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitRng_ex(NULL, HEAP_HINT, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_FreeRng(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

#ifdef HAVE_HASHDRBG
    /* Good parameter. */
    ExpectIntEQ(wc_InitRng(rng), 0);
    ExpectIntEQ(wc_FreeRng(rng), 0);
    ExpectIntEQ(wc_InitRng_ex(rng, HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_FreeRng(rng), 0);
#endif
#elif !defined(HAVE_FIPS) || \
      (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2))
    WC_RNG rng[1];

    (void)rng;

    ExpectIntEQ(wc_InitRng(NULL), WC_NO_ERR_TRACE(NOT_COMPILED_IN));
    ExpectIntEQ(wc_InitRng_ex(NULL, HEAP_HINT, INVALID_DEVID),
        WC_NO_ERR_TRACE(NOT_COMPILED_IN));
    ExpectIntEQ(wc_FreeRng(NULL), WC_NO_ERR_TRACE(NOT_COMPILED_IN));

    ExpectIntEQ(wc_InitRng(rng), WC_NO_ERR_TRACE(NOT_COMPILED_IN));
    ExpectIntEQ(wc_InitRng_ex(rng, HEAP_HINT, INVALID_DEVID),
        WC_NO_ERR_TRACE(NOT_COMPILED_IN));
    ExpectIntEQ(wc_FreeRng(rng), WC_NO_ERR_TRACE(NOT_COMPILED_IN));
#endif
    return EXPECT_RESULT();
}


int test_wc_RNG_GenerateBlock_Reseed(void)
{
    EXPECT_DECLS;
#if defined(HAVE_HASHDRBG) && defined(TEST_RESEED_INTERVAL)
    int i;
    WC_RNG rng;
    byte key[32];

    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    for (i = 0; i < WC_RESEED_INTERVAL + 10; i++) {
        ExpectIntEQ(wc_RNG_GenerateBlock(&rng, key, sizeof(key)), 0);
    }
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
}

int test_wc_RNG_GenerateBlock(void)
{
    EXPECT_DECLS;
#ifdef HAVE_HASHDRBG
    int i;
    WC_RNG rng;
    byte key[32];

    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* Bad parameters. */
    ExpectIntEQ(wc_RNG_GenerateBlock(NULL, NULL, sizeof(key)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RNG_GenerateBlock(&rng, NULL, sizeof(key)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RNG_GenerateBlock(NULL, key , sizeof(key)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    for (i = 0; i <= (int)sizeof(key); i++) {
        ExpectIntEQ(wc_RNG_GenerateBlock(&rng, key + i, sizeof(key) - i), 0);
    }
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
}

int test_wc_RNG_GenerateByte(void)
{
    EXPECT_DECLS;
#ifdef HAVE_HASHDRBG
    int i;
    WC_RNG rng;
    byte output[10];

    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* Bad parameters. */
    ExpectIntEQ(wc_RNG_GenerateByte(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RNG_GenerateByte(&rng, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RNG_GenerateByte(NULL, output),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    for (i = 0; i < (int)sizeof(output); i++) {
        ExpectIntEQ(wc_RNG_GenerateByte(&rng, output + i), 0);
    }

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
}

int test_wc_InitRngNonce(void)
{
    EXPECT_DECLS;
#if !defined(WC_NO_RNG) && !defined(HAVE_SELFTEST) && \
    (!defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && \
     HAVE_FIPS_VERSION >= 2))
    WC_RNG rng;
    byte   nonce[] = "\x0D\x74\xDB\x42\xA9\x10\x77\xDE"
                     "\x45\xAC\x13\x7A\xE1\x48\xAF\x16";
    word32 nonceSz = sizeof(nonce);

    /* Bad parameters. */
    ExpectIntEQ(wc_InitRngNonce(NULL, NULL , nonceSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitRngNonce(&rng, NULL , nonceSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitRngNonce(NULL, nonce, nonceSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Good parameters. */
    ExpectIntEQ(wc_InitRngNonce(&rng, nonce, nonceSz), 0);
    ExpectIntEQ(wc_FreeRng(&rng), 0);
    ExpectIntEQ(wc_InitRngNonce(&rng, NULL, 0), 0);
    ExpectIntEQ(wc_FreeRng(&rng), 0);
    ExpectIntEQ(wc_InitRngNonce(&rng, nonce, 0), 0);
    ExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
}

int test_wc_InitRngNonce_ex(void)
{
    EXPECT_DECLS;
#if !defined(WC_NO_RNG) && !defined(HAVE_SELFTEST) && \
    (!defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && \
     HAVE_FIPS_VERSION >= 2))
    WC_RNG rng;
    byte   nonce[] = "\x0D\x74\xDB\x42\xA9\x10\x77\xDE"
                     "\x45\xAC\x13\x7A\xE1\x48\xAF\x16";
    word32 nonceSz = sizeof(nonce);

    /* Bad parameters. */
    ExpectIntEQ(wc_InitRngNonce_ex(NULL, NULL , nonceSz, HEAP_HINT, testDevId),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitRngNonce_ex(&rng, NULL , nonceSz, HEAP_HINT, testDevId),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitRngNonce_ex(NULL, nonce, nonceSz, HEAP_HINT, testDevId),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_InitRngNonce_ex(&rng, nonce, nonceSz, HEAP_HINT, testDevId),
        0);
    ExpectIntEQ(wc_FreeRng(&rng), 0);
    ExpectIntEQ(wc_InitRngNonce_ex(&rng, NULL, 0, HEAP_HINT, testDevId), 0);
    ExpectIntEQ(wc_FreeRng(&rng), 0);
    ExpectIntEQ(wc_InitRngNonce_ex(&rng, nonce, 0, HEAP_HINT, testDevId), 0);
    ExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
}

int test_wc_GenerateSeed(void)
{
    EXPECT_DECLS;
#if !defined(WC_NO_RNG) && !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
    OS_Seed seed[1];
    byte output[16];

    XMEMSET(seed, 0, sizeof(OS_Seed));

    /* Different configurations have different paths and different errors or
     * no error at all. */
#ifdef TEST_WC_GENERATE_SEED_PARAMS
    /* Bad parameters. */
    ExpectIntEQ(wc_GenerateSeed(NULL, NULL  , 16),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntLT(wc_GenerateSeed(seed, NULL  , 16), 0);
    ExpectIntEQ(wc_GenerateSeed(NULL, output, 16),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif

    /* Good parameters. */
    ExpectIntEQ(wc_GenerateSeed(seed, output, 16), 0);
#endif
    return EXPECT_RESULT();
}

int test_wc_rng_new(void)
{
    EXPECT_DECLS;
#if !defined(WC_NO_RNG) && !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST) && \
    !defined(WOLFSSL_NO_MALLOC)
    WC_RNG* rng = NULL;
    unsigned char nonce[16];
    word32 nonceSz = (word32)sizeof(nonce);

    XMEMSET(nonce, 0xa5, nonceSz);

    /* Bad parameters. */
    ExpectNull(wc_rng_new(NULL, nonceSz, HEAP_HINT));
    ExpectIntEQ(wc_rng_new_ex(&rng, NULL, nonceSz, HEAP_HINT, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectNull(rng);

    /* Good parameters. */
    ExpectNotNull(rng = wc_rng_new(nonce, nonceSz, HEAP_HINT));
#ifdef HAVE_HASHDRBG
    /* Ensure random object is usable. */
    ExpectIntEQ(wc_RNG_GenerateBlock(rng, nonce, nonceSz), 0);
#endif
    wc_rng_free(rng);
    rng = NULL;
    ExpectNotNull(rng = wc_rng_new(nonce, 0, HEAP_HINT));
#ifdef HAVE_HASHDRBG
    /* Ensure random object is usable. */
    ExpectIntEQ(wc_RNG_GenerateBlock(rng, nonce, nonceSz), 0);
#endif
    wc_rng_free(rng);
    rng = NULL;

    ExpectIntEQ(wc_rng_new_ex(&rng, nonce, nonceSz, HEAP_HINT, INVALID_DEVID),
        0);
    ExpectNotNull(rng);
#ifdef HAVE_HASHDRBG
    /* Ensure random object is usable. */
    ExpectIntEQ(wc_RNG_GenerateBlock(rng, nonce, nonceSz), 0);
#endif
    wc_rng_free(rng);
    rng = NULL;
    ExpectIntEQ(wc_rng_new_ex(&rng, nonce, 0, HEAP_HINT, INVALID_DEVID), 0);
    ExpectNotNull(rng);
#ifdef HAVE_HASHDRBG
    /* Ensure random object is usable. */
    ExpectIntEQ(wc_RNG_GenerateBlock(rng, nonce, nonceSz), 0);
#endif
    wc_rng_free(rng);

    wc_rng_free(NULL);
#endif
    return EXPECT_RESULT();
}

int test_wc_RNG_DRBG_Reseed(void)
{
    EXPECT_DECLS;
#if defined(HAVE_HASHDRBG) && !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
    WC_RNG rng[1];
    byte entropy[16];
    word32 entropySz = sizeof(entropy);

    XMEMSET(entropy, 0xa5, entropySz);

    ExpectIntEQ(wc_InitRng(rng), 0);

    /* Bad Parameters. */
    ExpectIntEQ(wc_RNG_DRBG_Reseed(NULL, NULL, entropySz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RNG_DRBG_Reseed(rng, NULL, entropySz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RNG_DRBG_Reseed(NULL, entropy, entropySz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Good Parameters. */
    ExpectIntEQ(wc_RNG_DRBG_Reseed(rng, entropy, entropySz), 0);
    ExpectIntEQ(wc_RNG_GenerateBlock(rng, entropy, entropySz), 0);
    ExpectIntEQ(wc_RNG_DRBG_Reseed(rng, entropy, 0), 0);
    ExpectIntEQ(wc_RNG_GenerateBlock(rng, entropy, entropySz), 0);

    ExpectIntEQ(wc_FreeRng(rng), 0);
#endif
    return EXPECT_RESULT();
}

int test_wc_RNG_TestSeed(void)
{
    EXPECT_DECLS;
#if defined(HAVE_HASHDRBG) && \
    !(defined(HAVE_FIPS) || defined(HAVE_SELFTEST)) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2))
    byte seed[16];
    byte i;

#ifdef TEST_WC_RNG_TESTSEED_BAD_PARAMS
    /* Doesn't handle NULL. */
    ExpectIntEQ(wc_RNG_TestSeed(NULL, sizeof(seed)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Doesn't handle seed being less than SEED_BLOCK_SZ which is not public
     * and is different for different configurations. */
    for (i = 0; i < 4; i++) {
        ExpectIntEQ(wc_RNG_TestSeed(seed, i),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }
#endif

    /* Bad seed as it repeats. */
    XMEMSET(seed, 0xa5, sizeof(seed));
    /* Return value is DRBG_CONT_FAILURE which is not public. */
    ExpectIntGT(wc_RNG_TestSeed(seed, sizeof(seed)), 0);

    /* Good seed. */
    for (i = 0; i < (byte)sizeof(seed); i++)
        seed[i] = i;
    ExpectIntEQ(wc_RNG_TestSeed(seed, sizeof(seed)), 0);
#endif
    return EXPECT_RESULT();
}

int test_wc_RNG_HealthTest(void)
{
    EXPECT_DECLS;
#if defined(HAVE_HASHDRBG)
    static const byte test1Seed[] = {
        0xa6, 0x5a, 0xd0, 0xf3, 0x45, 0xdb, 0x4e, 0x0e,
        0xff, 0xe8, 0x75, 0xc3, 0xa2, 0xe7, 0x1f, 0x42,
        0xc7, 0x12, 0x9d, 0x62, 0x0f, 0xf5, 0xc1, 0x19,
        0xa9, 0xef, 0x55, 0xf0, 0x51, 0x85, 0xe0, 0xfb,
        0x85, 0x81, 0xf9, 0x31, 0x75, 0x17, 0x27, 0x6e,
        0x06, 0xe9, 0x60, 0x7d, 0xdb, 0xcb, 0xcc, 0x2e
    };
    static const byte test1Output[] = {
        0xd3, 0xe1, 0x60, 0xc3, 0x5b, 0x99, 0xf3, 0x40,
        0xb2, 0x62, 0x82, 0x64, 0xd1, 0x75, 0x10, 0x60,
        0xe0, 0x04, 0x5d, 0xa3, 0x83, 0xff, 0x57, 0xa5,
        0x7d, 0x73, 0xa6, 0x73, 0xd2, 0xb8, 0xd8, 0x0d,
        0xaa, 0xf6, 0xa6, 0xc3, 0x5a, 0x91, 0xbb, 0x45,
        0x79, 0xd7, 0x3f, 0xd0, 0xc8, 0xfe, 0xd1, 0x11,
        0xb0, 0x39, 0x13, 0x06, 0x82, 0x8a, 0xdf, 0xed,
        0x52, 0x8f, 0x01, 0x81, 0x21, 0xb3, 0xfe, 0xbd,
        0xc3, 0x43, 0xe7, 0x97, 0xb8, 0x7d, 0xbb, 0x63,
        0xdb, 0x13, 0x33, 0xde, 0xd9, 0xd1, 0xec, 0xe1,
        0x77, 0xcf, 0xa6, 0xb7, 0x1f, 0xe8, 0xab, 0x1d,
        0xa4, 0x66, 0x24, 0xed, 0x64, 0x15, 0xe5, 0x1c,
        0xcd, 0xe2, 0xc7, 0xca, 0x86, 0xe2, 0x83, 0x99,
        0x0e, 0xea, 0xeb, 0x91, 0x12, 0x04, 0x15, 0x52,
        0x8b, 0x22, 0x95, 0x91, 0x02, 0x81, 0xb0, 0x2d,
        0xd4, 0x31, 0xf4, 0xc9, 0xf7, 0x04, 0x27, 0xdf
    };
    static const byte test2SeedA[] = {
        0x63, 0x36, 0x33, 0x77, 0xe4, 0x1e, 0x86, 0x46,
        0x8d, 0xeb, 0x0a, 0xb4, 0xa8, 0xed, 0x68, 0x3f,
        0x6a, 0x13, 0x4e, 0x47, 0xe0, 0x14, 0xc7, 0x00,
        0x45, 0x4e, 0x81, 0xe9, 0x53, 0x58, 0xa5, 0x69,
        0x80, 0x8a, 0xa3, 0x8f, 0x2a, 0x72, 0xa6, 0x23,
        0x59, 0x91, 0x5a, 0x9f, 0x8a, 0x04, 0xca, 0x68
    };
    static const byte test2SeedB[] = {
        0xe6, 0x2b, 0x8a, 0x8e, 0xe8, 0xf1, 0x41, 0xb6,
        0x98, 0x05, 0x66, 0xe3, 0xbf, 0xe3, 0xc0, 0x49,
        0x03, 0xda, 0xd4, 0xac, 0x2c, 0xdf, 0x9f, 0x22,
        0x80, 0x01, 0x0a, 0x67, 0x39, 0xbc, 0x83, 0xd3
    };
    static const byte test2Output[] = {
        0x04, 0xee, 0xc6, 0x3b, 0xb2, 0x31, 0xdf, 0x2c,
        0x63, 0x0a, 0x1a, 0xfb, 0xe7, 0x24, 0x94, 0x9d,
        0x00, 0x5a, 0x58, 0x78, 0x51, 0xe1, 0xaa, 0x79,
        0x5e, 0x47, 0x73, 0x47, 0xc8, 0xb0, 0x56, 0x62,
        0x1c, 0x18, 0xbd, 0xdc, 0xdd, 0x8d, 0x99, 0xfc,
        0x5f, 0xc2, 0xb9, 0x20, 0x53, 0xd8, 0xcf, 0xac,
        0xfb, 0x0b, 0xb8, 0x83, 0x12, 0x05, 0xfa, 0xd1,
        0xdd, 0xd6, 0xc0, 0x71, 0x31, 0x8a, 0x60, 0x18,
        0xf0, 0x3b, 0x73, 0xf5, 0xed, 0xe4, 0xd4, 0xd0,
        0x71, 0xf9, 0xde, 0x03, 0xfd, 0x7a, 0xea, 0x10,
        0x5d, 0x92, 0x99, 0xb8, 0xaf, 0x99, 0xaa, 0x07,
        0x5b, 0xdb, 0x4d, 0xb9, 0xaa, 0x28, 0xc1, 0x8d,
        0x17, 0x4b, 0x56, 0xee, 0x2a, 0x01, 0x4d, 0x09,
        0x88, 0x96, 0xff, 0x22, 0x82, 0xc9, 0x55, 0xa8,
        0x19, 0x69, 0xe0, 0x69, 0xfa, 0x8c, 0xe0, 0x07,
        0xa1, 0x80, 0x18, 0x3a, 0x07, 0xdf, 0xae, 0x17
    };
#if !(defined(HAVE_FIPS) || defined(HAVE_SELFTEST)) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2))
    static const byte testEx1Nonce[] = {
        0x89, 0xc9, 0x49, 0xe9, 0xc8, 0x04, 0xaf, 0x01,
        0x4d, 0x56, 0x04, 0xb3, 0x94, 0x59, 0xf2, 0xc8
    };
    static const byte testEx1Output[] = {
        0x2d, 0xa7, 0x72, 0x76, 0xe2, 0xab, 0xf5, 0x79,
        0x08, 0x4f, 0x1a, 0xf3, 0x53, 0xb4, 0xec, 0x58,
        0x07, 0x09, 0x1f, 0x61, 0xa4, 0x3c, 0x65, 0x38,
        0xd3, 0x43, 0x66, 0x29, 0x10, 0x81, 0x33, 0xa6,
        0xb8, 0x71, 0x8d, 0xc0, 0x27, 0x80, 0xfe, 0x11,
        0x85, 0xc6, 0xe6, 0x40, 0x69, 0x23, 0x39, 0x74,
        0x4a, 0xc9, 0xdc, 0x68, 0x6f, 0x47, 0x5c, 0x5c,
        0x56, 0xc8, 0x00, 0x78, 0xcf, 0x12, 0x7a, 0x67,
        0x27, 0x1b, 0xe7, 0x14, 0xdf, 0x9d, 0x22, 0xb5,
        0x5a, 0x8a, 0x2f, 0xdd, 0x7b, 0x6f, 0xb7, 0xf4,
        0xe3, 0x58, 0x8e, 0x6c, 0x79, 0x09, 0xf1, 0xe3,
        0x15, 0x1d, 0x9f, 0x1f, 0x69, 0x23, 0x70, 0x2f,
        0xd0, 0xee, 0x4e, 0xdd, 0x02, 0x56, 0xeb, 0x3f,
        0x25, 0xcc, 0x63, 0x06, 0x70, 0x97, 0x07, 0x76,
        0xb3, 0xe1, 0x39, 0xbd, 0xd3, 0xc2, 0x12, 0xeb,
        0x42, 0x77, 0xe8, 0xc5, 0xd0, 0xde, 0xf1, 0x4f
    };
    static const byte testEx2Nonce[] = {
        0xeb, 0xb7, 0x73, 0xf9, 0x93, 0x27, 0x8e, 0xff,
        0xf0, 0x51, 0x77, 0x8b, 0x65, 0xdb, 0x13, 0x57
    };
    static const byte testEx2Output[] = {
        0x40, 0xb2, 0xeb, 0x2b, 0x10, 0x53, 0x30, 0x8f,
        0xe4, 0xa0, 0x47, 0xe0, 0x24, 0x22, 0xe7, 0x03,
        0x03, 0x90, 0x91, 0x7b, 0xa5, 0xa8, 0xa2, 0xfd,
        0xba, 0x3b, 0xc9, 0x8e, 0xfb, 0x39, 0xef, 0xd9,
        0xae, 0x62, 0xb7, 0x0b, 0x21, 0xe6, 0x93, 0x22,
        0xeb, 0x3d, 0x3b, 0x00, 0x59, 0xaa, 0xc0, 0x27,
        0x0c, 0xde, 0xb4, 0xbd, 0x5c, 0x73, 0xa6, 0x51,
        0xf5, 0x55, 0x2c, 0xf4, 0xb8, 0xc8, 0x46, 0x04,
        0x03, 0x63, 0xa7, 0x9f, 0x81, 0xd1, 0x34, 0x1c,
        0x93, 0x86, 0x43, 0x09, 0x4c, 0x0e, 0x0a, 0x7d,
        0x54, 0x63, 0xc4, 0x72, 0xbe, 0xe3, 0x30, 0x39,
        0x3b, 0x1b, 0x8d, 0xbe, 0x55, 0x9a, 0x46, 0x11,
        0x75, 0x22, 0x00, 0xcc, 0x5a, 0xa6, 0xbb, 0x8c,
        0xd1, 0x70, 0xba, 0xbc, 0x3c, 0xf5, 0xcf, 0x81,
        0xa5, 0x17, 0x5a, 0x34, 0x0c, 0x29, 0xca, 0xcf,
        0x2b, 0x27, 0x38, 0x42, 0x21, 0x32, 0x9b, 0xc0
    };
#endif
    byte output[WC_SHA256_DIGEST_SIZE * 4];

    /* Bad parameters. */
    ExpectIntEQ(wc_RNG_HealthTest(0, NULL     , 0                , NULL, 0,
        NULL  , 0             ), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RNG_HealthTest(0, test1Seed, sizeof(test1Seed), NULL, 0,
        NULL  , 0             ), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RNG_HealthTest(0, NULL     , 0                , NULL, 0,
        output, sizeof(output)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RNG_HealthTest(0, test1Seed, sizeof(test1Seed), NULL, 0,
        output, 0             ), WC_NO_ERR_TRACE(-1));

    /* Good parameters. */
    ExpectIntEQ(wc_RNG_HealthTest(0, test1Seed, sizeof(test1Seed), NULL, 0,
        output, sizeof(output)), 0);
    ExpectBufEQ(test1Output, output, sizeof(output));

    ExpectIntEQ(wc_RNG_HealthTest(1, test2SeedA, sizeof(test2SeedA), test2SeedB,
        sizeof(test2SeedB), output, sizeof(output)), 0);
    ExpectBufEQ(test2Output, output, sizeof(output));

#if !(defined(HAVE_FIPS) || defined(HAVE_SELFTEST)) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2))
    /* Bad parameters. */
    ExpectIntEQ(wc_RNG_HealthTest_ex(0, NULL, 0, NULL     , 0                ,
        NULL, 0, NULL  , 0             , HEAP_HINT, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RNG_HealthTest_ex(0, NULL, 0, test1Seed, sizeof(test1Seed),
        NULL, 0, NULL  , 0             , HEAP_HINT,
        INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RNG_HealthTest_ex(0, NULL, 0, NULL     , 0                ,
        NULL, 0, output, sizeof(output), HEAP_HINT, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RNG_HealthTest_ex(0, NULL, 0, test1Seed, sizeof(test1Seed),
        NULL, 0, output, 0             , HEAP_HINT, INVALID_DEVID),
        WC_NO_ERR_TRACE(-1));

    /* Good parameters. */
    ExpectIntEQ(wc_RNG_HealthTest_ex(0, NULL, 0, test1Seed, sizeof(test1Seed),
        NULL, 0, output, sizeof(output), HEAP_HINT, INVALID_DEVID), 0);
    ExpectBufEQ(test1Output, output, sizeof(output));
    /*  with nonce */
    ExpectIntEQ(wc_RNG_HealthTest_ex(0, testEx1Nonce, sizeof(testEx1Nonce),
        test1Seed, sizeof(test1Seed), NULL, 0, output, sizeof(output),
        HEAP_HINT, INVALID_DEVID), 0);
    ExpectBufEQ(testEx1Output, output, sizeof(output));

    ExpectIntEQ(wc_RNG_HealthTest_ex(1, NULL, 0, test2SeedA, sizeof(test2SeedA),
        test2SeedB, sizeof(test2SeedB), output, sizeof(output), HEAP_HINT,
        INVALID_DEVID), 0);
    ExpectBufEQ(test2Output, output, sizeof(output));
    /*  with nonce */
    ExpectIntEQ(wc_RNG_HealthTest_ex(1, testEx2Nonce, sizeof(testEx2Nonce),
        test2SeedA, sizeof(test2SeedA), test2SeedB, sizeof(test2SeedB), output,
        sizeof(output), HEAP_HINT, INVALID_DEVID), 0);
    ExpectBufEQ(testEx2Output, output, sizeof(output));
#endif
#endif
    return EXPECT_RESULT();
}

