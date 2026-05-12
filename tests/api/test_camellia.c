/* test_camellia.c
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

#include <wolfssl/wolfcrypt/camellia.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_camellia.h>

/*
 * testing wc_CamelliaSetKey
 */
int test_wc_CamelliaSetKey(void)
{
    EXPECT_DECLS;
#ifdef HAVE_CAMELLIA
    wc_Camellia camellia;
    /*128-bit key*/
    static const byte key16[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    /* 192-bit key */
    static const byte key24[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77
    };
    /* 256-bit key */
    static const byte key32[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    static const byte iv[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    ExpectIntEQ(wc_CamelliaSetKey(&camellia, key16, (word32)sizeof(key16), iv),
        0);
    ExpectIntEQ(wc_CamelliaSetKey(&camellia, key16, (word32)sizeof(key16),
        NULL), 0);
    ExpectIntEQ(wc_CamelliaSetKey(&camellia, key24, (word32)sizeof(key24), iv),
        0);
    ExpectIntEQ(wc_CamelliaSetKey(&camellia, key24, (word32)sizeof(key24),
        NULL), 0);
    ExpectIntEQ(wc_CamelliaSetKey(&camellia, key32, (word32)sizeof(key32), iv),
        0);
    ExpectIntEQ(wc_CamelliaSetKey(&camellia, key32, (word32)sizeof(key32),
        NULL), 0);

    /* Bad args. */
    ExpectIntEQ(wc_CamelliaSetKey(NULL, key32, (word32)sizeof(key32), iv),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    return EXPECT_RESULT();
} /* END test_wc_CameliaSetKey */

/*
 * Testing wc_CamelliaSetIV()
 */
int test_wc_CamelliaSetIV(void)
{
    EXPECT_DECLS;
#ifdef HAVE_CAMELLIA
    wc_Camellia    camellia;
    static const byte iv[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    ExpectIntEQ(wc_CamelliaSetIV(&camellia, iv), 0);
    ExpectIntEQ(wc_CamelliaSetIV(&camellia, NULL), 0);

    /* Bad args. */
    ExpectIntEQ(wc_CamelliaSetIV(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_CamelliaSetIV(NULL, iv), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    return EXPECT_RESULT();
} /* END test_wc_CamelliaSetIV*/

/*
 * Test wc_CamelliaFree zeroes the key schedule and is NULL safe.
 */
int test_wc_CamelliaFree(void)
{
    EXPECT_DECLS;
#ifdef HAVE_CAMELLIA
    wc_Camellia camellia;
    static const byte key[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    static const byte iv[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    byte zero[sizeof(camellia)];

    XMEMSET(zero, 0, sizeof(zero));

    /* NULL is safe. */
    wc_CamelliaFree(NULL);

    /* After SetKey the schedule is populated; Free must wipe it. */
    ExpectIntEQ(wc_CamelliaSetKey(&camellia, key, (word32)sizeof(key), iv), 0);
    ExpectIntNE(XMEMCMP(&camellia, zero, sizeof(camellia)), 0);
    wc_CamelliaFree(&camellia);
    ExpectIntEQ(XMEMCMP(&camellia, zero, sizeof(camellia)), 0);
#endif
    return EXPECT_RESULT();
} /* END test_wc_CamelliaFree */

/*
 * Test wc_CamelliaEncryptDirect and wc_CamelliaDecryptDirect
 */
int test_wc_CamelliaEncryptDecryptDirect(void)
{
    EXPECT_DECLS;
#ifdef HAVE_CAMELLIA
    wc_Camellia camellia;
    static const byte key24[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77
    };
    static const byte iv[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    static const byte plainT[] = {
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
        0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A
    };
    byte    enc[sizeof(plainT)];
    byte    dec[sizeof(enc)];

    /* Init stack variables.*/
    XMEMSET(enc, 0, 16);
    XMEMSET(enc, 0, 16);

    ExpectIntEQ(wc_CamelliaSetKey(&camellia, key24, (word32)sizeof(key24), iv),
        0);
    ExpectIntEQ(wc_CamelliaEncryptDirect(&camellia, enc, plainT), 0);
    ExpectIntEQ(wc_CamelliaDecryptDirect(&camellia, dec, enc), 0);
    ExpectIntEQ(XMEMCMP(plainT, dec, WC_CAMELLIA_BLOCK_SIZE), 0);

    /* Pass bad args. */
    ExpectIntEQ(wc_CamelliaEncryptDirect(NULL, enc, plainT),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_CamelliaEncryptDirect(&camellia, NULL, plainT),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_CamelliaEncryptDirect(&camellia, enc, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_CamelliaDecryptDirect(NULL, dec, enc),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_CamelliaDecryptDirect(&camellia, NULL, enc),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_CamelliaDecryptDirect(&camellia, dec, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    return EXPECT_RESULT();
} /* END test-wc_CamelliaEncryptDecryptDirect */

/*
 * Testing wc_CamelliaCbcEncrypt and wc_CamelliaCbcDecrypt
 */
int test_wc_CamelliaCbcEncryptDecrypt(void)
{
    EXPECT_DECLS;
#ifdef HAVE_CAMELLIA
    wc_Camellia camellia;
    static const byte key24[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77
    };
    static const byte plainT[] = {
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
        0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A
    };
    byte    enc[WC_CAMELLIA_BLOCK_SIZE];
    byte    dec[WC_CAMELLIA_BLOCK_SIZE];

    /* Init stack variables. */
    XMEMSET(enc, 0, WC_CAMELLIA_BLOCK_SIZE);
    XMEMSET(enc, 0, WC_CAMELLIA_BLOCK_SIZE);

    ExpectIntEQ(wc_CamelliaSetKey(&camellia, key24, (word32)sizeof(key24),
        NULL), 0);
    ExpectIntEQ(wc_CamelliaCbcEncrypt(&camellia, enc, plainT,
        WC_CAMELLIA_BLOCK_SIZE), 0);

    ExpectIntEQ(wc_CamelliaSetKey(&camellia, key24, (word32)sizeof(key24),
        NULL), 0);
    ExpectIntEQ(wc_CamelliaCbcDecrypt(&camellia, dec, enc,
        WC_CAMELLIA_BLOCK_SIZE),
        0);
    ExpectIntEQ(XMEMCMP(plainT, dec, WC_CAMELLIA_BLOCK_SIZE), 0);

    /* Pass in bad args. */
    ExpectIntEQ(wc_CamelliaCbcEncrypt(NULL, enc, plainT,
        WC_CAMELLIA_BLOCK_SIZE),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_CamelliaCbcEncrypt(&camellia, NULL, plainT,
        WC_CAMELLIA_BLOCK_SIZE), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_CamelliaCbcEncrypt(&camellia, enc, NULL,
        WC_CAMELLIA_BLOCK_SIZE), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_CamelliaCbcDecrypt(NULL, dec, enc, WC_CAMELLIA_BLOCK_SIZE),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_CamelliaCbcDecrypt(&camellia, NULL, enc,
        WC_CAMELLIA_BLOCK_SIZE), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_CamelliaCbcDecrypt(&camellia, dec, NULL,
        WC_CAMELLIA_BLOCK_SIZE), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* non-block-aligned input rejected with BAD_LENGTH_E */
    ExpectIntEQ(wc_CamelliaCbcEncrypt(&camellia, enc, plainT,
        WC_CAMELLIA_BLOCK_SIZE - 1), WC_NO_ERR_TRACE(BAD_LENGTH_E));
    ExpectIntEQ(wc_CamelliaCbcDecrypt(&camellia, dec, enc,
        WC_CAMELLIA_BLOCK_SIZE - 1), WC_NO_ERR_TRACE(BAD_LENGTH_E));
#endif
    return EXPECT_RESULT();
} /* END test_wc_CamelliaCbcEncryptDecrypt */


#include <wolfssl/wolfcrypt/random.h>

#define MC_CIPHER_TEST_COUNT    100
#define MC_CAMELLIA_MAX_DATA_SZ 1024

/* Monte Carlo test for Camellia-CBC: random key, IV, and plaintext each
 * iteration */
int test_wc_CamelliaCbc_MonteCarlo(void)
{
    EXPECT_DECLS;
#ifdef HAVE_CAMELLIA
    static const word32 keySizes[] = {16, 24, 32};
    int numKeySizes = (int)(sizeof(keySizes) / sizeof(keySizes[0]));
    wc_Camellia camellia;
    WC_RNG rng;
    byte key[32];
    byte iv[WC_CAMELLIA_BLOCK_SIZE];
    word32 plainLen = 0, keyLen;
    int i;
    WC_DECLARE_VAR(plain,     byte, MC_CAMELLIA_MAX_DATA_SZ, NULL);
    WC_DECLARE_VAR(cipher,    byte, MC_CAMELLIA_MAX_DATA_SZ, NULL);
    WC_DECLARE_VAR(decrypted, byte, MC_CAMELLIA_MAX_DATA_SZ, NULL);

    WC_ALLOC_VAR(plain,     byte, MC_CAMELLIA_MAX_DATA_SZ, NULL);
    WC_ALLOC_VAR(cipher,    byte, MC_CAMELLIA_MAX_DATA_SZ, NULL);
    WC_ALLOC_VAR(decrypted, byte, MC_CAMELLIA_MAX_DATA_SZ, NULL);
#ifdef WC_DECLARE_VAR_IS_HEAP_ALLOC
    ExpectNotNull(plain);
    ExpectNotNull(cipher);
    ExpectNotNull(decrypted);
#endif

    XMEMSET(&camellia, 0, sizeof(camellia));
    XMEMSET(&rng, 0, sizeof(rng));

    ExpectIntEQ(wc_InitRng(&rng), 0);

    for (i = 0; i < MC_CIPHER_TEST_COUNT && EXPECT_SUCCESS(); i++) {
        keyLen = keySizes[i % numKeySizes];
        ExpectIntEQ(wc_RNG_GenerateBlock(&rng, key, keyLen), 0);
        ExpectIntEQ(wc_RNG_GenerateBlock(&rng, iv, sizeof(iv)), 0);
        ExpectIntEQ(wc_RNG_GenerateBlock(&rng, (byte*)&plainLen,
            sizeof(plainLen)), 0);
        /* Length 1..1024, rounded up to Camellia block size */
        plainLen = (plainLen % MC_CAMELLIA_MAX_DATA_SZ) + 1;
        plainLen = (plainLen + WC_CAMELLIA_BLOCK_SIZE - 1) &
                   ~((word32)WC_CAMELLIA_BLOCK_SIZE - 1);
        ExpectIntEQ(wc_RNG_GenerateBlock(&rng, plain, plainLen), 0);

        ExpectIntEQ(wc_CamelliaSetKey(&camellia, key, keyLen, iv), 0);
        ExpectIntEQ(wc_CamelliaCbcEncrypt(&camellia, cipher, plain,
            plainLen), 0);
        /* Reset IV by calling SetKey again before decrypt */
        ExpectIntEQ(wc_CamelliaSetKey(&camellia, key, keyLen, iv), 0);
        ExpectIntEQ(wc_CamelliaCbcDecrypt(&camellia, decrypted, cipher,
            plainLen), 0);
        ExpectBufEQ(decrypted, plain, plainLen);
    }

    wc_FreeRng(&rng);
    WC_FREE_VAR(plain,     NULL);
    WC_FREE_VAR(cipher,    NULL);
    WC_FREE_VAR(decrypted, NULL);
#endif
    return EXPECT_RESULT();
}
