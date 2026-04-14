/* test_rc2.c
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

#include <wolfssl/wolfcrypt/rc2.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_rc2.h>

/*
 * Testing function for wc_Rc2SetKey().
 */
int test_wc_Rc2SetKey(void)
{
    EXPECT_DECLS;
#ifdef WC_RC2
    Rc2  rc2;
    byte key40[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    byte iv[]    = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

    /* valid key and IV */
    ExpectIntEQ(wc_Rc2SetKey(&rc2, key40, (word32) sizeof(key40) / sizeof(byte),
        iv, 40), 0);
    /* valid key, no IV */
    ExpectIntEQ(wc_Rc2SetKey(&rc2, key40, (word32) sizeof(key40) / sizeof(byte),
        NULL, 40), 0);

    /* bad arguments  */
    /* null Rc2 struct */
    ExpectIntEQ(wc_Rc2SetKey(NULL, key40, (word32) sizeof(key40) / sizeof(byte),
        iv, 40), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* null key */
    ExpectIntEQ(wc_Rc2SetKey(&rc2, NULL, (word32) sizeof(key40) / sizeof(byte),
        iv, 40), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* key size == 0 */
    ExpectIntEQ(wc_Rc2SetKey(&rc2, key40, 0, iv, 40),
        WC_NO_ERR_TRACE(WC_KEY_SIZE_E));
    /* key size > 128 */
    ExpectIntEQ(wc_Rc2SetKey(&rc2, key40, 129, iv, 40),
        WC_NO_ERR_TRACE(WC_KEY_SIZE_E));
    /* effective bits == 0 */
    ExpectIntEQ(wc_Rc2SetKey(&rc2, key40, (word32)sizeof(key40) / sizeof(byte),
        iv, 0), WC_NO_ERR_TRACE(WC_KEY_SIZE_E));
    /* effective bits > 1024 */
    ExpectIntEQ(wc_Rc2SetKey(&rc2, key40, (word32)sizeof(key40) / sizeof(byte),
        iv, 1025), WC_NO_ERR_TRACE(WC_KEY_SIZE_E));
#endif
    return EXPECT_RESULT();
} /* END test_wc_Rc2SetKey */

/*
 * Testing function for wc_Rc2SetIV().
 */
int test_wc_Rc2SetIV(void)
{
    EXPECT_DECLS;
#ifdef WC_RC2
    Rc2  rc2;
    byte iv[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

    /* valid IV */
    ExpectIntEQ(wc_Rc2SetIV(&rc2, iv), 0);
    /* valid NULL IV */
    ExpectIntEQ(wc_Rc2SetIV(&rc2, NULL), 0);

    /* bad arguments */
    ExpectIntEQ(wc_Rc2SetIV(NULL, iv), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Rc2SetIV(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    return EXPECT_RESULT();
} /* END test_wc_Rc2SetIV */

/*
 * Testing function for wc_Rc2EcbEncrypt() and wc_Rc2EcbDecrypt().
 */
int test_wc_Rc2EcbEncryptDecrypt(void)
{
    EXPECT_DECLS;
#ifdef WC_RC2
    Rc2 rc2;
    int effectiveKeyBits = 63;
    byte cipher[RC2_BLOCK_SIZE];
    byte plain[RC2_BLOCK_SIZE];
    byte key[]    = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    byte input[]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    byte output[] = { 0xeb, 0xb7, 0x73, 0xf9, 0x93, 0x27, 0x8e, 0xff };

    XMEMSET(cipher, 0, sizeof(cipher));
    XMEMSET(plain, 0, sizeof(plain));

    ExpectIntEQ(wc_Rc2SetKey(&rc2, key, (word32) sizeof(key) / sizeof(byte),
        NULL, effectiveKeyBits), 0);
    ExpectIntEQ(wc_Rc2EcbEncrypt(&rc2, cipher, input, RC2_BLOCK_SIZE), 0);
    ExpectIntEQ(XMEMCMP(cipher, output, RC2_BLOCK_SIZE), 0);

    ExpectIntEQ(wc_Rc2EcbDecrypt(&rc2, plain, cipher, RC2_BLOCK_SIZE), 0);
    ExpectIntEQ(XMEMCMP(plain, input, RC2_BLOCK_SIZE), 0);

    /* Rc2EcbEncrypt bad arguments */
    /* null Rc2 struct */
    ExpectIntEQ(wc_Rc2EcbEncrypt(NULL, cipher, input, RC2_BLOCK_SIZE),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* null out buffer */
    ExpectIntEQ(wc_Rc2EcbEncrypt(&rc2, NULL, input, RC2_BLOCK_SIZE),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* null input buffer */
    ExpectIntEQ(wc_Rc2EcbEncrypt(&rc2, cipher, NULL, RC2_BLOCK_SIZE),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* output buffer sz != RC2_BLOCK_SIZE (8) */
    ExpectIntEQ(wc_Rc2EcbEncrypt(&rc2, cipher, input, 7),
        WC_NO_ERR_TRACE(BUFFER_E));

    /* Rc2EcbDecrypt bad arguments */
    /* null Rc2 struct */
    ExpectIntEQ(wc_Rc2EcbDecrypt(NULL, plain, output, RC2_BLOCK_SIZE),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* null out buffer */
    ExpectIntEQ(wc_Rc2EcbDecrypt(&rc2, NULL, output, RC2_BLOCK_SIZE),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* null input buffer */
    ExpectIntEQ(wc_Rc2EcbDecrypt(&rc2, plain, NULL, RC2_BLOCK_SIZE),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* output buffer sz != RC2_BLOCK_SIZE (8) */
    ExpectIntEQ(wc_Rc2EcbDecrypt(&rc2, plain, output, 7),
        WC_NO_ERR_TRACE(BUFFER_E));
#endif
    return EXPECT_RESULT();
} /* END test_wc_Rc2EcbEncryptDecrypt */

/*
 * Testing function for wc_Rc2CbcEncrypt() and wc_Rc2CbcDecrypt().
 */
int test_wc_Rc2CbcEncryptDecrypt(void)
{
    EXPECT_DECLS;
#ifdef WC_RC2
    Rc2 rc2;
    int effectiveKeyBits = 63;
    byte cipher[RC2_BLOCK_SIZE*2];
    byte plain[RC2_BLOCK_SIZE*2];
    /* vector taken from test.c */
    byte key[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    byte iv[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    byte input[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    byte output[] = {
        0xeb, 0xb7, 0x73, 0xf9, 0x93, 0x27, 0x8e, 0xff,
        0xf0, 0x51, 0x77, 0x8b, 0x65, 0xdb, 0x13, 0x57
    };

    XMEMSET(cipher, 0, sizeof(cipher));
    XMEMSET(plain, 0, sizeof(plain));

    ExpectIntEQ(wc_Rc2SetKey(&rc2, key, (word32) sizeof(key) / sizeof(byte),
        iv, effectiveKeyBits), 0);
    ExpectIntEQ(wc_Rc2CbcEncrypt(&rc2, cipher, input, sizeof(input)), 0);
    ExpectIntEQ(XMEMCMP(cipher, output, sizeof(output)), 0);

    /* reset IV for decrypt */
    ExpectIntEQ(wc_Rc2SetIV(&rc2, iv), 0);
    ExpectIntEQ(wc_Rc2CbcDecrypt(&rc2, plain, cipher, sizeof(cipher)), 0);
    ExpectIntEQ(XMEMCMP(plain, input, sizeof(input)), 0);

    /* Rc2CbcEncrypt bad arguments */
    /* null Rc2 struct */
    ExpectIntEQ(wc_Rc2CbcEncrypt(NULL, cipher, input, sizeof(input)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* null out buffer */
    ExpectIntEQ(wc_Rc2CbcEncrypt(&rc2, NULL, input, sizeof(input)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* null input buffer */
    ExpectIntEQ(wc_Rc2CbcEncrypt(&rc2, cipher, NULL, sizeof(input)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Rc2CbcDecrypt bad arguments */
    /* in size is 0 */
    ExpectIntEQ(wc_Rc2CbcDecrypt(&rc2, plain, output, 0), 0);
    /* null Rc2 struct */
    ExpectIntEQ(wc_Rc2CbcDecrypt(NULL, plain, output, sizeof(output)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* null out buffer */
    ExpectIntEQ(wc_Rc2CbcDecrypt(&rc2, NULL, output, sizeof(output)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* null input buffer */
    ExpectIntEQ(wc_Rc2CbcDecrypt(&rc2, plain, NULL, sizeof(output)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    return EXPECT_RESULT();
} /* END test_wc_Rc2CbcEncryptDecrypt */


#define MC_CIPHER_TEST_COUNT 100
#define MC_RC2_MAX_DATA_SZ   1024

int test_wc_Rc2Cbc_MonteCarlo(void)
{
    EXPECT_DECLS;
#ifdef WC_RC2
    Rc2    enc, dec;
    WC_RNG rng;
    byte   key[RC2_MAX_KEY_SIZE];
    byte   iv[RC2_BLOCK_SIZE];
    word32 plainLen = 0;
    int    effectiveBits;
    int    i;
    WC_DECLARE_VAR(plain,     byte, MC_RC2_MAX_DATA_SZ, NULL);
    WC_DECLARE_VAR(cipher,    byte, MC_RC2_MAX_DATA_SZ, NULL);
    WC_DECLARE_VAR(decrypted, byte, MC_RC2_MAX_DATA_SZ, NULL);
    WC_ALLOC_VAR(plain,     byte, MC_RC2_MAX_DATA_SZ, NULL);
    WC_ALLOC_VAR(cipher,    byte, MC_RC2_MAX_DATA_SZ, NULL);
    WC_ALLOC_VAR(decrypted, byte, MC_RC2_MAX_DATA_SZ, NULL);
#ifdef WC_DECLARE_VAR_IS_HEAP_ALLOC
    ExpectNotNull(plain);
    ExpectNotNull(cipher);
    ExpectNotNull(decrypted);
#endif
    XMEMSET(&enc, 0, sizeof(enc));
    XMEMSET(&dec, 0, sizeof(dec));
    XMEMSET(&rng, 0, sizeof(rng));
    ExpectIntEQ(wc_InitRng(&rng), 0);
    for (i = 0; i < MC_CIPHER_TEST_COUNT && EXPECT_SUCCESS(); i++) {
        word32 keyLen = 0;
        ExpectIntEQ(wc_RNG_GenerateBlock(&rng, (byte*)&keyLen, sizeof(keyLen)),
            0);
        keyLen = (keyLen % (RC2_MAX_KEY_SIZE - 1)) + 1;
        effectiveBits = (int)(keyLen * 8);
        ExpectIntEQ(wc_RNG_GenerateBlock(&rng, key, keyLen), 0);
        ExpectIntEQ(wc_RNG_GenerateBlock(&rng, iv, sizeof(iv)), 0);
        ExpectIntEQ(wc_RNG_GenerateBlock(&rng, (byte*)&plainLen,
            sizeof(plainLen)), 0);
        plainLen = (plainLen % MC_RC2_MAX_DATA_SZ) + 1;
        plainLen = (plainLen + RC2_BLOCK_SIZE - 1) &
            ~((word32)RC2_BLOCK_SIZE - 1);
        ExpectIntEQ(wc_RNG_GenerateBlock(&rng, plain, plainLen), 0);
        ExpectIntEQ(wc_Rc2SetKey(&enc, key, keyLen, iv, effectiveBits), 0);
        ExpectIntEQ(wc_Rc2CbcEncrypt(&enc, cipher, plain, plainLen), 0);
        ExpectIntEQ(wc_Rc2SetKey(&dec, key, keyLen, iv, effectiveBits), 0);
        ExpectIntEQ(wc_Rc2CbcDecrypt(&dec, decrypted, cipher, plainLen), 0);
        ExpectBufEQ(decrypted, plain, plainLen);
    }
    wc_FreeRng(&rng);
    WC_FREE_VAR(plain,     NULL);
    WC_FREE_VAR(cipher,    NULL);
    WC_FREE_VAR(decrypted, NULL);
#endif
    return EXPECT_RESULT();
}
