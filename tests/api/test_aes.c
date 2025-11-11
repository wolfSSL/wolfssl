/* test_aes.c
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

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/wc_encrypt.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_aes.h>

/*******************************************************************************
 * AES
 ******************************************************************************/

#ifndef NO_AES
static int test_wc_AesSetKey_BadArgs(Aes* aes, byte* key, word32 keyLen,
    byte* iv)
{
    EXPECT_DECLS;

    ExpectIntEQ(wc_AesSetKey(NULL, NULL, keyLen, iv, AES_ENCRYPTION),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesSetKey(NULL, key , keyLen, iv, AES_ENCRYPTION),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesSetKey(aes , key , 48    , iv, AES_ENCRYPTION),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    return EXPECT_RESULT();
}

static int test_wc_AesSetKey_WithKey(Aes* aes, byte* key, word32 keyLen,
    byte* iv, int ret)
{
    EXPECT_DECLS;

    ExpectIntEQ(wc_AesSetKey(aes, key, keyLen, iv, AES_ENCRYPTION), ret);
    ExpectIntEQ(wc_AesSetKey(aes, key, keyLen, NULL, AES_DECRYPTION), ret);

    return EXPECT_RESULT();
}
#endif

/*
 * Testing function for wc_AesSetKey().
 */
int test_wc_AesSetKey(void)
{
    EXPECT_DECLS;
#ifndef NO_AES
    Aes  aes;
    byte key16[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    byte key24[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
    };
    byte key32[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    byte badKey16[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65
    };
    byte iv[] = "1234567890abcdef";
    byte* key;
    word32 keyLen;

#if defined(WOLFSSL_AES_128)
    key = key16;
    keyLen = (word32)sizeof(key16) / sizeof(byte);
#elif defined(WOLFSSL_AES_192)
    key = key24;
    keyLen = (word32)sizeof(key24) / sizeof(byte);
#else
    key = key32;
    keyLen = (word32)sizeof(key32) / sizeof(byte);
#endif

    XMEMSET(&aes, 0, sizeof(Aes));

    ExpectIntEQ(wc_AesInit(NULL, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesInit(&aes, NULL, INVALID_DEVID), 0);

    EXPECT_TEST(test_wc_AesSetKey_BadArgs(&aes, key, keyLen, iv));

#ifdef WOLFSSL_AES_128
    EXPECT_TEST(test_wc_AesSetKey_WithKey(&aes, key16,
        (word32)sizeof(key16) / sizeof(byte), iv, 0));
#else
    EXPECT_TEST(test_wc_AesSetKey_WithKey(&aes, key16,
        (word32)sizeof(key16) / sizeof(byte), iv, BAD_FUNC_ARG));
#endif
#ifdef WOLFSSL_AES_192
    EXPECT_TEST(test_wc_AesSetKey_WithKey(&aes, key24,
        (word32)sizeof(key24) / sizeof(byte), iv, 0));
#else
    EXPECT_TEST(test_wc_AesSetKey_WithKey(&aes, key24,
        (word32)sizeof(key24) / sizeof(byte), iv, BAD_FUNC_ARG));
#endif
#ifdef WOLFSSL_AES_256
    EXPECT_TEST(test_wc_AesSetKey_WithKey(&aes, key32,
        (word32)sizeof(key32) / sizeof(byte), iv, 0));
#else
    EXPECT_TEST(test_wc_AesSetKey_WithKey(&aes, key32,
        (word32)sizeof(key32) / sizeof(byte), iv, BAD_FUNC_ARG));
#endif

    ExpectIntEQ(wc_AesSetKey(&aes, badKey16,
        (word32)sizeof(badKey16) / sizeof(byte), iv, AES_ENCRYPTION),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_AesFree(&aes);
#endif
    return EXPECT_RESULT();
} /* END test_wc_AesSetKey */

/*
 * Testing function for wc_AesSetIV
 */
int test_wc_AesSetIV(void)
{
    EXPECT_DECLS;
#if !defined(NO_AES)
    Aes     aes;
#if defined(WOLFSSL_AES_128)
    byte    key16[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
#endif
    byte    iv1[]    = "1234567890abcdef";
    byte    iv2[]    = "0987654321fedcba";

    ExpectIntEQ(wc_AesInit(&aes, NULL, INVALID_DEVID), 0);

#if defined(WOLFSSL_AES_128)
    ExpectIntEQ(wc_AesSetKey(&aes, key16, (word32) sizeof(key16) / sizeof(byte),
        iv1, AES_ENCRYPTION), 0);
#endif
    ExpectIntEQ(wc_AesSetIV(&aes, iv2), 0);

    ExpectIntEQ(wc_AesSetIV(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesSetIV(NULL, iv1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesSetIV(&aes, NULL), 0);

    wc_AesFree(&aes);
#endif
    return EXPECT_RESULT();
} /* test_wc_AesSetIV */


/*******************************************************************************
 * AES Direct
 ******************************************************************************/

#if !defined(NO_AES) && defined(WOLFSSL_AES_DIRECT) && \
    (!defined(HAVE_FIPS) || !defined(HAVE_FIPS_VERSION) || \
        (HAVE_FIPS_VERSION > 6)) && !defined(HAVE_SELFTEST)
static int test_wc_AesEncryptDecryptDirect_WithKey(Aes* aes, byte* key,
    word32 keyLen, byte* expected)
{
    EXPECT_DECLS;
    byte plain[WC_AES_BLOCK_SIZE];
    byte cipher[WC_AES_BLOCK_SIZE];
#ifdef HAVE_AES_DECRYPT
    byte decrypted[WC_AES_BLOCK_SIZE];
#endif

    XMEMSET(plain, 0, WC_AES_BLOCK_SIZE);

    ExpectIntEQ(wc_AesSetKey(aes, key, keyLen, NULL, AES_ENCRYPTION), 0);

    ExpectIntEQ(wc_AesEncryptDirect(NULL, NULL, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_AesEncryptDirect(aes, cipher, plain), 0);
    ExpectBufEQ(cipher, expected, WC_AES_BLOCK_SIZE);

#ifdef HAVE_AES_DECRYPT
    ExpectIntEQ(wc_AesSetKey(aes, key, keyLen, NULL, AES_DECRYPTION), 0);
    ExpectIntEQ(wc_AesDecryptDirect(NULL, NULL, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesDecryptDirect(aes, decrypted, cipher), 0);
    ExpectBufEQ(decrypted, plain, WC_AES_BLOCK_SIZE);
#endif

    return EXPECT_RESULT();
}
#endif

int test_wc_AesEncryptDecryptDirect(void)
{
    EXPECT_DECLS;
#if !defined(NO_AES) && defined(WOLFSSL_AES_DIRECT) && \
    (!defined(HAVE_FIPS) || !defined(HAVE_FIPS_VERSION) || \
        (HAVE_FIPS_VERSION > 6)) && !defined(HAVE_SELFTEST)
    Aes aes;
#if defined(WOLFSSL_AES_128)
    byte key16[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    byte expected16[WC_AES_BLOCK_SIZE] = {
        0x0b, 0x9b, 0x15, 0xda, 0x4b, 0x44, 0xa0, 0xf5,
        0x15, 0x1d, 0xcf, 0xc4, 0xc0, 0x1f, 0x35, 0xd5,
    };
#endif
#if defined(WOLFSSL_AES_192)
    byte key24[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    byte expected24[WC_AES_BLOCK_SIZE] = {
        0xbe, 0x55, 0x02, 0x05, 0xfc, 0x91, 0xe8, 0x9c,
        0x9b, 0x9c, 0xc4, 0x70, 0x93, 0xb9, 0x0a, 0x08,
    };
#endif
#if defined(WOLFSSL_AES_256)
    byte key32[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    byte expected32[WC_AES_BLOCK_SIZE] = {
        0x7d, 0xbd, 0x88, 0x27, 0x2f, 0xb2, 0x59, 0x37,
        0x69, 0x2a, 0x3b, 0x81, 0x00, 0x47, 0x41, 0x75,
    };
#endif

    XMEMSET(&aes, 0, sizeof(Aes));
    ExpectIntEQ(wc_AesInit(&aes, NULL, INVALID_DEVID), 0);

#ifdef WOLFSSL_AES_128
    EXPECT_TEST(test_wc_AesEncryptDecryptDirect_WithKey(&aes, key16,
        (word32)sizeof(key16) / sizeof(byte), expected16));
#endif
#ifdef WOLFSSL_AES_192
    EXPECT_TEST(test_wc_AesEncryptDecryptDirect_WithKey(&aes, key24,
        (word32)sizeof(key24) / sizeof(byte), expected24));
#endif
#ifdef WOLFSSL_AES_256
    EXPECT_TEST(test_wc_AesEncryptDecryptDirect_WithKey(&aes, key32,
        (word32)sizeof(key32) / sizeof(byte), expected32));
#endif

    wc_AesFree(&aes);
#endif
    return EXPECT_RESULT();
}

/*******************************************************************************
 * AES-ECB
 ******************************************************************************/

#if !defined(NO_AES) && defined(HAVE_AES_ECB)
/* Assembly code doing 8 iterations at a time. */
#define ECB_LEN     (9 * WC_AES_BLOCK_SIZE)

static int test_wc_AesEcbEncryptDecrypt_BadArgs(Aes* aes, byte* key,
    word32 keyLen)
{
    EXPECT_DECLS;
    byte plain[WC_AES_BLOCK_SIZE];
    byte cipher[WC_AES_BLOCK_SIZE];
    byte decrypted[WC_AES_BLOCK_SIZE];

    XMEMSET(plain, 0, WC_AES_BLOCK_SIZE);
    XMEMSET(cipher, 0, WC_AES_BLOCK_SIZE);

    ExpectIntEQ(wc_AesSetKey(aes, key, keyLen, NULL, AES_DECRYPTION), 0);
    ExpectIntEQ(wc_AesEcbEncrypt(NULL, NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesEcbEncrypt(aes, NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesEcbEncrypt(NULL, cipher, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesEcbEncrypt(NULL, NULL, plain, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesEcbEncrypt(aes, cipher, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesEcbEncrypt(aes, NULL, plain, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesEcbEncrypt(NULL, cipher, plain, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_AesSetKey(aes, key, keyLen, NULL, AES_DECRYPTION), 0);
    ExpectIntEQ(wc_AesEcbDecrypt(NULL, NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesEcbDecrypt(aes, NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesEcbDecrypt(NULL, decrypted, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesEcbDecrypt(NULL, NULL, cipher, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesEcbDecrypt(aes, decrypted, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesEcbDecrypt(aes, NULL, cipher, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesEcbDecrypt(NULL, decrypted, cipher, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    return EXPECT_RESULT();
}

static int test_wc_AesEcbEncryptDecrypt_WithKey(Aes* aes, byte* key,
    word32 keyLen, byte* expected)
{
    EXPECT_DECLS;
    WC_DECLARE_VAR(plain, byte, ECB_LEN, NULL);
    WC_DECLARE_VAR(cipher, byte, ECB_LEN, NULL);
    WC_DECLARE_VAR(decrypted, byte, ECB_LEN, NULL);

    WC_ALLOC_VAR(plain, byte, ECB_LEN, NULL);
    WC_ALLOC_VAR(cipher, byte, ECB_LEN, NULL);
    WC_ALLOC_VAR(decrypted, byte, ECB_LEN, NULL);

#ifdef WC_DECLARE_VAR_IS_HEAP_ALLOC
    ExpectNotNull(plain);
    ExpectNotNull(cipher);
    ExpectNotNull(decrypted);
#endif

    XMEMSET(plain, 0, ECB_LEN);

    ExpectIntEQ(wc_AesSetKey(aes, key, keyLen, NULL, AES_ENCRYPTION), 0);
    ExpectIntEQ(wc_AesEcbEncrypt(aes, cipher, plain, WC_AES_BLOCK_SIZE), 0);
    ExpectBufEQ(cipher, expected, WC_AES_BLOCK_SIZE);

#ifdef HAVE_AES_DECRYPT
    ExpectIntEQ(wc_AesSetKey(aes, key, keyLen, NULL, AES_DECRYPTION), 0);
    ExpectIntEQ(wc_AesEcbDecrypt(aes, decrypted, cipher, WC_AES_BLOCK_SIZE),
        0);
    ExpectBufEQ(decrypted, plain, WC_AES_BLOCK_SIZE);
#endif

    ExpectIntEQ(wc_AesSetKey(aes, key, keyLen, NULL, AES_ENCRYPTION), 0);
    ExpectIntEQ(wc_AesEcbEncrypt(aes, cipher, plain, 32), 0);
    ExpectBufEQ(cipher + WC_AES_BLOCK_SIZE, cipher, WC_AES_BLOCK_SIZE);
    ExpectBufEQ(cipher, expected, WC_AES_BLOCK_SIZE);
#ifdef HAVE_AES_DECRYPT
    ExpectIntEQ(wc_AesSetKey(aes, key, keyLen, NULL, AES_DECRYPTION), 0);
    ExpectIntEQ(wc_AesEcbDecrypt(aes, decrypted, cipher, 32), 0);
    ExpectBufEQ(decrypted, plain, 32);
#endif

    WC_FREE_VAR(plain, NULL);
    WC_FREE_VAR(cipher, NULL);
    WC_FREE_VAR(decrypted, NULL);
    return EXPECT_RESULT();
}

static int test_wc_AesEcbEncryptDecrypt_MultiBlocks(Aes* aes, byte* key,
    word32 keyLen, byte* expected)
{
    EXPECT_DECLS;
    int sz;
    int cnt;
    WC_DECLARE_VAR(plain, byte, ECB_LEN, NULL);
    WC_DECLARE_VAR(cipher, byte, ECB_LEN, NULL);
    WC_DECLARE_VAR(decrypted, byte, ECB_LEN, NULL);

    WC_ALLOC_VAR(plain, byte, ECB_LEN, NULL);
    WC_ALLOC_VAR(cipher, byte, ECB_LEN, NULL);
    WC_ALLOC_VAR(decrypted, byte, ECB_LEN, NULL);

#ifdef WC_DECLARE_VAR_IS_HEAP_ALLOC
    ExpectNotNull(plain);
    ExpectNotNull(cipher);
    ExpectNotNull(decrypted);
#endif

    XMEMSET(plain, 0, ECB_LEN);

    ExpectIntEQ(wc_AesSetKey(aes, key, keyLen, NULL, AES_ENCRYPTION), 0);
    /* Test multiple blocks. */
    for (sz = WC_AES_BLOCK_SIZE; sz <= ECB_LEN; sz += WC_AES_BLOCK_SIZE) {
        XMEMSET(cipher, 0x00, ECB_LEN);
        for (cnt = 0; cnt + sz <= ECB_LEN; cnt += sz) {
            ExpectIntEQ(wc_AesEcbEncrypt(aes, cipher + cnt, plain + cnt, sz),
                0);
        }
        if (cnt < ECB_LEN) {
            ExpectIntEQ(wc_AesEcbEncrypt(aes, cipher + cnt, plain + cnt,
                ECB_LEN - cnt), 0);
        }
        for (cnt = 0; cnt < ECB_LEN; cnt += WC_AES_BLOCK_SIZE) {
            ExpectBufEQ(cipher + cnt, expected, WC_AES_BLOCK_SIZE);
        }
    }
#ifdef HAVE_AES_DECRYPT
    ExpectIntEQ(wc_AesSetKey(aes, key, keyLen, NULL, AES_DECRYPTION), 0);
    for (sz = WC_AES_BLOCK_SIZE; sz <= ECB_LEN; sz += WC_AES_BLOCK_SIZE) {
        XMEMSET(decrypted, 0xff, ECB_LEN);
        for (cnt = 0; cnt + sz <= ECB_LEN; cnt += sz) {
            ExpectIntEQ(wc_AesEcbDecrypt(aes, decrypted + cnt, cipher + cnt,
                sz), 0);
        }
        if (cnt < ECB_LEN) {
            ExpectIntEQ(wc_AesEcbDecrypt(aes, decrypted + cnt, cipher + cnt,
                ECB_LEN - cnt), 0);
        }
        for (cnt = 0; cnt < ECB_LEN; cnt += WC_AES_BLOCK_SIZE) {
            ExpectBufEQ(decrypted + cnt, plain, WC_AES_BLOCK_SIZE);
        }
    }
#endif

    WC_FREE_VAR(plain, NULL);
    WC_FREE_VAR(cipher, NULL);
    WC_FREE_VAR(decrypted, NULL);
    return EXPECT_RESULT();
}

static int test_wc_AesEcbEncryptDecrypt_SameBuffer(Aes* aes, byte* key,
    word32 keyLen, byte* expected)
{
    EXPECT_DECLS;
    int cnt;
    WC_DECLARE_VAR(plain, byte, ECB_LEN, NULL);
    WC_DECLARE_VAR(cipher, byte, ECB_LEN, NULL);

    WC_ALLOC_VAR(plain, byte, ECB_LEN, NULL);
    WC_ALLOC_VAR(cipher, byte, ECB_LEN, NULL);

#ifdef WC_DECLARE_VAR_IS_HEAP_ALLOC
    ExpectNotNull(plain);
    ExpectNotNull(cipher);
#endif

    XMEMSET(plain, 0, ECB_LEN);

    /* Testing using same buffer for input and output. */
    ExpectIntEQ(wc_AesSetKey(aes, key, keyLen, NULL, AES_ENCRYPTION), 0);
    XMEMCPY(cipher, plain, ECB_LEN);
    ExpectIntEQ(wc_AesEcbEncrypt(aes, cipher, cipher, ECB_LEN), 0);
    for (cnt = 0; cnt < ECB_LEN; cnt += WC_AES_BLOCK_SIZE) {
        ExpectBufEQ(cipher + cnt, expected, WC_AES_BLOCK_SIZE);
    }
#ifdef HAVE_AES_DECRYPT
    ExpectIntEQ(wc_AesSetKey(aes, key, keyLen,
        NULL, AES_DECRYPTION), 0);
    ExpectIntEQ(wc_AesEcbDecrypt(aes, cipher, cipher, ECB_LEN), 0);
    for (cnt = 0; cnt < ECB_LEN; cnt += WC_AES_BLOCK_SIZE) {
        ExpectBufEQ(cipher + cnt, plain, WC_AES_BLOCK_SIZE);
    }
#endif

    WC_FREE_VAR(plain, NULL);
    WC_FREE_VAR(cipher, NULL);
    return EXPECT_RESULT();
}
#endif

int test_wc_AesEcbEncryptDecrypt(void)
{
    EXPECT_DECLS;
#if !defined(NO_AES) && defined(HAVE_AES_ECB)
    Aes aes;
#if defined(WOLFSSL_AES_128)
    byte key16[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    byte expected16[WC_AES_BLOCK_SIZE] = {
        0x0b, 0x9b, 0x15, 0xda, 0x4b, 0x44, 0xa0, 0xf5,
        0x15, 0x1d, 0xcf, 0xc4, 0xc0, 0x1f, 0x35, 0xd5,
    };
#endif
#if defined(WOLFSSL_AES_192)
    byte key24[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    byte expected24[WC_AES_BLOCK_SIZE] = {
        0xbe, 0x55, 0x02, 0x05, 0xfc, 0x91, 0xe8, 0x9c,
        0x9b, 0x9c, 0xc4, 0x70, 0x93, 0xb9, 0x0a, 0x08,
    };
#endif
#if defined(WOLFSSL_AES_256)
    byte key32[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    byte expected32[WC_AES_BLOCK_SIZE] = {
        0x7d, 0xbd, 0x88, 0x27, 0x2f, 0xb2, 0x59, 0x37,
        0x69, 0x2a, 0x3b, 0x81, 0x00, 0x47, 0x41, 0x75,
    };
#endif
    byte* key;
    word32 keyLen;
    byte* expected;

#if defined(WOLFSSL_AES_128)
    key = key16;
    keyLen = (word32)sizeof(key16) / sizeof(byte);
    expected = expected16;
#elif defined(WOLFSSL_AES_192)
    key = key24;
    keyLen = (word32)sizeof(key24) / sizeof(byte);
    expected = expected24;
#else
    key = key32;
    keyLen = (word32)sizeof(key32) / sizeof(byte);
    expected = expected32;
#endif

    XMEMSET(&aes, 0, sizeof(Aes));
    ExpectIntEQ(wc_AesInit(&aes, NULL, INVALID_DEVID), 0);

    EXPECT_TEST(test_wc_AesEcbEncryptDecrypt_BadArgs(&aes, key, keyLen));

#if defined(WOLFSSL_AES_128)
    EXPECT_TEST(test_wc_AesEcbEncryptDecrypt_WithKey(&aes, key16,
        (word32)sizeof(key16) / sizeof(byte), expected16));
#endif
#if defined(WOLFSSL_AES_192)
    EXPECT_TEST(test_wc_AesEcbEncryptDecrypt_WithKey(&aes, key24,
        (word32)sizeof(key24) / sizeof(byte), expected24));
#endif
#if defined(WOLFSSL_AES_256)
    EXPECT_TEST(test_wc_AesEcbEncryptDecrypt_WithKey(&aes, key32,
        (word32)sizeof(key32) / sizeof(byte), expected32));
#endif

    EXPECT_TEST(test_wc_AesEcbEncryptDecrypt_MultiBlocks(&aes, key, keyLen,
        expected));
    EXPECT_TEST(test_wc_AesEcbEncryptDecrypt_SameBuffer(&aes, key, keyLen,
        expected));

    wc_AesFree(&aes);
#endif
    return EXPECT_RESULT();
}

/*******************************************************************************
 * AES-CBC
 ******************************************************************************/

#if !defined(NO_AES) && defined(HAVE_AES_CBC)
/* Assembly code doing 8 iterations at a time. */
#define CBC_LEN     (9 * WC_AES_BLOCK_SIZE)

static int test_wc_AesCbcEncryptDecrypt_BadArgs(Aes* aes, byte* key,
    word32 keyLen, byte* iv)
{
    EXPECT_DECLS;
    byte    plain[WC_AES_BLOCK_SIZE];
    byte    cipher[WC_AES_BLOCK_SIZE];
    byte    decrypted[WC_AES_BLOCK_SIZE];

    XMEMSET(plain, 0, WC_AES_BLOCK_SIZE);
    XMEMSET(cipher, 0, WC_AES_BLOCK_SIZE);
    XMEMSET(decrypted, 0, WC_AES_BLOCK_SIZE);

    ExpectIntEQ(wc_AesSetKey(aes, key, keyLen, iv, AES_ENCRYPTION), 0);
    ExpectIntEQ(wc_AesCbcEncrypt(NULL, NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCbcEncrypt(aes, NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCbcEncrypt(NULL, cipher, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCbcEncrypt(NULL, NULL, plain, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCbcEncrypt(aes, cipher, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCbcEncrypt(aes, NULL, plain, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCbcEncrypt(NULL, cipher, plain, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_AesSetKey(aes, key, keyLen, iv, AES_DECRYPTION), 0);
    ExpectIntEQ(wc_AesCbcDecrypt(NULL, NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCbcDecrypt(aes, NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCbcDecrypt(NULL, decrypted, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCbcDecrypt(NULL, NULL, cipher, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCbcDecrypt(aes, decrypted, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCbcDecrypt(aes, NULL, cipher, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCbcDecrypt(NULL, decrypted, cipher, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_AesCbcDecryptWithKey(NULL, NULL, 0, NULL, keyLen, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCbcDecryptWithKey(decrypted, NULL, 0, NULL, keyLen, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCbcDecryptWithKey(NULL, cipher, 0, NULL, keyLen, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCbcDecryptWithKey(NULL, NULL, 0, key, keyLen, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCbcDecryptWithKey(NULL, NULL, 0, NULL, keyLen, iv),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCbcDecryptWithKey(decrypted, cipher,
        WC_AES_BLOCK_SIZE * 2, key, keyLen, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCbcDecryptWithKey(decrypted, cipher,
        WC_AES_BLOCK_SIZE * 2, NULL, keyLen, iv),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCbcDecryptWithKey(decrypted, NULL,
        WC_AES_BLOCK_SIZE * 2, key, keyLen, iv),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCbcDecryptWithKey(NULL, cipher,
        WC_AES_BLOCK_SIZE * 2, key, keyLen, iv),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    return EXPECT_RESULT();
}

static int test_wc_AesCbcEncryptDecrypt_WithKey(Aes* aes, byte* key,
    word32 keyLen, byte* iv, byte* vector, byte* vector_enc, word32 vector_len)
{
    EXPECT_DECLS;
    byte    plain[WC_AES_BLOCK_SIZE * 2];
    byte    cipher[WC_AES_BLOCK_SIZE * 2];
    byte    decrypted[WC_AES_BLOCK_SIZE * 2];

    XMEMSET(plain, 0, WC_AES_BLOCK_SIZE * 2);
    XMEMSET(cipher, 0, WC_AES_BLOCK_SIZE * 2);
    XMEMSET(decrypted, 0, WC_AES_BLOCK_SIZE * 2);

    ExpectIntEQ(wc_AesSetKey(aes, key, keyLen, iv, AES_ENCRYPTION), 0);
#if defined(HAVE_FIPS) && defined(HAVE_FIPS_VERSION) && \
    (HAVE_FIPS_VERSION == 2) && defined(WOLFSSL_AESNI)
    fprintf(stderr, "Zero length inputs not supported with AESNI in FIPS "
                    "mode (v2), skip test");
#else
    /* Test passing in size of 0  */
    XMEMSET(cipher, 0x00, WC_AES_BLOCK_SIZE * 2);
    ExpectIntEQ(wc_AesCbcEncrypt(aes, cipher, vector, 0), 0);
    /* Check enc was not modified */
    {
        int i;
        for (i = 0; i < (int)WC_AES_BLOCK_SIZE * 2; i++)
            ExpectIntEQ(cipher[i], 0x00);
    }
#endif
    ExpectIntEQ(wc_AesCbcEncrypt(aes, cipher, vector, vector_len),
        0);
    ExpectBufEQ(cipher, vector_enc, vector_len);
#ifdef WOLFSSL_AES_CBC_LENGTH_CHECKS
    ExpectIntEQ(wc_AesCbcEncrypt(aes, cipher, vector, vector_len - 1),
        WC_NO_ERR_TRACE(BAD_LENGTH_E));
#endif

#ifdef HAVE_AES_DECRYPT
    ExpectIntEQ(wc_AesSetKey(aes, key, keyLen, iv, AES_DECRYPTION), 0);
    ExpectIntEQ(wc_AesCbcDecrypt(aes, decrypted, cipher,
        WC_AES_BLOCK_SIZE * 2), 0);
    ExpectBufEQ(decrypted, vector, vector_len);
#ifdef WOLFSSL_AES_CBC_LENGTH_CHECKS
    ExpectIntEQ(wc_AesCbcDecrypt(aes, decrypted, cipher,
        WC_AES_BLOCK_SIZE * 2 - 1), WC_NO_ERR_TRACE(BAD_LENGTH_E));
#else
    ExpectIntEQ(wc_AesCbcDecrypt(aes, decrypted, cipher,
        WC_AES_BLOCK_SIZE * 2 - 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif

    ExpectIntEQ(wc_AesCbcDecryptWithKey(decrypted, cipher,
        WC_AES_BLOCK_SIZE * 2, key, keyLen, iv), 0);
    ExpectBufEQ(decrypted, vector, vector_len);

    /* Test passing in size of 0  */
    XMEMSET(decrypted, 0, WC_AES_BLOCK_SIZE * 2);
    ExpectIntEQ(wc_AesCbcDecrypt(aes, decrypted, cipher, 0), 0);
    /* Check dec was not modified */
    {
        int i;
        for (i = 0; i < (int)WC_AES_BLOCK_SIZE * 2; i++)
            ExpectIntEQ(decrypted[i], 0);
    }
#endif

    return EXPECT_RESULT();
}

static int test_wc_AesCbcEncryptDecrypt_MultiBlocks(Aes* aes, byte* key,
    word32 keyLen, byte* iv, byte* expected)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_KCAPI
    (void)aes;
    (void)key;
    (void)keyLen;
    (void)iv;
    (void)expected;
#else /* !WOLFSSL_KCAPI */
    int sz;
    int cnt;
    WC_DECLARE_VAR(plain, byte, CBC_LEN, NULL);
    WC_DECLARE_VAR(cipher, byte, CBC_LEN, NULL);
    WC_DECLARE_VAR(decrypted, byte, CBC_LEN, NULL);

    WC_ALLOC_VAR(plain, byte, CBC_LEN, NULL);
    WC_ALLOC_VAR(cipher, byte, CBC_LEN, NULL);
    WC_ALLOC_VAR(decrypted, byte, CBC_LEN, NULL);

#ifdef WC_DECLARE_VAR_IS_HEAP_ALLOC
    ExpectNotNull(plain);
    ExpectNotNull(cipher);
    ExpectNotNull(decrypted);
#endif


    XMEMSET(plain, 0, CBC_LEN);
    XMEMSET(cipher, 0, CBC_LEN);
    XMEMSET(decrypted, 0, CBC_LEN);

    ExpectIntEQ(wc_AesSetKey(aes, key, keyLen, NULL, AES_ENCRYPTION), 0);
    /* Test multiple blocks. */
    for (sz = WC_AES_BLOCK_SIZE; sz <= CBC_LEN; sz += WC_AES_BLOCK_SIZE) {
        XMEMSET(cipher, 0x00, CBC_LEN);
        ExpectIntEQ(wc_AesSetIV(aes, iv), 0);
        for (cnt = 0; cnt + sz <= CBC_LEN; cnt += sz) {
            ExpectIntEQ(wc_AesCbcEncrypt(aes, cipher + cnt, plain + cnt, sz),
                0);
        }
        if (cnt < CBC_LEN) {
            ExpectIntEQ(wc_AesCbcEncrypt(aes, cipher + cnt, plain + cnt,
                CBC_LEN - cnt), 0);
        }
        ExpectBufEQ(cipher, expected, CBC_LEN);
    }
#ifdef HAVE_AES_DECRYPT
    ExpectIntEQ(wc_AesSetKey(aes, key, keyLen, NULL, AES_DECRYPTION), 0);
    for (sz = WC_AES_BLOCK_SIZE; sz <= CBC_LEN; sz += WC_AES_BLOCK_SIZE) {
        XMEMSET(decrypted, 0xff, CBC_LEN);
        ExpectIntEQ(wc_AesSetIV(aes, iv), 0);
        for (cnt = 0; cnt + sz <= CBC_LEN; cnt += sz) {
            ExpectIntEQ(wc_AesCbcDecrypt(aes, decrypted + cnt, cipher + cnt,
                sz), 0);
        }
        if (cnt < CBC_LEN) {
            ExpectIntEQ(wc_AesCbcDecrypt(aes, decrypted + cnt, cipher + cnt,
                CBC_LEN - cnt), 0);
        }
        ExpectBufEQ(decrypted, plain, CBC_LEN);
    }
#endif

    WC_FREE_VAR(plain, NULL);
    WC_FREE_VAR(cipher, NULL);
    WC_FREE_VAR(decrypted, NULL);
#endif /* !WOLFSSL_KCAPI */
    return EXPECT_RESULT();
}

static int test_wc_AesCbcEncryptDecrypt_SameBuffer(Aes* aes, byte* key,
    word32 keyLen, byte* iv, byte* expected)
{
    EXPECT_DECLS;
    WC_DECLARE_VAR(plain, byte, CBC_LEN, NULL);
    WC_DECLARE_VAR(cipher, byte, CBC_LEN, NULL);

    WC_ALLOC_VAR(plain, byte, CBC_LEN, NULL);
    WC_ALLOC_VAR(cipher, byte, CBC_LEN, NULL);

#ifdef WC_DECLARE_VAR_IS_HEAP_ALLOC
    ExpectNotNull(plain);
    ExpectNotNull(cipher);
#endif

    XMEMSET(plain, 0, CBC_LEN);

    /* Testing using same buffer for input and output. */
    ExpectIntEQ(wc_AesSetKey(aes, key, keyLen, iv, AES_ENCRYPTION), 0);
    XMEMCPY(cipher, plain, CBC_LEN);
    ExpectIntEQ(wc_AesCbcEncrypt(aes, cipher, cipher, CBC_LEN), 0);
    ExpectBufEQ(cipher, expected, CBC_LEN);
#ifdef HAVE_AES_DECRYPT
    ExpectIntEQ(wc_AesSetKey(aes, key, keyLen, iv, AES_DECRYPTION), 0);
    ExpectIntEQ(wc_AesCbcDecrypt(aes, cipher, cipher, CBC_LEN), 0);
    ExpectBufEQ(cipher, plain, CBC_LEN);
#endif

    WC_FREE_VAR(plain, NULL);
    WC_FREE_VAR(cipher, NULL);
    return EXPECT_RESULT();
}
#endif

/*
 * test function for wc_AesCbcEncrypt(), wc_AesCbcDecrypt(),
 * and wc_AesCbcDecryptWithKey()
 */
int test_wc_AesCbcEncryptDecrypt(void)
{
    EXPECT_DECLS;
#if !defined(NO_AES) && defined(HAVE_AES_CBC)
    Aes  aes;
    byte vector[] = { /* Now is the time for all good men w/o trailing 0 */
        0x4e, 0x6f, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74,
        0x68, 0x65, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x20,
        0x66, 0x6f, 0x72, 0x20, 0x61, 0x6c, 0x6c, 0x20,
        0x67, 0x6f, 0x6f, 0x64, 0x20, 0x6d, 0x65, 0x6e
    };
#if defined(WOLFSSL_AES_128)
    byte key16[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    byte vector_enc16[] = {
        0x26, 0x5b, 0x55, 0xf1, 0xcc, 0x77, 0xc0, 0x9a,
        0x60, 0x77, 0x99, 0x1d, 0x52, 0xf1, 0xc0, 0x3a,
        0x0f, 0x16, 0xae, 0x62, 0xf1, 0x71, 0xf5, 0x95,
        0xb6, 0x74, 0x98, 0x2a, 0x6b, 0x7c, 0x7c, 0x39
    };
#endif
#if defined(WOLFSSL_AES_192)
    byte key24[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    byte vector_enc24[] = {
        0xdb, 0x96, 0xfa, 0x55, 0x90, 0x1e, 0x0c, 0x4f,
        0xe4, 0x0f, 0xde, 0x16, 0x33, 0x44, 0xca, 0xa5,
        0xe6, 0xa8, 0xbd, 0xd4, 0x88, 0xe5, 0x2f, 0x88,
        0xfd, 0x61, 0x0f, 0x88, 0x6d, 0xf1, 0xf6, 0xa5
    };
#endif
#if defined(WOLFSSL_AES_256)
    byte key32[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    byte vector_enc32[] = {
        0xd7, 0xd6, 0x04, 0x5b, 0x4d, 0xc4, 0x90, 0xdf,
        0x4a, 0x82, 0xed, 0x61, 0x26, 0x4e, 0x23, 0xb3,
        0xe4, 0xb5, 0x85, 0x30, 0x29, 0x4c, 0x9d, 0xcf,
        0x73, 0xc9, 0x46, 0xd1, 0xaa, 0xc8, 0xcb, 0x62,
    };
#endif
#ifdef WOLFSSL_AES_128
    byte expected16[CBC_LEN] = {
        0x46, 0x1a, 0x5f, 0xfd, 0x9d, 0xf7, 0x91, 0x71,
        0x35, 0x8e, 0x9e, 0x01, 0x77, 0xd8, 0x4e, 0xaa,
        0x34, 0x28, 0xba, 0x95, 0x76, 0xa5, 0x60, 0xeb,
        0xbf, 0x6e, 0x89, 0xf5, 0x9a, 0x03, 0x7a, 0x7e,
        0x07, 0xc5, 0xec, 0x60, 0xe1, 0x9b, 0x7a, 0x35,
        0x9c, 0x29, 0x74, 0x6c, 0x2b, 0x1c, 0xff, 0x1b,
        0xa0, 0xd5, 0xf3, 0x5b, 0x23, 0x86, 0x31, 0xbe,
        0x1a, 0x20, 0x2c, 0x57, 0xf4, 0x9e, 0x81, 0x67,
        0xb8, 0xf2, 0x60, 0x28, 0x36, 0x50, 0x6c, 0x06,
        0x69, 0xa8, 0xec, 0x36, 0x46, 0x2a, 0xc9, 0x12,
        0x54, 0xc8, 0xeb, 0x73, 0x8d, 0xe8, 0x0f, 0x0c,
        0xd6, 0x53, 0x8b, 0xd2, 0x24, 0xdb, 0x08, 0xf7,
        0x1e, 0x2e, 0x34, 0x8d, 0x27, 0x6d, 0x77, 0x8f,
        0x00, 0xa5, 0x8e, 0xc3, 0x0d, 0x07, 0x61, 0xd4,
        0xe0, 0x54, 0x9b, 0xfe, 0x71, 0x4f, 0x25, 0x75,
        0x9f, 0x7a, 0x2c, 0xa4, 0x0e, 0x47, 0x1f, 0xef,
        0x85, 0x19, 0x36, 0x65, 0x3b, 0x28, 0x20, 0x3a,
        0xf9, 0x7f, 0x13, 0xe8, 0x24, 0xd7, 0x64, 0x27,
    };
#elif defined(WOLFSSL_AES_192)
    byte expected24[CBC_LEN] = {
        0x7b, 0xde, 0x53, 0xac, 0x88, 0x24, 0xe6, 0xde,
        0x68, 0xd4, 0x64, 0x18, 0x20, 0x96, 0x62, 0x68,
        0xd0, 0x04, 0x81, 0x50, 0x73, 0xe7, 0x6d, 0x8e,
        0x14, 0x44, 0x87, 0xad, 0x6d, 0x44, 0xf9, 0xc3,
        0xe9, 0x82, 0x2e, 0x2d, 0x17, 0x16, 0x43, 0xa6,
        0x29, 0xe3, 0x9d, 0x7f, 0x84, 0x2e, 0x9a, 0x14,
        0x69, 0xe9, 0x7b, 0x38, 0xfd, 0xec, 0x71, 0x4a,
        0xf7, 0x0f, 0xbf, 0x6e, 0x4d, 0x46, 0x7e, 0xad,
        0x83, 0xcb, 0xfa, 0x20, 0x25, 0xf8, 0x13, 0xc6,
        0x75, 0xdd, 0x12, 0x1f, 0xed, 0xfa, 0x3a, 0x1c,
        0x01, 0x68, 0x02, 0x12, 0x69, 0x4c, 0xe7, 0x00,
        0xf1, 0x9c, 0x40, 0xed, 0x7d, 0x64, 0x16, 0x1c,
        0x63, 0x07, 0x87, 0x37, 0xb3, 0x5b, 0x59, 0x97,
        0xc9, 0xe4, 0x86, 0xfd, 0xd2, 0xae, 0x5b, 0x59,
        0x5a, 0xe9, 0xf5, 0x0b, 0xa0, 0x87, 0xf4, 0xb5,
        0x65, 0x9c, 0x98, 0x0f, 0xbf, 0x11, 0xa4, 0x7d,
        0x06, 0x80, 0xb5, 0x27, 0x9c, 0xd5, 0x09, 0x7a,
        0xa1, 0x42, 0xbd, 0x87, 0x6b, 0x85, 0x2f, 0x6e,
    };
#else
    byte expected32[CBC_LEN] = {
        0x18, 0x5a, 0x48, 0xfd, 0xb7, 0xd5, 0x35, 0xf3,
        0x3f, 0xb9, 0x14, 0x16, 0xf3, 0x05, 0xf3, 0x71,
        0xea, 0x4e, 0x22, 0xcd, 0x15, 0x3a, 0xcc, 0xba,
        0x3f, 0x5b, 0x85, 0x15, 0xdf, 0x07, 0xf6, 0xa4,
        0xf4, 0x41, 0xe7, 0x08, 0x30, 0x9b, 0x09, 0x2d,
        0xd4, 0x3e, 0x68, 0xea, 0x45, 0x3d, 0x3a, 0xe3,
        0x7c, 0x68, 0x00, 0xda, 0xeb, 0x87, 0xd7, 0x11,
        0x2a, 0x0b, 0x7c, 0x48, 0xe5, 0xef, 0xae, 0x6d,
        0x61, 0x04, 0xa4, 0x16, 0xc7, 0xb6, 0x0f, 0xab,
        0x24, 0x0c, 0x74, 0x0b, 0x4f, 0xfe, 0xfd, 0xd1,
        0x38, 0xae, 0x92, 0x18, 0x57, 0xdd, 0x20, 0x90,
        0x74, 0x0a, 0xdf, 0x7b, 0x06, 0x2d, 0x8a, 0xe8,
        0x43, 0x77, 0x0d, 0x18, 0x25, 0x8b, 0x04, 0x98,
        0xf4, 0x4c, 0x43, 0x19, 0x99, 0x16, 0x5a, 0xac,
        0x7f, 0x52, 0x0f, 0x79, 0xd2, 0x10, 0xa5, 0xf3,
        0x88, 0xf3, 0x79, 0x0a, 0x05, 0x22, 0xb8, 0xb2,
        0xb7, 0xd4, 0x8e, 0x17, 0x80, 0x1b, 0x4d, 0xcb,
        0x99, 0xa7, 0x30, 0x1b, 0xe0, 0xee, 0xd5, 0xd3,
    };
#endif
    byte    iv[]   = "1234567890abcdef";
    byte* key;
    word32 keyLen;
    byte* expected;

#if defined(WOLFSSL_AES_128)
    key = key16;
    keyLen = (word32)sizeof(key16) / sizeof(byte);
    expected = expected16;
#elif defined(WOLFSSL_AES_192)
    key = key24;
    keyLen = (word32)sizeof(key24) / sizeof(byte);
    expected = expected24;
#else
    key = key32;
    keyLen = (word32)sizeof(key32) / sizeof(byte);
    expected = expected32;
#endif

    /* Init stack variables. */
    XMEMSET(&aes, 0, sizeof(Aes));

    ExpectIntEQ(wc_AesInit(&aes, NULL, INVALID_DEVID), 0);

    EXPECT_TEST(test_wc_AesCbcEncryptDecrypt_BadArgs(&aes, key, keyLen, iv));

#ifdef WOLFSSL_AES_128
    EXPECT_TEST(test_wc_AesCbcEncryptDecrypt_WithKey(&aes, key16,
        (word32)sizeof(key16) / sizeof(byte), iv, vector, vector_enc16,
        (word32)sizeof(vector) / sizeof(byte)));
#endif
#ifdef WOLFSSL_AES_192
    EXPECT_TEST(test_wc_AesCbcEncryptDecrypt_WithKey(&aes, key24,
        (word32)sizeof(key24) / sizeof(byte), iv, vector, vector_enc24,
        (word32)sizeof(vector) / sizeof(byte)));
#endif
#ifdef WOLFSSL_AES_256
    EXPECT_TEST(test_wc_AesCbcEncryptDecrypt_WithKey(&aes, key32,
        (word32)sizeof(key32) / sizeof(byte), iv, vector, vector_enc32,
        (word32)sizeof(vector) / sizeof(byte)));
#endif

    EXPECT_TEST(test_wc_AesCbcEncryptDecrypt_MultiBlocks(&aes, key, keyLen, iv,
        expected));
    EXPECT_TEST(test_wc_AesCbcEncryptDecrypt_SameBuffer(&aes, key, keyLen, iv,
        expected));

    wc_AesFree(&aes);
#endif
    return EXPECT_RESULT();
} /* END test_wc_AesCbcEncryptDecrypt */

/*******************************************************************************
 * AES-CFB
 ******************************************************************************/

#if !defined(NO_AES) && defined(WOLFSSL_AES_CFB)
#define CFB_LEN     (5 * WC_AES_BLOCK_SIZE)

static int test_wc_AesCfbEncryptDecrypt_BadArgs(Aes* aes, byte* key,
    word32 keyLen, byte* iv)
{
    EXPECT_DECLS;
    byte plain[WC_AES_BLOCK_SIZE];
    byte cipher[WC_AES_BLOCK_SIZE];
#ifdef HAVE_AES_DECRYPT
    byte decrypted[WC_AES_BLOCK_SIZE];
#endif

    XMEMSET(plain, 0x00, WC_AES_BLOCK_SIZE);
    XMEMSET(cipher, 0x00, WC_AES_BLOCK_SIZE);

    ExpectIntEQ(wc_AesSetKey(aes, key, keyLen, NULL, AES_ENCRYPTION), 0);

    ExpectIntEQ(wc_AesSetIV(aes, iv), 0);
    ExpectIntEQ(wc_AesCfbEncrypt(NULL, NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCfbEncrypt(aes, NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCfbEncrypt(NULL, cipher, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCfbEncrypt(NULL, NULL, plain, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCfbEncrypt(aes, cipher, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCfbEncrypt(aes, NULL, plain, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCfbEncrypt(NULL, cipher, plain, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

#ifdef HAVE_AES_DECRYPT
    ExpectIntEQ(wc_AesSetIV(aes, iv), 0);
    ExpectIntEQ(wc_AesCfbDecrypt(NULL, NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCfbDecrypt(aes, NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCfbDecrypt(NULL, decrypted, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCfbDecrypt(NULL, NULL, cipher, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCfbDecrypt(aes, decrypted, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCfbDecrypt(aes, NULL, cipher, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCfbDecrypt(NULL, decrypted, cipher, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif

    return EXPECT_RESULT();
}

static int test_wc_AesCfbEncryptDecrypt_WithKey(Aes* aes, byte* key,
    word32 keyLen, byte* iv, byte* expected)
{
    EXPECT_DECLS;
    WC_DECLARE_VAR(plain, byte, CFB_LEN, NULL);
    WC_DECLARE_VAR(cipher, byte, CFB_LEN, NULL);
#ifdef HAVE_AES_DECRYPT
    WC_DECLARE_VAR(decrypted, byte, CFB_LEN, NULL);
#endif

    WC_ALLOC_VAR(plain, byte, CFB_LEN, NULL);
    WC_ALLOC_VAR(cipher, byte, CFB_LEN, NULL);
#ifdef HAVE_AES_DECRYPT
    WC_ALLOC_VAR(decrypted, byte, CFB_LEN, NULL);
#endif

#ifdef WC_DECLARE_VAR_IS_HEAP_ALLOC
    ExpectNotNull(plain);
    ExpectNotNull(cipher);
#ifdef HAVE_AES_DECRYPT
    ExpectNotNull(decrypted);
#endif
#endif

    XMEMSET(plain, 0xa5, CFB_LEN);

    ExpectIntEQ(wc_AesSetKey(aes, key, keyLen, NULL, AES_ENCRYPTION), 0);

    ExpectIntEQ(wc_AesSetIV(aes, iv), 0);
    ExpectIntEQ(wc_AesCfbEncrypt(aes, cipher, plain, WC_AES_BLOCK_SIZE), 0);
    ExpectBufEQ(cipher, expected, WC_AES_BLOCK_SIZE);

#ifdef HAVE_AES_DECRYPT
    ExpectIntEQ(wc_AesSetIV(aes, iv), 0);
    ExpectIntEQ(wc_AesCfbDecrypt(aes, decrypted, cipher, WC_AES_BLOCK_SIZE),
        0);
    ExpectBufEQ(decrypted, plain, WC_AES_BLOCK_SIZE);
#endif

    ExpectIntEQ(wc_AesSetIV(aes, iv), 0);
    ExpectIntEQ(wc_AesCfbEncrypt(aes, cipher, plain, CFB_LEN), 0);
    ExpectBufEQ(cipher, expected, CFB_LEN);
#ifdef HAVE_AES_DECRYPT
    ExpectIntEQ(wc_AesSetIV(aes, iv), 0);
    ExpectIntEQ(wc_AesCfbDecrypt(aes, decrypted, cipher, CFB_LEN), 0);
    ExpectBufEQ(decrypted, plain, CFB_LEN);
#endif

    WC_FREE_VAR(plain, NULL);
    WC_FREE_VAR(cipher, NULL);
#ifdef HAVE_AES_DECRYPT
    WC_FREE_VAR(decrypted, NULL);
#endif
    return EXPECT_RESULT();
}

static int test_wc_AesCfbEncryptDecrypt_Chunking(Aes* aes, byte* key,
    word32 keyLen, byte* iv, byte* expected)
{
    EXPECT_DECLS;
    int sz;
    int cnt;
    WC_DECLARE_VAR(plain, byte, CFB_LEN, NULL);
    WC_DECLARE_VAR(cipher, byte, CFB_LEN, NULL);
#ifdef HAVE_AES_DECRYPT
    WC_DECLARE_VAR(decrypted, byte, CFB_LEN, NULL);
#endif

    WC_ALLOC_VAR(plain, byte, CFB_LEN, NULL);
    WC_ALLOC_VAR(cipher, byte, CFB_LEN, NULL);
#ifdef HAVE_AES_DECRYPT
    WC_ALLOC_VAR(decrypted, byte, CFB_LEN, NULL);
#endif

#ifdef WC_DECLARE_VAR_IS_HEAP_ALLOC
    ExpectNotNull(plain);
    ExpectNotNull(cipher);
#ifdef HAVE_AES_DECRYPT
    ExpectNotNull(decrypted);
#endif
#endif

    XMEMSET(plain, 0xa5, CFB_LEN);

    ExpectIntEQ(wc_AesSetKey(aes, key, keyLen, NULL, AES_ENCRYPTION), 0);

    for (sz = 1; sz < CFB_LEN; sz++) {
        ExpectIntEQ(wc_AesSetIV(aes, iv), 0);
        XMEMSET(cipher, 0, CFB_LEN);
        for (cnt = 0; cnt + sz <= CFB_LEN; cnt += sz) {
            ExpectIntEQ(wc_AesCfbEncrypt(aes, cipher + cnt, plain + cnt, sz),
                0);
        }
        if (cnt < CFB_LEN) {
            ExpectIntEQ(wc_AesCfbEncrypt(aes, cipher + cnt, plain + cnt,
                CFB_LEN - cnt), 0);
        }
        ExpectBufEQ(cipher, expected, CFB_LEN);
    }
#ifdef HAVE_AES_DECRYPT
    for (sz = 1; sz < CFB_LEN; sz++) {
        ExpectIntEQ(wc_AesSetIV(aes, iv), 0);
        XMEMSET(decrypted, 0xff, CFB_LEN);
        for (cnt = 0; cnt + sz <= CFB_LEN; cnt += sz) {
            ExpectIntEQ(wc_AesCfbDecrypt(aes, decrypted + cnt, cipher + cnt,
                sz), 0);
        }
        if (cnt < CFB_LEN) {
            ExpectIntEQ(wc_AesCfbDecrypt(aes, decrypted + cnt, cipher + cnt,
                CFB_LEN - cnt), 0);
        }
        ExpectBufEQ(decrypted, plain, CFB_LEN);
    }
#endif

    WC_FREE_VAR(plain, NULL);
    WC_FREE_VAR(cipher, NULL);
#ifdef HAVE_AES_DECRYPT
    WC_FREE_VAR(decrypted, NULL);
#endif
    return EXPECT_RESULT();
}

#if (!defined(HAVE_FIPS) || !defined(HAVE_FIPS_VERSION) || \
        (HAVE_FIPS_VERSION > 6)) && !defined(HAVE_SELFTEST)
static int test_wc_AesCfbEncryptDecrypt_SameBuffer(Aes* aes, byte* key,
    word32 keyLen, byte* iv, byte* expected)
{
    EXPECT_DECLS;
    WC_DECLARE_VAR(plain, byte, CFB_LEN, NULL);
    WC_DECLARE_VAR(cipher, byte, CFB_LEN, NULL);

    WC_ALLOC_VAR(plain, byte, CBC_LEN, NULL);
    WC_ALLOC_VAR(cipher, byte, CBC_LEN, NULL);

#ifdef WC_DECLARE_VAR_IS_HEAP_ALLOC
    ExpectNotNull(plain);
    ExpectNotNull(cipher);
#endif

    XMEMSET(plain, 0xa5, CFB_LEN);

    ExpectIntEQ(wc_AesSetKey(aes, key, keyLen, NULL, AES_ENCRYPTION), 0);

    /* Testing using same buffer for input and output. */
    XMEMCPY(cipher, plain, CFB_LEN);
    ExpectIntEQ(wc_AesSetIV(aes, iv), 0);
    ExpectIntEQ(wc_AesCfbEncrypt(aes, cipher, cipher, CFB_LEN), 0);
    ExpectBufEQ(cipher, expected, CFB_LEN);
#ifdef HAVE_AES_DECRYPT
    ExpectIntEQ(wc_AesSetIV(aes, iv), 0);
    ExpectIntEQ(wc_AesCfbDecrypt(aes, cipher, cipher, CFB_LEN), 0);
    ExpectBufEQ(cipher, plain, CFB_LEN);
#endif

    WC_FREE_VAR(plain, NULL);
    WC_FREE_VAR(cipher, NULL);
    return EXPECT_RESULT();
}
#endif
#endif

int test_wc_AesCfbEncryptDecrypt(void)
{
    EXPECT_DECLS;
#if !defined(NO_AES) && defined(WOLFSSL_AES_CFB)
    Aes aes;
#if defined(WOLFSSL_AES_128)
    byte key16[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    byte expected16[CFB_LEN] = {
        0xe3, 0xbf, 0xfa, 0x58, 0x38, 0x52, 0x34, 0xd4,
        0x90, 0x2b, 0x3b, 0xa4, 0xd2, 0x7d, 0xeb, 0x0f,
        0x01, 0x1f, 0xb4, 0x51, 0xa3, 0x6b, 0x21, 0x0c,
        0x17, 0xb0, 0xb2, 0xbf, 0x33, 0x3d, 0xe4, 0x3f,
        0xf9, 0x50, 0xcc, 0x2b, 0xab, 0xb7, 0x30, 0xaa,
        0xaf, 0x56, 0xad, 0xdb, 0xca, 0x73, 0x4b, 0x13,
        0x3b, 0xe2, 0xef, 0x8a, 0xb9, 0x1c, 0xfe, 0xfa,
        0x79, 0xcd, 0x92, 0x34, 0x27, 0xae, 0x6c, 0xe9,
        0x18, 0x60, 0x05, 0x44, 0xdd, 0x87, 0xe5, 0xfa,
        0x87, 0x64, 0xd0, 0x4c, 0x21, 0x00, 0xe9, 0x8d,
    };
#endif
#if defined(WOLFSSL_AES_192)
    byte key24[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    byte expected24[CFB_LEN] = {
        0xde, 0x7b, 0xf6, 0x09, 0x2d, 0x81, 0x43, 0x7b,
        0xcd, 0x71, 0xc1, 0xbd, 0x85, 0x33, 0xc7, 0xcd,
        0x23, 0xb2, 0x9f, 0xf8, 0x69, 0xe5, 0x77, 0xbf,
        0x5a, 0x7f, 0xad, 0x5d, 0x98, 0x8f, 0x17, 0x70,
        0x65, 0xf6, 0x18, 0x90, 0x95, 0x5f, 0x85, 0xfd,
        0xfb, 0xc4, 0xed, 0xf2, 0x85, 0x6a, 0x3f, 0x62,
        0x8c, 0x33, 0x08, 0x42, 0x5d, 0x29, 0x51, 0xec,
        0xaa, 0x37, 0x7c, 0x57, 0x51, 0xa0, 0xde, 0xf8,
        0x68, 0x12, 0xf7, 0x73, 0x1c, 0x0c, 0xc7, 0xa6,
        0xb1, 0x82, 0x0e, 0xc8, 0xbd, 0xe3, 0x48, 0x3c,
    };
#endif
#if defined(WOLFSSL_AES_256)
    byte key32[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    byte expected32[CFB_LEN] = {
        0xbd, 0xff, 0xed, 0x58, 0x12, 0x70, 0x90, 0x56,
        0x9a, 0x1c, 0xb1, 0xb3, 0x56, 0xa0, 0x56, 0xd4,
        0x97, 0xb3, 0x9c, 0xf9, 0xeb, 0x2a, 0xb6, 0x23,
        0x11, 0x0c, 0x8d, 0x15, 0x2d, 0x03, 0x66, 0x76,
        0x4a, 0x7f, 0xb4, 0xf4, 0xe6, 0x7c, 0xec, 0x8b,
        0xe9, 0xa9, 0x40, 0x2b, 0x97, 0xec, 0x0e, 0x24,
        0xfe, 0x4b, 0xa1, 0xd6, 0xfc, 0x8f, 0x9c, 0x79,
        0x0c, 0x84, 0x18, 0x67, 0x14, 0x7d, 0x8c, 0x5a,
        0x78, 0x4f, 0x18, 0xb1, 0x04, 0xd9, 0x41, 0x79,
        0x72, 0x92, 0x5e, 0x91, 0xe8, 0xa9, 0xe7, 0xe9,
    };
#endif
    byte iv[]   = "1234567890abcdef";
    byte* key;
    word32 keyLen;
    byte* expected;

#if defined(WOLFSSL_AES_128)
    key = key16;
    keyLen = (word32)sizeof(key16) / sizeof(byte);
    expected = expected16;
#elif defined(WOLFSSL_AES_192)
    key = key24;
    keyLen = (word32)sizeof(key24) / sizeof(byte);
    expected = expected24;
#else
    key = key32;
    keyLen = (word32)sizeof(key32) / sizeof(byte);
    expected = expected32;
#endif

    XMEMSET(&aes, 0, sizeof(Aes));
    ExpectIntEQ(wc_AesInit(&aes, NULL, INVALID_DEVID), 0);

    EXPECT_TEST(test_wc_AesCfbEncryptDecrypt_BadArgs(&aes, key, keyLen, iv));

#if defined(WOLFSSL_AES_128)
    EXPECT_TEST(test_wc_AesCfbEncryptDecrypt_WithKey(&aes, key16,
        (word32)sizeof(key16) / sizeof(byte), iv, expected16));
#endif
#if defined(WOLFSSL_AES_192)
    EXPECT_TEST(test_wc_AesCfbEncryptDecrypt_WithKey(&aes, key24,
        (word32)sizeof(key24) / sizeof(byte), iv, expected24));
#endif
#if defined(WOLFSSL_AES_256)
    EXPECT_TEST(test_wc_AesCfbEncryptDecrypt_WithKey(&aes, key32,
        (word32)sizeof(key32) / sizeof(byte), iv, expected32));
#endif

    EXPECT_TEST(test_wc_AesCfbEncryptDecrypt_Chunking(&aes, key, keyLen, iv,
        expected));
#if (!defined(HAVE_FIPS) || !defined(HAVE_FIPS_VERSION) || \
        (HAVE_FIPS_VERSION > 6)) && !defined(HAVE_SELFTEST)
    EXPECT_TEST(test_wc_AesCfbEncryptDecrypt_SameBuffer(&aes, key, keyLen, iv,
        expected));
#endif

    wc_AesFree(&aes);
#endif
    return EXPECT_RESULT();
}

/*******************************************************************************
 * AES-OFB
 ******************************************************************************/

#if !defined(NO_AES) && defined(WOLFSSL_AES_OFB)
#define OFB_LEN     (5 * WC_AES_BLOCK_SIZE)

static int test_wc_AesOfbEncryptDecrypt_BadArgs(Aes* aes, byte* key,
    word32 keyLen, byte* iv)
{
    EXPECT_DECLS;
    byte plain[WC_AES_BLOCK_SIZE];
    byte cipher[WC_AES_BLOCK_SIZE];
#ifdef HAVE_AES_DECRYPT
    byte decrypted[WC_AES_BLOCK_SIZE];
#endif

    XMEMSET(plain, 0x00, WC_AES_BLOCK_SIZE);
    XMEMSET(cipher, 0x00, WC_AES_BLOCK_SIZE);

    ExpectIntEQ(wc_AesSetKey(aes, key, keyLen, NULL, AES_ENCRYPTION), 0);

    ExpectIntEQ(wc_AesSetIV(aes, iv), 0);
    ExpectIntEQ(wc_AesOfbEncrypt(NULL, NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesOfbEncrypt(aes, NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesOfbEncrypt(NULL, cipher, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesOfbEncrypt(NULL, NULL, plain, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesOfbEncrypt(aes, cipher, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesOfbEncrypt(aes, NULL, plain, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesOfbEncrypt(NULL, cipher, plain, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

#ifdef HAVE_AES_DECRYPT
    ExpectIntEQ(wc_AesSetIV(aes, iv), 0);
    ExpectIntEQ(wc_AesOfbDecrypt(NULL, NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesOfbDecrypt(aes, NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesOfbDecrypt(NULL, decrypted, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesOfbDecrypt(NULL, NULL, cipher, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesOfbDecrypt(aes, decrypted, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesOfbDecrypt(aes, NULL, cipher, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesOfbDecrypt(NULL, decrypted, cipher, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif

    return EXPECT_RESULT();
}

static int test_wc_AesOfbEncryptDecrypt_WithKey(Aes* aes, byte* key,
    word32 keyLen, byte* iv, byte* expected)
{
    EXPECT_DECLS;
    WC_DECLARE_VAR(plain, byte, OFB_LEN, NULL);
    WC_DECLARE_VAR(cipher, byte, OFB_LEN, NULL);
#ifdef HAVE_AES_DECRYPT
    WC_DECLARE_VAR(decrypted, byte, OFB_LEN, NULL);
#endif

    WC_ALLOC_VAR(plain, byte, OFB_LEN, NULL);
    WC_ALLOC_VAR(cipher, byte, OFB_LEN, NULL);
#ifdef HAVE_AES_DECRYPT
    WC_ALLOC_VAR(decrypted, byte, OFB_LEN, NULL);
#endif

    XMEMSET(plain, 0xa5, OFB_LEN);

    ExpectIntEQ(wc_AesSetKey(aes, key, keyLen, NULL, AES_ENCRYPTION), 0);

    ExpectIntEQ(wc_AesSetIV(aes, iv), 0);
    ExpectIntEQ(wc_AesOfbEncrypt(aes, cipher, plain, WC_AES_BLOCK_SIZE), 0);
    ExpectBufEQ(cipher, expected, WC_AES_BLOCK_SIZE);

#ifdef HAVE_AES_DECRYPT
    ExpectIntEQ(wc_AesSetIV(aes, iv), 0);
    ExpectIntEQ(wc_AesOfbDecrypt(aes, decrypted, cipher, WC_AES_BLOCK_SIZE),
        0);
    ExpectBufEQ(decrypted, plain, WC_AES_BLOCK_SIZE);
#endif

    ExpectIntEQ(wc_AesSetIV(aes, iv), 0);
    ExpectIntEQ(wc_AesOfbEncrypt(aes, cipher, plain, OFB_LEN), 0);
    ExpectBufEQ(cipher, expected, OFB_LEN);
#ifdef HAVE_AES_DECRYPT
    ExpectIntEQ(wc_AesSetIV(aes, iv), 0);
    ExpectIntEQ(wc_AesOfbDecrypt(aes, decrypted, cipher, OFB_LEN), 0);
    ExpectBufEQ(decrypted, plain, OFB_LEN);
#endif

    WC_FREE_VAR(plain, NULL);
    WC_FREE_VAR(cipher, NULL);
#ifdef HAVE_AES_DECRYPT
    WC_FREE_VAR(decrypted, NULL);
#endif
    return EXPECT_RESULT();
}

static int test_wc_AesOfbEncryptDecrypt_Chunking(Aes* aes, byte* key,
    word32 keyLen, byte* iv, byte* expected)
{
    EXPECT_DECLS;
    int sz;
    int cnt;
    WC_DECLARE_VAR(plain, byte, OFB_LEN, NULL);
    WC_DECLARE_VAR(cipher, byte, OFB_LEN, NULL);
#ifdef HAVE_AES_DECRYPT
    WC_DECLARE_VAR(decrypted, byte, OFB_LEN, NULL);
#endif

    WC_ALLOC_VAR(plain, byte, OFB_LEN, NULL);
    WC_ALLOC_VAR(cipher, byte, OFB_LEN, NULL);
#ifdef HAVE_AES_DECRYPT
    WC_ALLOC_VAR(decrypted, byte, OFB_LEN, NULL);
#endif

#ifdef WC_DECLARE_VAR_IS_HEAP_ALLOC
    ExpectNotNull(plain);
    ExpectNotNull(cipher);
#ifdef HAVE_AES_DECRYPT
    ExpectNotNull(decrypted);
#endif
#endif

    XMEMSET(plain, 0xa5, OFB_LEN);

    ExpectIntEQ(wc_AesSetKey(aes, key, keyLen, NULL, AES_ENCRYPTION), 0);

    for (sz = 1; sz < OFB_LEN; sz++) {
        ExpectIntEQ(wc_AesSetIV(aes, iv), 0);
        XMEMSET(cipher, 0, OFB_LEN);
        for (cnt = 0; cnt + sz <= OFB_LEN; cnt += sz) {
            ExpectIntEQ(wc_AesOfbEncrypt(aes, cipher + cnt, plain + cnt, sz),
                0);
        }
        if (cnt < OFB_LEN) {
            ExpectIntEQ(wc_AesOfbEncrypt(aes, cipher + cnt, plain + cnt,
                OFB_LEN - cnt), 0);
        }
        ExpectBufEQ(cipher, expected, OFB_LEN);
    }
#ifdef HAVE_AES_DECRYPT
    for (sz = 1; sz < OFB_LEN; sz++) {
        ExpectIntEQ(wc_AesSetIV(aes, iv), 0);
        XMEMSET(decrypted, 0xff, OFB_LEN);
        for (cnt = 0; cnt + sz <= OFB_LEN; cnt += sz) {
            ExpectIntEQ(wc_AesOfbDecrypt(aes, decrypted + cnt, cipher + cnt,
                sz), 0);
        }
        if (cnt < OFB_LEN) {
            ExpectIntEQ(wc_AesOfbDecrypt(aes, decrypted + cnt, cipher + cnt,
                OFB_LEN - cnt), 0);
        }
        ExpectBufEQ(decrypted, plain, OFB_LEN);
    }
#endif

    WC_FREE_VAR(plain, NULL);
    WC_FREE_VAR(cipher, NULL);
#ifdef HAVE_AES_DECRYPT
    WC_FREE_VAR(decrypted, NULL);
#endif
    return EXPECT_RESULT();
}

static int test_wc_AesOfbEncryptDecrypt_SameBuffer(Aes* aes, byte* key,
    word32 keyLen, byte* iv, byte* expected)
{
    EXPECT_DECLS;
    WC_DECLARE_VAR(plain, byte, OFB_LEN, NULL);
    WC_DECLARE_VAR(cipher, byte, OFB_LEN, NULL);

    WC_ALLOC_VAR(plain, byte, OFB_LEN, NULL);
    WC_ALLOC_VAR(cipher, byte, OFB_LEN, NULL);

#ifdef WC_DECLARE_VAR_IS_HEAP_ALLOC
    ExpectNotNull(plain);
    ExpectNotNull(cipher);
#endif
    XMEMSET(plain, 0xa5, OFB_LEN);

    ExpectIntEQ(wc_AesSetKey(aes, key, keyLen, NULL, AES_ENCRYPTION), 0);

    /* Testing using same buffer for input and output. */
    XMEMCPY(cipher, plain, OFB_LEN);
    ExpectIntEQ(wc_AesSetIV(aes, iv), 0);
    ExpectIntEQ(wc_AesOfbEncrypt(aes, cipher, cipher, OFB_LEN), 0);
    ExpectBufEQ(cipher, expected, OFB_LEN);
#ifdef HAVE_AES_DECRYPT
    ExpectIntEQ(wc_AesSetIV(aes, iv), 0);
    ExpectIntEQ(wc_AesOfbDecrypt(aes, cipher, cipher, OFB_LEN), 0);
    ExpectBufEQ(cipher, plain, OFB_LEN);
#endif

    WC_FREE_VAR(plain, NULL);
    WC_FREE_VAR(cipher, NULL);
    return EXPECT_RESULT();
}
#endif

int test_wc_AesOfbEncryptDecrypt(void)
{
    EXPECT_DECLS;
#if !defined(NO_AES) && defined(WOLFSSL_AES_OFB)
    Aes aes;
#if defined(WOLFSSL_AES_128)
    byte key16[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    byte expected16[OFB_LEN] = {
        0xe3, 0xbf, 0xfa, 0x58, 0x38, 0x52, 0x34, 0xd4,
        0x90, 0x2b, 0x3b, 0xa4, 0xd2, 0x7d, 0xeb, 0x0f,
        0x91, 0x8d, 0x1f, 0x30, 0xd3, 0x00, 0xc5, 0x4e,
        0x1a, 0xcb, 0x2c, 0x50, 0x3f, 0xa6, 0xdf, 0xdb,
        0xa2, 0x60, 0x49, 0xc5, 0x44, 0x3e, 0xdf, 0x90,
        0x39, 0x8c, 0xd1, 0xc9, 0x8e, 0xb9, 0x5a, 0xbe,
        0x05, 0x70, 0x56, 0xfe, 0x86, 0x23, 0x94, 0x1b,
        0xbf, 0x85, 0x89, 0xf2, 0x51, 0x3b, 0x24, 0xc2,
        0x1d, 0x57, 0xc5, 0x8d, 0x93, 0xf5, 0xc9, 0xa3,
        0xcc, 0x0d, 0x49, 0x93, 0xe3, 0x8f, 0x6c, 0xb7,
    };
#endif
#if defined(WOLFSSL_AES_192)
    byte key24[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    byte expected24[OFB_LEN] = {
        0xde, 0x7b, 0xf6, 0x09, 0x2d, 0x81, 0x43, 0x7b,
        0xcd, 0x71, 0xc1, 0xbd, 0x85, 0x33, 0xc7, 0xcd,
        0x75, 0xa1, 0x24, 0xf5, 0xd6, 0x42, 0xc8, 0x2b,
        0xb1, 0xe1, 0x22, 0x08, 0xc8, 0xe1, 0x5c, 0x66,
        0x4c, 0x27, 0x8b, 0x88, 0xb2, 0xb3, 0xe6, 0x03,
        0x8c, 0x46, 0x38, 0xda, 0x21, 0x8b, 0x3f, 0xb1,
        0xcc, 0x4c, 0xde, 0x9d, 0x58, 0x49, 0xd4, 0xef,
        0x52, 0xaa, 0x1a, 0xcb, 0xe8, 0xe3, 0xdb, 0x08,
        0x26, 0x6e, 0x5f, 0x85, 0x80, 0x5d, 0xb6, 0x63,
        0xd0, 0x78, 0xb7, 0xba, 0x48, 0x5f, 0x9f, 0xb9,
    };
#endif
#if defined(WOLFSSL_AES_256)
    byte key32[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    byte expected32[OFB_LEN] = {
        0xbd, 0xff, 0xed, 0x58, 0x12, 0x70, 0x90, 0x56,
        0x9a, 0x1c, 0xb1, 0xb3, 0x56, 0xa0, 0x56, 0xd4,
        0x4f, 0xeb, 0x87, 0x68, 0xb0, 0x9f, 0x69, 0x1f,
        0x9a, 0xfe, 0x20, 0xb0, 0x7a, 0xa2, 0x53, 0x01,
        0x51, 0xe4, 0x42, 0xad, 0x95, 0x3e, 0xac, 0x88,
        0x71, 0x9b, 0xcd, 0x4f, 0xe0, 0x98, 0x9f, 0x46,
        0xd9, 0xcd, 0xa5, 0x7f, 0x4e, 0x22, 0x72, 0xb4,
        0x8f, 0xae, 0xd9, 0xed, 0x40, 0x4a, 0x0b, 0xc8,
        0xc4, 0xa1, 0x01, 0xb3, 0x62, 0x13, 0xaa, 0x0e,
        0x81, 0xa9, 0xd1, 0xae, 0xea, 0x5b, 0x58, 0x74,
    };
#endif
    byte iv[]   = "1234567890abcdef";
    byte* key;
    word32 keyLen;
    byte* expected;

#if defined(WOLFSSL_AES_128)
    key = key16;
    keyLen = (word32)sizeof(key16) / sizeof(byte);
    expected = expected16;
#elif defined(WOLFSSL_AES_192)
    key = key24;
    keyLen = (word32)sizeof(key24) / sizeof(byte);
    expected = expected24;
#else
    key = key32;
    keyLen = (word32)sizeof(key32) / sizeof(byte);
    expected = expected32;
#endif

    XMEMSET(&aes, 0, sizeof(Aes));
    ExpectIntEQ(wc_AesInit(&aes, NULL, INVALID_DEVID), 0);

    EXPECT_TEST(test_wc_AesOfbEncryptDecrypt_BadArgs(&aes, key, keyLen, iv));

#if defined(WOLFSSL_AES_128)
    EXPECT_TEST(test_wc_AesOfbEncryptDecrypt_WithKey(&aes, key16,
        (word32)sizeof(key16) / sizeof(byte), iv, expected16));
#endif
#if defined(WOLFSSL_AES_192)
    EXPECT_TEST(test_wc_AesOfbEncryptDecrypt_WithKey(&aes, key24,
        (word32)sizeof(key24) / sizeof(byte), iv, expected24));
#endif
#if defined(WOLFSSL_AES_256)
    EXPECT_TEST(test_wc_AesOfbEncryptDecrypt_WithKey(&aes, key32,
        (word32)sizeof(key32) / sizeof(byte), iv, expected32));
#endif

    EXPECT_TEST(test_wc_AesOfbEncryptDecrypt_Chunking(&aes, key, keyLen, iv,
        expected));
    EXPECT_TEST(test_wc_AesOfbEncryptDecrypt_SameBuffer(&aes, key, keyLen, iv,
        expected));

    wc_AesFree(&aes);
#endif
    return EXPECT_RESULT();
}

/*******************************************************************************
 * AES-CTS
 ******************************************************************************/

int test_wc_AesCtsEncryptDecrypt(void)
{
    EXPECT_DECLS;
#if !defined(NO_AES) && defined(WOLFSSL_AES_CTS) && \
    defined(HAVE_AES_DECRYPT) && defined(WOLFSSL_AES_128)
    /* Test vectors taken form RFC3962 Appendix B */
    const struct {
        const char* input;
        const char* output;
        size_t inLen;
        size_t outLen;
    } vects[] = {
        {
            "\x49\x20\x77\x6f\x75\x6c\x64\x20\x6c\x69\x6b\x65\x20\x74\x68\x65"
            "\x20",
            "\xc6\x35\x35\x68\xf2\xbf\x8c\xb4\xd8\xa5\x80\x36\x2d\xa7\xff\x7f"
            "\x97",
            17, 17
        },
        {
            "\x49\x20\x77\x6f\x75\x6c\x64\x20\x6c\x69\x6b\x65\x20\x74\x68\x65"
            "\x20\x47\x65\x6e\x65\x72\x61\x6c\x20\x47\x61\x75\x27\x73\x20",
            "\xfc\x00\x78\x3e\x0e\xfd\xb2\xc1\xd4\x45\xd4\xc8\xef\xf7\xed\x22"
            "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5",
            31, 31
        },
        {
            "\x49\x20\x77\x6f\x75\x6c\x64\x20\x6c\x69\x6b\x65\x20\x74\x68\x65"
            "\x20\x47\x65\x6e\x65\x72\x61\x6c\x20\x47\x61\x75\x27\x73\x20\x43",
            "\x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5\xa8"
            "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84",
            32, 32
        },
        {
            "\x49\x20\x77\x6f\x75\x6c\x64\x20\x6c\x69\x6b\x65\x20\x74\x68\x65"
            "\x20\x47\x65\x6e\x65\x72\x61\x6c\x20\x47\x61\x75\x27\x73\x20\x43"
            "\x68\x69\x63\x6b\x65\x6e\x2c\x20\x70\x6c\x65\x61\x73\x65\x2c",
            "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84"
            "\xb3\xff\xfd\x94\x0c\x16\xa1\x8c\x1b\x55\x49\xd2\xf8\x38\x02\x9e"
            "\x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5",
            47, 47
        },
        {
            "\x49\x20\x77\x6f\x75\x6c\x64\x20\x6c\x69\x6b\x65\x20\x74\x68\x65"
            "\x20\x47\x65\x6e\x65\x72\x61\x6c\x20\x47\x61\x75\x27\x73\x20\x43"
            "\x68\x69\x63\x6b\x65\x6e\x2c\x20\x70\x6c\x65\x61\x73\x65\x2c\x20",
            "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84"
            "\x9d\xad\x8b\xbb\x96\xc4\xcd\xc0\x3b\xc1\x03\xe1\xa1\x94\xbb\xd8"
            "\x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5\xa8",
            48, 48
        },
        {
            "\x49\x20\x77\x6f\x75\x6c\x64\x20\x6c\x69\x6b\x65\x20\x74\x68\x65"
            "\x20\x47\x65\x6e\x65\x72\x61\x6c\x20\x47\x61\x75\x27\x73\x20\x43"
            "\x68\x69\x63\x6b\x65\x6e\x2c\x20\x70\x6c\x65\x61\x73\x65\x2c\x20"
            "\x61\x6e\x64\x20\x77\x6f\x6e\x74\x6f\x6e\x20\x73\x6f\x75\x70\x2e",
            "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84"
            "\x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5\xa8"
            "\x48\x07\xef\xe8\x36\xee\x89\xa5\x26\x73\x0d\xbc\x2f\x7b\xc8\x40"
            "\x9d\xad\x8b\xbb\x96\xc4\xcd\xc0\x3b\xc1\x03\xe1\xa1\x94\xbb\xd8",
            64, 64
        }
    };
    const byte keyBytes[AES_128_KEY_SIZE] = {
        0x63, 0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x20,
        0x74, 0x65, 0x72, 0x69, 0x79, 0x61, 0x6b, 0x69
    };
    byte tmp[64]; /* Largest vector size */
    size_t i;
    byte iv[AES_IV_SIZE]; /* All-zero IV for all cases */

    XMEMSET(iv, 0, sizeof(iv));
    for (i = 0; i < XELEM_CNT(vects) && EXPECT_SUCCESS(); i++) {
        /* One-shot encrypt */
        XMEMSET(tmp, 0, sizeof(tmp));
        ExpectIntEQ(wc_AesCtsEncrypt(keyBytes, sizeof(keyBytes), tmp,
                 (const byte*)vects[i].input, (word32)vects[i].inLen, iv), 0);
        ExpectBufEQ(tmp, vects[i].output, vects[i].outLen);
        XMEMSET(tmp, 0, sizeof(tmp));
        ExpectIntEQ(wc_AesCtsDecrypt(keyBytes, sizeof(keyBytes), tmp,
                 (const byte*)vects[i].output, (word32)vects[i].outLen, iv), 0);
        ExpectBufEQ(tmp, vects[i].input, vects[i].inLen);
    }
    /* Execute all branches */
    {
        Aes* aes = NULL;
        int result_code = 0;
        const byte* in = (const byte*)vects[5].input;
        byte* out = tmp;
        word32 outSz = (word32)vects[5].outLen;
        word32 remSz = (word32)vects[5].outLen;

        XMEMSET(tmp, 0, sizeof(tmp));
        ExpectNotNull(aes = wc_AesNew(NULL, INVALID_DEVID, &result_code));
        ExpectIntEQ(wc_AesSetKey(aes, keyBytes, sizeof(keyBytes), iv,
                                 AES_ENCRYPTION), 0);
        ExpectIntEQ(wc_AesCtsEncryptUpdate(aes, out, &outSz, in, 1), 0);
        in += 1; out += outSz; remSz -= outSz; outSz = remSz;
        ExpectIntEQ(wc_AesCtsEncryptUpdate(aes, out, &outSz, in, 31), 0);
        in += 31; out += outSz; remSz -= outSz; outSz = remSz;
        ExpectIntEQ(wc_AesCtsEncryptUpdate(aes, out, &outSz, in, 32), 0);
        in += 32; out += outSz; remSz -= outSz; outSz = remSz;
        ExpectIntEQ(wc_AesCtsEncryptFinal(aes, out, &outSz), 0);
        remSz -= outSz;
        ExpectIntEQ(remSz, 0);
        ExpectBufEQ(tmp, vects[5].output, vects[5].outLen);
        ExpectIntEQ(wc_AesDelete(aes, &aes), 0);
    }
    {
        Aes* aes = NULL;
        int result_code = 0;
        const byte* in = (const byte*)vects[5].input;
        byte* out = tmp;
        word32 outSz = (word32)vects[5].outLen;
        word32 remSz = (word32)vects[5].outLen;

        ExpectNotNull(aes = wc_AesNew(NULL, INVALID_DEVID, &result_code));
        ExpectIntEQ(wc_AesSetKey(aes, keyBytes, sizeof(keyBytes), iv,
                                 AES_ENCRYPTION), 0);
        ExpectIntEQ(wc_AesCtsEncryptUpdate(aes, out, &outSz, in, 1), 0);
        in += 1; out += outSz; remSz -= outSz; outSz = remSz;
        ExpectIntEQ(wc_AesCtsEncryptUpdate(aes, out, &outSz, in, 63), 0);
        in += 63; out += outSz; remSz -= outSz; outSz = remSz;
        ExpectIntEQ(wc_AesCtsEncryptFinal(aes, out, &outSz), 0);
        remSz -= outSz;
        ExpectIntEQ(remSz, 0);
        ExpectBufEQ(tmp, vects[5].output, vects[5].outLen);
        ExpectIntEQ(wc_AesDelete(aes, &aes), 0);
    }
    {
        Aes* aes = NULL;
        int result_code = 0;
        const byte* in = (const byte*)vects[2].input;
        byte* out = tmp;
        word32 outSz = (word32)vects[2].outLen;
        word32 remSz = (word32)vects[2].outLen;

        ExpectNotNull(aes = wc_AesNew(NULL, INVALID_DEVID, &result_code));
        ExpectIntEQ(wc_AesSetKey(aes, keyBytes, sizeof(keyBytes), iv,
                                 AES_ENCRYPTION), 0);
        ExpectIntEQ(wc_AesCtsEncryptUpdate(aes, out, &outSz, in, 16), 0);
        in += 16; out += outSz; remSz -= outSz; outSz = remSz;
        ExpectIntEQ(wc_AesCtsEncryptUpdate(aes, out, &outSz, in, 16), 0);
        in += 16; out += outSz; remSz -= outSz; outSz = remSz;
        ExpectIntEQ(wc_AesCtsEncryptFinal(aes, out, &outSz), 0);
        remSz -= outSz;
        ExpectIntEQ(remSz, 0);
        ExpectBufEQ(tmp, vects[2].output, vects[2].outLen);
        ExpectIntEQ(wc_AesDelete(aes, &aes), 0);
    }
    {
        Aes* aes = NULL;
        int result_code = 0;
        const byte* in = (const byte*)vects[5].output;
        byte* out = tmp;
        word32 outSz = (word32)vects[5].inLen;
        word32 remSz = (word32)vects[5].inLen;

        XMEMSET(tmp, 0, sizeof(tmp));
        ExpectNotNull(aes = wc_AesNew(NULL, INVALID_DEVID, &result_code));
        ExpectIntEQ(wc_AesSetKey(aes, keyBytes, sizeof(keyBytes), iv,
                                 AES_DECRYPTION), 0);
        ExpectIntEQ(wc_AesCtsDecryptUpdate(aes, out, &outSz, in, 1), 0);
        in += 1; out += outSz; remSz -= outSz; outSz = remSz;
        ExpectIntEQ(wc_AesCtsDecryptUpdate(aes, out, &outSz, in, 31), 0);
        in += 31; out += outSz; remSz -= outSz; outSz = remSz;
        ExpectIntEQ(wc_AesCtsDecryptUpdate(aes, out, &outSz, in, 32), 0);
        in += 32; out += outSz; remSz -= outSz; outSz = remSz;
        ExpectIntEQ(wc_AesCtsDecryptFinal(aes, out, &outSz), 0);
        remSz -= outSz;
        ExpectIntEQ(remSz, 0);
        ExpectBufEQ(tmp, vects[5].input, vects[5].inLen);
        ExpectIntEQ(wc_AesDelete(aes, &aes), 0);
    }
    {
        Aes* aes = NULL;
        int result_code = 0;
        const byte* in = (const byte*)vects[5].output;
        byte* out = tmp;
        word32 outSz = (word32)vects[5].inLen;
        word32 remSz = (word32)vects[5].inLen;

        ExpectNotNull(aes = wc_AesNew(NULL, INVALID_DEVID, &result_code));
        ExpectIntEQ(wc_AesSetKey(aes, keyBytes, sizeof(keyBytes), iv,
                                 AES_DECRYPTION), 0);
        ExpectIntEQ(wc_AesCtsDecryptUpdate(aes, out, &outSz, in, 1), 0);
        in += 1; out += outSz; remSz -= outSz; outSz = remSz;
        ExpectIntEQ(wc_AesCtsDecryptUpdate(aes, out, &outSz, in, 63), 0);
        in += 63; out += outSz; remSz -= outSz; outSz = remSz;
        ExpectIntEQ(wc_AesCtsDecryptFinal(aes, out, &outSz), 0);
        remSz -= outSz;
        ExpectIntEQ(remSz, 0);
        ExpectBufEQ(tmp, vects[5].input, vects[5].inLen);
        ExpectIntEQ(wc_AesDelete(aes, &aes), 0);
    }
    {
        Aes* aes = NULL;
        int result_code = 0;
        const byte* in = (const byte*)vects[2].output;
        byte* out = tmp;
        word32 outSz = (word32)vects[2].inLen;
        word32 remSz = (word32)vects[2].inLen;

        ExpectNotNull(aes = wc_AesNew(NULL, INVALID_DEVID, &result_code));
        ExpectIntEQ(wc_AesSetKey(aes, keyBytes, sizeof(keyBytes), iv,
                                 AES_DECRYPTION), 0);
        ExpectIntEQ(wc_AesCtsDecryptUpdate(aes, out, &outSz, in, 16), 0);
        in += 16; out += outSz; remSz -= outSz; outSz = remSz;
        ExpectIntEQ(wc_AesCtsDecryptUpdate(aes, out, &outSz, in, 16), 0);
        in += 16; out += outSz; remSz -= outSz; outSz = remSz;
        ExpectIntEQ(wc_AesCtsDecryptFinal(aes, out, &outSz), 0);
        remSz -= outSz;
        ExpectIntEQ(remSz, 0);
        ExpectBufEQ(tmp, vects[2].input, vects[2].inLen);
        ExpectIntEQ(wc_AesDelete(aes, &aes), 0);
    }
#endif
    return EXPECT_RESULT();
}

/*******************************************************************************
 * AES-CTR
 ******************************************************************************/

#if !defined(NO_AES) && defined(WOLFSSL_AES_COUNTER) && \
    (!defined(HAVE_FIPS) || FIPS_VERSION_GE(7,0)) && \
    !defined(HAVE_SELFTEST) && !defined(WOLFSSL_AFALG) && \
    !defined(WOLFSSL_KCAPI)
static int test_wc_AesCtrSetKey_BadArgs(Aes* aes, byte* key, word32 keyLen,
    byte* iv)
{
    EXPECT_DECLS;

    ExpectIntEQ(wc_AesCtrSetKey(NULL, NULL, keyLen, iv, AES_ENCRYPTION),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCtrSetKey(NULL, key , keyLen, iv, AES_ENCRYPTION),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCtrSetKey(aes , key , 48    , iv, AES_ENCRYPTION),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    return EXPECT_RESULT();
}

static int test_wc_AesCtrSetKey_WithKey(Aes* aes, byte* key, word32 keyLen,
    byte* iv, int ret)
{
    EXPECT_DECLS;

    ExpectIntEQ(wc_AesCtrSetKey(aes, key, keyLen, iv, AES_ENCRYPTION), ret);
    ExpectIntEQ(wc_AesCtrSetKey(aes, key, keyLen, NULL, AES_DECRYPTION), ret);

    return EXPECT_RESULT();
}
#endif /* !NO_AES && WOLFSSL_AES_COUNTER &&       */
       /* (!HAVE_FIPS || FIPS_VERSION_GE(7,0)) && */
       /* !HAVE_SELFTEST && !WOLFSSL_AFALG &&     */
       /* !WOLFSSL_KCAPI */

/*
 * Testing function for wc_AesCtrSetKey().
 */
int test_wc_AesCtrSetKey(void)
{
    EXPECT_DECLS;
#if !defined(NO_AES) && defined(WOLFSSL_AES_COUNTER) && \
    (!defined(HAVE_FIPS) || FIPS_VERSION_GE(7,0)) && \
    !defined(HAVE_SELFTEST) && !defined(WOLFSSL_AFALG) && \
    !defined(WOLFSSL_KCAPI)
    Aes  aes;
    byte key16[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    byte key24[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
    };
    byte key32[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    byte badKey16[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65
    };
    byte iv[] = "1234567890abcdef";
    byte* key;
    word32 keyLen;

#if defined(WOLFSSL_AES_128)
    key = key16;
    keyLen = (word32)sizeof(key16) / sizeof(byte);
#elif defined(WOLFSSL_AES_192)
    key = key24;
    keyLen = (word32)sizeof(key24) / sizeof(byte);
#else
    key = key32;
    keyLen = (word32)sizeof(key32) / sizeof(byte);
#endif

    XMEMSET(&aes, 0, sizeof(Aes));

    ExpectIntEQ(wc_AesInit(NULL, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesInit(&aes, NULL, INVALID_DEVID), 0);

    EXPECT_TEST(test_wc_AesCtrSetKey_BadArgs(&aes, key, keyLen, iv));

#ifdef WOLFSSL_AES_128
    EXPECT_TEST(test_wc_AesCtrSetKey_WithKey(&aes, key16,
        (word32)sizeof(key16) / sizeof(byte), iv, 0));
#else
    EXPECT_TEST(test_wc_AesCtrSetKey_WithKey(&aes, key16,
        (word32)sizeof(key16) / sizeof(byte), iv, BAD_FUNC_ARG));
#endif
#ifdef WOLFSSL_AES_192
    EXPECT_TEST(test_wc_AesCtrSetKey_WithKey(&aes, key24,
        (word32)sizeof(key24) / sizeof(byte), iv, 0));
#else
    EXPECT_TEST(test_wc_AesCtrSetKey_WithKey(&aes, key24,
        (word32)sizeof(key24) / sizeof(byte), iv, BAD_FUNC_ARG));
#endif
#ifdef WOLFSSL_AES_256
    EXPECT_TEST(test_wc_AesCtrSetKey_WithKey(&aes, key32,
        (word32)sizeof(key32) / sizeof(byte), iv, 0));
#else
    EXPECT_TEST(test_wc_AesCtrSetKey_WithKey(&aes, key32,
        (word32)sizeof(key32) / sizeof(byte), iv, BAD_FUNC_ARG));
#endif

    ExpectIntEQ(wc_AesCtrSetKey(&aes, badKey16,
        (word32)sizeof(badKey16) / sizeof(byte), iv, AES_ENCRYPTION),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_AesFree(&aes);
#endif /* !NO_AES && WOLFSSL_AES_COUNTER &&       */
       /* (!HAVE_FIPS || FIPS_VERSION_GE(7,0)) && */
       /* !HAVE_SELFTEST && !WOLFSSL_AFALG &&     */
       /* !WOLFSSL_KCAPI */

    return EXPECT_RESULT();
} /* END test_wc_AesCtrSetKey */

#if !defined(NO_AES) && defined(WOLFSSL_AES_COUNTER)
/* Assembly code doing 8 iterations at a time. */
#define CTR_LEN     (9 * WC_AES_BLOCK_SIZE)

static int test_wc_AesCtrEncrypt_BadArgs(Aes* aes, byte* key,
    word32 keyLen, byte* iv)
{
    EXPECT_DECLS;
    byte    plain[WC_AES_BLOCK_SIZE];
    byte    cipher[WC_AES_BLOCK_SIZE];
    byte    decrypted[WC_AES_BLOCK_SIZE];

    XMEMSET(plain, 0, WC_AES_BLOCK_SIZE);
    XMEMSET(cipher, 0, WC_AES_BLOCK_SIZE);
    XMEMSET(decrypted, 0, WC_AES_BLOCK_SIZE);

#if (!defined(HAVE_FIPS) || FIPS_VERSION_GE(7,0)) && \
    !defined(HAVE_SELFTEST) && !defined(WOLFSSL_AFALG) && \
    !defined(WOLFSSL_KCAPI)
    ExpectIntEQ(wc_AesCtrSetKey(aes, key, keyLen, iv, AES_ENCRYPTION), 0);
#else
    ExpectIntEQ(wc_AesSetKey(aes, key, keyLen, iv, AES_ENCRYPTION), 0);
#endif
    ExpectIntEQ(wc_AesCtrEncrypt(NULL, NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCtrEncrypt(aes, NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCtrEncrypt(NULL, cipher, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCtrEncrypt(NULL, NULL, plain, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCtrEncrypt(aes, cipher, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCtrEncrypt(aes, NULL, plain, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCtrEncrypt(NULL, cipher, plain, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    return EXPECT_RESULT();
}

static int test_wc_AesCtrEncrypt_WithKey(Aes* aes, byte* key,
    word32 keyLen, byte* iv, byte* vector, byte* vector_enc, word32 vector_len)
{
    EXPECT_DECLS;
    byte    plain[WC_AES_BLOCK_SIZE * 2];
    byte    cipher[WC_AES_BLOCK_SIZE * 2];
    byte    decrypted[WC_AES_BLOCK_SIZE * 2];

    XMEMSET(plain, 0, WC_AES_BLOCK_SIZE * 2);
    XMEMSET(cipher, 0, WC_AES_BLOCK_SIZE * 2);
    XMEMSET(decrypted, 0, WC_AES_BLOCK_SIZE * 2);

#if (!defined(HAVE_FIPS) || FIPS_VERSION_GE(7,0)) && \
    !defined(HAVE_SELFTEST) && !defined(WOLFSSL_AFALG) && \
    !defined(WOLFSSL_KCAPI)
    ExpectIntEQ(wc_AesCtrSetKey(aes, key, keyLen, iv, AES_ENCRYPTION), 0);
#else
    ExpectIntEQ(wc_AesSetKey(aes, key, keyLen, iv, AES_ENCRYPTION), 0);
#endif
    ExpectIntEQ(wc_AesCtrEncrypt(aes, cipher, vector, vector_len), 0);
    ExpectBufEQ(cipher, vector_enc, vector_len);
    /* Decrypt with wc_AesCtrEncrypt() */
#if (!defined(HAVE_FIPS) || FIPS_VERSION_GE(7,0)) && \
    !defined(HAVE_SELFTEST) && !defined(WOLFSSL_AFALG) && \
    !defined(WOLFSSL_KCAPI)
    ExpectIntEQ(wc_AesCtrSetKey(aes, key, keyLen, iv, AES_ENCRYPTION), 0);
#else
    ExpectIntEQ(wc_AesSetKey(aes, key, keyLen, iv, AES_ENCRYPTION), 0);
#endif
    ExpectIntEQ(wc_AesCtrEncrypt(aes, decrypted, cipher, vector_len), 0);
    ExpectBufEQ(decrypted, vector, vector_len);

    return EXPECT_RESULT();
}

static int test_wc_AesCtrEncrypt_Chunking(Aes* aes, byte* key,
    word32 keyLen, byte* iv, byte* expected)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_AFALG) || defined(WOLFSSL_KCAPI)
    (void)aes;
    (void)key;
    (void)keyLen;
    (void)iv;
    (void)expected;
#else
    int sz;
    int cnt;
    WC_DECLARE_VAR(plain, byte, CTR_LEN, NULL);
    WC_DECLARE_VAR(cipher, byte, CTR_LEN, NULL);
#ifdef HAVE_AES_DECRYPT
    WC_DECLARE_VAR(decrypted, byte, CTR_LEN, NULL);
#endif

    WC_ALLOC_VAR(plain, byte, CTR_LEN, NULL);
    WC_ALLOC_VAR(cipher, byte, CTR_LEN, NULL);
#ifdef HAVE_AES_DECRYPT
    WC_ALLOC_VAR(decrypted, byte, CTR_LEN, NULL);
#endif

#ifdef WC_DECLARE_VAR_IS_HEAP_ALLOC
    ExpectNotNull(plain);
    ExpectNotNull(cipher);
#ifdef HAVE_AES_DECRYPT
    ExpectNotNull(decrypted);
#endif
#endif

    XMEMSET(plain, 0, CTR_LEN);
    XMEMSET(cipher, 0, CTR_LEN);
    XMEMSET(decrypted, 0, CTR_LEN);

#if (!defined(HAVE_FIPS) || FIPS_VERSION_GE(7,0)) && \
    !defined(HAVE_SELFTEST)
    ExpectIntEQ(wc_AesCtrSetKey(aes, key, keyLen, NULL, AES_ENCRYPTION), 0);
#else
    ExpectIntEQ(wc_AesSetKey(aes, key, keyLen, NULL, AES_ENCRYPTION), 0);
#endif
    /* Test multiple blocks. */
    for (sz = 1; sz <= CTR_LEN; sz++) {
        XMEMSET(cipher, 0x00, CTR_LEN);
        ExpectIntEQ(wc_AesSetIV(aes, iv), 0);
        for (cnt = 0; cnt + sz <= CTR_LEN; cnt += sz) {
            ExpectIntEQ(wc_AesCtrEncrypt(aes, cipher + cnt, plain + cnt, sz),
                0);
        }
        if (cnt < CTR_LEN) {
            ExpectIntEQ(wc_AesCtrEncrypt(aes, cipher + cnt, plain + cnt,
                CTR_LEN - cnt), 0);
        }
        ExpectBufEQ(cipher, expected, CTR_LEN);
    }

    WC_FREE_VAR(plain, NULL);
    WC_FREE_VAR(cipher, NULL);
#ifdef HAVE_AES_DECRYPT
    WC_FREE_VAR(decrypted, NULL);
#endif
#endif /* !WOLFSSL_AFALG && !WOLFSSL_KCAPI */
    return EXPECT_RESULT();
}

#if (!defined(HAVE_FIPS) || FIPS_VERSION_GE(7,0)) && \
    !defined(HAVE_SELFTEST) && !defined(WOLFSSL_AFALG) && \
    !defined(WOLFSSL_KCAPI)
static int test_wc_AesCtrEncrypt_SameBuffer(Aes* aes, byte* key,
    word32 keyLen, byte* iv, byte* expected)
{
    EXPECT_DECLS;
    WC_DECLARE_VAR(plain, byte, CTR_LEN, NULL);
    WC_DECLARE_VAR(cipher, byte, CTR_LEN, NULL);

    WC_ALLOC_VAR(plain, byte, CTR_LEN, NULL);
    WC_ALLOC_VAR(cipher, byte, CTR_LEN, NULL);

#ifdef WC_DECLARE_VAR_IS_HEAP_ALLOC
    ExpectNotNull(plain);
    ExpectNotNull(cipher);
#endif

    XMEMSET(plain, 0, CTR_LEN);

    /* Testing using same buffer for input and output. */
    ExpectIntEQ(wc_AesCtrSetKey(aes, key, keyLen, iv, AES_ENCRYPTION), 0);
    XMEMCPY(cipher, plain, CTR_LEN);
    ExpectIntEQ(wc_AesCtrEncrypt(aes, cipher, cipher, CTR_LEN), 0);
    ExpectBufEQ(cipher, expected, CTR_LEN);

    WC_FREE_VAR(plain, NULL);
    WC_FREE_VAR(cipher, NULL);
    return EXPECT_RESULT();
}
#endif
#endif

/*
 * Testing wc_AesCtrEncrypt
 * Decrypt is an encrypt.
 */
int test_wc_AesCtrEncryptDecrypt(void)
{
    EXPECT_DECLS;
#if !defined(NO_AES) && defined(WOLFSSL_AES_COUNTER)
    Aes aes;
    byte vector[] = { /* Now is the time for all w/o trailing 0 */
        0x4e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
        0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20
    };
#if defined(WOLFSSL_AES_128)
    byte key16[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    byte vector_enc16[] = {
        0x08, 0x75, 0x28, 0xdd, 0xf4, 0x84, 0xb1, 0x05,
        0x5d, 0xeb, 0xbe, 0x75, 0x1e, 0xb5, 0x2b, 0x8a,
        0x39, 0x70, 0x64, 0x06, 0x98, 0xa1, 0x82, 0x35,
    };
#endif
#if defined(WOLFSSL_AES_192)
    byte key24[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    byte vector_enc24[] = {
        0x35, 0xb1, 0x24, 0x8c, 0xe1, 0x57, 0xc6, 0xaa,
        0x00, 0xb1, 0x44, 0x6c, 0x49, 0xfb, 0x07, 0x48,
        0xd2, 0xa7, 0x1e, 0x81, 0xcf, 0xa0, 0x72, 0x54,
    };
#endif
#if defined(WOLFSSL_AES_256)
    byte key32[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    byte vector_enc32[] = {
        0x56, 0x35, 0x3f, 0xdd, 0xde, 0xa6, 0x15, 0x87,
        0x57, 0xdc, 0x34, 0x62, 0x9a, 0x68, 0x96, 0x51,
        0x14, 0xeb, 0xfa, 0xba, 0x30, 0x8e, 0xfb, 0x8a,
    };
#endif
#if defined(WOLFSSL_AES_128)
    byte expected16[CTR_LEN] = {
        0x46, 0x1a, 0x5f, 0xfd, 0x9d, 0xf7, 0x91, 0x71,
        0x35, 0x8e, 0x9e, 0x01, 0x77, 0xd8, 0x4e, 0xaa,
        0x5f, 0x1f, 0x16, 0x26, 0xf9, 0xcd, 0xee, 0x15,
        0xce, 0x4d, 0x4d, 0x3d, 0x17, 0x56, 0xa1, 0x48,
        0x36, 0x0b, 0x0e, 0x8b, 0x3d, 0x3b, 0x70, 0x02,
        0x2e, 0xd1, 0x0b, 0x61, 0x51, 0x05, 0xd6, 0x2b,
        0x4b, 0xb9, 0xaf, 0x26, 0x27, 0xed, 0x41, 0x50,
        0x08, 0xaf, 0xdd, 0xbf, 0x5b, 0x12, 0x4b, 0xb2,
        0x80, 0xd5, 0xba, 0x31, 0x31, 0x70, 0xfa, 0xfd,
        0x15, 0x19, 0x1e, 0x35, 0xc9, 0x10, 0x96, 0x6c,
        0xe4, 0x38, 0x61, 0xd8, 0x95, 0x30, 0x4d, 0xca,
        0xd8, 0x68, 0xc9, 0xdc, 0x6f, 0x8b, 0x86, 0x26,
        0x11, 0xee, 0x2d, 0x01, 0xd3, 0x0e, 0x35, 0xa2,
        0x4b, 0x26, 0x22, 0x8c, 0xd0, 0x4e, 0xda, 0x5d,
        0x49, 0x1e, 0x6d, 0xfa, 0x33, 0xcb, 0xa0, 0x0f,
        0x86, 0x8f, 0x83, 0xff, 0x3d, 0xbe, 0x6e, 0xfa,
        0xd2, 0x2b, 0x3e, 0x70, 0x21, 0x1c, 0xe8, 0x7b,
        0xe4, 0x01, 0x2c, 0xd0, 0x82, 0xe2, 0x7a, 0x4a,
    };
#elif defined(WOLFSSL_AES_192)
    byte expected24[CTR_LEN] = {
        0x7b, 0xde, 0x53, 0xac, 0x88, 0x24, 0xe6, 0xde,
        0x68, 0xd4, 0x64, 0x18, 0x20, 0x96, 0x62, 0x68,
        0xb4, 0xc8, 0x6c, 0xa1, 0xae, 0xcc, 0x1e, 0x74,
        0x2a, 0xd6, 0x69, 0x5c, 0x71, 0x76, 0x92, 0x5b,
        0xd8, 0x61, 0xfa, 0x70, 0x8c, 0x80, 0x3e, 0xfc,
        0xdc, 0xd8, 0xbb, 0x31, 0x22, 0x47, 0x78, 0x02,
        0x5b, 0xa2, 0xb5, 0xb1, 0x41, 0x88, 0xc4, 0x84,
        0x82, 0xd7, 0x20, 0x11, 0xdc, 0x58, 0xea, 0xf9,
        0x2c, 0x43, 0x50, 0xc2, 0x33, 0x15, 0x58, 0x14,
        0xd0, 0xf3, 0xe5, 0xe1, 0x17, 0x86, 0x4b, 0xfb,
        0xdd, 0x83, 0xa3, 0xdd, 0x3a, 0xcc, 0x82, 0x05,
        0xb9, 0xf2, 0xfd, 0x8d, 0x3c, 0x08, 0x5f, 0xd9,
        0x79, 0x2d, 0xa3, 0xa0, 0xeb, 0xa3, 0xa2, 0xfe,
        0x7b, 0x2b, 0xf9, 0x5d, 0x32, 0x52, 0xeb, 0xee,
        0xe1, 0x68, 0xff, 0xe7, 0xb3, 0x0c, 0x08, 0x74,
        0x8d, 0x3b, 0xa9, 0x17, 0x4c, 0x2a, 0xc7, 0x97,
        0x99, 0xb7, 0xaf, 0x86, 0x17, 0xf9, 0xe4, 0x2c,
        0x5a, 0x4d, 0x6d, 0x7f, 0xfe, 0xb8, 0xaa, 0x9b,
    };
#else
    byte expected32[CTR_LEN] = {
        0x18, 0x5a, 0x48, 0xfd, 0xb7, 0xd5, 0x35, 0xf3,
        0x3f, 0xb9, 0x14, 0x16, 0xf3, 0x05, 0xf3, 0x71,
        0x72, 0x84, 0x88, 0x9a, 0x51, 0xe2, 0x97, 0xaa,
        0x65, 0xc1, 0x3c, 0x0b, 0x1e, 0x9f, 0x29, 0xb8,
        0xf4, 0xc8, 0x16, 0x9c, 0x47, 0x42, 0x0a, 0x9e,
        0xae, 0xf0, 0x75, 0x9b, 0x54, 0xdd, 0x8a, 0xa4,
        0x28, 0x97, 0xc1, 0x5a, 0xbb, 0x08, 0x52, 0x73,
        0xf7, 0x67, 0xa4, 0xb8, 0xc9, 0x37, 0x8d, 0x9e,
        0x23, 0x27, 0x68, 0xca, 0x2b, 0xb5, 0xd0, 0x1c,
        0x11, 0xe2, 0x2e, 0x7e, 0x17, 0x6b, 0x38, 0x99,
        0x82, 0x0c, 0x65, 0xed, 0x33, 0xd8, 0xa4, 0x47,
        0x43, 0x9c, 0x16, 0xa6, 0xab, 0x5d, 0x39, 0xad,
        0x88, 0x6a, 0x50, 0x86, 0xd4, 0x95, 0x1b, 0x91,
        0xb3, 0x91, 0x7d, 0x06, 0xe0, 0xfc, 0x5e, 0xd1,
        0xaf, 0x4c, 0xb3, 0xdb, 0x01, 0x01, 0xc9, 0x09,
        0xf1, 0x7b, 0x2b, 0x87, 0xe4, 0xcd, 0x93, 0x22,
        0x07, 0xdc, 0x35, 0x46, 0x8a, 0x1d, 0xf5, 0xe4,
        0x23, 0x01, 0x67, 0x00, 0x66, 0x7b, 0xd6, 0x56,
    };
#endif
    byte    iv[]   = "1234567890abcdef";
    byte* key;
    word32 keyLen;
    byte* expected;

#if defined(WOLFSSL_AES_128)
    key = key16;
    keyLen = (word32)sizeof(key16) / sizeof(byte);
    expected = expected16;
#elif defined(WOLFSSL_AES_192)
    key = key24;
    keyLen = (word32)sizeof(key24) / sizeof(byte);
    expected = expected24;
#else
    key = key32;
    keyLen = (word32)sizeof(key32) / sizeof(byte);
    expected = expected32;
#endif

    /* Init stack variables. */
    XMEMSET(&aes, 0, sizeof(Aes));

    ExpectIntEQ(wc_AesInit(&aes, NULL, INVALID_DEVID), 0);

    EXPECT_TEST(test_wc_AesCtrEncrypt_BadArgs(&aes, key, keyLen, iv));

#ifdef WOLFSSL_AES_128
    EXPECT_TEST(test_wc_AesCtrEncrypt_WithKey(&aes, key16,
        (word32)sizeof(key16) / sizeof(byte), iv, vector, vector_enc16,
        (word32)sizeof(vector) / sizeof(byte)));
#endif
#ifdef WOLFSSL_AES_192
    EXPECT_TEST(test_wc_AesCtrEncrypt_WithKey(&aes, key24,
        (word32)sizeof(key24) / sizeof(byte), iv, vector, vector_enc24,
        (word32)sizeof(vector) / sizeof(byte)));
#endif
#ifdef WOLFSSL_AES_256
    EXPECT_TEST(test_wc_AesCtrEncrypt_WithKey(&aes, key32,
        (word32)sizeof(key32) / sizeof(byte), iv, vector, vector_enc32,
        (word32)sizeof(vector) / sizeof(byte)));
#endif

    EXPECT_TEST(test_wc_AesCtrEncrypt_Chunking(&aes, key, keyLen, iv,
        expected));
#if (!defined(HAVE_FIPS) || FIPS_VERSION_GE(7,0)) && \
    !defined(HAVE_SELFTEST) && !defined(WOLFSSL_AFALG) && \
    !defined(WOLFSSL_KCAPI)
    EXPECT_TEST(test_wc_AesCtrEncrypt_SameBuffer(&aes, key, keyLen, iv,
        expected));
#endif

    wc_AesFree(&aes);
#endif
    return EXPECT_RESULT();
} /* END test_wc_AesCtrEncryptDecrypt */

/*******************************************************************************
 * AES-GCM
 ******************************************************************************/

/*
 * test function for wc_AesGcmSetKey()
 */
int test_wc_AesGcmSetKey(void)
{
    EXPECT_DECLS;
#if  !defined(NO_AES) && defined(HAVE_AESGCM)
    Aes aes;
#ifdef WOLFSSL_AES_128
    byte key16[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
#endif
#ifdef WOLFSSL_AES_192
    byte key24[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
    };
#endif
#ifdef WOLFSSL_AES_256
    byte key32[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
#endif
    byte badKey16[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65
    };
    byte badKey24[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36
    };
    byte badKey32[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x37, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65
    };
    byte* key;
    word32 keyLen;

#ifdef WOLFSSL_AES_128
    key = key16;
    keyLen = sizeof(key16)/sizeof(byte);
#elif defined(WOLFSSL_AES_192)
    key = key24;
    keyLen = sizeof(key24)/sizeof(byte);
#else
    key = key32;
    keyLen = sizeof(key32)/sizeof(byte);
#endif

    ExpectIntEQ(wc_AesInit(&aes, NULL, INVALID_DEVID), 0);

#ifdef WOLFSSL_AES_128
    ExpectIntEQ(wc_AesGcmSetKey(&aes, key16, sizeof(key16)/sizeof(byte)), 0);
#endif
#ifdef WOLFSSL_AES_192
    ExpectIntEQ(wc_AesGcmSetKey(&aes, key24, sizeof(key24)/sizeof(byte)), 0);
#endif
#ifdef WOLFSSL_AES_256
    ExpectIntEQ(wc_AesGcmSetKey(&aes, key32, sizeof(key32)/sizeof(byte)), 0);
#endif

    /* Pass in bad args. */
    ExpectIntEQ(wc_AesGcmSetKey(NULL, NULL, keyLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesGcmSetKey(NULL, key, keyLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#if (!defined(HAVE_FIPS) || !defined(HAVE_FIPS_VERSION) || \
        (HAVE_FIPS_VERSION > 6)) && !defined(HAVE_SELFTEST)
    ExpectIntEQ(wc_AesGcmSetKey(&aes, NULL, keyLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wc_AesGcmSetKey(&aes, badKey16, sizeof(badKey16)/sizeof(byte)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesGcmSetKey(&aes, badKey24, sizeof(badKey24)/sizeof(byte)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesGcmSetKey(&aes, badKey32, sizeof(badKey32)/sizeof(byte)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_AesFree(&aes);
#endif
    return EXPECT_RESULT();
} /* END test_wc_AesGcmSetKey */

int test_wc_AesGcmEncryptDecrypt_Sizes(void)
{
    EXPECT_DECLS;
#if !defined(NO_AES) && defined(HAVE_AESGCM) && defined(WOLFSSL_AES_256) && \
    !defined(WOLFSSL_AFALG) && !defined(WOLFSSL_KCAPI)
    #define GCM_LEN     (WC_AES_BLOCK_SIZE * 16)
    byte expTagShort[WC_AES_BLOCK_SIZE][WC_AES_BLOCK_SIZE] = {
        {
            0x41, 0x5d, 0x72, 0x1e, 0xe0, 0x17, 0x7c, 0xe2,
            0x33, 0xfb, 0x0e, 0xab, 0x5a, 0x08, 0x4c, 0xb0,
        },
        {
            0x26, 0xe8, 0xc0, 0x9f, 0xbc, 0x70, 0x1d, 0x7e,
            0x22, 0x43, 0x26, 0x1b, 0x21, 0x9d, 0x2c, 0x5b,
        },
        {
            0x94, 0x8f, 0x24, 0xeb, 0xd1, 0x5b, 0x3d, 0x2a,
            0x31, 0xf2, 0xe4, 0xf9, 0x07, 0xc8, 0xe7, 0x63,
        },
        {
            0x62, 0xa9, 0x79, 0x97, 0x6c, 0x93, 0x77, 0x52,
            0x2f, 0xbf, 0x51, 0xb2, 0xc2, 0xf7, 0xe5, 0xf4,
        },
        {
            0xa5, 0x44, 0xfd, 0x3c, 0x16, 0x2a, 0x05, 0x7a,
            0x52, 0xe1, 0xed, 0x13, 0x49, 0x81, 0x93, 0x7a,
        },
        {
            0xe5, 0x3b, 0xd4, 0xc9, 0x9f, 0x9e, 0xf0, 0x55,
            0xcd, 0x80, 0xb7, 0x42, 0xa4, 0xaf, 0x33, 0x88,
        },
        {
            0x65, 0xa8, 0xc9, 0xa7, 0x8b, 0xdb, 0x80, 0xfe,
            0x40, 0xfe, 0xb6, 0xe4, 0x00, 0xf9, 0x23, 0x72,
        },
        {
            0xe0, 0x1e, 0xec, 0x38, 0x45, 0xf0, 0x9c, 0x82,
            0x72, 0xac, 0x2f, 0xec, 0x3b, 0x2b, 0xfe, 0x75,
        },
        {
            0xea, 0xb4, 0x5b, 0x4d, 0x76, 0x98, 0xc8, 0x34,
            0x07, 0x1d, 0x7b, 0xaf, 0x36, 0xfa, 0x72, 0x9b,
        },
        {
            0xcf, 0x2b, 0x12, 0x7a, 0x5a, 0x5a, 0x73, 0x73,
            0xb5, 0xb6, 0xb6, 0xb0, 0x42, 0xa5, 0xc0, 0x23,
        },
        {
            0xc1, 0x14, 0x52, 0xd0, 0xd0, 0x1d, 0xca, 0xce,
            0x2e, 0x4c, 0xd8, 0x94, 0x62, 0x92, 0xf6, 0x9c,
        },
        {
            0x5b, 0xd9, 0xa6, 0x8c, 0x34, 0x0e, 0x81, 0xaf,
            0x09, 0xc3, 0x44, 0x74, 0x35, 0xce, 0x89, 0x92,
        },
        {
            0xdc, 0x9f, 0xd0, 0xd5, 0xaa, 0x38, 0xe2, 0xce,
            0x75, 0x88, 0x64, 0xee, 0x7a, 0x5d, 0x44, 0xa4,
        },
        {
            0xc3, 0x35, 0xfe, 0xa9, 0x9d, 0x3d, 0x75, 0xb7,
            0xba, 0xdd, 0x9e, 0xa5, 0x5d, 0xd3, 0x65, 0x80,
        },
        {
            0x1d, 0x1a, 0x04, 0x99, 0xb5, 0x8b, 0xe8, 0xec,
            0x81, 0xd1, 0xde, 0xd3, 0x3a, 0x09, 0xb4, 0x9f,
        },
        {
            0xb8, 0x14, 0x0a, 0xc3, 0x8b, 0x88, 0x87, 0xa1,
            0xdf, 0xfa, 0x6d, 0x15, 0x70, 0xde, 0xff, 0x3b,
        },
    };
    byte expected[GCM_LEN] = {
        0x9a, 0x10, 0xb2, 0x60, 0x38, 0x65, 0x46, 0x81,
        0xc0, 0xa7, 0x0d, 0x3f, 0x5b, 0x4f, 0x27,
    };
    byte expTagLong[][WC_AES_BLOCK_SIZE] = {
        {
            0xdd, 0x1c, 0x3d, 0x12, 0xa4, 0x16, 0xa5, 0xf7,
            0x67, 0xc5, 0x58, 0xb8, 0xda, 0x22, 0x6c, 0x22,
        },
        {
            0xbe, 0x5e, 0x04, 0x61, 0xae, 0x36, 0x61, 0xfb,
            0x86, 0x66, 0xda, 0x62, 0xaa, 0x36, 0x7e, 0x22,
        },
        {
            0x18, 0xc3, 0xf5, 0xcf, 0x76, 0x24, 0xd4, 0x5c,
            0xbb, 0xeb, 0xb3, 0x0a, 0x7a, 0x53, 0x64, 0x9b,
        },
        {
            0xe0, 0xaa, 0xe9, 0x10, 0x41, 0x16, 0x72, 0x1b,
            0x16, 0xd6, 0xd9, 0xcd, 0x2f, 0xe4, 0xd2, 0xe8,
        },
        {
            0xfa, 0xdc, 0x28, 0x4a, 0x65, 0x96, 0xe0, 0x73,
            0xfb, 0xcd, 0x2b, 0x35, 0xa0, 0x68, 0xde, 0x60,
        },
    };
    byte key32[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    Aes aes;
    byte tag[WC_AES_BLOCK_SIZE];
    byte iv[] = "1234567890a";
    word32 ivLen = (word32)sizeof(iv)/sizeof(byte);
    int sz;
    int i;
    WC_DECLARE_VAR(plain, byte, GCM_LEN, NULL);
    WC_DECLARE_VAR(cipher, byte, GCM_LEN, NULL);
#ifdef HAVE_AES_DECRYPT
    WC_DECLARE_VAR(decrypted, byte, GCM_LEN, NULL);
#endif

    WC_ALLOC_VAR(plain, byte, GCM_LEN, NULL);
    WC_ALLOC_VAR(cipher, byte, GCM_LEN, NULL);
#ifdef HAVE_AES_DECRYPT
    WC_ALLOC_VAR(decrypted, byte, GCM_LEN, NULL);
#endif

#ifdef WC_DECLARE_VAR_IS_HEAP_ALLOC
    ExpectNotNull(plain);
    ExpectNotNull(cipher);
#ifdef HAVE_AES_DECRYPT
    ExpectNotNull(decrypted);
#endif
#endif

    XMEMSET(&aes, 0, sizeof(Aes));
    XMEMSET(plain, 0xa5, GCM_LEN);

    ExpectIntEQ(wc_AesInit(&aes, NULL, INVALID_DEVID), 0);

    ExpectIntEQ(wc_AesGcmSetKey(&aes, key32, sizeof(key32)/sizeof(byte)), 0);
    for (sz = 0; sz < WC_AES_BLOCK_SIZE; sz++) {
        XMEMSET(cipher, 0, GCM_LEN);
        ExpectIntEQ(wc_AesGcmEncrypt(&aes, cipher, plain, sz, iv, ivLen, tag,
            sizeof(tag), NULL, 0), 0);
        ExpectBufEQ(cipher, expected, sz);
        ExpectBufEQ(tag, expTagShort[sz], WC_AES_BLOCK_SIZE);

#ifdef HAVE_AES_DECRYPT
        XMEMSET(decrypted, 0xff, GCM_LEN);
        ExpectIntEQ(wc_AesGcmDecrypt(&aes, decrypted, cipher, sz, iv, ivLen,
            tag, sizeof(tag), NULL, 0), 0);
        ExpectBufEQ(decrypted, plain, sz);
#endif
    }

    i = 0;
    for (sz = WC_AES_BLOCK_SIZE; sz <= GCM_LEN; sz *= 2) {
        XMEMSET(cipher, 0, GCM_LEN);
        ExpectIntEQ(wc_AesGcmEncrypt(&aes, cipher, plain, sz, iv, ivLen, tag,
            sizeof(tag), NULL, 0), 0);
        ExpectBufEQ(tag, expTagLong[i], WC_AES_BLOCK_SIZE);
        i++;

#ifdef HAVE_AES_DECRYPT
        XMEMSET(decrypted, 0xff, GCM_LEN);
        ExpectIntEQ(wc_AesGcmDecrypt(&aes, decrypted, cipher, sz, iv, ivLen,
            tag, sizeof(tag), NULL, 0), 0);
        ExpectBufEQ(decrypted, plain, sz);
#endif
    }

    wc_AesFree(&aes);
    WC_FREE_VAR(plain, NULL);
    WC_FREE_VAR(cipher, NULL);
#ifdef HAVE_AES_DECRYPT
    WC_FREE_VAR(decrypted, NULL);
#endif
#endif
    return EXPECT_RESULT();
}

/*
 * test function for wc_AesGcmEncrypt and wc_AesGcmDecrypt
 */
int test_wc_AesGcmEncryptDecrypt(void)
{
    EXPECT_DECLS;
    /* WOLFSSL_AFALG requires 12 byte IV */
#if !defined(NO_AES) && defined(HAVE_AESGCM) && defined(WOLFSSL_AES_256) && \
    !defined(WOLFSSL_AFALG) && !defined(WOLFSSL_DEVCRYPTO_AES)
    Aes  aes;
    byte key32[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    byte vector[] = { /* Now is the time for all w/o trailing 0 */
        0x4e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
        0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20
    };
    const byte a[] = {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xab, 0xad, 0xda, 0xd2
    };
    byte iv[] = "1234567890a";
    byte longIV[] = "1234567890abcdefghij";
    byte enc[sizeof(vector)];
    byte resultT[WC_AES_BLOCK_SIZE];
    byte dec[sizeof(vector)];

    /* Init stack variables. */
    XMEMSET(&aes, 0, sizeof(Aes));
    XMEMSET(enc, 0, sizeof(vector));
    XMEMSET(dec, 0, sizeof(vector));
    XMEMSET(resultT, 0, WC_AES_BLOCK_SIZE);

    ExpectIntEQ(wc_AesInit(&aes, NULL, INVALID_DEVID), 0);

    ExpectIntEQ(wc_AesGcmSetKey(&aes, key32, sizeof(key32)/sizeof(byte)), 0);
    ExpectIntEQ(wc_AesGcmEncrypt(&aes, enc, vector, sizeof(vector), iv,
        sizeof(iv)/sizeof(byte), resultT, sizeof(resultT), a, sizeof(a)), 0);
    ExpectIntEQ(wc_AesGcmDecrypt(&aes, dec, enc, sizeof(vector), iv,
        sizeof(iv)/sizeof(byte), resultT, sizeof(resultT), a, sizeof(a)), 0);
    ExpectIntEQ(XMEMCMP(vector, dec, sizeof(vector)), 0);

    /* Test bad args for wc_AesGcmEncrypt and wc_AesGcmDecrypt */
    ExpectIntEQ(wc_AesGcmEncrypt(NULL, enc, vector, sizeof(vector), iv,
        sizeof(iv)/sizeof(byte), resultT, sizeof(resultT), a, sizeof(a)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesGcmEncrypt(&aes, enc, vector, sizeof(vector), iv,
        sizeof(iv)/sizeof(byte), resultT, sizeof(resultT) + 1, a, sizeof(a)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesGcmEncrypt(&aes, enc, vector, sizeof(vector), iv,
        sizeof(iv)/sizeof(byte), resultT, sizeof(resultT) - 5, a, sizeof(a)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

#if (defined(HAVE_FIPS) && defined(HAVE_FIPS_VERSION) && \
        (HAVE_FIPS_VERSION == 2)) || defined(HAVE_SELFTEST) || \
        defined(WOLFSSL_AES_GCM_FIXED_IV_AAD)
        /* FIPS does not check the lower bound of ivSz */
#else
        ExpectIntEQ(wc_AesGcmEncrypt(&aes, enc, vector, sizeof(vector), iv, 0,
            resultT, sizeof(resultT), a, sizeof(a)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif

    /* This case is now considered good. Long IVs are now allowed.
     * Except for the original FIPS release, it still has an upper
     * bound on the IV length. */
#if (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2))) && \
    !defined(WOLFSSL_AES_GCM_FIXED_IV_AAD)
    ExpectIntEQ(wc_AesGcmEncrypt(&aes, enc, vector, sizeof(vector), longIV,
        sizeof(longIV)/sizeof(byte), resultT, sizeof(resultT), a, sizeof(a)),
        0);
#else
    (void)longIV;
#endif /* Old FIPS */
    /* END wc_AesGcmEncrypt */

#ifdef HAVE_AES_DECRYPT
    ExpectIntEQ(wc_AesGcmDecrypt(NULL, dec, enc, sizeof(enc)/sizeof(byte), iv,
        sizeof(iv)/sizeof(byte), resultT, sizeof(resultT), a, sizeof(a)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesGcmDecrypt(&aes, NULL, enc, sizeof(enc)/sizeof(byte), iv,
        sizeof(iv)/sizeof(byte), resultT, sizeof(resultT), a, sizeof(a)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesGcmDecrypt(&aes, dec, NULL, sizeof(enc)/sizeof(byte), iv,
        sizeof(iv)/sizeof(byte), resultT, sizeof(resultT), a, sizeof(a)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesGcmDecrypt(&aes, dec, enc, sizeof(enc)/sizeof(byte), NULL,
        sizeof(iv)/sizeof(byte), resultT, sizeof(resultT), a, sizeof(a)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesGcmDecrypt(&aes, dec, enc, sizeof(enc)/sizeof(byte), iv,
        sizeof(iv)/sizeof(byte), NULL, sizeof(resultT), a, sizeof(a)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    #if (defined(HAVE_FIPS) && FIPS_VERSION_LE(2,0) && defined(WOLFSSL_ARMASM))
    ExpectIntEQ(wc_AesGcmDecrypt(&aes, dec, enc, sizeof(enc)/sizeof(byte), iv,
        sizeof(iv)/sizeof(byte), resultT, sizeof(resultT) + 1, a, sizeof(a)),
        WC_NO_ERR_TRACE(AES_GCM_AUTH_E));
    #else
    ExpectIntEQ(wc_AesGcmDecrypt(&aes, dec, enc, sizeof(enc)/sizeof(byte), iv,
        sizeof(iv)/sizeof(byte), resultT, sizeof(resultT) + 1, a, sizeof(a)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    #endif
    #if ((defined(HAVE_FIPS) && defined(HAVE_FIPS_VERSION) && \
            (HAVE_FIPS_VERSION == 2)) || defined(HAVE_SELFTEST)) && \
            !defined(WOLFSSL_AES_GCM_FIXED_IV_AAD)
            /* FIPS does not check the lower bound of ivSz */
    #else
        ExpectIntEQ(wc_AesGcmDecrypt(&aes, dec, enc, sizeof(enc)/sizeof(byte),
            iv, 0, resultT, sizeof(resultT), a, sizeof(a)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    #endif
#endif /* HAVE_AES_DECRYPT */

    wc_AesFree(&aes);
#endif
    return EXPECT_RESULT();

} /* END test_wc_AesGcmEncryptDecrypt */

/*
 * test function for mixed (one-shot encryption + stream decryption) AES GCM
 * using a long IV (older FIPS does NOT support long IVs).  Relates to zd15423
 */
int test_wc_AesGcmMixedEncDecLongIV(void)
{
    EXPECT_DECLS;
#if  (!defined(HAVE_FIPS) || \
      (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2))) && \
     !defined(NO_AES) && defined(HAVE_AESGCM) && defined(WOLFSSL_AES_256) && \
     defined(WOLFSSL_AESGCM_STREAM)
    const byte key[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    const byte in[] = {
        0x4e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
        0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20
    };
    const byte aad[] = {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xab, 0xad, 0xda, 0xd2
    };
    Aes aesEnc;
    Aes aesDec;
    byte iv[] = "1234567890abcdefghij";
    byte out[sizeof(in)];
    byte plain[sizeof(in)];
    byte tag[WC_AES_BLOCK_SIZE];

    XMEMSET(&aesEnc, 0, sizeof(Aes));
    XMEMSET(&aesDec, 0, sizeof(Aes));
    XMEMSET(out, 0, sizeof(out));
    XMEMSET(plain, 0, sizeof(plain));
    XMEMSET(tag, 0, sizeof(tag));

    /* Perform one-shot encryption using long IV */
    ExpectIntEQ(wc_AesInit(&aesEnc, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_AesGcmSetKey(&aesEnc, key, sizeof(key)), 0);
    ExpectIntEQ(wc_AesGcmEncrypt(&aesEnc, out, in, sizeof(in), iv, sizeof(iv),
        tag, sizeof(tag), aad, sizeof(aad)), 0);

    /* Perform streaming decryption using long IV */
    ExpectIntEQ(wc_AesInit(&aesDec, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_AesGcmInit(&aesDec, key, sizeof(key), iv, sizeof(iv)), 0);
    ExpectIntEQ(wc_AesGcmDecryptUpdate(&aesDec, plain, out, sizeof(out), aad,
        sizeof(aad)), 0);
    ExpectIntEQ(wc_AesGcmDecryptFinal(&aesDec, tag, sizeof(tag)), 0);
    ExpectIntEQ(XMEMCMP(plain, in, sizeof(in)), 0);

    /* Free resources */
    wc_AesFree(&aesEnc);
    wc_AesFree(&aesDec);
#endif
    return EXPECT_RESULT();

} /* END wc_AesGcmMixedEncDecLongIV */

/*
 * Testing streaming AES-GCM API.
 */
int test_wc_AesGcmStream(void)
{
    EXPECT_DECLS;
#if !defined(NO_AES) && defined(WOLFSSL_AES_128) && defined(HAVE_AESGCM) && \
    defined(WOLFSSL_AESGCM_STREAM)
    int i;
    WC_RNG rng[1];
    Aes aesEnc[1];
    Aes aesDec[1];
    byte tag[WC_AES_BLOCK_SIZE];
    byte in[WC_AES_BLOCK_SIZE * 3 + 2] = { 0, };
    byte out[WC_AES_BLOCK_SIZE * 3 + 2];
    byte plain[WC_AES_BLOCK_SIZE * 3 + 2];
    byte aad[WC_AES_BLOCK_SIZE * 3 + 2] = { 0, };
    byte key[AES_128_KEY_SIZE] = { 0, };
    byte iv[AES_IV_SIZE] = { 1, };
    byte ivOut[AES_IV_SIZE];
    static const byte expTagAAD1[WC_AES_BLOCK_SIZE] = {
        0x6c, 0x35, 0xe6, 0x7f, 0x59, 0x9e, 0xa9, 0x2f,
        0x27, 0x2d, 0x5f, 0x8e, 0x7e, 0x42, 0xd3, 0x05
    };
    static const byte expTagPlain1[WC_AES_BLOCK_SIZE] = {
        0x24, 0xba, 0x57, 0x95, 0xd0, 0x27, 0x9e, 0x78,
        0x3a, 0x88, 0x4c, 0x0a, 0x5d, 0x50, 0x23, 0xd1
    };
    static const byte expTag[WC_AES_BLOCK_SIZE] = {
        0x22, 0x91, 0x70, 0xad, 0x42, 0xc3, 0xad, 0x96,
        0xe0, 0x31, 0x57, 0x60, 0xb7, 0x92, 0xa3, 0x6d
    };

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(&aesEnc, 0, sizeof(Aes));
    XMEMSET(&aesDec, 0, sizeof(Aes));

    /* Create a random for generating IV/nonce. */
    ExpectIntEQ(wc_InitRng(rng), 0);

    /* Initialize data structures. */
    ExpectIntEQ(wc_AesInit(aesEnc, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_AesInit(aesDec, NULL, INVALID_DEVID), 0);

    /* BadParameters to streaming init. */
    ExpectIntEQ(wc_AesGcmEncryptInit(NULL, NULL, 0, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesGcmDecryptInit(NULL, NULL, 0, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesGcmDecryptInit(aesEnc, NULL, AES_128_KEY_SIZE, NULL,
        0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesGcmDecryptInit(aesEnc, NULL, 0, NULL, GCM_NONCE_MID_SZ),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Bad parameters to encrypt update. */
    ExpectIntEQ(wc_AesGcmEncryptUpdate(NULL, NULL, NULL, 0, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesGcmEncryptUpdate(aesEnc, NULL, NULL, 1, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesGcmEncryptUpdate(aesEnc, NULL, in, 1, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesGcmEncryptUpdate(aesEnc, out, NULL, 1, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesGcmEncryptUpdate(aesEnc, NULL, NULL, 0, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Bad parameters to decrypt update. */
    ExpectIntEQ(wc_AesGcmDecryptUpdate(NULL, NULL, NULL, 0, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesGcmDecryptUpdate(aesDec, NULL, NULL, 1, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesGcmDecryptUpdate(aesDec, NULL, in, 1, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesGcmDecryptUpdate(aesDec, out, NULL, 1, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesGcmDecryptUpdate(aesDec, NULL, NULL, 0, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Bad parameters to encrypt final. */
    ExpectIntEQ(wc_AesGcmEncryptFinal(NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesGcmEncryptFinal(NULL, tag, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesGcmEncryptFinal(NULL, NULL, WC_AES_BLOCK_SIZE),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesGcmEncryptFinal(aesEnc, tag, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesGcmEncryptFinal(aesEnc, NULL, WC_AES_BLOCK_SIZE),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesGcmEncryptFinal(aesEnc, tag, WC_AES_BLOCK_SIZE + 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Bad parameters to decrypt final. */
    ExpectIntEQ(wc_AesGcmDecryptFinal(NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesGcmDecryptFinal(NULL, tag, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesGcmDecryptFinal(NULL, NULL, WC_AES_BLOCK_SIZE),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesGcmDecryptFinal(aesDec, tag, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesGcmDecryptFinal(aesDec, NULL, WC_AES_BLOCK_SIZE),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesGcmDecryptFinal(aesDec, tag, WC_AES_BLOCK_SIZE + 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Check calling final before setting key fails. */
    ExpectIntEQ(wc_AesGcmEncryptFinal(aesEnc, tag, sizeof(tag)),
        WC_NO_ERR_TRACE(MISSING_KEY));
    ExpectIntEQ(wc_AesGcmEncryptFinal(aesDec, tag, sizeof(tag)),
        WC_NO_ERR_TRACE(MISSING_KEY));
    /* Check calling update before setting key else fails. */
    ExpectIntEQ(wc_AesGcmEncryptUpdate(aesEnc, NULL, NULL, 0, aad, 1),
        WC_NO_ERR_TRACE(MISSING_KEY));
    ExpectIntEQ(wc_AesGcmDecryptUpdate(aesDec, NULL, NULL, 0, aad, 1),
        WC_NO_ERR_TRACE(MISSING_KEY));

    /* Set key but not IV. */
    ExpectIntEQ(wc_AesGcmInit(aesEnc, key, sizeof(key), NULL, 0), 0);
    ExpectIntEQ(wc_AesGcmInit(aesDec, key, sizeof(key), NULL, 0), 0);
    /* Check calling final before setting IV fails. */
    ExpectIntEQ(wc_AesGcmEncryptFinal(aesEnc, tag, sizeof(tag)),
        WC_NO_ERR_TRACE(MISSING_IV));
    ExpectIntEQ(wc_AesGcmEncryptFinal(aesDec, tag, sizeof(tag)),
        WC_NO_ERR_TRACE(MISSING_IV));
    /* Check calling update before setting IV else fails. */
    ExpectIntEQ(wc_AesGcmEncryptUpdate(aesEnc, NULL, NULL, 0, aad, 1),
        WC_NO_ERR_TRACE(MISSING_IV));
    ExpectIntEQ(wc_AesGcmDecryptUpdate(aesDec, NULL, NULL, 0, aad, 1),
        WC_NO_ERR_TRACE(MISSING_IV));

    /* Set IV using fixed part IV and external IV APIs. */
    ExpectIntEQ(wc_AesGcmSetIV(aesEnc, GCM_NONCE_MID_SZ, iv, AES_IV_FIXED_SZ,
        rng), 0);
    ExpectIntEQ(wc_AesGcmEncryptInit_ex(aesEnc, NULL, 0, ivOut,
        GCM_NONCE_MID_SZ), 0);
    ExpectIntEQ(wc_AesGcmSetExtIV(aesDec, ivOut, GCM_NONCE_MID_SZ), 0);
    ExpectIntEQ(wc_AesGcmInit(aesDec, NULL, 0, NULL, 0), 0);
    /* Encrypt and decrypt data. */
    ExpectIntEQ(wc_AesGcmEncryptUpdate(aesEnc, out, in, 1, aad, 1), 0);
    ExpectIntEQ(wc_AesGcmDecryptUpdate(aesDec, plain, out, 1, aad, 1), 0);
    ExpectIntEQ(XMEMCMP(plain, in, 1), 0);
    /* Finalize and check tag matches. */
    ExpectIntEQ(wc_AesGcmEncryptFinal(aesEnc, tag, WC_AES_BLOCK_SIZE), 0);
    ExpectIntEQ(wc_AesGcmDecryptFinal(aesDec, tag, WC_AES_BLOCK_SIZE), 0);

    /* Set key and IV through streaming init API. */
    wc_AesFree(aesEnc);
    wc_AesFree(aesDec);
    ExpectIntEQ(wc_AesInit(aesEnc, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_AesInit(aesDec, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_AesGcmInit(aesEnc, key, sizeof(key), iv, AES_IV_SIZE), 0);
    ExpectIntEQ(wc_AesGcmInit(aesDec, key, sizeof(key), iv, AES_IV_SIZE), 0);
    /* Encrypt/decrypt one block and AAD of one block. */
    ExpectIntEQ(wc_AesGcmEncryptUpdate(aesEnc, out, in, WC_AES_BLOCK_SIZE, aad,
        WC_AES_BLOCK_SIZE), 0);
    ExpectIntEQ(wc_AesGcmDecryptUpdate(aesDec, plain, out, WC_AES_BLOCK_SIZE,
        aad, WC_AES_BLOCK_SIZE), 0);
    ExpectIntEQ(XMEMCMP(plain, in, WC_AES_BLOCK_SIZE), 0);
    /* Finalize and check tag matches. */
    ExpectIntEQ(wc_AesGcmEncryptFinal(aesEnc, tag, WC_AES_BLOCK_SIZE), 0);
    ExpectIntEQ(wc_AesGcmDecryptFinal(aesDec, tag, WC_AES_BLOCK_SIZE), 0);

    /* Set key and IV through streaming init API. */
    wc_AesFree(aesEnc);
    wc_AesFree(aesDec);
    ExpectIntEQ(wc_AesInit(aesEnc, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_AesInit(aesDec, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_AesGcmInit(aesEnc, key, sizeof(key), iv, AES_IV_SIZE), 0);
    ExpectIntEQ(wc_AesGcmInit(aesDec, key, sizeof(key), iv, AES_IV_SIZE), 0);
    /* No data to encrypt/decrypt one byte of AAD. */
    ExpectIntEQ(wc_AesGcmEncryptUpdate(aesEnc, NULL, NULL, 0, aad, 1), 0);
    ExpectIntEQ(wc_AesGcmDecryptUpdate(aesDec, NULL, NULL, 0, aad, 1), 0);
    /* Finalize and check tag matches. */
    ExpectIntEQ(wc_AesGcmEncryptFinal(aesEnc, tag, WC_AES_BLOCK_SIZE), 0);
    ExpectIntEQ(XMEMCMP(tag, expTagAAD1, WC_AES_BLOCK_SIZE), 0);
    ExpectIntEQ(wc_AesGcmDecryptFinal(aesDec, tag, WC_AES_BLOCK_SIZE), 0);

    /* Set key and IV through streaming init API. */
    wc_AesFree(aesEnc);
    wc_AesFree(aesDec);
    ExpectIntEQ(wc_AesInit(aesEnc, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_AesInit(aesDec, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_AesGcmInit(aesEnc, key, sizeof(key), iv, AES_IV_SIZE), 0);
    ExpectIntEQ(wc_AesGcmInit(aesDec, key, sizeof(key), iv, AES_IV_SIZE), 0);
    /* Encrypt/decrypt one byte and no AAD. */
    ExpectIntEQ(wc_AesGcmEncryptUpdate(aesEnc, out, in, 1, NULL, 0), 0);
    ExpectIntEQ(wc_AesGcmDecryptUpdate(aesDec, plain, out, 1, NULL, 0), 0);
    ExpectIntEQ(XMEMCMP(plain, in, 1), 0);
    /* Finalize and check tag matches. */
    ExpectIntEQ(wc_AesGcmEncryptFinal(aesEnc, tag, WC_AES_BLOCK_SIZE), 0);
    ExpectIntEQ(XMEMCMP(tag, expTagPlain1, WC_AES_BLOCK_SIZE), 0);
    ExpectIntEQ(wc_AesGcmDecryptFinal(aesDec, tag, WC_AES_BLOCK_SIZE), 0);

    /* Set key and IV through streaming init API. */
    wc_AesFree(aesEnc);
    wc_AesFree(aesDec);
    ExpectIntEQ(wc_AesInit(aesEnc, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_AesInit(aesDec, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_AesGcmInit(aesEnc, key, sizeof(key), iv, AES_IV_SIZE), 0);
    ExpectIntEQ(wc_AesGcmInit(aesDec, key, sizeof(key), iv, AES_IV_SIZE), 0);
    /* Encryption AES is one byte at a time */
    for (i = 0; i < (int)sizeof(aad); i++) {
        ExpectIntEQ(wc_AesGcmEncryptUpdate(aesEnc, NULL, NULL, 0, aad + i, 1),
            0);
    }
    for (i = 0; i < (int)sizeof(in); i++) {
        ExpectIntEQ(wc_AesGcmEncryptUpdate(aesEnc, out + i, in + i, 1, NULL, 0),
            0);
    }
    /* Decryption AES is two bytes at a time */
    for (i = 0; i < (int)sizeof(aad); i += 2) {
        ExpectIntEQ(wc_AesGcmDecryptUpdate(aesDec, NULL, NULL, 0, aad + i, 2),
            0);
    }
    for (i = 0; i < (int)sizeof(aad); i += 2) {
        ExpectIntEQ(wc_AesGcmDecryptUpdate(aesDec, plain + i, out + i, 2, NULL,
            0), 0);
    }
    ExpectIntEQ(XMEMCMP(plain, in, sizeof(in)), 0);
    /* Finalize and check tag matches. */
    ExpectIntEQ(wc_AesGcmEncryptFinal(aesEnc, tag, WC_AES_BLOCK_SIZE), 0);
    ExpectIntEQ(XMEMCMP(tag, expTag, WC_AES_BLOCK_SIZE), 0);
    ExpectIntEQ(wc_AesGcmDecryptFinal(aesDec, tag, WC_AES_BLOCK_SIZE), 0);

    /* Check streaming encryption can be decrypted with one shot. */
    wc_AesFree(aesDec);
    ExpectIntEQ(wc_AesInit(aesDec, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_AesGcmInit(aesDec, key, sizeof(key), iv, AES_IV_SIZE), 0);
    ExpectIntEQ(wc_AesGcmSetKey(aesDec, key, sizeof(key)), 0);
    ExpectIntEQ(wc_AesGcmDecrypt(aesDec, plain, out, sizeof(in), iv,
        AES_IV_SIZE, tag, WC_AES_BLOCK_SIZE, aad, sizeof(aad)), 0);
    ExpectIntEQ(XMEMCMP(plain, in, sizeof(in)), 0);

    wc_AesFree(aesEnc);
    wc_AesFree(aesDec);
    wc_FreeRng(rng);
#endif
    return EXPECT_RESULT();
} /* END test_wc_AesGcmStream */

/*******************************************************************************
 * GMAC
 ******************************************************************************/

/*
 * unit test for wc_GmacSetKey()
 */
int test_wc_GmacSetKey(void)
{
    EXPECT_DECLS;
#if !defined(NO_AES) && defined(HAVE_AESGCM)
    Gmac gmac;
    byte key16[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
#ifdef WOLFSSL_AES_192
    byte key24[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
    };
#endif
#ifdef WOLFSSL_AES_256
    byte key32[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
#endif
    byte badKey16[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x66
    };
    byte badKey24[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
    };
    byte badKey32[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };

    XMEMSET(&gmac, 0, sizeof(Gmac));

    ExpectIntEQ(wc_AesInit(&gmac.aes, NULL, INVALID_DEVID), 0);

#ifdef WOLFSSL_AES_128
    ExpectIntEQ(wc_GmacSetKey(&gmac, key16, sizeof(key16)/sizeof(byte)), 0);
#endif
#ifdef WOLFSSL_AES_192
    ExpectIntEQ(wc_GmacSetKey(&gmac, key24, sizeof(key24)/sizeof(byte)), 0);
#endif
#ifdef WOLFSSL_AES_256
    ExpectIntEQ(wc_GmacSetKey(&gmac, key32, sizeof(key32)/sizeof(byte)), 0);
#endif

    /* Pass in bad args. */
    ExpectIntEQ(wc_GmacSetKey(NULL, key16, sizeof(key16)/sizeof(byte)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_GmacSetKey(&gmac, NULL, sizeof(key16)/sizeof(byte)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_GmacSetKey(&gmac, badKey16, sizeof(badKey16)/sizeof(byte)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_GmacSetKey(&gmac, badKey24, sizeof(badKey24)/sizeof(byte)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_GmacSetKey(&gmac, badKey32, sizeof(badKey32)/sizeof(byte)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_AesFree(&gmac.aes);
#endif
    return EXPECT_RESULT();
} /* END test_wc_GmacSetKey */

/*
 * unit test for wc_GmacUpdate
 */
int test_wc_GmacUpdate(void)
{
    EXPECT_DECLS;
#if !defined(NO_AES) && defined(HAVE_AESGCM)
    Gmac gmac;
#ifdef WOLFSSL_AES_128
    const byte key16[] = {
        0x89, 0xc9, 0x49, 0xe9, 0xc8, 0x04, 0xaf, 0x01,
        0x4d, 0x56, 0x04, 0xb3, 0x94, 0x59, 0xf2, 0xc8
    };
#endif
#ifdef WOLFSSL_AES_192
    byte key24[] = {
        0x41, 0xc5, 0xda, 0x86, 0x67, 0xef, 0x72, 0x52,
        0x20, 0xff, 0xe3, 0x9a, 0xe0, 0xac, 0x59, 0x0a,
        0xc9, 0xfc, 0xa7, 0x29, 0xab, 0x60, 0xad, 0xa0
    };
#endif
#ifdef WOLFSSL_AES_256
   byte key32[] = {
        0x78, 0xdc, 0x4e, 0x0a, 0xaf, 0x52, 0xd9, 0x35,
        0xc3, 0xc0, 0x1e, 0xea, 0x57, 0x42, 0x8f, 0x00,
        0xca, 0x1f, 0xd4, 0x75, 0xf5, 0xda, 0x86, 0xa4,
        0x9c, 0x8d, 0xd7, 0x3d, 0x68, 0xc8, 0xe2, 0x23
    };
#endif
#ifdef WOLFSSL_AES_128
    const byte authIn[] = {
        0x82, 0xad, 0xcd, 0x63, 0x8d, 0x3f, 0xa9, 0xd9,
        0xf3, 0xe8, 0x41, 0x00, 0xd6, 0x1e, 0x07, 0x77
    };
#endif
#ifdef WOLFSSL_AES_192
    const byte authIn2[] = {
       0x8b, 0x5c, 0x12, 0x4b, 0xef, 0x6e, 0x2f, 0x0f,
       0xe4, 0xd8, 0xc9, 0x5c, 0xd5, 0xfa, 0x4c, 0xf1
    };
#endif
    const byte authIn3[] = {
        0xb9, 0x6b, 0xaa, 0x8c, 0x1c, 0x75, 0xa6, 0x71,
        0xbf, 0xb2, 0xd0, 0x8d, 0x06, 0xbe, 0x5f, 0x36
    };
#ifdef WOLFSSL_AES_128
    const byte tag1[] = { /* Known. */
        0x88, 0xdb, 0x9d, 0x62, 0x17, 0x2e, 0xd0, 0x43,
        0xaa, 0x10, 0xf1, 0x6d, 0x22, 0x7d, 0xc4, 0x1b
    };
#endif
#ifdef WOLFSSL_AES_192
    const byte tag2[] = { /* Known */
        0x20, 0x4b, 0xdb, 0x1b, 0xd6, 0x21, 0x54, 0xbf,
        0x08, 0x92, 0x2a, 0xaa, 0x54, 0xee, 0xd7, 0x05
    };
#endif
    const byte tag3[] = { /* Known */
        0x3e, 0x5d, 0x48, 0x6a, 0xa2, 0xe3, 0x0b, 0x22,
        0xe0, 0x40, 0xb8, 0x57, 0x23, 0xa0, 0x6e, 0x76
    };
#ifdef WOLFSSL_AES_128
    const byte iv[] = {
        0xd1, 0xb1, 0x04, 0xc8, 0x15, 0xbf, 0x1e, 0x94,
        0xe2, 0x8c, 0x8f, 0x16
    };
#endif
#ifdef WOLFSSL_AES_192
    const byte iv2[] = {
        0x05, 0xad, 0x13, 0xa5, 0xe2, 0xc2, 0xab, 0x66,
        0x7e, 0x1a, 0x6f, 0xbc
    };
#endif
    const byte iv3[] = {
        0xd7, 0x9c, 0xf2, 0x2d, 0x50, 0x4c, 0xc7, 0x93,
        0xc3, 0xfb, 0x6c, 0x8a
    };
    byte tagOut[16];
    byte tagOut2[24];
    byte tagOut3[32];

    /* Init stack variables. */
    XMEMSET(&gmac, 0, sizeof(Gmac));
    XMEMSET(tagOut, 0, sizeof(tagOut));
    XMEMSET(tagOut2, 0, sizeof(tagOut2));
    XMEMSET(tagOut3, 0, sizeof(tagOut3));

#ifdef WOLFSSL_AES_128
    ExpectIntEQ(wc_AesInit(&gmac.aes, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_GmacSetKey(&gmac, key16, sizeof(key16)), 0);
    ExpectIntEQ(wc_GmacUpdate(&gmac, iv, sizeof(iv), authIn, sizeof(authIn),
        tagOut, sizeof(tag1)), 0);
    ExpectIntEQ(XMEMCMP(tag1, tagOut, sizeof(tag1)), 0);
    wc_AesFree(&gmac.aes);
#endif

#ifdef WOLFSSL_AES_192
    ExpectNotNull(XMEMSET(&gmac, 0, sizeof(Gmac)));
    ExpectIntEQ(wc_AesInit(&gmac.aes, HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_GmacSetKey(&gmac, key24, sizeof(key24)/sizeof(byte)), 0);
    ExpectIntEQ(wc_GmacUpdate(&gmac, iv2, sizeof(iv2), authIn2, sizeof(authIn2),
        tagOut2, sizeof(tag2)), 0);
    ExpectIntEQ(XMEMCMP(tagOut2, tag2, sizeof(tag2)), 0);
    wc_AesFree(&gmac.aes);
#endif

#ifdef WOLFSSL_AES_256
    ExpectNotNull(XMEMSET(&gmac, 0, sizeof(Gmac)));
    ExpectIntEQ(wc_AesInit(&gmac.aes, HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_GmacSetKey(&gmac, key32, sizeof(key32)/sizeof(byte)), 0);
    ExpectIntEQ(wc_GmacUpdate(&gmac, iv3, sizeof(iv3), authIn3, sizeof(authIn3),
        tagOut3, sizeof(tag3)), 0);
    ExpectIntEQ(XMEMCMP(tag3, tagOut3, sizeof(tag3)), 0);
    wc_AesFree(&gmac.aes);
#endif

    /* Pass bad args. */
    ExpectIntEQ(wc_AesInit(&gmac.aes, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_GmacUpdate(NULL, iv3, sizeof(iv3), authIn3, sizeof(authIn3),
        tagOut3, sizeof(tag3)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_GmacUpdate(&gmac, iv3, sizeof(iv3), authIn3, sizeof(authIn3),
        tagOut3, sizeof(tag3) - 5), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_GmacUpdate(&gmac, iv3, sizeof(iv3), authIn3, sizeof(authIn3),
        tagOut3, sizeof(tag3) + 1),  WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    wc_AesFree(&gmac.aes);

#endif
    return EXPECT_RESULT();
} /* END test_wc_GmacUpdate */

/*******************************************************************************
 * AES-CCM
 ******************************************************************************/

/*
 * unit test for wc_AesCcmSetKey
 */
int test_wc_AesCcmSetKey(void)
{
    EXPECT_DECLS;
#ifdef HAVE_AESCCM
    Aes aes;
    const byte key16[] = {
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf
    };
    const byte key24[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
    };
    const byte key32[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };

    XMEMSET(&aes, 0, sizeof(Aes));

    ExpectIntEQ(wc_AesInit(&aes, NULL, INVALID_DEVID), 0);

#ifdef WOLFSSL_AES_128
    ExpectIntEQ(wc_AesCcmSetKey(&aes, key16, sizeof(key16)), 0);
#endif
#ifdef WOLFSSL_AES_192
    ExpectIntEQ(wc_AesCcmSetKey(&aes, key24, sizeof(key24)), 0);
#endif
#ifdef WOLFSSL_AES_256
    ExpectIntEQ(wc_AesCcmSetKey(&aes, key32, sizeof(key32)), 0);
#endif

    /* Test bad args. */
   ExpectIntEQ(wc_AesCcmSetKey(&aes, key16, sizeof(key16) - 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
   ExpectIntEQ(wc_AesCcmSetKey(&aes, key24, sizeof(key24) - 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
   ExpectIntEQ(wc_AesCcmSetKey(&aes, key32, sizeof(key32) - 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_AesFree(&aes);
#endif
    return EXPECT_RESULT();

} /* END test_wc_AesCcmSetKey */

/*
 * Unit test function for wc_AesCcmEncrypt and wc_AesCcmDecrypt
 */
int test_wc_AesCcmEncryptDecrypt(void)
{
    EXPECT_DECLS;
#if defined(HAVE_AESCCM) && defined(WOLFSSL_AES_128)
    Aes aes;
    const byte key16[] = {
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf
    };
    /* plaintext */
    const byte plainT[] = {
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e
    };
    /* nonce */
    const byte iv[] = {
        0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0xa0,
        0xa1, 0xa2, 0xa3, 0xa4, 0xa5
    };
    const byte c[] = { /* cipher text. */
        0x58, 0x8c, 0x97, 0x9a, 0x61, 0xc6, 0x63, 0xd2,
        0xf0, 0x66, 0xd0, 0xc2, 0xc0, 0xf9, 0x89, 0x80,
        0x6d, 0x5f, 0x6b, 0x61, 0xda, 0xc3, 0x84
    };
    const byte t[] = { /* Auth tag */
        0x17, 0xe8, 0xd1, 0x2c, 0xfd, 0xf9, 0x26, 0xe0
    };
    const byte authIn[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };
    byte cipherOut[sizeof(plainT)];
    byte authTag[sizeof(t)];
#ifdef HAVE_AES_DECRYPT
    byte plainOut[sizeof(cipherOut)];
#endif

    XMEMSET(&aes, 0, sizeof(Aes));

    ExpectIntEQ(wc_AesInit(&aes, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_AesCcmSetKey(&aes, key16, sizeof(key16)), 0);

    ExpectIntEQ(wc_AesCcmEncrypt(&aes, cipherOut, plainT, sizeof(cipherOut),
        iv, sizeof(iv), authTag, sizeof(authTag), authIn , sizeof(authIn)), 0);
    ExpectIntEQ(XMEMCMP(cipherOut, c, sizeof(c)), 0);
    ExpectIntEQ(XMEMCMP(t, authTag, sizeof(t)), 0);
#ifdef HAVE_AES_DECRYPT
    ExpectIntEQ(wc_AesCcmDecrypt(&aes, plainOut, cipherOut, sizeof(plainOut),
        iv, sizeof(iv), authTag, sizeof(authTag), authIn, sizeof(authIn)), 0);
    ExpectIntEQ(XMEMCMP(plainOut, plainT, sizeof(plainT)), 0);
#endif

    /* Pass in bad args. Encrypt*/
    ExpectIntEQ(wc_AesCcmEncrypt(NULL, cipherOut, plainT, sizeof(cipherOut),
        iv, sizeof(iv), authTag, sizeof(authTag), authIn , sizeof(authIn)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCcmEncrypt(&aes, NULL, plainT, sizeof(cipherOut),
        iv, sizeof(iv), authTag, sizeof(authTag), authIn , sizeof(authIn)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCcmEncrypt(&aes, cipherOut, NULL, sizeof(cipherOut),
        iv, sizeof(iv), authTag, sizeof(authTag), authIn , sizeof(authIn)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCcmEncrypt(&aes, cipherOut, plainT, sizeof(cipherOut),
        NULL, sizeof(iv), authTag, sizeof(authTag), authIn , sizeof(authIn)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCcmEncrypt(&aes, cipherOut, plainT, sizeof(cipherOut),
        iv, sizeof(iv), NULL, sizeof(authTag), authIn , sizeof(authIn)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCcmEncrypt(&aes, cipherOut, plainT, sizeof(cipherOut),
        iv, sizeof(iv) + 1, authTag, sizeof(authTag), authIn , sizeof(authIn)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCcmEncrypt(&aes, cipherOut, plainT, sizeof(cipherOut),
        iv, sizeof(iv) - 7, authTag, sizeof(authTag), authIn , sizeof(authIn)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

#ifdef HAVE_AES_DECRYPT
    /* Pass in bad args. Decrypt*/
    ExpectIntEQ(wc_AesCcmDecrypt(NULL, plainOut, cipherOut, sizeof(plainOut),
        iv, sizeof(iv), authTag, sizeof(authTag), authIn, sizeof(authIn)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCcmDecrypt(&aes, NULL, cipherOut, sizeof(plainOut),
        iv, sizeof(iv), authTag, sizeof(authTag), authIn, sizeof(authIn)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCcmDecrypt(&aes, plainOut, NULL, sizeof(plainOut),
        iv, sizeof(iv), authTag, sizeof(authTag), authIn, sizeof(authIn)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCcmDecrypt(&aes, plainOut, cipherOut, sizeof(plainOut),
        NULL, sizeof(iv), authTag, sizeof(authTag), authIn, sizeof(authIn)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCcmDecrypt(&aes, plainOut, cipherOut, sizeof(plainOut),
        iv, sizeof(iv), NULL, sizeof(authTag), authIn, sizeof(authIn)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCcmDecrypt(&aes, plainOut, cipherOut, sizeof(plainOut),
        iv, sizeof(iv) + 1, authTag, sizeof(authTag), authIn, sizeof(authIn)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCcmDecrypt(&aes, plainOut, cipherOut, sizeof(plainOut),
        iv, sizeof(iv) - 7, authTag, sizeof(authTag), authIn, sizeof(authIn)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    #endif

    wc_AesFree(&aes);
#endif  /* HAVE_AESCCM */
    return EXPECT_RESULT();
} /* END test_wc_AesCcmEncryptDecrypt */

#if defined(WOLFSSL_AES_EAX) && defined(WOLFSSL_AES_256) && \
    (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5, 3)) && !defined(HAVE_SELFTEST)

/*******************************************************************************
 * AES-EAX
 ******************************************************************************/

/*
 * Testing test_wc_AesEaxVectors()
 */
int test_wc_AesEaxVectors(void)
{
    EXPECT_DECLS;

    typedef struct {
        byte key[AES_256_KEY_SIZE];
        int key_length;
        byte iv[WC_AES_BLOCK_SIZE];
        int iv_length;
        byte aad[WC_AES_BLOCK_SIZE * 2];
        int aad_length;
        byte msg[WC_AES_BLOCK_SIZE * 5];
        int msg_length;
        byte ct[WC_AES_BLOCK_SIZE * 5];
        int ct_length;
        byte tag[WC_AES_BLOCK_SIZE];
        int tag_length;
        int valid;
    } AadVector;

    /*  Test vectors obtained from Google wycheproof project
     *  https://github.com/google/wycheproof
     *  from testvectors/aes_eax_test.json
     */
    const AadVector vectors[] = {
    #ifdef WOLFSSL_AES_128
        {
            /* key, key length  */
            {0x23, 0x39, 0x52, 0xde, 0xe4, 0xd5, 0xed, 0x5f,
             0x9b, 0x9c, 0x6d, 0x6f, 0xf8, 0x0f, 0xf4, 0x78}, 16,
            /* iv, iv length  */
            {0x62, 0xec, 0x67, 0xf9, 0xc3, 0xa4, 0xa4, 0x07,
             0xfc, 0xb2, 0xa8, 0xc4, 0x90, 0x31, 0xa8, 0xb3}, 16,
            /* aad, aad length  */
            {0x6b, 0xfb, 0x91, 0x4f, 0xd0, 0x7e, 0xae, 0x6b}, 8,
            /* msg, msg length  */
            {0x00}, 0,
            /* ct, ct length  */
            {0x00}, 0,
            /* tag, tag length  */
            {0xe0, 0x37, 0x83, 0x0e, 0x83, 0x89, 0xf2, 0x7b,
             0x02, 0x5a, 0x2d, 0x65, 0x27, 0xe7, 0x9d, 0x01}, 16,
            /* valid */
            1,
        },
        {
            /* key, key length  */
            {0x91, 0x94, 0x5d, 0x3f, 0x4d, 0xcb, 0xee, 0x0b,
             0xf4, 0x5e, 0xf5, 0x22, 0x55, 0xf0, 0x95, 0xa4}, 16,
            /* iv, iv length  */
            {0xbe, 0xca, 0xf0, 0x43, 0xb0, 0xa2, 0x3d, 0x84,
             0x31, 0x94, 0xba, 0x97, 0x2c, 0x66, 0xde, 0xbd}, 16,
            /* aad, aad length  */
            {0xfa, 0x3b, 0xfd, 0x48, 0x06, 0xeb, 0x53, 0xfa}, 8,
            /* msg, msg length  */
            {0xf7, 0xfb}, 2,
            /* ct, ct length  */
            {0x19, 0xdd}, 2,
            /* tag, tag length  */
            {0x5c, 0x4c, 0x93, 0x31, 0x04, 0x9d, 0x0b, 0xda,
             0xb0, 0x27, 0x74, 0x08, 0xf6, 0x79, 0x67, 0xe5}, 16,
            /* valid */
            1,
        },
        {
            /* key, key length  */
            {0x01, 0xf7, 0x4a, 0xd6, 0x40, 0x77, 0xf2, 0xe7,
             0x04, 0xc0, 0xf6, 0x0a, 0xda, 0x3d, 0xd5, 0x23}, 16,
            /* iv, iv length  */
            {0x70, 0xc3, 0xdb, 0x4f, 0x0d, 0x26, 0x36, 0x84,
             0x00, 0xa1, 0x0e, 0xd0, 0x5d, 0x2b, 0xff, 0x5e}, 16,
            /* aad, aad length  */
            {0x23, 0x4a, 0x34, 0x63, 0xc1, 0x26, 0x4a, 0xc6}, 8,
            /* msg, msg length  */
            {0x1a, 0x47, 0xcb, 0x49, 0x33}, 5,
            /* ct, ct length  */
            {0xd8, 0x51, 0xd5, 0xba, 0xe0}, 5,
            /* tag, tag length  */
            {0x3a, 0x59, 0xf2, 0x38, 0xa2, 0x3e, 0x39, 0x19,
             0x9d, 0xc9, 0x26, 0x66, 0x26, 0xc4, 0x0f, 0x80}, 16,
            /* valid */
            1,
        },
        {
            /* key, key length  */
            {0xd0, 0x7c, 0xf6, 0xcb, 0xb7, 0xf3, 0x13, 0xbd,
             0xde, 0x66, 0xb7, 0x27, 0xaf, 0xd3, 0xc5, 0xe8}, 16,
            /* iv, iv length  */
            {0x84, 0x08, 0xdf, 0xff, 0x3c, 0x1a, 0x2b, 0x12,
             0x92, 0xdc, 0x19, 0x9e, 0x46, 0xb7, 0xd6, 0x17}, 16,
            /* aad, aad length  */
            {0x33, 0xcc, 0xe2, 0xea, 0xbf, 0xf5, 0xa7, 0x9d}, 8,
            /* msg, msg length  */
            {0x48, 0x1c, 0x9e, 0x39, 0xb1}, 5,
            /* ct, ct length  */
            {0x63, 0x2a, 0x9d, 0x13, 0x1a}, 5,
            /* tag, tag length  */
            {0xd4, 0xc1, 0x68, 0xa4, 0x22, 0x5d, 0x8e, 0x1f,
             0xf7, 0x55, 0x93, 0x99, 0x74, 0xa7, 0xbe, 0xde}, 16,
            /* valid */
            1,
        },
        {
            /* key, key length  */
            {0x35, 0xb6, 0xd0, 0x58, 0x00, 0x05, 0xbb, 0xc1,
             0x2b, 0x05, 0x87, 0x12, 0x45, 0x57, 0xd2, 0xc2}, 16,
            /* iv, iv length  */
            {0xfd, 0xb6, 0xb0, 0x66, 0x76, 0xee, 0xdc, 0x5c,
             0x61, 0xd7, 0x42, 0x76, 0xe1, 0xf8, 0xe8, 0x16}, 16,
            /* aad, aad length  */
            {0xae, 0xb9, 0x6e, 0xae, 0xbe, 0x29, 0x70, 0xe9}, 8,
            /* msg, msg length  */
            {0x40, 0xd0, 0xc0, 0x7d, 0xa5, 0xe4}, 6,
            /* ct, ct length  */
            {0x07, 0x1d, 0xfe, 0x16, 0xc6, 0x75}, 6,
            /* tag, tag length  */
            {0xcb, 0x06, 0x77, 0xe5, 0x36, 0xf7, 0x3a, 0xfe,
             0x6a, 0x14, 0xb7, 0x4e, 0xe4, 0x98, 0x44, 0xdd}, 16,
            /* valid */
            1,
        },
        {
            /* key, key length  */
            {0xbd, 0x8e, 0x6e, 0x11, 0x47, 0x5e, 0x60, 0xb2,
             0x68, 0x78, 0x4c, 0x38, 0xc6, 0x2f, 0xeb, 0x22}, 16,
            /* iv, iv length  */
            {0x6e, 0xac, 0x5c, 0x93, 0x07, 0x2d, 0x8e, 0x85,
             0x13, 0xf7, 0x50, 0x93, 0x5e, 0x46, 0xda, 0x1b}, 16,
            /* aad, aad length  */
            {0xd4, 0x48, 0x2d, 0x1c, 0xa7, 0x8d, 0xce, 0x0f}, 8,
            /* msg, msg length  */
            {0x4d, 0xe3, 0xb3, 0x5c, 0x3f, 0xc0, 0x39, 0x24,
             0x5b, 0xd1, 0xfb, 0x7d}, 12,
            /* ct, ct length  */
            {0x83, 0x5b, 0xb4, 0xf1, 0x5d, 0x74, 0x3e, 0x35,
             0x0e, 0x72, 0x84, 0x14}, 12,
            /* tag, tag length  */
            {0xab, 0xb8, 0x64, 0x4f, 0xd6, 0xcc, 0xb8, 0x69,
             0x47, 0xc5, 0xe1, 0x05, 0x90, 0x21, 0x0a, 0x4f}, 16,
            /* valid */
            1,
        },
        {
            /* key, key length  */
            {0x7c, 0x77, 0xd6, 0xe8, 0x13, 0xbe, 0xd5, 0xac,
             0x98, 0xba, 0xa4, 0x17, 0x47, 0x7a, 0x2e, 0x7d}, 16,
            /* iv, iv length  */
            {0x1a, 0x8c, 0x98, 0xdc, 0xd7, 0x3d, 0x38, 0x39,
             0x3b, 0x2b, 0xf1, 0x56, 0x9d, 0xee, 0xfc, 0x19}, 16,
            /* aad, aad length  */
            {0x65, 0xd2, 0x01, 0x79, 0x90, 0xd6, 0x25, 0x28}, 8,
            /* msg, msg length  */
            {0x8b, 0x0a, 0x79, 0x30, 0x6c, 0x9c, 0xe7, 0xed,
             0x99, 0xda, 0xe4, 0xf8, 0x7f, 0x8d, 0xd6, 0x16,
             0x36}, 17,
            /* ct, ct length  */
            {0x02, 0x08, 0x3e, 0x39, 0x79, 0xda, 0x01, 0x48,
             0x12, 0xf5, 0x9f, 0x11, 0xd5, 0x26, 0x30, 0xda,
             0x30}, 17,
            /* tag, tag length  */
            {0x13, 0x73, 0x27, 0xd1, 0x06, 0x49, 0xb0, 0xaa,
             0x6e, 0x1c, 0x18, 0x1d, 0xb6, 0x17, 0xd7, 0xf2}, 16,
            /* valid */
            1,
        },
        {
            /* key, key length  */
            {0x5f, 0xff, 0x20, 0xca, 0xfa, 0xb1, 0x19, 0xca,
             0x2f, 0xc7, 0x35, 0x49, 0xe2, 0x0f, 0x5b, 0x0d}, 16,
            /* iv, iv length  */
            {0xdd, 0xe5, 0x9b, 0x97, 0xd7, 0x22, 0x15, 0x6d,
             0x4d, 0x9a, 0xff, 0x2b, 0xc7, 0x55, 0x98, 0x26}, 16,
            /* aad, aad length  */
            {0x54, 0xb9, 0xf0, 0x4e, 0x6a, 0x09, 0x18, 0x9a}, 8,
            /* msg, msg length  */
            {0x1b, 0xda, 0x12, 0x2b, 0xce, 0x8a, 0x8d, 0xba,
             0xf1, 0x87, 0x7d, 0x96, 0x2b, 0x85, 0x92, 0xdd,
             0x2d, 0x56}, 18,
            /* ct, ct length  */
            {0x2e, 0xc4, 0x7b, 0x2c, 0x49, 0x54, 0xa4, 0x89,
             0xaf, 0xc7, 0xba, 0x48, 0x97, 0xed, 0xcd, 0xae,
             0x8c, 0xc3}, 18,
            /* tag, tag length  */
            {0x3b, 0x60, 0x45, 0x05, 0x99, 0xbd, 0x02, 0xc9,
             0x63, 0x82, 0x90, 0x2a, 0xef, 0x7f, 0x83, 0x2a}, 16,
            /* valid */
            1,
        },
        {
            /* key, key length  */
            {0xa4, 0xa4, 0x78, 0x2b, 0xcf, 0xfd, 0x3e, 0xc5,
             0xe7, 0xef, 0x6d, 0x8c, 0x34, 0xa5, 0x61, 0x23}, 16,
            /* iv, iv length  */
            {0xb7, 0x81, 0xfc, 0xf2, 0xf7, 0x5f, 0xa5, 0xa8,
             0xde, 0x97, 0xa9, 0xca, 0x48, 0xe5, 0x22, 0xec}, 16,
            /* aad, aad length  */
            {0x89, 0x9a, 0x17, 0x58, 0x97, 0x56, 0x1d, 0x7e}, 8,
            /* msg, msg length  */
            {0x6c, 0xf3, 0x67, 0x20, 0x87, 0x2b, 0x85, 0x13,
             0xf6, 0xea, 0xb1, 0xa8, 0xa4, 0x44, 0x38, 0xd5,
             0xef, 0x11}, 18,
            /* ct, ct length  */
            {0x0d, 0xe1, 0x8f, 0xd0, 0xfd, 0xd9, 0x1e, 0x7a,
             0xf1, 0x9f, 0x1d, 0x8e, 0xe8, 0x73, 0x39, 0x38,
             0xb1, 0xe8}, 18,
            /* tag, tag length  */
            {0xe7, 0xf6, 0xd2, 0x23, 0x16, 0x18, 0x10, 0x2f,
             0xdb, 0x7f, 0xe5, 0x5f, 0xf1, 0x99, 0x17, 0x00}, 16,
            /* valid */
            1,
        },
        {
            /* key, key length  */
            {0x83, 0x95, 0xfc, 0xf1, 0xe9, 0x5b, 0xeb, 0xd6,
             0x97, 0xbd, 0x01, 0x0b, 0xc7, 0x66, 0xaa, 0xc3}, 16,
            /* iv, iv length  */
            {0x22, 0xe7, 0xad, 0xd9, 0x3c, 0xfc, 0x63, 0x93,
             0xc5, 0x7e, 0xc0, 0xb3, 0xc1, 0x7d, 0x6b, 0x44}, 16,
            /* aad, aad length  */
            {0x12, 0x67, 0x35, 0xfc, 0xc3, 0x20, 0xd2, 0x5a}, 8,
            /* msg, msg length  */
            {0xca, 0x40, 0xd7, 0x44, 0x6e, 0x54, 0x5f, 0xfa,
             0xed, 0x3b, 0xd1, 0x2a, 0x74, 0x0a, 0x65, 0x9f,
             0xfb, 0xbb, 0x3c, 0xea, 0xb7}, 21,
            /* ct, ct length  */
            {0xcb, 0x89, 0x20, 0xf8, 0x7a, 0x6c, 0x75, 0xcf,
             0xf3, 0x96, 0x27, 0xb5, 0x6e, 0x3e, 0xd1, 0x97,
             0xc5, 0x52, 0xd2, 0x95, 0xa7}, 21,
            /* tag, tag length  */
            {0xcf, 0xc4, 0x6a, 0xfc, 0x25, 0x3b, 0x46, 0x52,
             0xb1, 0xaf, 0x37, 0x95, 0xb1, 0x24, 0xab, 0x6e}, 16,
            /* valid */
            1,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0x3c, 0x8c, 0xc2, 0x97, 0x0a, 0x00, 0x8f, 0x75,
             0xcc, 0x5b, 0xea, 0xe2, 0x84, 0x72, 0x58, 0xc2}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
             0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}, 32,
            /* ct, ct length  */
            {0x3c, 0x44, 0x1f, 0x32, 0xce, 0x07, 0x82, 0x23,
             0x64, 0xd7, 0xa2, 0x99, 0x0e, 0x50, 0xbb, 0x13,
             0xd7, 0xb0, 0x2a, 0x26, 0x96, 0x9e, 0x4a, 0x93,
             0x7e, 0x5e, 0x90, 0x73, 0xb0, 0xd9, 0xc9, 0x68}, 32,
            /* tag, tag length  */
            {0xdb, 0x90, 0xbd, 0xb3, 0xda, 0x3d, 0x00, 0xaf,
             0xd0, 0xfc, 0x6a, 0x83, 0x55, 0x1d, 0xa9, 0x5e}, 16,
            /* valid */
            1,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0xae, 0xf0, 0x3d, 0x00, 0x59, 0x84, 0x94, 0xe9,
             0xfb, 0x03, 0xcd, 0x7d, 0x8b, 0x59, 0x08, 0x66}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
             0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}, 32,
            /* ct, ct length  */
            {0xd1, 0x9a, 0xc5, 0x98, 0x49, 0x02, 0x6a, 0x91,
             0xaa, 0x1b, 0x9a, 0xec, 0x29, 0xb1, 0x1a, 0x20,
             0x2a, 0x4d, 0x73, 0x9f, 0xd8, 0x6c, 0x28, 0xe3,
             0xae, 0x3d, 0x58, 0x8e, 0xa2, 0x1d, 0x70, 0xc6}, 32,
            /* tag, tag length  */
            {0xc3, 0x0f, 0x6c, 0xd9, 0x20, 0x20, 0x74, 0xed,
             0x6e, 0x2a, 0x2a, 0x36, 0x0e, 0xac, 0x8c, 0x47}, 16,
            /* valid */
            1,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0x55, 0xd1, 0x25, 0x11, 0xc6, 0x96, 0xa8, 0x0d,
             0x05, 0x14, 0xd1, 0xff, 0xba, 0x49, 0xca, 0xda}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
             0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}, 32,
            /* ct, ct length  */
            {0x21, 0x08, 0x55, 0x8a, 0xc4, 0xb2, 0xc2, 0xd5,
             0xcc, 0x66, 0xce, 0xa5, 0x1d, 0x62, 0x10, 0xe0,
             0x46, 0x17, 0x7a, 0x67, 0x63, 0x1c, 0xd2, 0xdd,
             0x8f, 0x09, 0x46, 0x97, 0x33, 0xac, 0xb5, 0x17}, 32,
            /* tag, tag length  */
            {0xfc, 0x35, 0x5e, 0x87, 0xa2, 0x67, 0xbe, 0x3a,
             0xe3, 0xe4, 0x4c, 0x0b, 0xf3, 0xf9, 0x9b, 0x2b}, 16,
            /* valid */
            1,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0x79, 0x42, 0x2d, 0xdd, 0x91, 0xc4, 0xee, 0xe2,
             0xde, 0xae, 0xf1, 0xf9, 0x68, 0x30, 0x53, 0x04}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
             0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}, 32,
            /* ct, ct length  */
            {0x4d, 0x2c, 0x15, 0x24, 0xca, 0x4b, 0xaa, 0x4e,
             0xef, 0xcc, 0xe6, 0xb9, 0x1b, 0x22, 0x7e, 0xe8,
             0x3a, 0xba, 0xff, 0x81, 0x05, 0xdc, 0xaf, 0xa2,
             0xab, 0x19, 0x1f, 0x5d, 0xf2, 0x57, 0x50, 0x35}, 32,
            /* tag, tag length  */
            {0xe2, 0xc8, 0x65, 0xce, 0x2d, 0x7a, 0xbd, 0xac,
             0x02, 0x4c, 0x6f, 0x99, 0x1a, 0x84, 0x83, 0x90}, 16,
            /* valid */
            1,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0x0a, 0xf5, 0xaa, 0x7a, 0x76, 0x76, 0xe2, 0x83,
             0x06, 0x30, 0x6b, 0xcd, 0x9b, 0xf2, 0x00, 0x3a}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
             0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}, 32,
            /* ct, ct length  */
            {0x8e, 0xb0, 0x1e, 0x62, 0x18, 0x5d, 0x78, 0x2e,
             0xb9, 0x28, 0x7a, 0x34, 0x1a, 0x68, 0x62, 0xac,
             0x52, 0x57, 0xd6, 0xf9, 0xad, 0xc9, 0x9e, 0xe0,
             0xa2, 0x4d, 0x9c, 0x22, 0xb3, 0xe9, 0xb3, 0x8a}, 32,
            /* tag, tag length  */
            {0x39, 0xc3, 0x39, 0xbc, 0x8a, 0x74, 0xc7, 0x5e,
             0x2c, 0x65, 0xc6, 0x11, 0x95, 0x44, 0xd6, 0x1e}, 16,
            /* valid */
            1,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0xaf, 0x5a, 0x03, 0xae, 0x7e, 0xdd, 0x73, 0x47,
             0x1b, 0xdc, 0xdf, 0xac, 0x5e, 0x19, 0x4a, 0x60}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
             0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}, 32,
            /* ct, ct length  */
            {0x94, 0xc5, 0xd2, 0xac, 0xa6, 0xdb, 0xbc, 0xe8,
             0xc2, 0x45, 0x13, 0xa2, 0x5e, 0x09, 0x5c, 0x0e,
             0x54, 0xa9, 0x42, 0x86, 0x0d, 0x32, 0x7a, 0x22,
             0x2a, 0x81, 0x5c, 0xc7, 0x13, 0xb1, 0x63, 0xb4}, 32,
            /* tag, tag length  */
            {0xf5, 0x0b, 0x30, 0x30, 0x4e, 0x45, 0xc9, 0xd4,
             0x11, 0xe8, 0xdf, 0x45, 0x08, 0xa9, 0x86, 0x12}, 16,
            /* valid */
            1,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0xb3, 0x70, 0x87, 0x68, 0x0f, 0x0e, 0xdd, 0x5a,
             0x52, 0x22, 0x8b, 0x8c, 0x7a, 0xae, 0xa6, 0x64}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
             0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
             0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
             0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
             0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
             0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33}, 64,
            /* ct, ct length  */
            {0x3b, 0xb6, 0x17, 0x3e, 0x37, 0x72, 0xd4, 0xb6,
             0x2e, 0xef, 0x37, 0xf9, 0xef, 0x07, 0x81, 0xf3,
             0x60, 0xb6, 0xc7, 0x4b, 0xe3, 0xbf, 0x6b, 0x37,
             0x10, 0x67, 0xbc, 0x1b, 0x09, 0x0d, 0x9d, 0x66,
             0x22, 0xa1, 0xfb, 0xec, 0x6a, 0xc4, 0x71, 0xb3,
             0x34, 0x9c, 0xd4, 0x27, 0x7a, 0x10, 0x1d, 0x40,
             0x89, 0x0f, 0xbf, 0x27, 0xdf, 0xdc, 0xd0, 0xb4,
             0xe3, 0x78, 0x1f, 0x98, 0x06, 0xda, 0xab, 0xb6}, 64,
            /* tag, tag length  */
            {0xa0, 0x49, 0x87, 0x45, 0xe5, 0x99, 0x99, 0xdd,
             0xc3, 0x2d, 0x5b, 0x14, 0x02, 0x41, 0x12, 0x4e}, 16,
            /* valid */
            1,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0x4f, 0x80, 0x2d, 0xa6, 0x2a, 0x38, 0x45, 0x55,
             0xa1, 0x9b, 0xc2, 0xb3, 0x82, 0xeb, 0x25, 0xaf}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
             0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
             0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
             0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
             0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
             0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
             0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
             0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44}, 80,
            /* ct, ct length  */
            {0xe9, 0xb0, 0xbb, 0x88, 0x57, 0x81, 0x8c, 0xe3,
             0x20, 0x1c, 0x36, 0x90, 0xd2, 0x1d, 0xaa, 0x7f,
             0x26, 0x4f, 0xb8, 0xee, 0x93, 0xcc, 0x7a, 0x46,
             0x74, 0xea, 0x2f, 0xc3, 0x2b, 0xf1, 0x82, 0xfb,
             0x2a, 0x7e, 0x8a, 0xd5, 0x15, 0x07, 0xad, 0x4f,
             0x31, 0xce, 0xfc, 0x23, 0x56, 0xfe, 0x79, 0x36,
             0xa7, 0xf6, 0xe1, 0x9f, 0x95, 0xe8, 0x8f, 0xdb,
             0xf1, 0x76, 0x20, 0x91, 0x6d, 0x3a, 0x6f, 0x3d,
             0x01, 0xfc, 0x17, 0xd3, 0x58, 0x67, 0x2f, 0x77,
             0x7f, 0xd4, 0x09, 0x92, 0x46, 0xe4, 0x36, 0xe1}, 80,
            /* tag, tag length  */
            {0x67, 0x91, 0x0b, 0xe7, 0x44, 0xb8, 0x31, 0x5a,
             0xe0, 0xeb, 0x61, 0x24, 0x59, 0x0c, 0x5d, 0x8b}, 16,
            /* valid */
            1,
        },
        {
            /* key, key length  */
            {0xb6, 0x7b, 0x1a, 0x6e, 0xfd, 0xd4, 0x0d, 0x37,
             0x08, 0x0f, 0xbe, 0x8f, 0x80, 0x47, 0xae, 0xb9}, 16,
            /* iv, iv length  */
            {0xfa, 0x29, 0x4b, 0x12, 0x99, 0x72, 0xf7, 0xfc,
             0x5b, 0xbd, 0x5b, 0x96, 0xbb, 0xa8, 0x37, 0xc9}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x00}, 0,
            /* ct, ct length  */
            {0x00}, 0,
            /* tag, tag length  */
            {0xb1, 0x4b, 0x64, 0xfb, 0x58, 0x98, 0x99, 0x69,
             0x95, 0x70, 0xcc, 0x91, 0x60, 0xe3, 0x98, 0x96}, 16,
            /* valid */
            1,
        },
        {
            /* key, key length  */
            {0x20, 0x9e, 0x6d, 0xbf, 0x2a, 0xd2, 0x6a, 0x10,
             0x54, 0x45, 0xfc, 0x02, 0x07, 0xcd, 0x9e, 0x9a}, 16,
            /* iv, iv length  */
            {0x94, 0x77, 0x84, 0x9d, 0x6c, 0xcd, 0xfc, 0xa1,
             0x12, 0xd9, 0x2e, 0x53, 0xfa, 0xe4, 0xa7, 0xca}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x01}, 1,
            /* ct, ct length  */
            {0x1d}, 1,
            /* tag, tag length  */
            {0x52, 0xa5, 0xf6, 0x00, 0xfe, 0x53, 0x38, 0x02,
             0x6a, 0x7c, 0xb0, 0x9c, 0x11, 0x64, 0x00, 0x82}, 16,
            /* valid */
            1,
        },
        {
            /* key, key length  */
            {0xa5, 0x49, 0x44, 0x2e, 0x35, 0x15, 0x40, 0x32,
             0xd0, 0x7c, 0x86, 0x66, 0x00, 0x6a, 0xa6, 0xa2}, 16,
            /* iv, iv length  */
            {0x51, 0x71, 0x52, 0x45, 0x68, 0xe8, 0x1d, 0x97,
             0xe8, 0xc4, 0xde, 0x4b, 0xa5, 0x6c, 0x10, 0xa0}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x11, 0x82, 0xe9, 0x35, 0x96, 0xca, 0xc5, 0x60,
             0x89, 0x46, 0x40, 0x0b, 0xc7, 0x3f, 0x3a}, 15,
            /* ct, ct length  */
            {0xd7, 0xb8, 0xa6, 0xb4, 0x3d, 0x2e, 0x9f, 0x98,
             0xc2, 0xb4, 0x4c, 0xe5, 0xe3, 0xcf, 0xdb}, 15,
            /* tag, tag length  */
            {0x1b, 0xdd, 0x52, 0xfc, 0x98, 0x7d, 0xaf, 0x0e,
             0xe1, 0x92, 0x34, 0xc9, 0x05, 0xea, 0x64, 0x5f}, 16,
            /* valid */
            1,
        },
        {
            /* key, key length  */
            {0x95, 0x8b, 0xcd, 0xb6, 0x6a, 0x39, 0x52, 0xb5,
             0x37, 0x01, 0x58, 0x2a, 0x68, 0xa0, 0xe4, 0x74}, 16,
            /* iv, iv length  */
            {0x0e, 0x6e, 0xc8, 0x79, 0xb0, 0x2c, 0x6f, 0x51,
             0x69, 0x76, 0xe3, 0x58, 0x98, 0x42, 0x8d, 0xa7}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x14, 0x04, 0x15, 0x82, 0x3e, 0xcc, 0x89, 0x32,
             0xa0, 0x58, 0x38, 0x4b, 0x73, 0x8e, 0xa6, 0xea,
             0x6d, 0x4d, 0xfe, 0x3b, 0xbe, 0xee}, 22,
            /* ct, ct length  */
            {0x73, 0xe5, 0xc6, 0xf0, 0xe7, 0x03, 0xa5, 0x2d,
             0x02, 0xf7, 0xf7, 0xfa, 0xeb, 0x1b, 0x77, 0xfd,
             0x4f, 0xd0, 0xcb, 0x42, 0x1e, 0xaf}, 22,
            /* tag, tag length  */
            {0x6c, 0x15, 0x4a, 0x85, 0x96, 0x8e, 0xdd, 0x74,
             0x77, 0x65, 0x75, 0xa4, 0x45, 0x0b, 0xd8, 0x97}, 16,
            /* valid */
            1,
        },
        {
            /* key, key length  */
            {0x96, 0x5b, 0x75, 0x7b, 0xa5, 0x01, 0x8a, 0x8d,
             0x66, 0xed, 0xc7, 0x8e, 0x0c, 0xee, 0xe8, 0x6b}, 16,
            /* iv, iv length  */
            {0x2e, 0x35, 0x90, 0x1a, 0xe7, 0xd4, 0x91, 0xee,
             0xcc, 0x88, 0x38, 0xfe, 0xdd, 0x63, 0x14, 0x05}, 16,
            /* aad, aad length  */
            {0xdf, 0x10, 0xd0, 0xd2, 0x12, 0x24, 0x24, 0x50}, 8,
            /* msg, msg length  */
            {0x36, 0xe5, 0x7a, 0x76, 0x39, 0x58, 0xb0, 0x2c,
             0xea, 0x9d, 0x6a, 0x67, 0x6e, 0xbc, 0xe8, 0x1f}, 16,
            /* ct, ct length  */
            {0x93, 0x6b, 0x69, 0xb6, 0xc9, 0x55, 0xad, 0xfd,
             0x15, 0x53, 0x9b, 0x9b, 0xe4, 0x98, 0x9c, 0xb6}, 16,
            /* tag, tag length  */
            {0xee, 0x15, 0xa1, 0x45, 0x4e, 0x88, 0xfa, 0xad,
             0x8e, 0x48, 0xa8, 0xdf, 0x29, 0x83, 0xb4, 0x25}, 16,
            /* valid */
            1,
        },
        {
            /* key, key length  */
            {0x88, 0xd0, 0x20, 0x33, 0x78, 0x1c, 0x7b, 0x41,
             0x64, 0x71, 0x1a, 0x05, 0x42, 0x0f, 0x25, 0x6e}, 16,
            /* iv, iv length  */
            {0x7f, 0x29, 0x85, 0x29, 0x63, 0x15, 0x50, 0x7a,
             0xa4, 0xc0, 0xa9, 0x3d, 0x5c, 0x12, 0xbd, 0x77}, 16,
            /* aad, aad length  */
            {0x7c, 0x57, 0x1d, 0x2f, 0xbb, 0x5f, 0x62, 0x52,
             0x3c, 0x0e, 0xb3, 0x38, 0xbe, 0xf9, 0xa9}, 15,
            /* msg, msg length  */
            {0xd9, 0x8a, 0xdc, 0x03, 0xd9, 0xd5, 0x82, 0x73,
             0x2e, 0xb0, 0x7d, 0xf2, 0x3d, 0x7b, 0x9f, 0x74}, 16,
            /* ct, ct length  */
            {0x67, 0xca, 0xac, 0x35, 0x44, 0x3a, 0x31, 0x38,
             0xd2, 0xcb, 0x81, 0x1f, 0x0c, 0xe0, 0x4d, 0xd2}, 16,
            /* tag, tag length  */
            {0xb7, 0x96, 0x8e, 0x0b, 0x56, 0x40, 0xe3, 0xb2,
             0x36, 0x56, 0x96, 0x53, 0x20, 0x8b, 0x9d, 0xeb}, 16,
            /* valid */
            1,
        },
        {
            /* key, key length  */
            {0x51, 0x58, 0x40, 0xcf, 0x67, 0xd2, 0xe4, 0x0e,
             0xb6, 0x5e, 0x54, 0xa2, 0x4c, 0x72, 0xcb, 0xf2}, 16,
            /* iv, iv length  */
            {0xbf, 0x47, 0xaf, 0xdf, 0xd4, 0x92, 0x13, 0x7a,
             0x24, 0x23, 0x6b, 0xc3, 0x67, 0x97, 0xa8, 0x8e}, 16,
            /* aad, aad length  */
            {0x16, 0x84, 0x3c, 0x09, 0x1d, 0x43, 0xb0, 0xa1,
             0x91, 0xd0, 0xc7, 0x3d, 0x15, 0x60, 0x1b, 0xe9}, 16,
            /* msg, msg length  */
            {0xc8, 0x34, 0x58, 0x8c, 0xb6, 0xda, 0xf9, 0xf0,
             0x6d, 0xd2, 0x35, 0x19, 0xf4, 0xbe, 0x9f, 0x56}, 16,
            /* ct, ct length  */
            {0x20, 0x0a, 0xc4, 0x51, 0xfb, 0xeb, 0x0f, 0x61,
             0x51, 0xd6, 0x15, 0x83, 0xa4, 0x3b, 0x73, 0x43}, 16,
            /* tag, tag length  */
            {0x2a, 0xd4, 0x3e, 0x4c, 0xaa, 0x51, 0x98, 0x3a,
             0x9d, 0x4d, 0x24, 0x48, 0x1b, 0xf4, 0xc8, 0x39}, 16,
            /* valid */
            1,
        },
        {
            /* key, key length  */
            {0x2e, 0x44, 0x92, 0xd4, 0x44, 0xe5, 0xb6, 0xf4,
             0xce, 0xc8, 0xc2, 0xd3, 0x61, 0x5a, 0xc8, 0x58}, 16,
            /* iv, iv length  */
            {0xd0, 0x2b, 0xf0, 0x76, 0x3a, 0x9f, 0xef, 0xbf,
             0x70, 0xc3, 0x3a, 0xee, 0x1e, 0x9d, 0xa1, 0xd6}, 16,
            /* aad, aad length  */
            {0x90, 0x4d, 0x86, 0xf1, 0x33, 0xce, 0xc1, 0x5a,
             0x0c, 0x3c, 0xaf, 0x14, 0xd7, 0xe0, 0x29, 0xc8,
             0x2a, 0x07, 0x70, 0x5a, 0x23, 0xf0, 0xd0, 0x80}, 24,
            /* msg, msg length  */
            {0x9e, 0x62, 0xd6, 0x51, 0x1b, 0x0b, 0xda, 0x7d,
             0xd7, 0x74, 0x0b, 0x61, 0x4d, 0x97, 0xba, 0xe0}, 16,
            /* ct, ct length  */
            {0x27, 0xc6, 0xe9, 0xa6, 0x53, 0xc5, 0x25, 0x3c,
             0xa1, 0xc5, 0x67, 0x3f, 0x97, 0xb9, 0xb3, 0x3e}, 16,
            /* tag, tag length  */
            {0x2d, 0x58, 0x12, 0x71, 0xe1, 0xfa, 0x9e, 0x36,
             0x86, 0x13, 0x6c, 0xaa, 0x8f, 0x4d, 0x6c, 0x8e}, 16,
            /* valid */
            1,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
             0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
             0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}, 16,
            /* ct, ct length  */
            {0x29, 0xa0, 0x91, 0x4f, 0xec, 0x4b, 0xef, 0x54,
             0xba, 0xbf, 0x66, 0x13, 0xa9, 0xf9, 0xcd, 0x70}, 16,
            /* tag, tag length  */
            {0xe7, 0x0e, 0x7c, 0x50, 0x13, 0xa6, 0xdb, 0xf2,
             0x52, 0x98, 0xb1, 0x92, 0x9b, 0xc3, 0x56, 0xa7}, 16,
            /* valid */
            0,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
             0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
             0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}, 16,
            /* ct, ct length  */
            {0x29, 0xa0, 0x91, 0x4f, 0xec, 0x4b, 0xef, 0x54,
             0xba, 0xbf, 0x66, 0x13, 0xa9, 0xf9, 0xcd, 0x70}, 16,
            /* tag, tag length  */
            {0xe4, 0x0e, 0x7c, 0x50, 0x13, 0xa6, 0xdb, 0xf2,
             0x52, 0x98, 0xb1, 0x92, 0x9b, 0xc3, 0x56, 0xa7}, 16,
            /* valid */
            0,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
             0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
             0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}, 16,
            /* ct, ct length  */
            {0x29, 0xa0, 0x91, 0x4f, 0xec, 0x4b, 0xef, 0x54,
             0xba, 0xbf, 0x66, 0x13, 0xa9, 0xf9, 0xcd, 0x70}, 16,
            /* tag, tag length  */
            {0x66, 0x0e, 0x7c, 0x50, 0x13, 0xa6, 0xdb, 0xf2,
             0x52, 0x98, 0xb1, 0x92, 0x9b, 0xc3, 0x56, 0xa7}, 16,
            /* valid */
            0,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
             0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
             0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}, 16,
            /* ct, ct length  */
            {0x29, 0xa0, 0x91, 0x4f, 0xec, 0x4b, 0xef, 0x54,
             0xba, 0xbf, 0x66, 0x13, 0xa9, 0xf9, 0xcd, 0x70}, 16,
            /* tag, tag length  */
            {0xe6, 0x0f, 0x7c, 0x50, 0x13, 0xa6, 0xdb, 0xf2,
             0x52, 0x98, 0xb1, 0x92, 0x9b, 0xc3, 0x56, 0xa7}, 16,
            /* valid */
            0,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
             0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
             0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}, 16,
            /* ct, ct length  */
            {0x29, 0xa0, 0x91, 0x4f, 0xec, 0x4b, 0xef, 0x54,
             0xba, 0xbf, 0x66, 0x13, 0xa9, 0xf9, 0xcd, 0x70}, 16,
            /* tag, tag length  */
            {0xe6, 0x0e, 0x7c, 0xd0, 0x13, 0xa6, 0xdb, 0xf2,
             0x52, 0x98, 0xb1, 0x92, 0x9b, 0xc3, 0x56, 0xa7}, 16,
            /* valid */
            0,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
             0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
             0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}, 16,
            /* ct, ct length  */
            {0x29, 0xa0, 0x91, 0x4f, 0xec, 0x4b, 0xef, 0x54,
             0xba, 0xbf, 0x66, 0x13, 0xa9, 0xf9, 0xcd, 0x70}, 16,
            /* tag, tag length  */
            {0xe6, 0x0e, 0x7c, 0x50, 0x12, 0xa6, 0xdb, 0xf2,
             0x52, 0x98, 0xb1, 0x92, 0x9b, 0xc3, 0x56, 0xa7}, 16,
            /* valid */
            0,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
             0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
             0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}, 16,
            /* ct, ct length  */
            {0x29, 0xa0, 0x91, 0x4f, 0xec, 0x4b, 0xef, 0x54,
             0xba, 0xbf, 0x66, 0x13, 0xa9, 0xf9, 0xcd, 0x70}, 16,
            /* tag, tag length  */
            {0xe6, 0x0e, 0x7c, 0x50, 0x11, 0xa6, 0xdb, 0xf2,
             0x52, 0x98, 0xb1, 0x92, 0x9b, 0xc3, 0x56, 0xa7}, 16,
            /* valid */
            0,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
             0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
             0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}, 16,
            /* ct, ct length  */
            {0x29, 0xa0, 0x91, 0x4f, 0xec, 0x4b, 0xef, 0x54,
             0xba, 0xbf, 0x66, 0x13, 0xa9, 0xf9, 0xcd, 0x70}, 16,
            /* tag, tag length  */
            {0xe6, 0x0e, 0x7c, 0x50, 0x13, 0xa6, 0xdb, 0x72,
             0x52, 0x98, 0xb1, 0x92, 0x9b, 0xc3, 0x56, 0xa7}, 16,
            /* valid */
            0,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
             0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
             0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}, 16,
            /* ct, ct length  */
            {0x29, 0xa0, 0x91, 0x4f, 0xec, 0x4b, 0xef, 0x54,
             0xba, 0xbf, 0x66, 0x13, 0xa9, 0xf9, 0xcd, 0x70}, 16,
            /* tag, tag length  */
            {0xe6, 0x0e, 0x7c, 0x50, 0x13, 0xa6, 0xdb, 0xf2,
             0x53, 0x98, 0xb1, 0x92, 0x9b, 0xc3, 0x56, 0xa7}, 16,
            /* valid */
            0,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
             0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
             0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}, 16,
            /* ct, ct length  */
            {0x29, 0xa0, 0x91, 0x4f, 0xec, 0x4b, 0xef, 0x54,
             0xba, 0xbf, 0x66, 0x13, 0xa9, 0xf9, 0xcd, 0x70}, 16,
            /* tag, tag length  */
            {0xe6, 0x0e, 0x7c, 0x50, 0x13, 0xa6, 0xdb, 0xf2,
             0xd2, 0x98, 0xb1, 0x92, 0x9b, 0xc3, 0x56, 0xa7}, 16,
            /* valid */
            0,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
             0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
             0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}, 16,
            /* ct, ct length  */
            {0x29, 0xa0, 0x91, 0x4f, 0xec, 0x4b, 0xef, 0x54,
             0xba, 0xbf, 0x66, 0x13, 0xa9, 0xf9, 0xcd, 0x70}, 16,
            /* tag, tag length  */
            {0xe6, 0x0e, 0x7c, 0x50, 0x13, 0xa6, 0xdb, 0xf2,
             0x52, 0xb8, 0xb1, 0x92, 0x9b, 0xc3, 0x56, 0xa7}, 16,
            /* valid */
            0,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
             0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
             0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}, 16,
            /* ct, ct length  */
            {0x29, 0xa0, 0x91, 0x4f, 0xec, 0x4b, 0xef, 0x54,
             0xba, 0xbf, 0x66, 0x13, 0xa9, 0xf9, 0xcd, 0x70}, 16,
            /* tag, tag length  */
            {0xe6, 0x0e, 0x7c, 0x50, 0x13, 0xa6, 0xdb, 0xf2,
             0x52, 0x98, 0xb0, 0x92, 0x9b, 0xc3, 0x56, 0xa7}, 16,
            /* valid */
            0,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
             0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
             0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}, 16,
            /* ct, ct length  */
            {0x29, 0xa0, 0x91, 0x4f, 0xec, 0x4b, 0xef, 0x54,
             0xba, 0xbf, 0x66, 0x13, 0xa9, 0xf9, 0xcd, 0x70}, 16,
            /* tag, tag length  */
            {0xe6, 0x0e, 0x7c, 0x50, 0x13, 0xa6, 0xdb, 0xf2,
             0x52, 0x98, 0xb1, 0x92, 0x9a, 0xc3, 0x56, 0xa7}, 16,
            /* valid */
            0,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
             0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
             0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}, 16,
            /* ct, ct length  */
            {0x29, 0xa0, 0x91, 0x4f, 0xec, 0x4b, 0xef, 0x54,
             0xba, 0xbf, 0x66, 0x13, 0xa9, 0xf9, 0xcd, 0x70}, 16,
            /* tag, tag length  */
            {0xe6, 0x0e, 0x7c, 0x50, 0x13, 0xa6, 0xdb, 0xf2,
             0x52, 0x98, 0xb1, 0x92, 0x99, 0xc3, 0x56, 0xa7}, 16,
            /* valid */
            0,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
             0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
             0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}, 16,
            /* ct, ct length  */
            {0x29, 0xa0, 0x91, 0x4f, 0xec, 0x4b, 0xef, 0x54,
             0xba, 0xbf, 0x66, 0x13, 0xa9, 0xf9, 0xcd, 0x70}, 16,
            /* tag, tag length  */
            {0xe6, 0x0e, 0x7c, 0x50, 0x13, 0xa6, 0xdb, 0xf2,
             0x52, 0x98, 0xb1, 0x92, 0x1b, 0xc3, 0x56, 0xa7}, 16,
            /* valid */
            0,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
             0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
             0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}, 16,
            /* ct, ct length  */
            {0x29, 0xa0, 0x91, 0x4f, 0xec, 0x4b, 0xef, 0x54,
             0xba, 0xbf, 0x66, 0x13, 0xa9, 0xf9, 0xcd, 0x70}, 16,
            /* tag, tag length  */
            {0xe6, 0x0e, 0x7c, 0x50, 0x13, 0xa6, 0xdb, 0xf2,
             0x52, 0x98, 0xb1, 0x92, 0x9b, 0xc3, 0x56, 0xa6}, 16,
            /* valid */
            0,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
             0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
             0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}, 16,
            /* ct, ct length  */
            {0x29, 0xa0, 0x91, 0x4f, 0xec, 0x4b, 0xef, 0x54,
             0xba, 0xbf, 0x66, 0x13, 0xa9, 0xf9, 0xcd, 0x70}, 16,
            /* tag, tag length  */
            {0xe6, 0x0e, 0x7c, 0x50, 0x13, 0xa6, 0xdb, 0xf2,
             0x52, 0x98, 0xb1, 0x92, 0x9b, 0xc3, 0x56, 0xa5}, 16,
            /* valid */
            0,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
             0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
             0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}, 16,
            /* ct, ct length  */
            {0x29, 0xa0, 0x91, 0x4f, 0xec, 0x4b, 0xef, 0x54,
             0xba, 0xbf, 0x66, 0x13, 0xa9, 0xf9, 0xcd, 0x70}, 16,
            /* tag, tag length  */
            {0xe6, 0x0e, 0x7c, 0x50, 0x13, 0xa6, 0xdb, 0xf2,
             0x52, 0x98, 0xb1, 0x92, 0x9b, 0xc3, 0x56, 0xe7}, 16,
            /* valid */
            0,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
             0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
             0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}, 16,
            /* ct, ct length  */
            {0x29, 0xa0, 0x91, 0x4f, 0xec, 0x4b, 0xef, 0x54,
             0xba, 0xbf, 0x66, 0x13, 0xa9, 0xf9, 0xcd, 0x70}, 16,
            /* tag, tag length  */
            {0xe6, 0x0e, 0x7c, 0x50, 0x13, 0xa6, 0xdb, 0xf2,
             0x52, 0x98, 0xb1, 0x92, 0x9b, 0xc3, 0x56, 0x27}, 16,
            /* valid */
            0,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
             0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
             0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}, 16,
            /* ct, ct length  */
            {0x29, 0xa0, 0x91, 0x4f, 0xec, 0x4b, 0xef, 0x54,
             0xba, 0xbf, 0x66, 0x13, 0xa9, 0xf9, 0xcd, 0x70}, 16,
            /* tag, tag length  */
            {0xe7, 0x0e, 0x7c, 0x50, 0x13, 0xa6, 0xdb, 0xf2,
             0x53, 0x98, 0xb1, 0x92, 0x9b, 0xc3, 0x56, 0xa7}, 16,
            /* valid */
            0,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
             0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
             0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}, 16,
            /* ct, ct length  */
            {0x29, 0xa0, 0x91, 0x4f, 0xec, 0x4b, 0xef, 0x54,
             0xba, 0xbf, 0x66, 0x13, 0xa9, 0xf9, 0xcd, 0x70}, 16,
            /* tag, tag length  */
            {0xe6, 0x0e, 0x7c, 0xd0, 0x13, 0xa6, 0xdb, 0x72,
             0x52, 0x98, 0xb1, 0x92, 0x9b, 0xc3, 0x56, 0xa7}, 16,
            /* valid */
            0,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
             0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
             0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}, 16,
            /* ct, ct length  */
            {0x29, 0xa0, 0x91, 0x4f, 0xec, 0x4b, 0xef, 0x54,
             0xba, 0xbf, 0x66, 0x13, 0xa9, 0xf9, 0xcd, 0x70}, 16,
            /* tag, tag length  */
            {0xe6, 0x0e, 0x7c, 0x50, 0x13, 0xa6, 0xdb, 0x72,
             0x52, 0x98, 0xb1, 0x92, 0x9b, 0xc3, 0x56, 0x27}, 16,
            /* valid */
            0,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
             0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
             0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}, 16,
            /* ct, ct length  */
            {0x29, 0xa0, 0x91, 0x4f, 0xec, 0x4b, 0xef, 0x54,
             0xba, 0xbf, 0x66, 0x13, 0xa9, 0xf9, 0xcd, 0x70}, 16,
            /* tag, tag length  */
            {0x19, 0xf1, 0x83, 0xaf, 0xec, 0x59, 0x24, 0x0d,
             0xad, 0x67, 0x4e, 0x6d, 0x64, 0x3c, 0xa9, 0x58}, 16,
            /* valid */
            0,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
             0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
             0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}, 16,
            /* ct, ct length  */
            {0x29, 0xa0, 0x91, 0x4f, 0xec, 0x4b, 0xef, 0x54,
             0xba, 0xbf, 0x66, 0x13, 0xa9, 0xf9, 0xcd, 0x70}, 16,
            /* tag, tag length  */
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 16,
            /* valid */
            0,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
             0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
             0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}, 16,
            /* ct, ct length  */
            {0x29, 0xa0, 0x91, 0x4f, 0xec, 0x4b, 0xef, 0x54,
             0xba, 0xbf, 0x66, 0x13, 0xa9, 0xf9, 0xcd, 0x70}, 16,
            /* tag, tag length  */
            {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 16,
            /* valid */
            0,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
             0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
             0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}, 16,
            /* ct, ct length  */
            {0x29, 0xa0, 0x91, 0x4f, 0xec, 0x4b, 0xef, 0x54,
             0xba, 0xbf, 0x66, 0x13, 0xa9, 0xf9, 0xcd, 0x70}, 16,
            /* tag, tag length  */
            {0x66, 0x8e, 0xfc, 0xd0, 0x93, 0x26, 0x5b, 0x72,
             0xd2, 0x18, 0x31, 0x12, 0x1b, 0x43, 0xd6, 0x27}, 16,
            /* valid */
            0,
        },
        {
            /* key, key length  */
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, 16,
            /* iv, iv length  */
            {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
             0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f}, 16,
            /* aad, aad length  */
            {0x00}, 0,
            /* msg, msg length  */
            {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
             0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}, 16,
            /* ct, ct length  */
            {0x29, 0xa0, 0x91, 0x4f, 0xec, 0x4b, 0xef, 0x54,
             0xba, 0xbf, 0x66, 0x13, 0xa9, 0xf9, 0xcd, 0x70}, 16,
            /* tag, tag length  */
            {0xe7, 0x0f, 0x7d, 0x51, 0x12, 0xa7, 0xda, 0xf3,
             0x53, 0x99, 0xb0, 0x93, 0x9a, 0xc2, 0x57, 0xa6}, 16,
            /* valid */
            0,
        },
    #endif
    };

    byte ciphertext[sizeof(vectors[0].ct)];
    byte authtag[sizeof(vectors[0].tag)];
    int i;
    int len;
    int ret;


    for (i = 0; i < (int)(sizeof(vectors)/sizeof(vectors[0])); i++) {

        XMEMSET(ciphertext, 0, sizeof(ciphertext));

        len = sizeof(authtag);
        ExpectIntEQ(wc_AesEaxEncryptAuth(vectors[i].key, vectors[i].key_length,
                                         ciphertext,
                                         vectors[i].msg, vectors[i].msg_length,
                                         vectors[i].iv, vectors[i].iv_length,
                                         authtag, len,
                                         vectors[i].aad, vectors[i].aad_length),
                                         0);

        /* check ciphertext matches vector */
        ExpectIntEQ(XMEMCMP(ciphertext, vectors[i].ct, vectors[i].ct_length),
                    0);

        /* check that computed tag matches vector only for vectors marked asx
         * valid */
        ret = XMEMCMP(authtag, vectors[i].tag, len);
        if (vectors[i].valid) {
            ExpectIntEQ(ret, 0);
        }
        else {
            ExpectIntNE(ret, 0);
        }

        XMEMSET(ciphertext, 0, sizeof(ciphertext));

        /* Decrypt, checking that the computed auth tags match */
        ExpectIntEQ(wc_AesEaxDecryptAuth(vectors[i].key, vectors[i].key_length,
                                         ciphertext,
                                         vectors[i].ct, vectors[i].ct_length,
                                         vectors[i].iv, vectors[i].iv_length,
                                         authtag, len,
                                         vectors[i].aad, vectors[i].aad_length),
                                         0);

        /* check decrypted ciphertext matches vector plaintext */
        ExpectIntEQ(XMEMCMP(ciphertext, vectors[i].msg, vectors[i].msg_length),
                    0);
    }
    return EXPECT_RESULT();
} /* END test_wc_AesEaxVectors */

/*
 * Testing test_wc_AesEaxEncryptAuth()
 */
int test_wc_AesEaxEncryptAuth(void)
{
    EXPECT_DECLS;

    const byte key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    const byte iv[]  = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    const byte aad[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    const byte msg[] = {0x00, 0x01, 0x02, 0x03, 0x04};

    byte ciphertext[sizeof(msg)];
    byte authtag[WC_AES_BLOCK_SIZE];
    int i;
    int len;

    len = sizeof(authtag);
    ExpectIntEQ(wc_AesEaxEncryptAuth(key, sizeof(key),
                                     ciphertext,
                                     msg, sizeof(msg),
                                     iv, sizeof(iv),
                                     authtag, (word32)len,
                                     aad, sizeof(aad)),
                                     0);

    /* Test null checking */
    ExpectIntEQ(wc_AesEaxEncryptAuth(NULL, sizeof(key),
                                     ciphertext,
                                     msg, sizeof(msg),
                                     iv, sizeof(iv),
                                     authtag, (word32)len,
                                     aad, sizeof(aad)),
                                     WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesEaxEncryptAuth(key, sizeof(key),
                                     NULL,
                                     msg, sizeof(msg),
                                     iv, sizeof(iv),
                                     authtag, (word32)len,
                                     aad, sizeof(aad)),
                                     WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesEaxEncryptAuth(key, sizeof(key),
                                     ciphertext,
                                     NULL, sizeof(msg),
                                     iv, sizeof(iv),
                                     authtag, (word32)len,
                                     aad, sizeof(aad)),
                                     WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesEaxEncryptAuth(key, sizeof(key),
                                     ciphertext,
                                     msg, sizeof(msg),
                                     NULL, sizeof(iv),
                                     authtag, (word32)len,
                                     aad, sizeof(aad)),
                                     WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesEaxEncryptAuth(key, sizeof(key),
                                     ciphertext,
                                     msg, sizeof(msg),
                                     iv, sizeof(iv),
                                     NULL, (word32)len,
                                     aad, sizeof(aad)),
                                     WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesEaxEncryptAuth(key, sizeof(key),
                                     ciphertext,
                                     msg, sizeof(msg),
                                     iv, sizeof(iv),
                                     authtag, (word32)len,
                                     NULL, sizeof(aad)),
                                     WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test bad key lengths */
    for (i = 0; i <= 32; i++) {
        int exp_ret;
    #ifdef WOLFSSL_AES_128
        if (i == AES_128_KEY_SIZE) {
            exp_ret = 0;
        }
        else
    #endif
    #ifdef WOLFSSL_AES_192
        if (i == AES_192_KEY_SIZE) {
            exp_ret = 0;
        }
        else
    #endif
    #ifdef WOLFSSL_AES_256
        if (i == AES_256_KEY_SIZE) {
            exp_ret = 0;
        }
        else
    #endif
        {
            exp_ret = WC_NO_ERR_TRACE(BAD_FUNC_ARG);
        }

        ExpectIntEQ(wc_AesEaxEncryptAuth(key, (word32)i,
                                         ciphertext,
                                         msg, sizeof(msg),
                                         iv, sizeof(iv),
                                         authtag, (word32)len,
                                         aad, sizeof(aad)),
                                         exp_ret);
    }


    /* Test auth tag size out of range */
    len = WC_AES_BLOCK_SIZE + 1;
    ExpectIntEQ(wc_AesEaxEncryptAuth(key, sizeof(key),
                                     ciphertext,
                                     msg, sizeof(msg),
                                     iv, sizeof(iv),
                                     authtag, (word32)len,
                                     aad, sizeof(aad)),
                                     WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    return EXPECT_RESULT();
} /* END test_wc_AesEaxEncryptAuth() */

/*
 * Testing test_wc_AesEaxDecryptAuth()
 */
int test_wc_AesEaxDecryptAuth(void)
{
    EXPECT_DECLS;

    const byte key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    const byte iv[]  = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    const byte aad[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    const byte ct[] =  {0x00, 0x01, 0x02, 0x03, 0x04};
    /* Garbage tag that should always fail for above aad */
    const byte tag[] = {0xFE, 0xED, 0xBE, 0xEF, 0xDE, 0xAD, 0xC0, 0xDE,
                        0xCA, 0xFE, 0xBE, 0xEF, 0xDE, 0xAF, 0xBE, 0xEF};

    byte plaintext[sizeof(ct)];
    int i;
    int len;

    len = sizeof(tag);
    ExpectIntEQ(wc_AesEaxDecryptAuth(key, sizeof(key),
                                     plaintext,
                                     ct, sizeof(ct),
                                     iv, sizeof(iv),
                                     tag, (word32)len,
                                     aad, sizeof(aad)),
                                     WC_NO_ERR_TRACE(AES_EAX_AUTH_E));

    /* Test null checking */
    ExpectIntEQ(wc_AesEaxDecryptAuth(NULL, sizeof(key),
                                     plaintext,
                                     ct, sizeof(ct),
                                     iv, sizeof(iv),
                                     tag, (word32)len,
                                     aad, sizeof(aad)),
                                     WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesEaxDecryptAuth(key, sizeof(key),
                                     NULL,
                                     ct, sizeof(ct),
                                     iv, sizeof(iv),
                                     tag, (word32)len,
                                     aad, sizeof(aad)),
                                     WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesEaxDecryptAuth(key, sizeof(key),
                                     plaintext,
                                     NULL, sizeof(ct),
                                     iv, sizeof(iv),
                                     tag, (word32)len,
                                     aad, sizeof(aad)),
                                     WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesEaxDecryptAuth(key, sizeof(key),
                                     plaintext,
                                     ct, sizeof(ct),
                                     NULL, sizeof(iv),
                                     tag, (word32)len,
                                     aad, sizeof(aad)),
                                     WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesEaxDecryptAuth(key, sizeof(key),
                                     plaintext,
                                     ct, sizeof(ct),
                                     iv, sizeof(iv),
                                     NULL, (word32)len,
                                     aad, sizeof(aad)),
                                     WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesEaxDecryptAuth(key, sizeof(key),
                                     plaintext,
                                     ct, sizeof(ct),
                                     iv, sizeof(iv),
                                     tag, (word32)len,
                                     NULL, sizeof(aad)),
                                     WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test bad key lengths */
    for (i = 0; i <= 32; i++) {
        int exp_ret;
    #ifdef WOLFSSL_AES_128
        if (i == AES_128_KEY_SIZE) {
            exp_ret = WC_NO_ERR_TRACE(AES_EAX_AUTH_E);
        }
        else
    #endif
    #ifdef WOLFSSL_AES_192
        if (i == AES_192_KEY_SIZE) {
            exp_ret = WC_NO_ERR_TRACE(AES_EAX_AUTH_E);
        }
        else
    #endif
    #ifdef WOLFSSL_AES_256
        if (i == AES_256_KEY_SIZE) {
            exp_ret = WC_NO_ERR_TRACE(AES_EAX_AUTH_E);
        }
        else
    #endif
        {
            exp_ret = WC_NO_ERR_TRACE(BAD_FUNC_ARG);
        }

        ExpectIntEQ(wc_AesEaxDecryptAuth(key, (word32)i,
                                         plaintext,
                                         ct, sizeof(ct),
                                         iv, sizeof(iv),
                                         tag, (word32)len,
                                         aad, sizeof(aad)),
                                         exp_ret);
    }


    /* Test auth tag size out of range */
    len = WC_AES_BLOCK_SIZE + 1;
    ExpectIntEQ(wc_AesEaxDecryptAuth(key, sizeof(key),
                                     plaintext,
                                     ct, sizeof(ct),
                                     iv, sizeof(iv),
                                     tag, (word32)len,
                                     aad, sizeof(aad)),
                                     WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    return EXPECT_RESULT();
} /* END test_wc_AesEaxDecryptAuth() */

#endif /* WOLFSSL_AES_EAX && WOLFSSL_AES_256
        * (!HAVE_FIPS || FIPS_VERSION_GE(5, 3)) && !HAVE_SELFTEST
        */

