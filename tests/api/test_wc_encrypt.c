/* test_wc_encrypt.c
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

#include <wolfssl/wolfcrypt/wc_encrypt.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#ifndef NO_ASN
    #include <wolfssl/wolfcrypt/asn.h>
#endif
#include <wolfssl/wolfcrypt/oid_sum.h>
#include <tests/api/api.h>
#include <tests/api/test_wc_encrypt.h>

/*
 *  Unit test for wc_Des3_CbcEncryptWithKey and wc_Des3_CbcDecryptWithKey
 */
int test_wc_Des3_CbcEncryptDecryptWithKey(void)
{
    EXPECT_DECLS;
#ifndef NO_DES3
    word32 vectorSz, cipherSz;
    byte cipher[24];
    byte plain[24];
    byte vector[] = { /* Now is the time for all w/o trailing 0 */
        0x4e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
        0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20
    };
    byte key[] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xde,0xba,0x98,0x76,0x54,0x32,0x10,
        0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67
    };
    byte iv[] = {
        0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef,
        0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
        0x11,0x21,0x31,0x41,0x51,0x61,0x71,0x81
    };

    vectorSz = sizeof(byte) * 24;
    cipherSz = sizeof(byte) * 24;

    ExpectIntEQ(wc_Des3_CbcEncryptWithKey(cipher, vector, vectorSz, key, iv),
        0);
    ExpectIntEQ(wc_Des3_CbcDecryptWithKey(plain, cipher, cipherSz, key, iv), 0);
    ExpectIntEQ(XMEMCMP(plain, vector, 24), 0);

    /* pass in bad args. */
    ExpectIntEQ(wc_Des3_CbcEncryptWithKey(NULL, vector, vectorSz, key, iv),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Des3_CbcEncryptWithKey(cipher, NULL, vectorSz, key, iv),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Des3_CbcEncryptWithKey(cipher, vector, vectorSz, NULL, iv),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Des3_CbcEncryptWithKey(cipher, vector, vectorSz, key, NULL),
        0);

    ExpectIntEQ(wc_Des3_CbcDecryptWithKey(NULL, cipher, cipherSz, key, iv),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Des3_CbcDecryptWithKey(plain, NULL, cipherSz, key, iv),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Des3_CbcDecryptWithKey(plain, cipher, cipherSz, NULL, iv),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Des3_CbcDecryptWithKey(plain, cipher, cipherSz, key, NULL),
        0);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Des3_CbcEncryptDecryptWithKey */

/*
 * Unit test for wc_Des_CbcEncryptWithKey and wc_Des_CbcDecryptWithKey
 * (single DES, not triple-DES)
 */
int test_wc_Des_CbcEncryptDecryptWithKey(void)
{
    EXPECT_DECLS;
#ifndef NO_DES3
    /* "now is the time for all " */
    const byte vector[] = {
        0x6e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
        0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20
    };
    const byte key[] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef
    };
    const byte iv[] = {
        0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef
    };
    /* expected ciphertext matches wolfcrypt des_test */
    const byte verify[] = {
        0x8b,0x7c,0x52,0xb0,0x01,0x2b,0x6c,0xb8,
        0x4f,0x0f,0xeb,0xf3,0xfb,0x5f,0x86,0x73,
        0x15,0x85,0xb3,0x22,0x4b,0x86,0x2b,0x4b
    };
    byte cipher[sizeof(vector)];
    byte plain[sizeof(vector)];

    /* Encrypt */
    ExpectIntEQ(wc_Des_CbcEncryptWithKey(cipher, vector, sizeof(vector),
                                         key, iv), 0);
    ExpectBufEQ(cipher, verify, sizeof(verify));

    /* Decrypt */
    ExpectIntEQ(wc_Des_CbcDecryptWithKey(plain, cipher, sizeof(cipher),
                                         key, iv), 0);
    ExpectBufEQ(plain, vector, sizeof(vector));

    /* Bad args - encrypt */
    ExpectIntEQ(wc_Des_CbcEncryptWithKey(NULL, vector, sizeof(vector), key, iv),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Des_CbcEncryptWithKey(cipher, NULL, sizeof(vector), key, iv),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Des_CbcEncryptWithKey(cipher, vector, sizeof(vector),
                                         NULL, iv),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* NULL iv is allowed (uses zero IV) */
    ExpectIntEQ(wc_Des_CbcEncryptWithKey(cipher, vector, sizeof(vector),
                                         key, NULL), 0);

    /* Bad args - decrypt */
    ExpectIntEQ(wc_Des_CbcDecryptWithKey(NULL, cipher, sizeof(cipher), key, iv),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Des_CbcDecryptWithKey(plain, NULL, sizeof(cipher), key, iv),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Des_CbcDecryptWithKey(plain, cipher, sizeof(cipher),
                                         NULL, iv),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* NULL iv is allowed (uses zero IV) */
    ExpectIntEQ(wc_Des_CbcDecryptWithKey(plain, cipher, sizeof(cipher),
                                         key, NULL), 0);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Des_CbcEncryptDecryptWithKey */

/* ---------------------------------------------------------------------------
 * MC/DC batch 1 – wc_BufferKeyEncrypt / wc_BufferKeyDecrypt / wc_CryptKey
 * --------------------------------------------------------------------------*/

#if defined(WOLFSSL_ENCRYPTED_KEYS) && !defined(NO_ASN)
static void enc_info_init_des3(EncryptedInfo* info)
{
    XMEMSET(info, 0, sizeof(*info));
    XMEMCPY(info->iv, "0102030405060708", 16);
    info->ivSz = 16;
    info->keySz = 24;
    info->cipherType = WC_CIPHER_DES3;
}
#endif

int test_wc_EncryptBadArgCoverage(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_ENCRYPTED_KEYS) && !defined(NO_ASN)
    EncryptedInfo info;
    byte der[24];
    static const byte pass[] = "testpass";
    int passSz = (int)sizeof(pass) - 1;

    XMEMSET(der, 0xAB, sizeof(der));

    enc_info_init_des3(&info);
    ExpectIntEQ(wc_BufferKeyEncrypt(&info, NULL, sizeof(der), pass, passSz,
        WC_HASH_TYPE_SHA), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    enc_info_init_des3(&info);
    (void)wc_BufferKeyEncrypt(&info, der, sizeof(der), pass, passSz,
        WC_HASH_TYPE_SHA);

    enc_info_init_des3(&info);
    ExpectIntEQ(wc_BufferKeyEncrypt(&info, der, sizeof(der), NULL, passSz,
        WC_HASH_TYPE_SHA), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_BufferKeyEncrypt(NULL, der, sizeof(der), pass, passSz,
        WC_HASH_TYPE_SHA), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    enc_info_init_des3(&info);
    info.keySz = 0;
    ExpectIntEQ(wc_BufferKeyEncrypt(&info, der, sizeof(der), pass, passSz,
        WC_HASH_TYPE_SHA), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    enc_info_init_des3(&info);
    info.ivSz = 4;
    ExpectIntEQ(wc_BufferKeyEncrypt(&info, der, sizeof(der), pass, passSz,
        WC_HASH_TYPE_SHA), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    enc_info_init_des3(&info);
    ExpectIntEQ(wc_BufferKeyDecrypt(&info, NULL, sizeof(der), pass, passSz,
        WC_HASH_TYPE_SHA), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    enc_info_init_des3(&info);
    ExpectIntEQ(wc_BufferKeyDecrypt(&info, der, sizeof(der), NULL, passSz,
        WC_HASH_TYPE_SHA), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_BufferKeyDecrypt(NULL, der, sizeof(der), pass, passSz,
        WC_HASH_TYPE_SHA), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    enc_info_init_des3(&info);
    info.keySz = 0;
    ExpectIntEQ(wc_BufferKeyDecrypt(&info, der, sizeof(der), pass, passSz,
        WC_HASH_TYPE_SHA), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    enc_info_init_des3(&info);
    {
        int r = wc_BufferKeyDecrypt(&info, der, sizeof(der), pass, passSz,
            WC_HASH_TYPE_SHA);
        ExpectTrue(r != WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }
#endif
    return EXPECT_RESULT();
}

int test_wc_EncryptDecisionCoverage(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_ENCRYPTED_KEYS) && !defined(NO_ASN)
    EncryptedInfo info;
    /* Multiple of both DES (8) and AES (16) block sizes so in-place CBC
     * encrypt/decrypt never walks past the buffer. */
    byte buf[32];
    static const byte pass[] = "password1";
    int passSz = (int)sizeof(pass) - 1;

#ifndef NO_DES3
    enc_info_init_des3(&info);
    XMEMSET(buf, 0x55, sizeof(buf));
    (void)wc_BufferKeyEncrypt(&info, buf, sizeof(buf), pass, passSz,
        WC_HASH_TYPE_SHA);

    enc_info_init_des3(&info);
    info.cipherType = WC_CIPHER_DES;
    info.keySz = 8;
    XMEMSET(buf, 0x66, sizeof(buf));
    (void)wc_BufferKeyEncrypt(&info, buf, sizeof(buf), pass, passSz,
        WC_HASH_TYPE_SHA);
#endif

#if !defined(NO_AES) && defined(HAVE_AES_CBC)
    enc_info_init_des3(&info);
    info.cipherType = WC_CIPHER_AES_CBC;
    info.keySz = 16;
    XMEMSET(buf, 0x77, sizeof(buf));
    (void)wc_BufferKeyEncrypt(&info, buf, sizeof(buf), pass, passSz,
        WC_HASH_TYPE_SHA);
#endif

    enc_info_init_des3(&info);
    info.cipherType = 99;
    XMEMSET(buf, 0x88, sizeof(buf));
    (void)wc_BufferKeyEncrypt(&info, buf, sizeof(buf), pass, passSz,
        WC_HASH_TYPE_SHA);

#ifndef NO_DES3
    enc_info_init_des3(&info);
    XMEMSET(buf, 0xAA, sizeof(buf));
    (void)wc_BufferKeyDecrypt(&info, buf, sizeof(buf), pass, passSz,
        WC_HASH_TYPE_SHA);
#endif

#if !defined(NO_AES) && defined(HAVE_AES_CBC) && defined(HAVE_AES_DECRYPT)
    enc_info_init_des3(&info);
    info.cipherType = WC_CIPHER_AES_CBC;
    info.keySz = 16;
    XMEMSET(buf, 0xBB, sizeof(buf));
    (void)wc_BufferKeyDecrypt(&info, buf, sizeof(buf), pass, passSz,
        WC_HASH_TYPE_SHA);
#endif
#endif
    return EXPECT_RESULT();
}

int test_wc_CryptKeyBadArgCoverage(void)
{
    EXPECT_DECLS;
#if !defined(NO_PWDBASED) && !defined(NO_ASN) && \
    (defined(HAVE_PKCS8) || defined(HAVE_PKCS12))
    byte salt[8] = { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08 };
    byte cbcIv[16] = { 0 };
    byte input[24];
    static const char pass[] = "TestPass";
    int passSz = (int)sizeof(pass) - 1;

    XMEMSET(input, 0x5A, sizeof(input));

    ExpectIntEQ(wc_CryptKey(NULL, passSz, salt, (int)sizeof(salt),
        1, PBE_SHA1_DES3, input, (int)sizeof(input),
        PKCS5, cbcIv, 1, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_CryptKey(pass, passSz, NULL, (int)sizeof(salt),
        1, PBE_SHA1_DES3, input, (int)sizeof(input),
        PKCS5, cbcIv, 1, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_CryptKey(pass, passSz, salt, (int)sizeof(salt),
        1, PBE_SHA1_DES3, NULL, (int)sizeof(input),
        PKCS5, cbcIv, 1, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_CryptKey(pass, passSz, salt, (int)sizeof(salt),
        1, PBE_SHA1_DES3, input, -1,
        PKCS5, cbcIv, 1, 0), WC_NO_ERR_TRACE(BAD_LENGTH_E));

    ExpectIntEQ(wc_CryptKey(pass, passSz, salt, (int)sizeof(salt),
        1, 255, input, (int)sizeof(input),
        PKCS5, cbcIv, 1, 0), WC_NO_ERR_TRACE(ALGO_ID_E));
#endif
    return EXPECT_RESULT();
}

int test_wc_CryptKeyVersionBranches(void)
{
    EXPECT_DECLS;
#if !defined(NO_PWDBASED) && !defined(NO_ASN) && \
    (defined(HAVE_PKCS8) || defined(HAVE_PKCS12))
    byte salt[8] = { 0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88 };
    byte cbcIv[16];
    /* Multiple of both DES (8) and AES (16) block sizes so in-place
     * encrypt/decrypt never walks past the buffer. */
    byte input[32];
    static const char pass[] = "MCDCpass";
    int passSz = (int)sizeof(pass) - 1;
    int r;

    XMEMSET(cbcIv, 0x00, sizeof(cbcIv));
    XMEMSET(input, 0x5A, sizeof(input));

#ifndef NO_SHA
#ifndef NO_DES3
    XMEMSET(input, 0x5A, sizeof(input));
    r = wc_CryptKey(pass, passSz, salt, (int)sizeof(salt), 1,
        PBE_SHA1_DES3, input, (int)sizeof(input), PKCS5, cbcIv, 1, 0);
    (void)r;

    XMEMSET(input, 0x5A, sizeof(input));
    r = wc_CryptKey(pass, passSz, salt, (int)sizeof(salt), 1,
        PBE_SHA1_DES3, input, (int)sizeof(input), PKCS5, cbcIv, 0, 0);
    (void)r;
#endif

#if !defined(NO_DES3) && !defined(NO_SHA256)
    XMEMSET(input, 0x5A, sizeof(input));
    r = wc_CryptKey(pass, passSz, salt, (int)sizeof(salt), 1,
        PBE_SHA1_DES3, input, (int)sizeof(input),
        PKCS5, cbcIv, 1, HMAC_SHA256_OID);
    (void)r;
#endif
#endif

#ifndef NO_HMAC
#if defined(WOLFSSL_AES_256) && !defined(NO_SHA256) && \
    !defined(NO_AES) && defined(HAVE_AES_CBC)
    XMEMSET(input, 0x5A, sizeof(input));
    r = wc_CryptKey(pass, passSz, salt, (int)sizeof(salt), 1,
        PBE_AES256_CBC, input, (int)sizeof(input),
        PKCS5v2, cbcIv, 1, HMAC_SHA256_OID);
    (void)r;
#ifndef NO_SHA
    XMEMSET(input, 0x5A, sizeof(input));
    r = wc_CryptKey(pass, passSz, salt, (int)sizeof(salt), 1,
        PBE_AES256_CBC, input, (int)sizeof(input),
        PKCS5v2, cbcIv, 1, 0);
    (void)r;
#endif
#endif

#if defined(WOLFSSL_AES_128) && !defined(NO_SHA256) && \
    !defined(NO_AES) && defined(HAVE_AES_CBC)
    XMEMSET(input, 0x5A, sizeof(input));
    r = wc_CryptKey(pass, passSz, salt, (int)sizeof(salt), 1,
        PBE_AES128_CBC, input, (int)sizeof(input),
        PKCS5v2, cbcIv, 1, HMAC_SHA256_OID);
    (void)r;
#ifndef NO_SHA
    XMEMSET(input, 0x5A, sizeof(input));
    r = wc_CryptKey(pass, passSz, salt, (int)sizeof(salt), 1,
        PBE_AES128_CBC, input, (int)sizeof(input),
        PKCS5v2, cbcIv, 1, 0);
    (void)r;
#endif
#endif
#endif

#ifdef HAVE_PKCS12
#if !defined(NO_DES3) && !defined(NO_SHA)
    XMEMSET(input, 0x5A, sizeof(input));
    r = wc_CryptKey(pass, passSz, salt, (int)sizeof(salt), 1,
        PBE_SHA1_DES3, input, (int)sizeof(input),
        PKCS12v1, cbcIv, 1, 0);
    (void)r;
#endif

#ifndef NO_DES3
#ifndef NO_SHA
    XMEMSET(input, 0x5A, sizeof(input));
    r = wc_CryptKey(pass, passSz, salt, (int)sizeof(salt), 1,
        PBE_SHA1_DES3, input, (int)sizeof(input),
        99, cbcIv, 1, 0);
    ExpectIntEQ(r, WC_NO_ERR_TRACE(ALGO_ID_E));
#endif
#endif
#endif
#endif
    return EXPECT_RESULT();
}
