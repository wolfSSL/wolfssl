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
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/types.h>
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

/*
 * wc_AesCbcEncryptWithKey / wc_AesCbcDecryptWithKey round-trip: exercises the
 * WC_ALLOC/wc_AesInit/SetKey/CbcEncrypt ret==0 chains in wc_encrypt.c.
 */
int test_wc_AesCbcEncryptDecryptWithKey(void)
{
    EXPECT_DECLS;
#if !defined(NO_AES) && defined(HAVE_AES_CBC) && defined(HAVE_AES_DECRYPT)
    const byte key[16] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };
    const byte iv[16] = {
        0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80,
        0x90,0xa0,0xb0,0xc0,0xd0,0xe0,0xf0,0x00
    };
    const byte plain[16] = {
        'w','o','l','f','s','s','l',' ','a','e','s','c','b','c','!','!'
    };
    byte cipher[16] = {0};
    byte decrypted[16] = {0};

    ExpectIntEQ(wc_AesCbcEncryptWithKey(cipher, plain, (word32)sizeof(plain),
                                        key, (word32)sizeof(key), iv), 0);
    ExpectIntEQ(wc_AesCbcDecryptWithKey(decrypted, cipher,
                                        (word32)sizeof(cipher),
                                        key, (word32)sizeof(key), iv), 0);
    ExpectBufEQ(decrypted, plain, (int)sizeof(plain));

    /* invalid key size propagates an error out of the ret==0 chain */
    ExpectIntNE(wc_AesCbcEncryptWithKey(cipher, plain, (word32)sizeof(plain),
                                        key, 5, iv), 0);
#endif
    return EXPECT_RESULT();
} /* END test_wc_AesCbcEncryptDecryptWithKey */

/*
 * wc_BufferKeyEncrypt / wc_BufferKeyDecrypt: argument-check decision coverage
 * (the 5- and 4-operand OR guards) plus the info->cipherType dispatch arms
 * (WC_CIPHER_DES / WC_CIPHER_DES3 / WC_CIPHER_AES_CBC).
 */
int test_wc_BufferKeyEncryptDecryptDecisionCoverage(void)
{
    EXPECT_DECLS;
#if !defined(NO_ASN) && defined(WOLFSSL_ENCRYPTED_KEYS) && \
    !defined(NO_PWDBASED) && !defined(NO_SHA)
    const byte pw[] = { 'p','a','s','s','w','o','r','d' };
    EncryptedInfo info;
    byte der[32];

    /* ---- wc_BufferKeyEncrypt argument-check independence pairs ---- */
    /* baseline: all operands valid (built per cipher below); here vary one at a
     * time while the others are valid. */
    XMEMSET(&info, 0, sizeof(info));
    info.cipherType = WC_CIPHER_AES_CBC;
    info.keySz = 16;
    info.ivSz  = 16;
    XMEMSET(info.iv, 0x22, 16);
    XMEMSET(der, 0x33, sizeof(der));

    /* der == NULL */
    ExpectIntEQ(wc_BufferKeyEncrypt(&info, NULL, (word32)sizeof(der),
                    pw, (int)sizeof(pw), WC_HASH_TYPE_SHA),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* password == NULL */
    ExpectIntEQ(wc_BufferKeyEncrypt(&info, der, (word32)sizeof(der),
                    NULL, (int)sizeof(pw), WC_HASH_TYPE_SHA),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* info == NULL */
    ExpectIntEQ(wc_BufferKeyEncrypt(NULL, der, (word32)sizeof(der),
                    pw, (int)sizeof(pw), WC_HASH_TYPE_SHA),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* info->keySz == 0 */
    info.keySz = 0;
    ExpectIntEQ(wc_BufferKeyEncrypt(&info, der, (word32)sizeof(der),
                    pw, (int)sizeof(pw), WC_HASH_TYPE_SHA),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    info.keySz = 16;
    /* info->ivSz < PKCS5_SALT_SZ */
    info.ivSz = PKCS5_SALT_SZ - 1;
    ExpectIntEQ(wc_BufferKeyEncrypt(&info, der, (word32)sizeof(der),
                    pw, (int)sizeof(pw), WC_HASH_TYPE_SHA),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    info.ivSz = 16;

    /* ---- wc_BufferKeyDecrypt argument-check independence pairs ---- */
    ExpectIntEQ(wc_BufferKeyDecrypt(&info, NULL, (word32)sizeof(der),
                    pw, (int)sizeof(pw), WC_HASH_TYPE_SHA),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_BufferKeyDecrypt(&info, der, (word32)sizeof(der),
                    NULL, (int)sizeof(pw), WC_HASH_TYPE_SHA),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_BufferKeyDecrypt(NULL, der, (word32)sizeof(der),
                    pw, (int)sizeof(pw), WC_HASH_TYPE_SHA),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    info.keySz = 0;
    ExpectIntEQ(wc_BufferKeyDecrypt(&info, der, (word32)sizeof(der),
                    pw, (int)sizeof(pw), WC_HASH_TYPE_SHA),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    info.keySz = 16;

    /* ---- cipherType dispatch: AES-CBC encrypt (16-byte block) ---- */
#if defined(HAVE_AES_CBC)
    {
        XMEMSET(&info, 0, sizeof(info));
        info.cipherType = WC_CIPHER_AES_CBC;
        info.keySz = 16;
        info.ivSz  = 16;
        XMEMSET(info.iv, 0x24, 16);
        XMEMSET(der, 0x33, 16);
        ExpectIntEQ(wc_BufferKeyEncrypt(&info, der, 16,
                        pw, (int)sizeof(pw), WC_HASH_TYPE_SHA), 0);
    }
#endif
    /* ---- cipherType dispatch: 3DES and DES encrypt (8-byte block) ---- */
#ifndef NO_DES3
    {
        XMEMSET(&info, 0, sizeof(info));
        info.cipherType = WC_CIPHER_DES3;
        info.keySz = 24;
        info.ivSz  = PKCS5_SALT_SZ;
        XMEMSET(info.iv, 0x25, PKCS5_SALT_SZ);
        XMEMSET(der, 0x33, 24);
        ExpectIntEQ(wc_BufferKeyEncrypt(&info, der, 24,
                        pw, (int)sizeof(pw), WC_HASH_TYPE_SHA), 0);

        XMEMSET(&info, 0, sizeof(info));
        info.cipherType = WC_CIPHER_DES;
        info.keySz = 8;
        info.ivSz  = PKCS5_SALT_SZ;
        XMEMSET(info.iv, 0x26, PKCS5_SALT_SZ);
        XMEMSET(der, 0x33, 24);
        ExpectIntEQ(wc_BufferKeyEncrypt(&info, der, 24,
                        pw, (int)sizeof(pw), WC_HASH_TYPE_SHA), 0);
    }
#endif

    /* ---- decrypt dispatch: iv is hex (Base16-decoded to the PBKDF salt) ---- */
#if defined(HAVE_AES_CBC) && defined(HAVE_AES_DECRYPT) && defined(WOLFSSL_BASE16)
    {
        /* 16 hex chars -> 8-byte salt after Base16_Decode */
        const byte hexIv[16] = {
            '1','1','2','2','3','3','4','4',
            '5','5','6','6','7','7','8','8'
        };
        XMEMSET(&info, 0, sizeof(info));
        info.cipherType = WC_CIPHER_AES_CBC;
        info.keySz = 16;
        info.ivSz  = 16;
        XMEMCPY(info.iv, hexIv, 16);
        XMEMSET(der, 0x33, 16);
        ExpectIntEQ(wc_BufferKeyDecrypt(&info, der, 16,
                        pw, (int)sizeof(pw), WC_HASH_TYPE_SHA), 0);

        /* ivSz that decodes below PKCS5_SALT_SZ -> BUFFER_E */
        XMEMSET(&info, 0, sizeof(info));
        info.cipherType = WC_CIPHER_AES_CBC;
        info.keySz = 16;
        info.ivSz  = 4; /* 4 hex chars -> 2-byte salt < PKCS5_SALT_SZ */
        XMEMCPY(info.iv, hexIv, 4);
        XMEMSET(der, 0x33, 16);
        ExpectIntEQ(wc_BufferKeyDecrypt(&info, der, 16,
                        pw, (int)sizeof(pw), WC_HASH_TYPE_SHA),
                    WC_NO_ERR_TRACE(BUFFER_E));
    }
#endif
#endif
    return EXPECT_RESULT();
} /* END test_wc_BufferKeyEncryptDecryptDecisionCoverage */

