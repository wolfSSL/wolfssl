/* test_evp_cipher.c
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

#include <wolfssl/openssl/evp.h>
#include <tests/api/api.h>
#include <tests/api/test_evp_cipher.h>
#if defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION == 2)
    #include <wolfssl/wolfcrypt/wc_encrypt.h>
#endif


int test_wolfSSL_EVP_CIPHER_CTX(void)
{
    EXPECT_DECLS;
#if !defined(NO_AES) && defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_128) && \
    defined(OPENSSL_EXTRA)
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *init = EVP_aes_128_cbc();
    const EVP_CIPHER *test;
    byte key[AES_BLOCK_SIZE] = {0};
    byte iv[AES_BLOCK_SIZE] = {0};

    ExpectNotNull(ctx);
    wolfSSL_EVP_CIPHER_CTX_init(ctx);
    ExpectIntEQ(EVP_CipherInit(ctx, init, key, iv, 1), WOLFSSL_SUCCESS);
    test = EVP_CIPHER_CTX_cipher(ctx);
    ExpectTrue(init == test);
    ExpectIntEQ(EVP_CIPHER_nid(test), NID_aes_128_cbc);

    ExpectIntEQ(EVP_CIPHER_CTX_reset(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_CIPHER_CTX_reset(NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    EVP_CIPHER_CTX_free(ctx);
    /* test EVP_CIPHER_CTX_cleanup with NULL */
    ExpectIntEQ(EVP_CIPHER_CTX_cleanup(NULL), WOLFSSL_SUCCESS);
#endif /* !NO_AES && HAVE_AES_CBC && WOLFSSL_AES_128 && OPENSSL_EXTRA */
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_CIPHER_CTX_iv_length(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_ALL
    /* This is large enough to be used for all key sizes */
    byte key[AES_256_KEY_SIZE] = {0};
    byte iv[AES_BLOCK_SIZE] = {0};
    int i;
    int nids[] = {
    #ifdef HAVE_AES_CBC
         NID_aes_128_cbc,
    #endif
    #if (!defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)) || \
        (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2))
    #ifdef HAVE_AESGCM
         NID_aes_128_gcm,
    #endif
    #endif /* (HAVE_FIPS && !HAVE_SELFTEST) || HAVE_FIPS_VERSION > 2 */
    #ifdef WOLFSSL_AES_COUNTER
         NID_aes_128_ctr,
    #endif
    #ifndef NO_DES3
         NID_des_cbc,
         NID_des_ede3_cbc,
    #endif
    };
    int iv_lengths[] = {
    #ifdef HAVE_AES_CBC
         AES_BLOCK_SIZE,
    #endif
    #if (!defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)) || \
        (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2))
    #ifdef HAVE_AESGCM
         GCM_NONCE_MID_SZ,
    #endif
    #endif /* (HAVE_FIPS && !HAVE_SELFTEST) || HAVE_FIPS_VERSION > 2 */
    #ifdef WOLFSSL_AES_COUNTER
         AES_BLOCK_SIZE,
    #endif
    #ifndef NO_DES3
         DES_BLOCK_SIZE,
         DES_BLOCK_SIZE,
    #endif
    };
    int nidsLen = (sizeof(nids)/sizeof(int));

    for (i = 0; i < nidsLen; i++) {
        const EVP_CIPHER* init = wolfSSL_EVP_get_cipherbynid(nids[i]);
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        wolfSSL_EVP_CIPHER_CTX_init(ctx);

        ExpectIntEQ(EVP_CipherInit(ctx, init, key, iv, 1), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_iv_length(ctx), iv_lengths[i]);

        EVP_CIPHER_CTX_free(ctx);
    }
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_CIPHER_CTX_key_length(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_ALL
    byte key[AES_256_KEY_SIZE] = {0};
    byte iv[AES_BLOCK_SIZE] = {0};
    int i;
    int nids[] = {
    #ifdef HAVE_AES_CBC
        NID_aes_128_cbc,
        #ifdef WOLFSSL_AES_256
        NID_aes_256_cbc,
        #endif
    #endif
    #if (!defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)) || \
        (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2))
    #ifdef HAVE_AESGCM
        NID_aes_128_gcm,
        #ifdef WOLFSSL_AES_256
        NID_aes_256_gcm,
        #endif
    #endif
    #endif /* (HAVE_FIPS && !HAVE_SELFTEST) || HAVE_FIPS_VERSION > 2 */
    #ifdef WOLFSSL_AES_COUNTER
        NID_aes_128_ctr,
        #ifdef WOLFSSL_AES_256
        NID_aes_256_ctr,
        #endif
    #endif
    #ifndef NO_DES3
         NID_des_cbc,
         NID_des_ede3_cbc,
    #endif
    };
    int key_lengths[] = {
    #ifdef HAVE_AES_CBC
        AES_128_KEY_SIZE,
        #ifdef WOLFSSL_AES_256
        AES_256_KEY_SIZE,
        #endif
    #endif
    #if (!defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)) || \
        (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2))
    #ifdef HAVE_AESGCM
        AES_128_KEY_SIZE,
        #ifdef WOLFSSL_AES_256
        AES_256_KEY_SIZE,
        #endif
    #endif
    #endif /* (HAVE_FIPS && !HAVE_SELFTEST) || HAVE_FIPS_VERSION > 2 */
    #ifdef WOLFSSL_AES_COUNTER
        AES_128_KEY_SIZE,
        #ifdef WOLFSSL_AES_256
        AES_256_KEY_SIZE,
        #endif
    #endif
    #ifndef NO_DES3
         DES_KEY_SIZE,
         DES3_KEY_SIZE,
    #endif
    };
    int nidsLen = (sizeof(nids)/sizeof(int));

    for (i = 0; i < nidsLen; i++) {
        const EVP_CIPHER *init = wolfSSL_EVP_get_cipherbynid(nids[i]);
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        wolfSSL_EVP_CIPHER_CTX_init(ctx);

        ExpectIntEQ(EVP_CipherInit(ctx, init, key, iv, 1), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_key_length(ctx), key_lengths[i]);

        ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_set_key_length(ctx, key_lengths[i]),
            WOLFSSL_SUCCESS);

        EVP_CIPHER_CTX_free(ctx);
    }
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_CIPHER_CTX_set_iv(void)
{
    EXPECT_DECLS;
#if defined(HAVE_AESGCM) && !defined(NO_DES3) && defined(OPENSSL_ALL)
    int ivLen, keyLen;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
#ifdef HAVE_AESGCM
    byte key[AES_128_KEY_SIZE] = {0};
    byte iv[AES_BLOCK_SIZE] = {0};
    const EVP_CIPHER *init = EVP_aes_128_gcm();
#else
    byte key[DES3_KEY_SIZE] = {0};
    byte iv[DES_BLOCK_SIZE] = {0};
    const EVP_CIPHER *init = EVP_des_ede3_cbc();
#endif

    wolfSSL_EVP_CIPHER_CTX_init(ctx);
    ExpectIntEQ(EVP_CipherInit(ctx, init, key, iv, 1), WOLFSSL_SUCCESS);

    ivLen = wolfSSL_EVP_CIPHER_CTX_iv_length(ctx);
    keyLen = wolfSSL_EVP_CIPHER_CTX_key_length(ctx);

    /* Bad cases */
    ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_set_iv(NULL, iv, ivLen),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_set_iv(ctx, NULL, ivLen),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_set_iv(ctx, iv, 0),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_set_iv(NULL, NULL, 0),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_set_iv(ctx, iv, keyLen),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    /* Good case */
    ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_set_iv(ctx, iv, ivLen), 1);

    EVP_CIPHER_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_get_cipherbynid(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_EXTRA
#ifndef NO_AES
    const WOLFSSL_EVP_CIPHER* c;

    c = wolfSSL_EVP_get_cipherbynid(419);
    #if (defined(HAVE_AES_CBC) || defined(WOLFSSL_AES_DIRECT)) && \
         defined(WOLFSSL_AES_128)
        ExpectNotNull(c);
        ExpectNotNull(XSTRCMP("EVP_AES_128_CBC", c));
    #else
        ExpectNull(c);
    #endif

    c = wolfSSL_EVP_get_cipherbynid(423);
    #if (defined(HAVE_AES_CBC) || defined(WOLFSSL_AES_DIRECT)) && \
         defined(WOLFSSL_AES_192)
        ExpectNotNull(c);
        ExpectNotNull(XSTRCMP("EVP_AES_192_CBC", c));
    #else
        ExpectNull(c);
    #endif

    c = wolfSSL_EVP_get_cipherbynid(427);
    #if (defined(HAVE_AES_CBC) || defined(WOLFSSL_AES_DIRECT)) && \
         defined(WOLFSSL_AES_256)
        ExpectNotNull(c);
        ExpectNotNull(XSTRCMP("EVP_AES_256_CBC", c));
    #else
        ExpectNull(c);
    #endif

    c = wolfSSL_EVP_get_cipherbynid(904);
    #if defined(WOLFSSL_AES_COUNTER) && defined(WOLFSSL_AES_128)
        ExpectNotNull(c);
        ExpectNotNull(XSTRCMP("EVP_AES_128_CTR", c));
    #else
        ExpectNull(c);
    #endif

    c = wolfSSL_EVP_get_cipherbynid(905);
    #if defined(WOLFSSL_AES_COUNTER) && defined(WOLFSSL_AES_192)
        ExpectNotNull(c);
        ExpectNotNull(XSTRCMP("EVP_AES_192_CTR", c));
    #else
        ExpectNull(c);
    #endif

    c = wolfSSL_EVP_get_cipherbynid(906);
    #if defined(WOLFSSL_AES_COUNTER) && defined(WOLFSSL_AES_256)
        ExpectNotNull(c);
        ExpectNotNull(XSTRCMP("EVP_AES_256_CTR", c));
    #else
        ExpectNull(c);
    #endif

    c = wolfSSL_EVP_get_cipherbynid(418);
    #if defined(HAVE_AES_ECB) && defined(WOLFSSL_AES_128)
        ExpectNotNull(c);
        ExpectNotNull(XSTRCMP("EVP_AES_128_ECB", c));
    #else
        ExpectNull(c);
    #endif

    c = wolfSSL_EVP_get_cipherbynid(422);
    #if defined(HAVE_AES_ECB) && defined(WOLFSSL_AES_192)
        ExpectNotNull(c);
        ExpectNotNull(XSTRCMP("EVP_AES_192_ECB", c));
    #else
        ExpectNull(c);
    #endif

    c = wolfSSL_EVP_get_cipherbynid(426);
    #if defined(HAVE_AES_ECB) && defined(WOLFSSL_AES_256)
        ExpectNotNull(c);
        ExpectNotNull(XSTRCMP("EVP_AES_256_ECB", c));
    #else
        ExpectNull(c);
    #endif
#endif /* !NO_AES */

#ifndef NO_DES3
    ExpectNotNull(XSTRCMP("EVP_DES_CBC", wolfSSL_EVP_get_cipherbynid(31)));
#ifdef WOLFSSL_DES_ECB
    ExpectNotNull(XSTRCMP("EVP_DES_ECB", wolfSSL_EVP_get_cipherbynid(29)));
#endif
    ExpectNotNull(XSTRCMP("EVP_DES_EDE3_CBC", wolfSSL_EVP_get_cipherbynid(44)));
#ifdef WOLFSSL_DES_ECB
    ExpectNotNull(XSTRCMP("EVP_DES_EDE3_ECB", wolfSSL_EVP_get_cipherbynid(33)));
#endif
#endif /* !NO_DES3 */

#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    ExpectNotNull(XSTRCMP("EVP_CHACHA20_POLY13O5", EVP_get_cipherbynid(1018)));
#endif

    /* test for nid is out of range */
    ExpectNull(wolfSSL_EVP_get_cipherbynid(1));
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_CIPHER_block_size(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_ALL
#ifdef HAVE_AES_CBC
    #ifdef WOLFSSL_AES_128
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_128_cbc()), AES_BLOCK_SIZE);
    #endif
    #ifdef WOLFSSL_AES_192
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_192_cbc()), AES_BLOCK_SIZE);
    #endif
    #ifdef WOLFSSL_AES_256
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_256_cbc()), AES_BLOCK_SIZE);
    #endif
#endif

#ifdef HAVE_AESGCM
    #ifdef WOLFSSL_AES_128
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_128_gcm()), 1);
    #endif
    #ifdef WOLFSSL_AES_192
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_192_gcm()), 1);
    #endif
    #ifdef WOLFSSL_AES_256
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_256_gcm()), 1);
    #endif
#endif

#ifdef HAVE_AESCCM
    #ifdef WOLFSSL_AES_128
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_128_ccm()), 1);
    #endif
    #ifdef WOLFSSL_AES_192
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_192_ccm()), 1);
    #endif
    #ifdef WOLFSSL_AES_256
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_256_ccm()), 1);
    #endif
#endif

#ifdef WOLFSSL_AES_COUNTER
    #ifdef WOLFSSL_AES_128
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_128_ctr()), 1);
    #endif
    #ifdef WOLFSSL_AES_192
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_192_ctr()), 1);
    #endif
    #ifdef WOLFSSL_AES_256
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_256_ctr()), 1);
    #endif
#endif

#ifdef HAVE_AES_ECB
    #ifdef WOLFSSL_AES_128
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_128_ecb()), AES_BLOCK_SIZE);
    #endif
    #ifdef WOLFSSL_AES_192
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_192_ecb()), AES_BLOCK_SIZE);
    #endif
    #ifdef WOLFSSL_AES_256
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_256_ecb()), AES_BLOCK_SIZE);
    #endif
#endif

#ifdef WOLFSSL_AES_OFB
    #ifdef WOLFSSL_AES_128
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_128_ofb()), 1);
    #endif
    #ifdef WOLFSSL_AES_192
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_192_ofb()), 1);
    #endif
    #ifdef WOLFSSL_AES_256
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_aes_256_ofb()), 1);
    #endif
#endif

#ifndef NO_RC4
    ExpectIntEQ(EVP_CIPHER_block_size(wolfSSL_EVP_rc4()), 1);
#endif

#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    ExpectIntEQ(EVP_CIPHER_block_size(wolfSSL_EVP_chacha20_poly1305()), 1);
#endif

#ifdef WOLFSSL_SM4_ECB
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_sm4_ecb()), SM4_BLOCK_SIZE);
#endif
#ifdef WOLFSSL_SM4_CBC
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_sm4_cbc()), SM4_BLOCK_SIZE);
#endif
#ifdef WOLFSSL_SM4_CTR
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_sm4_ctr()), 1);
#endif
#ifdef WOLFSSL_SM4_GCM
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_sm4_gcm()), 1);
#endif
#ifdef WOLFSSL_SM4_CCM
    ExpectIntEQ(EVP_CIPHER_block_size(EVP_sm4_ccm()), 1);
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_CIPHER_iv_length(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_ALL
    int nids[] = {
    #if defined(HAVE_AES_CBC) || defined(WOLFSSL_AES_DIRECT)
    #ifdef WOLFSSL_AES_128
        NID_aes_128_cbc,
    #endif
    #ifdef WOLFSSL_AES_192
        NID_aes_192_cbc,
    #endif
    #ifdef WOLFSSL_AES_256
        NID_aes_256_cbc,
    #endif
    #endif /* HAVE_AES_CBC || WOLFSSL_AES_DIRECT */
    #if (!defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)) || \
        (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2))
    #ifdef HAVE_AESGCM
        #ifdef WOLFSSL_AES_128
            NID_aes_128_gcm,
        #endif
        #ifdef WOLFSSL_AES_192
            NID_aes_192_gcm,
        #endif
        #ifdef WOLFSSL_AES_256
            NID_aes_256_gcm,
        #endif
    #endif /* HAVE_AESGCM */
    #endif /* (HAVE_FIPS && !HAVE_SELFTEST) || HAVE_FIPS_VERSION > 2 */
    #ifdef WOLFSSL_AES_COUNTER
    #ifdef WOLFSSL_AES_128
         NID_aes_128_ctr,
    #endif
    #ifdef WOLFSSL_AES_192
        NID_aes_192_ctr,
    #endif
    #ifdef WOLFSSL_AES_256
        NID_aes_256_ctr,
    #endif
    #endif
    #ifndef NO_DES3
         NID_des_cbc,
         NID_des_ede3_cbc,
    #endif
    #if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
         NID_chacha20_poly1305,
    #endif
    };
    int iv_lengths[] = {
    #if defined(HAVE_AES_CBC) || defined(WOLFSSL_AES_DIRECT)
    #ifdef WOLFSSL_AES_128
            AES_BLOCK_SIZE,
    #endif
    #ifdef WOLFSSL_AES_192
            AES_BLOCK_SIZE,
    #endif
    #ifdef WOLFSSL_AES_256
            AES_BLOCK_SIZE,
    #endif
    #endif /* HAVE_AES_CBC || WOLFSSL_AES_DIRECT */
    #if (!defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)) || \
        (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2))
    #ifdef HAVE_AESGCM
        #ifdef WOLFSSL_AES_128
            GCM_NONCE_MID_SZ,
        #endif
        #ifdef WOLFSSL_AES_192
            GCM_NONCE_MID_SZ,
        #endif
        #ifdef WOLFSSL_AES_256
            GCM_NONCE_MID_SZ,
        #endif
    #endif /* HAVE_AESGCM */
    #endif /* (HAVE_FIPS && !HAVE_SELFTEST) || HAVE_FIPS_VERSION > 2 */
    #ifdef WOLFSSL_AES_COUNTER
    #ifdef WOLFSSL_AES_128
            AES_BLOCK_SIZE,
    #endif
    #ifdef WOLFSSL_AES_192
            AES_BLOCK_SIZE,
    #endif
    #ifdef WOLFSSL_AES_256
            AES_BLOCK_SIZE,
    #endif
    #endif
    #ifndef NO_DES3
            DES_BLOCK_SIZE,
            DES_BLOCK_SIZE,
    #endif
    #if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
            CHACHA20_POLY1305_AEAD_IV_SIZE,
    #endif
    };
    int i;
    int nidsLen = (sizeof(nids)/sizeof(int));

    for (i = 0; i < nidsLen; i++) {
        const EVP_CIPHER *c = EVP_get_cipherbynid(nids[i]);
        ExpectIntEQ(EVP_CIPHER_iv_length(c), iv_lengths[i]);
    }
#endif
    return EXPECT_RESULT();
}

/* Test for NULL_CIPHER_TYPE in wolfSSL_EVP_CipherUpdate() */
int test_wolfSSL_EVP_CipherUpdate_Null(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_EXTRA
    WOLFSSL_EVP_CIPHER_CTX* ctx;
    const char* testData = "Test NULL cipher data";
    unsigned char output[100];
    int outputLen = 0;
    int testDataLen = (int)XSTRLEN(testData);

    /* Create and initialize the cipher context */
    ctx = wolfSSL_EVP_CIPHER_CTX_new();
    ExpectNotNull(ctx);

    /* Initialize with NULL cipher */
    ExpectIntEQ(wolfSSL_EVP_CipherInit_ex(ctx, wolfSSL_EVP_enc_null(),
                                         NULL, NULL, NULL, 1), WOLFSSL_SUCCESS);

    /* Test encryption (which should just copy the data) */
    ExpectIntEQ(wolfSSL_EVP_CipherUpdate(ctx, output, &outputLen,
                                        (const unsigned char*)testData,
                                        testDataLen), WOLFSSL_SUCCESS);

    /* Verify output length matches input length */
    ExpectIntEQ(outputLen, testDataLen);

    /* Verify output data matches input data (no encryption occurred) */
    ExpectIntEQ(XMEMCMP(output, testData, testDataLen), 0);

    /* Clean up */
    wolfSSL_EVP_CIPHER_CTX_free(ctx);
#endif /* OPENSSL_EXTRA */

    return EXPECT_RESULT();
}

/* Test for wolfSSL_EVP_CIPHER_type_string() */
int test_wolfSSL_EVP_CIPHER_type_string(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_EXTRA
    const char* cipherStr;

    /* Test with valid cipher types */
#ifdef HAVE_AES_CBC
    #ifdef WOLFSSL_AES_128
    cipherStr = wolfSSL_EVP_CIPHER_type_string(WC_AES_128_CBC_TYPE);
    ExpectNotNull(cipherStr);
    ExpectStrEQ(cipherStr, "AES-128-CBC");
    #endif
#endif

#ifndef NO_DES3
    cipherStr = wolfSSL_EVP_CIPHER_type_string(WC_DES_CBC_TYPE);
    ExpectNotNull(cipherStr);
    ExpectStrEQ(cipherStr, "DES-CBC");
#endif

    /* Test with NULL cipher type */
    cipherStr = wolfSSL_EVP_CIPHER_type_string(WC_NULL_CIPHER_TYPE);
    ExpectNotNull(cipherStr);
    ExpectStrEQ(cipherStr, "NULL");

    /* Test with invalid cipher type */
    cipherStr = wolfSSL_EVP_CIPHER_type_string(0xFFFF);
    ExpectNull(cipherStr);
#endif /* OPENSSL_EXTRA */

    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_BytesToKey(void)
{
    EXPECT_DECLS;
#if !defined(NO_AES) && defined(HAVE_AES_CBC) && defined(OPENSSL_ALL)
    byte                key[AES_BLOCK_SIZE] = {0};
    byte                iv[AES_BLOCK_SIZE] = {0};
    int                 count = 0;
    const               EVP_MD* md = EVP_sha256();
    const EVP_CIPHER    *type;
    const unsigned char *salt = (unsigned char *)"salt1234";
    int                 sz = 5;
    const byte data[] = {
        0x48,0x65,0x6c,0x6c,0x6f,0x20,0x57,0x6f,
        0x72,0x6c,0x64
    };

    type = wolfSSL_EVP_get_cipherbynid(NID_aes_128_cbc);

    /* Bad cases */
    ExpectIntEQ(EVP_BytesToKey(NULL, md, salt, data, sz, count, key, iv),
                 0);
    ExpectIntEQ(EVP_BytesToKey(type, md, salt, NULL, sz, count, key, iv),
                16);
    md = "2";
    ExpectIntEQ(EVP_BytesToKey(type, md, salt, data, sz, count, key, iv),
                 WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    /* Good case */
    md = EVP_sha256();
    ExpectIntEQ(EVP_BytesToKey(type, md, salt, data, sz, count, key, iv),
                 16);
#endif
    return EXPECT_RESULT();
}

#if (defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)) &&\
    (!defined(NO_AES) && defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_128))
static void binary_dump(void *ptr, int size)
{
    #ifdef WOLFSSL_EVP_PRINT
    int i = 0;
    unsigned char *p = (unsigned char *) ptr;

    fprintf(stderr, "{");
    while ((p != NULL) && (i < size)) {
        if ((i % 8) == 0) {
            fprintf(stderr, "\n");
            fprintf(stderr, "    ");
        }
        fprintf(stderr, "0x%02x, ", p[i]);
        i++;
    }
    fprintf(stderr, "\n};\n");
    #else
    (void) ptr;
    (void) size;
    #endif
}

static int last_val = 0x0f;

static int check_result(unsigned char *data, int len)
{
    int i;

    for ( ; len; ) {
            last_val = (last_val + 1) % 16;
            for (i = 0; i < 16; len--, i++, data++)
                    if (*data != last_val) {
                            return -1;
                    }
    }
    return 0;
}

static int r_offset;
static int w_offset;

static void init_offset(void)
{
    r_offset = 0;
    w_offset = 0;
}

static void get_record(unsigned char *data, unsigned char *buf, int len)
{
    XMEMCPY(buf, data+r_offset, len);
    r_offset += len;
}

static void set_record(unsigned char *data, unsigned char *buf, int len)
{
    XMEMCPY(data+w_offset, buf, len);
    w_offset += len;
}

static void set_plain(unsigned char *plain, int rec)
{
    int i, j;
    unsigned char *p = plain;

    #define BLOCKSZ 16

    for (i=0; i<(rec/BLOCKSZ); i++) {
        for (j=0; j<BLOCKSZ; j++)
            *p++ = (i % 16);
    }
}
#endif

int test_wolfSSL_EVP_Cipher_extra(void)
{
    EXPECT_DECLS;
#if (defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)) &&\
    (!defined(NO_AES) && defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_128))
    /* aes128-cbc, keylen=16, ivlen=16 */
    byte aes128_cbc_key[] = {
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
    };

    byte aes128_cbc_iv[] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };

    /* teset data size table */
    static const int test_drive1[] = {8, 3, 5, 512, 8, 3, 8, 512, 0};
    static const int test_drive2[] = {8, 3, 8, 512, 0};
    static const int test_drive3[] = {512, 512, 504, 512, 512, 8, 512, 0};

    static const int *test_drive[] = { test_drive1, test_drive2, test_drive3,
                                       NULL };

    int test_drive_len[100];

    int ret = 0;
    EVP_CIPHER_CTX *evp = NULL;

    int ilen = 0;
    int klen = 0;
    int i, j;

    const EVP_CIPHER *type;
    byte *iv;
    byte *key;
    int ivlen;
    int keylen;

    #define RECORDS 16
    #define BUFFSZ  512
    byte plain [BUFFSZ * RECORDS];
    byte cipher[BUFFSZ * RECORDS];

    byte inb[BUFFSZ];
    byte outb[BUFFSZ+16];
    int outl = 0;
    int inl;

    iv = aes128_cbc_iv;
    ivlen = sizeof(aes128_cbc_iv);
    key = aes128_cbc_key;
    keylen = sizeof(aes128_cbc_key);
    type = EVP_aes_128_cbc();

    set_plain(plain, BUFFSZ * RECORDS);

    ExpectNotNull(evp = EVP_CIPHER_CTX_new());
    ExpectIntNE((ret = EVP_CipherInit(evp, type, NULL, iv, 0)), 0);

    ExpectIntEQ(EVP_CIPHER_CTX_nid(evp), NID_aes_128_cbc);

    klen = EVP_CIPHER_CTX_key_length(evp);
    if (klen > 0 && keylen != klen) {
        ExpectIntNE(EVP_CIPHER_CTX_set_key_length(evp, keylen), 0);
    }
    ilen = EVP_CIPHER_CTX_iv_length(evp);
    if (ilen > 0 && ivlen != ilen) {
        ExpectIntNE(EVP_CIPHER_CTX_set_iv_length(evp, ivlen), 0);
    }

    ExpectIntNE((ret = EVP_CipherInit(evp, NULL, key, iv, 1)), 0);

    for (j = 0; j<RECORDS; j++)
    {
        inl = BUFFSZ;
        get_record(plain, inb, inl);
        ExpectIntNE((ret = EVP_CipherUpdate(evp, outb, &outl, inb, inl)), 0);
        set_record(cipher, outb, outl);
    }

    for (i = 0; test_drive[i]; i++) {

        ExpectIntNE((ret = EVP_CipherInit(evp, NULL, key, iv, 1)), 0);

        init_offset();
        test_drive_len[i] = 0;
        for (j = 0; test_drive[i][j]; j++)
        {
            inl = test_drive[i][j];
            test_drive_len[i] += inl;

            get_record(plain, inb, inl);
            ExpectIntNE((ret = EVP_EncryptUpdate(evp, outb, &outl, inb, inl)),
                0);
            /* output to cipher buffer, so that following Dec test can detect
               if any error */
            set_record(cipher, outb, outl);
        }

        EVP_CipherFinal(evp, outb, &outl);

        if (outl > 0)
            set_record(cipher, outb, outl);
    }

    for (i = 0; test_drive[i]; i++) {
        last_val = 0x0f;

        ExpectIntNE((ret = EVP_CipherInit(evp, NULL, key, iv, 0)), 0);

        init_offset();

        for (j = 0; test_drive[i][j]; j++) {
            inl = test_drive[i][j];
            get_record(cipher, inb, inl);

            ExpectIntNE((ret = EVP_DecryptUpdate(evp, outb, &outl, inb, inl)),
                0);

            binary_dump(outb, outl);
            ExpectIntEQ((ret = check_result(outb, outl)), 0);
            ExpectFalse(outl > ((inl/16+1)*16) && outl > 16);
        }

        ret = EVP_CipherFinal(evp, outb, &outl);

        binary_dump(outb, outl);

        ret = (((test_drive_len[i] % 16) != 0) && (ret == 0)) ||
                 (((test_drive_len[i] % 16) == 0) && (ret == 1));
        ExpectTrue(ret);
    }

    ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_cleanup(evp), WOLFSSL_SUCCESS);

    EVP_CIPHER_CTX_free(evp);
    evp = NULL;

    /* Do an extra test to verify correct behavior with empty input. */

    ExpectNotNull(evp = EVP_CIPHER_CTX_new());
    ExpectIntNE((ret = EVP_CipherInit(evp, type, NULL, iv, 0)), 0);

    ExpectIntEQ(EVP_CIPHER_CTX_nid(evp), NID_aes_128_cbc);

    klen = EVP_CIPHER_CTX_key_length(evp);
    if (klen > 0 && keylen != klen) {
        ExpectIntNE(EVP_CIPHER_CTX_set_key_length(evp, keylen), 0);
    }
    ilen = EVP_CIPHER_CTX_iv_length(evp);
    if (ilen > 0 && ivlen != ilen) {
        ExpectIntNE(EVP_CIPHER_CTX_set_iv_length(evp, ivlen), 0);
    }

    ExpectIntNE((ret = EVP_CipherInit(evp, NULL, key, iv, 1)), 0);

    /* outl should be set to 0 after passing NULL, 0 for input args. */
    outl = -1;
    ExpectIntNE((ret = EVP_CipherUpdate(evp, outb, &outl, NULL, 0)), 0);
    ExpectIntEQ(outl, 0);

    EVP_CIPHER_CTX_free(evp);
#endif /* test_EVP_Cipher */
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_X_STATE(void)
{
    EXPECT_DECLS;
#if !defined(NO_DES3) && !defined(NO_RC4) && defined(OPENSSL_ALL)
    byte key[DES3_KEY_SIZE] = {0};
    byte iv[DES_IV_SIZE] = {0};
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *init = NULL;

    /* Bad test cases */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectNotNull(init = EVP_des_ede3_cbc());

    wolfSSL_EVP_CIPHER_CTX_init(ctx);
    ExpectIntEQ(EVP_CipherInit(ctx, init, key, iv, 1), WOLFSSL_SUCCESS);

    ExpectNull(wolfSSL_EVP_X_STATE(NULL));
    ExpectNull(wolfSSL_EVP_X_STATE(ctx));
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* Good test case */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectNotNull(init = wolfSSL_EVP_rc4());

    wolfSSL_EVP_CIPHER_CTX_init(ctx);
    ExpectIntEQ(EVP_CipherInit(ctx, init, key, iv, 1), WOLFSSL_SUCCESS);

    ExpectNotNull(wolfSSL_EVP_X_STATE(ctx));
    EVP_CIPHER_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}
int test_wolfSSL_EVP_X_STATE_LEN(void)
{
    EXPECT_DECLS;
#if !defined(NO_DES3) && !defined(NO_RC4) && defined(OPENSSL_ALL)
    byte key[DES3_KEY_SIZE] = {0};
    byte iv[DES_IV_SIZE] = {0};
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *init = NULL;

    /* Bad test cases */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectNotNull(init = EVP_des_ede3_cbc());

    wolfSSL_EVP_CIPHER_CTX_init(ctx);
    ExpectIntEQ(EVP_CipherInit(ctx, init, key, iv, 1), WOLFSSL_SUCCESS);

    ExpectIntEQ(wolfSSL_EVP_X_STATE_LEN(NULL), 0);
    ExpectIntEQ(wolfSSL_EVP_X_STATE_LEN(ctx), 0);
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* Good test case */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectNotNull(init = wolfSSL_EVP_rc4());

    wolfSSL_EVP_CIPHER_CTX_init(ctx);
    ExpectIntEQ(EVP_CipherInit(ctx, init, key, iv, 1), WOLFSSL_SUCCESS);

    ExpectIntEQ(wolfSSL_EVP_X_STATE_LEN(ctx), sizeof(Arc4));
    EVP_CIPHER_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}


int test_wolfSSL_EVP_aes_256_gcm(void)
{
    EXPECT_DECLS;
#if defined(HAVE_AESGCM) && defined(WOLFSSL_AES_256) && defined(OPENSSL_ALL)
    ExpectNotNull(wolfSSL_EVP_aes_256_gcm());
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_aes_192_gcm(void)
{
    EXPECT_DECLS;
#if defined(HAVE_AESGCM) && defined(WOLFSSL_AES_192) && defined(OPENSSL_ALL)
    ExpectNotNull(wolfSSL_EVP_aes_192_gcm());
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_aes_128_gcm(void)
{
    EXPECT_DECLS;
#if defined(HAVE_AESGCM) && defined(WOLFSSL_AES_128) && defined(OPENSSL_ALL)
    ExpectNotNull(wolfSSL_EVP_aes_128_gcm());
#endif
    return EXPECT_RESULT();
}

int test_evp_cipher_aes_gcm(void)
{
    EXPECT_DECLS;
#if defined(HAVE_AESGCM) && defined(OPENSSL_ALL) && ((!defined(HAVE_FIPS) && \
    !defined(HAVE_SELFTEST)) || (defined(HAVE_FIPS_VERSION) && \
    (HAVE_FIPS_VERSION >= 2))) && defined(WOLFSSL_AES_256)
    /*
     * This test checks data at various points in the encrypt/decrypt process
     * against known values produced using the same test with OpenSSL. This
     * interop testing is critical for verifying the correctness of our
     * EVP_Cipher implementation with AES-GCM. Specifically, this test exercises
     * a flow supported by OpenSSL that uses the control command
     * EVP_CTRL_GCM_IV_GEN to increment the IV between cipher operations without
     * the need to call EVP_CipherInit. OpenSSH uses this flow, for example. We
     * had a bug with OpenSSH where wolfSSL OpenSSH servers could only talk to
     * wolfSSL OpenSSH clients because there was a bug in this flow that
     * happened to "cancel out" if both sides of the connection had the bug.
     */
    enum {
        NUM_ENCRYPTIONS = 3,
        AAD_SIZE = 4
    };
    static const byte plainText1[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23
    };
    static const byte plainText2[] = {
        0x42, 0x49, 0x3b, 0x27, 0x03, 0x35, 0x59, 0x14, 0x41, 0x47, 0x37, 0x14,
        0x0e, 0x34, 0x0d, 0x28, 0x63, 0x09, 0x0a, 0x5b, 0x22, 0x57, 0x42, 0x22,
        0x0f, 0x5c, 0x1e, 0x53, 0x45, 0x15, 0x62, 0x08, 0x60, 0x43, 0x50, 0x2c
    };
    static const byte plainText3[] = {
        0x36, 0x0d, 0x2b, 0x09, 0x4a, 0x56, 0x3b, 0x4c, 0x21, 0x22, 0x58, 0x0e,
        0x5b, 0x57, 0x10
    };
    static const byte* plainTexts[NUM_ENCRYPTIONS] = {
        plainText1,
        plainText2,
        plainText3
    };
    static const int plainTextSzs[NUM_ENCRYPTIONS] = {
        sizeof(plainText1),
        sizeof(plainText2),
        sizeof(plainText3)
    };
    static const byte aad1[AAD_SIZE] = {
        0x00, 0x00, 0x00, 0x01
    };
    static const byte aad2[AAD_SIZE] = {
        0x00, 0x00, 0x00, 0x10
    };
    static const byte aad3[AAD_SIZE] = {
        0x00, 0x00, 0x01, 0x00
    };
    static const byte* aads[NUM_ENCRYPTIONS] = {
        aad1,
        aad2,
        aad3
    };
    const byte iv[GCM_NONCE_MID_SZ] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF
    };
    byte currentIv[GCM_NONCE_MID_SZ];
    const byte key[] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
    };
    const byte expIvs[NUM_ENCRYPTIONS][GCM_NONCE_MID_SZ] = {
        {
            0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE,
            0xEF
        },
        {
            0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE,
            0xF0
        },
        {
            0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE,
            0xF1
        }
    };
    const byte expTags[NUM_ENCRYPTIONS][AES_BLOCK_SIZE] = {
        {
            0x65, 0x4F, 0xF7, 0xA0, 0xBB, 0x7B, 0x90, 0xB7, 0x9C, 0xC8, 0x14,
            0x3D, 0x32, 0x18, 0x34, 0xA9
        },
        {
            0x50, 0x3A, 0x13, 0x8D, 0x91, 0x1D, 0xEC, 0xBB, 0xBA, 0x5B, 0x57,
            0xA2, 0xFD, 0x2D, 0x6B, 0x7F
        },
        {
            0x3B, 0xED, 0x18, 0x9C, 0xB3, 0xE3, 0x61, 0x1E, 0x11, 0xEB, 0x13,
            0x5B, 0xEC, 0x52, 0x49, 0x32,
        }
    };
    static const byte expCipherText1[] = {
        0xCB, 0x93, 0x4F, 0xC8, 0x22, 0xE2, 0xC0, 0x35, 0xAA, 0x6B, 0x41, 0x15,
        0x17, 0x30, 0x2F, 0x97, 0x20, 0x74, 0x39, 0x28, 0xF8, 0xEB, 0xC5, 0x51,
        0x7B, 0xD9, 0x8A, 0x36, 0xB8, 0xDA, 0x24, 0x80, 0xE7, 0x9E, 0x09, 0xDE
    };
    static const byte expCipherText2[] = {
        0xF9, 0x32, 0xE1, 0x87, 0x37, 0x0F, 0x04, 0xC1, 0xB5, 0x59, 0xF0, 0x45,
        0x3A, 0x0D, 0xA0, 0x26, 0xFF, 0xA6, 0x8D, 0x38, 0xFE, 0xB8, 0xE5, 0xC2,
        0x2A, 0x98, 0x4A, 0x54, 0x8F, 0x1F, 0xD6, 0x13, 0x03, 0xB2, 0x1B, 0xC0
    };
    static const byte expCipherText3[] = {
        0xD0, 0x37, 0x59, 0x1C, 0x2F, 0x85, 0x39, 0x4D, 0xED, 0xC2, 0x32, 0x5B,
        0x80, 0x5E, 0x6B,
    };
    static const byte* expCipherTexts[NUM_ENCRYPTIONS] = {
        expCipherText1,
        expCipherText2,
        expCipherText3
    };
    byte* cipherText = NULL;
    byte* calcPlainText = NULL;
    byte tag[AES_BLOCK_SIZE];
    EVP_CIPHER_CTX* encCtx = NULL;
    EVP_CIPHER_CTX* decCtx = NULL;
    int i, j, outl;

    /****************************************************/
    for (i = 0; i < 3; ++i) {
        ExpectNotNull(encCtx = EVP_CIPHER_CTX_new());
        ExpectNotNull(decCtx = EVP_CIPHER_CTX_new());

        /* First iteration, set key before IV. */
        if (i == 0) {
            ExpectIntEQ(EVP_CipherInit(encCtx, EVP_aes_256_gcm(), key, NULL, 1),
                        SSL_SUCCESS);

            /*
             * The call to EVP_CipherInit below (with NULL key) should clear the
             * authIvGenEnable flag set by EVP_CTRL_GCM_SET_IV_FIXED. As such, a
             * subsequent EVP_CTRL_GCM_IV_GEN should fail. This matches OpenSSL
             * behavior.
             */
            ExpectIntEQ(EVP_CIPHER_CTX_ctrl(encCtx, EVP_CTRL_GCM_SET_IV_FIXED,
                        -1, (void*)iv), SSL_SUCCESS);
            ExpectIntEQ(EVP_CipherInit(encCtx, NULL, NULL, iv, 1),
                        SSL_SUCCESS);
            ExpectIntEQ(EVP_CIPHER_CTX_ctrl(encCtx, EVP_CTRL_GCM_IV_GEN, -1,
                        currentIv), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

            ExpectIntEQ(EVP_CipherInit(decCtx, EVP_aes_256_gcm(), key, NULL, 0),
                        SSL_SUCCESS);
            ExpectIntEQ(EVP_CipherInit(decCtx, NULL, NULL, iv, 0),
                        SSL_SUCCESS);
        }
        /* Second iteration, IV before key. */
        else {
            ExpectIntEQ(EVP_CipherInit(encCtx, EVP_aes_256_gcm(), NULL, iv, 1),
                        SSL_SUCCESS);
            ExpectIntEQ(EVP_CipherInit(encCtx, NULL, key, NULL, 1),
                        SSL_SUCCESS);
            ExpectIntEQ(EVP_CipherInit(decCtx, EVP_aes_256_gcm(), NULL, iv, 0),
                        SSL_SUCCESS);
            ExpectIntEQ(EVP_CipherInit(decCtx, NULL, key, NULL, 0),
                        SSL_SUCCESS);
        }

        /*
         * EVP_CTRL_GCM_IV_GEN should fail if EVP_CTRL_GCM_SET_IV_FIXED hasn't
         * been issued first.
         */
        ExpectIntEQ(EVP_CIPHER_CTX_ctrl(encCtx, EVP_CTRL_GCM_IV_GEN, -1,
                        currentIv), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

        ExpectIntEQ(EVP_CIPHER_CTX_ctrl(encCtx, EVP_CTRL_GCM_SET_IV_FIXED, -1,
                    (void*)iv), SSL_SUCCESS);
        ExpectIntEQ(EVP_CIPHER_CTX_ctrl(decCtx, EVP_CTRL_GCM_SET_IV_FIXED, -1,
                    (void*)iv), SSL_SUCCESS);

        for (j = 0; j < NUM_ENCRYPTIONS; ++j) {
            /*************** Encrypt ***************/
            ExpectIntEQ(EVP_CIPHER_CTX_ctrl(encCtx, EVP_CTRL_GCM_IV_GEN, -1,
                        currentIv), SSL_SUCCESS);
            /* Check current IV against expected. */
            ExpectIntEQ(XMEMCMP(currentIv, expIvs[j], GCM_NONCE_MID_SZ), 0);

            /* Add AAD. */
            if (i == 2) {
                /* Test streaming API. */
                ExpectIntEQ(EVP_CipherUpdate(encCtx, NULL, &outl, aads[j],
                                             AAD_SIZE), SSL_SUCCESS);
            }
            else {
                ExpectIntEQ(EVP_Cipher(encCtx, NULL, (byte *)aads[j], AAD_SIZE),
                                       AAD_SIZE);
            }

            ExpectNotNull(cipherText = (byte*)XMALLOC(plainTextSzs[j], NULL,
                          DYNAMIC_TYPE_TMP_BUFFER));

            /* Encrypt plaintext. */
            if (i == 2) {
                ExpectIntEQ(EVP_CipherUpdate(encCtx, cipherText, &outl,
                                             plainTexts[j], plainTextSzs[j]),
                            SSL_SUCCESS);
            }
            else {
                ExpectIntEQ(EVP_Cipher(encCtx, cipherText,
                            (byte *)plainTexts[j], plainTextSzs[j]),
                            plainTextSzs[j]);
            }

            if (i == 2) {
                ExpectIntEQ(EVP_CipherFinal(encCtx, cipherText, &outl),
                            SSL_SUCCESS);
            }
            else {
                /*
                 * Calling EVP_Cipher with NULL input and output for AES-GCM is
                 * akin to calling EVP_CipherFinal.
                 */
                ExpectIntGE(EVP_Cipher(encCtx, NULL, NULL, 0), 0);
            }

            /* Check ciphertext against expected. */
            ExpectIntEQ(XMEMCMP(cipherText, expCipherTexts[j], plainTextSzs[j]),
                        0);

            /* Get and check tag against expected. */
            ExpectIntEQ(EVP_CIPHER_CTX_ctrl(encCtx, EVP_CTRL_GCM_GET_TAG,
                        sizeof(tag), tag), SSL_SUCCESS);
            ExpectIntEQ(XMEMCMP(tag, expTags[j], sizeof(tag)), 0);

            /*************** Decrypt ***************/
            ExpectIntEQ(EVP_CIPHER_CTX_ctrl(decCtx, EVP_CTRL_GCM_IV_GEN, -1,
                        currentIv), SSL_SUCCESS);
            /* Check current IV against expected. */
            ExpectIntEQ(XMEMCMP(currentIv, expIvs[j], GCM_NONCE_MID_SZ), 0);

            /* Add AAD. */
            if (i == 2) {
                /* Test streaming API. */
                ExpectIntEQ(EVP_CipherUpdate(decCtx, NULL, &outl, aads[j],
                                             AAD_SIZE), SSL_SUCCESS);
            }
            else {
                ExpectIntEQ(EVP_Cipher(decCtx, NULL, (byte *)aads[j], AAD_SIZE),
                            AAD_SIZE);
            }

            /* Set expected tag. */
            ExpectIntEQ(EVP_CIPHER_CTX_ctrl(decCtx, EVP_CTRL_GCM_SET_TAG,
                        sizeof(tag), tag), SSL_SUCCESS);

            /* Decrypt ciphertext. */
            ExpectNotNull(calcPlainText = (byte*)XMALLOC(plainTextSzs[j], NULL,
                          DYNAMIC_TYPE_TMP_BUFFER));
            if (i == 2) {
                ExpectIntEQ(EVP_CipherUpdate(decCtx, calcPlainText, &outl,
                                             cipherText, plainTextSzs[j]),
                            SSL_SUCCESS);
            }
            else {
                /* This first EVP_Cipher call will check the tag, too. */
                ExpectIntEQ(EVP_Cipher(decCtx, calcPlainText, cipherText,
                        plainTextSzs[j]), plainTextSzs[j]);
            }

            if (i == 2) {
                ExpectIntEQ(EVP_CipherFinal(decCtx, calcPlainText, &outl),
                            SSL_SUCCESS);
            }
            else {
                ExpectIntGE(EVP_Cipher(decCtx, NULL, NULL, 0), 0);
            }

            /* Check plaintext against expected. */
            ExpectIntEQ(XMEMCMP(calcPlainText, plainTexts[j], plainTextSzs[j]),
                        0);

            XFREE(cipherText, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            cipherText = NULL;
            XFREE(calcPlainText, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            calcPlainText = NULL;
        }

        EVP_CIPHER_CTX_free(encCtx);
        encCtx = NULL;
        EVP_CIPHER_CTX_free(decCtx);
        decCtx = NULL;
    }
#endif
    return EXPECT_RESULT();
}

int test_wolfssl_EVP_aes_gcm(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_AES) && defined(HAVE_AESGCM) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
    /* A 256 bit key, AES_128 will use the first 128 bit*/
    byte *key = (byte*)"01234567890123456789012345678901";
    /* A 128 bit IV */
    byte *iv = (byte*)"0123456789012345";
    int ivSz = AES_BLOCK_SIZE;
    /* Message to be encrypted */
    byte *plaintxt = (byte*)"for things to change you have to change";
    /* Additional non-confidential data */
    byte *aad = (byte*)"Don't spend major time on minor things.";

    unsigned char tag[AES_BLOCK_SIZE] = {0};
    int plaintxtSz = (int)XSTRLEN((char*)plaintxt);
    int aadSz = (int)XSTRLEN((char*)aad);
    byte ciphertxt[AES_BLOCK_SIZE * 4] = {0};
    byte decryptedtxt[AES_BLOCK_SIZE * 4] = {0};
    int ciphertxtSz = 0;
    int decryptedtxtSz = 0;
    int len = 0;
    int i = 0;
    EVP_CIPHER_CTX en[2];
    EVP_CIPHER_CTX de[2];

    for (i = 0; i < 2; i++) {
        EVP_CIPHER_CTX_init(&en[i]);
        if (i == 0) {
            /* Default uses 96-bits IV length */
#ifdef WOLFSSL_AES_128
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aes_128_gcm(), NULL,
                key, iv));
#elif defined(WOLFSSL_AES_192)
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aes_192_gcm(), NULL,
                key, iv));
#elif defined(WOLFSSL_AES_256)
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aes_256_gcm(), NULL,
                key, iv));
#endif
        }
        else {
#ifdef WOLFSSL_AES_128
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aes_128_gcm(), NULL,
                NULL, NULL));
#elif defined(WOLFSSL_AES_192)
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aes_192_gcm(), NULL,
                NULL, NULL));
#elif defined(WOLFSSL_AES_256)
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aes_256_gcm(), NULL,
                NULL, NULL));
#endif
             /* non-default must to set the IV length first */
            ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&en[i], EVP_CTRL_GCM_SET_IVLEN,
                ivSz, NULL));
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], NULL, NULL, key, iv));
        }
        ExpectIntEQ(1, EVP_EncryptUpdate(&en[i], NULL, &len, aad, aadSz));
        ExpectIntEQ(1, EVP_EncryptUpdate(&en[i], ciphertxt, &len, plaintxt,
            plaintxtSz));
        ciphertxtSz = len;
        ExpectIntEQ(1, EVP_EncryptFinal_ex(&en[i], ciphertxt, &len));
        ciphertxtSz += len;
        ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&en[i], EVP_CTRL_GCM_GET_TAG,
            AES_BLOCK_SIZE, tag));
        wolfSSL_EVP_CIPHER_CTX_cleanup(&en[i]);

        EVP_CIPHER_CTX_init(&de[i]);
        if (i == 0) {
            /* Default uses 96-bits IV length */
#ifdef WOLFSSL_AES_128
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_128_gcm(), NULL,
                key, iv));
#elif defined(WOLFSSL_AES_192)
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_192_gcm(), NULL,
                key, iv));
#elif defined(WOLFSSL_AES_256)
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_256_gcm(), NULL,
                key, iv));
#endif
        }
        else {
#ifdef WOLFSSL_AES_128
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_128_gcm(), NULL,
                NULL, NULL));
#elif defined(WOLFSSL_AES_192)
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_192_gcm(), NULL,
                NULL, NULL));
#elif defined(WOLFSSL_AES_256)
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_256_gcm(), NULL,
                NULL, NULL));
#endif
            /* non-default must to set the IV length first */
            ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_GCM_SET_IVLEN,
                ivSz, NULL));
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], NULL, NULL, key, iv));

        }
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], NULL, &len, aad, aadSz));
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], decryptedtxt, &len, ciphertxt,
            ciphertxtSz));
        decryptedtxtSz = len;
        ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_GCM_SET_TAG,
            AES_BLOCK_SIZE, tag));
        ExpectIntEQ(1, EVP_DecryptFinal_ex(&de[i], decryptedtxt, &len));
        decryptedtxtSz += len;
        ExpectIntEQ(ciphertxtSz, decryptedtxtSz);
        ExpectIntEQ(0, XMEMCMP(plaintxt, decryptedtxt, decryptedtxtSz));

        /* modify tag*/
        if (i == 0) {
            /* Default uses 96-bits IV length */
#ifdef WOLFSSL_AES_128
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_128_gcm(), NULL,
                key, iv));
#elif defined(WOLFSSL_AES_192)
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_192_gcm(), NULL,
                key, iv));
#elif defined(WOLFSSL_AES_256)
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_256_gcm(), NULL,
                key, iv));
#endif
        }
        else {
#ifdef WOLFSSL_AES_128
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_128_gcm(), NULL,
                NULL, NULL));
#elif defined(WOLFSSL_AES_192)
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_192_gcm(), NULL,
                NULL, NULL));
#elif defined(WOLFSSL_AES_256)
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_256_gcm(), NULL,
                NULL, NULL));
#endif
            /* non-default must to set the IV length first */
            ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_GCM_SET_IVLEN,
                ivSz, NULL));
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], NULL, NULL, key, iv));

        }
        tag[AES_BLOCK_SIZE-1]+=0xBB;
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], NULL, &len, aad, aadSz));
        ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_GCM_SET_TAG,
            AES_BLOCK_SIZE, tag));
        /* fail due to wrong tag */
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], decryptedtxt, &len, ciphertxt,
            ciphertxtSz));
        ExpectIntEQ(0, EVP_DecryptFinal_ex(&de[i], decryptedtxt, &len));
        ExpectIntEQ(0, len);

        wolfSSL_EVP_CIPHER_CTX_cleanup(&de[i]);
    }
#endif /* OPENSSL_EXTRA && !NO_AES && HAVE_AESGCM */
    return EXPECT_RESULT();
}

int test_wolfssl_EVP_aes_gcm_AAD_2_parts(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_AES) && defined(HAVE_AESGCM) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
    const byte iv[12] = { 0 };
    const byte key[16] = { 0 };
    const byte cleartext[16] = { 0 };
    const byte aad[] = {
        0x01, 0x10, 0x00, 0x2a, 0x08, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
        0x00, 0x00, 0xdc, 0x4d, 0xad, 0x6b, 0x06, 0x93,
        0x4f
    };
    byte out1Part[16];
    byte outTag1Part[16];
    byte out2Part[16];
    byte outTag2Part[16];
    byte decryptBuf[16];
    int len = 0;
    int tlen;
    EVP_CIPHER_CTX* ctx = NULL;

    /* ENCRYPT */
    /* Send AAD and data in 1 part */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    tlen = 0;
    ExpectIntEQ(EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL),
                1);
    ExpectIntEQ(EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv), 1);
    ExpectIntEQ(EVP_EncryptUpdate(ctx, NULL, &len, aad, sizeof(aad)), 1);
    ExpectIntEQ(EVP_EncryptUpdate(ctx, out1Part, &len, cleartext,
                                  sizeof(cleartext)), 1);
    tlen += len;
    ExpectIntEQ(EVP_EncryptFinal_ex(ctx, out1Part, &len), 1);
    tlen += len;
    ExpectIntEQ(tlen, sizeof(cleartext));
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16,
                                    outTag1Part), 1);
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* DECRYPT */
    /* Send AAD and data in 1 part */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    tlen = 0;
    ExpectIntEQ(EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL),
                1);
    ExpectIntEQ(EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv), 1);
    ExpectIntEQ(EVP_DecryptUpdate(ctx, NULL, &len, aad, sizeof(aad)), 1);
    ExpectIntEQ(EVP_DecryptUpdate(ctx, decryptBuf, &len, out1Part,
                                  sizeof(cleartext)), 1);
    tlen += len;
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16,
                                    outTag1Part), 1);
    ExpectIntEQ(EVP_DecryptFinal_ex(ctx, decryptBuf, &len), 1);
    tlen += len;
    ExpectIntEQ(tlen, sizeof(cleartext));
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    ExpectIntEQ(XMEMCMP(decryptBuf, cleartext, len), 0);

    /* ENCRYPT */
    /* Send AAD and data in 2 parts */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    tlen = 0;
    ExpectIntEQ(EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL),
                1);
    ExpectIntEQ(EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv), 1);
    ExpectIntEQ(EVP_EncryptUpdate(ctx, NULL, &len, aad, 1), 1);
    ExpectIntEQ(EVP_EncryptUpdate(ctx, NULL, &len, aad + 1, sizeof(aad) - 1),
                1);
    ExpectIntEQ(EVP_EncryptUpdate(ctx, out2Part, &len, cleartext, 1), 1);
    tlen += len;
    ExpectIntEQ(EVP_EncryptUpdate(ctx, out2Part + tlen, &len, cleartext + 1,
                                  sizeof(cleartext) - 1), 1);
    tlen += len;
    ExpectIntEQ(EVP_EncryptFinal_ex(ctx, out2Part + tlen, &len), 1);
    tlen += len;
    ExpectIntEQ(tlen, sizeof(cleartext));
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16,
                                    outTag2Part), 1);

    ExpectIntEQ(XMEMCMP(out1Part, out2Part, sizeof(out1Part)), 0);
    ExpectIntEQ(XMEMCMP(outTag1Part, outTag2Part, sizeof(outTag1Part)), 0);
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* DECRYPT */
    /* Send AAD and data in 2 parts */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    tlen = 0;
    ExpectIntEQ(EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL),
                1);
    ExpectIntEQ(EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv), 1);
    ExpectIntEQ(EVP_DecryptUpdate(ctx, NULL, &len, aad, 1), 1);
    ExpectIntEQ(EVP_DecryptUpdate(ctx, NULL, &len, aad + 1, sizeof(aad) - 1),
                1);
    ExpectIntEQ(EVP_DecryptUpdate(ctx, decryptBuf, &len, out1Part, 1), 1);
    tlen += len;
    ExpectIntEQ(EVP_DecryptUpdate(ctx, decryptBuf + tlen, &len, out1Part + 1,
                                  sizeof(cleartext) - 1), 1);
    tlen += len;
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16,
                                    outTag1Part), 1);
    ExpectIntEQ(EVP_DecryptFinal_ex(ctx, decryptBuf + tlen, &len), 1);
    tlen += len;
    ExpectIntEQ(tlen, sizeof(cleartext));

    ExpectIntEQ(XMEMCMP(decryptBuf, cleartext, len), 0);

    /* Test AAD reuse */
    EVP_CIPHER_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfssl_EVP_aes_gcm_zeroLen(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_AES) && defined(HAVE_AESGCM) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS) && defined(WOLFSSL_AES_256)
    /* Zero length plain text */
    byte key[] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    }; /* align */
    byte iv[]  = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    }; /* align */
    byte plaintxt[1];
    int ivSz  = 12;
    int plaintxtSz = 0;
    unsigned char tag[16];
    unsigned char tag_kat[] = {
        0x53,0x0f,0x8a,0xfb,0xc7,0x45,0x36,0xb9,
        0xa9,0x63,0xb4,0xf1,0xc4,0xcb,0x73,0x8b
    };

    byte ciphertxt[AES_BLOCK_SIZE * 4] = {0};
    byte decryptedtxt[AES_BLOCK_SIZE * 4] = {0};
    int ciphertxtSz = 0;
    int decryptedtxtSz = 0;
    int len = 0;

    EVP_CIPHER_CTX *en = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *de = EVP_CIPHER_CTX_new();

    ExpectIntEQ(1, EVP_EncryptInit_ex(en, EVP_aes_256_gcm(), NULL, key, iv));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(en, EVP_CTRL_GCM_SET_IVLEN, ivSz, NULL));
    ExpectIntEQ(1, EVP_EncryptUpdate(en, ciphertxt, &ciphertxtSz , plaintxt,
        plaintxtSz));
    ExpectIntEQ(1, EVP_EncryptFinal_ex(en, ciphertxt, &len));
    ciphertxtSz += len;
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(en, EVP_CTRL_GCM_GET_TAG, 16, tag));
    ExpectIntEQ(1, EVP_CIPHER_CTX_cleanup(en));

    ExpectIntEQ(0, ciphertxtSz);
    ExpectIntEQ(0, XMEMCMP(tag, tag_kat, sizeof(tag)));

    EVP_CIPHER_CTX_init(de);
    ExpectIntEQ(1, EVP_DecryptInit_ex(de, EVP_aes_256_gcm(), NULL, key, iv));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(de, EVP_CTRL_GCM_SET_IVLEN, ivSz, NULL));
    ExpectIntEQ(1, EVP_DecryptUpdate(de, NULL, &len, ciphertxt, len));
    decryptedtxtSz = len;
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(de, EVP_CTRL_GCM_SET_TAG, 16, tag));
    ExpectIntEQ(1, EVP_DecryptFinal_ex(de, decryptedtxt, &len));
    decryptedtxtSz += len;
    ExpectIntEQ(0, decryptedtxtSz);

    EVP_CIPHER_CTX_free(en);
    EVP_CIPHER_CTX_free(de);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_aes_256_ccm(void)
{
    EXPECT_DECLS;
#if defined(HAVE_AESCCM) && defined(WOLFSSL_AES_256) && defined(OPENSSL_ALL)
    ExpectNotNull(wolfSSL_EVP_aes_256_ccm());
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_aes_192_ccm(void)
{
    EXPECT_DECLS;
#if defined(HAVE_AESCCM) && defined(WOLFSSL_AES_192) && defined(OPENSSL_ALL)
    ExpectNotNull(wolfSSL_EVP_aes_192_ccm());
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_aes_128_ccm(void)
{
    EXPECT_DECLS;
#if defined(HAVE_AESCCM) && defined(WOLFSSL_AES_128) && defined(OPENSSL_ALL)
    ExpectNotNull(wolfSSL_EVP_aes_128_ccm());
#endif
    return EXPECT_RESULT();
}

int test_wolfssl_EVP_aes_ccm(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_AES) && defined(HAVE_AESCCM) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
    /* A 256 bit key, AES_128 will use the first 128 bit*/
    byte *key = (byte*)"01234567890123456789012345678901";
    /* A 128 bit IV */
    byte *iv = (byte*)"0123456789012";
    int ivSz = (int)XSTRLEN((char*)iv);
    /* Message to be encrypted */
    byte *plaintxt = (byte*)"for things to change you have to change";
    /* Additional non-confidential data */
    byte *aad = (byte*)"Don't spend major time on minor things.";

    unsigned char tag[AES_BLOCK_SIZE] = {0};
    int plaintxtSz = (int)XSTRLEN((char*)plaintxt);
    int aadSz = (int)XSTRLEN((char*)aad);
    byte ciphertxt[AES_BLOCK_SIZE * 4] = {0};
    byte decryptedtxt[AES_BLOCK_SIZE * 4] = {0};
    int ciphertxtSz = 0;
    int decryptedtxtSz = 0;
    int len = 0;
    int i = 0;
    int ret;
    EVP_CIPHER_CTX en[2];
    EVP_CIPHER_CTX de[2];

    for (i = 0; i < 2; i++) {
        EVP_CIPHER_CTX_init(&en[i]);

        if (i == 0) {
            /* Default uses 96-bits IV length */
#ifdef WOLFSSL_AES_128
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aes_128_ccm(), NULL,
                key, iv));
#elif defined(WOLFSSL_AES_192)
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aes_192_ccm(), NULL,
                key, iv));
#elif defined(WOLFSSL_AES_256)
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aes_256_ccm(), NULL,
                key, iv));
#endif
        }
        else {
#ifdef WOLFSSL_AES_128
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aes_128_ccm(), NULL,
                NULL, NULL));
#elif defined(WOLFSSL_AES_192)
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aes_192_ccm(), NULL,
                NULL, NULL));
#elif defined(WOLFSSL_AES_256)
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aes_256_ccm(), NULL,
                NULL, NULL));
#endif
             /* non-default must to set the IV length first */
            ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&en[i], EVP_CTRL_CCM_SET_IVLEN,
                ivSz, NULL));
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], NULL, NULL, key, iv));
        }
        ExpectIntEQ(1, EVP_EncryptUpdate(&en[i], NULL, &len, aad, aadSz));
        ExpectIntEQ(1, EVP_EncryptUpdate(&en[i], ciphertxt, &len, plaintxt,
              plaintxtSz));
        ciphertxtSz = len;
        ExpectIntEQ(1, EVP_EncryptFinal_ex(&en[i], ciphertxt, &len));
        ciphertxtSz += len;
        ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&en[i], EVP_CTRL_CCM_GET_TAG,
            AES_BLOCK_SIZE, tag));
        ret = wolfSSL_EVP_CIPHER_CTX_cleanup(&en[i]);
        ExpectIntEQ(ret, 1);

        EVP_CIPHER_CTX_init(&de[i]);
        if (i == 0) {
            /* Default uses 96-bits IV length */
#ifdef WOLFSSL_AES_128
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_128_ccm(), NULL,
                key, iv));
#elif defined(WOLFSSL_AES_192)
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_192_ccm(), NULL,
                key, iv));
#elif defined(WOLFSSL_AES_256)
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_256_ccm(), NULL,
                key, iv));
#endif
        }
        else {
#ifdef WOLFSSL_AES_128
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_128_ccm(), NULL,
                NULL, NULL));
#elif defined(WOLFSSL_AES_192)
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_192_ccm(), NULL,
                NULL, NULL));
#elif defined(WOLFSSL_AES_256)
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aes_256_ccm(), NULL,
                NULL, NULL));
#endif
            /* non-default must to set the IV length first */
            ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_CCM_SET_IVLEN,
                ivSz, NULL));
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], NULL, NULL, key, iv));

        }
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], NULL, &len, aad, aadSz));
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], decryptedtxt, &len, ciphertxt,
            ciphertxtSz));
        decryptedtxtSz = len;
        ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_CCM_SET_TAG,
            AES_BLOCK_SIZE, tag));
        ExpectIntEQ(1, EVP_DecryptFinal_ex(&de[i], decryptedtxt, &len));
        decryptedtxtSz += len;
        ExpectIntEQ(ciphertxtSz, decryptedtxtSz);
        ExpectIntEQ(0, XMEMCMP(plaintxt, decryptedtxt, decryptedtxtSz));

        /* modify tag*/
        tag[AES_BLOCK_SIZE-1]+=0xBB;
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], NULL, &len, aad, aadSz));
        ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_CCM_SET_TAG,
            AES_BLOCK_SIZE, tag));
        /* fail due to wrong tag */
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], decryptedtxt, &len, ciphertxt,
            ciphertxtSz));
        ExpectIntEQ(0, EVP_DecryptFinal_ex(&de[i], decryptedtxt, &len));
        ExpectIntEQ(0, len);
        ret = wolfSSL_EVP_CIPHER_CTX_cleanup(&de[i]);
        ExpectIntEQ(ret, 1);
    }
#endif /* OPENSSL_EXTRA && !NO_AES && HAVE_AESCCM */
    return EXPECT_RESULT();
}

int test_wolfssl_EVP_aes_ccm_zeroLen(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_AES) && defined(HAVE_AESCCM) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS) && defined(WOLFSSL_AES_256)
    /* Zero length plain text */
    byte key[] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    }; /* align */
    byte iv[]  = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    }; /* align */
    byte plaintxt[1];
    int ivSz  = 12;
    int plaintxtSz = 0;
    unsigned char tag[16];

    byte ciphertxt[AES_BLOCK_SIZE * 4] = {0};
    byte decryptedtxt[AES_BLOCK_SIZE * 4] = {0};
    int ciphertxtSz = 0;
    int decryptedtxtSz = 0;
    int len = 0;

    EVP_CIPHER_CTX *en = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *de = EVP_CIPHER_CTX_new();

    ExpectIntEQ(1, EVP_EncryptInit_ex(en, EVP_aes_256_ccm(), NULL, key, iv));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(en, EVP_CTRL_CCM_SET_IVLEN, ivSz, NULL));
    ExpectIntEQ(1, EVP_EncryptUpdate(en, ciphertxt, &ciphertxtSz , plaintxt,
                                     plaintxtSz));
    ExpectIntEQ(1, EVP_EncryptFinal_ex(en, ciphertxt, &len));
    ciphertxtSz += len;
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(en, EVP_CTRL_CCM_GET_TAG, 16, tag));
    ExpectIntEQ(1, EVP_CIPHER_CTX_cleanup(en));

    ExpectIntEQ(0, ciphertxtSz);

    EVP_CIPHER_CTX_init(de);
    ExpectIntEQ(1, EVP_DecryptInit_ex(de, EVP_aes_256_ccm(), NULL, key, iv));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(de, EVP_CTRL_CCM_SET_IVLEN, ivSz, NULL));
    ExpectIntEQ(1, EVP_DecryptUpdate(de, NULL, &len, ciphertxt, len));
    decryptedtxtSz = len;
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(de, EVP_CTRL_CCM_SET_TAG, 16, tag));
    ExpectIntEQ(1, EVP_DecryptFinal_ex(de, decryptedtxt, &len));
    decryptedtxtSz += len;
    ExpectIntEQ(0, decryptedtxtSz);

    EVP_CIPHER_CTX_free(en);
    EVP_CIPHER_CTX_free(de);
#endif
    return EXPECT_RESULT();
}

int test_wolfssl_EVP_chacha20(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_CHACHA)
    byte key[CHACHA_MAX_KEY_SZ];
    byte iv [WOLFSSL_EVP_CHACHA_IV_BYTES];
    byte plainText[] = {0xDE, 0xAD, 0xBE, 0xEF};
    byte cipherText[sizeof(plainText)];
    byte decryptedText[sizeof(plainText)];
    EVP_CIPHER_CTX* ctx = NULL;
    int outSz;

    XMEMSET(key, 0, sizeof(key));
    XMEMSET(iv, 0, sizeof(iv));
    /* Encrypt. */
    ExpectNotNull((ctx = EVP_CIPHER_CTX_new()));
    ExpectIntEQ(EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, NULL,
                NULL), WOLFSSL_SUCCESS);
    /* Any tag length must fail - not an AEAD cipher. */
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                16, NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_EncryptUpdate(ctx, cipherText, &outSz, plainText,
                sizeof(plainText)), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, sizeof(plainText));
    ExpectIntEQ(EVP_EncryptFinal_ex(ctx, cipherText, &outSz), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, 0);
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* Decrypt. */
    ExpectNotNull((ctx = EVP_CIPHER_CTX_new()));
    ExpectIntEQ(EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, NULL,
                NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DecryptUpdate(ctx, decryptedText, &outSz, cipherText,
                sizeof(cipherText)), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, sizeof(cipherText));
    ExpectIntEQ(EVP_DecryptFinal_ex(ctx, decryptedText, &outSz),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, 0);
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* Test partial Inits. CipherInit() allow setting of key and iv
     * in separate calls. */
    ExpectNotNull((ctx = EVP_CIPHER_CTX_new()));
    ExpectIntEQ(wolfSSL_EVP_CipherInit(ctx, EVP_chacha20(),
                key, NULL, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_EVP_CipherInit(ctx, NULL, NULL, iv, 1),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DecryptUpdate(ctx, decryptedText, &outSz, cipherText,
                sizeof(cipherText)), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, sizeof(cipherText));
    ExpectIntEQ(EVP_DecryptFinal_ex(ctx, decryptedText, &outSz),
            WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, 0);
    EVP_CIPHER_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfssl_EVP_chacha20_poly1305(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    byte key[CHACHA20_POLY1305_AEAD_KEYSIZE];
    byte iv [CHACHA20_POLY1305_AEAD_IV_SIZE];
    byte plainText[] = {0xDE, 0xAD, 0xBE, 0xEF};
    byte aad[] = {0xAA, 0XBB, 0xCC, 0xDD, 0xEE, 0xFF};
    byte cipherText[sizeof(plainText)];
    byte decryptedText[sizeof(plainText)];
    byte tag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    EVP_CIPHER_CTX* ctx = NULL;
    int outSz;

    XMEMSET(key, 0, sizeof(key));
    XMEMSET(iv, 0, sizeof(iv));

    /* Encrypt. */
    ExpectNotNull((ctx = EVP_CIPHER_CTX_new()));
    ExpectIntEQ(EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL,
                NULL), WOLFSSL_SUCCESS);
    /* Invalid IV length. */
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                CHACHA20_POLY1305_AEAD_IV_SIZE-1, NULL),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    /* Valid IV length. */
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                CHACHA20_POLY1305_AEAD_IV_SIZE, NULL), WOLFSSL_SUCCESS);
    /* Invalid tag length. */
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE-1, NULL),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    /* Valid tag length. */
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE, NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_EncryptUpdate(ctx, NULL, &outSz, aad, sizeof(aad)),
               WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, sizeof(aad));
    ExpectIntEQ(EVP_EncryptUpdate(ctx, cipherText, &outSz, plainText,
                sizeof(plainText)), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, sizeof(plainText));
    ExpectIntEQ(EVP_EncryptFinal_ex(ctx, cipherText, &outSz), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, 0);
    /* Invalid tag length. */
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE-1, tag),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    /* Valid tag length. */
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE, tag), WOLFSSL_SUCCESS);
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* Decrypt. */
    ExpectNotNull((ctx = EVP_CIPHER_CTX_new()));
    ExpectIntEQ(EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL,
                NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                CHACHA20_POLY1305_AEAD_IV_SIZE, NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE, tag), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DecryptUpdate(ctx, NULL, &outSz, aad, sizeof(aad)),
               WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, sizeof(aad));
    ExpectIntEQ(EVP_DecryptUpdate(ctx, decryptedText, &outSz, cipherText,
                sizeof(cipherText)), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, sizeof(cipherText));
    ExpectIntEQ(EVP_DecryptFinal_ex(ctx, decryptedText, &outSz),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, 0);
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* Test partial Inits. CipherInit() allow setting of key and iv
     * in separate calls. */
    ExpectNotNull((ctx = EVP_CIPHER_CTX_new()));
    ExpectIntEQ(wolfSSL_EVP_CipherInit(ctx, EVP_chacha20_poly1305(),
                key, NULL, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_EVP_CipherInit(ctx, NULL, NULL, iv, 1),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_EVP_CipherUpdate(ctx, NULL, &outSz,
                aad, sizeof(aad)), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, sizeof(aad));
    ExpectIntEQ(outSz, sizeof(aad));
    ExpectIntEQ(EVP_DecryptUpdate(ctx, decryptedText, &outSz, cipherText,
                sizeof(cipherText)), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, sizeof(cipherText));
    ExpectIntEQ(EVP_DecryptFinal_ex(ctx, decryptedText, &outSz),
            WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, 0);
    EVP_CIPHER_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfssl_EVP_aria_gcm(void)
{
    int res = TEST_SKIPPED;
#if defined(OPENSSL_EXTRA) && defined(HAVE_ARIA) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)

    /* A 256 bit key, AES_128 will use the first 128 bit*/
    byte *key = (byte*)"01234567890123456789012345678901";
    /* A 128 bit IV */
    byte *iv = (byte*)"0123456789012345";
    int ivSz = ARIA_BLOCK_SIZE;
    /* Message to be encrypted */
    const int plaintxtSz = 40;
    byte plaintxt[WC_ARIA_GCM_GET_CIPHERTEXT_SIZE(plaintxtSz)];
    XMEMCPY(plaintxt,"for things to change you have to change",plaintxtSz);
    /* Additional non-confidential data */
    byte *aad = (byte*)"Don't spend major time on minor things.";

    unsigned char tag[ARIA_BLOCK_SIZE] = {0};
    int aadSz = (int)XSTRLEN((char*)aad);
    byte ciphertxt[WC_ARIA_GCM_GET_CIPHERTEXT_SIZE(plaintxtSz)];
    byte decryptedtxt[plaintxtSz];
    int ciphertxtSz = 0;
    int decryptedtxtSz = 0;
    int len = 0;
    int i = 0;
    #define TEST_ARIA_GCM_COUNT 6
    EVP_CIPHER_CTX en[TEST_ARIA_GCM_COUNT];
    EVP_CIPHER_CTX de[TEST_ARIA_GCM_COUNT];

    for (i = 0; i < TEST_ARIA_GCM_COUNT; i++) {

        EVP_CIPHER_CTX_init(&en[i]);
        switch (i) {
            case 0:
                /* Default uses 96-bits IV length */
                AssertIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aria_128_gcm(),
                    NULL, key, iv));
                break;
            case 1:
                /* Default uses 96-bits IV length */
                AssertIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aria_192_gcm(),
                    NULL, key, iv));
                break;
            case 2:
                /* Default uses 96-bits IV length */
                AssertIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aria_256_gcm(),
                    NULL, key, iv));
                break;
            case 3:
                AssertIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aria_128_gcm(),
                    NULL, NULL, NULL));
                /* non-default must to set the IV length first */
                AssertIntEQ(1, EVP_CIPHER_CTX_ctrl(&en[i],
                    EVP_CTRL_GCM_SET_IVLEN, ivSz, NULL));
                AssertIntEQ(1, EVP_EncryptInit_ex(&en[i], NULL, NULL, key, iv));
                break;
            case 4:
                AssertIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aria_192_gcm(),
                    NULL, NULL, NULL));
                /* non-default must to set the IV length first */
                AssertIntEQ(1, EVP_CIPHER_CTX_ctrl(&en[i],
                    EVP_CTRL_GCM_SET_IVLEN, ivSz, NULL));
                AssertIntEQ(1, EVP_EncryptInit_ex(&en[i], NULL, NULL, key, iv));
                break;
            case 5:
                AssertIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aria_256_gcm(),
                    NULL, NULL, NULL));
                /* non-default must to set the IV length first */
                AssertIntEQ(1, EVP_CIPHER_CTX_ctrl(&en[i],
                    EVP_CTRL_GCM_SET_IVLEN, ivSz, NULL));
                AssertIntEQ(1, EVP_EncryptInit_ex(&en[i], NULL, NULL, key, iv));
                break;
        }
        XMEMSET(ciphertxt,0,sizeof(ciphertxt));
        AssertIntEQ(1, EVP_EncryptUpdate(&en[i], NULL, &len, aad, aadSz));
        AssertIntEQ(1, EVP_EncryptUpdate(&en[i], ciphertxt, &len, plaintxt,
            plaintxtSz));
        ciphertxtSz = len;
        AssertIntEQ(1, EVP_EncryptFinal_ex(&en[i], ciphertxt, &len));
        AssertIntNE(0, XMEMCMP(plaintxt, ciphertxt, plaintxtSz));
        ciphertxtSz += len;
        AssertIntEQ(1, EVP_CIPHER_CTX_ctrl(&en[i], EVP_CTRL_GCM_GET_TAG,
            ARIA_BLOCK_SIZE, tag));
        AssertIntEQ(wolfSSL_EVP_CIPHER_CTX_cleanup(&en[i]), 1);

        EVP_CIPHER_CTX_init(&de[i]);
        switch (i) {
            case 0:
                /* Default uses 96-bits IV length */
                AssertIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aria_128_gcm(),
                    NULL, key, iv));
                break;
            case 1:
                /* Default uses 96-bits IV length */
                AssertIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aria_192_gcm(),
                    NULL, key, iv));
                break;
            case 2:
                /* Default uses 96-bits IV length */
                AssertIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aria_256_gcm(),
                    NULL, key, iv));
                break;
            case 3:
                AssertIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aria_128_gcm(),
                    NULL, NULL, NULL));
                /* non-default must to set the IV length first */
                AssertIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i],
                    EVP_CTRL_GCM_SET_IVLEN, ivSz, NULL));
                AssertIntEQ(1, EVP_DecryptInit_ex(&de[i], NULL, NULL, key, iv));
                break;
            case 4:
                AssertIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aria_192_gcm(),
                    NULL, NULL, NULL));
                /* non-default must to set the IV length first */
                AssertIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i],
                    EVP_CTRL_GCM_SET_IVLEN, ivSz, NULL));
                AssertIntEQ(1, EVP_DecryptInit_ex(&de[i], NULL, NULL, key, iv));
                break;
            case 5:
                AssertIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aria_256_gcm(),
                    NULL, NULL, NULL));
                /* non-default must to set the IV length first */
                AssertIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i],
                    EVP_CTRL_GCM_SET_IVLEN, ivSz, NULL));
                AssertIntEQ(1, EVP_DecryptInit_ex(&de[i], NULL, NULL, key, iv));
                break;
        }
        XMEMSET(decryptedtxt,0,sizeof(decryptedtxt));
        AssertIntEQ(1, EVP_DecryptUpdate(&de[i], NULL, &len, aad, aadSz));
        AssertIntEQ(1, EVP_DecryptUpdate(&de[i], decryptedtxt, &len, ciphertxt,
            ciphertxtSz));
        decryptedtxtSz = len;
        AssertIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_GCM_SET_TAG,
            ARIA_BLOCK_SIZE, tag));
        AssertIntEQ(1, EVP_DecryptFinal_ex(&de[i], decryptedtxt, &len));
        decryptedtxtSz += len;
        AssertIntEQ(plaintxtSz, decryptedtxtSz);
        AssertIntEQ(0, XMEMCMP(plaintxt, decryptedtxt, decryptedtxtSz));

        XMEMSET(decryptedtxt,0,sizeof(decryptedtxt));
        /* modify tag*/
        tag[AES_BLOCK_SIZE-1]+=0xBB;
        AssertIntEQ(1, EVP_DecryptUpdate(&de[i], NULL, &len, aad, aadSz));
        AssertIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_GCM_SET_TAG,
            ARIA_BLOCK_SIZE, tag));
        /* fail due to wrong tag */
        AssertIntEQ(1, EVP_DecryptUpdate(&de[i], decryptedtxt, &len, ciphertxt,
            ciphertxtSz));
        AssertIntEQ(0, EVP_DecryptFinal_ex(&de[i], decryptedtxt, &len));
        AssertIntEQ(0, len);
        AssertIntEQ(wolfSSL_EVP_CIPHER_CTX_cleanup(&de[i]), 1);
    }

    res = TEST_RES_CHECK(1);
#endif /* OPENSSL_EXTRA && !NO_AES && HAVE_AESGCM */
    return res;
}

int test_wolfssl_EVP_sm4_ecb(void)
{
    int res = TEST_SKIPPED;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_SM4_ECB)
    EXPECT_DECLS;
    byte key[SM4_KEY_SIZE];
    byte plainText[SM4_BLOCK_SIZE] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
        0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF
    };
    byte cipherText[sizeof(plainText) + SM4_BLOCK_SIZE];
    byte decryptedText[sizeof(plainText) + SM4_BLOCK_SIZE];
    EVP_CIPHER_CTX* ctx;
    int outSz;

    XMEMSET(key, 0, sizeof(key));

    /* Encrypt. */
    ExpectNotNull((ctx = EVP_CIPHER_CTX_new()));
    ExpectIntEQ(EVP_EncryptInit_ex(ctx, EVP_sm4_ecb(), NULL, NULL, NULL),
        WOLFSSL_SUCCESS);
    /* Any tag length must fail - not an AEAD cipher. */
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_EncryptInit_ex(ctx, NULL, NULL, key, NULL),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_EncryptUpdate(ctx, cipherText, &outSz, plainText,
        sizeof(plainText)), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, sizeof(plainText));
    ExpectIntEQ(EVP_EncryptFinal_ex(ctx, cipherText + outSz, &outSz),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, SM4_BLOCK_SIZE);
    ExpectBufNE(cipherText, plainText, sizeof(plainText));
    EVP_CIPHER_CTX_free(ctx);

    /* Decrypt. */
    ExpectNotNull((ctx = EVP_CIPHER_CTX_new()));
    ExpectIntEQ(EVP_DecryptInit_ex(ctx, EVP_sm4_ecb(), NULL, NULL, NULL),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DecryptInit_ex(ctx, NULL, NULL, key, NULL),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DecryptUpdate(ctx, decryptedText, &outSz, cipherText,
        sizeof(cipherText)), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, sizeof(plainText));
    ExpectIntEQ(EVP_DecryptFinal_ex(ctx, decryptedText + outSz, &outSz),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, 0);
    ExpectBufEQ(decryptedText, plainText, sizeof(plainText));
    EVP_CIPHER_CTX_free(ctx);

    res = EXPECT_RESULT();
#endif
    return res;
}

int test_wolfssl_EVP_sm4_cbc(void)
{
    int res = TEST_SKIPPED;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_SM4_CBC)
    EXPECT_DECLS;
    byte key[SM4_KEY_SIZE];
    byte iv[SM4_BLOCK_SIZE];
    byte plainText[SM4_BLOCK_SIZE] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
        0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF
    };
    byte cipherText[sizeof(plainText) + SM4_BLOCK_SIZE];
    byte decryptedText[sizeof(plainText) + SM4_BLOCK_SIZE];
    EVP_CIPHER_CTX* ctx;
    int outSz;

    XMEMSET(key, 0, sizeof(key));
    XMEMSET(iv, 0, sizeof(iv));

    /* Encrypt. */
    ExpectNotNull((ctx = EVP_CIPHER_CTX_new()));
    ExpectIntEQ(EVP_EncryptInit_ex(ctx, EVP_sm4_cbc(), NULL, NULL, NULL),
        WOLFSSL_SUCCESS);
    /* Any tag length must fail - not an AEAD cipher. */
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_EncryptUpdate(ctx, cipherText, &outSz, plainText,
        sizeof(plainText)), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, sizeof(plainText));
    ExpectIntEQ(EVP_EncryptFinal_ex(ctx, cipherText + outSz, &outSz),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, SM4_BLOCK_SIZE);
    ExpectBufNE(cipherText, plainText, sizeof(plainText));
    EVP_CIPHER_CTX_free(ctx);

    /* Decrypt. */
    ExpectNotNull((ctx = EVP_CIPHER_CTX_new()));
    ExpectIntEQ(EVP_DecryptInit_ex(ctx, EVP_sm4_cbc(), NULL, NULL, NULL),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DecryptUpdate(ctx, decryptedText, &outSz, cipherText,
        sizeof(cipherText)), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, sizeof(plainText));
    ExpectIntEQ(EVP_DecryptFinal_ex(ctx, decryptedText + outSz, &outSz),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, 0);
    ExpectBufEQ(decryptedText, plainText, sizeof(plainText));
    EVP_CIPHER_CTX_free(ctx);

    /* Test partial Inits. CipherInit() allow setting of key and iv
     * in separate calls. */
    ExpectNotNull((ctx = EVP_CIPHER_CTX_new()));
    ExpectIntEQ(wolfSSL_EVP_CipherInit(ctx, EVP_sm4_cbc(), key, NULL, 0),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_EVP_CipherInit(ctx, NULL, NULL, iv, 0),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DecryptUpdate(ctx, decryptedText, &outSz, cipherText,
         sizeof(cipherText)), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, sizeof(plainText));
    ExpectIntEQ(EVP_DecryptFinal_ex(ctx, decryptedText + outSz, &outSz),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, 0);
    ExpectBufEQ(decryptedText, plainText, sizeof(plainText));
    EVP_CIPHER_CTX_free(ctx);

    res = EXPECT_RESULT();
#endif
    return res;
}

int test_wolfssl_EVP_sm4_ctr(void)
{
    int res = TEST_SKIPPED;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_SM4_CTR)
    EXPECT_DECLS;
    byte key[SM4_KEY_SIZE];
    byte iv[SM4_BLOCK_SIZE];
    byte plainText[] = {0xDE, 0xAD, 0xBE, 0xEF};
    byte cipherText[sizeof(plainText)];
    byte decryptedText[sizeof(plainText)];
    EVP_CIPHER_CTX* ctx;
    int outSz;

    XMEMSET(key, 0, sizeof(key));
    XMEMSET(iv, 0, sizeof(iv));

    /* Encrypt. */
    ExpectNotNull((ctx = EVP_CIPHER_CTX_new()));
    ExpectIntEQ(EVP_EncryptInit_ex(ctx, EVP_sm4_ctr(), NULL, NULL, NULL),
        WOLFSSL_SUCCESS);
    /* Any tag length must fail - not an AEAD cipher. */
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_EncryptUpdate(ctx, cipherText, &outSz, plainText,
        sizeof(plainText)), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, sizeof(plainText));
    ExpectIntEQ(EVP_EncryptFinal_ex(ctx, cipherText, &outSz), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, 0);
    ExpectBufNE(cipherText, plainText, sizeof(plainText));
    EVP_CIPHER_CTX_free(ctx);

    /* Decrypt. */
    ExpectNotNull((ctx = EVP_CIPHER_CTX_new()));
    ExpectIntEQ(EVP_DecryptInit_ex(ctx, EVP_sm4_ctr(), NULL, NULL, NULL),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DecryptUpdate(ctx, decryptedText, &outSz, cipherText,
        sizeof(cipherText)), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, sizeof(cipherText));
    ExpectIntEQ(EVP_DecryptFinal_ex(ctx, decryptedText, &outSz),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, 0);
    ExpectBufEQ(decryptedText, plainText, sizeof(plainText));
    EVP_CIPHER_CTX_free(ctx);

    /* Test partial Inits. CipherInit() allow setting of key and iv
     * in separate calls. */
    ExpectNotNull((ctx = EVP_CIPHER_CTX_new()));
    ExpectIntEQ(wolfSSL_EVP_CipherInit(ctx, EVP_sm4_ctr(), key, NULL, 1),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_EVP_CipherInit(ctx, NULL, NULL, iv, 1),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DecryptUpdate(ctx, decryptedText, &outSz, cipherText,
         sizeof(cipherText)), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, sizeof(cipherText));
    ExpectIntEQ(EVP_DecryptFinal_ex(ctx, decryptedText, &outSz),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, 0);
    ExpectBufEQ(decryptedText, plainText, sizeof(plainText));
    EVP_CIPHER_CTX_free(ctx);

    res = EXPECT_RESULT();
#endif
    return res;
}

int test_wolfssl_EVP_sm4_gcm_zeroLen(void)
{
    int res = TEST_SKIPPED;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_SM4_GCM)
    /* Zero length plain text */
    EXPECT_DECLS;
    byte key[] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    }; /* align */
    byte iv[]  = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    }; /* align */
    byte plaintxt[1];
    int ivSz  = 12;
    int plaintxtSz = 0;
    unsigned char tag[16];
    unsigned char tag_kat[16] = {
        0x23,0x2f,0x0c,0xfe,0x30,0x8b,0x49,0xea,
        0x6f,0xc8,0x82,0x29,0xb5,0xdc,0x85,0x8d
    };

    byte ciphertxt[SM4_BLOCK_SIZE * 4] = {0};
    byte decryptedtxt[SM4_BLOCK_SIZE * 4] = {0};
    int ciphertxtSz = 0;
    int decryptedtxtSz = 0;
    int len = 0;

    EVP_CIPHER_CTX *en = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *de = EVP_CIPHER_CTX_new();

    ExpectIntEQ(1, EVP_EncryptInit_ex(en, EVP_sm4_gcm(), NULL, key, iv));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(en, EVP_CTRL_GCM_SET_IVLEN, ivSz, NULL));
    ExpectIntEQ(1, EVP_EncryptUpdate(en, ciphertxt, &ciphertxtSz , plaintxt,
        plaintxtSz));
    ExpectIntEQ(1, EVP_EncryptFinal_ex(en, ciphertxt, &len));
    ciphertxtSz += len;
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(en, EVP_CTRL_GCM_GET_TAG, 16, tag));
    ExpectIntEQ(1, EVP_CIPHER_CTX_cleanup(en));

    ExpectIntEQ(0, ciphertxtSz);
    ExpectIntEQ(0, XMEMCMP(tag, tag_kat, sizeof(tag)));

    EVP_CIPHER_CTX_init(de);
    ExpectIntEQ(1, EVP_DecryptInit_ex(de, EVP_sm4_gcm(), NULL, key, iv));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(de, EVP_CTRL_GCM_SET_IVLEN, ivSz, NULL));
    ExpectIntEQ(1, EVP_DecryptUpdate(de, NULL, &len, ciphertxt, len));
    decryptedtxtSz = len;
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(de, EVP_CTRL_GCM_SET_TAG, 16, tag));
    ExpectIntEQ(1, EVP_DecryptFinal_ex(de, decryptedtxt, &len));
    decryptedtxtSz += len;
    ExpectIntEQ(0, decryptedtxtSz);

    EVP_CIPHER_CTX_free(en);
    EVP_CIPHER_CTX_free(de);

    res = EXPECT_RESULT();
#endif /* OPENSSL_EXTRA && WOLFSSL_SM4_GCM */
    return res;
}

int test_wolfssl_EVP_sm4_gcm(void)
{
    int res = TEST_SKIPPED;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_SM4_GCM)
    EXPECT_DECLS;
    byte *key = (byte*)"0123456789012345";
    /* A 128 bit IV */
    byte *iv = (byte*)"0123456789012345";
    int ivSz = SM4_BLOCK_SIZE;
    /* Message to be encrypted */
    byte *plaintxt = (byte*)"for things to change you have to change";
    /* Additional non-confidential data */
    byte *aad = (byte*)"Don't spend major time on minor things.";

    unsigned char tag[SM4_BLOCK_SIZE] = {0};
    int plaintxtSz = (int)XSTRLEN((char*)plaintxt);
    int aadSz = (int)XSTRLEN((char*)aad);
    byte ciphertxt[SM4_BLOCK_SIZE * 4] = {0};
    byte decryptedtxt[SM4_BLOCK_SIZE * 4] = {0};
    int ciphertxtSz = 0;
    int decryptedtxtSz = 0;
    int len = 0;
    int i = 0;
    EVP_CIPHER_CTX en[2];
    EVP_CIPHER_CTX de[2];

    for (i = 0; i < 2; i++) {
        EVP_CIPHER_CTX_init(&en[i]);

        if (i == 0) {
            /* Default uses 96-bits IV length */
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_sm4_gcm(), NULL, key,
                iv));
        }
        else {
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_sm4_gcm(), NULL, NULL,
                NULL));
             /* non-default must to set the IV length first */
            ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&en[i], EVP_CTRL_GCM_SET_IVLEN,
                ivSz, NULL));
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], NULL, NULL, key, iv));
        }
        ExpectIntEQ(1, EVP_EncryptUpdate(&en[i], NULL, &len, aad, aadSz));
        ExpectIntEQ(1, EVP_EncryptUpdate(&en[i], ciphertxt, &len, plaintxt,
            plaintxtSz));
        ciphertxtSz = len;
        ExpectIntEQ(1, EVP_EncryptFinal_ex(&en[i], ciphertxt, &len));
        ciphertxtSz += len;
        ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&en[i], EVP_CTRL_GCM_GET_TAG,
            SM4_BLOCK_SIZE, tag));
        ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_cleanup(&en[i]), 1);

        EVP_CIPHER_CTX_init(&de[i]);
        if (i == 0) {
            /* Default uses 96-bits IV length */
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_sm4_gcm(), NULL, key,
                iv));
        }
        else {
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_sm4_gcm(), NULL, NULL,
                NULL));
            /* non-default must to set the IV length first */
            ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_GCM_SET_IVLEN,
                ivSz, NULL));
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], NULL, NULL, key, iv));

        }
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], NULL, &len, aad, aadSz));
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], decryptedtxt, &len, ciphertxt,
            ciphertxtSz));
        decryptedtxtSz = len;
        ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_GCM_SET_TAG,
            SM4_BLOCK_SIZE, tag));
        ExpectIntEQ(1, EVP_DecryptFinal_ex(&de[i], decryptedtxt, &len));
        decryptedtxtSz += len;
        ExpectIntEQ(ciphertxtSz, decryptedtxtSz);
        ExpectIntEQ(0, XMEMCMP(plaintxt, decryptedtxt, decryptedtxtSz));

        /* modify tag*/
        tag[SM4_BLOCK_SIZE-1]+=0xBB;
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], NULL, &len, aad, aadSz));
        ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_GCM_SET_TAG,
            SM4_BLOCK_SIZE, tag));
        /* fail due to wrong tag */
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], decryptedtxt, &len, ciphertxt,
            ciphertxtSz));
        ExpectIntEQ(0, EVP_DecryptFinal_ex(&de[i], decryptedtxt, &len));
        ExpectIntEQ(0, len);
        ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_cleanup(&de[i]), 1);
    }

    res = EXPECT_RESULT();
#endif /* OPENSSL_EXTRA && WOLFSSL_SM4_GCM */
    return res;
}

int test_wolfssl_EVP_sm4_ccm_zeroLen(void)
{
    int res = TEST_SKIPPED;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_SM4_CCM)
    /* Zero length plain text */
    EXPECT_DECLS;
    byte key[] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    }; /* align */
    byte iv[]  = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    }; /* align */
    byte plaintxt[1];
    int ivSz  = 12;
    int plaintxtSz = 0;
    unsigned char tag[16];

    byte ciphertxt[SM4_BLOCK_SIZE * 4] = {0};
    byte decryptedtxt[SM4_BLOCK_SIZE * 4] = {0};
    int ciphertxtSz = 0;
    int decryptedtxtSz = 0;
    int len = 0;

    EVP_CIPHER_CTX *en = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *de = EVP_CIPHER_CTX_new();

    ExpectIntEQ(1, EVP_EncryptInit_ex(en, EVP_sm4_ccm(), NULL, key, iv));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(en, EVP_CTRL_CCM_SET_IVLEN, ivSz, NULL));
    ExpectIntEQ(1, EVP_EncryptUpdate(en, ciphertxt, &ciphertxtSz , plaintxt,
                                     plaintxtSz));
    ExpectIntEQ(1, EVP_EncryptFinal_ex(en, ciphertxt, &len));
    ciphertxtSz += len;
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(en, EVP_CTRL_CCM_GET_TAG, 16, tag));
    ExpectIntEQ(1, EVP_CIPHER_CTX_cleanup(en));

    ExpectIntEQ(0, ciphertxtSz);

    EVP_CIPHER_CTX_init(de);
    ExpectIntEQ(1, EVP_DecryptInit_ex(de, EVP_sm4_ccm(), NULL, key, iv));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(de, EVP_CTRL_CCM_SET_IVLEN, ivSz, NULL));
    ExpectIntEQ(1, EVP_DecryptUpdate(de, NULL, &len, ciphertxt, len));
    decryptedtxtSz = len;
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(de, EVP_CTRL_CCM_SET_TAG, 16, tag));
    ExpectIntEQ(1, EVP_DecryptFinal_ex(de, decryptedtxt, &len));
    decryptedtxtSz += len;
    ExpectIntEQ(0, decryptedtxtSz);

    EVP_CIPHER_CTX_free(en);
    EVP_CIPHER_CTX_free(de);

    res = EXPECT_RESULT();
#endif /* OPENSSL_EXTRA && WOLFSSL_SM4_CCM */
    return res;
}

int test_wolfssl_EVP_sm4_ccm(void)
{
    int res = TEST_SKIPPED;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_SM4_CCM)
    EXPECT_DECLS;
    byte *key = (byte*)"0123456789012345";
    byte *iv = (byte*)"0123456789012";
    int ivSz = (int)XSTRLEN((char*)iv);
    /* Message to be encrypted */
    byte *plaintxt = (byte*)"for things to change you have to change";
    /* Additional non-confidential data */
    byte *aad = (byte*)"Don't spend major time on minor things.";

    unsigned char tag[SM4_BLOCK_SIZE] = {0};
    int plaintxtSz = (int)XSTRLEN((char*)plaintxt);
    int aadSz = (int)XSTRLEN((char*)aad);
    byte ciphertxt[SM4_BLOCK_SIZE * 4] = {0};
    byte decryptedtxt[SM4_BLOCK_SIZE * 4] = {0};
    int ciphertxtSz = 0;
    int decryptedtxtSz = 0;
    int len = 0;
    int i = 0;
    EVP_CIPHER_CTX en[2];
    EVP_CIPHER_CTX de[2];

    for (i = 0; i < 2; i++) {
        EVP_CIPHER_CTX_init(&en[i]);

        if (i == 0) {
            /* Default uses 96-bits IV length */
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_sm4_ccm(), NULL, key,
                iv));
        }
        else {
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_sm4_ccm(), NULL, NULL,
                NULL));
             /* non-default must to set the IV length first */
            ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&en[i], EVP_CTRL_CCM_SET_IVLEN,
                ivSz, NULL));
            ExpectIntEQ(1, EVP_EncryptInit_ex(&en[i], NULL, NULL, key, iv));
        }
        ExpectIntEQ(1, EVP_EncryptUpdate(&en[i], NULL, &len, aad, aadSz));
        ExpectIntEQ(1, EVP_EncryptUpdate(&en[i], ciphertxt, &len, plaintxt,
            plaintxtSz));
        ciphertxtSz = len;
        ExpectIntEQ(1, EVP_EncryptFinal_ex(&en[i], ciphertxt, &len));
        ciphertxtSz += len;
        ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&en[i], EVP_CTRL_CCM_GET_TAG,
            SM4_BLOCK_SIZE, tag));
        ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_cleanup(&en[i]), 1);

        EVP_CIPHER_CTX_init(&de[i]);
        if (i == 0) {
            /* Default uses 96-bits IV length */
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_sm4_ccm(), NULL, key,
                iv));
        }
        else {
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_sm4_ccm(), NULL, NULL,
                NULL));
            /* non-default must to set the IV length first */
            ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_CCM_SET_IVLEN,
                ivSz, NULL));
            ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], NULL, NULL, key, iv));

        }
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], NULL, &len, aad, aadSz));
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], decryptedtxt, &len, ciphertxt,
            ciphertxtSz));
        decryptedtxtSz = len;
        ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_CCM_SET_TAG,
            SM4_BLOCK_SIZE, tag));
        ExpectIntEQ(1, EVP_DecryptFinal_ex(&de[i], decryptedtxt, &len));
        decryptedtxtSz += len;
        ExpectIntEQ(ciphertxtSz, decryptedtxtSz);
        ExpectIntEQ(0, XMEMCMP(plaintxt, decryptedtxt, decryptedtxtSz));

        /* modify tag*/
        tag[SM4_BLOCK_SIZE-1]+=0xBB;
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], NULL, &len, aad, aadSz));
        ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_CCM_SET_TAG,
            SM4_BLOCK_SIZE, tag));
        /* fail due to wrong tag */
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], decryptedtxt, &len, ciphertxt,
            ciphertxtSz));
        ExpectIntEQ(0, EVP_DecryptFinal_ex(&de[i], decryptedtxt, &len));
        ExpectIntEQ(0, len);
        ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_cleanup(&de[i]), 1);
    }

    res = EXPECT_RESULT();
#endif /* OPENSSL_EXTRA && WOLFSSL_SM4_CCM */
    return res;
}


int test_wolfSSL_EVP_rc4(void)
{
    EXPECT_DECLS;
#if !defined(NO_RC4) && defined(OPENSSL_ALL)
    ExpectNotNull(wolfSSL_EVP_rc4());
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_enc_null(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_ALL
    ExpectNotNull(wolfSSL_EVP_enc_null());
#endif
    return EXPECT_RESULT();
}
int test_wolfSSL_EVP_rc2_cbc(void)

{
    EXPECT_DECLS;
#if defined(WOLFSSL_QT) && !defined(NO_WOLFSSL_STUB)
    ExpectNull(wolfSSL_EVP_rc2_cbc());
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_mdc2(void)
{
    EXPECT_DECLS;
#if !defined(NO_WOLFSSL_STUB) && defined(OPENSSL_ALL)
    ExpectNull(wolfSSL_EVP_mdc2());
#endif
    return EXPECT_RESULT();
}

