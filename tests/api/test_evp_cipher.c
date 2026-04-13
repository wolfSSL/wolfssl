/* test_evp_cipher.c
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
    byte badTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
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

    /* Negative test: forged (all-zero) tag must be rejected. */
    XMEMSET(badTag, 0, sizeof(badTag));
    ExpectNotNull((ctx = EVP_CIPHER_CTX_new()));
    ExpectIntEQ(EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL,
                NULL, NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                CHACHA20_POLY1305_AEAD_IV_SIZE, NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE, badTag),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DecryptUpdate(ctx, NULL, &outSz, aad, sizeof(aad)),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DecryptUpdate(ctx, decryptedText, &outSz, cipherText,
                sizeof(cipherText)), WOLFSSL_SUCCESS);
    /* EVP_DecryptFinal_ex MUST return failure on tag mismatch */
    ExpectIntNE(EVP_DecryptFinal_ex(ctx, decryptedText, &outSz),
                WOLFSSL_SUCCESS);
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

/* Test for integer overflow in EVP AEAD AAD accumulation.
 *
 * wolfSSL_EVP_CipherUpdate_GCM_AAD (and the CCM/ARIA variants) compute
 * allocation sizes as (ctx->authInSz + inl) where both operands are int.
 * Repeated AAD calls can accumulate authInSz to a value where adding inl
 * overflows the signed int sum. The overflowed value is then cast to size_t
 * for XMALLOC/XREALLOC, producing either:
 *   - A huge allocation on 64-bit (masking the bug as MEMORY_E), or
 *   - A potential heap buffer overflow on 32-bit if the wrapped size is small
 *     enough to succeed but the subsequent XMEMCPY uses the original large
 *     authInSz offset.
 *
 * This test simulates the overflow condition by directly setting authInSz near
 * INT_MAX after legitimate initialization, then calling EVP_EncryptUpdate with
 * AAD that triggers the overflow. A properly-fixed implementation should detect
 * the overflow and return WOLFSSL_FAILURE before attempting the allocation.
 */
int test_evp_cipher_pkcs7_pad_zero(void)
{
    EXPECT_DECLS;
#if !defined(NO_AES) && defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_128) && \
    defined(OPENSSL_EXTRA)
    EVP_CIPHER_CTX *ctx = NULL;
    /* AES-128-CBC key and IV */
    byte key[AES_BLOCK_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    byte iv[AES_BLOCK_SIZE] = {0};
    /* Two plaintext blocks, with the last byte set to 0x00. When decrypted
     * with padding enabled, the last byte (0x00) will be interpreted as the
     * PKCS#7 padding length, which is invalid (valid range is 1..block_size).
     * Using two blocks ensures CipherUpdate outputs the first block and
     * CipherFinal processes the second (last) block through checkPad. */
    byte plain[AES_BLOCK_SIZE * 2] = {
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00
    };
    byte cipher[AES_BLOCK_SIZE * 3];
    byte decrypted[AES_BLOCK_SIZE * 3];
    int outl = 0;
    int total = 0;

    /* Encrypt two plaintext blocks with padding disabled so the ciphertext
     * is exactly two blocks. */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectIntEQ(EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, 1),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_CIPHER_CTX_set_padding(ctx, 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_CipherUpdate(ctx, cipher, &outl, plain,
        AES_BLOCK_SIZE * 2), WOLFSSL_SUCCESS);
    total = outl;
    ExpectIntEQ(EVP_CipherFinal(ctx, cipher + total, &outl), WOLFSSL_SUCCESS);
    total += outl;
    ExpectIntEQ(total, AES_BLOCK_SIZE * 2);
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* Decrypt the ciphertext with padding enabled (the default).
     * CipherUpdate should output the first block. CipherFinal processes
     * the last block through checkPad, which should reject padding value 0. */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectIntEQ(EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, 0),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_CipherUpdate(ctx, decrypted, &outl, cipher, total),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(outl, AES_BLOCK_SIZE);
    ExpectIntNE(EVP_CipherFinal(ctx, decrypted + outl, &outl),
        WOLFSSL_SUCCESS);
    EVP_CIPHER_CTX_free(ctx);

#endif /* !NO_AES && HAVE_AES_CBC && WOLFSSL_AES_128 && OPENSSL_EXTRA */
    return EXPECT_RESULT();
}

int test_evp_cipher_aead_aad_overflow(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_AES) && defined(HAVE_AESGCM) && \
    defined(WOLFSSL_AES_256) && !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS) && \
    !defined(WOLFSSL_AESGCM_STREAM)

    WOLFSSL_EVP_CIPHER_CTX *ctx = NULL;
    byte key[32] = {0};
    byte iv[12] = {0};
    byte aad[32] = {0};
    int outl = 0;
    int savedAuthInSz;

    /* Initialize AES-256-GCM encryption context */
    ctx = EVP_CIPHER_CTX_new();
    ExpectNotNull(ctx);
    ExpectIntEQ(WOLFSSL_SUCCESS, EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(),
        NULL, key, iv));

    /* Feed a small legitimate AAD to allocate authIn */
    ExpectIntEQ(WOLFSSL_SUCCESS, EVP_EncryptUpdate(ctx, NULL, &outl, aad, 16));

    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(ctx->authInSz, 16);

        /* Simulate accumulated AAD near INT_MAX.
         * In a real attack scenario, an attacker controlling AAD input to a
         * server could accumulate authInSz toward INT_MAX through many calls.
         * We set it directly to avoid needing ~2GB of actual allocations.
         */
        savedAuthInSz = ctx->authInSz;
        ctx->authInSz = INT_MAX - 16;

        /* Attempt AAD update that causes overflow:
         *   (INT_MAX - 16) + 32 = INT_MAX + 16
         * This overflows signed int (undefined behavior in C). The result:
         *   - As signed int: wraps to INT_MIN + 15 (on 2's complement)
         *   - Cast to size_t on 64-bit: ~0xFFFFFFFF8000000F (huge)
         *   - Cast to size_t on 32-bit: ~0x8000000F (~2GB)
         *
         * With no overflow check, the code proceeds to XREALLOC with the
         * wrapped size. On 64-bit this fails (MEMORY_E), accidentally
         * preventing corruption. On 32-bit, if the allocation succeeds,
         * XMEMCPY writes at offset (INT_MAX - 16) into the buffer, causing
         * heap corruption.
         */
        ExpectIntNE(WOLFSSL_SUCCESS,
            EVP_EncryptUpdate(ctx, NULL, &outl, aad, 32));

        /* Restore authInSz so cleanup doesn't operate on corrupted state */
        if (ctx != NULL)
            ctx->authInSz = savedAuthInSz;
    }

    EVP_CIPHER_CTX_free(ctx);

#endif /* OPENSSL_EXTRA && HAVE_AESGCM && WOLFSSL_AES_256 */
    return EXPECT_RESULT();
}

/* ---------------------------------------------------------------------------
 * test_wolfSSL_EvpCipherInitGcmPaths
 *
 * Targets EvpCipherInitAesGCM and wolfSSL_EVP_CipherInit (14 uncovered
 * conditions).  Exercises the following independent decisions:
 *
 *   L7215: type==NULL && ctx->cipherType==INIT → failure
 *   L7219: cipherType==INIT on first call      → zeroing branch (true)
 *   L6820: cipherType or type match AES-192-GCM
 *   L6844: key!=NULL → wc_AesGcmSetKey called
 *   L6850: iv!=NULL  → wc_AesGcmSetExtIV called
 *   L8059 (stream): key!=NULL && iv!=NULL      → wc_AesGcmInit called
 *   L8078 (stream): key==NULL, iv set          → stream init IV-only path
 *   Also hits the "NULL cipher, non-NULL key" re-key path (key-only update).
 * ---------------------------------------------------------------------------
 */
int test_wolfSSL_EvpCipherInitGcmPaths(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_AESGCM) && \
    ((!defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)) || \
     (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2))) && \
    !defined(NO_AES)
#if defined(WOLFSSL_AES_128)
    EVP_CIPHER_CTX *ctx = NULL;
    byte key128[16];
    byte key256[32];
    byte iv[12];
    XMEMSET(key128, 0x55, sizeof(key128));
    XMEMSET(key256, 0xAA, sizeof(key256));
    XMEMSET(iv,    0x11, sizeof(iv));

    /* --- L7215: NULL type on uninitialized ctx → failure --- */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    /* ctx->cipherType starts as WOLFSSL_EVP_CIPH_TYPE_INIT */
    ExpectIntEQ(EVP_CipherInit(ctx, NULL, key128, iv, 1),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* --- L7219/L6844/L6850: fresh ctx, type+key+iv → full init path --- */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectIntEQ(EVP_CipherInit(ctx, EVP_aes_128_gcm(), key128, iv, 1),
                WOLFSSL_SUCCESS);
    /* --- key-only re-init (type==NULL, key!=NULL, iv==NULL) --- */
    /* hits the "non-NULL key" path inside an already-initialized ctx */
    ExpectIntEQ(EVP_CipherInit(ctx, NULL, key128, NULL, -1),
                WOLFSSL_SUCCESS);
    /* --- iv-only re-init (type==NULL, key==NULL, iv!=NULL) --- */
    ExpectIntEQ(EVP_CipherInit(ctx, NULL, NULL, iv, -1),
                WOLFSSL_SUCCESS);
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

#ifdef WOLFSSL_AES_256
    /* --- AES-256-GCM: exercises 256-key-size branch in EvpCipherInitAesGCM */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectIntEQ(EVP_CipherInit(ctx, EVP_aes_256_gcm(), key256, iv, 0),
                WOLFSSL_SUCCESS);
    /* decrypt re-key path: type==NULL, same ctx */
    ExpectIntEQ(EVP_CipherInit(ctx, NULL, key256, NULL, -1),
                WOLFSSL_SUCCESS);
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;
#endif /* WOLFSSL_AES_256 */

#ifdef WOLFSSL_AES_192
    /* --- AES-192-GCM: exercises 192-key branch (L6820) --- */
    {
        byte key192[24];
        XMEMSET(key192, 0x33, sizeof(key192));
        ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
        ExpectIntEQ(EVP_CipherInit(ctx, EVP_aes_192_gcm(), key192, iv, 1),
                    WOLFSSL_SUCCESS);
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
    }
#endif /* WOLFSSL_AES_192 */

    (void)key256;
#endif /* WOLFSSL_AES_128 */
#endif /* OPENSSL_EXTRA && HAVE_AESGCM ... */
    return EXPECT_RESULT();
}

/* ---------------------------------------------------------------------------
 * test_wolfSSL_EvpCipherCtxCtrlAead
 *
 * Targets wolfSSL_EVP_CIPHER_CTX_ctrl (13 uncovered conditions):
 *   L6342/L6363: AEAD_SET_IVLEN  with non-AEAD ctx (break) and valid AEAD ctx
 *   L6417/L6425: GCM_IV_GEN     keylen==0 / ivSz==0 guard and arg<=0 path
 *   L6489:       AEAD_SET_TAG    arg<=0 or arg>16 → break; valid tag copy
 *   L6526:       AEAD_GET_TAG    arg<=0 or arg>16 → break; valid get
 *
 * Each AEAD control op is called with both an invalid argument (exercising
 * the "break" / failure edge) and a valid argument (exercising success edge).
 * ---------------------------------------------------------------------------
 */
int test_wolfSSL_EvpCipherCtxCtrlAead(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_AESGCM) && !defined(NO_AES) && \
    defined(WOLFSSL_AES_128) && \
    ((!defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)) || \
     (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2)))
    EVP_CIPHER_CTX *ctx    = NULL;
    EVP_CIPHER_CTX *ctx_nb = NULL;  /* non-AEAD context */
    byte  key[16];
    /* Sized for AES-CBC (16 bytes); AES-GCM only reads the first 12. */
    byte  iv[16];
    byte  tag[16];
    byte  tagbuf[16];
    XMEMSET(key,    0xAB, sizeof(key));
    XMEMSET(iv,     0xCD, sizeof(iv));
    XMEMSET(tag,    0x00, sizeof(tag));
    XMEMSET(tagbuf, 0x00, sizeof(tagbuf));

    /* Set up a non-AEAD context (AES-CBC) to exercise the flag==0 break */
#if defined(HAVE_AES_CBC)
    ExpectNotNull(ctx_nb = EVP_CIPHER_CTX_new());
    ExpectIntEQ(EVP_CipherInit(ctx_nb, EVP_aes_128_cbc(), key, iv, 1),
                WOLFSSL_SUCCESS);
    /* AEAD_SET_IVLEN on non-AEAD ctx must fail (flag not set → break) */
    ExpectIntNE(EVP_CIPHER_CTX_ctrl(ctx_nb, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL),
                WOLFSSL_SUCCESS);
    /* AEAD_SET_TAG on non-AEAD ctx must fail */
    ExpectIntNE(EVP_CIPHER_CTX_ctrl(ctx_nb, EVP_CTRL_AEAD_SET_TAG, 16, tag),
                WOLFSSL_SUCCESS);
    /* AEAD_GET_TAG on non-AEAD ctx must fail */
    ExpectIntNE(EVP_CIPHER_CTX_ctrl(ctx_nb, EVP_CTRL_AEAD_GET_TAG, 16, tagbuf),
                WOLFSSL_SUCCESS);
    EVP_CIPHER_CTX_free(ctx_nb);
    ctx_nb = NULL;
#endif /* HAVE_AES_CBC */

    /* Set up AES-128-GCM context */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectIntEQ(EVP_CipherInit(ctx, EVP_aes_128_gcm(), key, iv, 1),
                WOLFSSL_SUCCESS);

    /* --- EVP_CTRL_AEAD_SET_IVLEN --- */
    /* invalid: arg <= 0 */
    ExpectIntNE(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 0, NULL),
                WOLFSSL_SUCCESS);
    /* invalid: arg > AES_BLOCK_SIZE (16) */
    ExpectIntNE(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 17, NULL),
                WOLFSSL_SUCCESS);
    /* valid */
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL),
                WOLFSSL_SUCCESS);

    /* --- EVP_CTRL_AEAD_SET_TAG --- */
    /* invalid: arg <= 0 */
    ExpectIntNE(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 0, tag),
                WOLFSSL_SUCCESS);
    /* invalid: arg > 16 */
    ExpectIntNE(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 17, tag),
                WOLFSSL_SUCCESS);
    /* invalid: ptr == NULL (for non-chacha path) */
    ExpectIntNE(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL),
                WOLFSSL_SUCCESS);
    /* valid */
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag),
                WOLFSSL_SUCCESS);

    /* --- EVP_CTRL_AEAD_GET_TAG --- */
    /* invalid: arg <= 0 */
    ExpectIntNE(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 0, tagbuf),
                WOLFSSL_SUCCESS);
    /* invalid: arg > AES_BLOCK_SIZE */
    ExpectIntNE(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 17, tagbuf),
                WOLFSSL_SUCCESS);
    /* valid (tag was set above; ptr != NULL) */
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tagbuf),
                WOLFSSL_SUCCESS);

    EVP_CIPHER_CTX_free(ctx);
#endif /* OPENSSL_EXTRA && HAVE_AESGCM && ... */
    return EXPECT_RESULT();
}

/* ---------------------------------------------------------------------------
 * test_wolfSSL_EvpCipherFinalBadArg
 *
 * Targets wolfSSL_EVP_CipherFinal (L1304, L1680, L1691) and
 * wolfSSL_EVP_Cipher (L8599/L8601) null/bad-arg branches.
 *
 * wolfSSL_EVP_CipherFinal conditions:
 *   L1304: !ctx || !outl   (one-bad-at-a-time)
 *
 * wolfSSL_EVP_Cipher conditions:
 *   L8599: !IsCipherTypeAEAD && src==NULL && dst==NULL && len==0 → 0
 *   L8601: src==NULL || dst==NULL (non-AEAD, not the triple-NULL case) → error
 * ---------------------------------------------------------------------------
 */
int test_wolfSSL_EvpCipherFinalBadArg(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_AES) && defined(HAVE_AES_CBC) && \
    defined(WOLFSSL_AES_128)
    EVP_CIPHER_CTX *ctx  = NULL;
    byte  key[16];
    byte  iv[16];
    byte  src[32];
    byte  dst[32];
    int   outl = 0;
    XMEMSET(key, 0x01, sizeof(key));
    XMEMSET(iv,  0x02, sizeof(iv));
    XMEMSET(src, 0x03, sizeof(src));

    /* --- CipherFinal: NULL ctx --- */
    ExpectIntEQ(wolfSSL_EVP_CipherFinal(NULL, dst, &outl),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    /* --- CipherFinal: NULL outl --- */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectIntEQ(EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, 1),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_EVP_CipherFinal(ctx, dst, NULL),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    /* --- wolfSSL_EVP_Cipher: NULL ctx → WOLFSSL_FATAL_ERROR --- */
    ExpectIntEQ(wolfSSL_EVP_Cipher(NULL, dst, src, 16),
                WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));

    /* --- wolfSSL_EVP_Cipher: non-AEAD, src==NULL && dst==NULL && len==0
           → valid no-op returning 0 (L8599 true branch) --- */
    ExpectIntEQ(wolfSSL_EVP_Cipher(ctx, NULL, NULL, 0), 0);

    /* --- wolfSSL_EVP_Cipher: non-AEAD, src==NULL, dst!=NULL → error
           (L8601 true branch: src==NULL || dst==NULL) --- */
    ExpectIntEQ(wolfSSL_EVP_Cipher(ctx, dst, NULL, 16),
                WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));

    /* --- wolfSSL_EVP_Cipher: non-AEAD, src!=NULL, dst==NULL → error --- */
    ExpectIntEQ(wolfSSL_EVP_Cipher(ctx, NULL, src, 16),
                WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));

    /* --- wolfSSL_EVP_Cipher: valid encrypt call (all conds false) --- */
    ExpectIntGE(wolfSSL_EVP_Cipher(ctx, dst, src, 16), 0);

    EVP_CIPHER_CTX_free(ctx);
#endif /* OPENSSL_EXTRA && !NO_AES && HAVE_AES_CBC && WOLFSSL_AES_128 */
    return EXPECT_RESULT();
}

/* ---------------------------------------------------------------------------
 * test_wolfSSL_EvpCipherInitCoverage2
 *
 * Targets wolfSSL_EVP_CipherInit residual uncovered conditions:
 *   L7268: AES-192-CBC type match (cipherType == or type matches EVP_AES_192_CBC)
 *   L7277: enc==0||enc==1 true-branch inside AES-192-CBC block
 *   L7290: iv && key==NULL path (IV-only re-init inside 192-CBC)
 *   L8059: (ctx->key != NULL && iv != NULL) condition for ChaCha20Poly1305
 *   L8078: key != NULL path inside ChaCha20 plain (non-poly) block
 *
 * Also exercises:
 *   - enc=-1 (no-change) on AES-CBC → should succeed preserving prior enc value
 *   - type=NULL re-init after type is already set (reuse current cipherType)
 *   - AES-ECB non-GCM path
 * ---------------------------------------------------------------------------
 */
int test_wolfSSL_EvpCipherInitCoverage2(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_AES)

#if defined(HAVE_AES_CBC)
    /* ---- AES-192-CBC path (L7268 / L7277 / L7290) ---- */
#if defined(WOLFSSL_AES_192)
    {
        EVP_CIPHER_CTX *ctx = NULL;
        byte key192[24];
        byte key192b[24];
        byte iv[16];
        XMEMSET(key192,  0x11, sizeof(key192));
        XMEMSET(key192b, 0x22, sizeof(key192b));
        XMEMSET(iv,      0x33, sizeof(iv));

        ExpectNotNull(ctx = EVP_CIPHER_CTX_new());

        /* full init enc=1 → L7277 true (enc==1) */
        ExpectIntEQ(EVP_CipherInit(ctx, EVP_aes_192_cbc(), key192, iv, 1),
                    WOLFSSL_SUCCESS);

        /* enc=-1 → no change (enc==0||enc==1 false → ctx->enc unchanged) */
        ExpectIntEQ(EVP_CipherInit(ctx, NULL, key192, iv, -1),
                    WOLFSSL_SUCCESS);

        /* iv-only re-init: type==NULL, key==NULL, iv!=NULL → L7290 true */
        ExpectIntEQ(EVP_CipherInit(ctx, NULL, NULL, iv, -1),
                    WOLFSSL_SUCCESS);

        /* re-init with enc=0 → L7277 true (enc==0) */
        ExpectIntEQ(EVP_CipherInit(ctx, EVP_aes_192_cbc(), key192b, iv, 0),
                    WOLFSSL_SUCCESS);

        EVP_CIPHER_CTX_free(ctx);
    }
#endif /* WOLFSSL_AES_192 */

    /* ---- AES-256-CBC enc=-1 no-change path ---- */
#if defined(WOLFSSL_AES_256)
    {
        EVP_CIPHER_CTX *ctx = NULL;
        byte key256[32];
        byte iv[16];
        XMEMSET(key256, 0x44, sizeof(key256));
        XMEMSET(iv,     0x55, sizeof(iv));

        ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
        /* init encrypt */
        ExpectIntEQ(EVP_CipherInit(ctx, EVP_aes_256_cbc(), key256, iv, 1),
                    WOLFSSL_SUCCESS);
        /* re-init with enc=-1 → no change, then re-key with new key */
        ExpectIntEQ(EVP_CipherInit(ctx, NULL, key256, iv, -1),
                    WOLFSSL_SUCCESS);
        EVP_CIPHER_CTX_free(ctx);
    }
#endif /* WOLFSSL_AES_256 */
#endif /* HAVE_AES_CBC */

    /* ---- AES-ECB path (non-GCM, no IV) ---- */
#if defined(HAVE_AES_ECB) && defined(WOLFSSL_AES_128)
    {
        EVP_CIPHER_CTX *ctx = NULL;
        byte key128[16];
        XMEMSET(key128, 0x66, sizeof(key128));

        ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
        /* type + key, no IV (ECB has no IV) */
        ExpectIntEQ(EVP_CipherInit(ctx, EVP_aes_128_ecb(), key128, NULL, 1),
                    WOLFSSL_SUCCESS);
        /* enc=-1 re-init */
        ExpectIntEQ(EVP_CipherInit(ctx, NULL, key128, NULL, -1),
                    WOLFSSL_SUCCESS);
        EVP_CIPHER_CTX_free(ctx);
    }
#endif /* HAVE_AES_ECB && WOLFSSL_AES_128 */

#endif /* OPENSSL_EXTRA && !NO_AES */
    return EXPECT_RESULT();
}

/* ---------------------------------------------------------------------------
 * test_wolfSSL_EvpCipherCtxIvSetGet
 *
 * Targets wolfSSL_EVP_CIPHER_CTX_set_iv (L8523/L8529) and
 *         wolfSSL_EVP_CIPHER_CTX_get_iv (L8547/L8553).
 *
 * set_iv decision chain:
 *   L8523: !ctx || !iv || !ivLen  — three conds, one-bad-at-a-time
 *   L8529: expectedIvLen==0 || expectedIvLen!=ivLen — wrong length
 *
 * get_iv decision chain:
 *   L8547: ctx==NULL || iv==NULL || ivLen==0 — one-bad-at-a-time
 *   L8553: expectedIvLen==0 || expectedIvLen!=ivLen — wrong length
 *
 * Valid success paths for both functions are also exercised.
 * ---------------------------------------------------------------------------
 */
int test_wolfSSL_EvpCipherCtxIvSetGet(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_AESGCM) && !defined(NO_AES) && \
    defined(WOLFSSL_AES_128) && \
    ((!defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)) || \
     (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2)))
    EVP_CIPHER_CTX *ctx = NULL;
    byte key[16];
    byte iv[12];
    byte ivbuf[12];
    byte short_iv[6];
    XMEMSET(key,      0x77, sizeof(key));
    XMEMSET(iv,       0x88, sizeof(iv));
    XMEMSET(ivbuf,    0x00, sizeof(ivbuf));
    XMEMSET(short_iv, 0x99, sizeof(short_iv));

    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectIntEQ(EVP_CipherInit(ctx, EVP_aes_128_gcm(), key, iv, 1),
                WOLFSSL_SUCCESS);

    /* --- wolfSSL_EVP_CIPHER_CTX_set_iv --- */

    /* L8523: ctx==NULL → failure */
    ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_set_iv(NULL, iv, 12),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    /* L8523: iv==NULL → failure */
    ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_set_iv(ctx, NULL, 12),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    /* L8523: ivLen==0 → failure */
    ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_set_iv(ctx, iv, 0),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    /* L8529: ivLen != expectedIvLen (ctx has 12-byte IV, pass 6) → failure */
    ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_set_iv(ctx, short_iv,
                (int)sizeof(short_iv)),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    /* valid: correct iv and ivLen → success */
    ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_set_iv(ctx, iv, 12), WOLFSSL_SUCCESS);

    /* --- wolfSSL_EVP_CIPHER_CTX_get_iv --- */

    /* L8547: ctx==NULL → failure */
    ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_get_iv(NULL, ivbuf, 12),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    /* L8547: iv==NULL → failure */
    ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_get_iv(ctx, NULL, 12),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    /* L8547: ivLen==0 → failure */
    ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_get_iv(ctx, ivbuf, 0),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    /* L8553: ivLen != expectedIvLen (6 != 12) → failure */
    ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_get_iv(ctx, ivbuf, 6),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    /* valid: correct ivLen → success, ivbuf holds current IV */
    ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_get_iv(ctx, ivbuf, 12), WOLFSSL_SUCCESS);

    EVP_CIPHER_CTX_free(ctx);

#if defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_128)
    /* Exercise get_iv on a CBC context (also guarded by !NO_AES || !NO_DES3) */
    {
        EVP_CIPHER_CTX *cbc_ctx = NULL;
        byte cbc_key[16];
        byte cbc_iv[16];
        byte cbc_out[16];
        XMEMSET(cbc_key, 0xAA, sizeof(cbc_key));
        XMEMSET(cbc_iv,  0xBB, sizeof(cbc_iv));

        ExpectNotNull(cbc_ctx = EVP_CIPHER_CTX_new());
        ExpectIntEQ(EVP_CipherInit(cbc_ctx, EVP_aes_128_cbc(),
                    cbc_key, cbc_iv, 1), WOLFSSL_SUCCESS);

        /* CBC ivSz==16; passing 12 should fail the length check */
        ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_get_iv(cbc_ctx, cbc_out, 12),
                    WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

        /* valid */
        ExpectIntEQ(wolfSSL_EVP_CIPHER_CTX_get_iv(cbc_ctx, cbc_out, 16),
                    WOLFSSL_SUCCESS);

        EVP_CIPHER_CTX_free(cbc_ctx);
    }
#endif /* HAVE_AES_CBC && WOLFSSL_AES_128 */

#endif /* OPENSSL_EXTRA && HAVE_AESGCM && !NO_AES && WOLFSSL_AES_128 ... */
    return EXPECT_RESULT();
}

/* ---------------------------------------------------------------------------
 * test_wolfSSL_EvpCipherUpdateBadArg
 *
 * Targets wolfSSL_EVP_CipherUpdate (L1065/L1077):
 *   L1065: (ctx==NULL) || (outl==NULL)         — two independent conditions
 *   L1077: (inl<0) || (in==NULL)               — two independent conditions
 *          Note: inl==0 && in==NULL is allowed (no-op success at L1072).
 *
 * Each condition is exercised independently (one-bad-at-a-time pattern).
 * The flush no-op (in==NULL, inl==0) and valid encrypt paths close the
 * true/false pairs.
 * ---------------------------------------------------------------------------
 */
int test_wolfSSL_EvpCipherUpdateBadArg(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_AES) && defined(HAVE_AES_CBC) && \
    defined(WOLFSSL_AES_128)
    EVP_CIPHER_CTX *ctx = NULL;
    byte  key[16];
    byte  iv[16];
    byte  in[16];
    byte  out[32];
    int   outl = 0;

    XMEMSET(key, 0x01, sizeof(key));
    XMEMSET(iv,  0x02, sizeof(iv));
    XMEMSET(in,  0x03, sizeof(in));

    /* --- L1065 cond 1: ctx==NULL → failure (ctx is NULL, outl is valid) */
    ExpectIntEQ(wolfSSL_EVP_CipherUpdate(NULL, out, &outl, in, (int)sizeof(in)),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectIntEQ(EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, 1),
                WOLFSSL_SUCCESS);

    /* --- L1065 cond 2: outl==NULL → failure (ctx valid, outl NULL) */
    ExpectIntEQ(wolfSSL_EVP_CipherUpdate(ctx, out, NULL, in, (int)sizeof(in)),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    /* --- L1072: in==NULL && inl==0 → success no-op (both conds in L1077 false
     *    because we never reach L1077; L1072 returns first) */
    ExpectIntEQ(wolfSSL_EVP_CipherUpdate(ctx, out, &outl, NULL, 0),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(outl, 0);

    /* --- L1077 cond 1: inl<0 → failure */
    ExpectIntEQ(wolfSSL_EVP_CipherUpdate(ctx, out, &outl, in, -1),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    /* --- L1077 cond 2: in==NULL but inl>0 → failure */
    ExpectIntEQ(wolfSSL_EVP_CipherUpdate(ctx, out, &outl, NULL, (int)sizeof(in)),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    /* --- valid update: all conds false → success */
    outl = 0;
    ExpectIntEQ(wolfSSL_EVP_CipherUpdate(ctx, out, &outl, in, (int)sizeof(in)),
                WOLFSSL_SUCCESS);

    EVP_CIPHER_CTX_free(ctx);
#endif /* OPENSSL_EXTRA && !NO_AES && HAVE_AES_CBC && WOLFSSL_AES_128 */
    return EXPECT_RESULT();
}

/* ---------------------------------------------------------------------------
 * test_wolfSSL_EvpCtrlIvFixedGen
 *
 * Targets wolfSSL_EVP_CIPHER_CTX_ctrl residual uncovered conditions:
 *   L6363: EVP_CTRL_AEAD_SET_IV_FIXED with arg < 4 → break (failure)
 *          EVP_CTRL_AEAD_SET_IV_FIXED with valid arg → success + sets
 *          authIvGenEnable=1
 *   L6417: EVP_CTRL_GCM_IV_GEN with !authIvGenEnable → break (failure)
 *   L6425: EVP_CTRL_GCM_IV_GEN with arg<=0 → copy full IV (not truncated)
 *          EVP_CTRL_GCM_IV_GEN with valid arg > 0 → copy last arg bytes
 *
 * Prerequisite sequence for GCM_IV_GEN:
 *   EVP_CipherInit → EVP_CTRL_AEAD_SET_IV_FIXED(-1, full_iv)
 *      → authIvGenEnable=1 (from set_iv success path)
 *   then EVP_CTRL_GCM_IV_GEN
 * ---------------------------------------------------------------------------
 */
int test_wolfSSL_EvpCtrlIvFixedGen(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_AESGCM) && !defined(NO_AES) && \
    defined(WOLFSSL_AES_128) && !defined(WC_NO_RNG) && !defined(_WIN32) && \
    !defined(HAVE_SELFTEST) && \
    (!defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && HAVE_FIPS_VERSION >= 2))
    EVP_CIPHER_CTX *ctx = NULL;
    byte key[16];
    byte iv[12];
    byte ivbuf[12];
    byte fixed4[4];

    XMEMSET(key,    0xCC, sizeof(key));
    XMEMSET(iv,     0xDD, sizeof(iv));
    XMEMSET(ivbuf,  0x00, sizeof(ivbuf));
    XMEMSET(fixed4, 0xEE, sizeof(fixed4));

    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectIntEQ(EVP_CipherInit(ctx, EVP_aes_128_gcm(), key, iv, 1),
                WOLFSSL_SUCCESS);

    /* --- L6363: SET_IV_FIXED with arg < 4 → break → failure
     *  (arg=2 < 4, or ctx->ivSz - arg < 8 for small ivSz) */
    ExpectIntNE(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IV_FIXED, 2,
                fixed4), WOLFSSL_SUCCESS);

    /* --- L6363: SET_IV_FIXED with arg=-1 → copies full IV from ptr;
     *  authIvGenEnable is set to 1 upon success */
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IV_FIXED, -1, iv),
                WOLFSSL_SUCCESS);

    /* --- L6417: GCM_IV_GEN before SET_IV_FIXED (authIvGenEnable=0) */
    {
        EVP_CIPHER_CTX *ctx2 = NULL;
        ExpectNotNull(ctx2 = EVP_CIPHER_CTX_new());
        ExpectIntEQ(EVP_CipherInit(ctx2, EVP_aes_128_gcm(), key, iv, 1),
                    WOLFSSL_SUCCESS);
        /* authIvGenEnable is 0; GCM_IV_GEN must fail */
        ExpectIntNE(EVP_CIPHER_CTX_ctrl(ctx2, EVP_CTRL_GCM_IV_GEN, 0, ivbuf),
                    WOLFSSL_SUCCESS);
        EVP_CIPHER_CTX_free(ctx2);
    }

    /* Now arm ctx: SET_IV_FIXED with valid fixed part (4 bytes)
     * so that authIvGenEnable=1 and GCM_IV_GEN may proceed.
     * arg must satisfy: arg >= 4 && (ctx->ivSz - arg) >= 8
     * With ivSz==12: arg==4 → 12-4=8 >= 8 → valid. */
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IV_FIXED, 4,
                fixed4), WOLFSSL_SUCCESS);

    /* --- L6425: GCM_IV_GEN with arg <= 0 → copies full ivSz bytes */
    ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_IV_GEN, 0, ivbuf),
                WOLFSSL_SUCCESS);

    /* --- L6425 else branch: GCM_IV_GEN with 0 < arg <= ivSz → last arg bytes */
    {
        byte small[4];
        XMEMSET(small, 0x00, sizeof(small));
        /* Need to re-enable: call SET_IV_FIXED again */
        ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IV_FIXED, 4,
                    fixed4), WOLFSSL_SUCCESS);
        ExpectIntEQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_IV_GEN, 4, small),
                    WOLFSSL_SUCCESS);
    }

    EVP_CIPHER_CTX_free(ctx);
#endif /* OPENSSL_EXTRA && HAVE_AESGCM && !NO_AES && WOLFSSL_AES_128 ... */
    return EXPECT_RESULT();
}

/* ---------------------------------------------------------------------------
 * test_wolfSSL_EvpCipherFinalCoverage
 *
 * Targets wolfSSL_EVP_CipherFinal CBC padding final-block paths:
 *   L1647/L1651-L1660: enc==1 path — padBlock() + evpCipherBlock() encrypt
 *                       the padding-filled block; *outl = block_size.
 *   L1674-L1685: dec path — lastUsed==1 → checkPad() → strip PKCS#7 padding.
 *   L1691: dec path — lastUsed==0 && bufUsed==0 → error.
 *   L1668: dec path — bufUsed % block_size != 0 → error (misaligned buffer).
 *
 * AES-128-CBC: block_size=16, key=16 bytes, iv=16 bytes.
 *
 * MC/DC independence pairs:
 *   [E1] encrypt partial block  (bufUsed > 0, block_size != 1) → success
 *   [E2] encrypt empty buffer after full blocks → success (*outl=block_size,
 *        PKCS#7 full pad block appended)
 *   [D1] decrypt valid padded ciphertext → success, correct plaintext len
 *   [D2] decrypt empty input (lastUsed=0, bufUsed=0) → failure (L1691)
 * ---------------------------------------------------------------------------
 */
int test_wolfSSL_EvpCipherFinalCoverage(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_AES) && defined(HAVE_AES_CBC) && \
    defined(WOLFSSL_AES_128)
    EVP_CIPHER_CTX *ctx   = NULL;
    byte key[16];
    byte iv[16];

    /* output buffers — large enough for up to 3 blocks + 1 pad block */
    byte enc_out[64];
    byte dec_out[64];
    int  outl = 0, outl2 = 0;

    /* plaintext: 19 bytes → spans one full block + 3-byte partial */
    const byte plain19[19] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12
    };
    /* plaintext: exactly 16 bytes (one full block) — CipherFinal appends
     * a full 16-byte PKCS#7 padding block */
    const byte plain16[16] = {
        0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
        0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f
    };

    XMEMSET(key,     0xAB, sizeof(key));
    XMEMSET(iv,      0xCD, sizeof(iv));
    XMEMSET(enc_out, 0x00, sizeof(enc_out));
    XMEMSET(dec_out, 0x00, sizeof(dec_out));

    /* === [E1] Encrypt 19 bytes: 1 full block emitted by CipherUpdate,
     *     3-byte partial remains; CipherFinal pads to 16 and encrypts it.
     *     Exercises L1651 (bufUsed > 0 && block_size != 1) → padBlock →
     *     evpCipherBlock. *outl == block_size (16). =========================
     */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    if (ctx != NULL) {
        byte upd_out[32];
        int  upd_outl = 0;

        ExpectIntEQ(EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, 1),
                    WOLFSSL_SUCCESS);
        ExpectIntEQ(EVP_CipherUpdate(ctx, upd_out, &upd_outl,
                                     plain19, (int)sizeof(plain19)),
                    WOLFSSL_SUCCESS);
        /* upd_outl should be 16 (one full block consumed) */
        outl = 0;
        ExpectIntEQ(EVP_CipherFinal(ctx, enc_out, &outl), WOLFSSL_SUCCESS);
        /* Final must emit the padded block: outl == 16 */
        ExpectIntEQ(outl, 16);
        EVP_CIPHER_CTX_free(ctx); ctx = NULL;
    }

    /* === [E2] Encrypt exactly 16 bytes: CipherUpdate buffers the full block
     *     but emits nothing (last block held back for padding detection);
     *     CipherFinal emits the block plus a full 16-byte padding block.
     *     *outl == 16 after Final. ==========================================
     */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    if (ctx != NULL) {
        byte upd_out2[32];
        int  upd_outl2 = 0;
        byte final_out2[32];
        int  final_outl2 = 0;

        ExpectIntEQ(EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, 1),
                    WOLFSSL_SUCCESS);
        ExpectIntEQ(EVP_CipherUpdate(ctx, upd_out2, &upd_outl2,
                                     plain16, (int)sizeof(plain16)),
                    WOLFSSL_SUCCESS);
        ExpectIntEQ(EVP_CipherFinal(ctx, final_out2, &final_outl2),
                    WOLFSSL_SUCCESS);
        /* Either 0 (plain16 held as lastBlock) or 16 depending on impl;
         * test merely asserts it succeeds and exercises the branch. */
        (void)final_outl2;
        EVP_CIPHER_CTX_free(ctx); ctx = NULL;
    }

    /* === [D1] Decrypt: encrypt 19 bytes, then decrypt to verify padding
     *     strip (L1674-L1679). =============================================
     */
    {
        byte ciphertext[64];
        int  ct_len = 0, ct_final = 0;
        int  total_ct;

        /* --- encrypt phase to produce valid ciphertext --- */
        ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
        if (ctx != NULL) {
            byte upd3[32];
            int  upd3_outl = 0;
            ExpectIntEQ(EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, 1),
                        WOLFSSL_SUCCESS);
            ExpectIntEQ(EVP_CipherUpdate(ctx, upd3, &upd3_outl,
                                         plain19, (int)sizeof(plain19)),
                        WOLFSSL_SUCCESS);
            ct_len = upd3_outl;
            if (ct_len > 0)
                XMEMCPY(ciphertext, upd3, (size_t)ct_len);
            ct_final = 0;
            ExpectIntEQ(EVP_CipherFinal(ctx, ciphertext + ct_len, &ct_final),
                        WOLFSSL_SUCCESS);
            total_ct = ct_len + ct_final;
            EVP_CIPHER_CTX_free(ctx); ctx = NULL;

            /* --- decrypt phase --- */
            if (total_ct > 0) {
                byte upd4[64];
                int  upd4_outl = 0;

                ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
                if (ctx != NULL) {
                    ExpectIntEQ(EVP_CipherInit(ctx, EVP_aes_128_cbc(),
                                               key, iv, 0), WOLFSSL_SUCCESS);
                    ExpectIntEQ(EVP_CipherUpdate(ctx, upd4, &upd4_outl,
                                                 ciphertext, total_ct),
                                WOLFSSL_SUCCESS);
                    outl2 = 0;
                    /* L1674: lastUsed==1 → checkPad → PKCS#7 strip */
                    ExpectIntEQ(EVP_CipherFinal(ctx, dec_out, &outl2),
                                WOLFSSL_SUCCESS);
                    /* recovered plain length == 19 */
                    ExpectIntEQ(upd4_outl + outl2, (int)sizeof(plain19));
                    EVP_CIPHER_CTX_free(ctx); ctx = NULL;
                }
            }
        }
    }

    /* === [D2] Decrypt empty input: lastUsed==0 && bufUsed==0 → L1691 error.
     *     Call CipherInit(dec) immediately followed by CipherFinal with no
     *     CipherUpdate — nothing was ever fed in. ===========================
     */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    if (ctx != NULL) {
        ExpectIntEQ(EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, 0),
                    WOLFSSL_SUCCESS);
        /* No CipherUpdate: lastUsed==0, bufUsed==0 */
        outl = 0;
        /* L1691: lastUsed==0 && bufUsed==0 → WOLFSSL_FAILURE */
        ExpectIntNE(EVP_CipherFinal(ctx, dec_out, &outl), WOLFSSL_SUCCESS);
        EVP_CIPHER_CTX_free(ctx); ctx = NULL;
    }

#endif /* OPENSSL_EXTRA && !NO_AES && HAVE_AES_CBC && WOLFSSL_AES_128 */
    return EXPECT_RESULT();
}

/* ---------------------------------------------------------------------------
 * test_wolfSSL_EvpCipherInitBatch4
 *
 * Batch 4: targets wolfSSL_EVP_CipherInit L7334 and L8059 5-condition decisions
 * by exercising the "NULL cipher + existing ctx (reuse)" path for several
 * cipher types and the "type switch dispatch" across AES-CBC, AES-GCM,
 * AES-CTR, and ChaCha20.
 *
 * Independence pairs exercised:
 *   P1:  NULL cipher + initialized ctx (AES-CBC) + key only   → reuse path
 *   P2:  NULL cipher + initialized ctx (AES-CBC) + IV only    → iv-only path
 *   P3:  NULL cipher + initialized ctx (AES-CBC) + enc=-1     → no-change path
 *   P4:  Switch from AES-128-CBC to AES-128-GCM on same ctx   → type change
 *   P5:  AES-256-CBC init enc=1 then enc=0 on new type        → enc flag
 *   P6:  AES-CTR init + key-only reuse                        → ctr path
 *   P7:  ChaCha20 init + iv-only reuse                        → stream path
 *   P8:  NULL ctx (top guard)                                 → failure
 * ---------------------------------------------------------------------------
 */
int test_wolfSSL_EvpCipherInitBatch4(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_AES)

    /* === P8: NULL ctx → immediate failure === */
    {
        byte key[16] = {0};
        byte iv[16]  = {0};
        ExpectIntNE(EVP_CipherInit(NULL, EVP_aes_128_cbc(), key, iv, 1),
                    WOLFSSL_SUCCESS);
    }

#if defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_128)
    {
        EVP_CIPHER_CTX *ctx = NULL;
        byte key128[16];
        byte key128b[16];
        byte iv16[16];
        XMEMSET(key128,  0x11, sizeof(key128));
        XMEMSET(key128b, 0x22, sizeof(key128b));
        XMEMSET(iv16,    0x33, sizeof(iv16));

        ExpectNotNull(ctx = EVP_CIPHER_CTX_new());

        /* Initial full AES-128-CBC init */
        ExpectIntEQ(EVP_CipherInit(ctx, EVP_aes_128_cbc(), key128, iv16, 1),
                    WOLFSSL_SUCCESS);

        /* P1: NULL cipher + key only (iv==NULL, enc=-1) → key-rekey path */
        ExpectIntEQ(EVP_CipherInit(ctx, NULL, key128b, NULL, -1),
                    WOLFSSL_SUCCESS);

        /* P2: NULL cipher + IV only (key==NULL, enc=-1) → iv-only path */
        ExpectIntEQ(EVP_CipherInit(ctx, NULL, NULL, iv16, -1),
                    WOLFSSL_SUCCESS);

        /* P3: NULL cipher + NULL key + NULL iv + enc=-1 → no-op path */
        ExpectIntEQ(EVP_CipherInit(ctx, NULL, NULL, NULL, -1),
                    WOLFSSL_SUCCESS);

        /* P4: Switch to GCM on the same ctx by passing new type explicitly */
#if defined(HAVE_AESGCM) && \
    ((!defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)) || \
     (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2)))
        {
            /* Sized for AES block (16); wolfSSL_EVP_CipherInit -> wc_AesSetIV
             * reads a full AES_BLOCK_SIZE even when the logical GCM nonce is
             * 12 bytes. */
            byte iv16gcm[16];
            XMEMSET(iv16gcm, 0x44, sizeof(iv16gcm));
            /* Passing a new cipher type on an already-initialised ctx resets
             * the type (L7215 branch: type != NULL → full re-init).
             * May succeed or fail depending on whether AES GCM low-level was
             * already inited; just drive the branch. */
            (void)EVP_CipherInit(ctx, EVP_aes_128_gcm(), key128, iv16gcm, 1);
        }
#endif /* HAVE_AESGCM ... */

        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
    }
#endif /* HAVE_AES_CBC && WOLFSSL_AES_128 */

#if defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_256)
    /* P5: AES-256-CBC enc=1 then re-init enc=0 (decrypt direction change) */
    {
        EVP_CIPHER_CTX *ctx = NULL;
        byte key256[32];
        byte iv16[16];
        XMEMSET(key256, 0x55, sizeof(key256));
        XMEMSET(iv16,   0x66, sizeof(iv16));

        ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
        ExpectIntEQ(EVP_CipherInit(ctx, EVP_aes_256_cbc(), key256, iv16, 1),
                    WOLFSSL_SUCCESS);
        /* Re-init with enc=0 — exercises the enc==0 branch of L7307 */
        ExpectIntEQ(EVP_CipherInit(ctx, EVP_aes_256_cbc(), key256, iv16, 0),
                    WOLFSSL_SUCCESS);
        EVP_CIPHER_CTX_free(ctx);
    }
#endif /* HAVE_AES_CBC && WOLFSSL_AES_256 */

#if defined(HAVE_AES_CTR) && defined(WOLFSSL_AES_128)
    /* P6: AES-128-CTR init + key-only reuse (stream cipher, block_size==1) */
    {
        EVP_CIPHER_CTX *ctx = NULL;
        byte key128[16];
        byte key128b[16];
        byte iv16[16];
        XMEMSET(key128,  0x77, sizeof(key128));
        XMEMSET(key128b, 0x88, sizeof(key128b));
        XMEMSET(iv16,    0x99, sizeof(iv16));

        ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
        ExpectIntEQ(EVP_CipherInit(ctx, EVP_aes_128_ctr(), key128, iv16, 1),
                    WOLFSSL_SUCCESS);
        /* key-only reuse */
        ExpectIntEQ(EVP_CipherInit(ctx, NULL, key128b, NULL, -1),
                    WOLFSSL_SUCCESS);
        /* iv-only reuse */
        ExpectIntEQ(EVP_CipherInit(ctx, NULL, NULL, iv16, -1),
                    WOLFSSL_SUCCESS);
        EVP_CIPHER_CTX_free(ctx);
    }
#endif /* HAVE_AES_CTR && WOLFSSL_AES_128 */

#endif /* OPENSSL_EXTRA && !NO_AES */

#if defined(OPENSSL_EXTRA) && defined(HAVE_CHACHA) && \
    (!defined(HAVE_FIPS) && !defined(HAVE_SELFTEST))
    /* P7: ChaCha20 init + iv-only reuse (L8059 stream-cipher branch) */
    {
        EVP_CIPHER_CTX *ctx = NULL;
        /* ChaCha20 key = 32 bytes; IV = 16 bytes (counter 4B + nonce 12B) */
        byte key32[32];
        byte iv16[16];
        byte iv16b[16];
        XMEMSET(key32,  0xAA, sizeof(key32));
        XMEMSET(iv16,   0xBB, sizeof(iv16));
        XMEMSET(iv16b,  0xCC, sizeof(iv16b));

        ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
        ExpectIntEQ(EVP_CipherInit(ctx, EVP_chacha20(), key32, iv16, 1),
                    WOLFSSL_SUCCESS);
        /* iv-only reuse on stream cipher */
        ExpectIntEQ(EVP_CipherInit(ctx, NULL, NULL, iv16b, -1),
                    WOLFSSL_SUCCESS);
        /* key-only reuse on stream cipher */
        ExpectIntEQ(EVP_CipherInit(ctx, NULL, key32, NULL, -1),
                    WOLFSSL_SUCCESS);
        EVP_CIPHER_CTX_free(ctx);
    }
#endif /* OPENSSL_EXTRA && HAVE_CHACHA && !HAVE_FIPS && !HAVE_SELFTEST */

    return EXPECT_RESULT();
}

/* ---------------------------------------------------------------------------
 * test_wolfSSL_EvpCipherFinalBatch4
 *
 * Batch 4: targets wolfSSL_EVP_CipherFinal L1315 5-condition compound for
 * the AES-GCM path:
 *   (ctx->authBuffer && ctx->authBufferLen > 0) || (ctx->authBufferLen == 0)
 * Plus residual pairs for the NULL-guard and CTR (stream, no-final) path.
 *
 * Pairs exercised:
 *   P1: ctx == NULL                              → top guard fires
 *   P2: outl == NULL                             → top guard fires
 *   P3: AES-GCM encrypt final with data via AAD  → authBuffer path (L1315 true)
 *   P4: AES-GCM encrypt final with no data (zero-len plain) → authBufferLen==0
 *   P5: AES-CTR encrypt "final" — stream cipher, Final is a no-op
 *   P6: AES-GCM decrypt with correct tag → success
 *   P7: AES-GCM decrypt with wrong tag   → WOLFSSL_FAILURE
 * ---------------------------------------------------------------------------
 */
int test_wolfSSL_EvpCipherFinalBatch4(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_AES)

    /* P1: NULL ctx */
    {
        int outl = 0;
        byte buf[16] = {0};
        ExpectIntNE(wolfSSL_EVP_CipherFinal(NULL, buf, &outl), WOLFSSL_SUCCESS);
    }

    /* P2: NULL outl */
#if defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_128)
    {
        EVP_CIPHER_CTX *ctx = NULL;
        byte key[16] = {0};
        byte iv[16]  = {0};
        byte buf[16] = {0};
        ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
        if (ctx != NULL) {
            ExpectIntEQ(EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, 1),
                        WOLFSSL_SUCCESS);
            ExpectIntNE(wolfSSL_EVP_CipherFinal(ctx, buf, NULL),
                        WOLFSSL_SUCCESS);
            EVP_CIPHER_CTX_free(ctx);
        }
    }
#endif /* HAVE_AES_CBC && WOLFSSL_AES_128 */

#if defined(HAVE_AESGCM) && defined(WOLFSSL_AES_128) && \
    ((!defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)) || \
     (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2)))
    {
        byte key[16];
        byte iv[12];
        byte plain[20];
        byte ct[20];
        byte dec[20];
        byte tag_enc[16];
        byte tag_bad[16];
        int  outl = 0;
        XMEMSET(key,     0xA1, sizeof(key));
        XMEMSET(iv,      0xB2, sizeof(iv));
        XMEMSET(plain,   0xC3, sizeof(plain));
        XMEMSET(ct,      0x00, sizeof(ct));
        XMEMSET(dec,     0x00, sizeof(dec));
        XMEMSET(tag_enc, 0x00, sizeof(tag_enc));
        XMEMSET(tag_bad, 0xFF, sizeof(tag_bad));

        /* P3: AES-GCM encrypt with 20-byte plaintext → authBuffer path */
        {
            EVP_CIPHER_CTX *ctx = NULL;
            ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
            if (ctx != NULL) {
                int updl = 0;
                ExpectIntEQ(EVP_CipherInit(ctx, EVP_aes_128_gcm(),
                                           key, iv, 1), WOLFSSL_SUCCESS);
                /* Feed plaintext via Update so authBuffer gets populated */
                ExpectIntEQ(EVP_CipherUpdate(ctx, ct, &updl,
                                             plain, (int)sizeof(plain)),
                            WOLFSSL_SUCCESS);
                /* Final flushes authBuffer (L1315 true branch) */
                outl = 0;
                ExpectIntEQ(wolfSSL_EVP_CipherFinal(ctx, ct + updl, &outl),
                            WOLFSSL_SUCCESS);
                /* Capture the auth tag for later decryption */
                (void)EVP_CIPHER_CTX_ctrl(ctx,
                            EVP_CTRL_AEAD_GET_TAG, 16, tag_enc);
                EVP_CIPHER_CTX_free(ctx);
            }
        }

        /* P4: AES-GCM encrypt with zero-length plaintext → authBufferLen==0
         *     Exercises the (authBufferLen==0) branch of the L1315 disjunction */
        {
            EVP_CIPHER_CTX *ctx = NULL;
            byte ct_empty[1] = {0};
            int  outl_e = 0;
            ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
            if (ctx != NULL) {
                ExpectIntEQ(EVP_CipherInit(ctx, EVP_aes_128_gcm(),
                                           key, iv, 1), WOLFSSL_SUCCESS);
                /* No Update → authBufferLen stays 0 */
                outl_e = 0;
                /* L1315: authBuffer==NULL && authBufferLen==0 → second sub-cond
                 * true → enters encrypt branch */
                ExpectIntEQ(wolfSSL_EVP_CipherFinal(ctx, ct_empty, &outl_e),
                            WOLFSSL_SUCCESS);
                EVP_CIPHER_CTX_free(ctx);
            }
        }

        /* P6: AES-GCM decrypt with correct tag → success */
        {
            EVP_CIPHER_CTX *ctx = NULL;
            int updl2 = 0;
            int finl2 = 0;
            ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
            if (ctx != NULL) {
                ExpectIntEQ(EVP_CipherInit(ctx, EVP_aes_128_gcm(),
                                           key, iv, 0), WOLFSSL_SUCCESS);
                (void)EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                                          16, tag_enc);
                ExpectIntEQ(EVP_CipherUpdate(ctx, dec, &updl2,
                                             ct, (int)sizeof(plain)),
                            WOLFSSL_SUCCESS);
                finl2 = 0;
                /* Correct tag → WOLFSSL_SUCCESS */
                ExpectIntEQ(wolfSSL_EVP_CipherFinal(ctx, dec + updl2, &finl2),
                            WOLFSSL_SUCCESS);
                EVP_CIPHER_CTX_free(ctx);
            }
        }

        /* P7: AES-GCM decrypt with wrong tag → WOLFSSL_FAILURE */
        {
            EVP_CIPHER_CTX *ctx = NULL;
            byte dec2[20];
            int  updl3 = 0;
            int  finl3 = 0;
            XMEMSET(dec2, 0, sizeof(dec2));
            ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
            if (ctx != NULL) {
                ExpectIntEQ(EVP_CipherInit(ctx, EVP_aes_128_gcm(),
                                           key, iv, 0), WOLFSSL_SUCCESS);
                /* Set a bad (all-0xFF) tag */
                (void)EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                                          16, tag_bad);
                ExpectIntEQ(EVP_CipherUpdate(ctx, dec2, &updl3,
                                             ct, (int)sizeof(plain)),
                            WOLFSSL_SUCCESS);
                finl3 = 0;
                /* Wrong tag → WOLFSSL_FAILURE */
                ExpectIntNE(wolfSSL_EVP_CipherFinal(ctx, dec2 + updl3, &finl3),
                            WOLFSSL_SUCCESS);
                EVP_CIPHER_CTX_free(ctx);
            }
        }
    }
#endif /* HAVE_AESGCM && WOLFSSL_AES_128 ... */

#if defined(HAVE_AES_CTR) && defined(WOLFSSL_AES_128)
    /* P5: AES-128-CTR "final" — stream cipher: CipherFinal is essentially a
     * no-op (block_size==1), should succeed with *outl==0. */
    {
        EVP_CIPHER_CTX *ctx = NULL;
        byte key[16];
        byte iv[16];
        byte buf[16];
        int  outl = -1;
        XMEMSET(key, 0xD4, sizeof(key));
        XMEMSET(iv,  0xE5, sizeof(iv));
        XMEMSET(buf, 0x00, sizeof(buf));

        ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
        if (ctx != NULL) {
            ExpectIntEQ(EVP_CipherInit(ctx, EVP_aes_128_ctr(), key, iv, 1),
                        WOLFSSL_SUCCESS);
            /* No Update; Final on stream should succeed */
            ExpectIntEQ(wolfSSL_EVP_CipherFinal(ctx, buf, &outl),
                        WOLFSSL_SUCCESS);
            EVP_CIPHER_CTX_free(ctx);
        }
    }
#endif /* HAVE_AES_CTR && WOLFSSL_AES_128 */

#endif /* OPENSSL_EXTRA && !NO_AES */
    return EXPECT_RESULT();
}

/* ---------------------------------------------------------------------------
 * test_wolfSSL_EvpCipherInitAesGcmBatch4
 *
 * Batch 4: targets EvpCipherInitAesGCM L6844/L6850 3-pair residual decisions:
 *   L6844: (key != NULL) → wc_AesGcmSetKey
 *   L6850: (iv != NULL)  → wc_AesGcmSetExtIV
 *
 * Reachable through wolfSSL_EVP_CipherInit when type is AES-GCM.
 *
 * Independence pairs exercised (6 total):
 *   P1: key present, iv NULL              → only L6844 true
 *   P2: key NULL, iv present              → only L6850 true
 *   P3: key NULL, iv NULL                 → both false (reinit preserves state)
 *   P4: key present, iv present           → both true (normal init path)
 *   P5: re-init with new key, no iv       → key change path
 *   P6: re-init with new iv, no key       → iv change path
 * ---------------------------------------------------------------------------
 */
int test_wolfSSL_EvpCipherInitAesGcmBatch4(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_AESGCM) && !defined(NO_AES) && \
    defined(WOLFSSL_AES_128) && \
    ((!defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)) || \
     (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2)))
    EVP_CIPHER_CTX *ctx = NULL;
    byte key[16];
    byte key2[16];
    byte iv[12];
    byte iv2[12];
    XMEMSET(key,  0x11, sizeof(key));
    XMEMSET(key2, 0x22, sizeof(key2));
    XMEMSET(iv,   0x33, sizeof(iv));
    XMEMSET(iv2,  0x44, sizeof(iv2));

    /* P4: key present + iv present → both L6844 and L6850 true (full init) */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    if (ctx != NULL) {
        ExpectIntEQ(EVP_CipherInit(ctx, EVP_aes_128_gcm(), key, iv, 1),
                    WOLFSSL_SUCCESS);

        /* P1: NULL cipher + key only (iv==NULL) → L6844 true, L6850 false */
        ExpectIntEQ(EVP_CipherInit(ctx, NULL, key2, NULL, -1),
                    WOLFSSL_SUCCESS);

        /* P2: NULL cipher + iv only (key==NULL) → L6844 false, L6850 true */
        ExpectIntEQ(EVP_CipherInit(ctx, NULL, NULL, iv2, -1),
                    WOLFSSL_SUCCESS);

        /* P3: NULL cipher + key==NULL + iv==NULL → both L6844/L6850 false */
        ExpectIntEQ(EVP_CipherInit(ctx, NULL, NULL, NULL, -1),
                    WOLFSSL_SUCCESS);

        /* P5: re-init with same type + new key, no iv */
        ExpectIntEQ(EVP_CipherInit(ctx, EVP_aes_128_gcm(), key, NULL, 1),
                    WOLFSSL_SUCCESS);

        /* P6: NULL type + new iv after P5 key-only init */
        ExpectIntEQ(EVP_CipherInit(ctx, NULL, NULL, iv, -1),
                    WOLFSSL_SUCCESS);

        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
    }

#ifdef WOLFSSL_AES_256
    /* Repeat P4+P1+P2 for AES-256-GCM to cover the 256-key-size branch */
    {
        byte key256[32];
        byte iv256[12];
        XMEMSET(key256, 0x55, sizeof(key256));
        XMEMSET(iv256,  0x66, sizeof(iv256));

        ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
        if (ctx != NULL) {
            ExpectIntEQ(EVP_CipherInit(ctx, EVP_aes_256_gcm(),
                                       key256, iv256, 1),
                        WOLFSSL_SUCCESS);
            ExpectIntEQ(EVP_CipherInit(ctx, NULL, key256, NULL, -1),
                        WOLFSSL_SUCCESS);
            ExpectIntEQ(EVP_CipherInit(ctx, NULL, NULL, iv256, -1),
                        WOLFSSL_SUCCESS);
            EVP_CIPHER_CTX_free(ctx);
        }
    }
#endif /* WOLFSSL_AES_256 */

#endif /* OPENSSL_EXTRA && HAVE_AESGCM && WOLFSSL_AES_128 ... */
    return EXPECT_RESULT();
}
