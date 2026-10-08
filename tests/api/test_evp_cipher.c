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
    ExpectIntEQ(EVP_CIPHER_CTX_is_encrypting(ctx), 1);
    ExpectIntEQ(EVP_CIPHER_CTX_encrypting(ctx), 1);
    ExpectIntEQ(EVP_CipherInit(ctx, NULL, key, iv, 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_CIPHER_CTX_is_encrypting(ctx), 0);
    ExpectIntEQ(EVP_CIPHER_CTX_is_encrypting(NULL), 0);

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
    #ifdef WOLFSSL_AES_CFB
    #ifdef WOLFSSL_AES_128
        NID_aes_128_cfb128,
    #endif
    #ifdef WOLFSSL_AES_192
        NID_aes_192_cfb128,
    #endif
    #ifdef WOLFSSL_AES_256
        NID_aes_256_cfb128,
    #endif
    #endif /* WOLFSSL_AES_CFB */
    #ifdef WOLFSSL_AES_OFB
    #ifdef WOLFSSL_AES_128
        NID_aes_128_ofb,
    #endif
    #ifdef WOLFSSL_AES_192
        NID_aes_192_ofb,
    #endif
    #ifdef WOLFSSL_AES_256
        NID_aes_256_ofb,
    #endif
    #endif /* WOLFSSL_AES_OFB */
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
    #ifdef WOLFSSL_AES_CFB
    #ifdef WOLFSSL_AES_128
            AES_BLOCK_SIZE,
    #endif
    #ifdef WOLFSSL_AES_192
            AES_BLOCK_SIZE,
    #endif
    #ifdef WOLFSSL_AES_256
            AES_BLOCK_SIZE,
    #endif
    #endif /* WOLFSSL_AES_CFB */
    #ifdef WOLFSSL_AES_OFB
    #ifdef WOLFSSL_AES_128
            AES_BLOCK_SIZE,
    #endif
    #ifdef WOLFSSL_AES_192
            AES_BLOCK_SIZE,
    #endif
    #ifdef WOLFSSL_AES_256
            AES_BLOCK_SIZE,
    #endif
    #endif /* WOLFSSL_AES_OFB */
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
#if !defined(NO_AES) && defined(HAVE_AES_CBC) && defined(OPENSSL_ALL) && \
    defined(WOLFSSL_ENCRYPTED_KEYS) && !defined(NO_PWDBASED)
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
            /* GCM's default IV length is 96 bits; this branch takes
             * that default rather than setting one. */
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
            /* GCM's default IV length is 96 bits; this branch takes
             * that default rather than setting one. */
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
            /* GCM's default IV length is 96 bits; this branch takes
             * that default rather than setting one. */
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
            /* CCM's default nonce is 7 bytes, as in OpenSSL; this branch
             * takes it rather than setting one. */
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
        /* The CCM tag length defaults to 12 bytes, as in OpenSSL, and the
         * tag is read back below at AES_BLOCK_SIZE, so ask for that length.
         * Passing a NULL tag sets the length alone, which is the only form
         * allowed while encrypting. */
        ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&en[i], EVP_CTRL_CCM_SET_TAG,
            AES_BLOCK_SIZE, NULL));
        /* CCM carries the payload length in its first block, so it has to be
         * declared - in and out both NULL - before any AAD. */
        ExpectIntEQ(1, EVP_EncryptUpdate(&en[i], NULL, &len, NULL, plaintxtSz));
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
            /* CCM's default nonce is 7 bytes, as in OpenSSL; this branch
             * takes it rather than setting one. */
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
        /* CCM verifies as it decrypts, inside EVP_DecryptUpdate(), so the
         * tag has to be set before the ciphertext is passed in - as OpenSSL
         * documents for this mode. */
        ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_CCM_SET_TAG,
            AES_BLOCK_SIZE, tag));
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], NULL, &len, NULL,
            ciphertxtSz));
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], NULL, &len, aad, aadSz));
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], decryptedtxt, &len, ciphertxt,
            ciphertxtSz));
        decryptedtxtSz = len;
        ExpectIntEQ(1, EVP_DecryptFinal_ex(&de[i], decryptedtxt, &len));
        decryptedtxtSz += len;
        ExpectIntEQ(ciphertxtSz, decryptedtxtSz);
        ExpectIntEQ(0, XMEMCMP(plaintxt, decryptedtxt, decryptedtxtSz));

        /* modify tag*/
        tag[AES_BLOCK_SIZE-1]+=0xBB;
        /* A second message on the same context begins with
         * EVP_DecryptInit_ex(). That is what clears the length and the AAD
         * the message above accumulated; declaring the length again does not,
         * and is refused. */
        ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], NULL, NULL, key, iv));
        ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_CCM_SET_TAG,
            AES_BLOCK_SIZE, tag));
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], NULL, &len, NULL,
            ciphertxtSz));
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], NULL, &len, aad, aadSz));
        /* Fail due to wrong tag. The update that decrypts reports it, and
         * returns no plaintext; final has nothing left to check. */
        ExpectIntEQ(0, EVP_DecryptUpdate(&de[i], decryptedtxt, &len, ciphertxt,
            ciphertxtSz));
        ExpectIntEQ(0, len);
        ExpectIntEQ(1, EVP_DecryptFinal_ex(&de[i], decryptedtxt, &len));
        ExpectIntEQ(0, len);
        ret = wolfSSL_EVP_CIPHER_CTX_cleanup(&de[i]);
        ExpectIntEQ(ret, 1);
    }
#endif /* OPENSSL_EXTRA && !NO_AES && HAVE_AESCCM */
    return EXPECT_RESULT();
}

/* The EVP interface to CCM follows a contract OpenSSL documents in
 * EVP_EncryptInit(3), and which differs from the other AEAD modes: the payload
 * length is part of the first block, so it has to be settled before anything
 * is processed, and there is no streaming. These check each rule that follows
 * from that, since a context that differs on any of them produces output no
 * other implementation will accept.
 */
/* EVP_CipherInit() on a context that already holds a cipher has to adopt the
 * new one. The cipher is selected from its name once, up front, so a context
 * carrying some other cipher cannot divert the call - which is what happened
 * when each cipher tested for itself and the first match won.
 */
int test_wolfssl_EVP_cipher_reinit(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_AES) && defined(HAVE_AES_CBC)
    byte key[32];
    byte iv[16];
    int i;
    /* Ciphers that share a key schedule or a name prefix, where a stale
     * cipher type is most likely to be kept by mistake. */
    struct {
        const EVP_CIPHER* (*get)(void);
        int keyLen;
        int blockSize;
    } ciphers[] = {
    #ifdef WOLFSSL_AES_128
        { EVP_aes_128_cbc, 16, 16 },
    #endif
    /* Listed so that an AES-192 only build - the outer guard still takes this
     * test - does not end up with an empty initializer. */
    #ifdef WOLFSSL_AES_192
        { EVP_aes_192_cbc, 24, 16 },
    #endif
    #ifdef WOLFSSL_AES_256
        { EVP_aes_256_cbc, 32, 16 },
    #endif
    #ifdef HAVE_AES_ECB
        #ifdef WOLFSSL_AES_128
        { EVP_aes_128_ecb, 16, 16 },
        #endif
    #endif
    #ifndef NO_DES3
        { EVP_des_cbc,      8,  8 },
        { EVP_des_ede3_cbc, 24, 8 },
        #ifdef WOLFSSL_DES_ECB
        { EVP_des_ecb,      8,  8 },
        { EVP_des_ede3_ecb, 24, 8 },
        #endif
    #endif
    };
    int n = (int)(sizeof(ciphers) / sizeof(ciphers[0]));
    int j;

    for (i = 0; i < (int)sizeof(key); i++) key[i] = (byte)i;
    for (i = 0; i < (int)sizeof(iv);  i++) iv[i]  = (byte)(0x80 + i);

    /* Every ordered pair, so both "later cipher replaces earlier" and the
     * reverse are covered. */
    for (i = 0; i < n; i++) {
        for (j = 0; j < n; j++) {
            EVP_CIPHER_CTX* ctx = NULL;
            EVP_CIPHER_CTX* fresh = NULL;

            ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
            ExpectIntEQ(1, EVP_EncryptInit_ex(ctx, ciphers[i].get(), NULL, key,
                iv));
            ExpectIntEQ(1, EVP_EncryptInit_ex(ctx, ciphers[j].get(), NULL, key,
                iv));

            /* The re-initialized context has to describe the second cipher,
             * and describe it the same way a context that only ever held it
             * does. */
            ExpectNotNull(fresh = EVP_CIPHER_CTX_new());
            ExpectIntEQ(1, EVP_EncryptInit_ex(fresh, ciphers[j].get(), NULL,
                key, iv));

            ExpectIntEQ(ciphers[j].keyLen, EVP_CIPHER_CTX_key_length(ctx));
            ExpectIntEQ(ciphers[j].blockSize, EVP_CIPHER_CTX_block_size(ctx));
            ExpectIntEQ(EVP_CIPHER_CTX_key_length(fresh),
                EVP_CIPHER_CTX_key_length(ctx));
            ExpectIntEQ(EVP_CIPHER_CTX_block_size(fresh),
                EVP_CIPHER_CTX_block_size(ctx));
            ExpectIntEQ(EVP_CIPHER_CTX_nid(fresh), EVP_CIPHER_CTX_nid(ctx));

            EVP_CIPHER_CTX_free(fresh);
            EVP_CIPHER_CTX_free(ctx);
        }
    }
#endif
    return EXPECT_RESULT();
}

/* A cipher is identified by name. The usual case is one of the library's own
 * name constants, which is settled by comparing pointers, but a caller may
 * pass a string of its own; both have to reach the same cipher.
 */
int test_wolfssl_EVP_cipher_name_copy(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_AES) && defined(HAVE_AES_CBC) && \
    defined(WOLFSSL_AES_128)
    char name[32];
    const EVP_CIPHER* byConst = NULL;
    const EVP_CIPHER* byCopy = NULL;
    byte key[16];
    byte iv[16];
    int i;

    for (i = 0; i < (int)sizeof(key); i++) key[i] = (byte)i;
    for (i = 0; i < (int)sizeof(iv);  i++) iv[i]  = (byte)(0x80 + i);

    ExpectNotNull(byConst = EVP_aes_128_cbc());
    /* A separate copy of the same text, so the pointer cannot match. */
    XSTRNCPY(name, (const char*)byConst, sizeof(name) - 1);
    name[sizeof(name) - 1] = '\0';
    ExpectNotNull(byCopy = (const EVP_CIPHER*)name);
    ExpectTrue(byConst != byCopy);

    ExpectIntEQ(EVP_CIPHER_block_size(byConst), EVP_CIPHER_block_size(byCopy));
    ExpectIntEQ(EVP_CIPHER_key_length(byConst), EVP_CIPHER_key_length(byCopy));
    ExpectIntEQ(EVP_CIPHER_iv_length(byConst), EVP_CIPHER_iv_length(byCopy));
    ExpectIntEQ(EVP_CIPHER_nid(byConst), EVP_CIPHER_nid(byCopy));

    /* And it initializes a context the same way. */
    {
        EVP_CIPHER_CTX* a = NULL;
        EVP_CIPHER_CTX* b = NULL;

        ExpectNotNull(a = EVP_CIPHER_CTX_new());
        ExpectNotNull(b = EVP_CIPHER_CTX_new());
        ExpectIntEQ(1, EVP_EncryptInit_ex(a, byConst, NULL, key, iv));
        ExpectIntEQ(1, EVP_EncryptInit_ex(b, byCopy, NULL, key, iv));
        ExpectIntEQ(EVP_CIPHER_CTX_nid(a), EVP_CIPHER_CTX_nid(b));
        ExpectIntEQ(EVP_CIPHER_CTX_key_length(a), EVP_CIPHER_CTX_key_length(b));
        EVP_CIPHER_CTX_free(b);
        EVP_CIPHER_CTX_free(a);
    }

    /* A name that is no cipher at all resolves to nothing. */
    ExpectNull(EVP_get_cipherbyname("definitely-not-a-cipher"));
#endif
    return EXPECT_RESULT();
}

#if defined(OPENSSL_EXTRA) && !defined(HAVE_SELFTEST) && \
    !defined(HAVE_FIPS) && \
    ((!defined(NO_AES) && defined(HAVE_AESCCM)) || defined(WOLFSSL_SM4_CCM))
static int ccm_openssl_semantics(const EVP_CIPHER* cipher, int keyLen)
{
    EXPECT_DECLS;
    byte key[32];
    byte iv[13];
    byte pt[32];
    byte aad[16];
    byte out[64];
    byte tag[16];
    int i;
    int len = 0;
    EVP_CIPHER_CTX* ctx = NULL;

    for (i = 0; i < keyLen; i++) key[i] = (byte)i;
    for (i = 0; i < (int)sizeof(iv);  i++) iv[i]  = (byte)(0xA0 + i);
    for (i = 0; i < (int)sizeof(pt);  i++) pt[i]  = (byte)(i * 3 + 1);
    for (i = 0; i < (int)sizeof(aad); i++) aad[i] = (byte)(i * 5 + 2);

    /* Defaults, taken when neither length is set: a 7 byte nonce (L = 8) and
     * a 12 byte tag. Both feed the first block, so a context that defaults
     * differently does not merely produce a different length of tag. */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectIntEQ(1, EVP_EncryptInit_ex(ctx, cipher, NULL, NULL,
        NULL));
    ExpectIntEQ(7, EVP_CIPHER_CTX_iv_length(ctx));
    ExpectIntEQ(1, EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv));
    ExpectIntEQ(1, EVP_EncryptUpdate(ctx, NULL, &len, NULL, (int)sizeof(pt)));
    ExpectIntEQ(1, EVP_EncryptUpdate(ctx, out, &len, pt, (int)sizeof(pt)));
    /* The tag is only readable at the length in force, 12 by default. */
    ExpectIntEQ(0, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 12, tag));
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* Tag length: even, 4 through 16. A tag value may only be supplied when
     * decrypting, since when encrypting the tag is an output. */
    for (i = 0; i <= 18; i++) {
        int want = ((i >= 4) && (i <= 16) && ((i & 1) == 0));

        ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
        ExpectIntEQ(1, EVP_EncryptInit_ex(ctx, cipher, NULL, NULL,
            NULL));
        ExpectIntEQ(want, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, i,
            NULL));
        /* ... but never with a tag value while encrypting. */
        ExpectIntEQ(0, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, i, tag));
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;

        ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
        ExpectIntEQ(1, EVP_DecryptInit_ex(ctx, cipher, NULL, NULL,
            NULL));
        ExpectIntEQ(want, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, i,
            tag));
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
    }

    /* Nonce length: 7 through 13, because L = 15 - ivLen has to be 2 to 8. */
    for (i = 0; i <= 17; i++) {
        int want = ((i >= 7) && (i <= 13));

        ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
        ExpectIntEQ(1, EVP_EncryptInit_ex(ctx, cipher, NULL, NULL,
            NULL));
        ExpectIntEQ(want, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, i,
            NULL));
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
    }

    /* A declared length is reported back, the payload comes out of the update
     * that supplies it, and final produces nothing. */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectIntEQ(1, EVP_EncryptInit_ex(ctx, cipher, NULL, NULL,
        NULL));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL));
    ExpectIntEQ(1, EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv));
    len = 0;
    ExpectIntEQ(1, EVP_EncryptUpdate(ctx, NULL, &len, NULL, (int)sizeof(pt)));
    ExpectIntEQ((int)sizeof(pt), len);
    len = 0;
    ExpectIntEQ(1, EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)sizeof(aad)));
    ExpectIntEQ((int)sizeof(aad), len);
    len = 0;
    ExpectIntEQ(1, EVP_EncryptUpdate(ctx, out, &len, pt, (int)sizeof(pt)));
    ExpectIntEQ((int)sizeof(pt), len);
    len = -1;
    ExpectIntEQ(1, EVP_EncryptFinal_ex(ctx, out + sizeof(pt), &len));
    ExpectIntEQ(0, len);
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag));
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* The payload cannot be split: a chunk that does not match the declared
     * length is refused rather than accumulated. */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectIntEQ(1, EVP_EncryptInit_ex(ctx, cipher, NULL, NULL,
        NULL));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL));
    ExpectIntEQ(1, EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv));
    ExpectIntEQ(1, EVP_EncryptUpdate(ctx, NULL, &len, NULL, (int)sizeof(pt)));
    ExpectIntEQ(0, EVP_EncryptUpdate(ctx, out, &len, pt, (int)sizeof(pt) / 2));
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* Nor can a second payload call extend a message already processed. */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectIntEQ(1, EVP_EncryptInit_ex(ctx, cipher, NULL, NULL,
        NULL));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL));
    ExpectIntEQ(1, EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv));
    ExpectIntEQ(1, EVP_EncryptUpdate(ctx, out, &len, pt, (int)sizeof(pt)));
    ExpectIntEQ(0, EVP_EncryptUpdate(ctx, out, &len, pt, (int)sizeof(pt)));
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* AAD before the length is refused, because the length comes first in the
     * block the AAD is folded into. A zero length AAD needs nothing known. */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectIntEQ(1, EVP_EncryptInit_ex(ctx, cipher, NULL, NULL,
        NULL));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL));
    ExpectIntEQ(1, EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv));
    ExpectIntEQ(1, EVP_EncryptUpdate(ctx, NULL, &len, aad, 0));
    ExpectIntEQ(0, EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)sizeof(aad)));
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* AAD after the payload is refused too: the tag was produced by the
     * payload call and cannot cover anything handed over later. Reporting
     * success would say the AAD was authenticated when it was not. A zero
     * length AAD adds nothing to authenticate, so it still passes. */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectIntEQ(1, EVP_EncryptInit_ex(ctx, cipher, NULL, NULL,
        NULL));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL));
    ExpectIntEQ(1, EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv));
    ExpectIntEQ(1, EVP_EncryptUpdate(ctx, NULL, &len, NULL, (int)sizeof(pt)));
    ExpectIntEQ(1, EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)sizeof(aad)));
    ExpectIntEQ(1, EVP_EncryptUpdate(ctx, out, &len, pt, (int)sizeof(pt)));
    ExpectIntEQ(0, EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)sizeof(aad)));
    ExpectIntEQ(1, EVP_EncryptUpdate(ctx, NULL, &len, aad, 0));
    /* Keep the tag over that message, to decrypt it below. */
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag));
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* Same on the decrypt side, where accepting it would mean AAD taken as
     * authenticated without being verified. */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectIntEQ(1, EVP_DecryptInit_ex(ctx, cipher, NULL, NULL,
        NULL));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag));
    ExpectIntEQ(1, EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv));
    ExpectIntEQ(1, EVP_DecryptUpdate(ctx, NULL, &len, NULL, (int)sizeof(pt)));
    ExpectIntEQ(1, EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)sizeof(aad)));
    ExpectIntEQ(1, EVP_DecryptUpdate(ctx, out, &len, out, (int)sizeof(pt)));
    ExpectIntEQ(0, EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)sizeof(aad)));
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* Declaring the length again does not start a new message: it is refused
     * after AAD and after a payload. Allowing it after a payload would clear
     * the one-payload rule above and let a second payload go out under the
     * same key and nonce, which for CCM repeats the keystream. */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectIntEQ(1, EVP_EncryptInit_ex(ctx, cipher, NULL, NULL,
        NULL));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL));
    ExpectIntEQ(1, EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv));
    ExpectIntEQ(1, EVP_EncryptUpdate(ctx, NULL, &len, NULL, (int)sizeof(pt)));
    /* Harmless while nothing has been fed in. */
    ExpectIntEQ(1, EVP_EncryptUpdate(ctx, NULL, &len, NULL, (int)sizeof(pt)));
    ExpectIntEQ(1, EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)sizeof(aad)));
    /* After AAD, refused. */
    ExpectIntEQ(0, EVP_EncryptUpdate(ctx, NULL, &len, NULL, (int)sizeof(pt)));
    ExpectIntEQ(1, EVP_EncryptUpdate(ctx, out, &len, pt, (int)sizeof(pt)));
    /* After the payload, refused - and so the second payload stays refused. */
    ExpectIntEQ(0, EVP_EncryptUpdate(ctx, NULL, &len, NULL, (int)sizeof(pt)));
    ExpectIntEQ(0, EVP_EncryptUpdate(ctx, out, &len, pt, (int)sizeof(pt)));
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* Starting a new message clears it, so a context can be reused. */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectIntEQ(1, EVP_EncryptInit_ex(ctx, cipher, NULL, NULL,
        NULL));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL));
    ExpectIntEQ(1, EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv));
    ExpectIntEQ(1, EVP_EncryptUpdate(ctx, out, &len, pt, (int)sizeof(pt)));
    ExpectIntEQ(1, EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv));
    ExpectIntEQ(1, EVP_EncryptUpdate(ctx, NULL, &len, NULL, (int)sizeof(pt)));
    ExpectIntEQ(1, EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)sizeof(aad)));
    ExpectIntEQ(1, EVP_EncryptUpdate(ctx, out, &len, pt, (int)sizeof(pt)));
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* With no length declared, the first payload call declares it, and the
     * ciphertext still comes out of that call. */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectIntEQ(1, EVP_EncryptInit_ex(ctx, cipher, NULL, NULL,
        NULL));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL));
    ExpectIntEQ(1, EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv));
    len = 0;
    ExpectIntEQ(1, EVP_EncryptUpdate(ctx, out, &len, pt, (int)sizeof(pt)));
    ExpectIntEQ((int)sizeof(pt), len);
    len = -1;
    ExpectIntEQ(1, EVP_EncryptFinal_ex(ctx, out + sizeof(pt), &len));
    ExpectIntEQ(0, len);
    /* Same ciphertext as the declared-length run above, which used the same
     * key, nonce and tag length but no AAD. */
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag));
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* The tag is not readable from a decrypting context, nor before the
     * operation has produced one. */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectIntEQ(1, EVP_EncryptInit_ex(ctx, cipher, NULL, NULL,
        NULL));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL));
    ExpectIntEQ(1, EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv));
    ExpectIntEQ(0, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag));
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectIntEQ(1, EVP_DecryptInit_ex(ctx, cipher, NULL, NULL,
        NULL));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL));
    ExpectIntEQ(1, EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv));
    ExpectIntEQ(0, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag));
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    return EXPECT_RESULT();
}
#endif

/* The EVP interface to CCM follows a contract OpenSSL documents in
 * EVP_EncryptInit(3), and which differs from the other AEAD modes: the payload
 * length is part of the first block, so it has to be settled before anything
 * is processed, and there is no streaming. AES-CCM and SM4-CCM go through the
 * same code for all of it, so both are checked against it.
 */
int test_wolfssl_EVP_aes_ccm_openssl_semantics(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_AES) && defined(HAVE_AESCCM) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS) && defined(WOLFSSL_AES_128)
    ExpectIntEQ(TEST_SUCCESS, ccm_openssl_semantics(EVP_aes_128_ccm(), 16));
#endif
    return EXPECT_RESULT();
}

/* An EVP_CIPHER_CTX reused for a different cipher has to release the first
 * cipher's low-level state. Nothing else will: once ctx->cipherType is
 * replaced, EVP_CIPHER_CTX_cleanup() frees whatever the *new* type names, and
 * if the two use different members of the cipher union the first one's
 * allocation is orphaned - a leak the CI leak-sanitizer jobs see as the
 * 4 byte WC_DEBUG_CIPHER_LIFECYCLE tag. Skipping the release also left the
 * new cipher uninitialized, because its wc_*Init() is gated on the
 * LOW_LEVEL_INITED flag the first cipher had already set, so this also checks
 * that the second cipher produces what a fresh context does. */
int test_wolfssl_EVP_cipher_switch_reinit(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_AES) && defined(HAVE_AES_CBC) && \
    defined(WOLFSSL_AES_128) && defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    byte key[32];
    byte iv[16];
    byte pt[32];
    byte reused[48];
    byte fresh[48];
    int reusedLen = 0;
    int freshLen = 0;
    EVP_CIPHER_CTX* ctx = NULL;

    XMEMSET(key, 0x41, sizeof(key));
    XMEMSET(iv, 0x42, sizeof(iv));
    XMEMSET(pt, 0x43, sizeof(pt));

    /* Use the context for AES-128-CBC first, so it has live AES state. */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectIntEQ(1, EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv));
    ExpectIntEQ(1, EVP_EncryptUpdate(ctx, reused, &reusedLen, pt,
        (int)sizeof(pt)));
    /* Then switch it to a cipher held in another member of the union. */
    reusedLen = 0;
    ExpectIntEQ(1, EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key,
        iv));
    ExpectIntEQ(1, EVP_EncryptUpdate(ctx, reused, &reusedLen, pt,
        (int)sizeof(pt)));
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* The same cipher on a context that has only ever held it. */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectIntEQ(1, EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key,
        iv));
    ExpectIntEQ(1, EVP_EncryptUpdate(ctx, fresh, &freshLen, pt,
        (int)sizeof(pt)));
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    ExpectIntEQ(reusedLen, freshLen);
    ExpectIntEQ(0, XMEMCMP(reused, fresh, (size_t)freshLen));
#endif
    return EXPECT_RESULT();
}

/* EVP_CIPHER_CTX_cleanup() frees the ChaCha20-Poly1305 key buffer, which is
 * always 32 bytes. It used to zero ctx->keyLen bytes of it, and keyLen can be
 * anything by then: another cipher set on the same context brings its own key
 * length, and EVP_CIPHER_CTX_set_key_length() stores what it is given without
 * checking. Both wrote past the end of the buffer. Run under ASAN this catches
 * a regression; without it the overwrite is silent. */
int test_wolfssl_EVP_chacha20_poly1305_key_free(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    byte key[64];
    byte iv[16];
    EVP_CIPHER_CTX* ctx = NULL;

    XMEMSET(key, 0x41, 32);
    /* AES-XTS refuses a key whose two halves match. */
    XMEMSET(key + 32, 0x5a, 32);
    XMEMSET(iv, 0x42, sizeof(iv));

    /* A key length the caller invented, larger than the buffer. */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectIntEQ(1, EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key,
        iv));
    ExpectIntEQ(1, EVP_CIPHER_CTX_set_key_length(ctx, 4096));
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

#if defined(WOLFSSL_AES_XTS) && defined(WOLFSSL_AES_256) && \
    (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5,3))
    /* The same through a cipher switch, which needs no invented length:
     * AES-256-XTS's key length is 64. */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectIntEQ(1, EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key,
        iv));
    ExpectIntEQ(1, EVP_EncryptInit_ex(ctx, EVP_aes_256_xts(), NULL, key, iv));
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfssl_EVP_sm4_ccm_openssl_semantics(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_SM4_CCM) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
    ExpectIntEQ(TEST_SUCCESS, ccm_openssl_semantics(EVP_sm4_ccm(), 16));
#endif
    return EXPECT_RESULT();
}

/* CCM verifies while it decrypts, so a wrong tag is reported by the update
 * that decrypts rather than by final, and no plaintext is handed back. */
int test_wolfssl_EVP_aes_ccm_decrypt_verify(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_AES) && defined(HAVE_AESCCM) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS) && defined(WOLFSSL_AES_128)
    byte key[16];
    byte iv[12];
    byte pt[32];
    byte aad[16];
    byte ct[64];
    byte dec[64];
    byte tag[16];
    int i;
    int len = 0;
    EVP_CIPHER_CTX* ctx = NULL;

    for (i = 0; i < (int)sizeof(key); i++) key[i] = (byte)i;
    for (i = 0; i < (int)sizeof(iv);  i++) iv[i]  = (byte)(0xA0 + i);
    for (i = 0; i < (int)sizeof(pt);  i++) pt[i]  = (byte)(i * 3 + 1);
    for (i = 0; i < (int)sizeof(aad); i++) aad[i] = (byte)(i * 5 + 2);
    XMEMSET(ct, 0, sizeof(ct));

    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectIntEQ(1, EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL,
        NULL));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL));
    ExpectIntEQ(1, EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv));
    ExpectIntEQ(1, EVP_EncryptUpdate(ctx, NULL, &len, NULL, (int)sizeof(pt)));
    ExpectIntEQ(1, EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)sizeof(aad)));
    ExpectIntEQ(1, EVP_EncryptUpdate(ctx, ct, &len, pt, (int)sizeof(pt)));
    ExpectIntEQ(1, EVP_EncryptFinal_ex(ctx, ct + len, &len));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag));
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* The right tag: the update decrypts and hands back the plaintext. */
    XMEMSET(dec, 0, sizeof(dec));
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectIntEQ(1, EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL,
        NULL));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag));
    ExpectIntEQ(1, EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv));
    ExpectIntEQ(1, EVP_DecryptUpdate(ctx, NULL, &len, NULL, (int)sizeof(pt)));
    ExpectIntEQ(1, EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)sizeof(aad)));
    len = 0;
    ExpectIntEQ(1, EVP_DecryptUpdate(ctx, dec, &len, ct, (int)sizeof(pt)));
    ExpectIntEQ((int)sizeof(pt), len);
    ExpectIntEQ(0, XMEMCMP(pt, dec, sizeof(pt)));
    len = -1;
    ExpectIntEQ(1, EVP_DecryptFinal_ex(ctx, dec + sizeof(pt), &len));
    ExpectIntEQ(0, len);
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* A wrong tag: the update fails, returns nothing, and final still
     * succeeds because there is nothing left for it to check. */
    tag[0] ^= 0xFF;
    XMEMSET(dec, 0, sizeof(dec));
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectIntEQ(1, EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL,
        NULL));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag));
    ExpectIntEQ(1, EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv));
    ExpectIntEQ(1, EVP_DecryptUpdate(ctx, NULL, &len, NULL, (int)sizeof(pt)));
    ExpectIntEQ(1, EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)sizeof(aad)));
    len = -1;
    ExpectIntEQ(0, EVP_DecryptUpdate(ctx, dec, &len, ct, (int)sizeof(pt)));
    ExpectIntEQ(0, len);
    len = -1;
    ExpectIntEQ(1, EVP_DecryptFinal_ex(ctx, dec, &len));
    ExpectIntEQ(0, len);
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;
#endif
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
    /* The tag is read back at 16 bytes below, and the CCM default is 12. */
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(en, EVP_CTRL_CCM_SET_TAG, 16, NULL));
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

    /* The tag has to actually be checked. No payload call is made above - a
     * zero length payload handed over with a NULL output buffer is an AAD
     * call - so the check falls to EVP_DecryptFinal_ex(), and a wrong tag has
     * to be refused there. Without that this whole sequence passes on any
     * tag at all. */
    tag[15] ^= 0xBB;
    ExpectIntEQ(1, EVP_CIPHER_CTX_cleanup(de));
    EVP_CIPHER_CTX_init(de);
    ExpectIntEQ(1, EVP_DecryptInit_ex(de, EVP_aes_256_ccm(), NULL, key, iv));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(de, EVP_CTRL_CCM_SET_IVLEN, ivSz, NULL));
    ExpectIntEQ(1, EVP_DecryptUpdate(de, NULL, &len, ciphertxt, 0));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(de, EVP_CTRL_CCM_SET_TAG, 16, tag));
    ExpectIntEQ(0, EVP_DecryptFinal_ex(de, decryptedtxt, &len));

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
                /* GCM's default IV length is 96 bits; this branch takes
                 * that default rather than setting one. */
                AssertIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aria_128_gcm(),
                    NULL, key, iv));
                break;
            case 1:
                /* GCM's default IV length is 96 bits; this branch takes
                 * that default rather than setting one. */
                AssertIntEQ(1, EVP_EncryptInit_ex(&en[i], EVP_aria_192_gcm(),
                    NULL, key, iv));
                break;
            case 2:
                /* GCM's default IV length is 96 bits; this branch takes
                 * that default rather than setting one. */
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
                /* GCM's default IV length is 96 bits; this branch takes
                 * that default rather than setting one. */
                AssertIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aria_128_gcm(),
                    NULL, key, iv));
                break;
            case 1:
                /* GCM's default IV length is 96 bits; this branch takes
                 * that default rather than setting one. */
                AssertIntEQ(1, EVP_DecryptInit_ex(&de[i], EVP_aria_192_gcm(),
                    NULL, key, iv));
                break;
            case 2:
                /* GCM's default IV length is 96 bits; this branch takes
                 * that default rather than setting one. */
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
    EVP_CIPHER_CTX* ctx = NULL;
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
    EVP_CIPHER_CTX* ctx = NULL;
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
    EVP_CIPHER_CTX* ctx = NULL;
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
            /* GCM's default IV length is 96 bits; this branch takes
             * that default rather than setting one. */
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
            /* GCM's default IV length is 96 bits; this branch takes
             * that default rather than setting one. */
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
    /* The tag is read back at 16 bytes below, and the CCM default is 12. */
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(en, EVP_CTRL_CCM_SET_TAG, 16, NULL));
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

    /* The tag has to actually be checked. No payload call is made above - a
     * zero length payload handed over with a NULL output buffer is an AAD
     * call - so the check falls to EVP_DecryptFinal_ex(), and a wrong tag has
     * to be refused there. Without that this whole sequence passes on any
     * tag at all. */
    tag[15] ^= 0xBB;
    ExpectIntEQ(1, EVP_CIPHER_CTX_cleanup(de));
    EVP_CIPHER_CTX_init(de);
    ExpectIntEQ(1, EVP_DecryptInit_ex(de, EVP_sm4_ccm(), NULL, key, iv));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(de, EVP_CTRL_CCM_SET_IVLEN, ivSz, NULL));
    ExpectIntEQ(1, EVP_DecryptUpdate(de, NULL, &len, ciphertxt, 0));
    ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(de, EVP_CTRL_CCM_SET_TAG, 16, tag));
    ExpectIntEQ(0, EVP_DecryptFinal_ex(de, decryptedtxt, &len));

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
            /* CCM's default nonce is 7 bytes, as in OpenSSL; this branch
             * takes it rather than setting one. */
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
        /* The CCM tag length defaults to 12 bytes, as in OpenSSL, and the tag
         * is read back below at SM4_BLOCK_SIZE. A NULL tag sets the length
         * alone, which is the only form allowed while encrypting. */
        ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&en[i], EVP_CTRL_CCM_SET_TAG,
            SM4_BLOCK_SIZE, NULL));
        /* CCM carries the payload length in its first block, so it has to be
         * declared - in and out both NULL - before any AAD. */
        ExpectIntEQ(1, EVP_EncryptUpdate(&en[i], NULL, &len, NULL, plaintxtSz));
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
            /* CCM's default nonce is 7 bytes, as in OpenSSL; this branch
             * takes it rather than setting one. */
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
        /* CCM verifies as it decrypts, inside EVP_DecryptUpdate(), so the tag
         * has to be set before the ciphertext is passed in - as OpenSSL
         * documents for this mode. */
        ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_CCM_SET_TAG,
            SM4_BLOCK_SIZE, tag));
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], NULL, &len, NULL,
            ciphertxtSz));
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], NULL, &len, aad, aadSz));
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], decryptedtxt, &len, ciphertxt,
            ciphertxtSz));
        decryptedtxtSz = len;
        ExpectIntEQ(1, EVP_DecryptFinal_ex(&de[i], decryptedtxt, &len));
        decryptedtxtSz += len;
        ExpectIntEQ(ciphertxtSz, decryptedtxtSz);
        ExpectIntEQ(0, XMEMCMP(plaintxt, decryptedtxt, decryptedtxtSz));

        /* modify tag*/
        tag[SM4_BLOCK_SIZE-1]+=0xBB;
        /* As in the AES-CCM test: a second message on the same context begins
         * with EVP_DecryptInit_ex(), which is what clears the length and the
         * AAD the message above accumulated. Declaring the length again does
         * not, and is refused. */
        ExpectIntEQ(1, EVP_DecryptInit_ex(&de[i], NULL, NULL, key, iv));
        ExpectIntEQ(1, EVP_CIPHER_CTX_ctrl(&de[i], EVP_CTRL_CCM_SET_TAG,
            SM4_BLOCK_SIZE, tag));
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], NULL, &len, NULL,
            ciphertxtSz));
        ExpectIntEQ(1, EVP_DecryptUpdate(&de[i], NULL, &len, aad, aadSz));
        /* Fail due to wrong tag. The update that decrypts reports it, and
         * returns no plaintext; final has nothing left to check. */
        ExpectIntEQ(0, EVP_DecryptUpdate(&de[i], decryptedtxt, &len, ciphertxt,
            ciphertxtSz));
        ExpectIntEQ(0, len);
        ExpectIntEQ(1, EVP_DecryptFinal_ex(&de[i], decryptedtxt, &len));
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

/*
 * The 3DES ECB entry points reject a context that has no key, and that is
 * visible here: wolfSSL_EVP_CipherInit only calls wc_Des3_SetKey when a key is
 * supplied, so initializing EVP_des_ede3_ecb() with a NULL key and then
 * feeding it data used to run against the zeroed key schedule and report
 * success. It must fail instead. The ordinary two-stage OpenSSL idiom --
 * install the cipher, then install the key -- does key the context and must
 * keep working.
 *
 * FIPS builds use the FIPS-certified DES3 implementation, which does not track
 * key state, so skip the test for FIPS.
 */
int test_wolfSSL_EVP_des_ede3_ecb_no_key(void)
{
    EXPECT_DECLS;
#if !defined(NO_DES3) && !defined(HAVE_FIPS) && defined(OPENSSL_EXTRA) && \
    defined(WOLFSSL_DES_ECB)
    EVP_CIPHER_CTX* ctx = NULL;
    byte out[32];
    int outl = 0;
    const byte key[24] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xde,0xba,0x98,0x76,0x54,0x32,0x10,
        0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67
    };
    const byte in[16] = {
        0x4e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20
    };

    XMEMSET(out, 0, sizeof(out));

    /* No key ever supplied: the update must not produce ciphertext. */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectIntEQ(EVP_CipherInit(ctx, EVP_des_ede3_ecb(), NULL, NULL, 1), 1);
    ExpectIntNE(EVP_CipherUpdate(ctx, out, &outl, in, (int)sizeof(in)), 1);
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* Cipher first, key second: unaffected. */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectIntEQ(EVP_CipherInit(ctx, EVP_des_ede3_ecb(), NULL, NULL, 1), 1);
    ExpectIntEQ(EVP_CipherInit(ctx, NULL, key, NULL, 1), 1);
    ExpectIntEQ(EVP_CipherUpdate(ctx, out, &outl, in, (int)sizeof(in)), 1);
    EVP_CIPHER_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/*
 * The DES-CBC branch of wolfSSL_EVP_Cipher used to discard the return value of
 * wc_Des_CbcEncrypt / wc_Des_CbcDecrypt. Because ret starts at WOLFSSL_FAILURE
 * (numerically zero), the "if (ret == 0)" success path then ran unconditionally
 * and a rounded byte count was reported even when the DES call had rejected the
 * request. A length that is not a multiple of DES_BLOCK_SIZE makes the software
 * DES path return BAD_LENGTH_E, so the one-shot EVP_Cipher call must now fail
 * rather than return a positive length. A block-multiple length still succeeds.
 *
 * FIPS builds use the FIPS-certified DES3 implementation for 3DES, but single
 * DES is not a FIPS algorithm, so skip the test for FIPS.
 */
int test_wolfSSL_EVP_Cipher_des_cbc_error(void)
{
    EXPECT_DECLS;
#if !defined(NO_DES3) && !defined(HAVE_FIPS) && defined(OPENSSL_EXTRA)
    EVP_CIPHER_CTX* ctx = NULL;
    const byte key[8] = { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef };
    const byte iv[8]  = { 0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef };
    const byte in[16] = {
        0x4e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20
    };
    byte out[16];

    XMEMSET(out, 0, sizeof(out));

    /* Not a multiple of DES_BLOCK_SIZE: the DES call fails and EVP_Cipher must
     * report the failure, not a rounded byte count. Both the encrypt and the
     * decrypt arm of the switch must propagate the error. */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectIntEQ(EVP_CipherInit(ctx, EVP_des_cbc(), key, iv, 1), 1);
    ExpectIntLT(EVP_Cipher(ctx, out, in, 15), 0);
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectIntEQ(EVP_CipherInit(ctx, EVP_des_cbc(), key, iv, 0), 1);
    ExpectIntLT(EVP_Cipher(ctx, out, in, 15), 0);
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* A block-multiple length still succeeds and reports the full length. */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectIntEQ(EVP_CipherInit(ctx, EVP_des_cbc(), key, iv, 1), 1);
    ExpectIntEQ(EVP_Cipher(ctx, out, in, (word32)sizeof(in)), (int)sizeof(in));
    EVP_CIPHER_CTX_free(ctx);
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


#if defined(OPENSSL_EXTRA) && !defined(NO_AES) && defined(HAVE_AES_CBC) && \
    defined(WOLFSSL_AES_128)

#define EVP_CHUNK_CANARY_SZ 32

/* Decrypt with EVP_DecryptUpdate in the given chunk sizes, giving every call
 * its own buffer of exactly inl + block size followed by a canary. */
static int evp_chunked_decrypt(const byte* key, const byte* iv,
    const byte* cipher, const int* chunks, int nchunks, int padding,
    byte* plain, int* plainSz)
{
    EVP_CIPHER_CTX* ctx = NULL;
    byte* out = NULL;
    byte final[AES_BLOCK_SIZE];
    int ret = 0;
    int offset = 0;
    int total = 0;
    int bound = 0;
    int outl = 0;
    int i = 0;
    int j = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) !=
            WOLFSSL_SUCCESS) {
        ret = -1;
    }
    if ((ret == 0) && (padding == 0) &&
            (EVP_CIPHER_CTX_set_padding(ctx, 0) != WOLFSSL_SUCCESS)) {
        ret = -1;
    }

    for (i = 0; (ret == 0) && (i < nchunks); i++) {
        bound = chunks[i] + AES_BLOCK_SIZE;
        out = (byte*)XMALLOC((size_t)(bound + EVP_CHUNK_CANARY_SZ), NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
        if (out == NULL) {
            ret = -1;
            break;
        }
        XMEMSET(out, 0xA5, (size_t)(bound + EVP_CHUNK_CANARY_SZ));

        outl = 0;
        if (EVP_DecryptUpdate(ctx, out, &outl, cipher + offset, chunks[i]) !=
                WOLFSSL_SUCCESS) {
            ret = -1;
        }
        else if ((outl < 0) || (outl > bound)) {
            ret = -2;
        }
        else {
            for (j = bound; j < bound + EVP_CHUNK_CANARY_SZ; j++) {
                if (out[j] != 0xA5)
                    ret = -3;
            }
        }
        if (ret == 0) {
            XMEMCPY(plain + total, out, (size_t)outl);
            total += outl;
            offset += chunks[i];
        }
        XFREE(out, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        out = NULL;
    }

    if (ret == 0) {
        outl = 0;
        if (EVP_DecryptFinal_ex(ctx, final, &outl) != WOLFSSL_SUCCESS) {
            ret = -1;
        }
        else {
            XMEMCPY(plain + total, final, (size_t)outl);
            total += outl;
        }
    }

    *plainSz = total;
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* Encrypt 48 bytes of known plaintext into a 64 byte PKCS#7 padded
 * ciphertext. */
static int evp_chunked_setup(const byte* key, const byte* iv, byte* plain,
    int plainSz, byte* cipher, int* cipherSz)
{
    EVP_CIPHER_CTX* ctx = NULL;
    int ret = 0;
    int outl = 0;
    int total = 0;
    int i = 0;

    for (i = 0; i < plainSz; i++)
        plain[i] = (byte)i;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) !=
            WOLFSSL_SUCCESS) {
        ret = -1;
    }
    if ((ret == 0) && (EVP_EncryptUpdate(ctx, cipher, &outl, plain, plainSz) !=
            WOLFSSL_SUCCESS)) {
        ret = -1;
    }
    if (ret == 0) {
        total = outl;
        if (EVP_EncryptFinal_ex(ctx, cipher + total, &outl) !=
                WOLFSSL_SUCCESS) {
            ret = -1;
        }
        else {
            total += outl;
        }
    }

    *cipherSz = total;
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

#endif /* OPENSSL_EXTRA && !NO_AES && HAVE_AES_CBC && WOLFSSL_AES_128 */

int test_evp_cipher_update_chunked_bound(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_AES) && defined(HAVE_AES_CBC) && \
    defined(WOLFSSL_AES_128)
    byte key[AES_BLOCK_SIZE];
    byte iv[AES_BLOCK_SIZE];
    byte plain[AES_BLOCK_SIZE * 3];
    byte cipher[AES_BLOCK_SIZE * 4];
    byte out[AES_BLOCK_SIZE * 4];
    int chunks[3];
    int cipherSz = 0;
    int outSz = 0;
    int i;
    int j;

    XMEMSET(key, 0x0b, sizeof(key));
    XMEMSET(iv, 0x0c, sizeof(iv));

    ExpectIntEQ(evp_chunked_setup(key, iv, plain, (int)sizeof(plain), cipher,
        &cipherSz), 0);
    ExpectIntEQ(cipherSz, (int)sizeof(cipher));

    /* EVP_DecryptUpdate must never write more than inl + block size,
     * whatever the input is split into */
    for (i = 1; EXPECT_SUCCESS() && (i < cipherSz); i++) {
        for (j = i + 1; EXPECT_SUCCESS() && (j < cipherSz); j++) {
            chunks[0] = i;
            chunks[1] = j - i;
            chunks[2] = cipherSz - j;
            ExpectIntEQ(evp_chunked_decrypt(key, iv, cipher, chunks, 3, 1, out,
                &outSz), 0);
            ExpectIntEQ(outSz, (int)sizeof(plain));
            ExpectBufEQ(out, plain, sizeof(plain));
        }
    }
#endif
    return EXPECT_RESULT();
}

int test_evp_cipher_update_no_padding_buffered(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_AES) && defined(HAVE_AES_CBC) && \
    defined(WOLFSSL_AES_128)
    byte key[AES_BLOCK_SIZE];
    byte iv[AES_BLOCK_SIZE];
    byte plain[AES_BLOCK_SIZE * 3];
    byte cipher[AES_BLOCK_SIZE * 4];
    byte out[AES_BLOCK_SIZE * 4];
    EVP_CIPHER_CTX* ctx = NULL;
    int chunks[2];
    int cipherSz = 0;
    int outSz = 0;

    XMEMSET(key, 0x0b, sizeof(key));
    XMEMSET(iv, 0x0c, sizeof(iv));

    ExpectIntEQ(evp_chunked_setup(key, iv, plain, (int)sizeof(plain), cipher,
        &cipherSz), 0);

    /* with padding disabled EVP_CipherFinal only checks that nothing is
     * buffered, so a block completed from the buffer has to be returned here */
    chunks[0] = 6;
    chunks[1] = AES_BLOCK_SIZE - 6;
    ExpectIntEQ(evp_chunked_decrypt(key, iv, cipher, chunks, 2, 0, out,
        &outSz), 0);
    ExpectIntEQ(outSz, AES_BLOCK_SIZE);
    ExpectBufEQ(out, plain, AES_BLOCK_SIZE);

    /* padding turned off after Update stored the block must not drop it */
    ExpectNotNull(ctx = EVP_CIPHER_CTX_new());
    ExpectIntEQ(EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv),
        WOLFSSL_SUCCESS);
    outSz = -1;
    ExpectIntEQ(EVP_DecryptUpdate(ctx, out, &outSz, cipher, AES_BLOCK_SIZE),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, 0);
    ExpectIntEQ(EVP_CIPHER_CTX_set_padding(ctx, 0), WOLFSSL_SUCCESS);
    outSz = -1;
    ExpectIntEQ(EVP_DecryptFinal_ex(ctx, out, &outSz), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, AES_BLOCK_SIZE);
    ExpectBufEQ(out, plain, AES_BLOCK_SIZE);
    EVP_CIPHER_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/*
 * EVP_get_cipherbyname() looks a name up in the table of cipher names and, for
 * the spellings that have no entry of their own, in a table of alternatives.
 * Over half of those alternatives are only a differently cased version of a
 * name that is already in the first table, so the two are consulted in that
 * order and the comparison ignores case.
 *
 * That makes the casing of the name, and which of the two tables answers,
 * the things worth pinning down. A NULL name is included because it used to
 * dereference it.
 */
int test_wolfSSL_EVP_get_cipherbyname_names(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_AES)
    /* Names that the cipher table holds itself. */
    static const char* const canonical[] = {
#if defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_128)
        "AES-128-CBC",
#endif
#if defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_256)
        "AES-256-CBC",
#endif
#if defined(HAVE_AESGCM) && defined(WOLFSSL_AES_256)
        "AES-256-GCM",
#endif
        NULL
    };
    /* Spellings that only the alternatives table knows. */
    static const char* const alternates[] = {
#if defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_128)
        "aes128-cbc", "aes128",
#endif
#if defined(HAVE_AESGCM) && defined(WOLFSSL_AES_256)
        "id-aes256-GCM",
#endif
        NULL
    };
    const char* const* lists[3];
    int li;
    char buf[64];

    lists[0] = canonical;
    lists[1] = alternates;
    lists[2] = NULL;

    /* Both the names the table holds and the alternative spellings have to
     * resolve, and to resolve the same way whatever their casing. The casings
     * matter on both lists: the table's own names are upper case while the
     * alternatives are mostly lower case, so only trying one of them would
     * leave half of the case folding unexercised. */
    for (li = 0; lists[li] != NULL; li++) {
        const char* const* list = lists[li];
        int i;

        for (i = 0; list[i] != NULL; i++) {
            const WOLFSSL_EVP_CIPHER* c = NULL;
            int mode;
            size_t n = XSTRLEN(list[i]);

            if (n >= sizeof(buf)) {
                continue;
            }
            ExpectNotNull(c = wolfSSL_EVP_get_cipherbyname(list[i]));
            /* Whatever answered has to be a usable cipher, not merely
             * non-NULL: an alternative spelling naming a cipher the build
             * left out must not resolve. */
            ExpectIntNE(wolfSSL_EVP_CIPHER_nid(c), 0);
            ExpectIntGT(wolfSSL_EVP_Cipher_key_length(c), 0);

            /* mode 0 lower cases, mode 1 upper cases, mode 2 alternates. */
            for (mode = 0; mode < 3; mode++) {
                const WOLFSSL_EVP_CIPHER* got = NULL;
                int j;

                for (j = 0; j < (int)n; j++) {
                    char ch = list[i][j];
                    int up = (mode == 1) || ((mode == 2) && ((j & 1) == 0));

                    if (up) {
                        if ((ch >= 'a') && (ch <= 'z')) {
                            ch = (char)(ch - 'a' + 'A');
                        }
                    }
                    else if ((ch >= 'A') && (ch <= 'Z')) {
                        ch = (char)(ch - 'A' + 'a');
                    }
                    buf[j] = ch;
                }
                buf[n] = '\0';

                ExpectNotNull(got = wolfSSL_EVP_get_cipherbyname(buf));
                ExpectPtrEq(got, c);
            }
        }
    }

    /* Names that are not ciphers, and a NULL name, give NULL rather than
     * anything worse. */
    ExpectNull(wolfSSL_EVP_get_cipherbyname(NULL));
    ExpectNull(wolfSSL_EVP_get_cipherbyname(""));
    ExpectNull(wolfSSL_EVP_get_cipherbyname("NO-SUCH-CIPHER"));
    ExpectNull(wolfSSL_EVP_get_cipherbyname("AES-256"));
    ExpectNull(wolfSSL_EVP_get_cipherbyname("AES-256-GCMM"));

    /* The digest equivalent had the same NULL problem. */
    ExpectNull(wolfSSL_EVP_get_digestbyname(NULL));
#endif
    return EXPECT_RESULT();
}
