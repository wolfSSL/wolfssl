/* test_sm4.c
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

#include <wolfssl/wolfcrypt/sm4.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_sm4.h>

/*
 * Testing streaming SM4 API.
 */
int test_wc_Sm4(void)
{
    int res = TEST_SKIPPED;
#ifdef WOLFSSL_SM4
    EXPECT_DECLS;
    wc_Sm4 sm4;
#if defined(WOLFSSL_SM4_ECB) || defined(WOLFSSL_SM4_CBC) || \
    defined(WOLFSSL_SM4_CTR) || defined(WOLFSSL_SM4_CCM)
    unsigned char key[SM4_KEY_SIZE];
#endif
#if defined(WOLFSSL_SM4_CBC) || defined(WOLFSSL_SM4_CTR)
    unsigned char iv[SM4_IV_SIZE];
#endif

    /* Invalid parameters - wc_Sm4Init */
    ExpectIntEQ(wc_Sm4Init(NULL, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Valid cases - wc_Sm4Init */
    ExpectIntEQ(wc_Sm4Init(&sm4, NULL, INVALID_DEVID), 0);

#if defined(WOLFSSL_SM4_ECB) || defined(WOLFSSL_SM4_CBC) || \
    defined(WOLFSSL_SM4_CTR) || defined(WOLFSSL_SM4_CCM)
    XMEMSET(key, 0, sizeof(key));

    /* Invalid parameters - wc_Sm4SetKey. */
    ExpectIntEQ(wc_Sm4SetKey(NULL, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4SetKey(&sm4, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4SetKey(NULL, key, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4SetKey(NULL, NULL, SM4_KEY_SIZE),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4SetKey(&sm4, key, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4SetKey(&sm4, NULL, SM4_KEY_SIZE),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4SetKey(NULL, key, SM4_KEY_SIZE),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4SetKey(&sm4, key, SM4_KEY_SIZE-1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4SetKey(&sm4, key, SM4_KEY_SIZE+1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Valid cases - wc_Sm4SetKey. */
    ExpectIntEQ(wc_Sm4SetKey(&sm4, key, SM4_KEY_SIZE), 0);
#endif

#if defined(WOLFSSL_SM4_CBC) || defined(WOLFSSL_SM4_CTR)
    XMEMSET(iv, 0, sizeof(iv));

    /* Invalid parameters - wc_Sm4SetIV. */
    ExpectIntEQ(wc_Sm4SetIV(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4SetIV(&sm4, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4SetIV(NULL, iv), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Valid cases - wc_Sm4SetIV. */
    ExpectIntEQ(wc_Sm4SetIV(&sm4, iv), 0);
#endif

    /* Valid cases - wc_Sm4Free */
    wc_Sm4Free(NULL);
    wc_Sm4Free(&sm4);

    res = EXPECT_RESULT();
#endif
    return res;
} /* END test_wc_Sm4 */

/*
 * Testing block based SM4-ECB API.
 */
int test_wc_Sm4Ecb(void)
{
    int res = TEST_SKIPPED;
#ifdef WOLFSSL_SM4_ECB
    EXPECT_DECLS;
    wc_Sm4 sm4;
    unsigned char key[SM4_KEY_SIZE];
    unsigned char in[SM4_BLOCK_SIZE * 2];
    unsigned char out[SM4_BLOCK_SIZE * 2];
    unsigned char out2[SM4_BLOCK_SIZE];

    XMEMSET(key, 0, sizeof(key));
    XMEMSET(in, 0, sizeof(in));

    ExpectIntEQ(wc_Sm4Init(&sm4, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_Sm4EcbEncrypt(&sm4, out, in, 0),
        WC_NO_ERR_TRACE(MISSING_KEY));
    ExpectIntEQ(wc_Sm4EcbDecrypt(&sm4, out, in, 0),
        WC_NO_ERR_TRACE(MISSING_KEY));

    /* Tested in test_wc_Sm4. */
    ExpectIntEQ(wc_Sm4SetKey(&sm4, key, SM4_KEY_SIZE), 0);

    /* Invalid parameters - wc_Sm4EcbEncrypt. */
    ExpectIntEQ(wc_Sm4EcbEncrypt(NULL, NULL, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4EcbEncrypt(&sm4, NULL, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4EcbEncrypt(NULL, out, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4EcbEncrypt(NULL, NULL, in, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4EcbEncrypt(NULL, NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4EcbEncrypt(NULL, out, in, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4EcbEncrypt(&sm4, NULL, in, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4EcbEncrypt(&sm4, out, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4EcbEncrypt(&sm4, out, in, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Valid cases - wc_Sm4EcbEncrypt. */
    ExpectIntEQ(wc_Sm4EcbEncrypt(&sm4, out, in, 0), 0);
    ExpectIntEQ(wc_Sm4EcbEncrypt(&sm4, out2, in, SM4_BLOCK_SIZE), 0);
    ExpectIntEQ(wc_Sm4EcbEncrypt(&sm4, out, in, SM4_BLOCK_SIZE * 2), 0);
    ExpectIntEQ(XMEMCMP(out, out2, SM4_BLOCK_SIZE), 0);
    /*   In and out are same pointer. */
    ExpectIntEQ(wc_Sm4EcbEncrypt(&sm4, in, in, SM4_BLOCK_SIZE * 2), 0);
    ExpectIntEQ(XMEMCMP(in, out, SM4_BLOCK_SIZE * 2), 0);

    /* Invalid parameters - wc_Sm4EcbDecrypt. */
    ExpectIntEQ(wc_Sm4EcbDecrypt(NULL, NULL, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4EcbDecrypt(&sm4, NULL, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4EcbDecrypt(NULL, out, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4EcbDecrypt(NULL, NULL, in, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4EcbDecrypt(NULL, NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4EcbDecrypt(NULL, out, in, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4EcbDecrypt(&sm4, NULL, in, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4EcbDecrypt(&sm4, out, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4EcbDecrypt(&sm4, out, in, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Valid cases - wc_Sm4EcbDecrypt. */
    ExpectIntEQ(wc_Sm4EcbDecrypt(&sm4, out, in, 0), 0);
    ExpectIntEQ(wc_Sm4EcbDecrypt(&sm4, out2, in, SM4_BLOCK_SIZE), 0);
    ExpectIntEQ(wc_Sm4EcbDecrypt(&sm4, out, in, SM4_BLOCK_SIZE * 2), 0);
    ExpectIntEQ(XMEMCMP(out, out2, SM4_BLOCK_SIZE), 0);
    /*   In and out are same pointer. */
    ExpectIntEQ(wc_Sm4EcbDecrypt(&sm4, in, in, SM4_BLOCK_SIZE * 2), 0);
    ExpectIntEQ(XMEMCMP(in, out, SM4_BLOCK_SIZE * 2), 0);

    wc_Sm4Free(&sm4);

    res = EXPECT_RESULT();
#endif
    return res;
} /* END test_wc_Sm4Ecb */

/*
 * Testing block based SM4-CBC API.
 */
int test_wc_Sm4Cbc(void)
{
    int res = TEST_SKIPPED;
#ifdef WOLFSSL_SM4_CBC
    EXPECT_DECLS;
    wc_Sm4 sm4;
    unsigned char key[SM4_KEY_SIZE];
    unsigned char iv[SM4_IV_SIZE];
    unsigned char in[SM4_BLOCK_SIZE * 2];
    unsigned char out[SM4_BLOCK_SIZE * 2];
    unsigned char out2[SM4_BLOCK_SIZE];

    XMEMSET(key, 0, sizeof(key));
    XMEMSET(iv, 0, sizeof(iv));
    XMEMSET(in, 0, sizeof(in));

    ExpectIntEQ(wc_Sm4Init(&sm4, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_Sm4CbcEncrypt(&sm4, out, in, 0),
        WC_NO_ERR_TRACE(MISSING_KEY));
    ExpectIntEQ(wc_Sm4CbcDecrypt(&sm4, out, in, 0),
        WC_NO_ERR_TRACE(MISSING_KEY));
    /* Tested in test_wc_Sm4. */
    ExpectIntEQ(wc_Sm4SetKey(&sm4, key, SM4_KEY_SIZE), 0);
    ExpectIntEQ(wc_Sm4CbcEncrypt(&sm4, out, in, 0),
        WC_NO_ERR_TRACE(MISSING_IV));
    ExpectIntEQ(wc_Sm4CbcDecrypt(&sm4, out, in, 0),
        WC_NO_ERR_TRACE(MISSING_IV));
    /* Tested in test_wc_Sm4. */
    ExpectIntEQ(wc_Sm4SetIV(&sm4, iv), 0);

    /* Invalid parameters - wc_Sm4CbcEncrypt. */
    ExpectIntEQ(wc_Sm4CbcEncrypt(NULL, NULL, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CbcEncrypt(&sm4, NULL, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CbcEncrypt(NULL, out, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CbcEncrypt(NULL, NULL, in, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CbcEncrypt(NULL, NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CbcEncrypt(NULL, out, in, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CbcEncrypt(&sm4, NULL, in, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CbcEncrypt(&sm4, out, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CbcEncrypt(&sm4, out, in, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Valid cases - wc_Sm4CbcEncrypt. */
    ExpectIntEQ(wc_Sm4CbcEncrypt(&sm4, out, in, 0), 0);
    ExpectIntEQ(wc_Sm4CbcEncrypt(&sm4, out2, in, SM4_BLOCK_SIZE), 0);
    ExpectIntEQ(wc_Sm4SetIV(&sm4, iv), 0);
    ExpectIntEQ(wc_Sm4CbcEncrypt(&sm4, out, in, SM4_BLOCK_SIZE * 2), 0);
    ExpectIntEQ(XMEMCMP(out, out2, SM4_BLOCK_SIZE), 0);
    /*   In and out are same pointer. */
    ExpectIntEQ(wc_Sm4SetIV(&sm4, iv), 0);
    ExpectIntEQ(wc_Sm4CbcEncrypt(&sm4, in, in, SM4_BLOCK_SIZE * 2), 0);
    ExpectIntEQ(XMEMCMP(in, out, SM4_BLOCK_SIZE * 2), 0);

    /* Invalid parameters - wc_Sm4CbcDecrypt. */
    ExpectIntEQ(wc_Sm4CbcDecrypt(NULL, NULL, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CbcDecrypt(&sm4, NULL, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CbcDecrypt(NULL, out, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CbcDecrypt(NULL, NULL, in, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CbcDecrypt(NULL, NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CbcDecrypt(NULL, out, in, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CbcDecrypt(&sm4, NULL, in, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CbcDecrypt(&sm4, out, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CbcDecrypt(&sm4, out, in, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_Sm4SetIV(&sm4, iv), 0);
    /* Valid cases - wc_Sm4CbcDecrypt. */
    ExpectIntEQ(wc_Sm4CbcDecrypt(&sm4, out, in, 0), 0);
    ExpectIntEQ(wc_Sm4CbcDecrypt(&sm4, out2, in, SM4_BLOCK_SIZE), 0);
    ExpectIntEQ(wc_Sm4SetIV(&sm4, iv), 0);
    ExpectIntEQ(wc_Sm4CbcDecrypt(&sm4, out, in, SM4_BLOCK_SIZE * 2), 0);
    ExpectIntEQ(XMEMCMP(out, out2, SM4_BLOCK_SIZE), 0);
    /*   In and out are same pointer. */
    ExpectIntEQ(wc_Sm4SetIV(&sm4, iv), 0);
    ExpectIntEQ(wc_Sm4CbcDecrypt(&sm4, in, in, SM4_BLOCK_SIZE * 2), 0);
    ExpectIntEQ(XMEMCMP(in, out, SM4_BLOCK_SIZE * 2), 0);

    wc_Sm4Free(&sm4);

    res = EXPECT_RESULT();
#endif
    return res;
} /* END test_wc_Sm4Cbc */

/*
 * Testing streaming SM4-CTR API.
 */
int test_wc_Sm4Ctr(void)
{
    int res = TEST_SKIPPED;
#ifdef WOLFSSL_SM4_CTR
    EXPECT_DECLS;
    wc_Sm4 sm4;
    unsigned char key[SM4_KEY_SIZE];
    unsigned char iv[SM4_IV_SIZE];
    unsigned char in[SM4_BLOCK_SIZE * 4];
    unsigned char out[SM4_BLOCK_SIZE * 4];
    unsigned char out2[SM4_BLOCK_SIZE * 4];
    word32 chunk;
    word32 i;

    XMEMSET(key, 0, sizeof(key));
    XMEMSET(iv, 0, sizeof(iv));
    XMEMSET(in, 0, sizeof(in));

    ExpectIntEQ(wc_Sm4Init(&sm4, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_Sm4CtrEncrypt(&sm4, out, in, 0),
        WC_NO_ERR_TRACE(MISSING_KEY));
    /* Tested in test_wc_Sm4. */
    ExpectIntEQ(wc_Sm4SetKey(&sm4, key, SM4_KEY_SIZE), 0);
    ExpectIntEQ(wc_Sm4CtrEncrypt(&sm4, out, in, 0),
        WC_NO_ERR_TRACE(MISSING_IV));
    /* Tested in test_wc_Sm4. */
    ExpectIntEQ(wc_Sm4SetIV(&sm4, iv), 0);

    /* Invalid parameters - wc_Sm4CtrEncrypt. */
    ExpectIntEQ(wc_Sm4CtrEncrypt(NULL, NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CtrEncrypt(&sm4, NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CtrEncrypt(NULL, out, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CtrEncrypt(NULL, NULL, in, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CtrEncrypt(&sm4, out, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CtrEncrypt(&sm4, NULL, in, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CtrEncrypt(NULL, out, in, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Valid cases - wc_Sm4CtrEncrypt. */
    ExpectIntEQ(wc_Sm4CtrEncrypt(&sm4, out, in, 0), 0);
    ExpectIntEQ(wc_Sm4CtrEncrypt(&sm4, out2, in, 1), 0);
    ExpectIntEQ(wc_Sm4SetIV(&sm4, iv), 0);
    ExpectIntEQ(wc_Sm4CtrEncrypt(&sm4, out, in, 2), 0);
    ExpectIntEQ(XMEMCMP(out, out2, 1), 0);
    ExpectIntEQ(wc_Sm4SetIV(&sm4, iv), 0);
    ExpectIntEQ(wc_Sm4CtrEncrypt(&sm4, out2, in, SM4_BLOCK_SIZE), 0);
    ExpectIntEQ(XMEMCMP(out2, out, 2), 0);
    ExpectIntEQ(wc_Sm4SetIV(&sm4, iv), 0);
    ExpectIntEQ(wc_Sm4CtrEncrypt(&sm4, out, in, SM4_BLOCK_SIZE * 2), 0);
    ExpectIntEQ(XMEMCMP(out, out2, SM4_BLOCK_SIZE), 0);
    /*   In and out are same pointer. Also check encrypt of cipher text produces
     *   plaintext.
     */
    ExpectIntEQ(wc_Sm4SetIV(&sm4, iv), 0);
    ExpectIntEQ(wc_Sm4CtrEncrypt(&sm4, out, out, SM4_BLOCK_SIZE * 2), 0);
    ExpectIntEQ(XMEMCMP(in, out, SM4_BLOCK_SIZE * 2), 0);

    /* Chunking tests. */
    ExpectIntEQ(wc_Sm4SetIV(&sm4, iv), 0);
    ExpectIntEQ(wc_Sm4CtrEncrypt(&sm4, out2, in, (word32)sizeof(in)), 0);
    for (chunk = 1; chunk <= SM4_BLOCK_SIZE + 1; chunk++) {
        ExpectIntEQ(wc_Sm4SetIV(&sm4, iv), 0);
        for (i = 0; i + chunk <= (word32)sizeof(in); i += chunk) {
             ExpectIntEQ(wc_Sm4CtrEncrypt(&sm4, out + i, in + i, chunk), 0);
        }
        if (i < (word32)sizeof(in)) {
             ExpectIntEQ(wc_Sm4CtrEncrypt(&sm4, out + i, in + i,
                 (word32)sizeof(in) - i), 0);
        }
        ExpectIntEQ(XMEMCMP(out, out2, (word32)sizeof(out)), 0);
    }

    for (i = 0; i < (word32)sizeof(iv); i++) {
        iv[i] = 0xff;
        ExpectIntEQ(wc_Sm4SetIV(&sm4, iv), 0);
        ExpectIntEQ(wc_Sm4CtrEncrypt(&sm4, out, in, SM4_BLOCK_SIZE * 2), 0);
        ExpectIntEQ(wc_Sm4SetIV(&sm4, iv), 0);
        ExpectIntEQ(wc_Sm4CtrEncrypt(&sm4, out2, out, SM4_BLOCK_SIZE * 2), 0);
        ExpectIntEQ(XMEMCMP(out2, in, SM4_BLOCK_SIZE * 2), 0);
    }

    wc_Sm4Free(&sm4);

    res = EXPECT_RESULT();
#endif
    return res;
} /* END test_wc_Sm4Ctr */

/*
 * Testing stream SM4-GCM API.
 */
int test_wc_Sm4Gcm(void)
{
    int res = TEST_SKIPPED;
#ifdef WOLFSSL_SM4_GCM
    EXPECT_DECLS;
    wc_Sm4 sm4;
    unsigned char key[SM4_KEY_SIZE];
    unsigned char nonce[GCM_NONCE_MAX_SZ];
    unsigned char in[SM4_BLOCK_SIZE * 2];
    unsigned char in2[SM4_BLOCK_SIZE * 2];
    unsigned char out[SM4_BLOCK_SIZE * 2];
    unsigned char out2[SM4_BLOCK_SIZE * 2];
    unsigned char dec[SM4_BLOCK_SIZE * 2];
    unsigned char tag[SM4_BLOCK_SIZE];
    unsigned char aad[SM4_BLOCK_SIZE * 2];
    word32 i;

    XMEMSET(key, 0, sizeof(key));
    XMEMSET(nonce, 0, sizeof(nonce));
    XMEMSET(in, 0, sizeof(in));
    XMEMSET(in2, 0, sizeof(in2));
    XMEMSET(aad, 0, sizeof(aad));

    ExpectIntEQ(wc_Sm4Init(&sm4, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_Sm4GcmEncrypt(&sm4, out, in, 0, nonce, GCM_NONCE_MID_SZ, tag,
        SM4_BLOCK_SIZE, aad, sizeof(aad)), WC_NO_ERR_TRACE(MISSING_KEY));
    ExpectIntEQ(wc_Sm4GcmDecrypt(&sm4, out, in, 0, nonce, GCM_NONCE_MID_SZ, tag,
        SM4_BLOCK_SIZE, aad, sizeof(aad)), WC_NO_ERR_TRACE(MISSING_KEY));

    /* Invalid parameters - wc_Sm4GcmSetKey. */
    ExpectIntEQ(wc_Sm4GcmSetKey(NULL, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4GcmSetKey(&sm4, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4GcmSetKey(NULL, key, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4GcmSetKey(NULL, NULL, SM4_KEY_SIZE),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4GcmSetKey(&sm4, key, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4GcmSetKey(&sm4, NULL, SM4_KEY_SIZE),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4GcmSetKey(NULL, key, SM4_KEY_SIZE),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Valid parameters - wc_Sm4GcmSetKey. */
    ExpectIntEQ(wc_Sm4GcmSetKey(&sm4, key, SM4_KEY_SIZE), 0);

    /* Invalid parameters - wc_Sm4GcmEncrypt. */
    ExpectIntEQ(wc_Sm4GcmEncrypt(NULL, NULL, NULL, 1, NULL, 0, NULL, 0, NULL,
        0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4GcmEncrypt(&sm4, NULL, NULL, 1, NULL, 0, NULL, 0, NULL,
        0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4GcmEncrypt(NULL, out, NULL, 1, NULL, 0, NULL, 0, NULL,
        0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4GcmEncrypt(NULL, NULL, in, 1, NULL, 0, NULL, 0, NULL,
        0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4GcmEncrypt(NULL, NULL, NULL, 1, nonce, GCM_NONCE_MID_SZ,
        NULL, 0, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4GcmEncrypt(NULL, NULL, NULL, 1, NULL, 0, tag,
        SM4_BLOCK_SIZE, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4GcmEncrypt(NULL, out, in, 1, nonce, GCM_NONCE_MID_SZ, tag,
        SM4_BLOCK_SIZE, aad, sizeof(aad)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4GcmEncrypt(&sm4, NULL, in, 1, nonce, GCM_NONCE_MID_SZ,
        tag, SM4_BLOCK_SIZE, aad, sizeof(aad)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4GcmEncrypt(&sm4, out, NULL, 1, nonce, GCM_NONCE_MID_SZ,
        tag, SM4_BLOCK_SIZE, aad, sizeof(aad)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4GcmEncrypt(&sm4, out, in, 1, NULL, GCM_NONCE_MID_SZ, tag,
        SM4_BLOCK_SIZE, aad, sizeof(aad)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4GcmEncrypt(&sm4, out, in, 1, nonce, 0, tag,
        SM4_BLOCK_SIZE, aad, sizeof(aad)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4GcmEncrypt(&sm4, out, in, 1, nonce, GCM_NONCE_MID_SZ,
        NULL, SM4_BLOCK_SIZE, aad, sizeof(aad)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4GcmEncrypt(&sm4, out, in, 1, nonce, GCM_NONCE_MID_SZ, tag,
        WOLFSSL_MIN_AUTH_TAG_SZ-1, aad, sizeof(aad)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4GcmEncrypt(&sm4, out, in, 1, nonce, GCM_NONCE_MID_SZ, tag,
        SM4_BLOCK_SIZE+1, aad, sizeof(aad)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Invalid parameters - wc_Sm4GcmDecrypt. */
    ExpectIntEQ(wc_Sm4GcmDecrypt(NULL, NULL, NULL, 1, NULL, 0, NULL, 0, NULL,
        0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4GcmDecrypt(&sm4, NULL, NULL, 1, NULL, 0, NULL, 0, NULL,
        0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4GcmDecrypt(NULL, out, NULL, 1, NULL, 0, NULL, 0, NULL,
        0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4GcmDecrypt(NULL, NULL, in, 1, NULL, 0, NULL, 0, NULL,
        0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4GcmDecrypt(NULL, NULL, NULL, 1, nonce, GCM_NONCE_MID_SZ,
        NULL, 0, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4GcmDecrypt(NULL, NULL, NULL, 1, NULL, 0, tag,
        SM4_BLOCK_SIZE, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4GcmDecrypt(NULL, out, in, 1, nonce, GCM_NONCE_MID_SZ, tag,
        SM4_BLOCK_SIZE, aad, sizeof(aad)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4GcmDecrypt(&sm4, NULL, in, 1, nonce, GCM_NONCE_MID_SZ,
        tag, SM4_BLOCK_SIZE, aad, sizeof(aad)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4GcmDecrypt(&sm4, out, NULL, 1, nonce, GCM_NONCE_MID_SZ,
        tag, SM4_BLOCK_SIZE, aad, sizeof(aad)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4GcmDecrypt(&sm4, out, in, 1, NULL, GCM_NONCE_MID_SZ, tag,
        SM4_BLOCK_SIZE, aad, sizeof(aad)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4GcmDecrypt(&sm4, out, in, 1, nonce, 0, tag,
        SM4_BLOCK_SIZE, aad, sizeof(aad)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4GcmDecrypt(&sm4, out, in, 1, nonce, GCM_NONCE_MID_SZ,
        NULL, SM4_BLOCK_SIZE, aad, sizeof(aad)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4GcmDecrypt(&sm4, out, in, 1, nonce, GCM_NONCE_MID_SZ, tag,
        WOLFSSL_MIN_AUTH_TAG_SZ-1, aad, sizeof(aad)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4GcmDecrypt(&sm4, out, in, 1, nonce, GCM_NONCE_MID_SZ, tag,
        SM4_BLOCK_SIZE+1, aad, sizeof(aad)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Valid cases - wc_Sm4GcmEncrypt/wc_Sm4GcmDecrypt. */
    ExpectIntEQ(wc_Sm4GcmEncrypt(&sm4, NULL, NULL, 0, nonce, GCM_NONCE_MID_SZ,
        tag, SM4_BLOCK_SIZE, NULL, 0), 0);
    ExpectIntEQ(wc_Sm4GcmDecrypt(&sm4, NULL, NULL, 0, nonce, GCM_NONCE_MID_SZ,
        tag, SM4_BLOCK_SIZE, NULL, 0), 0);
    ExpectIntEQ(wc_Sm4GcmEncrypt(&sm4, NULL, NULL, 0, nonce, GCM_NONCE_MID_SZ,
        tag, SM4_BLOCK_SIZE, aad, sizeof(aad)), 0);
    ExpectIntEQ(wc_Sm4GcmDecrypt(&sm4, NULL, NULL, 0, nonce, GCM_NONCE_MID_SZ,
        tag, SM4_BLOCK_SIZE, aad, sizeof(aad)), 0);
    ExpectIntEQ(wc_Sm4GcmEncrypt(&sm4, out, in, SM4_BLOCK_SIZE, nonce,
        GCM_NONCE_MID_SZ, tag, SM4_BLOCK_SIZE, NULL, 0), 0);
    ExpectIntEQ(wc_Sm4GcmDecrypt(&sm4, in, out, SM4_BLOCK_SIZE, nonce,
        GCM_NONCE_MID_SZ, tag, SM4_BLOCK_SIZE, NULL, 0), 0);
    ExpectIntEQ(wc_Sm4GcmEncrypt(&sm4, out, in, SM4_BLOCK_SIZE, nonce,
        GCM_NONCE_MID_SZ, tag, SM4_BLOCK_SIZE, NULL, 1), 0);
    ExpectIntEQ(wc_Sm4GcmDecrypt(&sm4, in, out, SM4_BLOCK_SIZE, nonce,
        GCM_NONCE_MID_SZ, tag, SM4_BLOCK_SIZE, NULL, 1), 0);
    ExpectIntEQ(wc_Sm4GcmEncrypt(&sm4, out, in, SM4_BLOCK_SIZE * 2, nonce,
        GCM_NONCE_MID_SZ, tag, SM4_BLOCK_SIZE, aad, sizeof(aad)), 0);
    ExpectIntEQ(wc_Sm4GcmDecrypt(&sm4, in, out, SM4_BLOCK_SIZE * 2, nonce,
        GCM_NONCE_MID_SZ, tag, SM4_BLOCK_SIZE, aad, sizeof(aad)), 0);
    ExpectIntEQ(wc_Sm4GcmEncrypt(&sm4, in2, in2, SM4_BLOCK_SIZE * 2, nonce,
        GCM_NONCE_MID_SZ, tag, SM4_BLOCK_SIZE, aad, sizeof(aad)), 0);
    ExpectIntEQ(XMEMCMP(in2, out, SM4_BLOCK_SIZE * 2), 0);
    ExpectIntEQ(wc_Sm4GcmDecrypt(&sm4, in2, in2, SM4_BLOCK_SIZE * 2, nonce,
        GCM_NONCE_MID_SZ, tag, SM4_BLOCK_SIZE, aad, sizeof(aad)), 0);
    ExpectIntEQ(XMEMCMP(in2, in, SM4_BLOCK_SIZE * 2), 0);

    /* Check vald values of nonce - wc_Sm4GcmEncrypt/wc_Sm4GcmDecrypt. */
    ExpectIntEQ(wc_Sm4GcmEncrypt(&sm4, out, in, SM4_BLOCK_SIZE, nonce,
        GCM_NONCE_MAX_SZ, tag, SM4_BLOCK_SIZE, aad, sizeof(aad)), 0);
    ExpectIntEQ(wc_Sm4GcmDecrypt(&sm4, in, out, SM4_BLOCK_SIZE, nonce,
        GCM_NONCE_MAX_SZ, tag, SM4_BLOCK_SIZE, aad, sizeof(aad)), 0);
    ExpectIntEQ(wc_Sm4GcmEncrypt(&sm4, out, in, SM4_BLOCK_SIZE * 2, nonce,
        GCM_NONCE_MIN_SZ, tag, SM4_BLOCK_SIZE, aad, sizeof(aad)), 0);
    ExpectIntEQ(wc_Sm4GcmDecrypt(&sm4, in, out, SM4_BLOCK_SIZE * 2, nonce,
        GCM_NONCE_MIN_SZ, tag, SM4_BLOCK_SIZE, aad, sizeof(aad)), 0);
    ExpectIntEQ(wc_Sm4GcmDecrypt(&sm4, in, out, SM4_BLOCK_SIZE * 2, nonce,
        GCM_NONCE_MAX_SZ, tag, SM4_BLOCK_SIZE, aad, sizeof(aad)),
        WC_NO_ERR_TRACE(SM4_GCM_AUTH_E));

    /* Check valid values of tag size - wc_Sm4GcmEncrypt/wc_Sm4GcmDecrypt. */
    for (i = WOLFSSL_MIN_AUTH_TAG_SZ; i < SM4_BLOCK_SIZE; i++) {
        ExpectIntEQ(wc_Sm4GcmEncrypt(&sm4, out, in, SM4_BLOCK_SIZE, nonce,
            GCM_NONCE_MID_SZ, tag, i, aad, sizeof(aad)), 0);
        ExpectIntEQ(wc_Sm4GcmDecrypt(&sm4, in, out, SM4_BLOCK_SIZE, nonce,
            GCM_NONCE_MID_SZ, tag, i, aad, sizeof(aad)), 0);
    }

    /* Check different in/out sizes. */
    ExpectIntEQ(wc_Sm4GcmEncrypt(&sm4, out, in, 0, nonce,
        GCM_NONCE_MID_SZ, tag, SM4_BLOCK_SIZE, NULL, 0), 0);
    ExpectIntEQ(wc_Sm4GcmDecrypt(&sm4, out, in, 0, nonce,
        GCM_NONCE_MID_SZ, tag, SM4_BLOCK_SIZE, NULL, 0), 0);
    ExpectIntEQ(wc_Sm4GcmEncrypt(&sm4, out, in, 1, nonce,
        GCM_NONCE_MID_SZ, tag, SM4_BLOCK_SIZE, NULL, 0), 0);
    for (i = 2; i <= SM4_BLOCK_SIZE * 2; i++) {
        XMEMCPY(out2, out, i - 1);
        ExpectIntEQ(wc_Sm4GcmEncrypt(&sm4, out, in, i, nonce, GCM_NONCE_MID_SZ,
            tag, SM4_BLOCK_SIZE, aad, sizeof(aad)), 0);
        ExpectIntEQ(XMEMCMP(out, out2, i - 1), 0);
        ExpectIntEQ(wc_Sm4GcmDecrypt(&sm4, dec, out, i, nonce, GCM_NONCE_MID_SZ,
            tag, SM4_BLOCK_SIZE, aad, sizeof(aad)), 0);
        ExpectIntEQ(XMEMCMP(in, dec, i), 0);
    }

    /* Force the counter to roll over in first byte. */
    {
        static unsigned char largeIn[256 * SM4_BLOCK_SIZE];
        static unsigned char largeOut[256 * SM4_BLOCK_SIZE];

        ExpectIntEQ(wc_Sm4GcmEncrypt(&sm4, largeOut, largeIn, sizeof(largeIn),
            nonce, GCM_NONCE_MID_SZ, tag, SM4_BLOCK_SIZE, aad, sizeof(aad)), 0);
        ExpectIntEQ(wc_Sm4GcmDecrypt(&sm4, largeOut, largeOut, sizeof(largeIn),
            nonce, GCM_NONCE_MID_SZ, tag, SM4_BLOCK_SIZE, aad, sizeof(aad)), 0);
        ExpectIntEQ(XMEMCMP(largeOut, largeIn, sizeof(largeIn)), 0);
    }

    wc_Sm4Free(&sm4);

    res = EXPECT_RESULT();
#endif
    return res;
} /* END test_wc_Sm4Gcm */

/*
 * Testing stream SM4-CCM API.
 */
int test_wc_Sm4Ccm(void)
{
    int res = TEST_SKIPPED;
#ifdef WOLFSSL_SM4_CCM
    EXPECT_DECLS;
    wc_Sm4 sm4;
    unsigned char key[SM4_KEY_SIZE];
    unsigned char nonce[CCM_NONCE_MAX_SZ];
    unsigned char in[SM4_BLOCK_SIZE * 2];
    unsigned char in2[SM4_BLOCK_SIZE * 2];
    unsigned char out[SM4_BLOCK_SIZE * 2];
    unsigned char out2[SM4_BLOCK_SIZE * 2];
    unsigned char dec[SM4_BLOCK_SIZE * 2];
    unsigned char tag[SM4_BLOCK_SIZE];
    unsigned char aad[SM4_BLOCK_SIZE * 2];
    word32 i;

    XMEMSET(key, 0, sizeof(key));
    XMEMSET(nonce, 0, sizeof(nonce));
    XMEMSET(in, 0, sizeof(in));
    XMEMSET(in2, 0, sizeof(in2));
    XMEMSET(aad, 0, sizeof(aad));

    ExpectIntEQ(wc_Sm4Init(&sm4, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_Sm4CcmEncrypt(&sm4, out, in, 0, nonce, CCM_NONCE_MAX_SZ, tag,
        SM4_BLOCK_SIZE, aad, sizeof(aad)), WC_NO_ERR_TRACE(MISSING_KEY));
    ExpectIntEQ(wc_Sm4CcmDecrypt(&sm4, out, in, 0, nonce, CCM_NONCE_MAX_SZ, tag,
        SM4_BLOCK_SIZE, aad, sizeof(aad)), WC_NO_ERR_TRACE(MISSING_KEY));
    ExpectIntEQ(wc_Sm4SetKey(&sm4, key, SM4_KEY_SIZE), 0);

    /* Invalid parameters - wc_Sm4CcmEncrypt. */
    ExpectIntEQ(wc_Sm4CcmEncrypt(NULL, NULL, NULL, 1, NULL, 0, NULL, 0, NULL,
        0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CcmEncrypt(&sm4, NULL, NULL, 1, NULL, 0, NULL, 0, NULL,
        0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CcmEncrypt(NULL, out, NULL, 1, NULL, 0, NULL, 0, NULL,
        0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CcmEncrypt(NULL, NULL, in, 1, NULL, 0, NULL, 0, NULL,
        0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CcmEncrypt(NULL, NULL, NULL, 1, nonce, CCM_NONCE_MAX_SZ,
        NULL, 0, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CcmEncrypt(NULL, NULL, NULL, 1, NULL, 0, tag,
        SM4_BLOCK_SIZE, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CcmEncrypt(NULL, out, in, 1, nonce, CCM_NONCE_MAX_SZ, tag,
        SM4_BLOCK_SIZE, aad, sizeof(aad)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CcmEncrypt(&sm4, NULL, in, 1, nonce, CCM_NONCE_MAX_SZ,
        tag, SM4_BLOCK_SIZE, aad, sizeof(aad)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CcmEncrypt(&sm4, out, NULL, 1, nonce, CCM_NONCE_MAX_SZ,
        tag, SM4_BLOCK_SIZE, aad, sizeof(aad)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CcmEncrypt(&sm4, out, in, 1, NULL, CCM_NONCE_MAX_SZ, tag,
        SM4_BLOCK_SIZE, aad, sizeof(aad)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CcmEncrypt(&sm4, out, in, 1, nonce, 0, tag,
        SM4_BLOCK_SIZE, aad, sizeof(aad)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CcmEncrypt(&sm4, out, in, 1, nonce, CCM_NONCE_MAX_SZ,
        NULL, SM4_BLOCK_SIZE, aad, sizeof(aad)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CcmEncrypt(&sm4, out, in, 1, nonce, CCM_NONCE_MAX_SZ, tag,
        WOLFSSL_MIN_AUTH_TAG_SZ-1, aad, sizeof(aad)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CcmEncrypt(&sm4, out, in, 1, nonce, CCM_NONCE_MAX_SZ, tag,
        SM4_BLOCK_SIZE+1, aad, sizeof(aad)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Invalid parameters - wc_Sm4CcmDecrypt. */
    ExpectIntEQ(wc_Sm4CcmDecrypt(NULL, NULL, NULL, 1, NULL, 0, NULL, 0, NULL,
        0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CcmDecrypt(&sm4, NULL, NULL, 1, NULL, 0, NULL, 0, NULL,
        0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CcmDecrypt(NULL, out, NULL, 1, NULL, 0, NULL, 0, NULL,
        0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CcmDecrypt(NULL, NULL, in, 1, NULL, 0, NULL, 0, NULL,
        0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CcmDecrypt(NULL, NULL, NULL, 1, nonce, CCM_NONCE_MAX_SZ,
        NULL, 0, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CcmDecrypt(NULL, NULL, NULL, 1, NULL, 0, tag,
        SM4_BLOCK_SIZE, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CcmDecrypt(NULL, out, in, 1, nonce, CCM_NONCE_MAX_SZ, tag,
        SM4_BLOCK_SIZE, aad, sizeof(aad)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CcmDecrypt(&sm4, NULL, in, 1, nonce, CCM_NONCE_MAX_SZ,
        tag, SM4_BLOCK_SIZE, aad, sizeof(aad)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CcmDecrypt(&sm4, out, NULL, 1, nonce, CCM_NONCE_MAX_SZ,
        tag, SM4_BLOCK_SIZE, aad, sizeof(aad)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CcmDecrypt(&sm4, out, in, 1, NULL, CCM_NONCE_MAX_SZ, tag,
        SM4_BLOCK_SIZE, aad, sizeof(aad)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CcmDecrypt(&sm4, out, in, 1, nonce, 0, tag,
        SM4_BLOCK_SIZE, aad, sizeof(aad)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CcmDecrypt(&sm4, out, in, 1, nonce, CCM_NONCE_MAX_SZ,
        NULL, SM4_BLOCK_SIZE, aad, sizeof(aad)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CcmDecrypt(&sm4, out, in, 1, nonce, CCM_NONCE_MAX_SZ, tag,
        WOLFSSL_MIN_AUTH_TAG_SZ - 1, aad, sizeof(aad)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm4CcmDecrypt(&sm4, out, in, 1, nonce, CCM_NONCE_MAX_SZ, tag,
        SM4_BLOCK_SIZE + 1, aad, sizeof(aad)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Valid cases - wc_Sm4CcmEncrypt/wc_Sm4CcmDecrypt. */
    ExpectIntEQ(wc_Sm4CcmEncrypt(&sm4, NULL, NULL, 0, nonce, CCM_NONCE_MAX_SZ,
        tag, SM4_BLOCK_SIZE, NULL, 0), 0);
    ExpectIntEQ(wc_Sm4CcmDecrypt(&sm4, NULL, NULL, 0, nonce, CCM_NONCE_MAX_SZ,
        tag, SM4_BLOCK_SIZE, NULL, 0), 0);
    ExpectIntEQ(wc_Sm4CcmEncrypt(&sm4, NULL, NULL, 0, nonce, CCM_NONCE_MAX_SZ,
        tag, SM4_BLOCK_SIZE, aad, sizeof(aad)), 0);
    ExpectIntEQ(wc_Sm4CcmDecrypt(&sm4, NULL, NULL, 0, nonce, CCM_NONCE_MAX_SZ,
        tag, SM4_BLOCK_SIZE, aad, sizeof(aad)), 0);
    ExpectIntEQ(wc_Sm4CcmEncrypt(&sm4, out, in, SM4_BLOCK_SIZE, nonce,
        CCM_NONCE_MAX_SZ, tag, SM4_BLOCK_SIZE, NULL, 0), 0);
    ExpectIntEQ(wc_Sm4CcmDecrypt(&sm4, in, out, SM4_BLOCK_SIZE, nonce,
        CCM_NONCE_MAX_SZ, tag, SM4_BLOCK_SIZE, NULL, 0), 0);
    ExpectIntEQ(wc_Sm4CcmEncrypt(&sm4, out, in, SM4_BLOCK_SIZE, nonce,
        CCM_NONCE_MAX_SZ, tag, SM4_BLOCK_SIZE, NULL, 1), 0);
    ExpectIntEQ(wc_Sm4CcmDecrypt(&sm4, in, out, SM4_BLOCK_SIZE, nonce,
        CCM_NONCE_MAX_SZ, tag, SM4_BLOCK_SIZE, NULL, 1), 0);
    ExpectIntEQ(wc_Sm4CcmEncrypt(&sm4, out, in, SM4_BLOCK_SIZE * 2, nonce,
        CCM_NONCE_MAX_SZ, tag, SM4_BLOCK_SIZE, aad, sizeof(aad)), 0);
    ExpectIntEQ(wc_Sm4CcmDecrypt(&sm4, in, out, SM4_BLOCK_SIZE * 2, nonce,
        CCM_NONCE_MAX_SZ, tag, SM4_BLOCK_SIZE, aad, sizeof(aad)), 0);
    ExpectIntEQ(wc_Sm4CcmEncrypt(&sm4, in2, in2, SM4_BLOCK_SIZE * 2, nonce,
        CCM_NONCE_MAX_SZ, tag, SM4_BLOCK_SIZE, aad, sizeof(aad)), 0);
    ExpectIntEQ(XMEMCMP(in2, out, SM4_BLOCK_SIZE * 2), 0);
    ExpectIntEQ(wc_Sm4CcmDecrypt(&sm4, in2, in2, SM4_BLOCK_SIZE * 2, nonce,
        CCM_NONCE_MAX_SZ, tag, SM4_BLOCK_SIZE, aad, sizeof(aad)), 0);
    ExpectIntEQ(XMEMCMP(in2, in, SM4_BLOCK_SIZE * 2), 0);

    /* Check vald values of nonce - wc_Sm4CcmEncrypt/wc_Sm4CcmDecrypt. */
    for (i = CCM_NONCE_MIN_SZ; i <= CCM_NONCE_MAX_SZ; i++) {
        ExpectIntEQ(wc_Sm4CcmEncrypt(&sm4, out, in, SM4_BLOCK_SIZE, nonce,
            i, tag, SM4_BLOCK_SIZE, aad, sizeof(aad)), 0);
        ExpectIntEQ(wc_Sm4CcmDecrypt(&sm4, in, out, SM4_BLOCK_SIZE, nonce,
            i, tag, SM4_BLOCK_SIZE, aad, sizeof(aad)), 0);
    }
    ExpectIntEQ(wc_Sm4CcmDecrypt(&sm4, in, out, SM4_BLOCK_SIZE, nonce,
        CCM_NONCE_MIN_SZ, tag, SM4_BLOCK_SIZE, aad, sizeof(aad)),
        WC_NO_ERR_TRACE(SM4_CCM_AUTH_E));

    /* Check invalid values of tag size - wc_Sm4CcmEncrypt/wc_Sm4CcmDecrypt. */
    for (i = 0; i < 4; i++) {
        ExpectIntEQ(wc_Sm4CcmEncrypt(&sm4, out, in, SM4_BLOCK_SIZE, nonce,
            CCM_NONCE_MAX_SZ, tag, i * 2 + 1, aad, sizeof(aad)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_Sm4CcmDecrypt(&sm4, in, out, SM4_BLOCK_SIZE, nonce,
            CCM_NONCE_MAX_SZ, tag, i * 2 + 1, aad, sizeof(aad)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }
    /*   Odd values in range 4..SM4_BLOCK_SIZE. */
    for (i = 2; i < SM4_BLOCK_SIZE / 2; i++) {
        ExpectIntEQ(wc_Sm4CcmEncrypt(&sm4, out, in, SM4_BLOCK_SIZE, nonce,
            CCM_NONCE_MAX_SZ, tag, i * 2 + 1, aad, sizeof(aad)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_Sm4CcmDecrypt(&sm4, in, out, SM4_BLOCK_SIZE, nonce,
            CCM_NONCE_MAX_SZ, tag, i * 2 + 1, aad, sizeof(aad)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }
    /* Check valid values of tag size - wc_Sm4CcmEncrypt/wc_Sm4CcmDecrypt.
     * Even values in range 4..SM4_BLOCK_SIZE.
     */
    for (i = 2; i < SM4_BLOCK_SIZE / 2; i++) {
        ExpectIntEQ(wc_Sm4CcmEncrypt(&sm4, out, in, SM4_BLOCK_SIZE, nonce,
            CCM_NONCE_MAX_SZ, tag, i * 2, aad, sizeof(aad)), 0);
        ExpectIntEQ(wc_Sm4CcmDecrypt(&sm4, in, out, SM4_BLOCK_SIZE, nonce,
            CCM_NONCE_MAX_SZ, tag, i * 2, aad, sizeof(aad)), 0);
    }

    /* Check different in/out sizes. */
    ExpectIntEQ(wc_Sm4CcmEncrypt(&sm4, out, in, 0, nonce,
        CCM_NONCE_MAX_SZ, tag, SM4_BLOCK_SIZE, NULL, 0), 0);
    ExpectIntEQ(wc_Sm4CcmDecrypt(&sm4, out, in, 0, nonce,
        CCM_NONCE_MAX_SZ, tag, SM4_BLOCK_SIZE, NULL, 0), 0);
    ExpectIntEQ(wc_Sm4CcmEncrypt(&sm4, out, in, 1, nonce,
        CCM_NONCE_MAX_SZ, tag, SM4_BLOCK_SIZE, NULL, 0), 0);
    for (i = 2; i <= SM4_BLOCK_SIZE * 2; i++) {
        XMEMCPY(out2, out, i - 1);
        ExpectIntEQ(wc_Sm4CcmEncrypt(&sm4, out, in, i, nonce, CCM_NONCE_MAX_SZ,
            tag, SM4_BLOCK_SIZE, aad, sizeof(aad)), 0);
        ExpectIntEQ(XMEMCMP(out, out2, i - 1), 0);
        ExpectIntEQ(wc_Sm4CcmDecrypt(&sm4, dec, out, i, nonce, CCM_NONCE_MAX_SZ,
            tag, SM4_BLOCK_SIZE, aad, sizeof(aad)), 0);
        ExpectIntEQ(XMEMCMP(in, dec, i), 0);
    }

    /* Force the counter to roll over in first byte. */
    {
        static unsigned char largeIn[256 * SM4_BLOCK_SIZE];
        static unsigned char largeOut[256 * SM4_BLOCK_SIZE];

        ExpectIntEQ(wc_Sm4CcmEncrypt(&sm4, largeOut, largeIn, sizeof(largeIn),
            nonce, CCM_NONCE_MAX_SZ, tag, SM4_BLOCK_SIZE, aad, sizeof(aad)), 0);
        ExpectIntEQ(wc_Sm4CcmDecrypt(&sm4, largeOut, largeOut, sizeof(largeIn),
            nonce, CCM_NONCE_MAX_SZ, tag, SM4_BLOCK_SIZE, aad, sizeof(aad)), 0);
        ExpectIntEQ(XMEMCMP(largeOut, largeIn, sizeof(largeIn)), 0);
    }

    wc_Sm4Free(&sm4);

    res = EXPECT_RESULT();
#endif
    return res;
} /* END test_wc_Sm4Ccm */

