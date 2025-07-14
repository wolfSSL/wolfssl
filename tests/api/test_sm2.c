/* test_sm2.c
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

#include <wolfssl/wolfcrypt/sm2.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_sm2.h>

/*
 * Testing wc_ecc_sm2_make_key()
 */
int test_wc_ecc_sm2_make_key(void)
{
    int res = TEST_SKIPPED;
#if defined(HAVE_ECC) && defined(WOLFSSL_SM2)
    EXPECT_DECLS;
    WC_RNG  rng[1];
    ecc_key key[1];

    XMEMSET(rng, 0, sizeof(*rng));
    XMEMSET(key, 0, sizeof(*key));

    ExpectIntEQ(wc_InitRng(rng), 0);
    ExpectIntEQ(wc_ecc_init(key), 0);

    /* Test invalid parameters. */
    ExpectIntEQ(wc_ecc_sm2_make_key(NULL, NULL, WC_ECC_FLAG_NONE),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_make_key(rng, NULL, WC_ECC_FLAG_NONE),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_make_key(NULL, key, WC_ECC_FLAG_NONE),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test valid parameters. */
    ExpectIntEQ(wc_ecc_sm2_make_key(rng, key, WC_ECC_FLAG_NONE), 0);
    ExpectIntEQ(key->dp->id, ECC_SM2P256V1);

    wc_ecc_free(key);
    wc_FreeRng(rng);
#ifdef FP_ECC
    wc_ecc_fp_free();
#endif

    res = EXPECT_RESULT();
#endif
    return res;
}

/*
 * Testing wc_ecc_sm2_shared_secret()
 */
int test_wc_ecc_sm2_shared_secret(void)
{
    int res = TEST_SKIPPED;
#if defined(HAVE_ECC) && defined(WOLFSSL_SM2)
    EXPECT_DECLS;
    WC_RNG  rng[1];
    ecc_key keyA[1];
    ecc_key keyB[1];
    byte outA[32];
    byte outB[32];
    word32 outALen = 32;
    word32 outBLen = 32;

    XMEMSET(rng, 0, sizeof(*rng));
    XMEMSET(keyA, 0, sizeof(*keyA));
    XMEMSET(keyB, 0, sizeof(*keyB));

    ExpectIntEQ(wc_InitRng(rng), 0);
    ExpectIntEQ(wc_ecc_init(keyA), 0);
    ExpectIntEQ(wc_ecc_init(keyB), 0);
    ExpectIntEQ(wc_ecc_sm2_make_key(rng, keyA, WC_ECC_FLAG_NONE), 0);
    ExpectIntEQ(wc_ecc_sm2_make_key(rng, keyB, WC_ECC_FLAG_NONE), 0);

#ifdef ECC_TIMING_RESISTANT
    ExpectIntEQ(wc_ecc_set_rng(keyA, rng), 0);
    ExpectIntEQ(wc_ecc_set_rng(keyB, rng), 0);
#endif

    /* Test invalid parameters. */
    ExpectIntEQ(wc_ecc_sm2_shared_secret(NULL, NULL, NULL, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_shared_secret(keyA, NULL, NULL, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_shared_secret(NULL, keyB, NULL, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_shared_secret(NULL, NULL, outA, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_shared_secret(NULL, NULL, NULL, &outALen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_shared_secret(NULL, keyB, outA, &outALen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_shared_secret(keyA, NULL, outA, &outALen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_shared_secret(keyA, keyB, NULL, &outALen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_shared_secret(keyA, keyB, outA, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test valid parameters. */
    ExpectIntEQ(wc_ecc_sm2_shared_secret(keyA, keyB, outA, &outALen), 0);
    ExpectIntLE(outALen, 32);
    ExpectIntEQ(wc_ecc_sm2_shared_secret(keyB, keyA, outB, &outBLen), 0);
    ExpectIntLE(outBLen, 32);
    ExpectIntEQ(outALen, outBLen);
    ExpectBufEQ(outA, outB, outALen);

    wc_ecc_free(keyB);
    wc_ecc_free(keyA);
    wc_FreeRng(rng);
#ifdef FP_ECC
    wc_ecc_fp_free();
#endif

    res = EXPECT_RESULT();
#endif
    return res;
}

/*
 * Testing wc_ecc_sm2_create_digest()
 */
int test_wc_ecc_sm2_create_digest(void)
{
    int res = TEST_SKIPPED;
#if defined(HAVE_ECC) && defined(WOLFSSL_SM2) && !defined(NO_HASH_WRAPPER) && \
    (defined(WOLFSSL_SM3) || !defined(NO_SHA256))
    EXPECT_DECLS;
    ecc_key key[1];
    enum wc_HashType hashType;
    unsigned char pub[] = {
        0x04,
        0x63, 0x7F, 0x1B, 0x13, 0x50, 0x36, 0xC9, 0x33,
        0xDC, 0x3F, 0x7A, 0x8E, 0xBB, 0x1B, 0x7B, 0x2F,
        0xD1, 0xDF, 0xBD, 0x26, 0x8D, 0x4F, 0x89, 0x4B,
        0x5A, 0xD4, 0x7D, 0xBD, 0xBE, 0xCD, 0x55, 0x8F,
        0xE8, 0x81, 0x01, 0xD0, 0x80, 0x48, 0xE3, 0x6C,
        0xCB, 0xF6, 0x1C, 0xA3, 0x8D, 0xDF, 0x7A, 0xBA,
        0x54, 0x2B, 0x44, 0x86, 0xE9, 0x9E, 0x49, 0xF3,
        0xA7, 0x47, 0x0A, 0x85, 0x7A, 0x09, 0x64, 0x33
    };
    unsigned char id[] = {
        0x01, 0x02, 0x03,
    };
    unsigned char msg[] = {
        0x01, 0x02, 0x03,
    };
    unsigned char hash[32];
#ifdef WOLFSSL_SM3
    unsigned char expHash[32] = {
        0xc1, 0xdd, 0x92, 0xc5, 0x60, 0xd3, 0x94, 0x28,
        0xeb, 0x0f, 0x57, 0x79, 0x3f, 0xc9, 0x96, 0xc5,
        0xfa, 0xf5, 0x90, 0xb2, 0x64, 0x2f, 0xaf, 0x9c,
        0xc8, 0x57, 0x21, 0x6a, 0x52, 0x7e, 0xf1, 0x95
    };
#else
    unsigned char expHash[32] = {
        0xea, 0x41, 0x55, 0x21, 0x61, 0x00, 0x5c, 0x9a,
        0x57, 0x35, 0x6b, 0x49, 0xca, 0x8f, 0x65, 0xc2,
        0x0e, 0x29, 0x0c, 0xa0, 0x1d, 0xa7, 0xc4, 0xed,
        0xdd, 0x51, 0x12, 0xf6, 0xe7, 0x55, 0xc5, 0xf4
    };
#endif

#ifdef WOLFSSL_SM3
    hashType = WC_HASH_TYPE_SM3;
#else
    hashType = WC_HASH_TYPE_SHA256;
#endif

    XMEMSET(key, 0, sizeof(*key));

    ExpectIntEQ(wc_ecc_init(key), 0);

    /* Test with no curve set. */
    ExpectIntEQ(wc_ecc_sm2_create_digest(id, sizeof(id), msg, sizeof(msg),
        hashType, hash, sizeof(hash), key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_ecc_import_x963_ex(pub, sizeof(pub), key, ECC_SM2P256V1), 0);

    /* Test invalid parameters. */
    ExpectIntEQ(wc_ecc_sm2_create_digest(NULL, sizeof(id), NULL, sizeof(msg),
        hashType, NULL, sizeof(hash), NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_create_digest(id, sizeof(id), NULL, sizeof(msg),
        hashType, NULL, sizeof(hash), NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_create_digest(NULL, sizeof(id), msg, sizeof(msg),
        hashType, NULL, sizeof(hash), NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_create_digest(NULL, sizeof(id), NULL, sizeof(msg),
        hashType, hash, sizeof(hash), NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_create_digest(NULL, sizeof(id), NULL, sizeof(msg),
        hashType, NULL, sizeof(hash), key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_create_digest(NULL, sizeof(id), msg, sizeof(msg),
        hashType, hash, sizeof(hash), key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_create_digest(id, sizeof(id), NULL, sizeof(msg),
        hashType, hash, sizeof(hash), key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_create_digest(id, sizeof(id), msg, sizeof(msg),
        hashType, NULL, sizeof(hash), key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_create_digest(id, sizeof(id), msg, sizeof(msg),
        hashType, hash, sizeof(hash), NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Bad hash type. */
    /* // NOLINTBEGIN(clang-analyzer-optin.core.EnumCastOutOfRange) */
    ExpectIntEQ(wc_ecc_sm2_create_digest(id, sizeof(id), msg, sizeof(msg),
        -1, hash, 0, key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* // NOLINTEND(clang-analyzer-optin.core.EnumCastOutOfRange) */
    /* Bad hash size. */
    ExpectIntEQ(wc_ecc_sm2_create_digest(id, sizeof(id), msg, sizeof(msg),
        hashType, hash, 0, key), WC_NO_ERR_TRACE(BUFFER_E));

    /* Test valid parameters. */
    ExpectIntEQ(wc_ecc_sm2_create_digest(id, sizeof(id), msg, sizeof(msg),
        hashType, hash, sizeof(hash), key), 0);
    ExpectBufEQ(hash, expHash, sizeof(expHash));

    wc_ecc_free(key);

    res = EXPECT_RESULT();
#endif
    return res;
}

/*
 * Testing wc_ecc_sm2_verify_hash_ex()
 */
int test_wc_ecc_sm2_verify_hash_ex(void)
{
    int res = TEST_SKIPPED;
#if defined(HAVE_ECC) && defined(WOLFSSL_SM2) && defined(HAVE_ECC_VERIFY) && \
    defined(WOLFSSL_PUBLIC_MP)
    EXPECT_DECLS;
    ecc_key key[1];
    mp_int r[1];
    mp_int s[1];
    int verified;
    unsigned char pub[] = {
        0x04,
        0x63, 0x7F, 0x1B, 0x13, 0x50, 0x36, 0xC9, 0x33,
        0xDC, 0x3F, 0x7A, 0x8E, 0xBB, 0x1B, 0x7B, 0x2F,
        0xD1, 0xDF, 0xBD, 0x26, 0x8D, 0x4F, 0x89, 0x4B,
        0x5A, 0xD4, 0x7D, 0xBD, 0xBE, 0xCD, 0x55, 0x8F,
        0xE8, 0x81, 0x01, 0xD0, 0x80, 0x48, 0xE3, 0x6C,
        0xCB, 0xF6, 0x1C, 0xA3, 0x8D, 0xDF, 0x7A, 0xBA,
        0x54, 0x2B, 0x44, 0x86, 0xE9, 0x9E, 0x49, 0xF3,
        0xA7, 0x47, 0x0A, 0x85, 0x7A, 0x09, 0x64, 0x33
    };
    unsigned char hash[] = {
        0x3B, 0xFA, 0x5F, 0xFB, 0xC4, 0x27, 0x8C, 0x9D,
        0x02, 0x3A, 0x19, 0xCB, 0x1E, 0xAA, 0xD2, 0xF1,
        0x50, 0x69, 0x5B, 0x20
    };
    unsigned char rData[] = {
        0xD2, 0xFC, 0xA3, 0x88, 0xE3, 0xDF, 0xA3, 0x00,
        0x73, 0x9B, 0x3C, 0x2A, 0x0D, 0xAD, 0x44, 0xA2,
        0xFC, 0x62, 0xD5, 0x6B, 0x84, 0x54, 0xD8, 0x40,
        0x22, 0x62, 0x3D, 0x5C, 0xA6, 0x61, 0x9B, 0xE7,
    };
    unsigned char sData[] = {
        0x1D,
        0xB5, 0xB5, 0xD9, 0xD8, 0xF1, 0x20, 0xDD, 0x97,
        0x92, 0xBF, 0x7E, 0x9B, 0x3F, 0xE6, 0x3C, 0x4B,
        0x03, 0xD8, 0x80, 0xBD, 0xB7, 0x27, 0x7E, 0x6A,
        0x84, 0x23, 0xDE, 0x61, 0x7C, 0x8D, 0xDC
    };
    unsigned char rBadData[] = {
        0xD2, 0xFC, 0xA3, 0x88, 0xE3, 0xDF, 0xA3, 0x00,
        0x73, 0x9B, 0x3C, 0x2A, 0x0D, 0xAD, 0x44, 0xA2,
        0xFC, 0x62, 0xD5, 0x6B, 0x84, 0x54, 0xD8, 0x40,
        0x22, 0x62, 0x3D, 0x5C, 0xA6, 0x61, 0x9B, 0xE8,
    };

    XMEMSET(key, 0, sizeof(*key));
    XMEMSET(r, 0, sizeof(*r));
    XMEMSET(s, 0, sizeof(*s));

    ExpectIntEQ(mp_init(r), 0);
    ExpectIntEQ(mp_init(s), 0);
    ExpectIntEQ(mp_read_unsigned_bin(r, rData, sizeof(rData)), 0);
    ExpectIntEQ(mp_read_unsigned_bin(s, sData, sizeof(sData)), 0);

    ExpectIntEQ(wc_ecc_init(key), 0);

    /* Test with no curve set. */
    ExpectIntEQ(wc_ecc_sm2_verify_hash_ex(r, s, hash, sizeof(hash),
        &verified, key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_ecc_import_x963_ex(pub, sizeof(pub), key, ECC_SM2P256V1), 0);

    /* Test invalid parameters. */
    ExpectIntEQ(wc_ecc_sm2_verify_hash_ex(NULL, NULL, NULL, sizeof(hash),
        NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_verify_hash_ex(r, NULL, NULL, sizeof(hash),
        NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_verify_hash_ex(NULL, s, NULL, sizeof(hash),
        NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_verify_hash_ex(NULL, NULL, hash, sizeof(hash),
        NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_verify_hash_ex(NULL, NULL, NULL, sizeof(hash),
        &verified, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_verify_hash_ex(NULL, NULL, NULL, sizeof(hash),
        NULL, key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_verify_hash_ex(NULL, s, hash, sizeof(hash),
        &verified, key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_verify_hash_ex(r, NULL, hash, sizeof(hash),
        &verified, key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_verify_hash_ex(r, s, NULL, sizeof(hash),
        &verified, key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_verify_hash_ex(r, s, hash, sizeof(hash),
        NULL, key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_verify_hash_ex(r, s, hash, sizeof(hash),
        &verified, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Make key not on the SM2 curve. */
    ExpectIntEQ(wc_ecc_set_curve(key, 32, ECC_SECP256R1), 0);
    ExpectIntEQ(wc_ecc_sm2_verify_hash_ex(r, s, hash, sizeof(hash),
        &verified, key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_set_curve(key, 32, ECC_SM2P256V1), 0);

    /* Test valid parameters. */
    ExpectIntEQ(wc_ecc_sm2_verify_hash_ex(r, s, hash, sizeof(hash),
        &verified, key), 0);
    ExpectIntEQ(verified, 1);

    ExpectIntEQ(mp_read_unsigned_bin(r, rBadData, sizeof(rBadData)), 0);
    ExpectIntEQ(wc_ecc_sm2_verify_hash_ex(r, s, hash, sizeof(hash),
        &verified, key), 0);
    ExpectIntEQ(verified, 0);

    mp_free(s);
    mp_free(r);
    wc_ecc_free(key);
#ifdef FP_ECC
    wc_ecc_fp_free();
#endif

    res = EXPECT_RESULT();
#endif
    return res;
}

/*
 * Testing wc_ecc_sm2_verify_hash()
 */
int test_wc_ecc_sm2_verify_hash(void)
{
    int res = TEST_SKIPPED;
#if defined(HAVE_ECC) && defined(WOLFSSL_SM2) && defined(HAVE_ECC_VERIFY)
    EXPECT_DECLS;
    ecc_key key[1];
    int verified;
    unsigned char pub[] = {
        0x04,
        0x63, 0x7F, 0x1B, 0x13, 0x50, 0x36, 0xC9, 0x33,
        0xDC, 0x3F, 0x7A, 0x8E, 0xBB, 0x1B, 0x7B, 0x2F,
        0xD1, 0xDF, 0xBD, 0x26, 0x8D, 0x4F, 0x89, 0x4B,
        0x5A, 0xD4, 0x7D, 0xBD, 0xBE, 0xCD, 0x55, 0x8F,
        0xE8, 0x81, 0x01, 0xD0, 0x80, 0x48, 0xE3, 0x6C,
        0xCB, 0xF6, 0x1C, 0xA3, 0x8D, 0xDF, 0x7A, 0xBA,
        0x54, 0x2B, 0x44, 0x86, 0xE9, 0x9E, 0x49, 0xF3,
        0xA7, 0x47, 0x0A, 0x85, 0x7A, 0x09, 0x64, 0x33
    };
    unsigned char hash[] = {
        0x3B, 0xFA, 0x5F, 0xFB, 0xC4, 0x27, 0x8C, 0x9D,
        0x02, 0x3A, 0x19, 0xCB, 0x1E, 0xAA, 0xD2, 0xF1,
        0x50, 0x69, 0x5B, 0x20
    };
    unsigned char sig[] = {
        0x30, 0x45, 0x02, 0x21, 0x00, 0xD2, 0xFC, 0xA3,
        0x88, 0xE3, 0xDF, 0xA3, 0x00, 0x73, 0x9B, 0x3C,
        0x2A, 0x0D, 0xAD, 0x44, 0xA2, 0xFC, 0x62, 0xD5,
        0x6B, 0x84, 0x54, 0xD8, 0x40, 0x22, 0x62, 0x3D,
        0x5C, 0xA6, 0x61, 0x9B, 0xE7, 0x02, 0x20, 0x1D,
        0xB5, 0xB5, 0xD9, 0xD8, 0xF1, 0x20, 0xDD, 0x97,
        0x92, 0xBF, 0x7E, 0x9B, 0x3F, 0xE6, 0x3C, 0x4B,
        0x03, 0xD8, 0x80, 0xBD, 0xB7, 0x27, 0x7E, 0x6A,
        0x84, 0x23, 0xDE, 0x61, 0x7C, 0x8D, 0xDC
    };
    unsigned char sigBad[] = {
        0x30, 0x45, 0x02, 0x21, 0x00, 0xD2, 0xFC, 0xA3,
        0x88, 0xE3, 0xDF, 0xA3, 0x00, 0x73, 0x9B, 0x3C,
        0x2A, 0x0D, 0xAD, 0x44, 0xA2, 0xFC, 0x62, 0xD5,
        0x6B, 0x84, 0x54, 0xD8, 0x40, 0x22, 0x62, 0x3D,
        0x5C, 0xA6, 0x61, 0x9B, 0xE7, 0x02, 0x20, 0x1D,
        0xB5, 0xB5, 0xD9, 0xD8, 0xF1, 0x20, 0xDD, 0x97,
        0x92, 0xBF, 0x7E, 0x9B, 0x3F, 0xE6, 0x3C, 0x4B,
        0x03, 0xD8, 0x80, 0xBD, 0xB7, 0x27, 0x7E, 0x6A,
        0x84, 0x23, 0xDE, 0x61, 0x7C, 0x8D, 0xDD
    };


    XMEMSET(key, 0, sizeof(*key));
    ExpectIntEQ(wc_ecc_init(key), 0);

    /* Test with no curve set. */
    ExpectIntEQ(wc_ecc_sm2_verify_hash(sig, sizeof(sig), hash, sizeof(hash),
        &verified, key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_ecc_import_x963_ex(pub, sizeof(pub), key, ECC_SM2P256V1), 0);

    /* Test invalid parameters. */
    ExpectIntEQ(wc_ecc_sm2_verify_hash(NULL, sizeof(sig), NULL, sizeof(hash),
        NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_verify_hash(sig, sizeof(sig), NULL, sizeof(hash),
        NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_verify_hash(NULL, sizeof(sig), hash, sizeof(hash),
        NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_verify_hash(NULL, sizeof(sig), NULL, sizeof(hash),
        &verified, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_verify_hash(NULL, sizeof(sig), NULL, sizeof(hash),
        NULL, key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_verify_hash(NULL, sizeof(sig), hash, sizeof(hash),
        &verified, key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_verify_hash(sig, sizeof(sig), NULL, sizeof(hash),
        &verified, key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_verify_hash(sig, sizeof(sig), hash, sizeof(hash),
        NULL, key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_verify_hash(sig, sizeof(sig), hash, sizeof(hash),
        &verified, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Make key not on the SM2 curve. */
    ExpectIntEQ(wc_ecc_set_curve(key, 32, ECC_SECP256R1), 0);
    ExpectIntEQ(wc_ecc_sm2_verify_hash(sig, sizeof(sig), hash, sizeof(hash),
        &verified, key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_set_curve(key, 32, ECC_SM2P256V1), 0);

    /* Test valid parameters. */
    ExpectIntEQ(wc_ecc_sm2_verify_hash(sig, sizeof(sig), hash, sizeof(hash),
        &verified, key), 0);
    ExpectIntEQ(verified, 1);

    ExpectIntEQ(wc_ecc_sm2_verify_hash(sigBad, sizeof(sigBad), hash,
        sizeof(hash), &verified, key), 0);
    ExpectIntEQ(verified, 0);

    wc_ecc_free(key);
#ifdef FP_ECC
    wc_ecc_fp_free();
#endif

    res = EXPECT_RESULT();
#endif
    return res;
}

/*
 * Testing wc_ecc_sm2_sign_hash_ex()
 */
int test_wc_ecc_sm2_sign_hash_ex(void)
{
    int res = TEST_SKIPPED;
#if defined(HAVE_ECC) && defined(WOLFSSL_SM2) && defined(HAVE_ECC_SIGN) && \
    defined(WOLFSSL_PUBLIC_MP)
    EXPECT_DECLS;
    WC_RNG  rng[1];
    ecc_key key[1];
    mp_int r[1];
    mp_int s[1];
    unsigned char hash[32];
#ifdef HAVE_ECC_VERIFY
    int verified;
#endif

    XMEMSET(rng, 0, sizeof(*rng));
    XMEMSET(key, 0, sizeof(*key));
    XMEMSET(r, 0, sizeof(*r));
    XMEMSET(s, 0, sizeof(*s));

    ExpectIntEQ(wc_InitRng(rng), 0);
    ExpectIntEQ(mp_init(r), 0);
    ExpectIntEQ(mp_init(s), 0);
    ExpectIntEQ(wc_RNG_GenerateBlock(rng, hash, sizeof(hash)), 0);

    ExpectIntEQ(wc_ecc_init(key), 0);

    /* Test with no curve set. */
    ExpectIntEQ(wc_ecc_sm2_sign_hash_ex(hash, sizeof(hash), rng, key, r, s),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_ecc_sm2_make_key(rng, key, WC_ECC_FLAG_NONE), 0);

    /* Test invalid parameters. */
    ExpectIntEQ(wc_ecc_sm2_sign_hash_ex(NULL, sizeof(hash), NULL, NULL, NULL,
        NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_sign_hash_ex(hash, sizeof(hash), NULL, NULL, NULL,
        NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_sign_hash_ex(NULL, sizeof(hash), rng, NULL, NULL,
        NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_sign_hash_ex(NULL, sizeof(hash), NULL, key, NULL,
        NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_sign_hash_ex(NULL, sizeof(hash), NULL, NULL, r,
        NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_sign_hash_ex(NULL, sizeof(hash), NULL, NULL, NULL,
        s), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_sign_hash_ex(NULL, sizeof(hash), rng, key, r, s),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_sign_hash_ex(hash, sizeof(hash), NULL, key, r, s),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_sign_hash_ex(hash, sizeof(hash), rng, NULL, r, s),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_sign_hash_ex(hash, sizeof(hash), rng, key, NULL, s),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_sign_hash_ex(hash, sizeof(hash), rng, key, r, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Make key not on the SM2 curve. */
    ExpectIntEQ(wc_ecc_set_curve(key, 32, ECC_SECP256R1), 0);
    ExpectIntEQ(wc_ecc_sm2_sign_hash_ex(hash, sizeof(hash), rng, key, r, s),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_set_curve(key, 32, ECC_SM2P256V1), 0);

#ifdef WOLFSSL_SP_MATH_ALL
    {
        mp_int smallR[1];
        sp_init_size(smallR, 1);
        /* Force failure in _ecc_sm2_calc_r_s by r being too small. */
        ExpectIntLT(wc_ecc_sm2_sign_hash_ex(hash, sizeof(hash), rng, key,
            smallR, s), 0);
    }
#endif

    /* Test valid parameters. */
    ExpectIntEQ(wc_ecc_sm2_sign_hash_ex(hash, sizeof(hash), rng, key, r, s),
        0);
#ifdef HAVE_ECC_VERIFY
    ExpectIntEQ(wc_ecc_sm2_verify_hash_ex(r, s, hash, sizeof(hash), &verified,
        key), 0);
    ExpectIntEQ(verified, 1);
#endif

    mp_free(s);
    mp_free(r);
    wc_ecc_free(key);
    wc_FreeRng(rng);
#ifdef FP_ECC
    wc_ecc_fp_free();
#endif

    res = EXPECT_RESULT();
#endif
    return res;
}

/*
 * Testing wc_ecc_sm2_sign_hash()
 */
int test_wc_ecc_sm2_sign_hash(void)
{
    int res = TEST_SKIPPED;
#if defined(HAVE_ECC) && defined(WOLFSSL_SM2) && defined(HAVE_ECC_SIGN)
    EXPECT_DECLS;
    WC_RNG  rng[1];
    ecc_key key[1];
    unsigned char hash[32];
    unsigned char sig[72];
    word32 sigSz = sizeof(sig);
#ifdef HAVE_ECC_VERIFY
    int verified;
#endif

    XMEMSET(rng, 0, sizeof(*rng));
    XMEMSET(key, 0, sizeof(*key));

    ExpectIntEQ(wc_InitRng(rng), 0);
    ExpectIntEQ(wc_RNG_GenerateBlock(rng, hash, sizeof(hash)), 0);

    ExpectIntEQ(wc_ecc_init(key), 0);

    /* Test with no curve set. */
    ExpectIntEQ(wc_ecc_sm2_sign_hash(hash, sizeof(hash), sig, &sigSz, rng, key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_ecc_sm2_make_key(rng, key, WC_ECC_FLAG_NONE), 0);

    /* Test invalid parameters. */
    ExpectIntEQ(wc_ecc_sm2_sign_hash(NULL, sizeof(hash), NULL, NULL, NULL,
        NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_sign_hash(hash, sizeof(hash), NULL, NULL, NULL,
        NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_sign_hash(NULL, sizeof(hash), sig, NULL, NULL,
        NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_sign_hash(NULL, sizeof(hash), NULL, &sigSz, NULL,
        NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_sign_hash(NULL, sizeof(hash), NULL, NULL, rng,
        NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_sign_hash(NULL, sizeof(hash), NULL, NULL, NULL,
        key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_sign_hash(NULL, sizeof(hash), sig, &sigSz, rng,
        key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_sign_hash(hash, sizeof(hash), NULL, &sigSz, rng,
        key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_sign_hash(hash, sizeof(hash), sig, NULL, rng,
        key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_sign_hash(hash, sizeof(hash), sig, &sigSz, NULL,
        key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_sm2_sign_hash(hash, sizeof(hash), sig, &sigSz, rng,
        NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Make key not on the SM2 curve. */
    ExpectIntEQ(wc_ecc_set_curve(key, 32, ECC_SECP256R1), 0);
    ExpectIntEQ(wc_ecc_sm2_sign_hash(hash, sizeof(hash), sig, &sigSz, rng, key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_set_curve(key, 32, ECC_SM2P256V1), 0);

    /* Test valid parameters. */
    ExpectIntEQ(wc_ecc_sm2_sign_hash(hash, sizeof(hash), sig, &sigSz, rng, key),
        0);
#ifdef HAVE_ECC_VERIFY
    ExpectIntEQ(wc_ecc_sm2_verify_hash(sig, sigSz, hash, sizeof(hash),
        &verified, key), 0);
    ExpectIntEQ(verified, 1);
#endif

    wc_ecc_free(key);
    wc_FreeRng(rng);
#ifdef FP_ECC
    wc_ecc_fp_free();
#endif

    res = EXPECT_RESULT();
#endif
    return res;
}

