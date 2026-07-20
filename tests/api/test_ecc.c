/* test_ecc.c
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

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_ecc.h>

int test_wc_ecc_get_curve_size_from_name(void)
{
    EXPECT_DECLS;
#ifdef HAVE_ECC
    #if !defined(NO_ECC256) && !defined(NO_ECC_SECP)
        ExpectIntEQ(wc_ecc_get_curve_size_from_name("SECP256R1"), 32);
    #endif
    /* invalid case */
    ExpectIntEQ(wc_ecc_get_curve_size_from_name("BADCURVE"), -1);
    /* NULL input */
    ExpectIntEQ(wc_ecc_get_curve_size_from_name(NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif /* HAVE_ECC */
    return EXPECT_RESULT();
}

int test_wc_ecc_get_curve_id_from_name(void)
{
    EXPECT_DECLS;
#ifdef HAVE_ECC
    #if !defined(NO_ECC256) && !defined(NO_ECC_SECP)
        ExpectIntEQ(wc_ecc_get_curve_id_from_name("SECP256R1"),
            ECC_SECP256R1);
    #endif
    /* invalid case */
    ExpectIntEQ(wc_ecc_get_curve_id_from_name("BADCURVE"), -1);
    /* NULL input */
    ExpectIntEQ(wc_ecc_get_curve_id_from_name(NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif /* HAVE_ECC */
    return EXPECT_RESULT();
}

int test_wc_ecc_get_curve_id_from_params(void)
{
    EXPECT_DECLS;
#ifdef HAVE_ECC
    const byte prime[] =
    {
        0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x01,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
    };

    const byte primeInvalid[] =
    {
        0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x01,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x01,0x01
    };

    const byte Af[] =
    {
        0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x01,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFC
    };

    const byte Bf[] =
    {
        0x5A,0xC6,0x35,0xD8,0xAA,0x3A,0x93,0xE7,
        0xB3,0xEB,0xBD,0x55,0x76,0x98,0x86,0xBC,
        0x65,0x1D,0x06,0xB0,0xCC,0x53,0xB0,0xF6,
        0x3B,0xCE,0x3C,0x3E,0x27,0xD2,0x60,0x4B
    };

    const byte order[] =
    {
        0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xBC,0xE6,0xFA,0xAD,0xA7,0x17,0x9E,0x84,
        0xF3,0xB9,0xCA,0xC2,0xFC,0x63,0x25,0x51
    };

    const byte Gx[] =
    {
        0x6B,0x17,0xD1,0xF2,0xE1,0x2C,0x42,0x47,
        0xF8,0xBC,0xE6,0xE5,0x63,0xA4,0x40,0xF2,
        0x77,0x03,0x7D,0x81,0x2D,0xEB,0x33,0xA0,
        0xF4,0xA1,0x39,0x45,0xD8,0x98,0xC2,0x96
    };

    const byte Gy[] =
    {
        0x4F,0xE3,0x42,0xE2,0xFE,0x1A,0x7F,0x9B,
        0x8E,0xE7,0xEB,0x4A,0x7C,0x0F,0x9E,0x16,
        0x2B,0xCE,0x33,0x57,0x6B,0x31,0x5E,0xCE,
        0xCB,0xB6,0x40,0x68,0x37,0xBF,0x51,0xF5
    };

    int cofactor = 1;
    int fieldSize = 256;

    #if !defined(NO_ECC256) && !defined(NO_ECC_SECP)
        ExpectIntEQ(wc_ecc_get_curve_id_from_params(fieldSize,
            prime, sizeof(prime), Af, sizeof(Af), Bf, sizeof(Bf),
            order, sizeof(order), Gx, sizeof(Gx), Gy, sizeof(Gy), cofactor),
            ECC_SECP256R1);
    #endif

    /* invalid case, fieldSize = 0 */
    ExpectIntEQ(wc_ecc_get_curve_id_from_params(0, prime, sizeof(prime),
        Af, sizeof(Af), Bf, sizeof(Bf), order, sizeof(order),
        Gx, sizeof(Gx), Gy, sizeof(Gy), cofactor), ECC_CURVE_INVALID);

    /* invalid case, NULL prime */
    ExpectIntEQ(wc_ecc_get_curve_id_from_params(fieldSize, NULL, sizeof(prime),
        Af, sizeof(Af), Bf, sizeof(Bf), order, sizeof(order),
        Gx, sizeof(Gx), Gy, sizeof(Gy), cofactor),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* invalid case, invalid prime */
    ExpectIntEQ(wc_ecc_get_curve_id_from_params(fieldSize,
        primeInvalid, sizeof(primeInvalid),
        Af, sizeof(Af), Bf, sizeof(Bf), order, sizeof(order),
        Gx, sizeof(Gx), Gy, sizeof(Gy), cofactor), ECC_CURVE_INVALID);
#endif
    return EXPECT_RESULT();
}

int test_wc_ecc_get_curve_id_from_dp_params(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_ECC) && \
    !defined(HAVE_SELFTEST) && \
    !(defined(HAVE_FIPS) || defined(HAVE_FIPS_VERSION))
#if !defined(NO_ECC256) && !defined(NO_ECC_SECP)
    ecc_key* key;
    const ecc_set_type* params = NULL;
    int ret;
#endif
    WOLFSSL_EC_KEY *ecKey = NULL;

    #if !defined(NO_ECC256) && !defined(NO_ECC_SECP)
        ExpectIntEQ(wc_ecc_get_curve_id_from_name("SECP256R1"), ECC_SECP256R1);
        ExpectNotNull(ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));

        if (EXPECT_SUCCESS()) {
            ret = EC_KEY_generate_key(ecKey);
        } else
            ret = 0;

        if (ret == 1) {
            /* normal test */
            key = (ecc_key*)ecKey->internal;
            if (key != NULL) {
                params = key->dp;
            }

            ExpectIntEQ(wc_ecc_get_curve_id_from_dp_params(params),
                ECC_SECP256R1);
        }
    #endif
    /* invalid case, NULL input */
    ExpectIntEQ(wc_ecc_get_curve_id_from_dp_params(NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wolfSSL_EC_KEY_free(ecKey);
#endif
    return EXPECT_RESULT();
}

/*
 * Testing wc_ecc_make_key.
 */
int test_wc_ecc_make_key(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && !defined(WC_NO_RNG)
    ecc_key key;
    WC_RNG  rng;
    int     ret;

    XMEMSET(&key, 0, sizeof(ecc_key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_ecc_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ret = wc_ecc_make_key(&rng, KEY14, &key);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    ExpectIntEQ(ret, 0);

    /* Pass in bad args. */
    ExpectIntEQ(wc_ecc_make_key(NULL, KEY14, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_make_key(&rng, KEY14, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ecc_free(&key);

#ifdef FP_ECC
    wc_ecc_fp_free();
#endif
#endif
    return EXPECT_RESULT();
} /* END test_wc_ecc_make_key */


/*
 * Testing wc_ecc_init()
 */
int test_wc_ecc_init(void)
{
    EXPECT_DECLS;
#ifdef HAVE_ECC
    ecc_key key;

    XMEMSET(&key, 0, sizeof(ecc_key));

    ExpectIntEQ(wc_ecc_init(&key), 0);
    /* Pass in bad args. */
    ExpectIntEQ(wc_ecc_init(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_ecc_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ecc_init */

/*
 * Testing wc_ecc_check_key()
 */
int test_wc_ecc_check_key(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && !defined(WC_NO_RNG)
    ecc_key key;
    WC_RNG  rng;
    int     ret;

    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&key, 0, sizeof(key));

    ExpectIntEQ(wc_ecc_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ret = wc_ecc_make_key(&rng, KEY14, &key);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    ExpectIntEQ(ret, 0);

    ExpectIntEQ(wc_ecc_check_key(&key), 0);

    /* Pass in bad args. */
    ExpectIntEQ(wc_ecc_check_key(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ecc_free(&key);

#ifdef FP_ECC
    wc_ecc_fp_free();
#endif
#endif
    return EXPECT_RESULT();
} /* END test_wc_ecc_check_key */

/*
 * Testing wc_ecc_get_generator()
 */
int test_wc_ecc_get_generator(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && !defined(WC_NO_RNG) && !defined(HAVE_SELFTEST) && \
    !defined(HAVE_FIPS) && defined(OPENSSL_EXTRA)
    ecc_point* pt = NULL;

    ExpectNotNull(pt = wc_ecc_new_point());

    ExpectIntEQ(wc_ecc_get_generator(pt, wc_ecc_get_curve_idx(ECC_SECP256R1)),
        MP_OKAY);

    /* Test bad args. */
    /* Returns Zero for bad arg. */
    ExpectIntNE(wc_ecc_get_generator(pt, -1), MP_OKAY);
    ExpectIntNE(wc_ecc_get_generator(NULL, wc_ecc_get_curve_idx(ECC_SECP256R1)),
        MP_OKAY);
    /* If we ever get to 1000 curves increase this number */
    ExpectIntNE(wc_ecc_get_generator(pt, 1000), MP_OKAY);
    ExpectIntNE(wc_ecc_get_generator(NULL, -1), MP_OKAY);

    wc_ecc_del_point(pt);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ecc_get_generator */

/*
 * Testing wc_ecc_size()
 */
int test_wc_ecc_size(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && !defined(WC_NO_RNG)
    WC_RNG      rng;
    ecc_key     key;
    int         ret;

    XMEMSET(&key, 0, sizeof(ecc_key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_ecc_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ret = wc_ecc_make_key(&rng, KEY14, &key);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    ExpectIntEQ(ret, 0);

    ExpectIntEQ(wc_ecc_size(&key), KEY14);
    /* Test bad args. */
    /* Returns Zero for bad arg. */
    ExpectIntEQ(wc_ecc_size(NULL), 0);

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ecc_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ecc_size */

int test_wc_ecc_params(void)
{
    EXPECT_DECLS;
    /* FIPS/CAVP self-test modules do not have `wc_ecc_get_curve_params`.
        It was added after certifications */
#if defined(HAVE_ECC) && !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
    const ecc_set_type* ecc_set = NULL;
#if !defined(NO_ECC256) && !defined(NO_ECC_SECP)
    /* Test for SECP256R1 curve */
    int curve_id = ECC_SECP256R1;
    int curve_idx = 0;

    ExpectIntNE(curve_idx = wc_ecc_get_curve_idx(curve_id), ECC_CURVE_INVALID);
    ExpectNotNull(ecc_set = wc_ecc_get_curve_params(curve_idx));
    ExpectIntEQ(ecc_set->id, curve_id);
#endif
    /* Test case when SECP256R1 is not enabled */
    /* Test that we get curve params for index 0 */
    ExpectNotNull(ecc_set = wc_ecc_get_curve_params(0));
#endif /* HAVE_ECC && !HAVE_FIPS && !HAVE_SELFTEST */
    return EXPECT_RESULT();
}

/*
 * Testing wc_ecc_sign_hash() and wc_ecc_verify_hash()
 */
int test_wc_ecc_signVerify_hash(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && defined(HAVE_ECC_SIGN) && !defined(NO_ASN) && \
    !defined(WC_NO_RNG)
    ecc_key key;
    WC_RNG  rng;
    int     ret;
#ifdef HAVE_ECC_VERIFY
    int     verify = 0;
#endif
    word32  siglen = ECC_BUFSIZE;
    byte    sig[ECC_BUFSIZE];
    byte    adjustedSig[ECC_BUFSIZE+1];
    byte    digest[] = TEST_STRING;
    word32  digestlen = (word32)TEST_STRING_SZ;

    /* Init stack var */
    XMEMSET(&key, 0, sizeof(ecc_key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(sig, 0, siglen);
    XMEMSET(adjustedSig, 0, ECC_BUFSIZE+1);

    /* Init structs. */
    ExpectIntEQ(wc_ecc_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ret = wc_ecc_make_key(&rng, KEY14, &key);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    ExpectIntEQ(ret, 0);

    ExpectIntEQ(wc_ecc_sign_hash(digest, digestlen, sig, &siglen, &rng, &key),
        0);

    /* Check bad args. */
    ExpectIntEQ(wc_ecc_sign_hash(NULL, digestlen, sig, &siglen, &rng, &key),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_ecc_sign_hash(digest, digestlen, NULL, &siglen, &rng, &key),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_ecc_sign_hash(digest, digestlen, sig, NULL, &rng, &key),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_ecc_sign_hash(digest, digestlen, sig, &siglen, NULL, &key),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_ecc_sign_hash(digest, digestlen, sig, &siglen, &rng, NULL),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
#if (!defined(HAVE_FIPS) || FIPS_VERSION_GT(7,0)) && !defined(HAVE_SELFTEST)
    ExpectIntEQ(wc_ecc_sign_hash(digest, WC_MAX_DIGEST_SIZE+1, sig, &siglen,
        &rng, &key), WC_NO_ERR_TRACE(BAD_LENGTH_E));
#endif

#ifdef HAVE_ECC_VERIFY
    ExpectIntEQ(wc_ecc_verify_hash(sig, siglen, digest, digestlen, &verify,
        &key), 0);
    ExpectIntEQ(verify, 1);

    /* test check on length of signature passed in */
    XMEMCPY(adjustedSig, sig, siglen);
    adjustedSig[1] = adjustedSig[1] + 1; /* add 1 to length for extra byte */
#ifndef NO_STRICT_ECDSA_LEN
    ExpectIntNE(wc_ecc_verify_hash(adjustedSig, siglen+1, digest, digestlen,
        &verify, &key), 0);
#else
    /* if NO_STRICT_ECDSA_LEN is set then extra bytes after the signature
     * is allowed */
    ExpectIntEQ(wc_ecc_verify_hash(adjustedSig, siglen+1, digest, digestlen,
        &verify, &key), 0);
#endif

    /* Test bad args. */
    ExpectIntEQ(wc_ecc_verify_hash(NULL, siglen, digest, digestlen, &verify,
        &key), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_ecc_verify_hash(sig, siglen, NULL, digestlen, &verify, &key),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_ecc_verify_hash(sig, siglen, digest, digestlen, NULL, &key),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_ecc_verify_hash(sig, siglen, digest, digestlen, &verify,
        NULL), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
#if (!defined(HAVE_FIPS) || FIPS_VERSION_GT(7,0)) && !defined(HAVE_SELFTEST)
    ExpectIntEQ(wc_ecc_verify_hash(sig, siglen, digest, WC_MAX_DIGEST_SIZE+1,
        &verify, &key), WC_NO_ERR_TRACE(BAD_LENGTH_E));
#endif
#endif /* HAVE_ECC_VERIFY */

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ecc_free(&key);

#ifdef FP_ECC
    wc_ecc_fp_free();
#endif
#endif
    return EXPECT_RESULT();
} /*  END test_wc_ecc_sign_hash */

/*
 * Testing wc_ecc_shared_secret()
 */
int test_wc_ecc_shared_secret(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && defined(HAVE_ECC_DHE) && !defined(WC_NO_RNG)
    ecc_key     key;
    ecc_key     pubKey;
    WC_RNG      rng;
#if defined(NO_ECC256)
    int         ret;
#endif
    byte        out[KEY32];
    int         keySz = sizeof(out);
    word32      outlen = (word32)sizeof(out);

#if defined(HAVE_ECC) && !defined(NO_ECC256)
    const char* qx =
        "bb33ac4c27504ac64aa504c33cde9f36db722dce94ea2bfacb2009392c16e861";
    const char* qy =
        "02e9af4dd302939a315b9792217ff0cf18da9111023486e82058330b803489d8";
    const char* d  =
        "45b66902739c6c85a1385b72e8e8c7acc4038d533504fa6c28dc348de1a8098c";
    const char* curveName = "SECP256R1";
    const byte expected_shared_secret[] =
        {
            0x65, 0xc0, 0xd4, 0x61, 0x17, 0xe6, 0x09, 0x75,
            0xf0, 0x12, 0xa0, 0x4d, 0x0b, 0x41, 0x30, 0x7a,
            0x51, 0xf0, 0xb3, 0xaf, 0x23, 0x8f, 0x0f, 0xdf,
            0xf1, 0xff, 0x23, 0x64, 0x28, 0xca, 0xf8, 0x06
        };
#endif

    PRIVATE_KEY_UNLOCK();

    /* Initialize variables. */
    XMEMSET(&key, 0, sizeof(ecc_key));
    XMEMSET(&pubKey, 0, sizeof(ecc_key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(out, 0, keySz);

    ExpectIntEQ(wc_ecc_init(&key), 0);
    ExpectIntEQ(wc_ecc_init(&pubKey), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);

#if !defined(NO_ECC256)
    ExpectIntEQ(wc_ecc_import_raw(&key, qx, qy, d, curveName), 0);
    ExpectIntEQ(wc_ecc_import_raw(&pubKey, qx, qy, NULL, curveName), 0);
#else
    ret = wc_ecc_make_key(&rng, keySz, &key);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    ExpectIntEQ(ret, 0);
    ret = wc_ecc_make_key(&rng, keySz, &key);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    ExpectIntEQ(ret, 0);
#endif

#if defined(ECC_TIMING_RESISTANT) && (!defined(HAVE_FIPS) || \
    (!defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION != 2))) && \
    !defined(HAVE_SELFTEST)
    ExpectIntEQ(wc_ecc_set_rng(&key, &rng), 0);
#endif

    ExpectIntEQ(wc_ecc_shared_secret(&key, &pubKey, out, &outlen), 0);

#if !defined(NO_ECC256)
    ExpectIntEQ(XMEMCMP(out, expected_shared_secret, outlen), 0);
#endif

    /* Test bad args. */
    ExpectIntEQ(wc_ecc_shared_secret(NULL, &pubKey, out, &outlen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_shared_secret(&key, NULL, out, &outlen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_shared_secret(&key, &pubKey, NULL, &outlen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_shared_secret(&key, &pubKey, out, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Invalid length */
    outlen = 1;
    ExpectIntEQ(wc_ecc_shared_secret(&key, &pubKey, out, &outlen),
        WC_NO_ERR_TRACE(BUFFER_E));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ecc_free(&pubKey);
    wc_ecc_free(&key);

#ifdef FP_ECC
    wc_ecc_fp_free();
#endif

    PRIVATE_KEY_LOCK();
#endif
    return EXPECT_RESULT();
} /* END tests_wc_ecc_shared_secret */

/*
 * A shared secret that computes to the point at infinity must be rejected
 * (SP 800-56Ar3 5.7.1.2), not returned as an all-zero secret. Setting the
 * private scalar to the curve order makes k times the peer point the identity
 * for any peer point. Uses secp224r1, which is not single precision
 * accelerated, so the non-SP ECDH path runs even in SP builds that offload
 * P-256.
 */
int test_wc_ecc_shared_secret_at_infinity(void)
{
    EXPECT_DECLS;
    /* ECC_INF_E rejection is not present in the frozen ecc.c of older
     * FIPS-certified modules, so restrict to non-FIPS or FIPS v7 and later,
     * and skip the CAVP selftest build. */
#if (!defined(HAVE_FIPS) || FIPS_VERSION3_GE(7,0,0)) && \
    !defined(HAVE_SELFTEST) && \
    defined(HAVE_ECC) && defined(HAVE_ECC_DHE) && !defined(WC_NO_RNG) && \
    (defined(HAVE_ECC224) || defined(HAVE_ALL_CURVES)) && \
    (ECC_MIN_KEY_SZ <= 224) && \
    !defined(WOLFSSL_SP_MATH) && !defined(WOLFSSL_VALIDATE_ECC_IMPORT) && \
    !defined(WOLFSSL_ATECC508A) && !defined(WOLFSSL_ATECC608A) && \
    !defined(WOLFSSL_CRYPTOCELL) && !defined(WOLFSSL_SE050) && \
    !defined(WOLFSSL_KCAPI_ECC) && !defined(WOLF_CRYPTO_CB_ONLY_ECC)
    ecc_key key;
    ecc_key pubKey;
    WC_RNG  rng;
    byte    out[MAX_ECC_BYTES];
    word32  outlen = (word32)sizeof(out);
    /* A valid SECP224R1 public point. */
    const char* qx =
        "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21";
    const char* qy =
        "bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34";
    /* Order n of SECP224R1. Every valid point has order n on this curve, so
     * a private scalar equal to n makes n times the peer point the identity. */
    const char* order =
        "ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d";

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&pubKey, 0, sizeof(pubKey));
    XMEMSET(&rng, 0, sizeof(rng));

    PRIVATE_KEY_UNLOCK();

    ExpectIntEQ(wc_ecc_init(&key), 0);
    ExpectIntEQ(wc_ecc_init(&pubKey), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);

    ExpectIntEQ(wc_ecc_import_raw(&key, qx, qy, order, "SECP224R1"), 0);
    ExpectIntEQ(wc_ecc_import_raw(&pubKey, qx, qy, NULL, "SECP224R1"), 0);

#if defined(ECC_TIMING_RESISTANT) && (!defined(HAVE_FIPS) || \
    (!defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION != 2))) && \
    !defined(HAVE_SELFTEST)
    ExpectIntEQ(wc_ecc_set_rng(&key, &rng), 0);
#endif

    ExpectIntEQ(wc_ecc_shared_secret(&key, &pubKey, out, &outlen),
        WC_NO_ERR_TRACE(ECC_INF_E));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ecc_free(&pubKey);
    wc_ecc_free(&key);
#ifdef FP_ECC
    wc_ecc_fp_free();
#endif
    PRIVATE_KEY_LOCK();
#endif
    return EXPECT_RESULT();
} /* END test_wc_ecc_shared_secret_at_infinity */

#if defined(HAVE_ECC) && defined(HAVE_ECC_DHE) && !defined(WC_NO_RNG) && \
    (defined(HAVE_ECC384) || defined(HAVE_ECC521) || \
     defined(HAVE_ALL_CURVES)) && \
    (!defined(WOLFSSL_SP_521) || \
     ((!defined(HAVE_FIPS) || FIPS_VERSION_GT(7,0)) && !defined(HAVE_SELFTEST)))
/* Verify the output-buffer size contract of wc_ecc_shared_secret() at the
 * field-size boundary. The single-precision (SP) math secret generators for
 * P-384/P-521 historically validated the caller's buffer against the wrong
 * length (e.g. P-521 checked 65 but writes 66), so a buffer declared one byte
 * short of the field size slipped past the check and was overwritten. Assert
 * that fieldSz-1 is rejected with BUFFER_E and fieldSz succeeds, for whichever
 * math backend is built.
 *
 * Coverage note: this drives the blocking generators only (wc_ecc_shared_secret
 * is synchronous). The fix also corrected the non-blocking (_nb) variants
 * (sp_ecc_secret_gen_384_nb / _521_nb), which need WOLFSSL_SP_NONBLOCK plus the
 * specialized SP build and are not exercised here. Of the blocking cases only
 * P-521 (65->66) actually fails without the fix; P-384 already used 48, so its
 * case is a guard against regression rather than a reproduction. */
static int ecc_shared_secret_size_bound(WC_RNG* rng, int curveId, int fieldSz)
{
    EXPECT_DECLS;
    ecc_key key;
    ecc_key pub;
    byte    out[80]; /* >= P-521 field size (66) */
    word32  outlen;
    int     keyInit = 0, pubInit = 0;
    int     ret;

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&pub, 0, sizeof(pub));

    ExpectIntEQ(wc_ecc_init(&key), 0);
    if (EXPECT_SUCCESS()) keyInit = 1;
    ExpectIntEQ(wc_ecc_init(&pub), 0);
    if (EXPECT_SUCCESS()) pubInit = 1;

    ret = wc_ecc_make_key_ex(rng, fieldSz, &key, curveId);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    ExpectIntEQ(ret, 0);

    ret = wc_ecc_make_key_ex(rng, fieldSz, &pub, curveId);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &pub.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    ExpectIntEQ(ret, 0);

#if defined(ECC_TIMING_RESISTANT) && (!defined(HAVE_FIPS) || \
    (!defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION != 2))) && \
    !defined(HAVE_SELFTEST)
    ExpectIntEQ(wc_ecc_set_rng(&key, rng), 0);
#endif

    /* One byte short of the field size: must be rejected, not written past. */
    outlen = (word32)(fieldSz - 1);
    ExpectIntEQ(wc_ecc_shared_secret(&key, &pub, out, &outlen),
        WC_NO_ERR_TRACE(BUFFER_E));

    /* Exactly the field size: must succeed and report the field size. */
    outlen = (word32)fieldSz;
    ExpectIntEQ(wc_ecc_shared_secret(&key, &pub, out, &outlen), 0);
    ExpectIntEQ(outlen, (word32)fieldSz);

    if (pubInit)
        wc_ecc_free(&pub);
    if (keyInit)
        wc_ecc_free(&key);
    return EXPECT_RESULT();
}
#endif

/*
 * Testing wc_ecc_shared_secret() output buffer bounds at the field-size edge.
 */
int test_wc_ecc_shared_secret_size_bounds(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && defined(HAVE_ECC_DHE) && !defined(WC_NO_RNG) && \
    (defined(HAVE_ECC384) || defined(HAVE_ECC521) || \
     defined(HAVE_ALL_CURVES)) && \
    (!defined(WOLFSSL_SP_521) || \
     ((!defined(HAVE_FIPS) || FIPS_VERSION_GT(7,0)) && !defined(HAVE_SELFTEST)))
    WC_RNG rng;
    int    rngInit = 0;

    XMEMSET(&rng, 0, sizeof(rng));
    PRIVATE_KEY_UNLOCK();
    ExpectIntEQ(wc_InitRng(&rng), 0);
    if (EXPECT_SUCCESS())
        rngInit = 1;

#if defined(HAVE_ECC384) || defined(HAVE_ALL_CURVES)
    ExpectIntEQ(ecc_shared_secret_size_bound(&rng, ECC_SECP384R1, 48), 1);
#endif
#if defined(HAVE_ECC521) || defined(HAVE_ALL_CURVES)
    ExpectIntEQ(ecc_shared_secret_size_bound(&rng, ECC_SECP521R1, 66), 1);
#endif

    if (rngInit)
        DoExpectIntEQ(wc_FreeRng(&rng), 0);
#ifdef FP_ECC
    wc_ecc_fp_free();
#endif
    PRIVATE_KEY_LOCK();
#endif
    return EXPECT_RESULT();
}

/*
 * testint wc_ecc_export_x963()
 */
int test_wc_ecc_export_x963(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_EXPORT) && !defined(WC_NO_RNG)
    ecc_key key;
    WC_RNG  rng;
    byte    out[ECC_ASN963_MAX_BUF_SZ];
    word32  outlen = sizeof(out);
    int     ret;

    PRIVATE_KEY_UNLOCK();

    /* Initialize variables. */
    XMEMSET(&key, 0, sizeof(ecc_key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(out, 0, outlen);

    ExpectIntEQ(wc_ecc_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ret = wc_ecc_make_key(&rng, KEY20, &key);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    ExpectIntEQ(ret, 0);

    ExpectIntEQ(wc_ecc_export_x963(&key, out, &outlen), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_ecc_export_x963(NULL, out, &outlen),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_ecc_export_x963(&key, NULL, &outlen),
        WC_NO_ERR_TRACE(LENGTH_ONLY_E));
    ExpectIntEQ(wc_ecc_export_x963(&key, out, NULL),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    key.idx = -4;
    ExpectIntEQ(wc_ecc_export_x963(&key, out, &outlen),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ecc_free(&key);

#ifdef FP_ECC
    wc_ecc_fp_free();
#endif

    PRIVATE_KEY_LOCK();
#endif
    return EXPECT_RESULT();
} /* END test_wc_ecc_export_x963 */

/*
 * Testing wc_ecc_export_x963_ex()
 * compile with --enable-compkey will use compression.
 */
int test_wc_ecc_export_x963_ex(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_EXPORT) && !defined(WC_NO_RNG)
    ecc_key key;
    WC_RNG  rng;
    int     ret;
    byte    out[ECC_ASN963_MAX_BUF_SZ];
    word32  outlen = sizeof(out);
    #ifdef HAVE_COMP_KEY
        word32  badOutLen = 5;
    #endif

    /* Init stack variables. */
    XMEMSET(&key, 0, sizeof(ecc_key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(out, 0, outlen);
    PRIVATE_KEY_UNLOCK();

    ExpectIntEQ(wc_ecc_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ret = wc_ecc_make_key(&rng, KEY64, &key);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    ExpectIntEQ(ret, 0);

#ifdef HAVE_COMP_KEY
    ExpectIntEQ(wc_ecc_export_x963_ex(&key, out, &outlen, COMP), 0);
#else
    ExpectIntEQ(ret = wc_ecc_export_x963_ex(&key, out, &outlen, NOCOMP), 0);
#endif

    /* Test bad args. */
#ifdef HAVE_COMP_KEY
    ExpectIntEQ(wc_ecc_export_x963_ex(NULL, out, &outlen, COMP),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_export_x963_ex(&key, NULL, &outlen, COMP),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_export_x963_ex(&key, out, NULL, COMP),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#if (defined(HAVE_FIPS) && (!defined(FIPS_VERSION_LT) || FIPS_VERSION_LT(5,3)))\
    || defined(HAVE_SELFTEST)
    ExpectIntEQ(wc_ecc_export_x963_ex(&key, out, &badOutLen, COMP),
        WC_NO_ERR_TRACE(BUFFER_E));
#else
    ExpectIntEQ(wc_ecc_export_x963_ex(&key, out, &badOutLen, COMP),
        WC_NO_ERR_TRACE(LENGTH_ONLY_E));
#endif
    key.idx = -4;
    ExpectIntEQ(wc_ecc_export_x963_ex(&key, out, &outlen, COMP),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
#else
    ExpectIntEQ(wc_ecc_export_x963_ex(NULL, out, &outlen, NOCOMP),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_ecc_export_x963_ex(&key, NULL, &outlen, NOCOMP),
        WC_NO_ERR_TRACE(LENGTH_ONLY_E));
    ExpectIntEQ(wc_ecc_export_x963_ex(&key, out, &outlen, 1),
        WC_NO_ERR_TRACE(NOT_COMPILED_IN));
    ExpectIntEQ(wc_ecc_export_x963_ex(&key, out, NULL, NOCOMP),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    key.idx = -4;
    ExpectIntEQ(wc_ecc_export_x963_ex(&key, out, &outlen, NOCOMP),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
#endif
    PRIVATE_KEY_LOCK();

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ecc_free(&key);

#ifdef FP_ECC
    wc_ecc_fp_free();
#endif
#endif
    return EXPECT_RESULT();
} /* END test_wc_ecc_export_x963_ex */

/*
 * testing wc_ecc_import_x963()
 */
int test_wc_ecc_import_x963(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_IMPORT) && \
    defined(HAVE_ECC_KEY_EXPORT) && !defined(WC_NO_RNG)
    ecc_key pubKey;
    ecc_key key;
    WC_RNG  rng;
    byte    x963[ECC_ASN963_MAX_BUF_SZ];
    word32  x963Len = (word32)sizeof(x963);
    int     ret;

    /* Init stack variables. */
    XMEMSET(&key, 0, sizeof(ecc_key));
    XMEMSET(&pubKey, 0, sizeof(ecc_key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(x963, 0, x963Len);

    ExpectIntEQ(wc_ecc_init(&pubKey), 0);
    ExpectIntEQ(wc_ecc_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
#if FIPS_VERSION3_GE(6,0,0)
    ret = wc_ecc_make_key(&rng, KEY32, &key);
#else
    ret = wc_ecc_make_key(&rng, KEY24, &key);
#endif
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_NONE);
#endif

    ExpectIntEQ(ret, 0);

    PRIVATE_KEY_UNLOCK();
    ExpectIntEQ(wc_ecc_export_x963(&key, x963, &x963Len), 0);
    PRIVATE_KEY_LOCK();

    ExpectIntEQ(wc_ecc_import_x963(x963, x963Len, &pubKey), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_ecc_import_x963(NULL, x963Len, &pubKey),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_import_x963(x963, x963Len, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_import_x963(x963, x963Len + 1, &pubKey),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ecc_free(&key);
    wc_ecc_free(&pubKey);

#ifdef FP_ECC
    wc_ecc_fp_free();
#endif
#endif
    return EXPECT_RESULT();
} /* END wc_ecc_import_x963 */

/*
 * testing wc_ecc_import_x963() rejects an off-curve public point.
 *
 * Regression coverage for the invalid-curve attack: the legacy wrapper
 * wc_ecc_import_x963_ex (called by wc_ecc_import_x963()) must pass untrusted=1
 * to wc_ecc_import_x963_ex2 so that ECIES, PKCS#7 KARI, and EVP ECDH callers
 * validate that the imported point actually lies on the curve. Without that,
 * an attacker can feed a point from a weak twist and leak the victim's private
 * scalar modulo small primes (Biehl-Meyer-Mueller).
 */
int test_wc_ecc_import_x963_off_curve(void)
{
    EXPECT_DECLS;
/* point-on-curve validation inside wc_ecc_import_x963 is raw math stripped
 * by WOLF_CRYPTO_CB_ONLY_ECC; swdev cannot reach below the dispatch layer. */
#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_IMPORT) && \
    !defined(NO_ECC256) && !defined(NO_ECC_SECP) && \
    (!defined(HAVE_FIPS) || FIPS_VERSION_GE(7,0)) && !defined(HAVE_SELFTEST) && \
    !defined(WOLF_CRYPTO_CB_ONLY_ECC)
    ecc_key pubKey;
    /* Uncompressed X9.63 P-256 point: 0x04 || Gx || Gy with the last byte
     * of Gy flipped by 1. Gx/Gy are the NIST P-256 generator coordinates;
     * modifying a single bit of Gy produces a point that is not on the
     * curve, so wc_ecc_import_x963 must reject it. */
    static const byte offCurveX963[] = {
        0x04,
        0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47,
        0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
        0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
        0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96,
        0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B,
        0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
        0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE,
        0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF4
    };

    XMEMSET(&pubKey, 0, sizeof(ecc_key));

    ExpectIntEQ(wc_ecc_init(&pubKey), 0);

    /* Importing an off-curve point must fail. wc_ecc_import_x963() calls
     * wc_ecc_import_x963_ex() which ultimately calls wc_ecc_import_x963_ex2()
     * with the required untrusted=1 flag. */
    ExpectIntNE(wc_ecc_import_x963(offCurveX963, (word32)sizeof(offCurveX963),
                                   &pubKey), 0);

    wc_ecc_free(&pubKey);

#ifdef FP_ECC
    wc_ecc_fp_free();
#endif
#endif
    return EXPECT_RESULT();
} /* END test_wc_ecc_import_x963_off_curve */

/*
 * testing wc_ecc_import_private_key()
 */
int test_wc_ecc_import_private_key(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_IMPORT) && \
    defined(HAVE_ECC_KEY_EXPORT) && !defined(WC_NO_RNG)
    ecc_key key;
    ecc_key keyImp;
    WC_RNG  rng;
    byte    privKey[ECC_PRIV_KEY_BUF]; /* Raw private key.*/
    byte    x963Key[ECC_ASN963_MAX_BUF_SZ];
    word32  privKeySz = (word32)sizeof(privKey);
    word32  x963KeySz = (word32)sizeof(x963Key);
    int     ret;

    /* Init stack variables. */
    XMEMSET(&key, 0, sizeof(ecc_key));
    XMEMSET(&keyImp, 0, sizeof(ecc_key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(privKey, 0, privKeySz);
    XMEMSET(x963Key, 0, x963KeySz);
    PRIVATE_KEY_UNLOCK();

    ExpectIntEQ(wc_ecc_init(&key), 0);
    ExpectIntEQ(wc_ecc_init(&keyImp), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ret = wc_ecc_make_key(&rng, KEY48, &key);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    ExpectIntEQ(ret, 0);

    PRIVATE_KEY_UNLOCK();
    ExpectIntEQ(wc_ecc_export_x963(&key, x963Key, &x963KeySz), 0);
    PRIVATE_KEY_LOCK();
    ExpectIntEQ(wc_ecc_export_private_only(&key, privKey, &privKeySz), 0);

    ExpectIntEQ(wc_ecc_import_private_key(privKey, privKeySz, x963Key,
        x963KeySz, &keyImp), 0);
    /* Pass in bad args. */
    ExpectIntEQ(wc_ecc_import_private_key(privKey, privKeySz, x963Key,
        x963KeySz, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_import_private_key(NULL, privKeySz, x963Key, x963KeySz,
        &keyImp), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    PRIVATE_KEY_LOCK();

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ecc_free(&keyImp);
    wc_ecc_free(&key);

#ifdef FP_ECC
    wc_ecc_fp_free();
#endif
#endif
    return EXPECT_RESULT();
} /* END test_wc_ecc_import_private_key */

/*
 * Testing wc_ecc_export_private_only()
 */
int test_wc_ecc_export_private_only(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_EXPORT) && !defined(WC_NO_RNG)
    ecc_key key;
    WC_RNG  rng;
    byte    out[ECC_PRIV_KEY_BUF];
    word32  outlen = sizeof(out);
    int     ret;

    /* Init stack variables. */
    XMEMSET(&key, 0, sizeof(ecc_key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(out, 0, outlen);
    PRIVATE_KEY_UNLOCK();

    ExpectIntEQ(wc_ecc_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ret = wc_ecc_make_key(&rng, KEY32, &key);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    ExpectIntEQ(ret, 0);

    ExpectIntEQ(wc_ecc_export_private_only(&key, out, &outlen), 0);
    /* Pass in bad args. */
    ExpectIntEQ(wc_ecc_export_private_only(NULL, out, &outlen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_export_private_only(&key, NULL, &outlen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_export_private_only(&key, out, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    PRIVATE_KEY_LOCK();

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ecc_free(&key);

#ifdef FP_ECC
    wc_ecc_fp_free();
#endif
#endif
    return EXPECT_RESULT();
} /* END test_wc_ecc_export_private_only */

/*
 * Testing wc_ecc_rs_to_sig()
 */
int test_wc_ecc_rs_to_sig(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && !defined(NO_ASN)
    /* first [P-192,SHA-1] vector from FIPS 186-3 NIST vectors */
    const char* R = "6994d962bdd0d793ffddf855ec5bf2f91a9698b46258a63e";
    const char* S = "02ba6465a234903744ab02bc8521405b73cf5fc00e1a9f41";
    const char* zeroStr = "0";
    byte        sig[ECC_MAX_SIG_SIZE];
    word32      siglen = (word32)sizeof(sig);
    /* R and S max size is the order of curve. 2^192.*/
    int         keySz = KEY24;
    byte        r[KEY24];
    byte        s[KEY24];
    word32      rlen = (word32)sizeof(r);
    word32      slen = (word32)sizeof(s);
#if !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
    word32      zeroLen = 0;
#endif

    /* Init stack variables. */
    XMEMSET(sig, 0, ECC_MAX_SIG_SIZE);
    XMEMSET(r, 0, keySz);
    XMEMSET(s, 0, keySz);

    ExpectIntEQ(wc_ecc_rs_to_sig(R, S, sig, &siglen), 0);
    ExpectIntEQ(wc_ecc_sig_to_rs(sig, siglen, r, &rlen, s, &slen), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_ecc_rs_to_sig(NULL, S, sig, &siglen),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_ecc_rs_to_sig(R, NULL, sig, &siglen),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_ecc_rs_to_sig(R, S, sig, NULL),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_ecc_rs_to_sig(R, S, NULL, &siglen),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_ecc_rs_to_sig(R, zeroStr, sig, &siglen),
        WC_NO_ERR_TRACE(MP_ZERO_E));
    ExpectIntEQ(wc_ecc_rs_to_sig(zeroStr, S, sig, &siglen),
        WC_NO_ERR_TRACE(MP_ZERO_E));
    ExpectIntEQ(wc_ecc_sig_to_rs(NULL, siglen, r, &rlen, s, &slen),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_ecc_sig_to_rs(sig, siglen, NULL, &rlen, s, &slen),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_ecc_sig_to_rs(sig, siglen, r, NULL, s, &slen),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_ecc_sig_to_rs(sig, siglen, r, &rlen, NULL, &slen),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_ecc_sig_to_rs(sig, siglen, r, &rlen, s, NULL),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
#if !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
    ExpectIntEQ(wc_ecc_sig_to_rs(sig, siglen, r, &zeroLen, s, &slen),
        WC_NO_ERR_TRACE(BUFFER_E));
    ExpectIntEQ(wc_ecc_sig_to_rs(sig, siglen, r, &rlen, s, &zeroLen),
        WC_NO_ERR_TRACE(BUFFER_E));
#endif
#endif
    return EXPECT_RESULT();
} /* END test_wc_ecc_rs_to_sig */

int test_wc_ecc_import_raw(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && !defined(NO_ECC256)
    ecc_key     key;
    const char* qx =
        "bb33ac4c27504ac64aa504c33cde9f36db722dce94ea2bfacb2009392c16e861";
    const char* qy =
        "02e9af4dd302939a315b9792217ff0cf18da9111023486e82058330b803489d8";
    const char* d  =
        "45b66902739c6c85a1385b72e8e8c7acc4038d533504fa6c28dc348de1a8098c";
    const char* curveName = "SECP256R1";
#ifdef WOLFSSL_VALIDATE_ECC_IMPORT
    const char* kNullStr = "";
    int ret;
#endif

    XMEMSET(&key, 0, sizeof(ecc_key));

    ExpectIntEQ(wc_ecc_init(&key), 0);

    /* Test good import */
    ExpectIntEQ(wc_ecc_import_raw(&key, qx, qy, d, curveName), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_ecc_import_raw(NULL, qx, qy, d, curveName),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_import_raw(&key, NULL, qy, d, curveName),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_import_raw(&key, qx, NULL, d, curveName),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_import_raw(&key, qx, qy, d, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifdef WOLFSSL_VALIDATE_ECC_IMPORT
    #if !defined(USE_FAST_MATH) && !defined(WOLFSSL_SP_MATH)
        wc_ecc_free(&key);
    #endif
    ExpectIntLT(ret = wc_ecc_import_raw(&key, kNullStr, kNullStr, kNullStr,
        curveName), 0);
    ExpectTrue((ret == WC_NO_ERR_TRACE(ECC_INF_E)) ||
               (ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG)));
#endif
#if !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
    #if !defined(USE_FAST_MATH) && !defined(WOLFSSL_SP_MATH)
        wc_ecc_free(&key);
    #endif
#ifdef WOLFSSL_VALIDATE_ECC_IMPORT
    ExpectIntLT(ret = wc_ecc_import_raw(&key, "0", qy, d, curveName), 0);
    ExpectTrue((ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG)) ||
               (ret == WC_NO_ERR_TRACE(MP_VAL)));
#else
    ExpectIntEQ(wc_ecc_import_raw(&key, "0", qy, d, curveName), 0);
#endif
    #if !defined(USE_FAST_MATH) && !defined(WOLFSSL_SP_MATH)
        wc_ecc_free(&key);
    #endif
#ifdef WOLFSSL_VALIDATE_ECC_IMPORT
    ExpectIntLT(ret = wc_ecc_import_raw(&key, qx, "0", d, curveName), 0);
    ExpectTrue((ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG)) ||
               (ret == WC_NO_ERR_TRACE(MP_VAL)));
#else
    ExpectIntEQ(wc_ecc_import_raw(&key, qx, "0", d, curveName), 0);
#endif
    #if !defined(USE_FAST_MATH) && !defined(WOLFSSL_SP_MATH)
        wc_ecc_free(&key);
    #endif
    ExpectIntEQ(wc_ecc_import_raw(&key, "0", "0", d, curveName),
        WC_NO_ERR_TRACE(ECC_INF_E));
#endif

    wc_ecc_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ecc_import_raw */

int test_wc_ecc_import_unsigned(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && !defined(NO_ECC256) && !defined(HAVE_SELFTEST) && \
    (!defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && \
     HAVE_FIPS_VERSION >= 2))
    ecc_key    key;
    const byte qx[] = {
        0xbb, 0x33, 0xac, 0x4c, 0x27, 0x50, 0x4a, 0xc6,
        0x4a, 0xa5, 0x04, 0xc3, 0x3c, 0xde, 0x9f, 0x36,
        0xdb, 0x72, 0x2d, 0xce, 0x94, 0xea, 0x2b, 0xfa,
        0xcb, 0x20, 0x09, 0x39, 0x2c, 0x16, 0xe8, 0x61
    };
    const byte qy[] = {
        0x02, 0xe9, 0xaf, 0x4d, 0xd3, 0x02, 0x93, 0x9a,
        0x31, 0x5b, 0x97, 0x92, 0x21, 0x7f, 0xf0, 0xcf,
        0x18, 0xda, 0x91, 0x11, 0x02, 0x34, 0x86, 0xe8,
        0x20, 0x58, 0x33, 0x0b, 0x80, 0x34, 0x89, 0xd8
    };
    const byte d[] = {
        0x45, 0xb6, 0x69, 0x02, 0x73, 0x9c, 0x6c, 0x85,
        0xa1, 0x38, 0x5b, 0x72, 0xe8, 0xe8, 0xc7, 0xac,
        0xc4, 0x03, 0x8d, 0x53, 0x35, 0x04, 0xfa, 0x6c,
        0x28, 0xdc, 0x34, 0x8d, 0xe1, 0xa8, 0x09, 0x8c
    };
#ifdef WOLFSSL_VALIDATE_ECC_IMPORT
    const byte nullBytes[32] = {0};
    int ret;
#endif
    int        curveId = ECC_SECP256R1;

    XMEMSET(&key, 0, sizeof(ecc_key));

    ExpectIntEQ(wc_ecc_init(&key), 0);

    ExpectIntEQ(wc_ecc_import_unsigned(&key, (byte*)qx, (byte*)qy, (byte*)d,
        curveId), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_ecc_import_unsigned(NULL, (byte*)qx, (byte*)qy, (byte*)d,
        curveId), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_import_unsigned(&key, NULL, (byte*)qy, (byte*)d,
        curveId), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_import_unsigned(&key, (byte*)qx, NULL, (byte*)d,
        curveId), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_import_unsigned(&key, (byte*)qx, (byte*)qy, (byte*)d,
        ECC_CURVE_INVALID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifdef WOLFSSL_VALIDATE_ECC_IMPORT
    ExpectIntLT(ret = wc_ecc_import_unsigned(&key, (byte*)nullBytes,
        (byte*)nullBytes, (byte*)nullBytes, curveId), 0);
    ExpectTrue((ret == WC_NO_ERR_TRACE(ECC_INF_E)) ||
               (ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG)));
#endif

    wc_ecc_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ecc_import_unsigned */

/*
 * Testing wc_ecc_sig_size()
 */
int test_wc_ecc_sig_size(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && !defined(WC_NO_RNG)
    ecc_key key;
    WC_RNG  rng;
    int     keySz = KEY16;
    int     ret;

    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&key, 0, sizeof(key));

    ExpectIntEQ(wc_ecc_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ret = wc_ecc_make_key(&rng, keySz, &key);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    ExpectIntEQ(ret, 0);

    ExpectIntLE(wc_ecc_sig_size(&key),
         (2 * keySz + SIG_HEADER_SZ + ECC_MAX_PAD_SZ));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ecc_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ecc_sig_size */

/*
 * Testing wc_ecc_ctx_new()
 */
int test_wc_ecc_ctx_new(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && defined(HAVE_ECC_ENCRYPT) && !defined(WC_NO_RNG)
    WC_RNG    rng;
    ecEncCtx* cli = NULL;
    ecEncCtx* srv = NULL;

    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectNotNull(cli = wc_ecc_ctx_new(REQ_RESP_CLIENT, &rng));
    ExpectNotNull(srv = wc_ecc_ctx_new(REQ_RESP_SERVER, &rng));
    wc_ecc_ctx_free(cli);
    cli = NULL;
    wc_ecc_ctx_free(srv);

    /* Test bad args. */
    /* wc_ecc_ctx_new_ex() will free if returned NULL. */
    ExpectNull(cli = wc_ecc_ctx_new(0, &rng));
    ExpectNull(cli = wc_ecc_ctx_new(REQ_RESP_CLIENT, NULL));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ecc_ctx_free(cli);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ecc_ctx_new */

/*
 * Tesing wc_ecc_reset()
 */
int test_wc_ecc_ctx_reset(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && defined(HAVE_ECC_ENCRYPT) && !defined(WC_NO_RNG)
    ecEncCtx* ctx = NULL;
    WC_RNG    rng;

    XMEMSET(&rng, 0, sizeof(rng));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectNotNull(ctx = wc_ecc_ctx_new(REQ_RESP_CLIENT, &rng));

    ExpectIntEQ(wc_ecc_ctx_reset(ctx, &rng), 0);

    /* Pass in bad args. */
    ExpectIntEQ(wc_ecc_ctx_reset(NULL, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_ctx_reset(ctx, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_ecc_ctx_free(ctx);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ecc_ctx_reset */

/*
 * Testing wc_ecc_ctx_set_peer_salt() and wc_ecc_ctx_get_own_salt()
 */
int test_wc_ecc_ctx_set_peer_salt(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && defined(HAVE_ECC_ENCRYPT) && !defined(WC_NO_RNG)
    WC_RNG      rng;
    ecEncCtx*   cliCtx      = NULL;
    ecEncCtx*   servCtx     = NULL;
    const byte* cliSalt     = NULL;
    const byte* servSalt    = NULL;

    XMEMSET(&rng, 0, sizeof(rng));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectNotNull(cliCtx = wc_ecc_ctx_new(REQ_RESP_CLIENT, &rng));
    ExpectNotNull(servCtx = wc_ecc_ctx_new(REQ_RESP_SERVER, &rng));

    /* Test bad args. */
    ExpectNull(cliSalt = wc_ecc_ctx_get_own_salt(NULL));

    ExpectNotNull(cliSalt = wc_ecc_ctx_get_own_salt(cliCtx));
    ExpectNotNull(servSalt = wc_ecc_ctx_get_own_salt(servCtx));

    ExpectIntEQ(wc_ecc_ctx_set_peer_salt(cliCtx, servSalt), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_ecc_ctx_set_peer_salt(NULL, servSalt),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_ctx_set_peer_salt(cliCtx, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_ecc_ctx_free(cliCtx);
    wc_ecc_ctx_free(servCtx);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();

} /* END test_wc_ecc_ctx_set_peer_salt */

/*
 * Testing wc_ecc_ctx_set_info()
 */
int test_wc_ecc_ctx_set_info(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && defined(HAVE_ECC_ENCRYPT) && !defined(WC_NO_RNG)
    ecEncCtx*   ctx = NULL;
    WC_RNG      rng;
    const char* optInfo = "Optional Test Info.";
    int         optInfoSz = (int)XSTRLEN(optInfo);
    const char* badOptInfo = NULL;

    XMEMSET(&rng, 0, sizeof(rng));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectNotNull(ctx = wc_ecc_ctx_new(REQ_RESP_CLIENT, &rng));

    ExpectIntEQ(wc_ecc_ctx_set_info(ctx, (byte*)optInfo, optInfoSz), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_ecc_ctx_set_info(NULL, (byte*)optInfo, optInfoSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_ctx_set_info(ctx, (byte*)badOptInfo, optInfoSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_ctx_set_info(ctx, (byte*)optInfo, -1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_ecc_ctx_free(ctx);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ecc_ctx_set_info */

/*
 * Testing wc_ecc_encrypt() and wc_ecc_decrypt()
 */
int test_wc_ecc_encryptDecrypt(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && defined(HAVE_ECC_ENCRYPT) && !defined(WC_NO_RNG) && \
    defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_128)
    ecc_key     srvKey;
    ecc_key     cliKey;
    ecc_key     tmpKey;
    WC_RNG      rng;
    int         ret;
    const char* msg   = "EccBlock Size 16";
    word32      msgSz = (word32)XSTRLEN("EccBlock Size 16");
#ifdef WOLFSSL_ECIES_OLD
    byte        out[(sizeof("EccBlock Size 16") - 1) + WC_SHA256_DIGEST_SIZE];
#elif defined(WOLFSSL_ECIES_GEN_IV)
    byte        out[KEY20 * 2 + 1 + AES_BLOCK_SIZE +
                    (sizeof("EccBlock Size 16") - 1) + WC_SHA256_DIGEST_SIZE];
#else
    byte        out[KEY20 * 2 + 1 + (sizeof("EccBlock Size 16") - 1) +
                    WC_SHA256_DIGEST_SIZE];
#endif
    word32      outSz = (word32)sizeof(out);
    byte        plain[sizeof("EccBlock Size 16")];
    word32      plainSz = (word32)sizeof(plain);
    int         keySz = KEY20;

    /* Init stack variables. */
    XMEMSET(out, 0, outSz);
    XMEMSET(plain, 0, plainSz);
    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&srvKey, 0, sizeof(ecc_key));
    XMEMSET(&cliKey, 0, sizeof(ecc_key));
    XMEMSET(&tmpKey, 0, sizeof(ecc_key));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ecc_init(&cliKey), 0);
    ret = wc_ecc_make_key(&rng, keySz, &cliKey);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &cliKey.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    ExpectIntEQ(ret, 0);

    ExpectIntEQ(wc_ecc_init(&srvKey), 0);
    ret = wc_ecc_make_key(&rng, keySz, &srvKey);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &srvKey.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    ExpectIntEQ(ret, 0);

    ExpectIntEQ(wc_ecc_init(&tmpKey), 0);

#if defined(ECC_TIMING_RESISTANT) && (!defined(HAVE_FIPS) || \
    (!defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION != 2))) && \
    !defined(HAVE_SELFTEST)
    ExpectIntEQ(wc_ecc_set_rng(&srvKey, &rng), 0);
    ExpectIntEQ(wc_ecc_set_rng(&cliKey, &rng), 0);
#endif

    ExpectIntEQ(wc_ecc_encrypt(&cliKey, &srvKey, (byte*)msg, msgSz, out,
        &outSz, NULL), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_ecc_encrypt(NULL, &srvKey, (byte*)msg, msgSz, out, &outSz,
        NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_encrypt(&cliKey, NULL, (byte*)msg, msgSz, out, &outSz,
        NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_encrypt(&cliKey, &srvKey, NULL, msgSz, out, &outSz,
        NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_encrypt(&cliKey, &srvKey, (byte*)msg, msgSz, NULL,
        &outSz, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_encrypt(&cliKey, &srvKey, (byte*)msg, msgSz, out, NULL,
        NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

#ifdef WOLFSSL_ECIES_OLD
    tmpKey.dp = cliKey.dp;
    tmpKey.idx = cliKey.idx;
    ExpectIntEQ(wc_ecc_copy_point(&cliKey.pubkey, &tmpKey.pubkey), 0);
#endif

    ExpectIntEQ(wc_ecc_decrypt(&srvKey, &tmpKey, out, outSz, plain, &plainSz,
         NULL), 0);
    ExpectIntEQ(wc_ecc_decrypt(NULL, &tmpKey, out, outSz, plain, &plainSz,
         NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifdef WOLFSSL_ECIES_OLD
    /* NULL parameter allowed in new implementations - public key comes from
     * the message. */
    ExpectIntEQ(wc_ecc_decrypt(&srvKey, NULL, out, outSz, plain, &plainSz,
        NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wc_ecc_decrypt(&srvKey, &tmpKey, NULL, outSz, plain, &plainSz,
        NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_decrypt(&srvKey, &tmpKey, out, outSz, NULL, &plainSz,
        NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_decrypt(&srvKey, &tmpKey, out, outSz, plain, NULL, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(XMEMCMP(msg, plain, msgSz), 0);

    wc_ecc_free(&tmpKey);
    wc_ecc_free(&srvKey);
    wc_ecc_free(&cliKey);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ecc_encryptDecrypt */

/*
 * Testing wc_ecc_del_point() and wc_ecc_new_point()
 */
int test_wc_ecc_del_point(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC)
    ecc_point* pt = NULL;

    ExpectNotNull(pt = wc_ecc_new_point());
    wc_ecc_del_point(pt);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ecc_del_point */

/*
 * Testing wc_ecc_point_is_at_infinity(), wc_ecc_export_point_der(),
 * wc_ecc_import_point_der(), wc_ecc_copy_point(), wc_ecc_point_is_on_curve(),
 * and wc_ecc_cmp_point()
 */
int test_wc_ecc_pointFns(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_EXPORT) && \
    !defined(WC_NO_RNG) && !defined(WOLFSSL_ATECC508A) && \
    !defined(WOLFSSL_ATECC608A) && !defined(WOLF_CRYPTO_CB_ONLY_ECC) && \
    !defined(WOLFSSL_MICROCHIP_TA100)
    ecc_key    key;
    WC_RNG     rng;
    int        ret;
    ecc_point* point = NULL;
    ecc_point* cpypt = NULL;
    int        idx = 0;
    int        keySz = KEY32;
    byte       der[DER_SZ(KEY32)];
    word32     derlenChk = 0;
    word32     derSz = DER_SZ(KEY32);

    /* Init stack variables. */
    XMEMSET(der, 0, derSz);
    XMEMSET(&key, 0, sizeof(ecc_key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ecc_init(&key), 0);
    ret = wc_ecc_make_key(&rng, keySz, &key);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    ExpectIntEQ(ret, 0);

    ExpectNotNull(point = wc_ecc_new_point());
    ExpectNotNull(cpypt = wc_ecc_new_point());

    /* Export */
    ExpectIntEQ(wc_ecc_export_point_der((idx = key.idx), &key.pubkey, NULL,
        &derlenChk), WC_NO_ERR_TRACE(LENGTH_ONLY_E));
    /* Check length value. */
    ExpectIntEQ(derSz, derlenChk);
    ExpectIntEQ(wc_ecc_export_point_der((idx = key.idx), &key.pubkey, der,
        &derSz), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_ecc_export_point_der(-2, &key.pubkey, der, &derSz),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_ecc_export_point_der((idx = key.idx), NULL, der, &derSz),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_ecc_export_point_der((idx = key.idx), &key.pubkey, der,
        NULL), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));

    /* Import */
    ExpectIntEQ(wc_ecc_import_point_der(der, derSz, idx, point), 0);
    ExpectIntEQ(wc_ecc_cmp_point(&key.pubkey, point), 0);
    /* Test bad args. */
    ExpectIntEQ( wc_ecc_import_point_der(NULL, derSz, idx, point),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_ecc_import_point_der(der, derSz, idx, NULL),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_ecc_import_point_der(der, derSz, -1, point),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_ecc_import_point_der(der, derSz + 1, idx, point),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));

    /* Copy */
    ExpectIntEQ(wc_ecc_copy_point(point, cpypt), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_ecc_copy_point(NULL, cpypt), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_ecc_copy_point(point, NULL), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));

    /* Compare point */
    ExpectIntEQ(wc_ecc_cmp_point(point, cpypt), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_ecc_cmp_point(NULL, cpypt), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_cmp_point(point, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* At infinity if return == 1, otherwise return == 0. */
    ExpectIntEQ(wc_ecc_point_is_at_infinity(point), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_ecc_point_is_at_infinity(NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

#if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2)))
    /* On curve if ret == 0 */
    ExpectIntEQ(wc_ecc_point_is_on_curve(point, idx), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_ecc_point_is_on_curve(NULL, idx),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_point_is_on_curve(point, 1000),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
#endif /* !HAVE_SELFTEST && (!HAVE_FIPS || HAVE_FIPS_VERSION > 2) */

    /* Free */
    wc_ecc_del_point(point);
    wc_ecc_del_point(cpypt);
    wc_ecc_free(&key);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ecc_pointFns */

/*
 * Testing wc_ecc_shared_secret_ssh()
 */
int test_wc_ecc_shared_secret_ssh(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && defined(HAVE_ECC_DHE) && \
    !defined(WC_NO_RNG) && !defined(WOLFSSL_ATECC508A) && \
    !defined(WOLFSSL_ATECC608A) && !defined(PLUTON_CRYPTO_ECC) && \
    !defined(WOLFSSL_CRYPTOCELL) && !defined(WOLF_CRYPTO_CB_ONLY_ECC) && \
    !defined(WOLFSSL_MICROCHIP_TA100)
    ecc_key key;
    ecc_key key2;
    WC_RNG  rng;
    int     ret;
    int     keySz = KEY32;
#if FIPS_VERSION3_GE(6,0,0)
    int     key2Sz = KEY28;
#else
    int     key2Sz = KEY24;
#endif
    byte    secret[KEY32];
    word32  secretLen = (word32)keySz;

    /* Init stack variables. */
    XMEMSET(&key, 0, sizeof(ecc_key));
    XMEMSET(&key2, 0, sizeof(ecc_key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(secret, 0, secretLen);
    PRIVATE_KEY_UNLOCK();

    /* Make keys */
    ExpectIntEQ(wc_ecc_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ret = wc_ecc_make_key(&rng, keySz, &key);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    ExpectIntEQ(ret, 0);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);

    ExpectIntEQ(wc_ecc_init(&key2), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ret = wc_ecc_make_key(&rng, key2Sz, &key2);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &key2.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    ExpectIntEQ(ret, 0);

#if defined(ECC_TIMING_RESISTANT) && (!defined(HAVE_FIPS) || \
    (!defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION != 2))) && \
    !defined(HAVE_SELFTEST)
    ExpectIntEQ(wc_ecc_set_rng(&key, &rng), 0);
#endif

    ExpectIntEQ(wc_ecc_shared_secret_ssh(&key, &key2.pubkey, secret,
        &secretLen), 0);
    /* Pass in bad args. */
    ExpectIntEQ(wc_ecc_shared_secret_ssh(NULL, &key2.pubkey, secret,
        &secretLen), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_shared_secret_ssh(&key, NULL, secret, &secretLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_shared_secret_ssh(&key, &key2.pubkey, NULL, &secretLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_shared_secret_ssh(&key, &key2.pubkey, secret, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    key.type = ECC_PUBLICKEY;
    ExpectIntEQ(wc_ecc_shared_secret_ssh(&key, &key2.pubkey, secret,
        &secretLen), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    PRIVATE_KEY_LOCK();

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ecc_free(&key);
    wc_ecc_free(&key2);

#ifdef FP_ECC
    wc_ecc_fp_free();
#endif
#endif
    return EXPECT_RESULT();
} /* END test_wc_ecc_shared_secret_ssh */

/*
 * Testing wc_ecc_verify_hash_ex() and wc_ecc_verify_hash_ex()
 */
int test_wc_ecc_verify_hash_ex(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && defined(HAVE_ECC_SIGN) && defined(WOLFSSL_PUBLIC_MP) \
    && !defined(WC_NO_RNG) && !defined(WOLFSSL_ATECC508A) && \
       !defined(WOLFSSL_ATECC608A) && !defined(WOLFSSL_KCAPI_ECC) && \
       !defined(WOLFSSL_MICROCHIP_TA100)
    ecc_key       key;
    WC_RNG        rng;
    int           ret;
    mp_int        r;
    mp_int        s;
    mp_int        z;
    unsigned char hash[] = "Everyone gets Friday off.EccSig";
    unsigned char iHash[] = "Everyone gets Friday off.......";
    unsigned char shortHash[] = TEST_STRING;
    word32        hashlen = sizeof(hash);
    word32        iHashLen = sizeof(iHash);
    word32        shortHashLen = sizeof(shortHash);
    int           keySz = KEY32;
    int           verify_ok = 0;

    XMEMSET(&key, 0, sizeof(ecc_key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(&r, 0, sizeof(mp_int));
    XMEMSET(&s, 0, sizeof(mp_int));
    XMEMSET(&z, 0, sizeof(mp_int));

    /* Initialize r, s and z. */
    ExpectIntEQ(mp_init_multi(&r, &s, &z, NULL, NULL, NULL), MP_OKAY);

    ExpectIntEQ(wc_ecc_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ret = wc_ecc_make_key(&rng, keySz, &key);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    ExpectIntEQ(ret, 0);

    ExpectIntEQ(wc_ecc_sign_hash_ex(hash, hashlen, &rng, &key, &r, &s), 0);
    /* verify_ok should be 1. */
    ExpectIntEQ(wc_ecc_verify_hash_ex(&r, &s, hash, hashlen, &verify_ok, &key),
        0);
    ExpectIntEQ(verify_ok, 1);

    /* verify_ok should be 0 */
    ExpectIntEQ(wc_ecc_verify_hash_ex(&r, &s, iHash, iHashLen, &verify_ok,
        &key), 0);
    ExpectIntEQ(verify_ok, 0);

    /* verify_ok should be 0. */
    ExpectIntEQ(wc_ecc_verify_hash_ex(&r, &s, shortHash, shortHashLen,
        &verify_ok, &key), 0);
    ExpectIntEQ(verify_ok, 0);

    /* Test bad args. */
    ExpectIntEQ(wc_ecc_sign_hash_ex(NULL, hashlen, &rng, &key, &r, &s),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_ecc_sign_hash_ex(hash, hashlen, NULL, &key, &r, &s),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_ecc_sign_hash_ex(hash, hashlen, &rng, NULL, &r, &s),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_ecc_sign_hash_ex(hash, hashlen, &rng, &key, NULL, &s),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_ecc_sign_hash_ex(hash, hashlen, &rng, &key, &r, NULL),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    /* Test bad args. */
    ExpectIntEQ(wc_ecc_verify_hash_ex(NULL, &s, shortHash, shortHashLen,
        &verify_ok, &key), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_ecc_verify_hash_ex(&r, NULL, shortHash, shortHashLen,
        &verify_ok, &key), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_ecc_verify_hash_ex(&z, &s, shortHash, shortHashLen,
        &verify_ok, &key), WC_NO_ERR_TRACE(MP_ZERO_E));
    ExpectIntEQ(wc_ecc_verify_hash_ex(&r, &z, shortHash, shortHashLen,
        &verify_ok, &key), WC_NO_ERR_TRACE(MP_ZERO_E));
    ExpectIntEQ(wc_ecc_verify_hash_ex(&z, &z, shortHash, shortHashLen,
        &verify_ok, &key), WC_NO_ERR_TRACE(MP_ZERO_E));
    ExpectIntEQ(wc_ecc_verify_hash_ex(&r, &s, NULL, shortHashLen, &verify_ok,
        &key), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_ecc_verify_hash_ex(&r, &s, shortHash, shortHashLen, NULL,
        &key), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_ecc_verify_hash_ex(&r, &s, shortHash, shortHashLen,
        &verify_ok, NULL), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));

    wc_ecc_free(&key);
    mp_free(&r);
    mp_free(&s);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ecc_verify_hash_ex */

/*
 * Testing wc_ecc_mulmod()
 */
int test_wc_ecc_mulmod(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && !defined(WC_NO_RNG) && \
    !(defined(WOLFSSL_ATECC508A) || defined(WOLFSSL_ATECC608A) || \
      defined(WOLFSSL_MICROCHIP_TA100) || \
      defined(WOLFSSL_VALIDATE_ECC_IMPORT)) && \
    !defined(WOLF_CRYPTO_CB_ONLY_ECC) && !defined(HAVE_SELFTEST) && \
    !defined(HAVE_FIPS)
    ecc_key     key1;
    ecc_key     key2;
    ecc_key     key3;
    WC_RNG      rng;
    int         ret;

    XMEMSET(&key1, 0, sizeof(ecc_key));
    XMEMSET(&key2, 0, sizeof(ecc_key));
    XMEMSET(&key3, 0, sizeof(ecc_key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_ecc_init(&key1), 0);
    ExpectIntEQ(wc_ecc_init(&key2), 0);
    ExpectIntEQ(wc_ecc_init(&key3), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ret = wc_ecc_make_key(&rng, KEY32, &key1);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &key1.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    ExpectIntEQ(ret, 0);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);

    ExpectIntEQ(wc_ecc_import_raw_ex(&key2, key1.dp->Gx, key1.dp->Gy,
        key1.dp->Af, ECC_SECP256R1), 0);
    ExpectIntEQ(wc_ecc_import_raw_ex(&key3, key1.dp->Gx, key1.dp->Gy,
        key1.dp->prime, ECC_SECP256R1), 0);

    ExpectIntEQ(wc_ecc_mulmod(wc_ecc_key_get_priv(&key1), &key2.pubkey,
        &key3.pubkey, wc_ecc_key_get_priv(&key2), wc_ecc_key_get_priv(&key3),
        1), 0);

    /* Test bad args. */
    ExpectIntEQ(ret = wc_ecc_mulmod(NULL, &key2.pubkey, &key3.pubkey,
        wc_ecc_key_get_priv(&key2), wc_ecc_key_get_priv(&key3), 1),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_ecc_mulmod(wc_ecc_key_get_priv(&key1), NULL, &key3.pubkey,
        wc_ecc_key_get_priv(&key2), wc_ecc_key_get_priv(&key3), 1),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_ecc_mulmod(wc_ecc_key_get_priv(&key1), &key2.pubkey, NULL,
        wc_ecc_key_get_priv(&key2), wc_ecc_key_get_priv(&key3), 1),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_ecc_mulmod(wc_ecc_key_get_priv(&key1), &key2.pubkey,
        &key3.pubkey, wc_ecc_key_get_priv(&key2), NULL, 1),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));

    wc_ecc_free(&key1);
    wc_ecc_free(&key2);
    wc_ecc_free(&key3);

#ifdef FP_ECC
    wc_ecc_fp_free();
#endif
#endif /* HAVE_ECC && !WOLFSSL_ATECC508A */
    return EXPECT_RESULT();
} /* END test_wc_ecc_mulmod */

/*
 * Testing wc_ecc_is_valid_idx()
 */
int test_wc_ecc_is_valid_idx(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && !defined(WC_NO_RNG)
    ecc_key key;
    WC_RNG  rng;
    int     ret;
    int     iVal = -2;
    int     iVal2 = 3000;

    XMEMSET(&key, 0, sizeof(ecc_key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_ecc_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ret = wc_ecc_make_key(&rng, 32, &key);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    ExpectIntEQ(ret, 0);

    ExpectIntEQ(wc_ecc_is_valid_idx(key.idx), 1);
    /* Test bad args. */
    ExpectIntEQ(wc_ecc_is_valid_idx(iVal), 0);
    ExpectIntEQ(wc_ecc_is_valid_idx(iVal2), 0);

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ecc_free(&key);

#ifdef FP_ECC
    wc_ecc_fp_free();
#endif
#endif
    return EXPECT_RESULT();
} /* END test_wc_ecc_is_valid_idx */

/*
 * Testing wc_ecc_get_curve_id_from_oid()
 */
int test_wc_ecc_get_curve_id_from_oid(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && !defined(NO_ECC256) && !defined(HAVE_SELFTEST) && \
    !defined(HAVE_FIPS)
    const byte oid[] = {0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07};
    word32 len = sizeof(oid);

    /* Bad Cases */
    ExpectIntEQ(wc_ecc_get_curve_id_from_oid(NULL, len),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_get_curve_id_from_oid(oid, 0), ECC_CURVE_INVALID);
    /* Good Case */
    ExpectIntEQ(wc_ecc_get_curve_id_from_oid(oid, len), ECC_SECP256R1);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ecc_get_curve_id_from_oid */

/*
 * Testing wc_ecc_sig_size_calc()
 */
int test_wc_ecc_sig_size_calc(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && !defined(WC_NO_RNG) && !defined(HAVE_SELFTEST)
    ecc_key key;
    WC_RNG  rng;
    int     sz = 0;
    int     ret;

    XMEMSET(&key, 0, sizeof(ecc_key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_ecc_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ret = wc_ecc_make_key(&rng, 16, &key);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
#if FIPS_VERSION3_GE(6,0,0)
    ExpectIntEQ(ret, WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#else
    ExpectIntEQ(ret, 0);
#endif
#if FIPS_VERSION3_LT(6,0,0)
    sz = key.dp->size;
    ExpectIntGT(wc_ecc_sig_size_calc(sz), 0);
#else
    (void) sz;
#endif

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ecc_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ecc_sig_size_calc */

/*
 * Testing wc_EccPrivateKeyToDer
 */
int test_wc_EccPrivateKeyToDer(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_EXPORT) && !defined(WC_NO_RNG)
    byte    output[ONEK_BUF];
    ecc_key eccKey;
    WC_RNG  rng;
    word32  inLen = 0;
    word32  outLen = 0;
    int     ret;

    XMEMSET(&eccKey, 0, sizeof(ecc_key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));
    PRIVATE_KEY_UNLOCK();

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ecc_init(&eccKey), 0);
    ret = wc_ecc_make_key(&rng, KEY14, &eccKey);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &eccKey.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    ExpectIntEQ(ret, 0);

    /* Bad Cases */
    ExpectIntEQ(wc_EccPrivateKeyToDer(NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_EccPrivateKeyToDer(NULL, output, inLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    inLen = wc_EccPrivateKeyToDer(&eccKey, NULL, 0);
    ExpectIntGT(inLen, 0);
    ExpectIntEQ(wc_EccPrivateKeyToDer(&eccKey, output, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Good Case */
    ExpectIntGT(outLen = (word32)wc_EccPrivateKeyToDer(&eccKey, output, inLen),
        0);

    wc_ecc_free(&eccKey);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);

#if defined(OPENSSL_EXTRA) && defined(HAVE_ALL_CURVES)
    {
        /* test importing private only into a PKEY struct */
        EC_KEY*   ec = NULL;
        EVP_PKEY* pkey = NULL;
        const unsigned char* der;

        der = output;
        ExpectNotNull(pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &der, outLen));

        der = output;
        ExpectNotNull(ec = d2i_ECPrivateKey(NULL, &der, outLen));
        ExpectIntEQ(EVP_PKEY_assign_EC_KEY(pkey, ec), SSL_SUCCESS);
        if (EXPECT_FAIL()) {
            EC_KEY_free(ec);
        }
        EVP_PKEY_free(pkey); /* EC_KEY should be free'd by free'ing pkey */
    }
#endif
    PRIVATE_KEY_LOCK();
#endif
    return EXPECT_RESULT();
} /* End test_wc_EccPrivateKeyToDer */

/*
 * MC/DC wave 1 - decision-targeted negative/edge paths for wolfcrypt/src/
 * ecc.c that the existing (already extensive) API tests above do not drive.
 * Each block cites the GAPS.md line:col:cond it targets. No library source
 * is changed; every case is reached through the public wc_ecc_* API.
 *
 * Split into several functions (test_wc_EccDecisionCoverage{,2,3,4}) rather
 * than one large one: a single function covering this many independent
 * decisions produced a stack-corrupting crash under this campaign's
 * -fcoverage-mcdc + -O0 combination (reproduced with gdb: a plain on-stack
 * mp_int's used/size fields were already garbage immediately after its own
 * mp_init(), and clearing it then walked off the end of its dp[] array and
 * stomped an unrelated local). Splitting into smaller functions -- each well
 * under the size of the pre-existing test_wc_RsaDecisionCoverage -- avoids
 * the failure mode entirely and keeps every function's own local mp_int/
 * ecc_key set small.
 */
int test_wc_EccDecisionCoverage(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && !defined(WC_NO_RNG) && \
    !defined(WOLF_CRYPTO_CB_ONLY_ECC) && !defined(WOLFSSL_ATECC508A) && \
    !defined(WOLFSSL_ATECC608A) && !defined(WOLFSSL_MICROCHIP_TA100) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
    WC_RNG  rng;
    ecc_key key;
    int     ret;

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(&key, 0, sizeof(ecc_key));
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ecc_init(&key), 0);
    ret = wc_ecc_make_key(&rng, KEY32, &key);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    ExpectIntEQ(ret, 0);

    /* ---- wc_ecc_set_curve: GAPS.md 1927 ----
     * if (key == NULL || (keysize <= 0 && curve_id < 0))
     * key==NULL true side is already exercised elsewhere (BAD_FUNC_ARG on a
     * NULL key is a common pattern); complete the compound's other operand
     * with a valid key but both keysize<=0 AND curve_id<0 (all-false needs a
     * legitimate positive keysize OR non-negative curve id, already shown by
     * every successful wc_ecc_make_key call in this suite). */
    ExpectIntEQ(wc_ecc_set_curve(NULL, KEY32, ECC_SECP256R1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#if !defined(NO_ECC256) && !defined(NO_ECC_SECP)
    ExpectIntEQ(wc_ecc_set_curve(&key, 0, -1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_set_curve(&key, 0, ECC_SECP256R1), 0);
    ExpectIntEQ(wc_ecc_set_curve(&key, KEY32, -1), 0);
#endif

    /* ---- wc_ecc_get_curve_id: GAPS.md 4317 ----
     * if (wc_ecc_is_valid_idx(curve_idx) && curve_idx >= 0)
     * curve_idx == -1 makes wc_ecc_is_valid_idx() true (ECC_CUSTOM_IDX is
     * a valid "user-supplied params" index) but curve_idx>=0 false: the
     * independence pair for the second operand. */
    ExpectIntEQ(wc_ecc_get_curve_id(-1), WC_NO_ERR_TRACE(ECC_CURVE_INVALID));
    ExpectIntEQ(wc_ecc_get_curve_id(-2), WC_NO_ERR_TRACE(ECC_CURVE_INVALID));
#if !defined(NO_ECC256) && !defined(NO_ECC_SECP)
    ExpectIntEQ(wc_ecc_get_curve_id(key.idx), ECC_SECP256R1);
#endif

    /* ---- wc_ecc_get_curve_params: GAPS.md 4654 ----
     * if (curve_idx >= 0 && curve_idx < (int)ECC_SET_COUNT)
     * both boundary violations (negative, and >= COUNT) plus a valid idx. */
    ExpectNull(wc_ecc_get_curve_params(-1));
    ExpectNull(wc_ecc_get_curve_params(1000000));
    ExpectNotNull(wc_ecc_get_curve_params(key.idx));

    /* ---- wc_ecc_point_is_at_infinity: GAPS.md 5320 ----
     * if (mp_iszero(p->x) && mp_iszero(p->y))
     * Unique-cause MC/DC for a 2-operand AND needs THREE vectors within
     * this same binary: (T,T), (F,T), (T,F) (the existing pointFns test's
     * real, non-infinity public point supplies the (F,F) "both false" one
     * elsewhere in this same "ecc" group). A freshly allocated point has
     * x=y=0 by construction (T,T); mp_set() one ordinate nonzero for the
     * mixed (T,F)/(F,T) pair. */
    {
        ecc_point* inf = NULL;
        ExpectNotNull(inf = wc_ecc_new_point());
        ExpectIntEQ(wc_ecc_point_is_at_infinity(inf), 1);
#if defined(WOLFSSL_PUBLIC_MP)
        /* x zero, y nonzero: idx0 (x) TRUE, idx1 (y) FALSE. */
        ExpectIntEQ(mp_set(inf->y, 1), MP_OKAY);
        ExpectIntEQ(wc_ecc_point_is_at_infinity(inf), 0);
        /* x nonzero, y zero: idx0 (x) FALSE, idx1 (y) TRUE. */
        ExpectIntEQ(mp_set(inf->x, 1), MP_OKAY);
        mp_zero(inf->y);
        ExpectIntEQ(wc_ecc_point_is_at_infinity(inf), 0);
#endif
        wc_ecc_del_point(inf);
    }

    /* ---- wc_ecc_gen_k: GAPS.md 5335 ----
     * if (rng==NULL || size<0 || size+8>ECC_MAXSIZE_GEN || k==NULL ||
     *                                                       order==NULL)
     * Exercise each operand's TRUE side individually against an otherwise
     * valid call. */
#if !defined(WOLFSSL_ECC_GEN_REJECT_SAMPLING) && defined(WOLFSSL_PUBLIC_MP)
    {
        mp_int k, order;
        ExpectIntEQ(mp_init(&k), MP_OKAY);
        ExpectIntEQ(mp_init(&order), MP_OKAY);
        ExpectIntEQ(mp_set(&order, 0xFFFFFFFF), MP_OKAY);
        ExpectIntEQ(wc_ecc_gen_k(NULL, KEY32, &k, &order),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_ecc_gen_k(&rng, -1, &k, &order),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_ecc_gen_k(&rng, ECC_MAXSIZE_GEN, &k, &order),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG)); /* size+8 > ECC_MAXSIZE_GEN */
        ExpectIntEQ(wc_ecc_gen_k(&rng, KEY32, NULL, &order),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_ecc_gen_k(&rng, KEY32, &k, NULL),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_ecc_gen_k(&rng, KEY32, &k, &order), 0);
        mp_clear(&k);
        mp_clear(&order);
    }
#endif

    /* ---- wc_ecc_init_id: GAPS.md 6479, 6483 ----
     * if (ret == 0 && (len < 0 || len > ECC_MAX_ID_LEN)) -> BUFFER_E
     * if (ret == 0 && id != NULL && len != 0) -> copy branch
     * Exercise: len<0, len>MAX, id==NULL (len!=0 skipped), len==0 (id!=NULL
     * skipped), and the true/true "copy" case. */
    #ifdef WOLF_PRIVATE_KEY_ID
    {
        ecc_key idKey;
        unsigned char idbuf[4] = { 1, 2, 3, 4 };

        XMEMSET(&idKey, 0, sizeof(idKey));
        ExpectIntEQ(wc_ecc_init_id(NULL, idbuf, sizeof(idbuf), NULL,
            INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_ecc_init_id(&idKey, idbuf, -1, NULL, INVALID_DEVID),
            WC_NO_ERR_TRACE(BUFFER_E));
        wc_ecc_free(&idKey);
        XMEMSET(&idKey, 0, sizeof(idKey));
        ExpectIntEQ(wc_ecc_init_id(&idKey, idbuf, ECC_MAX_ID_LEN + 1, NULL,
            INVALID_DEVID), WC_NO_ERR_TRACE(BUFFER_E));
        wc_ecc_free(&idKey);
        XMEMSET(&idKey, 0, sizeof(idKey));
        ExpectIntEQ(wc_ecc_init_id(&idKey, NULL, 0, NULL, INVALID_DEVID), 0);
        wc_ecc_free(&idKey);
        /* id != NULL, len == 0: GAPS.md 6483's 3rd operand (len != 0)
         * independence pair -- id!=NULL fixed TRUE across this call and
         * the all-true "copy" call below, len toggled 0 vs nonzero. */
        XMEMSET(&idKey, 0, sizeof(idKey));
        ExpectIntEQ(wc_ecc_init_id(&idKey, idbuf, 0, NULL, INVALID_DEVID), 0);
        wc_ecc_free(&idKey);
        XMEMSET(&idKey, 0, sizeof(idKey));
        ExpectIntEQ(wc_ecc_init_id(&idKey, idbuf, sizeof(idbuf), NULL,
            INVALID_DEVID), 0);
        wc_ecc_free(&idKey);
    }
    #endif

    /* ---- wc_ecc_init_label: GAPS.md 6503, 6507 ----
     * if (key == NULL || label == NULL)
     * if (labelLen == 0 || labelLen > ECC_MAX_LABEL_LEN) */
    #ifdef WOLF_PRIVATE_KEY_ID
    {
        ecc_key lblKey;
        char longLabel[ECC_MAX_LABEL_LEN + 2];

        XMEMSET(&lblKey, 0, sizeof(lblKey));
        XMEMSET(longLabel, 'A', sizeof(longLabel) - 1);
        longLabel[sizeof(longLabel) - 1] = '\0';

        ExpectIntEQ(wc_ecc_init_label(NULL, "x", NULL, INVALID_DEVID),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_ecc_init_label(&lblKey, NULL, NULL, INVALID_DEVID),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_ecc_init_label(&lblKey, "", NULL, INVALID_DEVID),
            WC_NO_ERR_TRACE(BUFFER_E));
        wc_ecc_free(&lblKey);
        XMEMSET(&lblKey, 0, sizeof(lblKey));
        ExpectIntEQ(wc_ecc_init_label(&lblKey, longLabel, NULL,
            INVALID_DEVID), WC_NO_ERR_TRACE(BUFFER_E));
        wc_ecc_free(&lblKey);
        XMEMSET(&lblKey, 0, sizeof(lblKey));
        ExpectIntEQ(wc_ecc_init_label(&lblKey, "x", NULL, INVALID_DEVID), 0);
        wc_ecc_free(&lblKey);
    }
    #endif

#if defined(HAVE_ECC_SIGN) && !defined(NO_ASN)
    /* ---- wc_ecc_sign_hash / wc_ecc_sign_hash_ex: GAPS.md 6909, 7443 ----
     * if ((inlen > WC_MAX_DIGEST_SIZE) || (inlen < WC_MIN_DIGEST_SIZE_FOR_SIGN))
     * The signVerify_hash test above already shows the ">MAX" true side;
     * complete the other operand with a too-short digest. */
    {
        byte    sig[ECC_MAX_SIG_SIZE];
        word32  siglen = (word32)sizeof(sig);
        byte    shortDigest[1] = { 0x42 };

        ExpectIntEQ(wc_ecc_sign_hash(shortDigest, 1, sig, &siglen, &rng,
            &key), WC_NO_ERR_TRACE(BAD_LENGTH_E));
#ifdef HAVE_ECC_VERIFY
        {
            int verify = 0;
            siglen = (word32)sizeof(sig);
            ExpectIntEQ(wc_ecc_verify_hash(sig, siglen, shortDigest, 1,
                &verify, &key), WC_NO_ERR_TRACE(BAD_LENGTH_E));
        }
#endif
        /* wc_ecc_sign_hash() has its OWN copy of this length check (it does
         * not delegate to wc_ecc_sign_hash_ex() before running it), so
         * GAPS.md 7443 (wc_ecc_sign_hash_ex's identical check) needs a
         * direct call in the SAME test binary to independently show its own
         * MC/DC pair -- llvm-cov computes independence per-binary, so
         * showing the FALSE side via signVerify_hash's normal-length call
         * elsewhere in this same "ecc" group and the TRUE side here (both
         * within tests/unit.test) is what actually closes it. */
#if defined(WOLFSSL_PUBLIC_MP)
        {
            mp_int r, s;
            byte   longDigest[WC_MAX_DIGEST_SIZE + 1];

            XMEMSET(longDigest, 0x24, sizeof(longDigest));
            ExpectIntEQ(mp_init(&r), MP_OKAY);
            ExpectIntEQ(mp_init(&s), MP_OKAY);
            ExpectIntEQ(wc_ecc_sign_hash_ex(shortDigest, 1, &rng, &key, &r,
                &s), WC_NO_ERR_TRACE(BAD_LENGTH_E));
            /* idx0 (inlen > WC_MAX_DIGEST_SIZE): independent of the
             * idx1 (< MIN) pair just shown above. */
            ExpectIntEQ(wc_ecc_sign_hash_ex(longDigest, sizeof(longDigest),
                &rng, &key, &r, &s), WC_NO_ERR_TRACE(BAD_LENGTH_E));
            mp_clear(&r);
            mp_clear(&s);
        }
#endif
    }
#endif /* HAVE_ECC_SIGN && !NO_ASN */

#if defined(HAVE_ECC_VERIFY) && defined(WOLFSSL_PUBLIC_MP)
    /* ---- wc_ecc_verify_hash_ex: GAPS.md 9476 ----
     * Same reasoning as wc_ecc_sign_hash_ex above: wc_ecc_verify_hash()
     * does not delegate through this check, so it needs its own direct
     * short-hash call in this binary. */
    {
        mp_int r, s;
        int    res = 0;
        byte   shortHash[1] = { 0x42 };
        byte   longHash[WC_MAX_DIGEST_SIZE + 1];

        XMEMSET(longHash, 0x24, sizeof(longHash));
        ExpectIntEQ(mp_init(&r), MP_OKAY);
        ExpectIntEQ(mp_init(&s), MP_OKAY);
        ExpectIntEQ(wc_ecc_verify_hash_ex(&r, &s, shortHash, 1, &res, &key),
            WC_NO_ERR_TRACE(BAD_LENGTH_E));
        /* idx0 (hashlen > WC_MAX_DIGEST_SIZE) independence pair. */
        ExpectIntEQ(wc_ecc_verify_hash_ex(&r, &s, longHash,
            sizeof(longHash), &res, &key), WC_NO_ERR_TRACE(BAD_LENGTH_E));
        mp_clear(&r);
        mp_clear(&s);
    }
#endif

    /* ---- wc_ecc_free: GAPS.md 8209 ----
     * if (key->deallocSet && key->dp != NULL)
     * Exercise the "deallocSet but dp already NULL" and "dp set but
     * deallocSet false" independence halves via wc_ecc_set_custom_curve
     * (which sets deallocSet) vs. a normal wc_ecc_make_key (deallocSet
     * stays 0, dp points at the static ecc_sets table). */
#if defined(WOLFSSL_CUSTOM_CURVES)
    {
        ecc_key ccKey;
        ecc_set_type customDp;

        XMEMSET(&ccKey, 0, sizeof(ccKey));
        XMEMSET(&customDp, 0, sizeof(customDp));
        ExpectIntEQ(wc_ecc_init(&ccKey), 0);
        if (key.dp != NULL) {
            customDp = *key.dp;
        }
        ExpectIntEQ(wc_ecc_set_custom_curve(&ccKey, &customDp), 0);
        wc_ecc_free(&ccKey); /* deallocSet && dp != NULL: TRUE/TRUE */
    }
#endif
    wc_ecc_free(&key); /* !deallocSet: FALSE short-circuit */

    wc_ecc_free(&key);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#ifdef FP_ECC
    wc_ecc_fp_free();
#endif
#endif /* HAVE_ECC && !WC_NO_RNG && !WOLF_CRYPTO_CB_ONLY_ECC */
    return EXPECT_RESULT();
} /* END test_wc_EccDecisionCoverage */

int test_wc_EccDecisionCoverage2(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && !defined(WC_NO_RNG) && \
    !defined(WOLF_CRYPTO_CB_ONLY_ECC) && !defined(WOLFSSL_ATECC508A) && \
    !defined(WOLFSSL_ATECC608A) && !defined(WOLFSSL_MICROCHIP_TA100) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
    WC_RNG  rng;
    ecc_key key;
    int     ret;

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(&key, 0, sizeof(ecc_key));
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ecc_init(&key), 0);
    ret = wc_ecc_make_key(&rng, KEY32, &key);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    ExpectIntEQ(ret, 0);

#if defined(HAVE_ECC_VERIFY) && !defined(WOLFSSL_SP_MATH) && \
    defined(WOLFSSL_PUBLIC_MP)
    /* ---- wc_ecc_check_r_s_range (via wc_ecc_verify_hash_ex): GAPS.md
     * 8939, 8942 ----
     * if ((err == 0) && (mp_cmp(r, curve->order) != MP_LT)) -> r >= order
     * if ((err == 0) && (mp_cmp(s, curve->order) != MP_LT)) -> s >= order
     * Both independence pairs need a real (positive) order value with a
     * TRUE (r/s >= order) and FALSE (r/s < order, shown by every
     * successful verify elsewhere) side; here the TRUE side. */
    if (key.dp != NULL)
    {
        mp_int r, s, bigVal;
        int    verify = 0;
        byte   digest[] = TEST_STRING;

        ExpectIntEQ(mp_init(&r), MP_OKAY);
        ExpectIntEQ(mp_init(&s), MP_OKAY);
        ExpectIntEQ(mp_init(&bigVal), MP_OKAY);
        ExpectIntEQ(mp_read_radix(&bigVal, key.dp->order, MP_RADIX_HEX),
            MP_OKAY);
        ExpectIntEQ(mp_copy(&bigVal, &r), MP_OKAY);
        ExpectIntEQ(mp_copy(&bigVal, &s), MP_OKAY);
        /* r == order: not < order -> MP_VAL by the range check */
        ExpectIntEQ(ret = wc_ecc_verify_hash_ex(&r, &s, digest,
            (word32)TEST_STRING_SZ, &verify, &key),
            WC_NO_ERR_TRACE(MP_VAL));
        mp_clear(&r);
        mp_clear(&s);
        mp_clear(&bigVal);
    }
#endif

    /* ---- wc_ecc_import_point_der_ex / wc_ecc_export_point_der{,_compressed}:
     * GAPS.md 9710, 9964, 9970, 9975, 9984, 10030, 10037, 10042 ---- */
#if defined(HAVE_ECC_KEY_EXPORT) && defined(HAVE_ECC_KEY_IMPORT)
    {
        ecc_point* point = NULL;
        byte       der[DER_SZ(KEY32)];
        word32     derSz = DER_SZ(KEY32);
        word32     lenOnly = 0;

        ExpectNotNull(point = wc_ecc_new_point());
        ExpectIntEQ(wc_ecc_export_point_der(key.idx, &key.pubkey, der,
            &derSz), 0);

        /* import_point_der_ex bad args: in==NULL, point==NULL, curve_idx<0,
         * invalid curve_idx (all before the compressed-point deref). */
        ExpectIntEQ(wc_ecc_import_point_der_ex(NULL, derSz, key.idx, point,
            1), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
        ExpectIntEQ(wc_ecc_import_point_der_ex(der, derSz, key.idx, NULL,
            1), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
        ExpectIntEQ(wc_ecc_import_point_der_ex(der, derSz, -1, point, 1),
            WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
        ExpectIntEQ(wc_ecc_import_point_der_ex(der, derSz, 1000000, point,
            1), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
        ExpectIntEQ(wc_ecc_import_point_der_ex(der, derSz, key.idx, point,
            1), 0);

        /* export_point_der: length-only request (point!=NULL, out==NULL,
         * outLen!=NULL) vs. the ECC_BAD_ARG_E "any of point/out/outLen
         * NULL" branch reached via out==NULL WITH outLen==NULL too. */
        ExpectIntEQ(wc_ecc_export_point_der(key.idx, &key.pubkey, NULL,
            &lenOnly), WC_NO_ERR_TRACE(LENGTH_ONLY_E));
        ExpectIntEQ(lenOnly, derSz);
        ExpectIntEQ(wc_ecc_export_point_der(key.idx, NULL, NULL, NULL),
            WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
        /* short output buffer -> BUFFER_E (buffer-size check runs before
         * the point-ordinate sanity check). */
        {
            byte   shortDer[4];
            word32 shortLen = sizeof(shortDer);
            ExpectIntEQ(wc_ecc_export_point_der(key.idx, &key.pubkey,
                shortDer, &shortLen), WC_NO_ERR_TRACE(BUFFER_E));
        }

#ifdef HAVE_COMP_KEY
        {
            /* wc_ecc_export_point_der_compressed is WOLFSSL_LOCAL (hidden in a
             * shared library), so it is not linkable from the shared-library
             * unit test; its own decision coverage is driven by the campaign's
             * ecc white-box (which includes ecc.c directly). The public
             * compressed export path wc_ecc_export_x963_ex(..., 1) is exercised
             * here (GAPS.md 16058, the static wc_ecc_export_x963_compressed
             * helper). */
#ifdef HAVE_ECC_KEY_EXPORT
            {
                byte   x963c[ECC_BUFSIZE];
                word32 x963cLen = sizeof(x963c);
                PRIVATE_KEY_UNLOCK();
                ExpectIntEQ(wc_ecc_export_x963_ex(&key, x963c, &x963cLen,
                    1), 0);
                PRIVATE_KEY_LOCK();
            }
#endif
        }
#endif /* HAVE_COMP_KEY */

        wc_ecc_del_point(point);
    }
#endif /* HAVE_ECC_KEY_EXPORT && HAVE_ECC_KEY_IMPORT */

    /* ---- wc_ecc_is_point: GAPS.md 10304, 10329, 10332, 10390, 10396,
     * 10403 ----
     * Direct call (rather than through wc_ecc_point_is_on_curve) with a
     * point that is genuinely ON the curve (the generator) and the
     * existing off-curve regression (test_wc_ecc_import_x963_off_curve)
     * supplies the FALSE side elsewhere; this adds the argument-NULL
     * independence pairs plus a real on-curve TRUE result. */
#if defined(HAVE_ECC_KEY_EXPORT) && defined(WOLFSSL_PUBLIC_MP)
    if (key.dp != NULL)
    {
        mp_int a, b, prime;

        ExpectIntEQ(mp_init(&a), MP_OKAY);
        ExpectIntEQ(mp_init(&b), MP_OKAY);
        ExpectIntEQ(mp_init(&prime), MP_OKAY);
        ExpectIntEQ(mp_read_radix(&a, key.dp->Af, MP_RADIX_HEX), MP_OKAY);
        ExpectIntEQ(mp_read_radix(&b, key.dp->Bf, MP_RADIX_HEX), MP_OKAY);
        ExpectIntEQ(mp_read_radix(&prime, key.dp->prime, MP_RADIX_HEX),
            MP_OKAY);

        ExpectIntEQ(wc_ecc_is_point(&key.pubkey, &a, &b, &prime), 0);
        ExpectIntEQ(wc_ecc_is_point(NULL, &a, &b, &prime),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_ecc_is_point(&key.pubkey, NULL, &b, &prime),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_ecc_is_point(&key.pubkey, &a, NULL, &prime),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_ecc_is_point(&key.pubkey, &a, &b, NULL),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        mp_clear(&a);
        mp_clear(&b);
        mp_clear(&prime);
    }
#endif

    wc_ecc_free(&key);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#ifdef FP_ECC
    wc_ecc_fp_free();
#endif
#endif /* HAVE_ECC && !WC_NO_RNG && !WOLF_CRYPTO_CB_ONLY_ECC */
    return EXPECT_RESULT();
} /* END test_wc_EccDecisionCoverage2 */

int test_wc_EccDecisionCoverage3(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && !defined(WC_NO_RNG) && \
    !defined(WOLF_CRYPTO_CB_ONLY_ECC) && !defined(WOLFSSL_ATECC508A) && \
    !defined(WOLFSSL_ATECC608A) && !defined(WOLFSSL_MICROCHIP_TA100) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
    WC_RNG  rng;
    ecc_key key;
    int     ret;

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(&key, 0, sizeof(ecc_key));
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ecc_init(&key), 0);
    ret = wc_ecc_make_key(&rng, KEY32, &key);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    ExpectIntEQ(ret, 0);

    /* ---- wc_ecc_export_public_raw / wc_ecc_export_private_raw:
     * GAPS.md 11477, 11484, 11538, 11548 ---- */
#if defined(HAVE_ECC_KEY_EXPORT)
    {
        byte   qx[MAX_ECC_BYTES], qy[MAX_ECC_BYTES], d[MAX_ECC_BYTES];
        word32 qxLen, qyLen, dLen;
        ecc_key noDpKey;

        /* key->dp == NULL (never curve-assigned): _ecc_export_ex's
         * wc_ecc_is_valid_idx()==0||dp==NULL branch, TRUE side. */
        XMEMSET(&noDpKey, 0, sizeof(noDpKey));
        ExpectIntEQ(wc_ecc_init(&noDpKey), 0);
        qxLen = sizeof(qx); qyLen = sizeof(qy);
        ExpectIntEQ(wc_ecc_export_public_raw(&noDpKey, qx, &qxLen, qy,
            &qyLen), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
        wc_ecc_free(&noDpKey);

        /* d != NULL but dLen == NULL: GAPS.md 11484 first operand. */
        qxLen = sizeof(qx); qyLen = sizeof(qy);
        ExpectIntEQ(wc_ecc_export_private_raw(&key, qx, &qxLen, qy, &qyLen,
            d, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* d != NULL, dLen != NULL, but key type is public-only: GAPS.md
         * 11484 second operand. */
        {
            ecc_key pubOnly;
            byte    qxb[MAX_ECC_BYTES], qyb[MAX_ECC_BYTES];
            word32  qxbLen = sizeof(qxb), qybLen = sizeof(qyb);

            XMEMSET(&pubOnly, 0, sizeof(pubOnly));
            ExpectIntEQ(wc_ecc_init(&pubOnly), 0);
            ExpectIntEQ(wc_ecc_export_public_raw(&key, qxb, &qxbLen, qyb,
                &qybLen), 0);
            ExpectIntEQ(wc_ecc_import_unsigned(&pubOnly, qxb, qyb, NULL,
                key.dp ? key.dp->id : ECC_SECP256R1), 0);
            dLen = sizeof(d);
            ExpectIntEQ(wc_ecc_export_private_raw(&pubOnly, NULL, NULL,
                NULL, NULL, d, &dLen), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

            /* qx != NULL, qxLen == NULL: GAPS.md 11538 first operand. */
            ExpectIntEQ(wc_ecc_export_private_raw(&key, qx, NULL, NULL,
                NULL, NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            /* qy != NULL, qyLen == NULL: GAPS.md 11548 first operand. */
            ExpectIntEQ(wc_ecc_export_private_raw(&key, NULL, NULL, qy,
                NULL, NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            /* qx != NULL against a PRIVATEKEY_ONLY key: GAPS.md 11538
             * second operand (type == ECC_PRIVATEKEY_ONLY). */
            pubOnly.type = ECC_PRIVATEKEY_ONLY;
            qxbLen = sizeof(qxb);
            ExpectIntEQ(wc_ecc_export_private_raw(&pubOnly, qxb, &qxbLen,
                NULL, NULL, NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            qybLen = sizeof(qyb);
            ExpectIntEQ(wc_ecc_export_private_raw(&pubOnly, NULL, NULL,
                qyb, &qybLen, NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

            wc_ecc_free(&pubOnly);
        }
    }
#endif /* HAVE_ECC_KEY_EXPORT */

    /* ---- wc_ecc_rs_raw_to_sig: GAPS.md 12015 ---- */
    {
        byte   r[KEY32], s[KEY32], sig[ECC_MAX_SIG_SIZE];
        word32 sigLen = sizeof(sig);

        XMEMSET(r, 0x11, sizeof(r));
        XMEMSET(s, 0x22, sizeof(s));
        ExpectIntEQ(wc_ecc_rs_raw_to_sig(r, sizeof(r), s, sizeof(s), sig,
            &sigLen), 0);
        ExpectIntEQ(wc_ecc_rs_raw_to_sig(NULL, sizeof(r), s, sizeof(s), sig,
            &sigLen), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
        ExpectIntEQ(wc_ecc_rs_raw_to_sig(r, sizeof(r), NULL, sizeof(s), sig,
            &sigLen), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
        ExpectIntEQ(wc_ecc_rs_raw_to_sig(r, sizeof(r), s, sizeof(s), NULL,
            &sigLen), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
        ExpectIntEQ(wc_ecc_rs_raw_to_sig(r, sizeof(r), s, sizeof(s), sig,
            NULL), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    }

    /* ---- wc_ecc_import_private_key_ex: GAPS.md 11671 (_ecc_import_
     * private_key_ex key==NULL||priv==NULL, reached via the public
     * wrapper's own identical pre-check, same independence pair) ---- */
#if defined(HAVE_ECC_KEY_IMPORT)
    {
        byte   priv[MAX_ECC_BYTES];
        XMEMSET(priv, 0x33, sizeof(priv));
        ExpectIntEQ(wc_ecc_import_private_key_ex(priv, sizeof(priv), NULL,
            0, NULL, ECC_SECP256R1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_ecc_import_private_key_ex(NULL, 0, NULL, 0, &key,
            ECC_SECP256R1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }
#endif

    wc_ecc_free(&key);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#ifdef FP_ECC
    wc_ecc_fp_free();
#endif
#endif /* HAVE_ECC && !WC_NO_RNG && !WOLF_CRYPTO_CB_ONLY_ECC */
    return EXPECT_RESULT();
} /* END test_wc_EccDecisionCoverage3 */

int test_wc_EccDecisionCoverage4(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && !defined(WC_NO_RNG) && \
    !defined(WOLF_CRYPTO_CB_ONLY_ECC) && !defined(WOLFSSL_ATECC508A) && \
    !defined(WOLFSSL_ATECC608A) && !defined(WOLFSSL_MICROCHIP_TA100) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
    WC_RNG  rng;
    ecc_key key;
    int     ret;

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(&key, 0, sizeof(ecc_key));
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ecc_init(&key), 0);
    ret = wc_ecc_make_key(&rng, KEY32, &key);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    ExpectIntEQ(ret, 0);

    /* ---- ecc_mul2add argument guard: GAPS.md 8446 ----
     * NOT closeable by any current variant, API or white-box: both bodies
     * of ecc_mul2add() (the argument-checked "normal" one at line ~8417 and
     * the Shamir/fixed-point-cache one at line ~13909 that supersedes it
     * when FP_ECC is also on) live inside an outer #ifdef ECC_SHAMIR /
     * #endif block (lines 8349-8701 and 13616-14035). Every one of this
     * module's 6 variants has ECC_SHAMIR either ON-with-FP_ECC-ON (base:
     * sp_default/sp_ecc/sp_ecc_nonblock/fastmath/small_stack, which
     * exercises the unchecked Shamir body under the name ecc_mul2add) or
     * turns BOTH ECC_SHAMIR and FP_ECC OFF together (no_fp_shamir, per its
     * config_base's philosophy of flipping the FALSE side of both feature
     * guards at once -- see modules.json's ecc notes), which compiles
     * *neither* body, making ecc_mul2add an undefined symbol there (link
     * failure, confirmed empirically). Reaching this decision needs a new,
     * not-yet-scaffolded variant: ECC_SHAMIR on + FP_ECC off. Classified as
     * a needs-variant residual; see RESIDUALS.md. */

    /* ---- wc_ecc_ctx_set_kdf_salt: GAPS.md 14607 ----
     * if (ctx == NULL || (salt == NULL && sz != 0))
     * ctx==NULL already the common BAD_FUNC_ARG idiom shown elsewhere; add
     * the salt==NULL/sz!=0 half here with a live ctx. */
#if defined(HAVE_ECC_ENCRYPT)
    {
        ecEncCtx* ctx = NULL;
        ExpectNotNull(ctx = wc_ecc_ctx_new(REQ_RESP_CLIENT, &rng));
        ExpectIntEQ(wc_ecc_ctx_set_kdf_salt(NULL, NULL, 0),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_ecc_ctx_set_kdf_salt(ctx, NULL, 4),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_ecc_ctx_set_kdf_salt(ctx, NULL, 0), 0);
        wc_ecc_ctx_free(ctx);
    }
#endif

    /* ---- wc_ecc_set_custom_curve: GAPS.md 16181 ---- */
#if defined(WOLFSSL_CUSTOM_CURVES)
    {
        ecc_key ccKey2;
        XMEMSET(&ccKey2, 0, sizeof(ccKey2));
        ExpectIntEQ(wc_ecc_init(&ccKey2), 0);
        ExpectIntEQ(wc_ecc_set_custom_curve(NULL, key.dp),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_ecc_set_custom_curve(&ccKey2, NULL),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        wc_ecc_free(&ccKey2);
    }
#endif

    /* ---- wc_X963_KDF: GAPS.md 16217, 16221 ---- */
    #ifdef HAVE_X963_KDF
    {
        byte   secret[16];
        byte   out[16];
        word32 outLen = sizeof(out);

        XMEMSET(secret, 0x44, sizeof(secret));
        ExpectIntEQ(wc_X963_KDF(WC_HASH_TYPE_SHA256, NULL, sizeof(secret),
            NULL, 0, out, outLen), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_X963_KDF(WC_HASH_TYPE_SHA256, secret, 0, NULL, 0,
            out, outLen), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_X963_KDF(WC_HASH_TYPE_SHA256, secret, sizeof(secret),
            NULL, 0, NULL, outLen), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* invalid hash type: neither of the five X9.63-allowed algos */
        ExpectIntEQ(wc_X963_KDF(WC_HASH_TYPE_MD5, secret, sizeof(secret),
            NULL, 0, out, outLen), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_SHA256
        ExpectIntEQ(wc_X963_KDF(WC_HASH_TYPE_SHA256, secret, sizeof(secret),
            NULL, 0, out, outLen), 0);
#endif
    }
    #endif

    wc_ecc_free(&key);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#ifdef FP_ECC
    wc_ecc_fp_free();
#endif
#endif /* HAVE_ECC && !WC_NO_RNG && !WOLF_CRYPTO_CB_ONLY_ECC */
    return EXPECT_RESULT();
} /* END test_wc_EccDecisionCoverage4 */
