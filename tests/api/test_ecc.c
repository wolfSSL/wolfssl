/* test_ecc.c
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
#if defined(HAVE_FIPS) && (!defined(FIPS_VERSION_LT) || FIPS_VERSION_LT(5,3))
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
    !defined(WOLFSSL_ATECC608A)
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
#ifdef USE_ECC_B_PARAM
    /* On curve if ret == 0 */
    ExpectIntEQ(wc_ecc_point_is_on_curve(point, idx), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_ecc_point_is_on_curve(NULL, idx),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ecc_point_is_on_curve(point, 1000),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
#endif /* USE_ECC_B_PARAM */
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
    !defined(WOLFSSL_CRYPTOCELL)
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
       !defined(WOLFSSL_ATECC608A) && !defined(WOLFSSL_KCAPI_ECC)
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
      defined(WOLFSSL_VALIDATE_ECC_IMPORT))
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

