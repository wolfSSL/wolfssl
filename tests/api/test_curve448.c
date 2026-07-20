/* test_curve448.c
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

#include <wolfssl/wolfcrypt/curve448.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_curve448.h>

/*
 * Testing wc_curve448_make_key
 */
int test_wc_curve448_make_key(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE448)
    curve448_key key;
    WC_RNG       rng;
    int          keysize = 0;

    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_curve448_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);

    ExpectIntEQ(wc_curve448_make_key(&rng, CURVE448_KEY_SIZE, &key), 0);
    ExpectIntEQ(keysize = wc_curve448_size(&key), CURVE448_KEY_SIZE);
    ExpectIntEQ(wc_curve448_make_key(&rng, keysize, &key), 0);

    /* test bad cases */
    ExpectIntEQ(wc_curve448_make_key(NULL, 0, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve448_make_key(&rng, keysize, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve448_make_key(NULL, keysize, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve448_make_key(&rng, 0, &key),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_curve448_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_curve448_make_key */

/*
 * Testing test_wc_curve448_shared_secret_ex
 */
int test_wc_curve448_shared_secret_ex(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE448)
    curve448_key private_key;
    curve448_key public_key;
    WC_RNG       rng;
    byte         out[CURVE448_KEY_SIZE];
    word32       outLen = sizeof(out);
    int          endian = EC448_BIG_ENDIAN;

    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_curve448_init(&private_key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_curve448_make_key(&rng, CURVE448_KEY_SIZE, &private_key), 0);

    ExpectIntEQ(wc_curve448_init(&public_key), 0);
    ExpectIntEQ(wc_curve448_make_key(&rng, CURVE448_KEY_SIZE, &public_key), 0);
    ExpectIntEQ(wc_curve448_shared_secret_ex(&private_key, &public_key, out,
        &outLen, endian), 0);

    /* test bad cases */
    ExpectIntEQ(wc_curve448_shared_secret_ex(NULL, NULL, NULL, 0, endian),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve448_shared_secret_ex(NULL, &public_key, out, &outLen,
        endian), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve448_shared_secret_ex(&private_key, NULL, out, &outLen,
        endian), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve448_shared_secret_ex(&private_key, &public_key, NULL,
        &outLen, endian), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve448_shared_secret_ex(&private_key, &public_key, out,
        NULL, endian), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    outLen = outLen - 2;
    ExpectIntEQ(wc_curve448_shared_secret_ex(&private_key, &public_key, out,
        &outLen, endian), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_curve448_free(&private_key);
    wc_curve448_free(&public_key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_curve448_shared_secret_ex */

/*
 * Testing that wc_curve448_shared_secret_ex rejects an all-zero shared
 * secret (RFC 7748 section 6.2). This is the default behavior; users that
 * need the legacy behavior can opt out with WOLFSSL_NO_ECDHX_SHARED_ZERO_CHECK.
 */
int test_wc_curve448_shared_secret_zero_check(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE448) && defined(HAVE_CURVE448_KEY_IMPORT) && \
    defined(HAVE_CURVE448_SHARED_SECRET) && \
    !defined(WOLFSSL_NO_ECDHX_SHARED_ZERO_CHECK)
    curve448_key private_key;
    curve448_key public_key;
    WC_RNG       rng;
    byte         out[CURVE448_KEY_SIZE];
    word32       outLen = sizeof(out);
    /* All-zero public key is a low-order point that yields an all-zero
     * shared secret for any private key. */
    byte         zero_pub[CURVE448_PUB_KEY_SIZE];

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(zero_pub, 0, sizeof(zero_pub));

    ExpectIntEQ(wc_curve448_init(&private_key), 0);
    ExpectIntEQ(wc_curve448_init(&public_key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);

    ExpectIntEQ(wc_curve448_make_key(&rng, CURVE448_KEY_SIZE, &private_key), 0);
    ExpectIntEQ(wc_curve448_import_public_ex(zero_pub, sizeof(zero_pub),
        &public_key, EC448_LITTLE_ENDIAN), 0);

    ExpectIntEQ(wc_curve448_shared_secret_ex(&private_key, &public_key, out,
        &outLen, EC448_BIG_ENDIAN),
        WC_NO_ERR_TRACE(ECC_OUT_OF_RANGE_E));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_curve448_free(&private_key);
    wc_curve448_free(&public_key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_curve448_shared_secret_zero_check */

/*
 * Testing test_wc_curve448_export_public_ex
 */
int test_wc_curve448_export_public_ex(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE448)
    WC_RNG        rng;
    curve448_key  key;
    byte          out[CURVE448_KEY_SIZE];
    word32        outLen = sizeof(out);
    int           endian = EC448_BIG_ENDIAN;

    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_curve448_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_curve448_make_key(&rng, CURVE448_KEY_SIZE, &key), 0);

    ExpectIntEQ(wc_curve448_export_public(&key, out, &outLen), 0);
    ExpectIntEQ(wc_curve448_export_public_ex(&key, out, &outLen, endian), 0);
    /* test bad cases */
    ExpectIntEQ(wc_curve448_export_public_ex(NULL, NULL, NULL, endian),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve448_export_public_ex(NULL, out, &outLen, endian),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve448_export_public_ex(&key, NULL, &outLen, endian),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve448_export_public_ex(&key, out, NULL, endian),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    outLen = outLen - 2;
    ExpectIntEQ(wc_curve448_export_public_ex(&key, out, &outLen, endian),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_curve448_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_curve448_export_public_ex */

/*
 * Testing test_wc_curve448_export_private_raw_ex
 */
int test_wc_curve448_export_private_raw_ex(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE448)
    curve448_key key;
    WC_RNG       rng;
    byte         out[CURVE448_KEY_SIZE];
    word32       outLen = sizeof(out);
    int          endian = EC448_BIG_ENDIAN;

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    ExpectIntEQ(wc_curve448_init(&key), 0);
    /* Reject export when private key not set (privSet == 0). */
    ExpectIntEQ(wc_curve448_export_private_raw_ex(&key, out, &outLen, endian),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    /* test bad cases */
    ExpectIntEQ(wc_curve448_export_private_raw_ex(NULL, NULL, NULL, endian),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve448_export_private_raw_ex(NULL, out, &outLen, endian),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve448_export_private_raw_ex(&key, NULL, &outLen, endian),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve448_export_private_raw_ex(&key, out, NULL, endian),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Populate the key, then exercise the buffer-too-small path. */
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_curve448_make_key(&rng, CURVE448_KEY_SIZE, &key), 0);
    outLen = CURVE448_KEY_SIZE - 1;
    ExpectIntEQ(wc_curve448_export_private_raw_ex(&key, out, &outLen, endian),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_curve448_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_curve448_export_private_raw_ex */

/*
 * Testing test_curve448_export_key_raw
 */
int test_wc_curve448_export_key_raw(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE448)
    curve448_key key;
    WC_RNG       rng;
    byte         priv[CURVE448_KEY_SIZE];
    byte         pub[CURVE448_KEY_SIZE];
    word32       privSz = sizeof(priv);
    word32       pubSz = sizeof(pub);

    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_curve448_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_curve448_make_key(&rng, CURVE448_KEY_SIZE, &key), 0);

    ExpectIntEQ(wc_curve448_export_private_raw(&key, priv, &privSz), 0);
    ExpectIntEQ(wc_curve448_export_public(&key, pub, &pubSz), 0);
    ExpectIntEQ(wc_curve448_export_key_raw(&key, priv, &privSz, pub, &pubSz),
        0);

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_curve448_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_curve448_import_private_raw_ex */

/*
 * Testing test_wc_curve448_import_private_raw_ex
 */
int test_wc_curve448_import_private_raw_ex(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE448)
    curve448_key key;
    WC_RNG       rng;
    byte         priv[CURVE448_KEY_SIZE];
    byte         pub[CURVE448_KEY_SIZE];
    word32       privSz = sizeof(priv);
    word32       pubSz = sizeof(pub);
    int          endian = EC448_BIG_ENDIAN;

    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_curve448_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_curve448_make_key(&rng, CURVE448_KEY_SIZE, &key), 0);

    ExpectIntEQ(wc_curve448_export_private_raw(&key, priv, &privSz), 0);
    ExpectIntEQ(wc_curve448_export_public(&key, pub, &pubSz), 0);
    ExpectIntEQ(wc_curve448_import_private_raw_ex(priv, privSz, pub, pubSz,
        &key, endian), 0);
    /* test bad cases */
    ExpectIntEQ(wc_curve448_import_private_raw_ex(NULL, 0, NULL, 0, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve448_import_private_raw_ex(NULL, privSz, pub, pubSz,
        &key, endian), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve448_import_private_raw_ex(priv, privSz, NULL, pubSz,
        &key, endian), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve448_import_private_raw_ex(priv, privSz, pub, pubSz,
        NULL, endian), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve448_import_private_raw_ex(priv, 0, pub, pubSz,
        &key, endian), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_curve448_import_private_raw_ex(priv, privSz, pub, 0,
        &key, endian), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_curve448_import_private_raw_ex(priv, privSz, pub, pubSz,
        &key, EC448_LITTLE_ENDIAN), 0);

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_curve448_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_curve448_import_private_raw_ex */

/*
 * Testing test_wc_curve448_import_private
 */
int test_wc_curve448_import_private(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE448)
    curve448_key key;
    WC_RNG       rng;
    byte         priv[CURVE448_KEY_SIZE];
    word32       privSz = sizeof(priv);

    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_curve448_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_curve448_make_key(&rng, CURVE448_KEY_SIZE, &key), 0);

    ExpectIntEQ(wc_curve448_export_private_raw(&key, priv, &privSz), 0);
    ExpectIntEQ(wc_curve448_import_private(priv, privSz, &key), 0);

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_curve448_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_curve448_import */

/*
 * Testing wc_curve448_init and wc_curve448_free.
 */
int test_wc_curve448_init(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE448)
    curve448_key key;

    /* Test bad args for wc_curve448_init */
    ExpectIntEQ(wc_curve448_init(&key), 0);
    /* Test bad args for wc_curve448_init */
    ExpectIntEQ(wc_curve448_init(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test good args for wc_curve_448_free */
    wc_curve448_free(&key);
    /* Test bad args for wc_curve448_free */
    wc_curve448_free(NULL);
#endif
    return EXPECT_RESULT();
} /* END test_wc_curve448_init and wc_curve_448_free */

/*
 * Testing test_wc_curve448_size.
 */
int test_wc_curve448_size(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE448)
    curve448_key key;

    ExpectIntEQ(wc_curve448_init(&key), 0);

    /*  Test good args for wc_curve448_size */
    ExpectIntEQ(wc_curve448_size(&key), CURVE448_KEY_SIZE);
    /* Test bad args for wc_curve448_size */
    ExpectIntEQ(wc_curve448_size(NULL), 0);

    wc_curve448_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_curve448_size */

/*
 * Testing wc_Curve448PrivateKeyToDer
 */
int test_wc_Curve448PrivateKeyToDer(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE448) && defined(HAVE_CURVE448_KEY_EXPORT) && \
    (defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_KEY_GEN))
    byte      output[ONEK_BUF];
    curve448_key curve448PrivKey;
    WC_RNG    rng;
    word32    inLen;

    XMEMSET(&curve448PrivKey, 0, sizeof(curve448PrivKey));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_curve448_init(&curve448PrivKey), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_curve448_make_key(&rng, CURVE448_KEY_SIZE, &curve448PrivKey),
        0);
    inLen = (word32)sizeof(output);

    /* Bad Cases */
    ExpectIntEQ(wc_Curve448PrivateKeyToDer(NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Curve448PrivateKeyToDer(NULL, output, inLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Curve448PrivateKeyToDer(&curve448PrivKey, output, 0),
        WC_NO_ERR_TRACE(BUFFER_E));
    /* Good cases */
    /* length only */
    ExpectIntGT(wc_Curve448PrivateKeyToDer(&curve448PrivKey, NULL, 0), 0);
    ExpectIntGT(wc_Curve448PrivateKeyToDer(&curve448PrivKey, output, inLen), 0);

    /* Bad Cases */
    ExpectIntEQ(wc_Curve448PublicKeyToDer(NULL, NULL, 0, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Curve448PublicKeyToDer(NULL, output, inLen, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Curve448PublicKeyToDer(&curve448PrivKey, output, 0, 0),
        WC_NO_ERR_TRACE(BUFFER_E));
    ExpectIntEQ(wc_Curve448PublicKeyToDer(&curve448PrivKey, output, 0, 1),
        WC_NO_ERR_TRACE(BUFFER_E));
    /* Good cases */
    /* length only */
    ExpectIntGT(wc_Curve448PublicKeyToDer(&curve448PrivKey, NULL, 0, 0), 0);
    ExpectIntGT(wc_Curve448PublicKeyToDer(&curve448PrivKey, NULL, 0, 1), 0);
    ExpectIntGT(wc_Curve448PublicKeyToDer(&curve448PrivKey, output, inLen, 0),
        0);
    ExpectIntGT(wc_Curve448PublicKeyToDer(&curve448PrivKey, output, inLen, 1),
        0);

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_curve448_free(&curve448PrivKey);
#endif
    return EXPECT_RESULT();
} /* End wc_Curve448PrivateKeyToDer*/

/*
 * RFC 5958: private only path must create version=v1 (0). Curve448 has no
 * public API to create bundled key. Only test private key path. */
int test_wc_Curve448PrivateKeyToDer_oneasymkey_version(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE448) && defined(HAVE_CURVE448_KEY_EXPORT) && \
    defined(HAVE_CURVE448_KEY_IMPORT)
    curve448_key key;
    curve448_key key2;
    WC_RNG rng;
    byte ref[256];   /* reference DER (private only) */
    byte rt[256];    /* re-export target for memcmp */
    int  refSz = 0;
    int  rtSz = 0;
    word32 idx = 0;

    XMEMSET(&key,  0, sizeof(key));
    XMEMSET(&key2, 0, sizeof(key2));
    XMEMSET(&rng,  0, sizeof(rng));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_curve448_init(&key), 0);
    ExpectIntEQ(wc_curve448_init(&key2), 0);
    ExpectIntEQ(wc_curve448_make_key(&rng, CURVE448_KEY_SIZE, &key), 0);

    ExpectIntGT(refSz = wc_Curve448PrivateKeyToDer(&key, ref,
        (word32)sizeof(ref)), 0);
    ExpectIntEQ(test_pkcs8_get_version_byte(ref, (word32)refSz), 0);

    idx = 0;
    ExpectIntEQ(wc_Curve448PrivateKeyDecode(ref, &idx, &key2,
        (word32)refSz), 0);
    ExpectIntGT(rtSz = wc_Curve448PrivateKeyToDer(&key2, rt,
        (word32)sizeof(rt)), 0);
    ExpectIntEQ(rtSz, refSz);
    ExpectIntEQ(XMEMCMP(ref, rt, (size_t)refSz), 0);

    wc_curve448_free(&key);
    wc_curve448_free(&key2);
    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

/*
 * MC/DC decision coverage for wolfcrypt/src/curve448.c. Split into several
 * small functions (rather than one large one) to keep each function's own
 * locals small, matching the lesson learned on the ecc.c/curve25519.c MC/DC
 * waves (a single large function tripped a stack-corrupting crash under
 * -fcoverage-mcdc + -O0).
 */

/*
 * wc_curve448_make_pub argument-check decisions (never called directly by
 * the pre-existing tests): the (pub == NULL || priv == NULL) OR and the
 * (public_size != PUB || private_size != KEY) OR, each operand independently.
 */
int test_wc_curve448_make_pub_argchecks(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE448)
    curve448_key key;
    WC_RNG       rng;
    byte         pub[CURVE448_PUB_KEY_SIZE];

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    ExpectIntEQ(wc_curve448_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_curve448_make_key(&rng, CURVE448_KEY_SIZE, &key), 0);

    /* all-false: valid direct call. */
    ExpectIntEQ(wc_curve448_make_pub((int)sizeof(pub), pub,
        (int)sizeof(key.k), key.k), 0);
    /* pub == NULL || priv == NULL: each operand's TRUE side (the other
     * kept valid so the OR does not already short-circuit). */
    ExpectIntEQ(wc_curve448_make_pub((int)sizeof(pub), NULL,
        (int)sizeof(key.k), key.k), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_curve448_make_pub((int)sizeof(pub), pub,
        (int)sizeof(key.k), NULL), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    /* public_size != PUB || private_size != KEY: each operand's TRUE side. */
    ExpectIntEQ(wc_curve448_make_pub((int)sizeof(pub) - 1, pub,
        (int)sizeof(key.k), key.k), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_curve448_make_pub((int)sizeof(pub), pub,
        (int)sizeof(key.k) - 1, key.k), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_curve448_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_curve448_make_pub_argchecks */

/*
 * wc_curve448_check_public little-endian branch: NULL/size guards, the
 * (i == 0 && (pub[0] == 0 || pub[0] == 1)) low-value compound, the
 * (i == 28 && pub[28] == 0xff) order rejection, and the
 * (i == 28 && pub[28] == 0xfe) -> (i == 0 && pub[0] >= 0xfe) high-value
 * compound, plus their false sides.
 */
int test_wc_curve448_check_public_le(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE448) && defined(HAVE_CURVE448_KEY_IMPORT)
    byte buf[CURVE448_PUB_KEY_SIZE];

    /* pub == NULL. */
    ExpectIntEQ(wc_curve448_check_public(NULL, CURVE448_PUB_KEY_SIZE,
        EC448_LITTLE_ENDIAN), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* pubSz == 0. */
    ExpectIntEQ(wc_curve448_check_public(buf, 0, EC448_LITTLE_ENDIAN),
        WC_NO_ERR_TRACE(BUFFER_E));
    /* pubSz != CURVE448_PUB_KEY_SIZE. */
    ExpectIntEQ(wc_curve448_check_public(buf, CURVE448_PUB_KEY_SIZE - 1,
        EC448_LITTLE_ENDIAN), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));

    /* value == 0: i walks down to 0, pub[0] == 0. */
    XMEMSET(buf, 0, sizeof(buf));
    ExpectIntEQ(wc_curve448_check_public(buf, sizeof(buf),
        EC448_LITTLE_ENDIAN), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    /* value == 1: i walks down to 0, pub[0] == 1. */
    XMEMSET(buf, 0, sizeof(buf));
    buf[0] = 1;
    ExpectIntEQ(wc_curve448_check_public(buf, sizeof(buf),
        EC448_LITTLE_ENDIAN), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    /* i reaches 0 but pub[0] is neither 0 nor 1: low compound false side,
     * and a small value so the order checks also pass -> valid (0). */
    XMEMSET(buf, 0, sizeof(buf));
    buf[0] = 2;
    ExpectIntEQ(wc_curve448_check_public(buf, sizeof(buf),
        EC448_LITTLE_ENDIAN), 0);
    /* order-1 or higher: bytes 55..28 all 0xff -> loop stops at i == 28 with
     * pub[28] == 0xff -> reject. */
    XMEMSET(buf, 0xff, sizeof(buf));
    ExpectIntEQ(wc_curve448_check_public(buf, sizeof(buf),
        EC448_LITTLE_ENDIAN), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    /* pub[28] == 0xfe with the remaining low bytes all 0xff and
     * pub[0] >= 0xfe -> inner reject fires. */
    XMEMSET(buf, 0xff, sizeof(buf));
    buf[28] = 0xfe;
    ExpectIntEQ(wc_curve448_check_public(buf, sizeof(buf),
        EC448_LITTLE_ENDIAN), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    /* pub[28] == 0xfe but a lower byte breaks the 0xff run (pub[10] = 0), so
     * the inner ">= 0xfe at i == 0" reject does NOT fire: false side -> 0. */
    XMEMSET(buf, 0xff, sizeof(buf));
    buf[28] = 0xfe;
    buf[10] = 0x00;
    ExpectIntEQ(wc_curve448_check_public(buf, sizeof(buf),
        EC448_LITTLE_ENDIAN), 0);
    /* i still lands on 28 (bytes 55..29 all 0xff), but pub[28] is neither
     * 0xff nor 0xfe: independence pair (false side) for the "pub[28] ==
     * 0xfe" operand of the high-value compound -> no inner check, valid. */
    XMEMSET(buf, 0xff, sizeof(buf));
    buf[28] = 0x00;
    ExpectIntEQ(wc_curve448_check_public(buf, sizeof(buf),
        EC448_LITTLE_ENDIAN), 0);
    /* pub[28] == 0xfe (enters the inner check, i lands on 0 with the low
     * bytes still all 0xff) but pub[0] is below the 0xfe threshold:
     * independence pair (false side) for the inner "pub[0] >= 0xfe"
     * operand -> valid. */
    XMEMSET(buf, 0xff, sizeof(buf));
    buf[28] = 0xfe;
    buf[0] = 0x00;
    ExpectIntEQ(wc_curve448_check_public(buf, sizeof(buf),
        EC448_LITTLE_ENDIAN), 0);
#endif
    return EXPECT_RESULT();
} /* END test_wc_curve448_check_public_le */

/*
 * wc_curve448_check_public big-endian branch (the else-side mirror of the
 * little-endian decisions above).
 */
int test_wc_curve448_check_public_be(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE448) && defined(HAVE_CURVE448_KEY_IMPORT)
    byte buf[CURVE448_PUB_KEY_SIZE];

    /* value == 0: i walks up to SIZE-1, pub[SIZE-1] == 0. */
    XMEMSET(buf, 0, sizeof(buf));
    ExpectIntEQ(wc_curve448_check_public(buf, sizeof(buf),
        EC448_BIG_ENDIAN), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    /* value == 1: pub[SIZE-1] == 1. */
    XMEMSET(buf, 0, sizeof(buf));
    buf[CURVE448_PUB_KEY_SIZE - 1] = 1;
    ExpectIntEQ(wc_curve448_check_public(buf, sizeof(buf),
        EC448_BIG_ENDIAN), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    /* i reaches SIZE-1 but value neither 0 nor 1: low compound false -> 0. */
    XMEMSET(buf, 0, sizeof(buf));
    buf[CURVE448_PUB_KEY_SIZE - 1] = 2;
    ExpectIntEQ(wc_curve448_check_public(buf, sizeof(buf),
        EC448_BIG_ENDIAN), 0);
    /* order-1 or higher: bytes 0..27 all 0xff -> loop stops at i == 27 with
     * pub[27] == 0xff -> reject. */
    XMEMSET(buf, 0xff, sizeof(buf));
    ExpectIntEQ(wc_curve448_check_public(buf, sizeof(buf),
        EC448_BIG_ENDIAN), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    /* pub[27] == 0xfe, remaining tail all 0xff, pub[SIZE-1] >= 0xfe ->
     * inner reject fires. */
    XMEMSET(buf, 0xff, sizeof(buf));
    buf[27] = 0xfe;
    ExpectIntEQ(wc_curve448_check_public(buf, sizeof(buf),
        EC448_BIG_ENDIAN), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    /* pub[27] == 0xfe but a tail byte breaks the 0xff run (pub[54] = 0):
     * inner reject does NOT fire -> 0. */
    XMEMSET(buf, 0xff, sizeof(buf));
    buf[27] = 0xfe;
    buf[CURVE448_PUB_KEY_SIZE - 2] = 0x00;
    ExpectIntEQ(wc_curve448_check_public(buf, sizeof(buf),
        EC448_BIG_ENDIAN), 0);
    /* i still lands on 27 (bytes 0..26 all 0xff), but pub[27] is neither
     * 0xff nor 0xfe: independence pair (false side) for the "pub[27] ==
     * 0xfe" operand of the high-value compound -> no inner check, valid. */
    XMEMSET(buf, 0xff, sizeof(buf));
    buf[27] = 0x00;
    ExpectIntEQ(wc_curve448_check_public(buf, sizeof(buf),
        EC448_BIG_ENDIAN), 0);
    /* pub[27] == 0xfe (enters the inner check, i lands on SIZE-1 with the
     * tail still all 0xff) but pub[SIZE-1] is below the 0xfe threshold:
     * independence pair (false side) for the inner "pub[SIZE-1] >= 0xfe"
     * operand -> valid. */
    XMEMSET(buf, 0xff, sizeof(buf));
    buf[27] = 0xfe;
    buf[CURVE448_PUB_KEY_SIZE - 1] = 0x00;
    ExpectIntEQ(wc_curve448_check_public(buf, sizeof(buf),
        EC448_BIG_ENDIAN), 0);
#endif
    return EXPECT_RESULT();
} /* END test_wc_curve448_check_public_be */

/*
 * wc_curve448_shared_secret_ex populated-key compound decision:
 * (!private_key->privSet || !public_key->pubSet), each operand's TRUE side
 * individually against otherwise-valid, non-NULL key structs, plus the
 * little-endian output branch as the all-false side.
 */
int test_wc_curve448_shared_secret_keyset_checks(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE448) && defined(HAVE_CURVE448_SHARED_SECRET)
    curve448_key priv;
    curve448_key pub;
    curve448_key unset_priv;
    curve448_key unset_pub;
    WC_RNG       rng;
    byte         out[CURVE448_KEY_SIZE];
    word32       outLen;

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    ExpectIntEQ(wc_curve448_init(&priv), 0);
    ExpectIntEQ(wc_curve448_init(&pub), 0);
    ExpectIntEQ(wc_curve448_init(&unset_priv), 0);
    ExpectIntEQ(wc_curve448_init(&unset_pub), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_curve448_make_key(&rng, CURVE448_KEY_SIZE, &priv), 0);
    ExpectIntEQ(wc_curve448_make_key(&rng, CURVE448_KEY_SIZE, &pub), 0);

    /* !privSet TRUE (fresh unset_priv), pub valid. */
    outLen = sizeof(out);
    ExpectIntEQ(wc_curve448_shared_secret_ex(&unset_priv, &pub, out, &outLen,
        EC448_BIG_ENDIAN), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    /* !pubSet TRUE (fresh unset_pub), priv valid. */
    outLen = sizeof(out);
    ExpectIntEQ(wc_curve448_shared_secret_ex(&priv, &unset_pub, out, &outLen,
        EC448_BIG_ENDIAN), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    /* all-false: valid call, little-endian output branch. */
    outLen = sizeof(out);
    ExpectIntEQ(wc_curve448_shared_secret_ex(&priv, &pub, out, &outLen,
        EC448_LITTLE_ENDIAN), 0);

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_curve448_free(&priv);
    wc_curve448_free(&pub);
    wc_curve448_free(&unset_priv);
    wc_curve448_free(&unset_pub);
#endif
    return EXPECT_RESULT();
} /* END test_wc_curve448_shared_secret_keyset_checks */

/*
 * wc_curve448_import_public_ex argument checks: the (key == NULL || in ==
 * NULL) compound each operand, the inLen size check, and both endian
 * branches as the all-false side.
 */
int test_wc_curve448_import_public_ex_argchecks(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE448) && defined(HAVE_CURVE448_KEY_IMPORT)
    curve448_key key;
    byte         in[CURVE448_PUB_KEY_SIZE];

    XMEMSET(in, 7, sizeof(in));
    ExpectIntEQ(wc_curve448_init(&key), 0);

    /* key == NULL || in == NULL: each operand's TRUE side. */
    ExpectIntEQ(wc_curve448_import_public_ex(in, sizeof(in), NULL,
        EC448_LITTLE_ENDIAN), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve448_import_public_ex(NULL, sizeof(in), &key,
        EC448_LITTLE_ENDIAN), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* inLen != CURVE448_PUB_KEY_SIZE. */
    ExpectIntEQ(wc_curve448_import_public_ex(in, sizeof(in) - 1, &key,
        EC448_LITTLE_ENDIAN), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    /* all-false, both endians (LE XMEMCPY branch + BE byte-reverse loop). */
    ExpectIntEQ(wc_curve448_import_public_ex(in, sizeof(in), &key,
        EC448_LITTLE_ENDIAN), 0);
    ExpectIntEQ(wc_curve448_import_public_ex(in, sizeof(in), &key,
        EC448_BIG_ENDIAN), 0);
    ExpectIntEQ(wc_curve448_import_public(in, sizeof(in), &key), 0);

    wc_curve448_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_curve448_import_public_ex_argchecks */

/*
 * Little-endian export/import branches (the non-BIG_ENDIAN XMEMCPY sides of
 * wc_curve448_export_private_raw_ex/export_public_ex/import_private_ex) and
 * the wc_curve448_export_public_ex "!pubSet -> internal make_pub" branch.
 */
int test_wc_curve448_export_import_endian(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE448) && defined(HAVE_CURVE448_KEY_EXPORT) && \
    defined(HAVE_CURVE448_KEY_IMPORT)
    curve448_key key;
    curve448_key imp;
    WC_RNG       rng;
    byte         priv[CURVE448_KEY_SIZE] = {0};
    byte         pub[CURVE448_PUB_KEY_SIZE] = {0};
    word32       privSz = sizeof(priv);
    word32       pubSz = sizeof(pub);

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    ExpectIntEQ(wc_curve448_init(&key), 0);
    ExpectIntEQ(wc_curve448_init(&imp), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_curve448_make_key(&rng, CURVE448_KEY_SIZE, &key), 0);

    /* Little-endian export branches. */
    ExpectIntEQ(wc_curve448_export_private_raw_ex(&key, priv, &privSz,
        EC448_LITTLE_ENDIAN), 0);
    ExpectIntEQ(wc_curve448_export_public_ex(&key, pub, &pubSz,
        EC448_LITTLE_ENDIAN), 0);
    /* Little-endian import branch (+ clamp). */
    ExpectIntEQ(wc_curve448_import_private_ex(priv, privSz, &imp,
        EC448_LITTLE_ENDIAN), 0);

    /* export_public_ex with !pubSet: a private-only key forces the internal
     * wc_curve448_make_pub path that computes and sets key->p. */
    wc_curve448_free(&imp);
    ExpectIntEQ(wc_curve448_init(&imp), 0);
    ExpectIntEQ(wc_curve448_import_private_ex(priv, privSz, &imp,
        EC448_LITTLE_ENDIAN), 0);
    pubSz = sizeof(pub);
    ExpectIntEQ(wc_curve448_export_public_ex(&imp, pub, &pubSz,
        EC448_BIG_ENDIAN), 0);

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_curve448_free(&key);
    wc_curve448_free(&imp);
#endif
    return EXPECT_RESULT();
} /* END test_wc_curve448_export_import_endian */

