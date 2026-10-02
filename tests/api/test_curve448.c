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
#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
#endif
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
    curve448_key  unset;
    curve448_key  pubOnly;
    byte          out[CURVE448_KEY_SIZE];
    byte          pubOut[CURVE448_KEY_SIZE];
    word32        outLen = sizeof(out);
    word32        pubOutLen = sizeof(pubOut);
    int           endian = EC448_BIG_ENDIAN;

    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_curve448_init(&key), 0);
    ExpectIntEQ(wc_curve448_init(&unset), 0);
    ExpectIntEQ(wc_curve448_init(&pubOnly), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_curve448_make_key(&rng, CURVE448_KEY_SIZE, &key), 0);

    ExpectIntEQ(wc_curve448_export_public(&key, out, &outLen), 0);
    ExpectIntEQ(wc_curve448_export_public_ex(&key, out, &outLen, endian), 0);
    /* a key holding only a public component exports it unchanged */
    ExpectIntEQ(wc_curve448_import_public(out, outLen, &pubOnly), 0);
    ExpectIntEQ(wc_curve448_export_public_ex(&pubOnly, pubOut, &pubOutLen,
        endian), 0);
    ExpectIntEQ(pubOutLen, CURVE448_PUB_KEY_SIZE);
    ExpectIntEQ(XMEMCMP(out, pubOut, CURVE448_PUB_KEY_SIZE), 0);
    /* test bad cases */
    ExpectIntEQ(wc_curve448_export_public_ex(NULL, NULL, NULL, endian),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve448_export_public_ex(NULL, out, &outLen, endian),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve448_export_public_ex(&key, NULL, &outLen, endian),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve448_export_public_ex(&key, out, NULL, endian),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* no private or public key set to export */
    ExpectIntEQ(wc_curve448_export_public(&unset, out, &outLen),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_curve448_export_public_ex(&unset, out, &outLen, endian),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    outLen = outLen - 2;
    ExpectIntEQ(wc_curve448_export_public_ex(&key, out, &outLen, endian),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_curve448_free(&key);
    wc_curve448_free(&unset);
    wc_curve448_free(&pubOnly);
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
 * (i == 28 && pub[28] == 0xff) -> p+1 (non-canonical 1) rejection, and the
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
    /* 2^448-1: bytes 55..28 all 0xff -> loop stops at i == 28 with
     * pub[28] == 0xff. This is the non-canonical encoding of 2^224 and must
     * be accepted (RFC 7748 Section 5). */
    XMEMSET(buf, 0xff, sizeof(buf));
    ExpectIntEQ(wc_curve448_check_public(buf, sizeof(buf),
        EC448_LITTLE_ENDIAN), 0);
    /* p+1 = 2^448 - 2^224: pub[55..28] == 0xff, pub[27..0] == 0x00, the
     * non-canonical encoding of the low-order value 1 -> reject. */
    XMEMSET(buf, 0x00, sizeof(buf));
    XMEMSET(buf + 28, 0xff, sizeof(buf) - 28);
    ExpectIntEQ(wc_curve448_check_public(buf, sizeof(buf),
        EC448_LITTLE_ENDIAN), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    /* p+2: as p+1 with pub[0] == 1, non-canonical 2 -> accepted. */
    buf[0] = 0x01;
    ExpectIntEQ(wc_curve448_check_public(buf, sizeof(buf),
        EC448_LITTLE_ENDIAN), 0);
    /* p+1 shape but a middle byte breaks the zero run: not p+1 -> accepted. */
    buf[0] = 0x00;
    buf[10] = 0x01;
    ExpectIntEQ(wc_curve448_check_public(buf, sizeof(buf),
        EC448_LITTLE_ENDIAN), 0);
    /* p-1 = fe ff[27] fe ff[27]: the low-order point u = -1 -> reject. */
    XMEMSET(buf, 0xff, sizeof(buf));
    buf[28] = 0xfe;
    buf[0] = 0xfe;
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
    /* 2^448-1: bytes 0..27 all 0xff -> loop stops at i == 27 with
     * pub[27] == 0xff. Non-canonical encoding of 2^224 -> accepted. */
    XMEMSET(buf, 0xff, sizeof(buf));
    ExpectIntEQ(wc_curve448_check_public(buf, sizeof(buf),
        EC448_BIG_ENDIAN), 0);
    /* p+1: pub[0..27] == 0xff, pub[28..55] == 0x00 -> non-canonical 1,
     * reject. */
    XMEMSET(buf, 0xff, sizeof(buf));
    XMEMSET(buf + 28, 0x00, sizeof(buf) - 28);
    ExpectIntEQ(wc_curve448_check_public(buf, sizeof(buf),
        EC448_BIG_ENDIAN), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    /* p+2: as p+1 with pub[55] == 1 -> accepted. */
    buf[CURVE448_PUB_KEY_SIZE - 1] = 0x01;
    ExpectIntEQ(wc_curve448_check_public(buf, sizeof(buf),
        EC448_BIG_ENDIAN), 0);
    /* p+1 shape but a middle byte breaks the zero run -> accepted. */
    buf[CURVE448_PUB_KEY_SIZE - 1] = 0x00;
    buf[45] = 0x01;
    ExpectIntEQ(wc_curve448_check_public(buf, sizeof(buf),
        EC448_BIG_ENDIAN), 0);
    /* p-1: ff[27] fe ff[27] fe -> the low-order point u = -1, reject. */
    XMEMSET(buf, 0xff, sizeof(buf));
    buf[27] = 0xfe;
    buf[CURVE448_PUB_KEY_SIZE - 1] = 0xfe;
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

/* Cross-check make_pub, generic and keygen: public keys must match and a
 * shared secret must round trip. */
/* The keys are built with wc_curve448_init (INVALID_DEVID), so under CB-only
 * the software path is stripped and wc_curve448_make_key only dispatches when
 * WOLF_CRYPTO_CB_FIND can route to a registered device. */
int test_wc_curve448_make_pub_generic(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE448) && defined(HAVE_CURVE448_SHARED_SECRET) && \
    (!defined(WOLF_CRYPTO_CB_ONLY_CURVE448) || defined(WOLF_CRYPTO_CB_FIND))
    curve448_key keyA;
    curve448_key keyB;
    WC_RNG       rng;
    byte         pubM[CURVE448_PUB_KEY_SIZE];
    byte         pubG[CURVE448_PUB_KEY_SIZE];
    const byte   base5[CURVE448_KEY_SIZE] = { 5 };
    byte         genAB[CURVE448_PUB_KEY_SIZE];
    byte         ssAB[CURVE448_PUB_KEY_SIZE];
    byte         ssBA[CURVE448_PUB_KEY_SIZE];
    word32       ssABLen = (word32)sizeof(ssAB);
    word32       ssBALen = (word32)sizeof(ssBA);

    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_curve448_init(&keyA), 0);
    ExpectIntEQ(wc_curve448_init(&keyB), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);

    ExpectIntEQ(wc_curve448_make_key(&rng, CURVE448_KEY_SIZE, &keyA), 0);
    ExpectIntEQ(wc_curve448_make_key(&rng, CURVE448_KEY_SIZE, &keyB), 0);

    /* make_pub from the private scalar must match the keygen public point */
    ExpectIntEQ(wc_curve448_make_pub((int)sizeof(pubM), pubM,
        (int)sizeof(keyA.k), keyA.k), 0);
    ExpectBufEQ(pubM, keyA.p, CURVE448_PUB_KEY_SIZE);

    /* generic against base point 5 is the same operation as make_pub */
    ExpectIntEQ(wc_curve448_generic((int)sizeof(pubG), pubG,
        (int)sizeof(keyA.k), keyA.k, (int)sizeof(base5), base5), 0);
    ExpectBufEQ(pubG, pubM, CURVE448_PUB_KEY_SIZE);

    /* generic against B's public point must equal the A-B shared secret,
     * proving generic actually uses the supplied base point */
    ExpectIntEQ(wc_curve448_generic((int)sizeof(genAB), genAB,
        (int)sizeof(keyA.k), keyA.k, (int)sizeof(keyB.p), keyB.p), 0);
    ExpectIntEQ(wc_curve448_shared_secret_ex(&keyA, &keyB, ssAB, &ssABLen,
        EC448_LITTLE_ENDIAN), 0);
    ExpectBufEQ(genAB, ssAB, CURVE448_PUB_KEY_SIZE);

    /* shared secret must agree both ways, proving the generated keys are
     * mutually consistent (a degenerate result is rejected by shared_secret) */
    ExpectIntEQ(wc_curve448_shared_secret_ex(&keyB, &keyA, ssBA, &ssBALen,
        EC448_LITTLE_ENDIAN), 0);
    ExpectBufEQ(ssBA, ssAB, CURVE448_PUB_KEY_SIZE);

#ifndef WOLFSSL_NO_ECDHX_SHARED_ZERO_CHECK
    /* an all-zero result (small-order basepoint) must be rejected, matching
     * wc_curve448_shared_secret_ex */
    XMEMSET(pubG, 0, sizeof(pubG));
    {
        byte baseZero[CURVE448_KEY_SIZE];
        XMEMSET(baseZero, 0, sizeof(baseZero));
        ExpectIntEQ(wc_curve448_generic((int)sizeof(pubG), pubG,
            (int)sizeof(keyA.k), keyA.k, (int)sizeof(baseZero), baseZero),
            WC_NO_ERR_TRACE(ECC_OUT_OF_RANGE_E));
    }
#endif

    /* argument checks on the new generic API */
    ExpectIntEQ(wc_curve448_generic((int)sizeof(pubG), NULL,
        (int)sizeof(keyA.k), keyA.k, (int)sizeof(base5), base5),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_curve448_generic((int)sizeof(pubG), pubG,
        (int)sizeof(keyA.k), NULL, (int)sizeof(base5), base5),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_curve448_generic((int)sizeof(pubG), pubG,
        (int)sizeof(keyA.k), keyA.k, (int)sizeof(base5), NULL),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_curve448_generic((int)sizeof(pubG) - 1, pubG,
        (int)sizeof(keyA.k), keyA.k, (int)sizeof(base5), base5),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_curve448_generic((int)sizeof(pubG), pubG,
        (int)sizeof(keyA.k) - 1, keyA.k, (int)sizeof(base5), base5),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_curve448_generic((int)sizeof(pubG), pubG,
        (int)sizeof(keyA.k), keyA.k, (int)sizeof(base5) - 1, base5),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));

    /* unclamped scalars must be rejected: low bits set, then top bit clear */
    keyA.k[0] |= 0x01;
    ExpectIntEQ(wc_curve448_make_pub((int)sizeof(pubM), pubM,
        (int)sizeof(keyA.k), keyA.k), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_curve448_generic((int)sizeof(pubG), pubG,
        (int)sizeof(keyA.k), keyA.k, (int)sizeof(base5), base5),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    keyA.k[0] &= 0xfc;
    keyA.k[CURVE448_KEY_SIZE-1] &= 0x7f;
    ExpectIntEQ(wc_curve448_make_pub((int)sizeof(pubM), pubM,
        (int)sizeof(keyA.k), keyA.k), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_curve448_generic((int)sizeof(pubG), pubG,
        (int)sizeof(keyA.k), keyA.k, (int)sizeof(base5), base5),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    keyA.k[CURVE448_KEY_SIZE-1] |= 0x80;
    /* restored key must work again */
    ExpectIntEQ(wc_curve448_make_pub((int)sizeof(pubM), pubM,
        (int)sizeof(keyA.k), keyA.k), 0);

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_curve448_free(&keyA);
    wc_curve448_free(&keyB);
#endif
    return EXPECT_RESULT();
} /* END test_wc_curve448_make_pub_generic */

/* Test Curve448 keygen/shared secret routed through a crypto callback
 * (CryptoCb) device. */
/* The spy services ops by re-entering the software API, which is stripped
 * under CB-only unless WOLF_CRYPTO_CB_FIND can route back to a device. */
#if defined(WOLF_CRYPTO_CB) && defined(HAVE_CURVE448) && \
    defined(HAVE_CURVE448_SHARED_SECRET) && !defined(WC_NO_RNG) && \
    (!defined(WOLF_CRYPTO_CB_ONLY_CURVE448) || defined(WOLF_CRYPTO_CB_FIND))
typedef struct curve448SpyCtx {
    int kgSeen;
    int ssSeen;
    int mpSeen;
    int genSeen;
    int decline;
    int forceErr;
    int zeroSecret;
} curve448SpyCtx;

/* Spy device: services Curve448 keygen/shared secret in software (devId
 * cleared) and counts each; declines everything else. */
static int curve448_test_crypto_cb(int devIdArg, wc_CryptoInfo* info, void* ctx)
{
    curve448SpyCtx* spy = (curve448SpyCtx*)ctx;
    int ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);

    (void)devIdArg;

    if (info == NULL || spy == NULL) {
        return BAD_FUNC_ARG;
    }

    if (info->algo_type == WC_ALGO_TYPE_PK) {
        if (info->pk.type == WC_PK_TYPE_CURVE448_KEYGEN) {
            int save = info->pk.curve448kg.key->devId;
            spy->kgSeen++;
            if (spy->decline)
                return ret;
            if (spy->forceErr)
                return WC_NO_ERR_TRACE(WC_HW_E);
            info->pk.curve448kg.key->devId = INVALID_DEVID;
            ret = wc_curve448_make_key(info->pk.curve448kg.rng,
                info->pk.curve448kg.size, info->pk.curve448kg.key);
            info->pk.curve448kg.key->devId = save;
        }
        if (info->pk.type == WC_PK_TYPE_CURVE448_MAKE_PUB) {
            /* count, then decline so the software path produces the point */
            spy->mpSeen++;
        }
        if (info->pk.type == WC_PK_TYPE_CURVE448_GENERIC) {
            spy->genSeen++;
            if (spy->zeroSecret) {
                /* misbehaving device: all-zero point with success rc */
                XMEMSET(info->pk.curve448generic.pub, 0,
                    CURVE448_PUB_KEY_SIZE);
                return 0;
            }
            /* otherwise decline so the software path produces the point */
        }
        if (info->pk.type == WC_PK_TYPE_CURVE448) {
            int save = info->pk.curve448.private_key->devId;
            spy->ssSeen++;
            if (spy->decline)
                return ret;
            if (spy->forceErr)
                return WC_NO_ERR_TRACE(WC_HW_E);
            if (spy->zeroSecret) {
                /* misbehaving device: all-zero secret with success rc */
                XMEMSET(info->pk.curve448.out, 0, CURVE448_PUB_KEY_SIZE);
                *info->pk.curve448.outlen = CURVE448_PUB_KEY_SIZE;
                return 0;
            }
            info->pk.curve448.private_key->devId = INVALID_DEVID;
            ret = wc_curve448_shared_secret_ex(
                info->pk.curve448.private_key, info->pk.curve448.public_key,
                info->pk.curve448.out, info->pk.curve448.outlen,
                info->pk.curve448.endian);
            info->pk.curve448.private_key->devId = save;
        }
    }

    return ret;
}
#endif

int test_wc_curve448_cryptocb(void)
{
    EXPECT_DECLS;
#if defined(WOLF_CRYPTO_CB) && defined(HAVE_CURVE448) && \
    defined(HAVE_CURVE448_SHARED_SECRET) && !defined(WC_NO_RNG) && \
    (!defined(WOLF_CRYPTO_CB_ONLY_CURVE448) || defined(WOLF_CRYPTO_CB_FIND))
    int devId = 4485;
    curve448SpyCtx spy;
    WC_RNG rng;
    curve448_key keyB;
    byte   ssAB[CURVE448_PUB_KEY_SIZE];
    byte   ssBA[CURVE448_PUB_KEY_SIZE];
    word32 ssABLen = (word32)sizeof(ssAB);
    word32 ssBALen = (word32)sizeof(ssBA);
#ifndef WC_NO_CONSTRUCTORS
    int ret = 0;
    curve448_key* keyA = NULL;
#else
    curve448_key keyA_stack;
    curve448_key* keyA = &keyA_stack;
#endif

    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&spy, 0, sizeof(spy));

    ExpectIntEQ(wc_CryptoCb_RegisterDevice(devId, curve448_test_crypto_cb,
                &spy), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
#ifndef WC_NO_CONSTRUCTORS
    /* exercise the new constructor path */
    ExpectNotNull(keyA = wc_curve448_new(HEAP_HINT, devId, &ret));
    ExpectIntEQ(ret, 0);
#else
    ExpectIntEQ(wc_curve448_init_ex(keyA, HEAP_HINT, devId), 0);
#endif
    ExpectIntEQ(wc_curve448_init_ex(&keyB, HEAP_HINT, devId), 0);

    /* keygen routes through the device callback */
    if (keyA != NULL) {
        ExpectIntEQ(wc_curve448_make_key(&rng, CURVE448_KEY_SIZE, keyA), 0);
    }
    ExpectIntEQ(wc_curve448_make_key(&rng, CURVE448_KEY_SIZE, &keyB), 0);
    ExpectIntGE(spy.kgSeen, 2);

    /* shared secret routes through the device callback both ways */
    if (keyA != NULL) {
        ExpectIntEQ(wc_curve448_shared_secret_ex(keyA, &keyB, ssAB, &ssABLen,
            EC448_LITTLE_ENDIAN), 0);
        ExpectIntEQ(wc_curve448_shared_secret_ex(&keyB, keyA, ssBA, &ssBALen,
            EC448_LITTLE_ENDIAN), 0);
        ExpectBufEQ(ssAB, ssBA, CURVE448_PUB_KEY_SIZE);
    }
    ExpectIntGE(spy.ssSeen, 2);

#ifndef WOLF_CRYPTO_CB_ONLY_CURVE448
    /* device declines: dispatch is seen, software fallback must succeed */
    spy.decline = 1;
    ExpectIntEQ(wc_curve448_make_key(&rng, CURVE448_KEY_SIZE, &keyB), 0);
    ExpectIntGE(spy.kgSeen, 3);
    if (keyA != NULL) {
        ssABLen = (word32)sizeof(ssAB);
        ExpectIntEQ(wc_curve448_shared_secret_ex(keyA, &keyB, ssAB, &ssABLen,
            EC448_LITTLE_ENDIAN), 0);
    }
    ExpectIntGE(spy.ssSeen, 3);
    spy.decline = 0;
#endif

    /* device errors: the error must propagate, not fall back to software */
    spy.forceErr = 1;
    ExpectIntEQ(wc_curve448_make_key(&rng, CURVE448_KEY_SIZE, &keyB),
        WC_NO_ERR_TRACE(WC_HW_E));
    if (keyA != NULL) {
        ssABLen = (word32)sizeof(ssAB);
        ExpectIntEQ(wc_curve448_shared_secret_ex(keyA, &keyB, ssAB, &ssABLen,
            EC448_LITTLE_ENDIAN), WC_NO_ERR_TRACE(WC_HW_E));
    }
    spy.forceErr = 0;

#ifndef WOLFSSL_NO_ECDHX_SHARED_ZERO_CHECK
    /* device returns an all-zero secret: wrapper must reject it */
    spy.zeroSecret = 1;
    if (keyA != NULL) {
        ssABLen = (word32)sizeof(ssAB);
        ExpectIntEQ(wc_curve448_shared_secret_ex(keyA, &keyB, ssAB, &ssABLen,
            EC448_LITTLE_ENDIAN), WC_NO_ERR_TRACE(ECC_OUT_OF_RANGE_E));
    }
    spy.zeroSecret = 0;
#endif

#if !defined(WOLF_CRYPTO_CB_FIND) && !defined(WOLF_CRYPTO_CB_ONLY_CURVE448)
    /* a key bound to no device must not have its private scalar handed to
     * whichever device happens to be registered: keygen derives the public
     * point in software without dispatching make_pub */
    {
        curve448_key unbound;
        byte pubTmp[CURVE448_PUB_KEY_SIZE];
        int mpBefore = spy.mpSeen;

        XMEMSET(&unbound, 0, sizeof(unbound));
        ExpectIntEQ(wc_curve448_init(&unbound), 0);
        ExpectIntEQ(wc_curve448_make_key(&rng, CURVE448_KEY_SIZE, &unbound),
            0);
        ExpectIntEQ(spy.mpSeen, mpBefore);
        /* the keyless public API has no devId to respect, so it still
         * reaches the device */
        ExpectIntEQ(wc_curve448_make_pub((int)sizeof(pubTmp), pubTmp,
            (int)sizeof(unbound.k), unbound.k), 0);
        ExpectIntGT(spy.mpSeen, mpBefore);

        /* wc_curve448_generic also has no devId to respect, so it reaches
         * the device; a device that answers with an all-zero point must be
         * rejected just like the software path's small-order result */
        {
            const byte base5[CURVE448_KEY_SIZE] = { 5 };
            int genBefore = spy.genSeen;

            ExpectIntEQ(wc_curve448_generic((int)sizeof(pubTmp), pubTmp,
                (int)sizeof(unbound.k), unbound.k, (int)sizeof(base5),
                base5), 0);
            ExpectIntGT(spy.genSeen, genBefore);
#ifndef WOLFSSL_NO_ECDHX_SHARED_ZERO_CHECK
            spy.zeroSecret = 1;
            ExpectIntEQ(wc_curve448_generic((int)sizeof(pubTmp), pubTmp,
                (int)sizeof(unbound.k), unbound.k, (int)sizeof(base5),
                base5), WC_NO_ERR_TRACE(ECC_OUT_OF_RANGE_E));
            spy.zeroSecret = 0;
#endif
        }
        wc_curve448_free(&unbound);
    }
#endif

    /* constructor arg checks */
    ExpectIntEQ(wc_curve448_init_ex(NULL, HEAP_HINT, devId),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_curve448_free(&keyB);
#ifndef WC_NO_CONSTRUCTORS
    /* result_code and key_p are both optional */
    {
        curve448_key* keyC = NULL;
        ExpectNotNull(keyC = wc_curve448_new(HEAP_HINT, devId, NULL));
        if (keyC != NULL) {
            DoExpectIntEQ(wc_curve448_delete(keyC, NULL), 0);
        }
    }
    if (keyA != NULL) {
        DoExpectIntEQ(wc_curve448_delete(keyA, &keyA), 0);
        ExpectNull(keyA);
    }
    ExpectIntEQ(wc_curve448_delete(NULL, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#else
    wc_curve448_free(keyA);
#endif
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_CryptoCb_UnRegisterDevice(devId);
#endif
    return EXPECT_RESULT();
} /* END test_wc_curve448_cryptocb */



/*
 * Non-canonical X448 public values (RFC 7748 Section 5): u in [p, 2^448-1],
 * p = 2^448 - 2^224 - 1, must be accepted and processed as if reduced
 * modulo p. Private key: RFC 7748 Section 6.2 Alice. Peer u = p+2, p+5 and
 * 2^448-1, the non-canonical encodings of 2, 5 and 2^224. Expected shared
 * secrets computed with OpenSSL 3.6.3 (pkeyutl -derive); the results must
 * also equal those for the canonical encodings. Finally the low-order points
 * 1, p-1, p and p+1 must never yield a shared secret.
 */
int test_wc_curve448_shared_secret_noncanonical_kat(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE448) && defined(HAVE_CURVE448_KEY_IMPORT) && \
    defined(HAVE_CURVE448_SHARED_SECRET)
    static const byte kPriv[CURVE448_KEY_SIZE] = {
        0x9a,0x8f,0x49,0x25,0xd1,0x51,0x9f,0x57,
        0x75,0xcf,0x46,0xb0,0x4b,0x58,0x00,0xd4,
        0xee,0x9e,0xe8,0xba,0xe8,0xbc,0x55,0x65,
        0xd4,0x98,0xc2,0x8d,0xd9,0xc9,0xba,0xf5,
        0x74,0xa9,0x41,0x97,0x44,0x89,0x73,0x91,
        0x00,0x63,0x82,0xa6,0xf1,0x27,0xab,0x1d,
        0x9a,0xc2,0xd8,0xc0,0xa5,0x98,0x72,0x6b
    };
    /* Non-canonical encodings (little-endian). */
    static const byte kPubNC[3][CURVE448_PUB_KEY_SIZE] = {
        { /* p + 2 */
            0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
        },
        { /* p + 5 */
            0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
        },
        { /* 2^448 - 1 */
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
        }
    };
    /* Canonical encodings of the same values: 2, 5 and 2^224. */
    static const byte kPubC[3][CURVE448_PUB_KEY_SIZE] = {
        {
            0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        },
        {
            0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        },
        {
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        }
    };
    static const byte kExpected[3][CURVE448_PUB_KEY_SIZE] = {
        {
            0x6c,0xbd,0xf8,0x29,0x07,0xd2,0xa3,0xf3,
            0xbd,0x7a,0x48,0x68,0xac,0x6a,0xe3,0x54,
            0xf9,0x7d,0x60,0xc4,0x78,0xfc,0xac,0x33,
            0x38,0x9f,0xea,0xb9,0xf0,0x22,0xa2,0x6c,
            0xcd,0x71,0x64,0xa2,0xfb,0x9c,0xfb,0x2b,
            0x74,0x07,0xa9,0x24,0xc6,0x26,0x26,0xf7,
            0x38,0xa6,0x28,0x69,0xf7,0x17,0xdf,0xad
        },
        {
            0x9b,0x08,0xf7,0xcc,0x31,0xb7,0xe3,0xe6,
            0x7d,0x22,0xd5,0xae,0xa1,0x21,0x07,0x4a,
            0x27,0x3b,0xd2,0xb8,0x3d,0xe0,0x9c,0x63,
            0xfa,0xa7,0x3d,0x2c,0x22,0xc5,0xd9,0xbb,
            0xc8,0x36,0x64,0x72,0x41,0xd9,0x53,0xd4,
            0x0c,0x5b,0x12,0xda,0x88,0x12,0x0d,0x53,
            0x17,0x7f,0x80,0xe5,0x32,0xc4,0x1f,0xa0
        },
        {
            0x66,0xe2,0xe6,0x82,0xb1,0xf8,0xe6,0x8c,
            0x80,0x9f,0x1b,0xb3,0xe4,0x06,0xbd,0x82,
            0x69,0x21,0xd9,0xc1,0xa5,0xbf,0xbf,0xcb,
            0xab,0x7a,0xe7,0x2f,0xee,0xce,0xe6,0x36,
            0x60,0xea,0xbd,0x54,0x93,0x4f,0x33,0x82,
            0x06,0x1d,0x17,0x60,0x7f,0x58,0x1a,0x90,
            0xbd,0xac,0x91,0x7a,0x06,0x49,0x59,0xfb
        }
    };
    /* Low-order points: 1, p-1 (u = -1), p (== 0), p+1 (== 1). */
    static const byte kLow[4][CURVE448_PUB_KEY_SIZE] = {
        {
            0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        },
        {
            0xfe,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
            0xff,0xff,0xff,0xff,0xfe,0xff,0xff,0xff,
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
        },
        {
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
            0xff,0xff,0xff,0xff,0xfe,0xff,0xff,0xff,
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
        },
        {
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
        }
    };
    curve448_key private_key;
    curve448_key public_key;
    byte         out[CURVE448_PUB_KEY_SIZE];
    byte         outCanon[CURVE448_PUB_KEY_SIZE];
    word32       outLen;
    int          i;

    ExpectIntEQ(wc_curve448_init(&private_key), 0);
    ExpectIntEQ(wc_curve448_init(&public_key), 0);
    ExpectIntEQ(wc_curve448_import_private_ex(kPriv, sizeof(kPriv),
        &private_key, EC448_LITTLE_ENDIAN), 0);

    for (i = 0; i < 3; i++) {
        ExpectIntEQ(wc_curve448_check_public(kPubNC[i], CURVE448_PUB_KEY_SIZE,
            EC448_LITTLE_ENDIAN), 0);
        ExpectIntEQ(wc_curve448_import_public_ex(kPubNC[i],
            CURVE448_PUB_KEY_SIZE, &public_key, EC448_LITTLE_ENDIAN), 0);
        outLen = sizeof(out);
        XMEMSET(out, 0, sizeof(out));
        ExpectIntEQ(wc_curve448_shared_secret_ex(&private_key, &public_key,
            out, &outLen, EC448_LITTLE_ENDIAN), 0);
        ExpectIntEQ(outLen, CURVE448_PUB_KEY_SIZE);
        ExpectBufEQ(out, kExpected[i], CURVE448_PUB_KEY_SIZE);

        ExpectIntEQ(wc_curve448_check_public(kPubC[i], CURVE448_PUB_KEY_SIZE,
            EC448_LITTLE_ENDIAN), 0);
        ExpectIntEQ(wc_curve448_import_public_ex(kPubC[i],
            CURVE448_PUB_KEY_SIZE, &public_key, EC448_LITTLE_ENDIAN), 0);
        outLen = sizeof(outCanon);
        XMEMSET(outCanon, 0, sizeof(outCanon));
        ExpectIntEQ(wc_curve448_shared_secret_ex(&private_key, &public_key,
            outCanon, &outLen, EC448_LITTLE_ENDIAN), 0);
        ExpectBufEQ(outCanon, out, CURVE448_PUB_KEY_SIZE);
    }

    for (i = 0; i < 4; i++) {
        ExpectIntEQ(wc_curve448_check_public(kLow[i], CURVE448_PUB_KEY_SIZE,
            EC448_LITTLE_ENDIAN), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
#ifndef WOLFSSL_NO_ECDHX_SHARED_ZERO_CHECK
        ExpectIntEQ(wc_curve448_import_public_ex(kLow[i],
            CURVE448_PUB_KEY_SIZE, &public_key, EC448_LITTLE_ENDIAN), 0);
        outLen = sizeof(out);
        ExpectIntEQ(wc_curve448_shared_secret_ex(&private_key, &public_key,
            out, &outLen, EC448_LITTLE_ENDIAN),
            WC_NO_ERR_TRACE(ECC_OUT_OF_RANGE_E));
#endif
    }

    wc_curve448_free(&private_key);
    wc_curve448_free(&public_key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_curve448_shared_secret_noncanonical_kat */
