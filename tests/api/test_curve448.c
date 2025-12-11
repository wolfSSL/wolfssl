/* test_curve448.c
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
    byte         out[CURVE448_KEY_SIZE];
    word32       outLen = sizeof(out);
    int          endian = EC448_BIG_ENDIAN;

    ExpectIntEQ(wc_curve448_init(&key), 0);
    ExpectIntEQ(wc_curve448_export_private_raw_ex(&key, out, &outLen, endian),
        0);
    /* test bad cases */
    ExpectIntEQ(wc_curve448_export_private_raw_ex(NULL, NULL, NULL, endian),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve448_export_private_raw_ex(NULL, out, &outLen, endian),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve448_export_private_raw_ex(&key, NULL, &outLen, endian),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve448_export_private_raw_ex(&key, out, NULL, endian),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve448_export_private_raw_ex(&key, out, &outLen,
        EC448_LITTLE_ENDIAN), 0);
    outLen = outLen - 2;
    ExpectIntEQ(wc_curve448_export_private_raw_ex(&key, out, &outLen, endian),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));

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

