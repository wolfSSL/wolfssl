/* test_curve25519.c
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

#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_curve25519.h>


/*
 * Testing wc_curve25519_init and wc_curve25519_free.
 */
int test_wc_curve25519_init(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE25519)
    curve25519_key key;

    ExpectIntEQ(wc_curve25519_init(&key), 0);
    /* Test bad args for wc_curve25519_init */
    ExpectIntEQ(wc_curve25519_init(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test good args for wc_curve_25519_free */
    wc_curve25519_free(&key);
    /* Test bad args for wc_curve25519 free. */
    wc_curve25519_free(NULL);
#endif
    return EXPECT_RESULT();
} /* END test_wc_curve25519_init and wc_curve_25519_free */
/*
 * Testing test_wc_curve25519_size.
 */
int test_wc_curve25519_size(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE25519)
    curve25519_key key;

    ExpectIntEQ(wc_curve25519_init(&key), 0);

    /* Test good args for wc_curve25519_size */
    ExpectIntEQ(wc_curve25519_size(&key), CURVE25519_KEYSIZE);
    /* Test bad args for wc_curve25519_size */
    ExpectIntEQ(wc_curve25519_size(NULL), 0);

    wc_curve25519_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_curve25519_size */

/*
 * Testing test_wc_curve25519_export_key_raw().
 */
int test_wc_curve25519_export_key_raw(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE25519) && defined(HAVE_CURVE25519_KEY_EXPORT)
    curve25519_key key;
    WC_RNG         rng;
    byte           privateKey[CURVE25519_KEYSIZE];
    byte           publicKey[CURVE25519_KEYSIZE];
    word32         prvkSz;
    word32         pubkSz;
    byte           prik[CURVE25519_KEYSIZE];
    byte           pubk[CURVE25519_KEYSIZE];
    word32         prksz;
    word32         pbksz;

    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_curve25519_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &key), 0);

    /* bad-argument-test cases - target function should return BAD_FUNC_ARG */
    prvkSz = CURVE25519_KEYSIZE;
    pubkSz = CURVE25519_KEYSIZE;
    ExpectIntEQ(wc_curve25519_export_key_raw(NULL, privateKey, &prvkSz,
        publicKey, &pubkSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    prvkSz = CURVE25519_KEYSIZE;
    pubkSz = CURVE25519_KEYSIZE;
    ExpectIntEQ(wc_curve25519_export_key_raw(&key, NULL, &prvkSz, publicKey,
        &pubkSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    prvkSz = CURVE25519_KEYSIZE;
    pubkSz = CURVE25519_KEYSIZE;
    ExpectIntEQ(wc_curve25519_export_key_raw(&key, privateKey, NULL,
        publicKey, &pubkSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* prvkSz = CURVE25519_KEYSIZE; */
    pubkSz = CURVE25519_KEYSIZE;
    ExpectIntEQ(wc_curve25519_export_key_raw(&key, privateKey, &prvkSz,
        NULL, &pubkSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    prvkSz = CURVE25519_KEYSIZE;
    pubkSz = CURVE25519_KEYSIZE;
    ExpectIntEQ(wc_curve25519_export_key_raw(&key, privateKey, &prvkSz,
        publicKey, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* cross-testing */
    prksz = CURVE25519_KEYSIZE;
    ExpectIntEQ(wc_curve25519_export_private_raw(&key, prik, &prksz), 0);
    pbksz = CURVE25519_KEYSIZE;
    ExpectIntEQ(wc_curve25519_export_public(&key, pubk, &pbksz), 0);
    prvkSz = CURVE25519_KEYSIZE;
    /* pubkSz = CURVE25519_KEYSIZE; */
    ExpectIntEQ(wc_curve25519_export_key_raw(&key, privateKey, &prvkSz,
        publicKey,  &pubkSz), 0);
    ExpectIntEQ(prksz, CURVE25519_KEYSIZE);
    ExpectIntEQ(pbksz, CURVE25519_KEYSIZE);
    ExpectIntEQ(prvkSz, CURVE25519_KEYSIZE);
    ExpectIntEQ(pubkSz, CURVE25519_KEYSIZE);
    ExpectIntEQ(XMEMCMP(privateKey, prik, CURVE25519_KEYSIZE), 0);
    ExpectIntEQ(XMEMCMP(publicKey,  pubk, CURVE25519_KEYSIZE), 0);

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_curve25519_free(&key);
#endif
    return EXPECT_RESULT();
} /* end of test_wc_curve25519_export_key_raw */

/*
 * Testing test_wc_curve25519_export_key_raw_ex().
 */
int test_wc_curve25519_export_key_raw_ex(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE25519) && defined(HAVE_CURVE25519_KEY_EXPORT)
    curve25519_key key;
    WC_RNG         rng;
    byte           privateKey[CURVE25519_KEYSIZE];
    byte           publicKey[CURVE25519_KEYSIZE];
    word32         prvkSz;
    word32         pubkSz;
    byte           prik[CURVE25519_KEYSIZE];
    byte           pubk[CURVE25519_KEYSIZE];
    word32         prksz;
    word32         pbksz;

    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_curve25519_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &key), 0);

    /* bad-argument-test cases - target function should return BAD_FUNC_ARG */
    prvkSz = CURVE25519_KEYSIZE;
    pubkSz = CURVE25519_KEYSIZE;
    ExpectIntEQ(wc_curve25519_export_key_raw_ex(NULL, privateKey,
        &prvkSz, publicKey, &pubkSz, EC25519_LITTLE_ENDIAN),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    prvkSz = CURVE25519_KEYSIZE;
    pubkSz = CURVE25519_KEYSIZE;
    ExpectIntEQ(wc_curve25519_export_key_raw_ex(&key, NULL,
        &prvkSz, publicKey, &pubkSz, EC25519_LITTLE_ENDIAN),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    prvkSz = CURVE25519_KEYSIZE;
    pubkSz = CURVE25519_KEYSIZE;
    ExpectIntEQ(wc_curve25519_export_key_raw_ex(&key, privateKey,
        NULL, publicKey, &pubkSz, EC25519_LITTLE_ENDIAN),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* prvkSz = CURVE25519_KEYSIZE; */
    pubkSz = CURVE25519_KEYSIZE;
    ExpectIntEQ(wc_curve25519_export_key_raw_ex(&key, privateKey,
        &prvkSz, NULL, &pubkSz, EC25519_LITTLE_ENDIAN),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    prvkSz = CURVE25519_KEYSIZE;
    pubkSz = CURVE25519_KEYSIZE;
    ExpectIntEQ(wc_curve25519_export_key_raw_ex(&key, privateKey,
        &prvkSz, publicKey, NULL, EC25519_LITTLE_ENDIAN),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    prvkSz = CURVE25519_KEYSIZE;
    /* pubkSz = CURVE25519_KEYSIZE; */
    ExpectIntEQ(wc_curve25519_export_key_raw_ex(NULL, privateKey,
        &prvkSz, publicKey, &pubkSz, EC25519_BIG_ENDIAN),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    prvkSz = CURVE25519_KEYSIZE;
    pubkSz = CURVE25519_KEYSIZE;
    ExpectIntEQ(wc_curve25519_export_key_raw_ex(&key, NULL,
        &prvkSz, publicKey, &pubkSz, EC25519_BIG_ENDIAN),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    prvkSz = CURVE25519_KEYSIZE;
    pubkSz = CURVE25519_KEYSIZE;
    ExpectIntEQ(wc_curve25519_export_key_raw_ex(&key, privateKey,
        NULL, publicKey, &pubkSz, EC25519_BIG_ENDIAN),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* prvkSz = CURVE25519_KEYSIZE; */
    pubkSz = CURVE25519_KEYSIZE;
    ExpectIntEQ(wc_curve25519_export_key_raw_ex(&key, privateKey,
        &prvkSz, NULL, &pubkSz, EC25519_BIG_ENDIAN),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    prvkSz = CURVE25519_KEYSIZE;
    pubkSz = CURVE25519_KEYSIZE;
    ExpectIntEQ(wc_curve25519_export_key_raw_ex(&key, privateKey,
        &prvkSz, publicKey, NULL, EC25519_BIG_ENDIAN),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* illegal value for endian */
    prvkSz = CURVE25519_KEYSIZE;
    /* pubkSz = CURVE25519_KEYSIZE; */
    ExpectIntEQ(wc_curve25519_export_key_raw_ex(&key, privateKey, &prvkSz,
        publicKey, NULL, EC25519_BIG_ENDIAN + 10),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* cross-testing */
    prksz = CURVE25519_KEYSIZE;
    ExpectIntEQ(wc_curve25519_export_private_raw( &key, prik, &prksz), 0);
    pbksz = CURVE25519_KEYSIZE;
    ExpectIntEQ(wc_curve25519_export_public( &key, pubk, &pbksz), 0);
    prvkSz = CURVE25519_KEYSIZE;
    /* pubkSz = CURVE25519_KEYSIZE; */
    ExpectIntEQ(wc_curve25519_export_key_raw_ex(&key, privateKey, &prvkSz,
        publicKey, &pubkSz, EC25519_BIG_ENDIAN), 0);
    ExpectIntEQ(prksz, CURVE25519_KEYSIZE);
    ExpectIntEQ(pbksz, CURVE25519_KEYSIZE);
    ExpectIntEQ(prvkSz, CURVE25519_KEYSIZE);
    ExpectIntEQ(pubkSz, CURVE25519_KEYSIZE);
    ExpectIntEQ(XMEMCMP(privateKey, prik, CURVE25519_KEYSIZE), 0);
    ExpectIntEQ(XMEMCMP(publicKey,  pubk, CURVE25519_KEYSIZE), 0);
    ExpectIntEQ(wc_curve25519_export_key_raw_ex(&key, privateKey, &prvkSz,
        publicKey, &pubkSz, EC25519_LITTLE_ENDIAN), 0);
    ExpectIntEQ(prvkSz, CURVE25519_KEYSIZE);
    ExpectIntEQ(pubkSz, CURVE25519_KEYSIZE);

    /* try once with another endian */
    prvkSz = CURVE25519_KEYSIZE;
    pubkSz = CURVE25519_KEYSIZE;
    ExpectIntEQ(wc_curve25519_export_key_raw_ex( &key, privateKey, &prvkSz,
        publicKey, &pubkSz, EC25519_BIG_ENDIAN), 0);
    ExpectIntEQ(prvkSz, CURVE25519_KEYSIZE);
    ExpectIntEQ(pubkSz, CURVE25519_KEYSIZE);

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_curve25519_free(&key);
#endif
    return EXPECT_RESULT();
} /* end of test_wc_curve25519_export_key_raw_ex */

/*
 * Testing wc_curve25519_make_key
 */
int test_wc_curve25519_make_key(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE25519)
    curve25519_key key;
    WC_RNG         rng;
    int            keysize = 0;

    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_curve25519_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);

    ExpectIntEQ(wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &key), 0);
    ExpectIntEQ(keysize = wc_curve25519_size(&key), CURVE25519_KEYSIZE);
    ExpectIntEQ(wc_curve25519_make_key(&rng, keysize, &key), 0);
    /* test bad cases */
    ExpectIntEQ(wc_curve25519_make_key(NULL, 0, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve25519_make_key(&rng, keysize, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve25519_make_key(NULL, keysize, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve25519_make_key(&rng, 0, &key),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_curve25519_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_curve25519_make_key */

/*
 * Testing wc_curve25519_shared_secret_ex
 */
int test_wc_curve25519_shared_secret_ex(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE25519)
    curve25519_key private_key;
    curve25519_key public_key;
    WC_RNG         rng;
    byte           out[CURVE25519_KEYSIZE];
    word32         outLen = sizeof(out);
    int            endian = EC25519_BIG_ENDIAN;

    ExpectIntEQ(wc_curve25519_init(&private_key), 0);
#ifdef WOLFSSL_CURVE25519_BLINDING
    ExpectIntEQ(wc_curve25519_set_rng(&private_key, &rng), 0);
#endif
    ExpectIntEQ(wc_curve25519_init(&public_key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);

    ExpectIntEQ(wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &private_key),
        0);
    ExpectIntEQ(wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &public_key),
        0);

    ExpectIntEQ(wc_curve25519_shared_secret_ex(&private_key, &public_key, out,
        &outLen, endian), 0);

    /* test bad cases */
    ExpectIntEQ(wc_curve25519_shared_secret_ex(NULL, NULL, NULL, 0, endian),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve25519_shared_secret_ex(NULL, &public_key, out, &outLen,
        endian), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve25519_shared_secret_ex(&private_key, NULL, out, &outLen,
        endian), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve25519_shared_secret_ex(&private_key, &public_key, NULL,
        &outLen, endian), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve25519_shared_secret_ex(&private_key, &public_key, out,
        NULL, endian), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* curve25519.c is checking for public_key size less than or equal to 0x7f,
     * increasing to 0x8f checks for error being returned */
    public_key.p.point[CURVE25519_KEYSIZE-1] = 0x8F;
    ExpectIntEQ(wc_curve25519_shared_secret_ex(&private_key, &public_key, out,
        &outLen, endian), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));

    outLen = outLen - 2;
    ExpectIntEQ(wc_curve25519_shared_secret_ex(&private_key, &public_key, out,
        &outLen, endian), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_curve25519_free(&private_key);
    wc_curve25519_free(&public_key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_curve25519_shared_secret_ex */

/*
 * Testing wc_curve25519_make_pub
 */
int test_wc_curve25519_make_pub(void)
{
    EXPECT_DECLS;
#ifdef HAVE_CURVE25519
    curve25519_key key;
    WC_RNG         rng;
    byte           out[CURVE25519_KEYSIZE];

    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_curve25519_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &key), 0);

    ExpectIntEQ(wc_curve25519_make_pub((int)sizeof(out), out,
        (int)sizeof(key.k), key.k), 0);
    /* test bad cases */
    ExpectIntEQ(wc_curve25519_make_pub((int)sizeof(key.k) - 1, key.k,
        (int)sizeof out, out), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_curve25519_make_pub((int)sizeof out, out, (int)sizeof(key.k),
        NULL), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_curve25519_make_pub((int)sizeof out - 1, out,
        (int)sizeof(key.k), key.k), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_curve25519_make_pub((int)sizeof out, NULL,
        (int)sizeof(key.k), key.k), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    /* verify clamping test */
    key.k[0] |= ~248;
    ExpectIntEQ(wc_curve25519_make_pub((int)sizeof out, out, (int)sizeof(key.k),
        key.k), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    key.k[0] &= 248;
    /* repeat the expected-to-succeed test. */
    ExpectIntEQ(wc_curve25519_make_pub((int)sizeof out, out, (int)sizeof(key.k),
        key.k), 0);

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_curve25519_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_curve25519_make_pub */

/*
 * Testing test_wc_curve25519_export_public_ex
 */
int test_wc_curve25519_export_public_ex(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE25519)
    curve25519_key key;
    WC_RNG         rng;
    byte           out[CURVE25519_KEYSIZE];
    word32         outLen = sizeof(out);
    int            endian = EC25519_BIG_ENDIAN;

    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_curve25519_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &key), 0);

    ExpectIntEQ(wc_curve25519_export_public(&key, out, &outLen), 0);
    ExpectIntEQ(wc_curve25519_export_public_ex(&key, out, &outLen, endian), 0);
    /* test bad cases */
    ExpectIntEQ(wc_curve25519_export_public_ex(NULL, NULL, NULL, endian),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve25519_export_public_ex(NULL, out, &outLen, endian),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve25519_export_public_ex(&key, NULL, &outLen, endian),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve25519_export_public_ex(&key, out, NULL, endian),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    outLen = outLen - 2;
    ExpectIntEQ(wc_curve25519_export_public_ex(&key, out, &outLen, endian),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_curve25519_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_curve25519_export_public_ex */

/*
 * Testing test_wc_curve25519_export_private_raw_ex
 */
int test_wc_curve25519_export_private_raw_ex(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE25519)
    curve25519_key key;
    byte           out[CURVE25519_KEYSIZE];
    word32         outLen = sizeof(out);
    int            endian = EC25519_BIG_ENDIAN;

    ExpectIntEQ(wc_curve25519_init(&key), 0);

    ExpectIntEQ(wc_curve25519_export_private_raw_ex(&key, out, &outLen, endian),
        0);
    /* test bad cases */
    ExpectIntEQ(wc_curve25519_export_private_raw_ex(NULL, NULL, NULL, endian),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve25519_export_private_raw_ex(NULL, out, &outLen, endian),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve25519_export_private_raw_ex(&key, NULL, &outLen,
        endian), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve25519_export_private_raw_ex(&key, out, NULL, endian),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve25519_export_private_raw_ex(&key, out, &outLen,
        EC25519_LITTLE_ENDIAN), 0);
    outLen = outLen - 2;
    ExpectIntEQ(wc_curve25519_export_private_raw_ex(&key, out, &outLen, endian),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));

    wc_curve25519_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_curve25519_export_private_raw_ex */

/*
 * Testing test_wc_curve25519_import_private_raw_ex
 */
int test_wc_curve25519_import_private_raw_ex(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE25519)
    curve25519_key key;
    WC_RNG         rng;
    byte           priv[CURVE25519_KEYSIZE];
    byte           pub[CURVE25519_KEYSIZE];
    word32         privSz = sizeof(priv);
    word32         pubSz = sizeof(pub);
    int            endian = EC25519_BIG_ENDIAN;

    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_curve25519_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &key), 0);

    ExpectIntEQ(wc_curve25519_export_private_raw_ex(&key, priv, &privSz,
        endian), 0);
    ExpectIntEQ(wc_curve25519_export_public(&key, pub, &pubSz), 0);
    ExpectIntEQ(wc_curve25519_import_private_raw_ex(priv, privSz, pub, pubSz,
        &key, endian), 0);
    /* test bad cases */
    ExpectIntEQ(wc_curve25519_import_private_raw_ex(NULL, 0, NULL, 0, NULL,
        endian), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve25519_import_private_raw_ex(NULL, privSz, pub, pubSz,
        &key, endian), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve25519_import_private_raw_ex(priv, privSz, NULL, pubSz,
        &key, endian), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve25519_import_private_raw_ex(priv, privSz, pub, pubSz,
        NULL, endian), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve25519_import_private_raw_ex(priv, 0, pub, pubSz,
        &key, endian), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_curve25519_import_private_raw_ex(priv, privSz, pub, 0,
        &key, endian), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    ExpectIntEQ(wc_curve25519_import_private_raw_ex(priv, privSz, pub, pubSz,
        &key, EC25519_LITTLE_ENDIAN), 0);

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_curve25519_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_curve25519_import_private_raw_ex */

/*
 * Testing test_wc_curve25519_import_private
 */
int test_wc_curve25519_import_private(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE25519)
    curve25519_key key;
    WC_RNG         rng;
    byte           priv[CURVE25519_KEYSIZE];
    word32         privSz = sizeof(priv);

    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_curve25519_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &key), 0);

    ExpectIntEQ(wc_curve25519_export_private_raw(&key, priv, &privSz), 0);
    ExpectIntEQ(wc_curve25519_import_private(priv, privSz, &key), 0);

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_curve25519_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_curve25519_import */

