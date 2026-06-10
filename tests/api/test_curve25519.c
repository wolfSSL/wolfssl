/* test_curve25519.c
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
 * Testing that wc_curve25519_shared_secret_ex rejects an all-zero shared
 * secret (RFC 7748 section 6.1). This is the default behavior; users that
 * need the legacy behavior can opt out with WOLFSSL_NO_ECDHX_SHARED_ZERO_CHECK.
 */
int test_wc_curve25519_shared_secret_zero_check(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE25519) && defined(HAVE_CURVE25519_KEY_IMPORT) && \
    !defined(WOLFSSL_NO_ECDHX_SHARED_ZERO_CHECK)
    curve25519_key private_key;
    curve25519_key public_key;
    WC_RNG         rng;
    byte           out[CURVE25519_KEYSIZE];
    word32         outLen = sizeof(out);
    /* All-zero public key is a low-order point that yields an all-zero
     * shared secret for any private key. */
    byte           zero_pub[CURVE25519_KEYSIZE];

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(zero_pub, 0, sizeof(zero_pub));

    ExpectIntEQ(wc_curve25519_init(&private_key), 0);
    ExpectIntEQ(wc_curve25519_init(&public_key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
#ifdef WOLFSSL_CURVE25519_BLINDING
    ExpectIntEQ(wc_curve25519_set_rng(&private_key, &rng), 0);
#endif

    ExpectIntEQ(wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &private_key),
        0);
    ExpectIntEQ(wc_curve25519_import_public_ex(zero_pub, sizeof(zero_pub),
        &public_key, EC25519_LITTLE_ENDIAN), 0);

    ExpectIntEQ(wc_curve25519_shared_secret_ex(&private_key, &public_key, out,
        &outLen, EC25519_BIG_ENDIAN),
        WC_NO_ERR_TRACE(ECC_OUT_OF_RANGE_E));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_curve25519_free(&private_key);
    wc_curve25519_free(&public_key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_curve25519_shared_secret_zero_check */

/*
 * Known-answer tests for wc_curve25519_shared_secret_ex.
 *
 * Both vectors share one private scalar and produce a shared secret that is a
 * small canonical value (9 and 16, little-endian). Because the result is close
 * to a multiple of the field prime, these exercise the final modular reduction
 * of the X25519 computation: a result that was only reduced mod 2^256 (or left
 * in [p, 2^255)) instead of fully reduced mod 2^255-19 would not match.
 * All values are 32-byte little-endian encodings per RFC 7748.
 */
int test_wc_curve25519_shared_secret_ex_kat(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE25519) && defined(HAVE_CURVE25519_KEY_IMPORT)
    /* Private scalar shared by both vectors. */
    static const byte kPriv[CURVE25519_KEYSIZE] = {
        0x60, 0xa3, 0xa4, 0xf1, 0x30, 0xb9, 0x8a, 0x5b,
        0xe4, 0xb1, 0xce, 0xdb, 0x7c, 0xb8, 0x55, 0x84,
        0xa3, 0x52, 0x0e, 0x14, 0x2d, 0x47, 0x4d, 0xc9,
        0xcc, 0xb9, 0x09, 0xa0, 0x73, 0xa9, 0x76, 0x7f
    };
    /* Vector 1 public value, expected shared secret == 9. */
    static const byte kPub1[CURVE25519_KEYSIZE] = {
        0x3b, 0x18, 0xdf, 0x1e, 0x50, 0xb8, 0x99, 0xeb,
        0xd5, 0x88, 0xc3, 0x16, 0x1c, 0xbd, 0x3b, 0xf9,
        0x8e, 0xbc, 0xc2, 0xc1, 0xf7, 0xdf, 0x53, 0xb8,
        0x11, 0xbd, 0x0e, 0x91, 0xb4, 0xd5, 0x15, 0x3d
    };
    static const byte kExpected1[CURVE25519_KEYSIZE] = {
        0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    /* Vector 2 public value, expected shared secret == 16. */
    static const byte kPub2[CURVE25519_KEYSIZE] = {
        0xca, 0xb6, 0xf9, 0xe7, 0xd8, 0xce, 0x00, 0xdf,
        0xce, 0xa9, 0xbb, 0xd8, 0xf0, 0x69, 0xef, 0x7f,
        0xb2, 0xac, 0x50, 0x4a, 0xbf, 0x83, 0xb8, 0x7d,
        0xb6, 0x01, 0xb5, 0xae, 0x0a, 0x7f, 0x76, 0x15
    };
    static const byte kExpected2[CURVE25519_KEYSIZE] = {
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    /* Table-driven so both vectors run through the identical code path. */
    struct {
        const byte* pub;
        const byte* expected;
    } vec[2];
    curve25519_key private_key;
    curve25519_key public_key;
    WC_RNG         rng;
    byte           out[CURVE25519_KEYSIZE];
    word32         outLen;
    int i;

    vec[0].pub = kPub1; vec[0].expected = kExpected1;
    vec[1].pub = kPub2; vec[1].expected = kExpected2;

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    ExpectIntEQ(wc_InitRng(&rng), 0);

    for (i = 0; i < 2; i++) {
        XMEMSET(&private_key, 0, sizeof(private_key));
        XMEMSET(&public_key, 0, sizeof(public_key));
        ExpectIntEQ(wc_curve25519_init(&private_key), 0);
        ExpectIntEQ(wc_curve25519_init(&public_key), 0);
    #ifdef WOLFSSL_CURVE25519_BLINDING
        ExpectIntEQ(wc_curve25519_set_rng(&private_key, &rng), 0);
    #endif
        ExpectIntEQ(wc_curve25519_import_private_ex(kPriv, sizeof(kPriv),
            &private_key, EC25519_LITTLE_ENDIAN), 0);
        ExpectIntEQ(wc_curve25519_import_public_ex(vec[i].pub,
            CURVE25519_KEYSIZE, &public_key, EC25519_LITTLE_ENDIAN), 0);

        outLen = sizeof(out);
        ExpectIntEQ(wc_curve25519_shared_secret_ex(&private_key, &public_key,
            out, &outLen, EC25519_LITTLE_ENDIAN), 0);
        ExpectIntEQ(outLen, CURVE25519_KEYSIZE);
        ExpectIntEQ(XMEMCMP(out, vec[i].expected, CURVE25519_KEYSIZE), 0);

        wc_curve25519_free(&private_key);
        wc_curve25519_free(&public_key);
    }

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
} /* END test_wc_curve25519_shared_secret_ex_kat */

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
    WC_RNG         rng;
    byte           out[CURVE25519_KEYSIZE];
    word32         outLen = sizeof(out);
    int            endian = EC25519_BIG_ENDIAN;

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    ExpectIntEQ(wc_curve25519_init(&key), 0);

    /* Reject export when private key not set (privSet == 0). */
    ExpectIntEQ(wc_curve25519_export_private_raw_ex(&key, out, &outLen, endian),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    /* test bad cases */
    ExpectIntEQ(wc_curve25519_export_private_raw_ex(NULL, NULL, NULL, endian),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve25519_export_private_raw_ex(NULL, out, &outLen, endian),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve25519_export_private_raw_ex(&key, NULL, &outLen,
        endian), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_curve25519_export_private_raw_ex(&key, out, NULL, endian),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Populate the key, then exercise the buffer-too-small path. */
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &key), 0);
    outLen = CURVE25519_KEYSIZE - 1;
    ExpectIntEQ(wc_curve25519_export_private_raw_ex(&key, out, &outLen, endian),
        WC_NO_ERR_TRACE(ECC_BAD_ARG_E));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
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

/*
 * Test curve25519_priv_clamp_check via wc_curve25519_make_pub.
 *
 * RFC 7748 section 5 requires three clamping invariants on a Curve25519
 * private scalar before use:
 *   Rule 1: bits 0-2 of byte  0 must be clear  (scalar &= 0xF8)
 *   Rule 2: bit  7 of byte 31 must be clear     (scalar &= 0x7F)
 *   Rule 3: bit  6 of byte 31 must be SET       (scalar |= 0x40)
 *
 * Test vectors are derived from RFC 7748 s5; they are the independent oracle.
 * Before the fix, rule 3 was not checked, so a scalar with byte[31]==0x00
 * (bit 6 clear) was silently accepted -- regression covered below.
 */
int test_wc_curve25519_priv_clamp_check(void)
{
    EXPECT_DECLS;
#ifdef HAVE_CURVE25519
    /* Valid clamped scalar: all bytes 0x00 except byte[31] = 0x40
     * (bit 7 clear, bit 6 set, byte[0] bits 0-2 clear). */
    static const byte kValidPriv[CURVE25519_KEYSIZE] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40
    };
    byte pub[CURVE25519_KEYSIZE];
    byte priv[CURVE25519_KEYSIZE];

    /* Valid key succeeds. */
    ExpectIntEQ(wc_curve25519_make_pub(CURVE25519_KEYSIZE, pub,
        CURVE25519_KEYSIZE, kValidPriv), 0);

    /* Rule 1 violation: bit 0 of byte[0] set (byte[0] = 0x01). */
    XMEMCPY(priv, kValidPriv, sizeof(priv));
    priv[0] |= 0x01;
    ExpectIntEQ(wc_curve25519_make_pub(CURVE25519_KEYSIZE, pub,
        CURVE25519_KEYSIZE, priv), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));

    /* Rule 2 violation: bit 7 of byte[31] set (byte[31] = 0xC0, keeping
     * bit 6 set so only rule 2 is violated). */
    XMEMCPY(priv, kValidPriv, sizeof(priv));
    priv[CURVE25519_KEYSIZE - 1] = 0xC0;
    ExpectIntEQ(wc_curve25519_make_pub(CURVE25519_KEYSIZE, pub,
        CURVE25519_KEYSIZE, priv), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));

    /* Rule 3 violation: bit 6 of byte[31] clear (byte[31] = 0x00).
     * Regression: this was silently accepted before the fix. */
    XMEMCPY(priv, kValidPriv, sizeof(priv));
    priv[CURVE25519_KEYSIZE - 1] = 0x00;
    ExpectIntEQ(wc_curve25519_make_pub(CURVE25519_KEYSIZE, pub,
        CURVE25519_KEYSIZE, priv), WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
#endif
    return EXPECT_RESULT();
} /* END test_wc_curve25519_priv_clamp_check */

/*
 * RFC 5958 OneAsymmetricKey: version=v2 (1) when publicKey is bundled,
 * version=v1 (0) for private only.
 */
int test_wc_Curve25519KeyToDer_oneasymkey_version(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE25519) && defined(HAVE_CURVE25519_KEY_EXPORT) && \
    defined(HAVE_CURVE25519_KEY_IMPORT)
    curve25519_key key;
    curve25519_key key2;
    WC_RNG rng;
    byte ref[256];   /* reference DER (bundled, then private only) */
    byte rt[256];    /* re-export target for memcmp */
    int  refSz = 0;
    int  rtSz = 0;
    word32 idx;

    XMEMSET(&key,  0, sizeof(key));
    XMEMSET(&key2, 0, sizeof(key2));
    XMEMSET(&rng,  0, sizeof(rng));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_curve25519_init(&key), 0);
    ExpectIntEQ(wc_curve25519_init(&key2), 0);
    ExpectIntEQ(wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &key), 0);

    /* make_key sets both priv and pub: KeyToDer bundles both (v=1).
     * Use wc_Curve25519KeyDecode so the publicKey field is preserved in key2 */
    ExpectIntGT(refSz = wc_Curve25519KeyToDer(&key, ref,
        (word32)sizeof(ref), 1), 0);
    ExpectIntEQ(test_pkcs8_get_version_byte(ref, (word32)refSz), 1);
    idx = 0;
    ExpectIntEQ(wc_Curve25519KeyDecode(ref, &idx, &key2, (word32)refSz), 0);
    ExpectIntEQ(rtSz = wc_Curve25519KeyToDer(&key2, rt, (word32)sizeof(rt), 1),
        refSz);
    ExpectIntEQ(XMEMCMP(ref, rt, (size_t)refSz), 0);

    /* Private only creates v=0. Reuse ref/rt. */
    XMEMSET(&key2, 0, sizeof(key2));
    ExpectIntEQ(wc_curve25519_init(&key2), 0);
    ExpectIntGT(refSz = wc_Curve25519PrivateKeyToDer(&key, ref,
        (word32)sizeof(ref)), 0);
    ExpectIntEQ(test_pkcs8_get_version_byte(ref, (word32)refSz), 0);
    idx = 0;
    ExpectIntEQ(wc_Curve25519PrivateKeyDecode(ref, &idx, &key2,
        (word32)refSz), 0);
    ExpectIntEQ(rtSz = wc_Curve25519PrivateKeyToDer(&key2, rt,
        (word32)sizeof(rt)), refSz);
    ExpectIntEQ(XMEMCMP(ref, rt, (size_t)refSz), 0);

    wc_curve25519_free(&key);
    wc_curve25519_free(&key2);
    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

