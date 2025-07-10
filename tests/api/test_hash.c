/* test_hash.c
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

#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_hash.h>
#include <tests/api/test_digest.h>

#ifndef NO_HASH_WRAPPER
/* enum for holding supported algorithms, #ifndef's restrict if disabled */
static const enum wc_HashType supportedHash[] = {
#ifndef NO_MD5
    WC_HASH_TYPE_MD5,
#endif
#ifndef NO_SHA
    WC_HASH_TYPE_SHA,
#endif
#ifdef WOLFSSL_SHA224
    WC_HASH_TYPE_SHA224,
#endif
#ifndef NO_SHA256
    WC_HASH_TYPE_SHA256,
#endif
#ifdef WOLFSSL_SHA384
    WC_HASH_TYPE_SHA384,
#endif
#ifdef WOLFSSL_SHA512
    WC_HASH_TYPE_SHA512,
#if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
#ifndef WOLFSSL_NOSHA512_224
    WC_HASH_TYPE_SHA512_224,
#endif
#ifndef WOLFSSL_NOSHA512_256
    WC_HASH_TYPE_SHA512_256,
#endif
#endif
#endif
#ifdef WOLFSSL_SHA3
    WC_HASH_TYPE_SHA3_224,
    WC_HASH_TYPE_SHA3_256,
    WC_HASH_TYPE_SHA3_384,
    WC_HASH_TYPE_SHA3_512,
#endif
#ifdef WOLFSSL_SM3
    WC_HASH_TYPE_SM3,
#endif
    WC_HASH_TYPE_NONE   /* Dummy value to ensure list is non-zero. */
};
static const int supportedHashLen = (sizeof(supportedHash) /
                                     sizeof(enum wc_HashType)) - 1;

static const enum wc_HashType notCompiledHash[] = {
#ifdef NO_MD5
    WC_HASH_TYPE_MD5,
#endif
#ifdef NO_SHA
    WC_HASH_TYPE_SHA,
#endif
#ifndef WOLFSSL_SHA224
    WC_HASH_TYPE_SHA224,
#endif
#ifdef NO_SHA256
    WC_HASH_TYPE_SHA256,
#endif
#ifndef WOLFSSL_SHA384
    WC_HASH_TYPE_SHA384,
#endif
#ifndef WOLFSSL_SHA512
    WC_HASH_TYPE_SHA512,
#endif
#ifndef WOLFSSL_SHA3
    WC_HASH_TYPE_SHA3_224,
    WC_HASH_TYPE_SHA3_256,
    WC_HASH_TYPE_SHA3_384,
    WC_HASH_TYPE_SHA3_512,
#endif
    WC_HASH_TYPE_NONE   /* Dummy value to ensure list is non-zero. */
};
static const int notCompiledHashLen = (sizeof(notCompiledHash) /
                                       sizeof(enum wc_HashType)) - 1;

static const enum wc_HashType notSupportedHash[] = {
#if defined(WOLFSSL_SHA3) && defined(WOLFSSL_SHAKE128)
    WC_HASH_TYPE_SHAKE128,
#endif
#if defined(WOLFSSL_SHA3) && defined(WOLFSSL_SHAKE256)
    WC_HASH_TYPE_SHAKE256,
#endif
    WC_HASH_TYPE_MD5_SHA,
    WC_HASH_TYPE_MD2,
    WC_HASH_TYPE_MD4,
    WC_HASH_TYPE_BLAKE2B,
    WC_HASH_TYPE_BLAKE2S,
    WC_HASH_TYPE_NONE
};
static const int notSupportedHashLen = (sizeof(notSupportedHash) /
                                        sizeof(enum wc_HashType));

static const enum wc_HashType sizeSupportedHash[] = {
#if !defined(NO_MD5) && !defined(NO_SHA)
    WC_HASH_TYPE_MD5_SHA,
#endif
#ifdef WOLFSSL_MD2
    WC_HASH_TYPE_MD2,
#endif
#ifndef NO_MD4
    WC_HASH_TYPE_MD4,
#endif
#if defined(HAVE_BLAKE2) || defined(HAVE_BLAKE2S)
    WC_HASH_TYPE_BLAKE2B,
    WC_HASH_TYPE_BLAKE2S,
#endif
    WC_HASH_TYPE_NONE   /* Dummy value to ensure list is non-zero. */
};
static const int sizeSupportedHashLen = (sizeof(sizeSupportedHash) /
                                         sizeof(enum wc_HashType)) - 1;
static const enum wc_HashType sizeNotCompiledHash[] = {
#if defined(NO_MD5) || defined(NO_SHA)
    WC_HASH_TYPE_MD5_SHA,
#endif
#ifndef WOLFSSL_MD2
    WC_HASH_TYPE_MD2,
#endif
#ifdef NO_MD4
    WC_HASH_TYPE_MD4,
#endif
#if !defined(HAVE_BLAKE2) && !defined(HAVE_BLAKE2S)
    WC_HASH_TYPE_BLAKE2B,
    WC_HASH_TYPE_BLAKE2S,
#endif
    WC_HASH_TYPE_NONE   /* Dummy value to ensure list is non-zero. */
};
static const int sizeNotCompiledHashLen = (sizeof(sizeNotCompiledHash) /
                                           sizeof(enum wc_HashType)) - 1;
static const enum wc_HashType sizeNotSupportedHash[] = {
#if defined(WOLFSSL_SHA3) && defined(WOLFSSL_SHAKE128)
    WC_HASH_TYPE_SHAKE128,
#endif
#if defined(WOLFSSL_SHA3) && defined(WOLFSSL_SHAKE256)
    WC_HASH_TYPE_SHAKE256,
#endif
    WC_HASH_TYPE_NONE
};
static const int sizeNotSupportedHashLen = (sizeof(sizeNotSupportedHash) /
                                            sizeof(enum wc_HashType));
#endif /* NO_HASH_WRAPPER */

int test_wc_HashInit(void)
{
    EXPECT_DECLS;
#ifndef NO_HASH_WRAPPER
    wc_HashAlg hash;
    int i;  /* 0 indicates tests passed, 1 indicates failure */

    /* For loop to test various arguments... */
    for (i = 0; i < supportedHashLen; i++) {
        /* check for null ptr */
        ExpectIntEQ(wc_HashInit(NULL, supportedHash[i]),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_HashInit_ex(NULL, supportedHash[i], HEAP_HINT,
            INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        ExpectIntEQ(wc_HashInit(&hash, supportedHash[i]), 0);
        wc_HashFree(&hash, supportedHash[i]);
        ExpectIntEQ(wc_HashInit_ex(&hash, supportedHash[i], HEAP_HINT,
            INVALID_DEVID), 0);
        wc_HashFree(&hash, supportedHash[i]);

        wc_HashFree(NULL,  supportedHash[i]);
    }  /* end of for loop */

    for (i = 0; i < notCompiledHashLen; i++) {
        /* check for null ptr */
        ExpectIntEQ(wc_HashInit(NULL, notCompiledHash[i]),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_HashInit_ex(NULL, notCompiledHash[i], HEAP_HINT,
            INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        ExpectIntEQ(wc_HashInit(&hash, notCompiledHash[i]),
            WC_NO_ERR_TRACE(HASH_TYPE_E));
        ExpectIntEQ(wc_HashInit_ex(&hash, notCompiledHash[i], HEAP_HINT,
            INVALID_DEVID), WC_NO_ERR_TRACE(HASH_TYPE_E));

        wc_HashFree(NULL,  notCompiledHash[i]);
    }

    for (i = 0; i < notSupportedHashLen; i++) {
        /* check for null ptr */
        ExpectIntEQ(wc_HashInit(NULL, supportedHash[i]),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_HashInit_ex(NULL, supportedHash[i], HEAP_HINT,
            INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        ExpectIntEQ(wc_HashInit(&hash, notSupportedHash[i]),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        wc_HashFree(&hash, notSupportedHash[i]);
        ExpectIntEQ(wc_HashInit_ex(&hash, notSupportedHash[i], HEAP_HINT,
            INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        wc_HashFree(&hash,  notSupportedHash[i]);

        wc_HashFree(NULL,  notSupportedHash[i]);
    }  /* end of for loop */

#endif
    return EXPECT_RESULT();
}  /* end of test_wc_HashInit */

int test_wc_HashUpdate(void)
{
    EXPECT_DECLS;
#ifndef NO_HASH_WRAPPER
    wc_HashAlg hash;
    int i;  /* 0 indicates tests passed, 1 indicates failure */

    for (i = 0; i < supportedHashLen; i++) {
        ExpectIntEQ(wc_HashInit(&hash, supportedHash[i]), 0);

        /* Invalid parameters */
        ExpectIntEQ(wc_HashUpdate(NULL, supportedHash[i], NULL, 1),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_HashUpdate(&hash, supportedHash[i], NULL, 1),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_HashUpdate(NULL, supportedHash[i], NULL, 0),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_HashUpdate(NULL, supportedHash[i], (byte*)"a", 1),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        ExpectIntEQ(wc_HashUpdate(&hash, supportedHash[i], NULL, 0), 0);
        ExpectIntEQ(wc_HashUpdate(&hash, supportedHash[i], (byte*)"a", 1), 0);

        wc_HashFree(&hash, supportedHash[i]);
    }

    for (i = 0; i < notCompiledHashLen; i++) {
        ExpectIntEQ(wc_HashInit(&hash, notCompiledHash[i]),
            WC_NO_ERR_TRACE(HASH_TYPE_E));

        /* Invalid parameters */
        ExpectIntEQ(wc_HashUpdate(NULL, notCompiledHash[i], NULL, 1),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_HashUpdate(&hash, notCompiledHash[i], NULL, 1),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_HashUpdate(NULL, notCompiledHash[i], NULL, 0),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_HashUpdate(NULL, notCompiledHash[i], (byte*)"a", 1),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        ExpectIntEQ(wc_HashUpdate(&hash, notCompiledHash[i], NULL, 0),
            WC_NO_ERR_TRACE(HASH_TYPE_E));
        ExpectIntEQ(wc_HashUpdate(&hash, notCompiledHash[i], (byte*)"a", 1),
            WC_NO_ERR_TRACE(HASH_TYPE_E));

        wc_HashFree(&hash, notCompiledHash[i]);
    }

    for (i = 0; i < notSupportedHashLen; i++) {
        ExpectIntEQ(wc_HashInit(&hash, notSupportedHash[i]),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* Invalid parameters */
        ExpectIntEQ(wc_HashUpdate(NULL, notSupportedHash[i], NULL, 1),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_HashUpdate(&hash, notSupportedHash[i], NULL, 1),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_HashUpdate(NULL, notSupportedHash[i], NULL, 0),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_HashUpdate(NULL, notSupportedHash[i], (byte*)"a", 1),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        ExpectIntEQ(wc_HashUpdate(&hash, notSupportedHash[i], NULL, 0),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_HashUpdate(&hash, notSupportedHash[i], (byte*)"a", 1),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        wc_HashFree(&hash, notSupportedHash[i]);
    }

#if defined(DEBUG_WOLFSSL) && !defined(NO_SHA256) && defined(WOLFSSL_SHA512)
    ExpectIntEQ(wc_HashInit(&hash, WC_HASH_TYPE_SHA256), 0);
    ExpectIntEQ(wc_HashUpdate(&hash, WC_HASH_TYPE_SHA512, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HashUpdate(&hash, WC_HASH_TYPE_SHA512, (byte*)"a", 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
#endif
    return EXPECT_RESULT();
}

int test_wc_HashFinal(void)
{
    EXPECT_DECLS;
#ifndef NO_HASH_WRAPPER
    wc_HashAlg hash;
    byte digest[WC_MAX_DIGEST_SIZE];
    int i;  /* 0 indicates tests passed, 1 indicates failure */

    for (i = 0; i < supportedHashLen; i++) {
        ExpectIntEQ(wc_HashInit(&hash, supportedHash[i]), 0);

        /* Invalid parameters */
        ExpectIntEQ(wc_HashFinal(NULL, supportedHash[i], NULL),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_HashFinal(&hash, supportedHash[i], NULL),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_HashFinal(NULL, supportedHash[i], digest),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        ExpectIntEQ(wc_HashFinal(&hash, supportedHash[i], digest), 0);

        wc_HashFree(&hash, supportedHash[i]);
    }

    for (i = 0; i < notCompiledHashLen; i++) {
        ExpectIntEQ(wc_HashInit(&hash, notCompiledHash[i]),
            WC_NO_ERR_TRACE(HASH_TYPE_E));

        /* Invalid parameters */
        ExpectIntEQ(wc_HashFinal(NULL, notCompiledHash[i], NULL),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_HashFinal(&hash, notCompiledHash[i], NULL),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_HashFinal(NULL, notCompiledHash[i], digest),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        ExpectIntEQ(wc_HashFinal(&hash, notCompiledHash[i], digest),
            WC_NO_ERR_TRACE(HASH_TYPE_E));

        wc_HashFree(&hash, notCompiledHash[i]);
    }

    for (i = 0; i < notSupportedHashLen; i++) {
        ExpectIntEQ(wc_HashInit(&hash, notSupportedHash[i]),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* Invalid parameters */
        ExpectIntEQ(wc_HashFinal(NULL, notSupportedHash[i], NULL),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_HashFinal(&hash, notSupportedHash[i], NULL),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_HashFinal(NULL, notSupportedHash[i], digest),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        ExpectIntEQ(wc_HashFinal(&hash, notSupportedHash[i], digest),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        wc_HashFree(&hash, notSupportedHash[i]);
    }
#if defined(DEBUG_WOLFSSL) && !defined(NO_SHA256) && defined(WOLFSSL_SHA512)
    ExpectIntEQ(wc_HashInit(&hash, WC_HASH_TYPE_SHA256), 0);
    ExpectIntEQ(wc_HashFinal(&hash, WC_HASH_TYPE_SHA512, digest),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
#endif
    return EXPECT_RESULT();
}

int test_wc_HashNewDelete(void)
{
    EXPECT_DECLS;
#if !defined(NO_HASH_WRAPPER) && !defined(WC_NO_CONSTRUCTORS)
    wc_HashAlg* hash;
    byte digest[WC_MAX_DIGEST_SIZE];
    int ret;
    int i;

    for (i = 0; i < supportedHashLen; i++) {
         ExpectNotNull(hash = wc_HashNew(supportedHash[i], HEAP_HINT,
             INVALID_DEVID, &ret));
         ExpectIntEQ(ret, 0);

         ExpectIntEQ(wc_HashUpdate(hash, supportedHash[i], (byte*)"a", 1), 0);
         ExpectIntEQ(wc_HashFinal(hash, supportedHash[i], digest), 0);

         ExpectIntEQ(wc_HashDelete(hash, &hash), 0);
         ExpectNull(hash);

         ExpectNotNull(hash = wc_HashNew(supportedHash[i], HEAP_HINT,
             INVALID_DEVID, &ret));
         ExpectIntEQ(ret, 0);
         ExpectIntEQ(wc_HashDelete(hash, NULL), 0);

         ExpectIntEQ(wc_HashDelete(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }

    for (i = 0; i < notCompiledHashLen; i++) {
         ExpectNull(wc_HashNew(notCompiledHash[i], HEAP_HINT, INVALID_DEVID,
             &ret));
         ExpectIntEQ(ret, WC_NO_ERR_TRACE(HASH_TYPE_E));
    }

    for (i = 0; i < notSupportedHashLen; i++) {
         ExpectNull(wc_HashNew(notSupportedHash[i], HEAP_HINT, INVALID_DEVID,
             &ret));
         ExpectIntEQ(ret, WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }
#endif
    return EXPECT_RESULT();
}

int test_wc_HashGetDigestSize(void)
{
    EXPECT_DECLS;
#ifndef NO_HASH_WRAPPER
    int i;

    for (i = 0; i < supportedHashLen; i++) {
        ExpectIntGT(wc_HashGetDigestSize(supportedHash[i]), 0);
    }
    for (i = 0; i < sizeSupportedHashLen; i++) {
        ExpectIntGT(wc_HashGetDigestSize(sizeSupportedHash[i]), 0);
    }

    for (i = 0; i < notCompiledHashLen; i++) {
        ExpectIntEQ(wc_HashGetDigestSize(notCompiledHash[i]),
            WC_NO_ERR_TRACE(HASH_TYPE_E));
    }
    for (i = 0; i < sizeNotCompiledHashLen; i++) {
        ExpectIntEQ(wc_HashGetDigestSize(sizeNotCompiledHash[i]),
            WC_NO_ERR_TRACE(HASH_TYPE_E));
    }

    for (i = 0; i < sizeNotSupportedHashLen; i++) {
        ExpectIntEQ(wc_HashGetDigestSize(sizeNotSupportedHash[i]),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }
#endif
    return EXPECT_RESULT();
}

int test_wc_HashGetBlockSize(void)
{
    EXPECT_DECLS;
#ifndef NO_HASH_WRAPPER
    int i;

    for (i = 0; i < supportedHashLen; i++) {
        ExpectIntGT(wc_HashGetBlockSize(supportedHash[i]), 0);
    }
    for (i = 0; i < sizeSupportedHashLen; i++) {
        ExpectIntGT(wc_HashGetBlockSize(sizeSupportedHash[i]), 0);
    }

    for (i = 0; i < notCompiledHashLen; i++) {
        ExpectIntEQ(wc_HashGetBlockSize(notCompiledHash[i]),
            WC_NO_ERR_TRACE(HASH_TYPE_E));
    }
    for (i = 0; i < sizeNotCompiledHashLen; i++) {
        ExpectIntEQ(wc_HashGetBlockSize(sizeNotCompiledHash[i]),
            WC_NO_ERR_TRACE(HASH_TYPE_E));
    }

    for (i = 0; i < sizeNotSupportedHashLen; i++) {
        ExpectIntEQ(wc_HashGetBlockSize(sizeNotSupportedHash[i]),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }
#endif
    return EXPECT_RESULT();
}

int test_wc_Hash(void)
{
    EXPECT_DECLS;
#if !defined(NO_HASH_WRAPPER) && !defined(WC_NO_CONSTRUCTORS)
    byte digest[WC_MAX_DIGEST_SIZE];
    int i;

    for (i = 0; i < supportedHashLen; i++) {
        ExpectIntEQ(wc_Hash(supportedHash[i], (byte*)"a", 1,
            digest, sizeof(digest)), 0);
        ExpectIntEQ(wc_Hash_ex(supportedHash[i], (byte*)"a", 1,
            digest, sizeof(digest), HEAP_HINT, INVALID_DEVID), 0);
    }
#if !defined(NO_MD5) && !defined(NO_SHA)
    ExpectIntEQ(wc_Hash(WC_HASH_TYPE_MD5_SHA, (byte*)"a", 1,
        digest, sizeof(digest)), 0);
    ExpectIntEQ(wc_Hash_ex(WC_HASH_TYPE_MD5_SHA, (byte*)"a", 1,
        digest, sizeof(digest), HEAP_HINT, INVALID_DEVID), 0);
#endif

    for (i = 0; i < notCompiledHashLen; i++) {
        ExpectIntEQ(wc_Hash(notCompiledHash[i], (byte*)"a", 1,
            digest, sizeof(digest)), WC_NO_ERR_TRACE(HASH_TYPE_E));
        ExpectIntEQ(wc_Hash_ex(notCompiledHash[i], (byte*)"a", 1,
            digest, sizeof(digest), HEAP_HINT, INVALID_DEVID),
            WC_NO_ERR_TRACE(HASH_TYPE_E));
    }
    for (i = 0; i < sizeNotCompiledHashLen; i++) {
        ExpectIntEQ(wc_Hash(sizeNotCompiledHash[i], (byte*)"a", 1,
            digest, sizeof(digest)), WC_NO_ERR_TRACE(HASH_TYPE_E));
        ExpectIntEQ(wc_Hash_ex(sizeNotCompiledHash[i], (byte*)"a", 1,
            digest, sizeof(digest), HEAP_HINT, INVALID_DEVID),
            WC_NO_ERR_TRACE(HASH_TYPE_E));
    }

    for (i = 0; i < sizeNotSupportedHashLen; i++) {
        if (notSupportedHash[i] == WC_HASH_TYPE_MD5_SHA) {
            /* Algorithm only supported with wc_Hash() and wc_Hash_ex(). */
            continue;
        }
        ExpectIntEQ(wc_Hash(sizeNotSupportedHash[i], (byte*)"a", 1,
            digest, sizeof(digest)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_Hash_ex(sizeNotSupportedHash[i], (byte*)"a", 1,
            digest, sizeof(digest), HEAP_HINT, INVALID_DEVID),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }
#endif
    return EXPECT_RESULT();
}


/*
 * Unit test function for wc_HashSetFlags()
 */
int test_wc_HashSetFlags(void)
{
    EXPECT_DECLS;
#if !defined(NO_HASH_WRAPPER) && defined(WOLFSSL_HASH_FLAGS)
    wc_HashAlg hash;
    word32 flags = 0;
    int i;


    /* For loop to test various arguments... */
    for (i = 0; i < supportedHashLen; i++) {
        ExpectIntEQ(wc_HashInit(&hash, supportedHash[i]), 0);
        ExpectIntEQ(wc_HashSetFlags(&hash, supportedHash[i], flags), 0);
        ExpectTrue((flags & WC_HASH_FLAG_ISCOPY) == 0);
        ExpectIntEQ(wc_HashSetFlags(NULL, supportedHash[i], flags),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        wc_HashFree(&hash, supportedHash[i]);

    }

    for (i = 0; i < notCompiledHashLen; i++) {
        ExpectIntEQ(wc_HashInit(&hash, notCompiledHash[i]),
            WC_NO_ERR_TRACE(HASH_TYPE_E));
        ExpectIntEQ(wc_HashSetFlags(&hash, notCompiledHash[i], flags),
            WC_NO_ERR_TRACE(HASH_TYPE_E));
        ExpectIntEQ(wc_HashFree(&hash, notCompiledHash[i]),
            WC_NO_ERR_TRACE(HASH_TYPE_E));
    }

    /* For loop to test not supported cases */
    for (i = 0; i < notSupportedHashLen; i++) {
        ExpectIntEQ(wc_HashInit(&hash, notSupportedHash[i]),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_HashSetFlags(&hash, notSupportedHash[i], flags),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_HashFree(&hash, notSupportedHash[i]),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }
#endif
    return EXPECT_RESULT();
}  /* END test_wc_HashSetFlags */

/*
 * Unit test function for wc_HashGetFlags()
 */
int test_wc_HashGetFlags(void)
{
    EXPECT_DECLS;
#if !defined(NO_HASH_WRAPPER) && defined(WOLFSSL_HASH_FLAGS)
    wc_HashAlg hash;
    word32 flags = 0;
    int i;

    /* For loop to test various arguments... */
    for (i = 0; i < supportedHashLen; i++) {
        ExpectIntEQ(wc_HashInit(&hash, supportedHash[i]), 0);
        ExpectIntEQ(wc_HashGetFlags(&hash, supportedHash[i], &flags), 0);
        ExpectTrue((flags & WC_HASH_FLAG_ISCOPY) == 0);
        ExpectIntEQ(wc_HashGetFlags(NULL, supportedHash[i], &flags),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        wc_HashFree(&hash, supportedHash[i]);
    }

    for (i = 0; i < notCompiledHashLen; i++) {
        ExpectIntEQ(wc_HashInit(&hash, notCompiledHash[i]),
            WC_NO_ERR_TRACE(HASH_TYPE_E));
        ExpectIntEQ(wc_HashGetFlags(&hash, notCompiledHash[i], &flags),
            WC_NO_ERR_TRACE(HASH_TYPE_E));
        ExpectIntEQ(wc_HashFree(&hash, notCompiledHash[i]),
            WC_NO_ERR_TRACE(HASH_TYPE_E));
    }

    /* For loop to test not supported cases */
    for (i = 0; i < notSupportedHashLen; i++) {
        ExpectIntEQ(wc_HashInit(&hash, notSupportedHash[i]),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_HashGetFlags(&hash, notSupportedHash[i], &flags),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_HashFree(&hash, notSupportedHash[i]),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }
#endif
    return EXPECT_RESULT();
}  /* END test_wc_HashGetFlags */

int test_wc_Hash_Algs(void)
{
    EXPECT_DECLS;
#ifndef NO_HASH_WRAPPER
#ifndef NO_MD5
    DIGEST_HASH_TEST(Md5, MD5);
#endif
#ifndef NO_SHA
    DIGEST_HASH_TEST(Sha, SHA);
#endif
#ifdef WOLFSSL_SHA224
    DIGEST_HASH_TEST(Sha224, SHA224);
#endif
#ifndef NO_SHA256
    DIGEST_HASH_TEST(Sha256, SHA256);
#endif
#ifdef WOLFSSL_SHA384
    DIGEST_HASH_TEST(Sha384, SHA384);
#endif
#ifdef WOLFSSL_SHA512
    DIGEST_HASH_TEST(Sha512, SHA512);
#ifndef WOLFSSL_NOSHA512_224
    DIGEST_HASH_TEST(Sha512_224, SHA512_224);
#endif
#ifndef WOLFSSL_NOSHA512_256
    DIGEST_HASH_TEST(Sha512_256, SHA512_256);
#endif
#endif /* WOLFSSL_SHA512 */
#ifdef WOLFSSL_SHA3
    #ifndef WOLFSSL_NOSHA3_224
    DIGEST_COUNT_HASH_TEST(Sha3_224, SHA3_224);
    #endif
    #ifndef WOLFSSL_NOSHA3_256
    DIGEST_COUNT_HASH_TEST(Sha3_256, SHA3_256);
    #endif
    #ifndef WOLFSSL_NOSHA3_384
    DIGEST_COUNT_HASH_TEST(Sha3_384, SHA3_384);
    #endif
    #ifndef WOLFSSL_NOSHA3_512
    DIGEST_COUNT_HASH_TEST(Sha3_512, SHA3_512);
    #endif
#endif
#ifdef WOLFSSL_SM3
    DIGEST_HASH_TEST(Sm3, SM3);
#endif
#endif /* !NO_HASH_WRAPPER */
    return EXPECT_RESULT();
}

int test_wc_HashGetOID(void)
{
    EXPECT_DECLS;
#if !defined(NO_HASH_WRAPPER) && (!defined(NO_ASN) || !defined(NO_DH) || \
                                  defined(HAVE_ECC))
    static const enum wc_HashType oidOnlySupportedHash[] = {
    #ifdef WOLFSSL_MD2
        WC_HASH_TYPE_MD2,
    #endif
    #ifndef NO_MD5
        WC_HASH_TYPE_MD5_SHA,
    #endif
        WC_HASH_TYPE_NONE   /* Dummy value to ensure list is non-zero. */
    };
    static const int oidOnlySupportedHashLen = (sizeof(oidOnlySupportedHash) /
                                                sizeof(enum wc_HashType)) - 1;
    static const enum wc_HashType oidOnlyNotCompiledHash[] = {
    #ifndef WOLFSSL_MD2
        WC_HASH_TYPE_MD2,
    #endif
    #ifdef NO_MD5
        WC_HASH_TYPE_MD5_SHA,
    #endif
        WC_HASH_TYPE_NONE   /* Dummy value to ensure list is non-zero. */
    };
    static const int oidOnlyNotCompiledHashLen =
        (sizeof(oidOnlyNotCompiledHash) / sizeof(enum wc_HashType)) - 1;
    static const enum wc_HashType oidNotSupportedHash[] = {
        WC_HASH_TYPE_MD4,
        WC_HASH_TYPE_BLAKE2B,
        WC_HASH_TYPE_BLAKE2S,
        WC_HASH_TYPE_NONE
    };
    static const int oidNotSupportedHashLen = (sizeof(oidNotSupportedHash) /
                                               sizeof(enum wc_HashType));
    int i;

    for (i = 0; i < supportedHashLen; i++) {
        ExpectIntGT(wc_HashGetOID(supportedHash[i]), 0);
    }
    for (i = 0; i < oidOnlySupportedHashLen; i++) {
        ExpectIntGT(wc_HashGetOID(oidOnlySupportedHash[i]), 0);
    }

    for (i = 0; i < notCompiledHashLen; i++) {
        ExpectIntEQ(wc_HashGetOID(notCompiledHash[i]),
            WC_NO_ERR_TRACE(HASH_TYPE_E));
    }
    for (i = 0; i < oidOnlyNotCompiledHashLen; i++) {
        ExpectIntEQ(wc_HashGetOID(oidOnlyNotCompiledHash[i]),
            WC_NO_ERR_TRACE(HASH_TYPE_E));
    }

    for (i = 0; i < oidNotSupportedHashLen; i++) {
        ExpectIntEQ(wc_HashGetOID(oidNotSupportedHash[i]),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }
#endif
    return EXPECT_RESULT();
}

int test_wc_OidGetHash(void)
{
    EXPECT_DECLS;
#if !defined(NO_HASH_WRAPPER) && !defined(NO_ASN)
    static const int sumSupportedHash[] = {
    #ifdef WOLFSSL_MD2
        MD2h,
    #endif
    #ifndef NO_MD5
        MD5h,
    #endif
    #ifndef NO_SHA
        SHAh,
    #endif
    #ifdef WOLFSSL_SHA224
        SHA224h,
    #endif
    #ifndef NO_SHA256
        SHA256h,
    #endif
    #ifdef WOLFSSL_SHA384
        SHA384h,
    #endif
    #ifdef WOLFSSL_SHA512
        SHA512h,
    #endif
    #ifdef WOLFSSL_SHA3
        SHA3_224h,
        SHA3_256h,
        SHA3_384h,
        SHA3_512h,
    #endif
    #ifdef WOLFSSL_SM3
        SM3h,
    #endif
        0   /* Dummy value to ensure list is non-zero. */
    };
    static const int sumSupportedHashLen = (sizeof(sumSupportedHash) /
                                            sizeof(enum wc_HashType)) - 1;
    static const int sumNotSupportedHash[] = {
        MD4h,
    #ifdef NO_MD5
        MD5h,
    #endif
    #ifdef NO_SHA
        SHAh,
    #endif
    #ifndef WOLFSSL_SHA224
        SHA224h,
    #endif
    #ifdef NO_SHA256
        SHA256h,
    #endif
    #ifndef WOLFSSL_SHA384
        SHA384h,
    #endif
    #ifndef WOLFSSL_SHA512
        SHA512h,
    #endif
    #ifndef WOLFSSL_SHA3
        SHA3_224h,
        SHA3_256h,
        SHA3_384h,
        SHA3_512h,
    #endif
    #ifndef WOLFSSL_SM3
        SM3h,
    #endif
        0
    };
    static const int sumNotSupportedHashLen = (sizeof(sumNotSupportedHash) /
                                               sizeof(enum wc_HashType));
    int i;
    enum wc_HashType hash;

    for (i = 0; i < sumSupportedHashLen; i++) {
        hash = wc_OidGetHash(sumSupportedHash[i]);
        ExpectTrue(hash != WC_HASH_TYPE_NONE);
    }

    for (i = 0; i < sumNotSupportedHashLen; i++) {
        hash = wc_OidGetHash(sumNotSupportedHash[i]);
        ExpectTrue(hash == WC_HASH_TYPE_NONE);
    }
#endif
    return EXPECT_RESULT();
}

