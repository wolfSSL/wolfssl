/* test_rsa.c
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

#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/types.h>
#ifndef NO_SHA256
#include <wolfssl/wolfcrypt/sha256.h>
#endif
#ifdef WOLFSSL_SHA384
#include <wolfssl/wolfcrypt/sha512.h>
#endif
#include <tests/api/api.h>
#include <tests/api/test_rsa.h>

/*
 * Testing wc_Init RsaKey()
 */
int test_wc_InitRsaKey(void)
{
    EXPECT_DECLS;
#ifndef NO_RSA
    RsaKey key;

    XMEMSET(&key, 0, sizeof(RsaKey));

    ExpectIntEQ(wc_InitRsaKey(&key, HEAP_HINT), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_InitRsaKey(NULL, HEAP_HINT), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    DoExpectIntEQ(wc_FreeRsaKey(&key), 0);
#endif
    return EXPECT_RESULT();
} /* END test_wc_InitRsaKey */


/*
 * Testing wc_RsaPrivateKeyDecode()
 */
int test_wc_RsaPrivateKeyDecode(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && (defined(USE_CERT_BUFFERS_1024) || \
        defined(USE_CERT_BUFFERS_2048)) && !defined(HAVE_FIPS)
    RsaKey key;
    byte*  tmp = NULL;
    word32 idx = 0;
    int    bytes = 0;

    XMEMSET(&key, 0, sizeof(RsaKey));

    ExpectNotNull(tmp = (byte*)XMALLOC(FOURK_BUF, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    ExpectIntEQ(wc_InitRsaKey(&key, HEAP_HINT), 0);
    if (tmp != NULL) {
    #ifdef USE_CERT_BUFFERS_1024
        XMEMCPY(tmp, client_key_der_1024, sizeof_client_key_der_1024);
        bytes = sizeof_client_key_der_1024;
    #else
        XMEMCPY(tmp, client_key_der_2048, sizeof_client_key_der_2048);
        bytes = sizeof_client_key_der_2048;
    #endif /* Use cert buffers. */
    }

    ExpectIntEQ(wc_RsaPrivateKeyDecode(tmp, &idx, &key, (word32)bytes), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_RsaPrivateKeyDecode(NULL, &idx, &key, (word32)bytes),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaPrivateKeyDecode(tmp, NULL, &key, (word32)bytes),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaPrivateKeyDecode(tmp, &idx, NULL, (word32)bytes),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    XFREE(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    DoExpectIntEQ(wc_FreeRsaKey(&key), 0);
#endif
    return EXPECT_RESULT();

} /* END test_wc_RsaPrivateKeyDecode */

/*
 * Testing wc_RsaPublicKeyDecode()
 */
int test_wc_RsaPublicKeyDecode(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && !defined(NO_SHA256) && \
        (defined(USE_CERT_BUFFERS_1024) || defined(USE_CERT_BUFFERS_2048)) && \
        !defined(HAVE_FIPS)
    RsaKey keyPub;
    byte*  tmp = NULL;
    word32 idx = 0;
    int    bytes = 0;
    word32 keySz = 0;
    word32 tstKeySz = 0;
#if defined(WC_RSA_PSS) && !defined(NO_FILESYSTEM)
    XFILE f = XBADFILE;
    const char* rsaPssPubKey = "./certs/rsapss/ca-rsapss-key.der";
    const char* rsaPssPubKeyNoParams = "./certs/rsapss/ca-3072-rsapss-key.der";
    byte buf[4096];
#endif

    XMEMSET(&keyPub, 0, sizeof(RsaKey));

    ExpectNotNull(tmp = (byte*)XMALLOC(GEN_BUF, NULL, DYNAMIC_TYPE_TMP_BUFFER));
    ExpectIntEQ(wc_InitRsaKey(&keyPub, HEAP_HINT), 0);
    if (tmp != NULL) {
    #ifdef USE_CERT_BUFFERS_1024
        XMEMCPY(tmp, client_keypub_der_1024, sizeof_client_keypub_der_1024);
        bytes = sizeof_client_keypub_der_1024;
        keySz = 1024;
    #else
        XMEMCPY(tmp, client_keypub_der_2048, sizeof_client_keypub_der_2048);
        bytes = sizeof_client_keypub_der_2048;
        keySz = 2048;
    #endif
    }

    ExpectIntEQ(wc_RsaPublicKeyDecode(tmp, &idx, &keyPub, (word32)bytes), 0);

    /* Pass in bad args. */
    ExpectIntEQ(wc_RsaPublicKeyDecode(NULL, &idx, &keyPub, (word32)bytes),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaPublicKeyDecode(tmp, NULL, &keyPub, (word32)bytes),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaPublicKeyDecode(tmp, &idx, NULL, (word32)bytes),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    DoExpectIntEQ(wc_FreeRsaKey(&keyPub), 0);

    /* Test for getting modulus key size */
    idx = 0;
    ExpectIntEQ(wc_RsaPublicKeyDecode_ex(tmp, &idx, (word32)bytes, NULL,
        &tstKeySz, NULL, NULL), 0);
    ExpectIntEQ(tstKeySz, keySz/8);

#if defined(WC_RSA_PSS) && !defined(NO_FILESYSTEM)
    ExpectTrue((f = XFOPEN(rsaPssPubKey, "rb")) != XBADFILE);
    ExpectIntGT(bytes = (int)XFREAD(buf, 1, sizeof(buf), f), 0);
    if (f != XBADFILE) {
        XFCLOSE(f);
        f = XBADFILE;
    }
    idx = 0;
    ExpectIntEQ(wc_RsaPublicKeyDecode_ex(buf, &idx, (word32)bytes, NULL, NULL,
        NULL, NULL), 0);
    ExpectTrue((f = XFOPEN(rsaPssPubKeyNoParams, "rb")) != XBADFILE);
    ExpectIntGT(bytes = (int)XFREAD(buf, 1, sizeof(buf), f), 0);
    if (f != XBADFILE)
        XFCLOSE(f);
    idx = 0;
    ExpectIntEQ(wc_RsaPublicKeyDecode_ex(buf, &idx, (word32)bytes, NULL, NULL,
        NULL, NULL), 0);
#endif

    XFREE(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}  /* END test_wc_RsaPublicKeyDecode */

/*
 * Testing wc_RsaPublicKeyDecodeRaw()
 */
int test_wc_RsaPublicKeyDecodeRaw(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA)
    RsaKey     key;
    const byte n = 0x23;
    const byte e = 0x03;
    word32     nSz = sizeof(n);
    word32     eSz = sizeof(e);

    ExpectIntEQ(wc_InitRsaKey(&key, HEAP_HINT), 0);
    ExpectIntEQ(wc_RsaPublicKeyDecodeRaw(&n, nSz, &e, eSz, &key), 0);

    /* Pass in bad args. */
    ExpectIntEQ(wc_RsaPublicKeyDecodeRaw(NULL, nSz, &e, eSz, &key),
       WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaPublicKeyDecodeRaw(&n, nSz, NULL, eSz, &key),
       WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaPublicKeyDecodeRaw(&n, nSz, &e, eSz, NULL),
       WC_NO_ERR_TRACE(BAD_FUNC_ARG));


    DoExpectIntEQ(wc_FreeRsaKey(&key), 0);
#endif
    return EXPECT_RESULT();

} /* END test_wc_RsaPublicKeyDecodeRaw */

/*
 * Testing wc_RsaPrivateKeyDecodeRaw()
 */
int test_wc_RsaPrivateKeyDecodeRaw(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
    RsaKey key;
    const byte n = 33;
    const byte e = 3;
    const byte d = 7;
    const byte u = 2;
    const byte p = 3;
    const byte q = 11;
    const byte dp = 1;
    const byte dq = 7;

    ExpectIntEQ(wc_InitRsaKey(&key, HEAP_HINT), 0);
    ExpectIntEQ(wc_RsaPrivateKeyDecodeRaw(&n, sizeof(n),
                &e, sizeof(e), &d, sizeof(d), &u, sizeof(u),
                &p, sizeof(p), &q, sizeof(q), NULL, 0,
                NULL, 0, &key), 0);
    ExpectIntEQ(wc_RsaPrivateKeyDecodeRaw(&n, sizeof(n),
                &e, sizeof(e), &d, sizeof(d), &u, sizeof(u),
                &p, sizeof(p), &q, sizeof(q), &dp, sizeof(dp),
                NULL, 0, &key), 0);
    ExpectIntEQ(wc_RsaPrivateKeyDecodeRaw(&n, sizeof(n),
                &e, sizeof(e), &d, sizeof(d), &u, sizeof(u),
                &p, sizeof(p), &q, sizeof(q), NULL, 0,
                &dq, sizeof(dq), &key), 0);
    ExpectIntEQ(wc_RsaPrivateKeyDecodeRaw(&n, sizeof(n),
                &e, sizeof(e), &d, sizeof(d), &u, sizeof(u),
                &p, sizeof(p), &q, sizeof(q), &dp, sizeof(dp),
                &dq, sizeof(dq), &key), 0);

    /* Pass in bad args. */
    ExpectIntEQ(wc_RsaPrivateKeyDecodeRaw(NULL, sizeof(n),
                &e, sizeof(e), &d, sizeof(d), &u, sizeof(u),
                &p, sizeof(p), &q, sizeof(q), &dp, sizeof(dp),
                &dq, sizeof(dq), &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaPrivateKeyDecodeRaw(&n, 0,
                &e, sizeof(e), &d, sizeof(d), &u, sizeof(u),
                &p, sizeof(p), &q, sizeof(q), &dp, sizeof(dp),
                &dq, sizeof(dq), &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaPrivateKeyDecodeRaw(&n, sizeof(n),
                NULL, sizeof(e), &d, sizeof(d), &u, sizeof(u),
                &p, sizeof(p), &q, sizeof(q), &dp, sizeof(dp),
                &dq, sizeof(dq), &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaPrivateKeyDecodeRaw(&n, sizeof(n),
                &e, 0, &d, sizeof(d), &u, sizeof(u),
                &p, sizeof(p), &q, sizeof(q), &dp, sizeof(dp),
                &dq, sizeof(dq), &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaPrivateKeyDecodeRaw(&n, sizeof(n),
                &e, sizeof(e), NULL, sizeof(d), &u, sizeof(u),
                &p, sizeof(p), &q, sizeof(q), &dp, sizeof(dp),
                &dq, sizeof(dq), &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaPrivateKeyDecodeRaw(&n, sizeof(n),
                &e, sizeof(e), &d, 0, &u, sizeof(u),
                &p, sizeof(p), &q, sizeof(q), &dp, sizeof(dp),
                &dq, sizeof(dq), &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaPrivateKeyDecodeRaw(&n, sizeof(n),
                &e, sizeof(e), &d, sizeof(d), &u, sizeof(u),
                NULL, sizeof(p), &q, sizeof(q), &dp, sizeof(dp),
                &dq, sizeof(dq), &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaPrivateKeyDecodeRaw(&n, sizeof(n),
                &e, sizeof(e), &d, sizeof(d), &u, sizeof(u),
                &p, 0, &q, sizeof(q), &dp, sizeof(dp),
                &dq, sizeof(dq), &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaPrivateKeyDecodeRaw(&n, sizeof(n),
                &e, sizeof(e), &d, sizeof(d), &u, sizeof(u),
                &p, sizeof(p), NULL, sizeof(q), &dp, sizeof(dp),
                &dq, sizeof(dq), &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaPrivateKeyDecodeRaw(&n, sizeof(n),
                &e, sizeof(e), &d, sizeof(d), &u, sizeof(u),
                &p, sizeof(p), &q, 0, &dp, sizeof(dp),
                &dq, sizeof(dq), &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#if defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA) || !defined(RSA_LOW_MEM)
    ExpectIntEQ(wc_RsaPrivateKeyDecodeRaw(&n, sizeof(n),
                &e, sizeof(e), &d, sizeof(d), &u, 0,
                &p, sizeof(p), &q, sizeof(q), &dp, sizeof(dp),
                &dq, sizeof(dq), &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaPrivateKeyDecodeRaw(&n, sizeof(n),
                &e, sizeof(e), &d, sizeof(d), NULL, sizeof(u),
                &p, sizeof(p), &q, sizeof(q), &dp, sizeof(dp),
                &dq, sizeof(dq), &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaPrivateKeyDecodeRaw(&n, sizeof(n),
                &e, sizeof(e), &d, sizeof(d), &u, 0,
                &p, sizeof(p), &q, sizeof(q), &dp, sizeof(dp),
                &dq, sizeof(dq), &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif

    DoExpectIntEQ(wc_FreeRsaKey(&key), 0);
#endif
    return EXPECT_RESULT();
} /* END  test_wc_RsaPrivateKeyDecodeRaw */

#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
    /* In FIPS builds, wc_MakeRsaKey() will return an error if it cannot find
     * a probable prime in 5*(modLen/2) attempts. In non-FIPS builds, it keeps
     * trying until it gets a probable prime. */
    #ifdef HAVE_FIPS
        int MakeRsaKeyRetry(RsaKey* key, int size, long e, WC_RNG* rng)
        {
            int ret;

            for (;;) {
                ret = wc_MakeRsaKey(key, size, e, rng);
                if (ret != WC_NO_ERR_TRACE(PRIME_GEN_E)) break;
                fprintf(stderr, "MakeRsaKey couldn't find prime; "
                                "trying again.\n");
            }

            return ret;
        }
    #endif
#endif

/*
 * Testing wc_MakeRsaKey()
 */
int test_wc_MakeRsaKey(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)

    RsaKey genKey;
    WC_RNG rng;
#if (!defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL)) && \
    (!defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION < 4)) && \
    (defined(RSA_MIN_SIZE) && (RSA_MIN_SIZE <= 1024))
    int bits = 1024;
#else
    int bits = 2048;
#endif

    XMEMSET(&genKey, 0, sizeof(RsaKey));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_InitRsaKey(&genKey, HEAP_HINT), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(MAKE_RSA_KEY(&genKey, bits, WC_RSA_EXPONENT, &rng), 0);
    DoExpectIntEQ(wc_FreeRsaKey(&genKey), 0);

    /* Test bad args. */
    ExpectIntEQ(MAKE_RSA_KEY(NULL, bits, WC_RSA_EXPONENT, &rng),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(MAKE_RSA_KEY(&genKey, bits, WC_RSA_EXPONENT, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* e < 3 */
    ExpectIntEQ(MAKE_RSA_KEY(&genKey, bits, 2, &rng),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* e & 1 == 0 */
    ExpectIntEQ(MAKE_RSA_KEY(&genKey, bits, 6, &rng),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
} /* END test_wc_MakeRsaKey */

/*
 * Testing wc_CheckProbablePrime()
 */
int test_wc_CheckProbablePrime(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN) && !defined(HAVE_SELFTEST) && \
 !defined(HAVE_FIPS) && defined(WC_RSA_BLINDING)
#define CHECK_PROBABLE_PRIME_KEY_BITS 2048
    RsaKey key;
    WC_RNG rng;
    byte   e[3];
    word32 eSz = (word32)sizeof(e);
    byte   n[CHECK_PROBABLE_PRIME_KEY_BITS / 8];
    word32 nSz = (word32)sizeof(n);
    byte   d[CHECK_PROBABLE_PRIME_KEY_BITS / 8];
    word32 dSz = (word32)sizeof(d);
    byte   p[CHECK_PROBABLE_PRIME_KEY_BITS / 8 / 2];
    word32 pSz = (word32)sizeof(p);
    byte   q[CHECK_PROBABLE_PRIME_KEY_BITS / 8 / 2];
    word32 qSz = (word32)sizeof(q);
    int    nlen = CHECK_PROBABLE_PRIME_KEY_BITS;
    int*   isPrime;
    int    test[5];
    isPrime = test;

    XMEMSET(&key, 0, sizeof(RsaKey));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_InitRsaKey(&key, HEAP_HINT), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_RsaSetRNG(&key, &rng), 0);
    ExpectIntEQ(wc_MakeRsaKey(&key, CHECK_PROBABLE_PRIME_KEY_BITS,
        WC_RSA_EXPONENT, &rng), 0);
    PRIVATE_KEY_UNLOCK();
    ExpectIntEQ(wc_RsaExportKey(&key, e, &eSz, n, &nSz, d, &dSz, p, &pSz, q,
        &qSz), 0);
    PRIVATE_KEY_LOCK();

    /* Bad cases */
    ExpectIntEQ(wc_CheckProbablePrime(NULL, pSz, q, qSz, e, eSz, nlen, isPrime),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_CheckProbablePrime(p, 0, q, qSz, e, eSz, nlen, isPrime),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_CheckProbablePrime(p, pSz, NULL, qSz, e, eSz, nlen, isPrime),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_CheckProbablePrime(p, pSz, q, 0, e, eSz, nlen, isPrime),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_CheckProbablePrime(p, pSz, q, qSz, NULL, eSz, nlen, isPrime),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_CheckProbablePrime(p, pSz, q, qSz, e, 0, nlen, isPrime),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_CheckProbablePrime(NULL, 0, NULL, 0, NULL, 0, nlen, isPrime),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Good case */
    ExpectIntEQ(wc_CheckProbablePrime(p, pSz, q, qSz, e, eSz, nlen, isPrime),
        0);

    DoExpectIntEQ(wc_FreeRsaKey(&key), 0);
    wc_FreeRng(&rng);
#undef CHECK_PROBABLE_PRIME_KEY_BITS
#endif
    return EXPECT_RESULT();
} /* END  test_wc_CheckProbablePrime */

/*
 * Testing wc_RsaPSS_Verify()
 */
int test_wc_RsaPSS_Verify(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN) && !defined(HAVE_SELFTEST) && \
 !defined(HAVE_FIPS) && defined(WC_RSA_BLINDING) && defined(WC_RSA_PSS)
    RsaKey        key;
    WC_RNG        rng;
    int           sz = 256;
    const char*   szMessage = "This is the string to be signed";
    unsigned char pSignature[2048/8]; /* 2048 is RSA_KEY_SIZE */
    unsigned char pDecrypted[2048/8];
    byte*         pt = pDecrypted;
    word32        outLen = sizeof(pDecrypted);

    XMEMSET(&key, 0, sizeof(RsaKey));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_InitRsaKey(&key, HEAP_HINT), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_RsaSetRNG(&key, &rng), 0);
    ExpectIntEQ(wc_MakeRsaKey(&key, 2048, WC_RSA_EXPONENT, &rng), 0);

    ExpectIntGT(sz = wc_RsaPSS_Sign((byte*)szMessage,
        (word32)XSTRLEN(szMessage)+1, pSignature, sizeof(pSignature),
        WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key, &rng), 0);

    /* Bad cases */
    ExpectIntEQ(wc_RsaPSS_Verify(NULL, (word32)sz, pt, outLen,
        WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaPSS_Verify(pSignature, 0, pt, outLen,
        WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaPSS_Verify(pSignature, (word32)sz, NULL, outLen,
        WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaPSS_Verify(NULL, 0, NULL, outLen,
        WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Good case */
    ExpectIntGT(wc_RsaPSS_Verify(pSignature, (word32)sz, pt, outLen,
        WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key), 0);

    DoExpectIntEQ(wc_FreeRsaKey(&key), 0);
    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
} /* END  test_wc_RsaPSS_Verify */

int test_wc_RsaPSS_BadTerminator(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN) && !defined(HAVE_SELFTEST) && \
    !defined(HAVE_FIPS) && defined(WC_RSA_BLINDING) && defined(WC_RSA_PSS) && \
    (defined(WC_RSA_DIRECT) || defined(WC_RSA_NO_PADDING) || \
     defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL))
    RsaKey        key;
    WC_RNG        rng;
    const char*   msg = "This is the string to be signed";
    unsigned char sig[2048/8];
    unsigned char em[2048/8];
    unsigned char badSig[2048/8];
    unsigned char verifyOut[2048/8];
    int           sigLen = 0;
    word32        emSz = sizeof(em);
    word32        badSigSz = sizeof(badSig);

    XMEMSET(&key, 0, sizeof(RsaKey));
    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(em, 0, sizeof(em));
    XMEMSET(sig, 0, sizeof(sig));
    XMEMSET(badSig, 0, sizeof(badSig));

    ExpectIntEQ(wc_InitRsaKey(&key, HEAP_HINT), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_RsaSetRNG(&key, &rng), 0);
    ExpectIntEQ(wc_MakeRsaKey(&key, 2048, WC_RSA_EXPONENT, &rng), 0);

    ExpectIntGT(sigLen = wc_RsaPSS_Sign((const byte*)msg,
        (word32)XSTRLEN(msg) + 1, sig, sizeof(sig),
        WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key, &rng), 0);

    ExpectIntGT(wc_RsaDirect(sig, (word32)sigLen, em, &emSz, &key,
        RSA_PUBLIC_DECRYPT, NULL), 0);

    ExpectTrue(emSz > 0);
    if (emSz > 0) {
        ExpectIntEQ((int)em[emSz - 1], 0xbc);
    }

    if (emSz > 0 && em[emSz - 1] == 0xbc) {
        em[emSz - 1] = 0xbd;

        ExpectIntGT(wc_RsaDirect(em, emSz, badSig, &badSigSz, &key,
            RSA_PRIVATE_ENCRYPT, &rng), 0);

        ExpectIntEQ(wc_RsaPSS_Verify(badSig, badSigSz, verifyOut,
            sizeof(verifyOut),
            WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key),
            WC_NO_ERR_TRACE(BAD_PADDING_E));
    }

    DoExpectIntEQ(wc_FreeRsaKey(&key), 0);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
} /* END test_wc_RsaPSS_BadTerminator */

/*
 * Testing wc_RsaPSS_VerifyCheck()
 */
int test_wc_RsaPSS_VerifyCheck(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN) && !defined(HAVE_SELFTEST) && \
 !defined(HAVE_FIPS) && defined(WC_RSA_BLINDING) && defined(WC_RSA_PSS)
    RsaKey        key;
    WC_RNG        rng;
    int           sz = 256; /* 2048/8 */
    byte          digest[32];
    word32        digestSz = sizeof(digest);
    unsigned char pSignature[2048/8]; /* 2048 is RSA_KEY_SIZE */
    word32        pSignatureSz = sizeof(pSignature);
    unsigned char pDecrypted[2048/8];
    byte*         pt = pDecrypted;
    word32        outLen = sizeof(pDecrypted);

    XMEMSET(&key, 0, sizeof(RsaKey));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    XMEMSET(digest, 0, sizeof(digest));
    XMEMSET(pSignature, 0, sizeof(pSignature));

    ExpectIntEQ(wc_InitRsaKey(&key, HEAP_HINT), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_RsaSetRNG(&key, &rng), 0);
    ExpectIntEQ(wc_MakeRsaKey(&key, 2048, WC_RSA_EXPONENT, &rng), 0);
    ExpectTrue((digestSz = (word32)wc_HashGetDigestSize(WC_HASH_TYPE_SHA256)) >
        0);
    ExpectIntEQ(wc_Hash(WC_HASH_TYPE_SHA256, pSignature, (word32)sz, digest,
        digestSz), 0);

    ExpectIntGT(sz = wc_RsaPSS_Sign(digest, digestSz, pSignature, pSignatureSz,
        WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key, &rng), 0);

    /* Bad cases */
    ExpectIntEQ(wc_RsaPSS_VerifyCheck(NULL, (word32)sz, pt, outLen, digest,
        digestSz, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaPSS_VerifyCheck(pSignature, 0, pt, outLen, digest,
        digestSz, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaPSS_VerifyCheck(pSignature, (word32)sz, NULL, outLen,
        digest, digestSz, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaPSS_VerifyCheck(NULL, 0, NULL, outLen, digest,
        digestSz, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Good case */
    ExpectIntGT(wc_RsaPSS_VerifyCheck(pSignature, (word32)sz, pt, outLen,
        digest, digestSz, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key), 0);

    ExpectIntEQ(wc_FreeRsaKey(&key), 0);
    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
} /* END  test_wc_RsaPSS_VerifyCheck */

/*
 * Testing wc_RsaPSS_VerifyCheckInline()
 */
int test_wc_RsaPSS_VerifyCheckInline(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN) && !defined(HAVE_SELFTEST) && \
 !defined(HAVE_FIPS) && defined(WC_RSA_BLINDING) && defined(WC_RSA_PSS)
    RsaKey        key;
    WC_RNG        rng;
    int           sz = 256;
    byte          digest[32];
    word32        digestSz = sizeof(digest);
    unsigned char pSignature[2048/8]; /* 2048 is RSA_KEY_SIZE */
    unsigned char pDecrypted[2048/8];
    byte*         pt = pDecrypted;

    XMEMSET(&key, 0, sizeof(RsaKey));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    XMEMSET(digest, 0, sizeof(digest));
    XMEMSET(pSignature, 0, sizeof(pSignature));

    ExpectIntEQ(wc_InitRsaKey(&key, HEAP_HINT), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_RsaSetRNG(&key, &rng), 0);
    ExpectIntEQ(wc_MakeRsaKey(&key, 2048, WC_RSA_EXPONENT, &rng), 0);
    ExpectTrue((digestSz = (word32)wc_HashGetDigestSize(WC_HASH_TYPE_SHA256)) >
        0);
    ExpectIntEQ(wc_Hash(WC_HASH_TYPE_SHA256, pSignature, (word32)sz, digest,
        digestSz), 0);

    ExpectIntGT(sz = wc_RsaPSS_Sign(digest, digestSz, pSignature,
        sizeof(pSignature), WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key, &rng), 0);

    /* Bad Cases */
    ExpectIntEQ(wc_RsaPSS_VerifyCheckInline(NULL, (word32)sz, &pt, digest,
        digestSz, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaPSS_VerifyCheckInline(pSignature, 0, NULL, digest,
        digestSz, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaPSS_VerifyCheckInline(NULL, 0, &pt, digest,
        digestSz, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaPSS_VerifyCheckInline(pSignature, (word32)sz, &pt, digest,
        digestSz, WC_HASH_TYPE_SHA, WC_MGF1SHA256, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Good case */
    ExpectIntGT(wc_RsaPSS_VerifyCheckInline(pSignature, (word32)sz, &pt, digest,
        digestSz, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key), 0);

    DoExpectIntEQ(wc_FreeRsaKey(&key), 0);
    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
} /* END  test_wc_RsaPSS_VerifyCheckInline */

/*
 * Testing wc_RsaKeyToDer()
 */
int test_wc_RsaKeyToDer(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && \
    (defined(WOLFSSL_KEY_GEN) || defined(WOLFSSL_KEY_TO_DER))
    RsaKey key;
    byte*  der = NULL;
    word32 derSz = 0;
#if defined(WOLFSSL_KEY_GEN)
    WC_RNG rng;
#if (!defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL)) && \
    (!defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION < 4)) && \
    (defined(RSA_MIN_SIZE) && (RSA_MIN_SIZE <= 1024))
    int    bits = 1024;
#else
    int    bits = 2048;
#endif
#else
    word32 idx = 0;
    byte* key_der = NULL;
#if !defined(NO_FILESYSTEM)
    const char* key_fname = "./certs/client-key.der";
    XFILE file = XBADFILE;
#endif
#endif /* WOLFSSL_KEY_GEN */

#if defined(WOLFSSL_KEY_GEN)
    XMEMSET(&rng, 0, sizeof(rng));
#endif
    XMEMSET(&key, 0, sizeof(key));

    /* Init RSA structure */
    ExpectIntEQ(wc_InitRsaKey(&key, HEAP_HINT), 0);

#if defined(WOLFSSL_KEY_GEN)
    /* Init RMG */
    ExpectIntEQ(wc_InitRng(&rng), 0);
    /* Make key */
    ExpectIntEQ(MAKE_RSA_KEY(&key, bits, WC_RSA_EXPONENT, &rng), 0);
#else
    /* Import a key */
#if !defined(NO_FILESYSTEM)
    ExpectTrue((file = XFOPEN(key_fname, "rb")) != XBADFILE);
    ExpectIntEQ(XFSEEK(file, 0, XSEEK_END), 0);
    ExpectIntGT(derSz = (word32)XFTELL(file), 0);
    ExpectIntEQ(XFSEEK(file, 0, XSEEK_SET), 0);
    ExpectNotNull(key_der = (byte*)XMALLOC(derSz, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    ExpectIntEQ((int)XFREAD(key_der, 1, derSz, file), derSz);
    XFCLOSE(file);
#elif defined(USE_CERT_BUFFERS_1024) && \
    (defined(RSA_MIN_SIZE) && (RSA_MIN_SIZE <= 1024))
    key_der = (byte*)client_key_der_1024;
    derSz = (word32)sizeof_client_key_der_1024;
#elif defined(USE_CERT_BUFFERS_2048)
    key_der = (byte*)client_key_der_2048;
    derSz = (word32)sizeof_client_key_der_2048;
#elif defined(USE_CERT_BUFFERS_3072)
    key_der = (byte*)client_key_der_3072;
    derSz = (word32)sizeof_client_key_der_3072;
#elif defined(USE_CERT_BUFFERS_4096)
    key_der = (byte*)client_key_der_4096;
    derSz = (word32)sizeof_client_key_der_4096;
#endif

    /* Import private key */
    ExpectIntEQ(wc_RsaPrivateKeyDecode(key_der, &idx, &key, derSz), 0);

#if !defined(NO_FILESYSTEM)
    XFREE(key_der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
#endif /* WOLFSSL_KEY_GEN */

    /* Get output length */
    ExpectIntGT((derSz = wc_RsaKeyToDer(&key, NULL, 0)), 0);
    ExpectNotNull(der = (byte*)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER));

    /* Test exporting private key to DER */
    ExpectIntGT(wc_RsaKeyToDer(&key, der, derSz), 0);

    /* Pass good/bad args. */
    ExpectIntEQ(wc_RsaKeyToDer(NULL, der, derSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Try Public Key. */
    key.type = 0;
    ExpectIntEQ(wc_RsaKeyToDer(&key, der, derSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    #ifdef WOLFSSL_CHECK_MEM_ZERO
        /* Put back to Private Key */
        key.type = 1;
    #endif

    XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    DoExpectIntEQ(wc_FreeRsaKey(&key), 0);
    #if defined(WOLFSSL_KEY_GEN)
        DoExpectIntEQ(wc_FreeRng(&rng), 0);
    #endif
#endif
    return EXPECT_RESULT();
} /* END test_wc_RsaKeyToDer */

/*
 *  Testing wc_RsaKeyToPublicDer()
 */
int test_wc_RsaKeyToPublicDer(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
    RsaKey key;
    WC_RNG rng;
    byte*  der = NULL;
#if (!defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL)) && \
    (!defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION < 4)) && \
    (defined(RSA_MIN_SIZE) && (RSA_MIN_SIZE <= 1024))
    int    bits = 1024;
    word32 derLen = 162;
#else
    int    bits = 2048;
    word32 derLen = 294;
#endif
    int    ret = 0;

    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&key, 0, sizeof(key));

    ExpectNotNull(der = (byte*)XMALLOC(derLen, NULL, DYNAMIC_TYPE_TMP_BUFFER));
    ExpectIntEQ(wc_InitRsaKey(&key, HEAP_HINT), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(MAKE_RSA_KEY(&key, bits, WC_RSA_EXPONENT, &rng), 0);

    /* test getting size only */
    ExpectIntGT(wc_RsaKeyToPublicDer(&key, NULL, derLen), 0);
    ExpectIntGT(wc_RsaKeyToPublicDer(&key, der, derLen), 0);

    /* test getting size only */
    ExpectIntGT(wc_RsaKeyToPublicDer_ex(&key, NULL, derLen, 0), 0);
    ExpectIntGT(wc_RsaKeyToPublicDer_ex(&key, der, derLen, 0), 0);

    /* Pass in bad args. */
    ExpectIntEQ(wc_RsaKeyToPublicDer(NULL, der, derLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntLT(ret = wc_RsaKeyToPublicDer(&key, der, -1), 0);
    ExpectTrue((ret == WC_NO_ERR_TRACE(BUFFER_E)) ||
               (ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG)));

    XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    DoExpectIntEQ(wc_FreeRsaKey(&key), 0);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
} /* END test_wc_RsaKeyToPublicDer */

/*
 *  Testing wc_RsaPublicEncrypt() and wc_RsaPrivateDecrypt()
 */
int test_wc_RsaPublicEncryptDecrypt(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN) && \
    !defined(WOLFSSL_RSA_PUBLIC_ONLY)
    RsaKey key;
    WC_RNG rng;
    const char inStr[] = TEST_STRING;
    const word32 plainLen = (word32)TEST_STRING_SZ;
    const word32 inLen = (word32)TEST_STRING_SZ;
    int          bits = TEST_RSA_BITS;
    const word32 cipherLen = TEST_RSA_BYTES;
    word32 cipherLenResult = cipherLen;
    WC_DECLARE_VAR(in, byte, TEST_STRING_SZ, NULL);
    WC_DECLARE_VAR(plain, byte, TEST_STRING_SZ, NULL);
    WC_DECLARE_VAR(cipher, byte, TEST_RSA_BYTES, NULL);

    WC_ALLOC_VAR(in, byte, TEST_STRING_SZ, NULL);
    WC_ALLOC_VAR(plain, byte, TEST_STRING_SZ, NULL);
    WC_ALLOC_VAR(cipher, byte, TEST_RSA_BYTES, NULL);

#ifdef WC_DECLARE_VAR_IS_HEAP_ALLOC
    ExpectNotNull(in);
    ExpectNotNull(plain);
    ExpectNotNull(cipher);
#endif
    ExpectNotNull(XMEMCPY(in, inStr, inLen));

    /* Initialize stack structures. */
    XMEMSET(&key, 0, sizeof(RsaKey));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_InitRsaKey(&key, HEAP_HINT), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(MAKE_RSA_KEY(&key, bits, WC_RSA_EXPONENT, &rng), 0);

    /* Encrypt. */
    ExpectIntGT(cipherLenResult = (word32)wc_RsaPublicEncrypt(in, inLen, cipher,
        cipherLen, &key, &rng), 0);
    /* Pass bad args - tested in another testing function.*/

    /* Decrypt */
#if defined(WC_RSA_BLINDING) && !defined(HAVE_FIPS)
    /* Bind rng */
    ExpectIntEQ(wc_RsaSetRNG(&key, &rng), 0);
#endif
    ExpectIntGE(wc_RsaPrivateDecrypt(cipher, cipherLenResult, plain, plainLen,
        &key), 0);
    ExpectIntEQ(XMEMCMP(plain, inStr, plainLen), 0);
    /* Pass bad args - tested in another testing function.*/

#if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || FIPS_VERSION3_GE(7,0,0))
    {
        WC_DECLARE_VAR(shortPlain, byte, TEST_STRING_SZ - 4, NULL);
        WC_ALLOC_VAR(shortPlain, byte, TEST_STRING_SZ - 4, NULL);
    #ifdef WC_DECLARE_VAR_IS_HEAP_ALLOC
        ExpectNotNull(shortPlain);
    #endif
        /* Test for when plain length is less than required. */
        ExpectIntEQ(wc_RsaPrivateDecrypt(cipher, cipherLenResult, shortPlain,
                                         TEST_STRING_SZ - 4, &key), RSA_BUFFER_E);
        WC_FREE_VAR(shortPlain, NULL);
    }
#endif /* !HAVE_SELFTEST && (!HAVE_FIPS || FIPS_VERSION3_GE(7,0,0)) */

    WC_FREE_VAR(in, NULL);
    WC_FREE_VAR(plain, NULL);
    WC_FREE_VAR(cipher, NULL);
    DoExpectIntEQ(wc_FreeRsaKey(&key), 0);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();

} /* END test_wc_RsaPublicEncryptDecrypt */

/*
 * Testing wc_RsaPrivateDecrypt_ex() and wc_RsaPrivateDecryptInline_ex()
 */
int test_wc_RsaPublicEncryptDecrypt_ex(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN) && !defined(HAVE_FIPS) && \
        !defined(WC_NO_RSA_OAEP) && !defined(NO_SHA256)
    RsaKey  key;
    WC_RNG  rng;
    const char inStr[] = TEST_STRING;
    const word32 inLen = (word32)TEST_STRING_SZ;
    int     idx = 0;
    int          bits = TEST_RSA_BITS;
    const word32 cipherSz = TEST_RSA_BYTES;
#ifndef WOLFSSL_RSA_PUBLIC_ONLY
    const word32 plainSz = (word32)TEST_STRING_SZ;
    byte*   res = NULL;

    WC_DECLARE_VAR(plain, byte, TEST_STRING_SZ, NULL);
#endif
    WC_DECLARE_VAR(in, byte, TEST_STRING_SZ, NULL);
    WC_DECLARE_VAR(cipher, byte, TEST_RSA_BYTES, NULL);

    WC_ALLOC_VAR(in, byte, TEST_STRING_SZ, NULL);
    WC_ALLOC_VAR(plain, byte, TEST_STRING_SZ, NULL);
    WC_ALLOC_VAR(cipher, byte, TEST_RSA_BYTES, NULL);

#ifdef WC_DECLARE_VAR_IS_HEAP_ALLOC
    ExpectNotNull(in);
    ExpectNotNull(plain);
    ExpectNotNull(cipher);
#endif
    ExpectNotNull(XMEMCPY(in, inStr, inLen));

    /* Initialize stack structures. */
    XMEMSET(&key, 0, sizeof(RsaKey));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_InitRsaKey_ex(&key, HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(MAKE_RSA_KEY(&key, bits, WC_RSA_EXPONENT, &rng), 0);

    /* Encrypt */
    ExpectIntGE(idx = wc_RsaPublicEncrypt_ex(in, inLen, cipher, cipherSz, &key,
        &rng, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, NULL, 0), 0);
    /* Pass bad args - tested in another testing function.*/

#ifndef WOLFSSL_RSA_PUBLIC_ONLY
    /* Decrypt */
    #if defined(WC_RSA_BLINDING) && !defined(HAVE_FIPS)
        ExpectIntEQ(wc_RsaSetRNG(&key, &rng), 0);
    #endif
    ExpectIntGE(wc_RsaPrivateDecrypt_ex(cipher, (word32)idx, plain, plainSz,
        &key, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, NULL, 0), 0);
    ExpectIntEQ(XMEMCMP(plain, inStr, plainSz), 0);
    /* Pass bad args - tested in another testing function.*/

    ExpectIntGE(wc_RsaPrivateDecryptInline_ex(cipher, (word32)idx, &res, &key,
        WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, NULL, 0), 0);
    ExpectIntEQ(XMEMCMP(inStr, res, plainSz), 0);
#endif

    WC_FREE_VAR(in, NULL);
    WC_FREE_VAR(plain, NULL);
    WC_FREE_VAR(cipher, NULL);
    DoExpectIntEQ(wc_FreeRsaKey(&key), 0);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
} /* END test_wc_RsaPublicEncryptDecrypt_ex */

/*
 * Tesing wc_RsaSSL_Sign() and wc_RsaSSL_Verify()
 */
int test_wc_RsaSSL_SignVerify(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
    RsaKey key;
    WC_RNG rng;
    const char inStr[] = TEST_STRING;
    const word32 plainSz = (word32)TEST_STRING_SZ;
    const word32 inLen = (word32)TEST_STRING_SZ;
    word32 idx = 0;
    int    bits = TEST_RSA_BITS;
    const word32 outSz = TEST_RSA_BYTES;

    WC_DECLARE_VAR(in, byte, TEST_STRING_SZ, NULL);
    WC_DECLARE_VAR(out, byte, TEST_RSA_BYTES, NULL);
    WC_DECLARE_VAR(plain, byte, TEST_STRING_SZ, NULL);

    WC_ALLOC_VAR(in, byte, TEST_STRING_SZ, NULL);
    WC_ALLOC_VAR(out, byte, TEST_RSA_BYTES, NULL);
    WC_ALLOC_VAR(plain, byte, TEST_STRING_SZ, NULL);

#ifdef WC_DECLARE_VAR_IS_HEAP_ALLOC
    ExpectNotNull(in);
    ExpectNotNull(out);
    ExpectNotNull(plain);
#endif
    ExpectNotNull(XMEMCPY(in, inStr, inLen));

    XMEMSET(&key, 0, sizeof(RsaKey));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_InitRsaKey(&key, HEAP_HINT), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(MAKE_RSA_KEY(&key, bits, WC_RSA_EXPONENT, &rng), 0);

    /* Sign. */
    ExpectIntEQ(wc_RsaSSL_Sign(in, inLen, out, outSz, &key, &rng), (int)outSz);
    idx = (int)outSz;

    /* Test bad args. */
    ExpectIntEQ(wc_RsaSSL_Sign(NULL, inLen, out, outSz, &key, &rng),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaSSL_Sign(in, 0, out, outSz, &key, &rng),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaSSL_Sign(in, inLen, NULL, outSz, &key, &rng),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaSSL_Sign(in, inLen, out, outSz, NULL, &rng),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Verify. */
    ExpectIntEQ(wc_RsaSSL_Verify(out, idx, plain, plainSz, &key), (int)inLen);

    /* Pass bad args. */
    ExpectIntEQ(wc_RsaSSL_Verify(NULL, idx, plain, plainSz, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaSSL_Verify(out, 0, plain, plainSz, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaSSL_Verify(out, idx, NULL, plainSz, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaSSL_Verify(out, idx, plain, plainSz, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    WC_FREE_VAR(in, NULL);
    WC_FREE_VAR(out, NULL);
    WC_FREE_VAR(plain, NULL);
    DoExpectIntEQ(wc_FreeRsaKey(&key), 0);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
} /* END test_wc_RsaSSL_SignVerify */

/*
 * Testing wc_RsaEncryptSize()
 */
int test_wc_RsaEncryptSize(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
    RsaKey key;
    WC_RNG rng;

    XMEMSET(&key, 0, sizeof(RsaKey));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_InitRsaKey(&key, HEAP_HINT), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);

#if (!defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL)) && \
    (!defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION < 4)) && \
    (defined(RSA_MIN_SIZE) && (RSA_MIN_SIZE <= 1024))
    ExpectIntEQ(MAKE_RSA_KEY(&key, 1024, WC_RSA_EXPONENT, &rng), 0);

    ExpectIntEQ(wc_RsaEncryptSize(&key), 128);
    DoExpectIntEQ(wc_FreeRsaKey(&key), 0);
#endif

    ExpectIntEQ(MAKE_RSA_KEY(&key, 2048, WC_RSA_EXPONENT, &rng), 0);
    ExpectIntEQ(wc_RsaEncryptSize(&key), 256);

    /* Pass in bad arg. */
    ExpectIntEQ(wc_RsaEncryptSize(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    DoExpectIntEQ(wc_FreeRsaKey(&key), 0);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();

} /* END test_wc_RsaEncryptSize*/

/*
 * Testing wc_RsaFlattenPublicKey()
 */
int test_wc_RsaFlattenPublicKey(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
    RsaKey key;
    WC_RNG rng;
    byte   e[256];
    byte   n[256];
    word32 eSz = sizeof(e);
    word32 nSz = sizeof(n);
    #if (!defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL)) && \
        (!defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION < 4)) && \
        (defined(RSA_MIN_SIZE) && (RSA_MIN_SIZE <= 1024))
    int    bits = 1024;
    #else
    int    bits = 2048;
    #endif

    XMEMSET(&key, 0, sizeof(RsaKey));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_InitRsaKey(&key, HEAP_HINT), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(MAKE_RSA_KEY(&key, bits, WC_RSA_EXPONENT, &rng), 0);

    ExpectIntEQ(wc_RsaFlattenPublicKey(&key, e, &eSz, n, &nSz), 0);

    /* Pass bad args. */
    ExpectIntEQ(wc_RsaFlattenPublicKey(NULL, e, &eSz, n, &nSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaFlattenPublicKey(&key, NULL, &eSz, n, &nSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaFlattenPublicKey(&key, e, NULL, n, &nSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaFlattenPublicKey(&key, e, &eSz, NULL, &nSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaFlattenPublicKey(&key, e, &eSz, n, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    DoExpectIntEQ(wc_FreeRsaKey(&key), 0);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();

} /* END test_wc_RsaFlattenPublicKey */

/*
 * Test the bounds checking on the cipher text versus the key modulus.
 * 1. Make a new RSA key.
 * 2. Set c to 1.
 * 3. Decrypt c into k. (error)
 * 4. Copy the key modulus to c and sub 1 from the copy.
 * 5. Decrypt c into k. (error)
 * Valid bounds test cases are covered by all the other RSA tests.
 */
int test_wc_RsaDecrypt_BoundsCheck(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && defined(WC_RSA_NO_PADDING) && \
    (defined(USE_CERT_BUFFERS_1024) || defined(USE_CERT_BUFFERS_2048)) && \
    defined(WOLFSSL_PUBLIC_MP) && !defined(NO_RSA_BOUNDS_CHECK)
    WC_RNG rng;
    RsaKey key;
    byte flatC[256];
    word32 flatCSz = 0;
    byte out[256];
    word32 outSz = sizeof(out);

    XMEMSET(&key, 0, sizeof(RsaKey));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_InitRsaKey(&key, HEAP_HINT), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);

    if (EXPECT_SUCCESS()) {
        const byte* derKey;
        word32 derKeySz;
        word32 idx = 0;

        #ifdef USE_CERT_BUFFERS_1024
            derKey = server_key_der_1024;
            derKeySz = (word32)sizeof_server_key_der_1024;
            flatCSz = 128;
        #else
            derKey = server_key_der_2048;
            derKeySz = (word32)sizeof_server_key_der_2048;
            flatCSz = 256;
        #endif

        ExpectIntEQ(wc_RsaPrivateKeyDecode(derKey, &idx, &key, derKeySz), 0);
    }

    if (EXPECT_SUCCESS()) {
        XMEMSET(flatC, 0, flatCSz);
        flatC[flatCSz-1] = 1;

        ExpectIntEQ(wc_RsaDirect(flatC, flatCSz, out, &outSz, &key,
            RSA_PRIVATE_DECRYPT, &rng), WC_NO_ERR_TRACE(RSA_OUT_OF_RANGE_E));
        if (EXPECT_SUCCESS()) {
            mp_int c;
        #ifndef WOLFSSL_SP_MATH
            ExpectIntEQ(mp_init_copy(&c, &key.n), 0);
        #else
            ExpectIntEQ(mp_init(&c), 0);
            ExpectIntEQ(mp_copy(&key.n, &c), 0);
        #endif
            ExpectIntEQ(mp_sub_d(&c, 1, &c), 0);
            ExpectIntEQ(mp_to_unsigned_bin(&c, flatC), 0);
            ExpectIntEQ(wc_RsaDirect(flatC, flatCSz, out, &outSz, &key,
                RSA_PRIVATE_DECRYPT, NULL),
                WC_NO_ERR_TRACE(RSA_OUT_OF_RANGE_E));
            mp_clear(&c);
        }
    }

    DoExpectIntEQ(wc_FreeRsaKey(&key), 0);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
} /* END test_wc_RsaDecryptBoundsCheck */

/*
 * Oversized RSA modulus (mp_bitsused(n) > RSA_MAX_SIZE) must not overflow the
 * static stack buffer used by RsaFunctionCheckIn (DECL_MP_INT_SIZE_DYN).
 *
 * The buffer is sized for RSA_MAX_SIZE digits, and NEW_MP_INT_SIZE would zero
 * mp_bitsused(&key->n) digits of it -- so an oversized modulus must be
 * caught by MP_BITS_OVER_MAX *before* NEW_MP_INT_SIZE is reached.  We feed
 * wc_RsaDirect() an input/output buffer matching the oversized modulus byte
 * size so we get past wc_RsaDirect()'s inLen sanity check and reach the
 * RsaFunctionCheckIn() guard inside wc_RsaFunction_ex().
 */
int test_wc_RsaFunctionCheckIn_OversizedModulus(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && defined(WC_RSA_NO_PADDING) && defined(WC_RSA_DIRECT) && \
    defined(WOLFSSL_PUBLIC_MP) && !defined(NO_RSA_BOUNDS_CHECK) && \
    !defined(WOLFSSL_RSA_VERIFY_ONLY) && !defined(TEST_UNPAD_CONSTANT_TIME) && \
    (defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL)) && \
    !defined(WOLFSSL_SMALL_STACK) && \
    (defined(USE_CERT_BUFFERS_1024) || defined(USE_CERT_BUFFERS_2048))
    /* Setting bit RSA_MAX_SIZE makes the modulus RSA_MAX_SIZE+1 bits, i.e.
     * (RSA_MAX_SIZE/8 + 1) bytes -- size buffers accordingly with slack. */
    #define WC_RSA_OVERSIZED_BUF_LEN ((RSA_MAX_SIZE / 8) + 8)
    WC_RNG rng;
    RsaKey key;
    const byte* derKey;
    word32 derKeySz;
    word32 idx = 0;
    byte flatC[WC_RSA_OVERSIZED_BUF_LEN];
    word32 flatCSz;
    byte out[WC_RSA_OVERSIZED_BUF_LEN];
    word32 outSz = sizeof(out);
    int    encSz;

    #ifdef USE_CERT_BUFFERS_1024
        derKey = server_key_der_1024;
        derKeySz = (word32)sizeof_server_key_der_1024;
    #else
        derKey = server_key_der_2048;
        derKeySz = (word32)sizeof_server_key_der_2048;
    #endif

    XMEMSET(&key, 0, sizeof(RsaKey));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_InitRsaKey(&key, HEAP_HINT), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_RsaPrivateKeyDecode(derKey, &idx, &key, derKeySz), 0);
    /* Force modulus bit count above RSA_MAX_SIZE. */
    ExpectIntEQ(mp_set_bit(&key.n, RSA_MAX_SIZE), 0);

    /* Match wc_RsaDirect()'s inLen check so we actually reach
     * RsaFunctionCheckIn() (where the MP_BITS_OVER_MAX guard lives). */
    encSz = wc_RsaEncryptSize(&key);
    ExpectIntGT(encSz, 0);
    ExpectIntLE(encSz, (int)sizeof(flatC));
    if (encSz > 0 && (size_t)encSz <= sizeof(flatC)) {
        flatCSz = (word32)encSz;
        XMEMSET(flatC, 0, flatCSz);
        ExpectIntEQ(wc_RsaDirect(flatC, flatCSz, out, &outSz, &key,
            RSA_PRIVATE_DECRYPT, &rng),
    #if !defined(HAVE_FIPS) || FIPS_VERSION_GE(7,0)
                WC_NO_ERR_TRACE(WC_KEY_SIZE_E));
    #else
                WC_NO_ERR_TRACE(RSA_OUT_OF_RANGE_E));
    #endif
    }

    DoExpectIntEQ(wc_FreeRsaKey(&key), 0);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    #undef WC_RSA_OVERSIZED_BUF_LEN
#endif
    return EXPECT_RESULT();
} /* END test_wc_RsaFunctionCheckIn_OversizedModulus */

/*
 * Test wc_RsaKeyToDer with an mp_int large enough to wrap size calculations.
 */
int test_wc_RsaKeyToDer_SizeOverflow(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && defined(USE_INTEGER_HEAP_MATH) && \
    !defined(USE_FAST_MATH) && \
    defined(WOLFSSL_ASN_TEMPLATE) && defined(WOLFSSL_PUBLIC_MP) && \
    (defined(WOLFSSL_KEY_GEN) || defined(WOLFSSL_KEY_TO_DER))
    RsaKey    key;
    int       i;
    int       derRet;
    int       crafted_used;
    int       top_bits;
    mp_digit  top_digit;
    mp_digit  storage   = 0;  /* the only digit mp_count_bits ever reads */
    mp_digit* fake_dp   = NULL;

    int       orig_used  = 0;
    int       orig_alloc = 0;
    int       orig_sign  = 0;
    mp_digit* orig_dp    = NULL;

    mp_int* fields[8];

    XMEMSET(&key, 0, sizeof(key));

    /* Skip on 32-bit: biasing dp by ~half the address space is unsafe. */
    if (sizeof(void*) < 8) {
        return TEST_SKIPPED;
    }

    /* Find 'used' count that makes (used-1)*DIGIT_BIT + top_bits = -48
     * as signed int, causing mp_unsigned_bin_size to return -6. */
    {
        unsigned int target = 0xFFFFFFD0u;  /* -48 as unsigned 32-bit */
        int found = 0;

        crafted_used = 0;
        top_bits = 0;
        top_digit = 0;

        for (top_bits = 1; top_bits < DIGIT_BIT; top_bits++) {
            unsigned int base = target - (unsigned int)top_bits;
            if (base % (unsigned int)DIGIT_BIT == 0) {
                crafted_used = (int)(base / (unsigned int)DIGIT_BIT) + 1;
                top_digit = (mp_digit)1 << (top_bits - 1);
                found = 1;
                break;
            }
        }
        if (!found) {
            return TEST_SKIPPED;
        }
    }

    ExpectIntEQ(wc_InitRsaKey(&key, HEAP_HINT), 0);

    /* Set up dummy RSA private key fields. */
    key.type = RSA_PRIVATE;
    fields[0] = &key.n;
    fields[1] = &key.e;
    fields[2] = &key.d;
    fields[3] = &key.p;
    fields[4] = &key.q;
    fields[5] = &key.dP;
    fields[6] = &key.dQ;
    fields[7] = &key.u;

    for (i = 0; i < 8; i++) {
        if (EXPECT_SUCCESS()) {
            ExpectIntEQ(mp_init(fields[i]), 0);
            mp_set(fields[i], 0x42);
        }
    }

    if (EXPECT_SUCCESS()) {
        orig_used  = key.p.used;
        orig_alloc = key.p.alloc;
        orig_sign  = key.p.sign;
        orig_dp    = key.p.dp;
    }

    /* The vulnerable path (mp_unsigned_bin_size -> mp_count_bits, and
     * mp_leading_bit) only reads dp[used-1].  Bias dp so that index
     * (used-1) lands on our single real digit -- no giant allocation
     * (and no mmap/VirtualAlloc) needed. */
    if (EXPECT_SUCCESS()) {
        storage = top_digit;
        fake_dp = (mp_digit*)((wc_ptr_t)&storage
                  - (wc_ptr_t)(crafted_used - 1) * sizeof(mp_digit));

        key.p.dp    = fake_dp;
        key.p.used  = crafted_used;
        key.p.alloc = crafted_used;
        key.p.sign  = 0;  /* MP_ZPOS */
    }

    /* Should return an error, not a bogus small size. */
    derRet = wc_RsaKeyToDer(&key, NULL, 0);
    ExpectIntLT(derRet, 0);

    /* Restore key.p before cleanup. */
    key.p.dp    = orig_dp;
    key.p.used  = orig_used;
    key.p.alloc = orig_alloc;
    key.p.sign  = orig_sign;

    DoExpectIntEQ(wc_FreeRsaKey(&key), 0);
#endif
    return EXPECT_RESULT();
} /* END test_wc_RsaKeyToDer_SizeOverflow */

/*
 * MC/DC wave 2 - decision-targeted negative paths for the high-level RSA
 * encrypt/decrypt/sign surfaces. The existing tests above deliberately leave
 * bad-arg coverage "tested in another testing function" for
 * wc_RsaPublicEncrypt{,_ex}, wc_RsaPrivateDecrypt{,Inline}{,_ex}, and
 * wc_RsaSetRNG. This function closes that gap by hitting the argument-check,
 * short-buffer, and invalid-mode branches in wolfcrypt/src/rsa.c without
 * changing any library source.
 */
int test_wc_RsaDecisionCoverage(void)
{
    EXPECT_DECLS;
/* This function asserts wolfcrypt/src/rsa.c *internal* decision outcomes
 * (short-buffer RSA_BUFFER_E, invalid pad-type, OAEP-vs-PKCSv15 padding
 * mismatch) whose whole value is MC/DC of the open wolfCrypt rsa.c. Under the
 * frozen self-test module that rsa.c is not the code being exercised, so these
 * error-code decisions are not part of its contract and can legitimately
 * differ. The sibling key-gen/decision tests in this file (e.g.
 * test_wc_CheckProbablePrime, the RsaKeyGeneration group) exclude HAVE_SELFTEST
 * for the same reason; do so here too. HAVE_FIPS is intentionally left running:
 * that (newer) module honours these decisions and the campaign gains coverage
 * from it. */
#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN) && \
    !defined(WOLFSSL_RSA_PUBLIC_ONLY) && !defined(HAVE_SELFTEST)
    RsaKey key;
    WC_RNG rng;
    const char inStr[] = TEST_STRING;
    const word32 inLen = (word32)TEST_STRING_SZ;
    int bits = TEST_RSA_BITS;
    const word32 cipherLen = TEST_RSA_BYTES;
    int cipherOutLen = 0;
    WC_DECLARE_VAR(in, byte, TEST_STRING_SZ, NULL);
    WC_DECLARE_VAR(cipher, byte, TEST_RSA_BYTES, NULL);
    WC_DECLARE_VAR(plain, byte, TEST_RSA_BYTES, NULL);

    WC_ALLOC_VAR(in, byte, TEST_STRING_SZ, NULL);
    WC_ALLOC_VAR(cipher, byte, TEST_RSA_BYTES, NULL);
    WC_ALLOC_VAR(plain, byte, TEST_RSA_BYTES, NULL);

#ifdef WC_DECLARE_VAR_IS_HEAP_ALLOC
    ExpectNotNull(in);
    ExpectNotNull(cipher);
    ExpectNotNull(plain);
#endif
    ExpectNotNull(XMEMCPY(in, inStr, inLen));

    XMEMSET(&key, 0, sizeof(RsaKey));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_InitRsaKey(&key, HEAP_HINT), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(MAKE_RSA_KEY(&key, bits, WC_RSA_EXPONENT, &rng), 0);

    /* ---- wc_RsaPublicEncrypt: argument-check decision branches ---- */
    ExpectIntEQ(wc_RsaPublicEncrypt(NULL, inLen, cipher, cipherLen, &key, &rng),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaPublicEncrypt(in, inLen, NULL, cipherLen, &key, &rng),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaPublicEncrypt(in, inLen, cipher, cipherLen, NULL, &rng),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Short output buffer: cipher buffer smaller than modulus byte length
     * must return RSA_BUFFER_E (short-buffer decision branch). */
    ExpectIntEQ(wc_RsaPublicEncrypt(in, inLen, cipher, cipherLen - 1, &key,
        &rng), WC_NO_ERR_TRACE(RSA_BUFFER_E));

    /* One real encrypt so the decrypt-side negative cases have a valid
     * cipher text to work with. */
    ExpectIntGT(cipherOutLen = wc_RsaPublicEncrypt(in, inLen, cipher, cipherLen,
        &key, &rng), 0);

    /* ---- wc_RsaPrivateDecrypt: argument-check + short-buffer branches ---- */
#if defined(WC_RSA_BLINDING) && !defined(HAVE_FIPS)
    ExpectIntEQ(wc_RsaSetRNG(&key, &rng), 0);
    /* wc_RsaSetRNG NULL arg decision branches. */
    ExpectIntEQ(wc_RsaSetRNG(NULL, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaSetRNG(&key, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wc_RsaPrivateDecrypt(NULL, (word32)cipherOutLen, plain,
        cipherLen, &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaPrivateDecrypt(cipher, (word32)cipherOutLen, NULL,
        cipherLen, &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaPrivateDecrypt(cipher, (word32)cipherOutLen, plain,
        cipherLen, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* ---- wc_RsaPrivateDecryptInline: argument-check decision branches ---- */
    {
        byte* outPtr = NULL;
        ExpectIntEQ(wc_RsaPrivateDecryptInline(NULL, (word32)cipherOutLen,
            &outPtr, &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        {
            int ret = wc_RsaPrivateDecryptInline(cipher, (word32)cipherOutLen,
                NULL, &key);
            ExpectTrue(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG) || ret > 0);
        }
        ExpectIntEQ(wc_RsaPrivateDecryptInline(cipher, (word32)cipherOutLen,
            &outPtr, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }

#if !defined(HAVE_FIPS) && !defined(WC_NO_RSA_OAEP) && !defined(NO_SHA256)
    /* ---- wc_RsaPublicEncrypt_ex: argument-check + invalid-mode branches --- */
    ExpectIntEQ(wc_RsaPublicEncrypt_ex(NULL, inLen, cipher, cipherLen, &key,
        &rng, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaPublicEncrypt_ex(in, inLen, NULL, cipherLen, &key, &rng,
        WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaPublicEncrypt_ex(in, inLen, cipher, cipherLen, NULL, &rng,
        WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Invalid padding type selector: should not dispatch to any valid path. */
    ExpectIntLT(wc_RsaPublicEncrypt_ex(in, inLen, cipher, cipherLen, &key,
        &rng, /* bogus pad type */ 99, WC_HASH_TYPE_SHA256, WC_MGF1SHA256,
        NULL, 0), 0);

    /* Produce a valid OAEP-SHA256 cipher text for the decrypt negative path. */
    cipherOutLen = wc_RsaPublicEncrypt_ex(in, inLen, cipher, cipherLen, &key,
        &rng, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, NULL, 0);
    ExpectIntGT(cipherOutLen, 0);

    /* ---- wc_RsaPrivateDecrypt_ex: argument-check + padding-mismatch ---- */
    ExpectIntEQ(wc_RsaPrivateDecrypt_ex(NULL, (word32)cipherOutLen, plain,
        cipherLen, &key, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256, WC_MGF1SHA256,
        NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaPrivateDecrypt_ex(cipher, (word32)cipherOutLen, NULL,
        cipherLen, &key, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256, WC_MGF1SHA256,
        NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RsaPrivateDecrypt_ex(cipher, (word32)cipherOutLen, plain,
        cipherLen, NULL, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256, WC_MGF1SHA256,
        NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Cipher text is OAEP-SHA256 with no label. Decrypting it as OAEP with a
     * non-empty label makes the recovered lHash mismatch, so OAEP's integrity
     * check fails *deterministically* and exercises the padding-mismatch
     * decision branch in rsa.c. (Decoding it as PKCS#1 v1.5 was flaky: v1.5
     * unpadding of the random OAEP plaintext spuriously "succeeds" a few
     * percent of the time when byte[1] lands on 0x02 with a valid separator.) */
    {
        byte wrongLabel[5] = { 'w', 'r', 'o', 'n', 'g' };
        ExpectIntLT(wc_RsaPrivateDecrypt_ex(cipher, (word32)cipherOutLen, plain,
            cipherLen, &key, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256,
            WC_MGF1SHA256, wrongLabel, sizeof(wrongLabel)), 0);
    }

    /* ---- wc_RsaPrivateDecryptInline_ex argument-check branches ---- */
    {
        byte* outPtr = NULL;
        ExpectIntEQ(wc_RsaPrivateDecryptInline_ex(NULL, (word32)cipherOutLen,
            &outPtr, &key, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256, WC_MGF1SHA256,
            NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        {
            int ret = wc_RsaPrivateDecryptInline_ex(cipher,
                (word32)cipherOutLen, NULL, &key, WC_RSA_OAEP_PAD,
                WC_HASH_TYPE_SHA256, WC_MGF1SHA256, NULL, 0);
            ExpectTrue(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG) || ret > 0);
        }
        ExpectIntEQ(wc_RsaPrivateDecryptInline_ex(cipher, (word32)cipherOutLen,
            &outPtr, NULL, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256, WC_MGF1SHA256,
            NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }
#endif /* !HAVE_FIPS && !WC_NO_RSA_OAEP && !NO_SHA256 */

    /* ---- wc_RsaFunction: 7-condition argument-check (rsa.c line ~3542) ----
     * key, in, inLen, out, outLen, outLen pointer, and type each
     * independently reject. The
     * all-false side is produced by every real encrypt/decrypt; these supply
     * the single-true half of each condition's MC/DC pair. */
    {
        word32 rawOutLen = cipherLen;
        word32 rawZeroLen = 0;
        ExpectIntEQ(wc_RsaFunction(NULL, cipherLen, plain, &rawOutLen,
            RSA_PUBLIC_DECRYPT, &key, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        rawOutLen = cipherLen;
        ExpectIntEQ(wc_RsaFunction(cipher, 0, plain, &rawOutLen,
            RSA_PUBLIC_DECRYPT, &key, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        rawOutLen = cipherLen;
        ExpectIntEQ(wc_RsaFunction(cipher, cipherLen, NULL, &rawOutLen,
            RSA_PUBLIC_DECRYPT, &key, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_RsaFunction(cipher, cipherLen, plain, NULL,
            RSA_PUBLIC_DECRYPT, &key, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_RsaFunction(cipher, cipherLen, plain, &rawZeroLen,
            RSA_PUBLIC_DECRYPT, &key, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        rawOutLen = cipherLen;
        ExpectIntEQ(wc_RsaFunction(cipher, cipherLen, plain, &rawOutLen,
            RSA_TYPE_UNKNOWN, &key, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        rawOutLen = cipherLen;
        ExpectIntEQ(wc_RsaFunction(cipher, cipherLen, plain, &rawOutLen,
            RSA_PUBLIC_DECRYPT, NULL, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }

    /* ---- wc_RsaDirect: in/outSz/key argument-check (rsa.c line ~3304) ----
     * Compiled because the base enables WC_RSA_NO_PADDING. */
#if defined(WC_RSA_DIRECT) || defined(WC_RSA_NO_PADDING)
    {
        word32 directSz = cipherLen;
        ExpectIntEQ(wc_RsaDirect(NULL, cipherLen, cipher, &directSz, &key,
            RSA_PUBLIC_ENCRYPT, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_RsaDirect(cipher, cipherLen, cipher, NULL, &key,
            RSA_PUBLIC_ENCRYPT, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_RsaDirect(cipher, cipherLen, cipher, &directSz, NULL,
            RSA_PUBLIC_ENCRYPT, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }
#endif

    /* ---- wc_MakeRsaKey size check: RsaSizeCheck (rsa.c line ~5153) ----
     * size < RSA_MIN_SIZE and size > RSA_MAX_SIZE both reject; the valid-size
     * (all-false) side came from the MAKE_RSA_KEY above. */
    ExpectIntEQ(wc_MakeRsaKey(&key, RSA_MIN_SIZE - 1, WC_RSA_EXPONENT, &rng),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_MakeRsaKey(&key, RSA_MAX_SIZE + 1, WC_RSA_EXPONENT, &rng),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* ---- wc_CheckProbablePrime_ex argument checks (rsa.c ~5286/~5293) ---- */
    {
        byte cpp_p[2] = { 0x03, 0x03 };
        byte cpp_e[3] = { 0x01, 0x00, 0x01 };
        int  cpp_isPrime = 0;
        /* line ~5286 cond isPrime==NULL. */
        ExpectIntEQ(wc_CheckProbablePrime(cpp_p, sizeof(cpp_p), NULL, 0,
            cpp_e, sizeof(cpp_e), 1024, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* line ~5293: qRaw!=NULL with qRawSz==0, and qRaw==NULL with
         * qRawSz!=0 (both invalid p/q pairings). */
        ExpectIntEQ(wc_CheckProbablePrime(cpp_p, sizeof(cpp_p), cpp_p, 0,
            cpp_e, sizeof(cpp_e), 1024, &cpp_isPrime),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_CheckProbablePrime(cpp_p, sizeof(cpp_p), NULL, 2,
            cpp_e, sizeof(cpp_e), 1024, &cpp_isPrime),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }

    /* ---- wc_RsaPSS_CheckPadding argument checks (rsa.c line ~4515) ---- */
#if defined(WC_RSA_PSS) && !defined(NO_SHA256)
    {
        byte pssHash[WC_SHA256_DIGEST_SIZE];
        byte pssSig[WC_SHA256_DIGEST_SIZE * 2];
        XMEMSET(pssHash, 0, sizeof(pssHash));
        XMEMSET(pssSig, 0, sizeof(pssSig));
        ExpectIntEQ(wc_RsaPSS_CheckPadding(NULL, sizeof(pssHash), pssSig,
            sizeof(pssSig), WC_HASH_TYPE_SHA256), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_RsaPSS_CheckPadding(pssHash, sizeof(pssHash), NULL,
            sizeof(pssSig), WC_HASH_TYPE_SHA256), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* digSz < 0 via an unsupported hash type. */
        ExpectIntEQ(wc_RsaPSS_CheckPadding(pssHash, sizeof(pssHash), pssSig,
            sizeof(pssSig), WC_HASH_TYPE_NONE), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* inSz != digSz. */
        ExpectIntEQ(wc_RsaPSS_CheckPadding(pssHash, 1, pssSig,
            sizeof(pssSig), WC_HASH_TYPE_SHA256), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }
#endif /* WC_RSA_PSS && !NO_SHA256 */

    /* ---- wc_InitRsaKey_Id / wc_InitRsaKey_Label argument checks
     * (rsa.c ~396/~400/~420/~424) ---- */
#ifdef WOLF_PRIVATE_KEY_ID
    {
        RsaKey idKey;
        static const byte idBuf[4] = { 0x01, 0x02, 0x03, 0x04 };

        /* line ~396: len < 0 and len > RSA_MAX_ID_LEN both return BUFFER_E
         * before init (no free required). */
        XMEMSET(&idKey, 0, sizeof(idKey));
        ExpectIntEQ(wc_InitRsaKey_Id(&idKey, (byte*)idBuf, -1, HEAP_HINT,
            INVALID_DEVID), WC_NO_ERR_TRACE(BUFFER_E));
        XMEMSET(&idKey, 0, sizeof(idKey));
        ExpectIntEQ(wc_InitRsaKey_Id(&idKey, (byte*)idBuf, RSA_MAX_ID_LEN + 1,
            HEAP_HINT, INVALID_DEVID), WC_NO_ERR_TRACE(BUFFER_E));
        /* key == NULL rejects (line ~394). */
        ExpectIntEQ(wc_InitRsaKey_Id(NULL, (byte*)idBuf, 4, HEAP_HINT,
            INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* line ~400: id==NULL and len==0 both SUCCEED (key initialized, no id
         * copied) - must free the initialized key. */
        XMEMSET(&idKey, 0, sizeof(idKey));
        ExpectIntEQ(wc_InitRsaKey_Id(&idKey, NULL, 4, HEAP_HINT, INVALID_DEVID),
            0);
        DoExpectIntEQ(wc_FreeRsaKey(&idKey), 0);
        XMEMSET(&idKey, 0, sizeof(idKey));
        ExpectIntEQ(wc_InitRsaKey_Id(&idKey, (byte*)idBuf, 0, HEAP_HINT,
            INVALID_DEVID), 0);
        DoExpectIntEQ(wc_FreeRsaKey(&idKey), 0);

        /* line ~420: key==NULL / label==NULL. */
        ExpectIntEQ(wc_InitRsaKey_Label(NULL, "lbl", HEAP_HINT, INVALID_DEVID),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        XMEMSET(&idKey, 0, sizeof(idKey));
        ExpectIntEQ(wc_InitRsaKey_Label(&idKey, NULL, HEAP_HINT, INVALID_DEVID),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* line ~424: empty label (labelLen==0) and over-long label both
         * return BUFFER_E before init. */
        XMEMSET(&idKey, 0, sizeof(idKey));
        ExpectIntEQ(wc_InitRsaKey_Label(&idKey, "", HEAP_HINT, INVALID_DEVID),
            WC_NO_ERR_TRACE(BUFFER_E));
        {
            char longLabel[RSA_MAX_LABEL_LEN + 2];
            XMEMSET(longLabel, 'a', sizeof(longLabel));
            longLabel[sizeof(longLabel) - 1] = '\0';
            XMEMSET(&idKey, 0, sizeof(idKey));
            ExpectIntEQ(wc_InitRsaKey_Label(&idKey, longLabel, HEAP_HINT,
                INVALID_DEVID), WC_NO_ERR_TRACE(BUFFER_E));
        }
    }
#endif /* WOLF_PRIVATE_KEY_ID */

    /* ---- OAEP RsaPad label mismatch: optLabel==NULL with labelLen>0
     * (rsa.c line ~1322 encrypt, ~1791 decrypt) rejects with BUFFER_E. ---- */
#if !defined(HAVE_FIPS) && !defined(WC_NO_RSA_OAEP) && !defined(NO_SHA256)
    ExpectIntLT(wc_RsaPublicEncrypt_ex(in, inLen, cipher, cipherLen, &key,
        &rng, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, NULL, 5), 0);
    /* Decrypt-side RsaUnPad_OAEP optLabel==NULL/labelLen>0 (line ~1791): make a
     * valid OAEP-SHA256 cipher, then decrypt requesting a NULL label with a
     * non-zero label length. */
    {
        int oaepLen = wc_RsaPublicEncrypt_ex(in, inLen, cipher, cipherLen, &key,
            &rng, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, NULL, 0);
        ExpectIntGT(oaepLen, 0);
        if (oaepLen > 0) {
            ExpectIntLT(wc_RsaPrivateDecrypt_ex(cipher, (word32)oaepLen, plain,
                cipherLen, &key, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256,
                WC_MGF1SHA256, NULL, 5), 0);
        }
    }
#endif

    /* ---- PSS with SHA-512 on a 1024-bit key: exercises the FIPS 186-4
     * 5.5(e) salt-length reduction branch (bits==1024 && hLen==SHA512) in
     * RsaPad_PSS / RsaUnPad_PSS / wc_RsaPSS_CheckPadding (rsa.c ~1530/~1939/
     * ~4524/~4655/~4715). Only reached when TEST_RSA_BITS==1024; harmless
     * (still valid PSS) at 2048. ---- */
#if defined(WC_RSA_PSS) && defined(WOLFSSL_SHA512) && !defined(HAVE_FIPS)
    if (TEST_RSA_BITS == 1024) {
        byte pssHash512[WC_SHA512_DIGEST_SIZE];
        byte pssSig512[TEST_RSA_BYTES];
        byte pssOut512[TEST_RSA_BYTES];
        int  pssSigLen512;
        XMEMSET(pssHash512, 0x2b, sizeof(pssHash512));
        pssSigLen512 = wc_RsaPSS_Sign(pssHash512, sizeof(pssHash512), pssSig512,
            sizeof(pssSig512), WC_HASH_TYPE_SHA512, WC_MGF1SHA512, &key, &rng);
        ExpectIntGT(pssSigLen512, 0);
        if (pssSigLen512 > 0) {
            ExpectIntGT(wc_RsaPSS_Verify(pssSig512, (word32)pssSigLen512,
                pssOut512, sizeof(pssOut512), WC_HASH_TYPE_SHA512,
                WC_MGF1SHA512, &key), 0);
        }
    }
#endif /* WC_RSA_PSS && WOLFSSL_SHA512 && !HAVE_FIPS */

    WC_FREE_VAR(in, NULL);
    WC_FREE_VAR(cipher, NULL);
    WC_FREE_VAR(plain, NULL);
    DoExpectIntEQ(wc_FreeRsaKey(&key), 0);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
} /* END test_wc_RsaDecisionCoverage */

/*
 * MC/DC wave 2 - feature-oriented positive paths to lift rsa.c MC/DC by
 * exercising OAEP, PSS, and PKCS#1 v1.5 sign/verify across multiple hash
 * algorithms and label/salt configurations using the static client key DER
 * (no runtime key generation).
 */
int test_wc_RsaFeatureCoverage(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY) && \
    defined(USE_CERT_BUFFERS_2048) && !defined(HAVE_FIPS)
    RsaKey key;
    WC_RNG rng;
    word32 idx = 0;
    byte cipher[256];
    byte plain[256];
    byte sig[256];
    int  cipherLen;
    int  sigLen;
    int  initKey = 0;
    int  initRng = 0;
    static const byte msg[16] = {
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    static const byte label[4] = { 0xde, 0xad, 0xbe, 0xef };

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&rng, 0, sizeof(rng));
    ExpectIntEQ(wc_InitRsaKey(&key, HEAP_HINT), 0);
    if (EXPECT_SUCCESS()) initKey = 1;
    ExpectIntEQ(wc_InitRng(&rng), 0);
    if (EXPECT_SUCCESS()) initRng = 1;
    ExpectIntEQ(wc_RsaPrivateKeyDecode(client_key_der_2048, &idx, &key,
        sizeof_client_key_der_2048), 0);
#ifdef WC_RSA_BLINDING
    ExpectIntEQ(wc_RsaSetRNG(&key, &rng), 0);
#endif

#if !defined(WC_NO_RSA_OAEP) && !defined(NO_SHA256)
    /* ---- OAEP-SHA256 round trip with empty label ---- */
    cipherLen = wc_RsaPublicEncrypt_ex(msg, sizeof(msg), cipher,
        sizeof(cipher), &key, &rng, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256,
        WC_MGF1SHA256, NULL, 0);
    ExpectIntGT(cipherLen, 0);
    if (cipherLen > 0) {
        int n = wc_RsaPrivateDecrypt_ex(cipher, (word32)cipherLen, plain,
            sizeof(plain), &key, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256,
            WC_MGF1SHA256, NULL, 0);
        ExpectIntEQ(n, (int)sizeof(msg));
        if (n == (int)sizeof(msg))
            ExpectBufEQ(plain, msg, sizeof(msg));
    }

    /* ---- OAEP-SHA256 round trip with non-empty label ---- */
    cipherLen = wc_RsaPublicEncrypt_ex(msg, sizeof(msg), cipher,
        sizeof(cipher), &key, &rng, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256,
        WC_MGF1SHA256, (byte*)label, sizeof(label));
    ExpectIntGT(cipherLen, 0);
    if (cipherLen > 0) {
        int n = wc_RsaPrivateDecrypt_ex(cipher, (word32)cipherLen, plain,
            sizeof(plain), &key, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256,
            WC_MGF1SHA256, (byte*)label, sizeof(label));
        ExpectIntEQ(n, (int)sizeof(msg));
        /* Wrong label must reject. */
        n = wc_RsaPrivateDecrypt_ex(cipher, (word32)cipherLen, plain,
            sizeof(plain), &key, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256,
            WC_MGF1SHA256, NULL, 0);
        ExpectIntLT(n, 0);
    }
#endif /* !WC_NO_RSA_OAEP && !NO_SHA256 */

#if !defined(WC_NO_RSA_OAEP) && defined(WOLFSSL_SHA384)
    /* ---- OAEP-SHA384 round trip ---- */
    cipherLen = wc_RsaPublicEncrypt_ex(msg, sizeof(msg), cipher,
        sizeof(cipher), &key, &rng, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA384,
        WC_MGF1SHA384, NULL, 0);
    ExpectIntGT(cipherLen, 0);
    if (cipherLen > 0) {
        int n = wc_RsaPrivateDecrypt_ex(cipher, (word32)cipherLen, plain,
            sizeof(plain), &key, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA384,
            WC_MGF1SHA384, NULL, 0);
        ExpectIntEQ(n, (int)sizeof(msg));
    }
#endif /* !WC_NO_RSA_OAEP && WOLFSSL_SHA384 */

    /* ---- PKCS#1 v1.5 raw encrypt/decrypt round trip ---- */
    cipherLen = wc_RsaPublicEncrypt(msg, sizeof(msg), cipher, sizeof(cipher),
        &key, &rng);
    ExpectIntGT(cipherLen, 0);
    if (cipherLen > 0) {
        int n = wc_RsaPrivateDecrypt(cipher, (word32)cipherLen, plain,
            sizeof(plain), &key);
        ExpectIntEQ(n, (int)sizeof(msg));
        if (n == (int)sizeof(msg))
            ExpectBufEQ(plain, msg, sizeof(msg));
    }

    /* ---- PKCS#1 v1.5 sign / verify ---- */
    sigLen = wc_RsaSSL_Sign(msg, sizeof(msg), sig, sizeof(sig), &key, &rng);
    ExpectIntGT(sigLen, 0);
    if (sigLen > 0) {
        int n = wc_RsaSSL_Verify(sig, (word32)sigLen, plain, sizeof(plain),
            &key);
        ExpectIntEQ(n, (int)sizeof(msg));
        if (n == (int)sizeof(msg))
            ExpectBufEQ(plain, msg, sizeof(msg));
    }
    /* Tampered signature must be rejected. */
    if (sigLen > 0) {
        sig[0] ^= 0x01;
        ExpectIntLT(wc_RsaSSL_Verify(sig, (word32)sigLen, plain, sizeof(plain),
            &key), 0);
        sig[0] ^= 0x01;
    }

#if defined(WC_RSA_PSS) && !defined(NO_SHA256)
    /* ---- PSS-SHA256 sign / verify with default salt length ----
     * PSS expects a hash-sized input, not arbitrary plaintext. */
    {
        byte hash256[WC_SHA256_DIGEST_SIZE];
        ExpectIntEQ(wc_Sha256Hash(msg, sizeof(msg), hash256), 0);

        sigLen = wc_RsaPSS_Sign(hash256, sizeof(hash256), sig, sizeof(sig),
            WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key, &rng);
        ExpectIntGT(sigLen, 0);
        if (sigLen > 0) {
            ExpectIntGT(wc_RsaPSS_Verify(sig, (word32)sigLen, plain,
                sizeof(plain), WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key), 0);
        }

        /* ---- PSS-SHA256 sign / verify with explicit salt length ---- */
        sigLen = wc_RsaPSS_Sign_ex(hash256, sizeof(hash256), sig, sizeof(sig),
            WC_HASH_TYPE_SHA256, WC_MGF1SHA256, /* saltLen */ 16, &key, &rng);
        ExpectIntGT(sigLen, 0);
        if (sigLen > 0) {
            ExpectIntGT(wc_RsaPSS_Verify_ex(sig, (word32)sigLen, plain,
                sizeof(plain), WC_HASH_TYPE_SHA256, WC_MGF1SHA256, 16, &key),
                0);
        }
    }
#endif /* WC_RSA_PSS && !NO_SHA256 */

#if defined(WC_RSA_PSS) && defined(WOLFSSL_SHA384)
    /* ---- PSS-SHA384 sign / verify ---- */
    {
        byte hash384[WC_SHA384_DIGEST_SIZE];
        ExpectIntEQ(wc_Sha384Hash(msg, sizeof(msg), hash384), 0);

        sigLen = wc_RsaPSS_Sign(hash384, sizeof(hash384), sig, sizeof(sig),
            WC_HASH_TYPE_SHA384, WC_MGF1SHA384, &key, &rng);
        ExpectIntGT(sigLen, 0);
        if (sigLen > 0) {
            ExpectIntGT(wc_RsaPSS_Verify(sig, (word32)sigLen, plain,
                sizeof(plain), WC_HASH_TYPE_SHA384, WC_MGF1SHA384, &key), 0);
        }
    }
#endif /* WC_RSA_PSS && WOLFSSL_SHA384 */

    /* ---- wc_CheckRsaKey: exercise consistency checks on a good key ---- */
    #ifdef WOLFSSL_RSA_KEY_CHECK
    ExpectIntEQ(wc_CheckRsaKey(&key), 0);
    #endif

    /* ---- wc_InitRsaKey_Id / wc_InitRsaKey_Label: positive path ---- */
    #ifdef WOLF_PRIVATE_KEY_ID
    {
        RsaKey tmpKey;
        static const byte idBuf[4] = { 0x01, 0x02, 0x03, 0x04 };
        XMEMSET(&tmpKey, 0, sizeof(tmpKey));
        ExpectIntEQ(wc_InitRsaKey_Id(&tmpKey, (byte*)idBuf, sizeof(idBuf),
            HEAP_HINT, INVALID_DEVID), 0);
        DoExpectIntEQ(wc_FreeRsaKey(&tmpKey), 0);
    }
    {
        RsaKey tmpKey;
        XMEMSET(&tmpKey, 0, sizeof(tmpKey));
        ExpectIntEQ(wc_InitRsaKey_Label(&tmpKey, "test-label", HEAP_HINT,
            INVALID_DEVID), 0);
        DoExpectIntEQ(wc_FreeRsaKey(&tmpKey), 0);
    }
    #endif /* WOLF_PRIVATE_KEY_ID */

    /* ---- wc_RsaKeyToPublicDer_ex: with and without algorithm header ---- */
    #ifdef WOLFSSL_KEY_GEN
    {
        byte pubDer[512];
        ExpectIntGT(wc_RsaKeyToPublicDer_ex(&key, pubDer, sizeof(pubDer), 1),
            0);
        ExpectIntGT(wc_RsaKeyToPublicDer_ex(&key, pubDer, sizeof(pubDer), 0),
            0);
    }
    #endif

    /* ---- wc_RsaEncryptSize / wc_RsaFlattenPublicKey positive path ---- */
    ExpectIntGT(wc_RsaEncryptSize(&key), 0);
    {
        byte n[256];
        byte e[8];
        word32 nSz = sizeof(n);
        word32 eSz = sizeof(e);
        ExpectIntEQ(wc_RsaFlattenPublicKey(&key, e, &eSz, n, &nSz), 0);
        ExpectIntGT(nSz, 0);
        ExpectIntGT(eSz, 0);
    }

    /* ---- WC_RSA_NO_PADDING raw round trip: drives the no-padding pad/unpad
     * branches (RsaPad/RsaUnPad WC_RSA_NO_PAD, rsa.c ~1731/~2150) via the
     * wc_RsaDirect API. Input is exactly the modulus byte length with a zero
     * leading byte so the integer stays below the modulus. ---- */
#ifdef WC_RSA_NO_PADDING
    {
        byte rawIn[256];
        byte rawEnc[256];
        byte rawDec[256];
        word32 rawEncSz;
        word32 rawDecSz;
        int keySz = wc_RsaEncryptSize(&key);
        if (keySz > 0 && keySz <= (int)sizeof(rawIn)) {
            XMEMSET(rawIn, 0, sizeof(rawIn));
            XMEMSET(rawIn + 1, 0x42, (size_t)keySz - 1);
            rawEncSz = (word32)keySz;
            ExpectIntGT(wc_RsaDirect(rawIn, (word32)keySz, rawEnc, &rawEncSz,
                &key, RSA_PUBLIC_ENCRYPT, &rng), 0);
            rawDecSz = (word32)keySz;
            ExpectIntGT(wc_RsaDirect(rawEnc, rawEncSz, rawDec, &rawDecSz, &key,
                RSA_PRIVATE_DECRYPT, &rng), 0);
            ExpectBufEQ(rawDec, rawIn, (word32)keySz);
        }
    }
#endif /* WC_RSA_NO_PADDING */

    if (initKey) DoExpectIntEQ(wc_FreeRsaKey(&key), 0);
    if (initRng) DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
} /* END test_wc_RsaFeatureCoverage */
