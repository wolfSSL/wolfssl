/* test_rsa.c
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

#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/types.h>
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
#if !defined(NO_RSA) && (defined(USE_CERT_BUFFERS_1024) || \
        defined(USE_CERT_BUFFERS_2048)) && !defined(HAVE_FIPS)
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
#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
    RsaKey genKey;
    WC_RNG rng;
    byte*  der = NULL;
#if (!defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL)) && \
    (!defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION < 4)) && \
    (defined(RSA_MIN_SIZE) && (RSA_MIN_SIZE <= 1024))
    int     bits = 1024;
    word32  derSz = 611;
    /* (2 x 128) + 2 (possible leading 00) + (5 x 64) + 5 (possible leading 00)
       + 3 (e) + 8 (ASN tag) + 10 (ASN length) + 4 seqSz + 3 version */
#else
    int     bits = 2048;
    word32  derSz = 1196;
    /* (2 x 256) + 2 (possible leading 00) + (5 x 128) + 5 (possible leading 00)
       + 3 (e) + 8 (ASN tag) + 17 (ASN length) + 4 seqSz + 3 version */
#endif

    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&genKey, 0, sizeof(genKey));

    ExpectNotNull(der = (byte*)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER));
    /* Init structures. */
    ExpectIntEQ(wc_InitRsaKey(&genKey, HEAP_HINT), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    /* Make key. */
    ExpectIntEQ(MAKE_RSA_KEY(&genKey, bits, WC_RSA_EXPONENT, &rng), 0);

    ExpectIntGT(wc_RsaKeyToDer(&genKey, der, derSz), 0);

    /* Pass good/bad args. */
    ExpectIntEQ(wc_RsaKeyToDer(NULL, der, FOURK_BUF),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Get just the output length */
    ExpectIntGT(wc_RsaKeyToDer(&genKey, NULL, 0), 0);
    /* Try Public Key. */
    genKey.type = 0;
    ExpectIntEQ(wc_RsaKeyToDer(&genKey, der, FOURK_BUF),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    #ifdef WOLFSSL_CHECK_MEM_ZERO
        /* Put back to Private Key */
        genKey.type = 1;
    #endif

    XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    DoExpectIntEQ(wc_FreeRsaKey(&genKey), 0);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
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
#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
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
    const word32 plainSz = (word32)TEST_STRING_SZ;
    byte*   res = NULL;
    int     idx = 0;
    int          bits = TEST_RSA_BITS;
    const word32 cipherSz = TEST_RSA_BYTES;

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

