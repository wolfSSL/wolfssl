/* test_dh.c
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

#include <wolfssl/wolfcrypt/dh.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_dh.h>

/* A sane, fixed private/public/agree buffer size for the tests below,
 * comfortably covering the largest enabled FFDHE named group (FFDHE-4096,
 * 512-byte p). NOT the library's own DH_MAX_SIZE: under WOLFSSL_SP_MATH_ALL,
 * DH_MAX_SIZE expands to WC_BITS_FULL_BYTES(SP_INT_BITS), and
 * WC_BITS_FULL_BYTES(x) is defined as (WC_BITS_TO_BYTES(x) << 3) - i.e. it
 * returns SP_INT_BITS itself (rounded up to a byte multiple), NOT
 * SP_INT_BITS/8 as its name suggests. With this campaign's SP_INT_BITS 4096,
 * DH_MAX_SIZE is therefore 4096 (bytes!), not the 512 a caller would
 * reasonably expect. Passing that value as *privSz (a requested private-key
 * size, not just a buffer capacity) to wc_DhGenerateKeyPair overflows the
 * fixed-capacity internal mp_int in GeneratePrivateDh186 (MP_VAL). The
 * canonical wolfcrypt/test/test.c dh_test() uses a plain byte[256] for the
 * same reason. Reported as a library macro-naming/semantics finding; not
 * fixed here (out of scope for this test-only change). */
#define TEST_DH_BUF_SIZE 512

/*
 * Testing wc_DhPublicKeyDecode
 */
int test_wc_DhPublicKeyDecode(void)
{
    EXPECT_DECLS;
#ifndef NO_DH
#if defined(WOLFSSL_DH_EXTRA) && defined(USE_CERT_BUFFERS_2048)
    DhKey  key;
    word32 inOutIdx;

    XMEMSET(&key, 0, sizeof(DhKey));

    ExpectIntEQ(wc_InitDhKey(&key), 0);

    ExpectIntEQ(wc_DhPublicKeyDecode(NULL,NULL,NULL,0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DhPublicKeyDecode(dh_pub_key_der_2048,NULL,NULL,0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DhPublicKeyDecode(dh_pub_key_der_2048,NULL,NULL,0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    inOutIdx = 0;
    ExpectIntEQ(wc_DhPublicKeyDecode(dh_pub_key_der_2048,&inOutIdx,NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    inOutIdx = 0;
    ExpectIntEQ(wc_DhPublicKeyDecode(dh_pub_key_der_2048,&inOutIdx,&key, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    inOutIdx = 0;
    ExpectIntEQ(wc_DhPublicKeyDecode(dh_pub_key_der_2048,&inOutIdx,&key,
        sizeof_dh_pub_key_der_2048), 0);
    ExpectIntNE(key.p.used, 0);
    ExpectIntNE(key.g.used, 0);
    ExpectIntEQ(key.q.used, 0);
    ExpectIntNE(key.pub.used, 0);
    ExpectIntEQ(key.priv.used, 0);

    DoExpectIntEQ(wc_FreeDhKey(&key), 0);
#endif
#endif /* !NO_DH */
    return EXPECT_RESULT();
}

/*
 * Tests that wc_DhAgree rejects peer public keys that are not in the expected
 * subgroup when the group order q is known (SP 800-56Ar3 section 5.6.2.3.1).
 * This test not compatible with WOLFSSL_SP_MATH, because p vector is not 2048,
 * 3072, or 4096 bits.
 */
int test_wc_DhAgree_subgroup_check(void)
{
    EXPECT_DECLS;
#if !defined(NO_DH) && !defined(WOLFSSL_SP_MATH) && !defined(HAVE_SELFTEST) && \
    (!defined(HAVE_FIPS) || FIPS_VERSION3_GT(7,0,0)) && DH_MIN_SIZE <= 512
    DhKey key;
    WC_RNG rng;
    byte agree[64];

    /* DSA-style 512-bit group where p - 1 == k * q, where q is
     * a 161-bit prime, and g generates the order-q subgroup.
     *
     * y_bad has order 3 mod p (y^3 mod p == 1). It passes the bounds check
     * (2 <= y <= p-2), but is not in the order-q subgroup (y^q mod p != 1).
     * */
    const byte dsa_dh_p[] = {
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xab, 0x80, 0x00, 0x00, 0x47
    };
    const byte dsa_dh_q[] = {
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x07
    };
    const byte dsa_dh_g[] = {
        0x63, 0x23, 0x85, 0x16, 0x66, 0xc1, 0xf1, 0xf0,
        0xc3, 0xa0, 0x95, 0xd0, 0x4b, 0x68, 0x92, 0xf3,
        0x64, 0x09, 0xbd, 0x89, 0x57, 0x85, 0xfa, 0x44,
        0x86, 0xc1, 0x64, 0x86, 0x1e, 0xa1, 0x91, 0x33,
        0xd8, 0xaf, 0xb5, 0xa6, 0x28, 0xed, 0xc2, 0x7c,
        0x37, 0xa1, 0x5b, 0x0b, 0xf7, 0x6a, 0xa4, 0x61,
        0x75, 0x08, 0x16, 0x12, 0xe5, 0x62, 0xc4, 0x89,
        0x5a, 0x9c, 0x1b, 0x76, 0xe1, 0x5f, 0x63, 0x21
    };
    /* Order-3 element: y^3 = 1 mod p, y^q mod p != 1 */
    const byte dsa_dh_y_bad[] = {
        0x41, 0x61, 0x8f, 0xcd, 0xb7, 0x76, 0xb7, 0xd2,
        0x38, 0x46, 0x98, 0x16, 0xa3, 0xfd, 0xd2, 0xa2,
        0x71, 0x6a, 0x0b, 0x66, 0x87, 0x3f, 0x6c, 0x15,
        0x28, 0x46, 0x79, 0xfb, 0x64, 0x4c, 0x2a, 0x28,
        0xe6, 0x65, 0x44, 0x8e, 0xf8, 0x30, 0x4e, 0x73,
        0xec, 0x8b, 0x4b, 0xd2, 0x82, 0xd1, 0x87, 0x20,
        0x35, 0x47, 0x42, 0xe6, 0x94, 0x49, 0x7c, 0x73,
        0xbc, 0x47, 0xcd, 0xcb, 0x88, 0xb8, 0xed, 0x62
    };
    /* A {priv, pub} keypair generated from these parameters.
     * This pair would pass a partial subgroup test. The pub key
     * is not actually needed for this test. */
    const byte priv[] = {
        0xc7, 0x82, 0xd1, 0xc4, 0x13, 0xa8, 0x3f, 0xe0,
        0xef, 0xdc, 0xf4, 0x10, 0xf9, 0xf4, 0xc7, 0x0e,
        0x30, 0xbc, 0x65, 0x14
    };
    /*
    byte pub[] = {
        0x28, 0x2e, 0x2b, 0xf4, 0x4d, 0x83, 0xf5, 0xd8,
        0x77, 0x5a, 0xea, 0x7c, 0x4d, 0x89, 0x98, 0x1b,
        0xe9, 0x61, 0x69, 0x35, 0x39, 0xdd, 0x1b, 0x2d,
        0x5f, 0x35, 0x29, 0x25, 0xd9, 0xec, 0xcc, 0x46,
        0x39, 0xfe, 0x3e, 0xe4, 0x67, 0xc9, 0x47, 0xe1,
        0xc4, 0x5b, 0x02, 0x95, 0x61, 0x4a, 0x23, 0xdc,
        0x3a, 0xf6, 0xce, 0x18, 0x99, 0x1e, 0xe0, 0x72,
        0xeb, 0x53, 0x1f, 0xf0, 0xc9, 0x50, 0x9a, 0xc7
    };
    */
    word32 privSz = sizeof(priv);
    word32 agreeSz;

    #if defined(WOLFSSL_PUBLIC_MP) && !defined(WOLFSSL_SMALL_STACK)
    /* optional sanity checks for the mp used in this dh test. */
    const byte expt[1] = {0x03};
    mp_int     p[1], e[1], q[1];
    mp_int     g[1], y[1], r[1];
    int        isPrime = 0;
    /* init mp */
    ExpectIntEQ(mp_init_multi(p, q, g, y, r, e), MP_OKAY);
    /* load mp values */
    ExpectIntEQ(mp_read_unsigned_bin(p, dsa_dh_p, sizeof(dsa_dh_p)),  MP_OKAY);
    ExpectIntEQ(mp_read_unsigned_bin(e, expt, sizeof(expt)),  MP_OKAY);
    ExpectIntEQ(mp_read_unsigned_bin(q, dsa_dh_q, sizeof(dsa_dh_q)),  MP_OKAY);
    ExpectIntEQ(mp_read_unsigned_bin(g, dsa_dh_g, sizeof(dsa_dh_g)),  MP_OKAY);
    ExpectIntEQ(mp_read_unsigned_bin(y, dsa_dh_y_bad, sizeof(dsa_dh_y_bad)),
                MP_OKAY);
    /* p, q are prime */
    ExpectIntEQ(mp_prime_is_prime(p, 8, &isPrime), MP_OKAY);
    ExpectIntEQ(isPrime, 1);
    ExpectIntEQ(mp_prime_is_prime(q, 8, &isPrime), MP_OKAY);
    ExpectIntEQ(isPrime, 1);
    /* (y ^ 3) mod p == 1*/
    ExpectIntEQ(mp_exptmod(y, e, p, r),  MP_OKAY);
    ExpectIntEQ(mp_cmp_d(r, 1),  MP_EQ);
    /* (g ^ q) mod p == 1*/
    ExpectIntEQ(mp_exptmod(g, q, p, r),  MP_OKAY);
    ExpectIntEQ(mp_cmp_d(r, 1),  MP_EQ);
    /* (y ^ q) mod p != 1*/
    ExpectIntEQ(mp_exptmod(y, q, p, r),  MP_OKAY);
    ExpectIntNE(mp_cmp_d(r, 1),  MP_EQ);
    /* clear them */
    mp_clear(p); mp_clear(e); mp_clear(q);
    mp_clear(g); mp_clear(y); mp_clear(r);
    #endif /* WOLFSSL_PUBLIC_MP && !WOLFSSL_SMALL_STACK */

    XMEMSET(&key, 0, sizeof(DhKey));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_InitDhKey(&key), 0);

    /* Set DH parameters. */
    ExpectIntEQ(wc_DhSetCheckKey(&key, dsa_dh_p, sizeof(dsa_dh_p),
                dsa_dh_g, sizeof(dsa_dh_g), dsa_dh_q, sizeof(dsa_dh_q),
                0, &rng), 0);

    /* sanity: agree with g (valid subgroup element). This should succeed */
    agreeSz = sizeof(agree);
    ExpectIntEQ(wc_DhAgree(&key, agree, &agreeSz, priv, privSz,
                            dsa_dh_g, sizeof(dsa_dh_g)), 0);

    /* y_bad is not in the order-q subgroup. This should be rejected with
     * error DH_CHECK_PUB_E.*/
    agreeSz = sizeof(agree);
    ExpectIntEQ(wc_DhAgree(&key, agree, &agreeSz, priv, privSz,
                            dsa_dh_y_bad, sizeof(dsa_dh_y_bad)),
                            DH_CHECK_PUB_E);

    wc_FreeDhKey(&key);
    wc_FreeRng(&rng);
#endif /* !NO_DH && !defined(WOLFSSL_SP_MATH) && !HAVE_SELFTEST && etc... */
    return EXPECT_RESULT();
}

/*
 * Testing wc_DhSetKey() / wc_DhSetKey_ex() / wc_DhSetCheckKey() bad args and
 * the untrusted-prime-check path: a known FFDHE prime short-circuits the
 * primality test (XMEMCMP fast-path in _DhSetKey), a trusted key skips the
 * primality test entirely, and an untrusted, non-table prime goes through
 * the generic mp_prime_is_prime(_ex) check and is rejected.
 */
int test_wc_DhSetKey(void)
{
    EXPECT_DECLS;
#if !defined(NO_DH) && defined(HAVE_PUBLIC_FFDHE) && defined(HAVE_FFDHE_2048) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
    DhKey key;
    WC_RNG rng;
    const DhParams* params = NULL;
    byte g[] = { 0x02 };
    byte notPrime[] = { 0x04 }; /* even -> not prime, tiny -> fast reject */

    XMEMSET(&key, 0, sizeof(DhKey));
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectNotNull(params = wc_Dh_ffdhe2048_Get());

    /* bad args: wc_DhSetKey */
    ExpectIntEQ(wc_InitDhKey(&key), 0);
    if (params != NULL) {
        ExpectIntEQ(wc_DhSetKey(NULL, params->p, params->p_len, params->g,
            params->g_len), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_DhSetKey(&key, NULL, params->p_len, params->g,
            params->g_len), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_DhSetKey(&key, params->p, 0, params->g,
            params->g_len), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_DhSetKey(&key, params->p, params->p_len, NULL,
            params->g_len), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_DhSetKey(&key, params->p, params->p_len, params->g,
            0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }
    wc_FreeDhKey(&key);

    if (params != NULL) {
        /* valid: known FFDHE prime, short-circuits the primality test */
        ExpectIntEQ(wc_InitDhKey(&key), 0);
        ExpectIntEQ(wc_DhSetKey(&key, params->p, params->p_len, params->g,
            params->g_len), 0);
        wc_FreeDhKey(&key);

        /* valid: wc_DhSetKey_ex with an explicit q (untrusted path; still
         * matches the known FFDHE prime, so the fast-path memcmp - not an
         * actual primality search - sets isPrime). */
        ExpectIntEQ(wc_InitDhKey(&key), 0);
    #ifdef HAVE_FFDHE_Q
        ExpectIntEQ(wc_DhSetKey_ex(&key, params->p, params->p_len,
            params->g, params->g_len, params->q, params->q_len), 0);
    #else
        ExpectIntEQ(wc_DhSetKey_ex(&key, params->p, params->p_len,
            params->g, params->g_len, NULL, 0), 0);
    #endif
        wc_FreeDhKey(&key);
    }

    /* wc_DhSetCheckKey: trusted=1 skips the primality test entirely, so a
     * non-prime p is accepted. */
    ExpectIntEQ(wc_InitDhKey(&key), 0);
    ExpectIntEQ(wc_DhSetCheckKey(&key, notPrime, sizeof(notPrime), g,
        sizeof(g), NULL, 0, 1, NULL), 0);
    wc_FreeDhKey(&key);

    /* wc_DhSetCheckKey: untrusted, non-FFDHE-table p forces the generic
     * mp_prime_is_prime_ex(rng) / mp_prime_is_prime(NULL) path; the value
     * is even (not prime) so both are rejected without a costly search. */
    ExpectIntEQ(wc_InitDhKey(&key), 0);
    ExpectIntEQ(wc_DhSetCheckKey(&key, notPrime, sizeof(notPrime), g,
        sizeof(g), NULL, 0, 0, &rng), WC_NO_ERR_TRACE(DH_CHECK_PUB_E));
    wc_FreeDhKey(&key);
    ExpectIntEQ(wc_InitDhKey(&key), 0);
    ExpectIntEQ(wc_DhSetCheckKey(&key, notPrime, sizeof(notPrime), g,
        sizeof(g), NULL, 0, 0, NULL), WC_NO_ERR_TRACE(DH_CHECK_PUB_E));
    wc_FreeDhKey(&key);

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
}

/*
 * wc_DhSetKey_ex validates untrusted parameters, so it must reject a composite
 * modulus even when that composite is a strong pseudoprime to the fixed
 * small-prime Miller-Rabin bases. n = 341550071728321 = 10670053 * 32010157 is
 * a strong pseudoprime to bases 2, 3, 5, 7, 11, 13, 17 and 19, which the
 * deterministic fixed-base test wrongly accepts as prime. Random-witness
 * testing rejects it. As with the library's own primality check, rejection is
 * probabilistic: eight random Miller-Rabin rounds leave a negligible
 * (well under 1e-4) chance of accepting the composite, so a one-off failure
 * here is statistical, not a regression.
 */
int test_wc_DhSetKey_ex_pseudoprime(void)
{
    EXPECT_DECLS;
#if !defined(NO_DH) && !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS) && \
    !defined(WC_NO_RNG)
    DhKey key;
    /* n = 341550071728321, big-endian. */
    byte p[] = { 0x01, 0x36, 0xA3, 0x52, 0xB2, 0xC8, 0xC1 };
    byte g[] = { 0x02 };

    XMEMSET(&key, 0, sizeof(key));

    ExpectIntEQ(wc_InitDhKey(&key), 0);
    ExpectIntEQ(wc_DhSetKey_ex(&key, p, sizeof(p), g, sizeof(g), NULL, 0),
        WC_NO_ERR_TRACE(DH_CHECK_PUB_E));
    wc_FreeDhKey(&key);
#endif
    return EXPECT_RESULT();
}

/*
 * Testing wc_DhSetNamedKey(), wc_DhGetNamedKeyParamSize(),
 * wc_DhCopyNamedKey() and wc_DhCmpNamedKey().
 */
int test_wc_DhSetNamedKey_and_helpers(void)
{
    EXPECT_DECLS;
#if !defined(NO_DH) && defined(HAVE_PUBLIC_FFDHE) && defined(HAVE_FFDHE_2048) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
    DhKey key;
    const DhParams* p2048 = NULL;
    word32 pSz = 0, gSz = 0, qSz = 0;
    byte pOut[TEST_DH_BUF_SIZE];
    byte gOut[TEST_DH_BUF_SIZE];
    byte qOut[TEST_DH_BUF_SIZE];

    ExpectNotNull(p2048 = wc_Dh_ffdhe2048_Get());

    /* wc_DhSetNamedKey: unknown name -> default case leaves p/g NULL,
     * _DhSetKey then rejects with BAD_FUNC_ARG (p==NULL). */
    ExpectIntEQ(wc_InitDhKey(&key), 0);
    ExpectIntEQ(wc_DhSetNamedKey(&key, 9999), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    wc_FreeDhKey(&key);

    /* valid named groups: exercise each HAVE_FFDHE_* case arm. */
    ExpectIntEQ(wc_InitDhKey(&key), 0);
    ExpectIntEQ(wc_DhSetNamedKey(&key, WC_FFDHE_2048), 0);
    wc_FreeDhKey(&key);
#ifdef HAVE_FFDHE_3072
    ExpectIntEQ(wc_InitDhKey(&key), 0);
    ExpectIntEQ(wc_DhSetNamedKey(&key, WC_FFDHE_3072), 0);
    wc_FreeDhKey(&key);
#endif
#ifdef HAVE_FFDHE_4096
    ExpectIntEQ(wc_InitDhKey(&key), 0);
    ExpectIntEQ(wc_DhSetNamedKey(&key, WC_FFDHE_4096), 0);
    wc_FreeDhKey(&key);
#endif

    /* wc_DhGetNamedKeyParamSize: NULL out pointers (each skipped
     * independently), unknown name (all sizes stay 0), valid name. */
    ExpectIntEQ(wc_DhGetNamedKeyParamSize(WC_FFDHE_2048, &pSz, &gSz, &qSz),
        0);
    ExpectIntEQ(pSz, p2048 != NULL ? p2048->p_len : 0);
    ExpectIntEQ(wc_DhGetNamedKeyParamSize(WC_FFDHE_2048, NULL, &gSz, &qSz),
        0);
    ExpectIntEQ(wc_DhGetNamedKeyParamSize(WC_FFDHE_2048, &pSz, NULL, &qSz),
        0);
    ExpectIntEQ(wc_DhGetNamedKeyParamSize(WC_FFDHE_2048, &pSz, &gSz, NULL),
        0);
    pSz = 1234; gSz = 1234; qSz = 1234;
    ExpectIntEQ(wc_DhGetNamedKeyParamSize(9999, &pSz, &gSz, &qSz), 0);
    ExpectIntEQ(pSz, 0);
    ExpectIntEQ(gSz, 0);
    ExpectIntEQ(qSz, 0);

    /* wc_DhCopyNamedKey: NULL output buffers (each skipped independently
     * both for the copy and the size-out); unknown name (pC/gC/qC stay
     * NULL, only the *Sz outs are touched, left at 0). */
    if (p2048 != NULL) {
        XMEMSET(pOut, 0, sizeof(pOut));
        XMEMSET(gOut, 0, sizeof(gOut));
        XMEMSET(qOut, 0, sizeof(qOut));
        pSz = sizeof(pOut); gSz = sizeof(gOut); qSz = sizeof(qOut);
        ExpectIntEQ(wc_DhCopyNamedKey(WC_FFDHE_2048, pOut, &pSz, gOut, &gSz,
            qOut, &qSz), 0);
        ExpectIntEQ(pSz, p2048->p_len);
        ExpectIntEQ(XMEMCMP(pOut, p2048->p, pSz), 0);
        ExpectIntEQ(XMEMCMP(gOut, p2048->g, gSz), 0);
    }
    ExpectIntEQ(wc_DhCopyNamedKey(WC_FFDHE_2048, NULL, NULL, NULL, NULL,
        NULL, NULL), 0);
    pSz = 999; gSz = 999; qSz = 999;
    ExpectIntEQ(wc_DhCopyNamedKey(9999, pOut, &pSz, gOut, &gSz, qOut, &qSz),
        0);
    ExpectIntEQ(pSz, 0);
    ExpectIntEQ(gSz, 0);
    ExpectIntEQ(qSz, 0);

    /* wc_DhCmpNamedKey: goodName false (unknown name -> cmp stays 0);
     * goodName true with a full p/g/q match (cmp=1); mismatched p, g and q
     * in turn (cmp=0 each time); matching p/g with noQ=1 and a corrupted q
     * (q ignored -> cmp=1). DhParams has no q/q_len member at all unless
     * HAVE_FFDHE_Q, so every p2048->q/q_len use below is guarded; without
     * HAVE_FFDHE_Q, noQ=1 with a NULL/0 q exercises the same p/g compare
     * logic (the q-compare operand of the cmp expression is skipped either
     * way when noQ is true). */
    if (p2048 != NULL) {
#ifdef HAVE_FFDHE_Q
        ExpectIntEQ(wc_DhCmpNamedKey(9999, 0, p2048->p, p2048->p_len,
            p2048->g, p2048->g_len, p2048->q, p2048->q_len), 0);
        ExpectIntEQ(wc_DhCmpNamedKey(WC_FFDHE_2048, 0, p2048->p,
            p2048->p_len, p2048->g, p2048->g_len, p2048->q, p2048->q_len),
            1);

        XMEMCPY(pOut, p2048->p, p2048->p_len);
        pOut[0] ^= 0x01;
        ExpectIntEQ(wc_DhCmpNamedKey(WC_FFDHE_2048, 0, pOut, p2048->p_len,
            p2048->g, p2048->g_len, p2048->q, p2048->q_len), 0);

        XMEMCPY(gOut, p2048->g, p2048->g_len);
        gOut[0] ^= 0x01;
        ExpectIntEQ(wc_DhCmpNamedKey(WC_FFDHE_2048, 0, p2048->p,
            p2048->p_len, gOut, p2048->g_len, p2048->q, p2048->q_len), 0);

        XMEMCPY(qOut, p2048->q, p2048->q_len);
        qOut[0] ^= 0x01;
        ExpectIntEQ(wc_DhCmpNamedKey(WC_FFDHE_2048, 0, p2048->p,
            p2048->p_len, p2048->g, p2048->g_len, qOut, p2048->q_len), 0);
        ExpectIntEQ(wc_DhCmpNamedKey(WC_FFDHE_2048, 1, p2048->p,
            p2048->p_len, p2048->g, p2048->g_len, qOut, p2048->q_len), 1);
#else
        ExpectIntEQ(wc_DhCmpNamedKey(9999, 1, p2048->p, p2048->p_len,
            p2048->g, p2048->g_len, NULL, 0), 0);
        ExpectIntEQ(wc_DhCmpNamedKey(WC_FFDHE_2048, 1, p2048->p,
            p2048->p_len, p2048->g, p2048->g_len, NULL, 0), 1);

        XMEMCPY(pOut, p2048->p, p2048->p_len);
        pOut[0] ^= 0x01;
        ExpectIntEQ(wc_DhCmpNamedKey(WC_FFDHE_2048, 1, pOut, p2048->p_len,
            p2048->g, p2048->g_len, NULL, 0), 0);

        XMEMCPY(gOut, p2048->g, p2048->g_len);
        gOut[0] ^= 0x01;
        ExpectIntEQ(wc_DhCmpNamedKey(WC_FFDHE_2048, 1, p2048->p,
            p2048->p_len, gOut, p2048->g_len, NULL, 0), 0);
#endif
    }
#endif
    return EXPECT_RESULT();
}

/*
 * Testing wc_DhGenerateKeyPair() / wc_DhGeneratePublic() bad args.
 */
int test_wc_DhGenerateKeyPair_bad_args(void)
{
    EXPECT_DECLS;
#if !defined(NO_DH) && defined(HAVE_FFDHE_2048) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
    DhKey key;
    WC_RNG rng;
    byte priv[TEST_DH_BUF_SIZE];
    byte pub[TEST_DH_BUF_SIZE];
    word32 privSz = sizeof(priv), pubSz = sizeof(pub);

    ExpectIntEQ(wc_InitDhKey(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_DhSetNamedKey(&key, WC_FFDHE_2048), 0);

    ExpectIntEQ(wc_DhGenerateKeyPair(NULL, &rng, priv, &privSz, pub, &pubSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DhGenerateKeyPair(&key, NULL, priv, &privSz, pub, &pubSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DhGenerateKeyPair(&key, &rng, NULL, &privSz, pub, &pubSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DhGenerateKeyPair(&key, &rng, priv, NULL, pub, &pubSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DhGenerateKeyPair(&key, &rng, priv, &privSz, NULL,
        &pubSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DhGenerateKeyPair(&key, &rng, priv, &privSz, pub, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_DhGeneratePublic(NULL, priv, 1, pub, &pubSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DhGeneratePublic(&key, NULL, 1, pub, &pubSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DhGeneratePublic(&key, priv, 0, pub, &pubSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DhGeneratePublic(&key, priv, 1, NULL, &pubSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DhGeneratePublic(&key, priv, 1, pub, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_FreeDhKey(&key);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
}

/*
 * Full key-generation + agreement round trip across every enabled FFDHE
 * named group. Exercises GeneratePrivateDh186 (q known from the named
 * group), GeneratePublicDh's SP-accelerated dispatch (2048/3072/4096, when
 * WOLFSSL_HAVE_SP_DH is compiled in) and its generic mp_exptmod fallback,
 * and the wc_DhAgree_Sync body (peer-key validation, SP dispatch, generic
 * fallback, and the constant-time fold-back via wc_DhAgree_ct).
 */
int test_wc_DhGenerateKeyPair_and_Agree(void)
{
    EXPECT_DECLS;
#if !defined(NO_DH) && !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
    DhKey aliceKey, bobKey;
    WC_RNG rng;
    byte alicePriv[TEST_DH_BUF_SIZE], alicePub[TEST_DH_BUF_SIZE];
    byte bobPriv[TEST_DH_BUF_SIZE], bobPub[TEST_DH_BUF_SIZE];
    byte aliceAgree[TEST_DH_BUF_SIZE], bobAgree[TEST_DH_BUF_SIZE];
    word32 alicePrivSz, alicePubSz, bobPrivSz, bobPubSz;
    word32 aliceAgreeSz, bobAgreeSz;
    static const int groups[] = {
    #ifdef HAVE_FFDHE_2048
        WC_FFDHE_2048,
    #endif
    #ifdef HAVE_FFDHE_3072
        WC_FFDHE_3072,
    #endif
    #ifdef HAVE_FFDHE_4096
        WC_FFDHE_4096,
    #endif
        0 /* keep the array non-empty when no HAVE_FFDHE_* is enabled */
    };
    size_t i;

    ExpectIntEQ(wc_InitRng(&rng), 0);

    for (i = 0; i < sizeof(groups) / sizeof(groups[0]) - 1; i++) {
        XMEMSET(&aliceKey, 0, sizeof(aliceKey));
        XMEMSET(&bobKey, 0, sizeof(bobKey));
        ExpectIntEQ(wc_InitDhKey(&aliceKey), 0);
        ExpectIntEQ(wc_InitDhKey(&bobKey), 0);
        ExpectIntEQ(wc_DhSetNamedKey(&aliceKey, groups[i]), 0);
        ExpectIntEQ(wc_DhSetNamedKey(&bobKey, groups[i]), 0);

        alicePrivSz = sizeof(alicePriv);
        alicePubSz = sizeof(alicePub);
        ExpectIntEQ(wc_DhGenerateKeyPair(&aliceKey, &rng, alicePriv,
            &alicePrivSz, alicePub, &alicePubSz), 0);

        bobPrivSz = sizeof(bobPriv);
        bobPubSz = sizeof(bobPub);
        ExpectIntEQ(wc_DhGenerateKeyPair(&bobKey, &rng, bobPriv, &bobPrivSz,
            bobPub, &bobPubSz), 0);

        aliceAgreeSz = sizeof(aliceAgree);
        ExpectIntEQ(wc_DhAgree(&aliceKey, aliceAgree, &aliceAgreeSz,
            alicePriv, alicePrivSz, bobPub, bobPubSz), 0);
        bobAgreeSz = sizeof(bobAgree);
        ExpectIntEQ(wc_DhAgree(&bobKey, bobAgree, &bobAgreeSz, bobPriv,
            bobPrivSz, alicePub, alicePubSz), 0);
        ExpectIntEQ(aliceAgreeSz, bobAgreeSz);
        ExpectIntEQ(XMEMCMP(aliceAgree, bobAgree, aliceAgreeSz), 0);

        /* wc_DhAgree bad args (all-valid baseline is the call above) */
        ExpectIntEQ(wc_DhAgree(NULL, aliceAgree, &aliceAgreeSz, alicePriv,
            alicePrivSz, bobPub, bobPubSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_DhAgree(&aliceKey, NULL, &aliceAgreeSz, alicePriv,
            alicePrivSz, bobPub, bobPubSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_DhAgree(&aliceKey, aliceAgree, NULL, alicePriv,
            alicePrivSz, bobPub, bobPubSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_DhAgree(&aliceKey, aliceAgree, &aliceAgreeSz, NULL,
            alicePrivSz, bobPub, bobPubSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_DhAgree(&aliceKey, aliceAgree, &aliceAgreeSz,
            alicePriv, alicePrivSz, NULL, bobPubSz),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* constant-time variant of the same exchange, plus its own bad
         * args and the too-small-buffer BUFFER_E path. */
        aliceAgreeSz = sizeof(aliceAgree);
        ExpectIntEQ(wc_DhAgree_ct(&aliceKey, aliceAgree, &aliceAgreeSz,
            alicePriv, alicePrivSz, bobPub, bobPubSz), 0);
        ExpectIntEQ(wc_DhAgree_ct(NULL, aliceAgree, &aliceAgreeSz,
            alicePriv, alicePrivSz, bobPub, bobPubSz),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_DhAgree_ct(&aliceKey, NULL, &aliceAgreeSz, alicePriv,
            alicePrivSz, bobPub, bobPubSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_DhAgree_ct(&aliceKey, aliceAgree, NULL, alicePriv,
            alicePrivSz, bobPub, bobPubSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_DhAgree_ct(&aliceKey, aliceAgree, &aliceAgreeSz, NULL,
            alicePrivSz, bobPub, bobPubSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_DhAgree_ct(&aliceKey, aliceAgree, &aliceAgreeSz,
            alicePriv, alicePrivSz, NULL, bobPubSz),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        aliceAgreeSz = 1;
        ExpectIntEQ(wc_DhAgree_ct(&aliceKey, aliceAgree, &aliceAgreeSz,
            alicePriv, alicePrivSz, bobPub, bobPubSz),
            WC_NO_ERR_TRACE(BUFFER_E));

        wc_FreeDhKey(&aliceKey);
        wc_FreeDhKey(&bobKey);
    }

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
}

/*
 * WC_DH_NONBLOCK: drives the incremental sp_DhExp_*_nb state machine in
 * wc_DhAgree_Sync (both the cached-pubkey-validation branch and the nb
 * dispatch itself), pairing with the default (key->nb == NULL) path
 * exercised by every other test in this file.
 */
int test_wc_DhAgree_nonblock(void)
{
    EXPECT_DECLS;
#if !defined(NO_DH) && defined(WC_DH_NONBLOCK) && defined(HAVE_FFDHE_2048) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
    DhKey aliceKey, bobKey;
    WC_RNG rng;
    DhNb nb;
    byte alicePriv[TEST_DH_BUF_SIZE], alicePub[TEST_DH_BUF_SIZE];
    byte bobPriv[TEST_DH_BUF_SIZE], bobPub[TEST_DH_BUF_SIZE];
    byte agree[TEST_DH_BUF_SIZE];
    word32 alicePrivSz = sizeof(alicePriv), alicePubSz = sizeof(alicePub);
    word32 bobPrivSz = sizeof(bobPriv), bobPubSz = sizeof(bobPub);
    word32 agreeSz;
    int ret;
    int rounds;

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_InitDhKey(&aliceKey), 0);
    ExpectIntEQ(wc_InitDhKey(&bobKey), 0);
    ExpectIntEQ(wc_DhSetNamedKey(&aliceKey, WC_FFDHE_2048), 0);
    ExpectIntEQ(wc_DhSetNamedKey(&bobKey, WC_FFDHE_2048), 0);

    ExpectIntEQ(wc_DhGenerateKeyPair(&aliceKey, &rng, alicePriv,
        &alicePrivSz, alicePub, &alicePubSz), 0);
    ExpectIntEQ(wc_DhGenerateKeyPair(&bobKey, &rng, bobPriv, &bobPrivSz,
        bobPub, &bobPubSz), 0);

    XMEMSET(&nb, 0, sizeof(nb));
    ExpectIntEQ(wc_DhSetNonBlock(&aliceKey, &nb), 0);
    ExpectIntEQ(wc_DhSetNonBlock(NULL, &nb), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* first op: key->nb->pubKeyValidated starts unset, so the peer-key
     * validation runs and caches its result. */
    ret = WC_NO_ERR_TRACE(MP_WOULDBLOCK);
    for (rounds = 0; ret == WC_NO_ERR_TRACE(MP_WOULDBLOCK) && rounds < 200000;
            rounds++) {
        agreeSz = sizeof(agree);
        ret = wc_DhAgree(&aliceKey, agree, &agreeSz, alicePriv, alicePrivSz,
            bobPub, bobPubSz);
    }
    ExpectIntEQ(ret, 0);

    /* second op on the same nb-attached key: pubKeyValidated was cleared
     * after the first op completed, so this re-enters the same validation
     * + dispatch path a second time. */
    ret = WC_NO_ERR_TRACE(MP_WOULDBLOCK);
    for (rounds = 0; ret == WC_NO_ERR_TRACE(MP_WOULDBLOCK) && rounds < 200000;
            rounds++) {
        agreeSz = sizeof(agree);
        ret = wc_DhAgree(&aliceKey, agree, &agreeSz, alicePriv, alicePrivSz,
            bobPub, bobPubSz);
    }
    ExpectIntEQ(ret, 0);

    /* disable non-blocking mode (nb == NULL) */
    ExpectIntEQ(wc_DhSetNonBlock(&aliceKey, NULL), 0);
    agreeSz = sizeof(agree);
    ExpectIntEQ(wc_DhAgree(&aliceKey, agree, &agreeSz, alicePriv,
        alicePrivSz, bobPub, bobPubSz), 0);

    wc_FreeDhKey(&aliceKey);
    wc_FreeDhKey(&bobKey);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
}

/*
 * Testing wc_DhImportKeyPair() / wc_DhExportKeyPair() (WOLFSSL_DH_EXTRA).
 */
int test_wc_DhImportExportKeyPair(void)
{
    EXPECT_DECLS;
#if !defined(NO_DH) && defined(WOLFSSL_DH_EXTRA) && defined(HAVE_FFDHE_2048) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
    DhKey key;
    WC_RNG rng;
    byte priv[TEST_DH_BUF_SIZE], pub[TEST_DH_BUF_SIZE];
    word32 privSz = sizeof(priv), pubSz = sizeof(pub);
    byte privOut[TEST_DH_BUF_SIZE], pubOut[TEST_DH_BUF_SIZE];
    word32 privOutSz, pubOutSz;

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_InitDhKey(&key), 0);
    ExpectIntEQ(wc_DhSetNamedKey(&key, WC_FFDHE_2048), 0);
    ExpectIntEQ(wc_DhGenerateKeyPair(&key, &rng, priv, &privSz, pub, &pubSz),
        0);
    wc_FreeDhKey(&key);

    /* bad args */
    ExpectIntEQ(wc_InitDhKey(&key), 0);
    ExpectIntEQ(wc_DhImportKeyPair(NULL, priv, privSz, pub, pubSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* neither priv nor pub supplied -> BAD_FUNC_ARG */
    ExpectIntEQ(wc_DhImportKeyPair(&key, NULL, 0, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* priv only */
    ExpectIntEQ(wc_DhImportKeyPair(&key, priv, privSz, NULL, 0), 0);
    wc_FreeDhKey(&key);

    /* pub only */
    ExpectIntEQ(wc_InitDhKey(&key), 0);
    ExpectIntEQ(wc_DhImportKeyPair(&key, NULL, 0, pub, pubSz), 0);
    wc_FreeDhKey(&key);

    /* both */
    ExpectIntEQ(wc_InitDhKey(&key), 0);
    ExpectIntEQ(wc_DhImportKeyPair(&key, priv, privSz, pub, pubSz), 0);

    /* export bad args */
    privOutSz = sizeof(privOut);
    pubOutSz = sizeof(pubOut);
    ExpectIntEQ(wc_DhExportKeyPair(NULL, privOut, &privOutSz, pubOut,
        &pubOutSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DhExportKeyPair(&key, privOut, NULL, pubOut, &pubOutSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DhExportKeyPair(&key, privOut, &privOutSz, pubOut, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* valid: neither priv nor pub requested (guard is all-false) */
    ExpectIntEQ(wc_DhExportKeyPair(&key, NULL, NULL, NULL, NULL), 0);

    /* valid: full export */
    privOutSz = sizeof(privOut);
    pubOutSz = sizeof(pubOut);
    ExpectIntEQ(wc_DhExportKeyPair(&key, privOut, &privOutSz, pubOut,
        &pubOutSz), 0);
    ExpectIntEQ(XMEMCMP(privOut, priv, privOutSz), 0);
    ExpectIntEQ(XMEMCMP(pubOut, pub, pubOutSz), 0);

    /* buffer too small, priv then pub */
    privOutSz = 1;
    ExpectIntEQ(wc_DhExportKeyPair(&key, privOut, &privOutSz, NULL, NULL),
        WC_NO_ERR_TRACE(BUFFER_E));
    pubOutSz = 1;
    ExpectIntEQ(wc_DhExportKeyPair(&key, NULL, NULL, pubOut, &pubOutSz),
        WC_NO_ERR_TRACE(BUFFER_E));

    wc_FreeDhKey(&key);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
}

/*
 * Testing wc_DhCheckPubKey() / wc_DhCheckPubKey_ex() (the file-static
 * _ffc_validate_public_key, reached only through these two thin wrappers).
 */
int test_wc_DhCheckPubKey(void)
{
    EXPECT_DECLS;
#if !defined(NO_DH) && defined(HAVE_PUBLIC_FFDHE) && defined(HAVE_FFDHE_2048) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
    DhKey key;
    WC_RNG rng;
    const DhParams* params = NULL;
    byte priv[TEST_DH_BUF_SIZE], pub[TEST_DH_BUF_SIZE];
    word32 privSz = sizeof(priv), pubSz = sizeof(pub);
    byte tiny[1] = { 0x01 };

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectNotNull(params = wc_Dh_ffdhe2048_Get());

    ExpectIntEQ(wc_InitDhKey(&key), 0);
    ExpectIntEQ(wc_DhSetNamedKey(&key, WC_FFDHE_2048), 0);
    ExpectIntEQ(wc_DhGenerateKeyPair(&key, &rng, priv, &privSz, pub, &pubSz),
        0);

    /* bad args */
    ExpectIntEQ(wc_DhCheckPubKey(NULL, pub, pubSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DhCheckPubKey(&key, NULL, pubSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DhCheckPubKey_ex(NULL, pub, pubSz, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DhCheckPubKey_ex(&key, NULL, pubSz, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* valid: uses key->q (named group, q known) */
    ExpectIntEQ(wc_DhCheckPubKey(&key, pub, pubSz), 0);
    if (params != NULL) {
        /* valid: explicit prime (q) override */
    #ifdef HAVE_FFDHE_Q
        ExpectIntEQ(wc_DhCheckPubKey_ex(&key, pub, pubSz, params->q,
            params->q_len), 0);
    #endif

        /* invalid: pub >= p - 1 (use p itself, definitely out of range) */
        ExpectIntEQ(wc_DhCheckPubKey(&key, params->p, params->p_len),
            WC_NO_ERR_TRACE(MP_CMP_E));
    }

    /* invalid: pub < 2 */
    ExpectIntEQ(wc_DhCheckPubKey(&key, tiny, sizeof(tiny)),
        WC_NO_ERR_TRACE(MP_CMP_E));

    wc_FreeDhKey(&key);

    if (params != NULL) {
        /* key with no q known: the order-q subgroup check is skipped
         * entirely (prime==NULL && mp_iszero(&key->q)==MP_NO is false). */
        ExpectIntEQ(wc_InitDhKey(&key), 0);
        ExpectIntEQ(wc_DhSetKey(&key, params->p, params->p_len, params->g,
            params->g_len), 0);
        ExpectIntEQ(wc_DhCheckPubKey(&key, pub, pubSz), 0);
        wc_FreeDhKey(&key);
    }

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
}

/*
 * Testing wc_DhCheckPrivKey() / wc_DhCheckPrivKey_ex().
 */
int test_wc_DhCheckPrivKey(void)
{
    EXPECT_DECLS;
#if !defined(NO_DH) && defined(HAVE_PUBLIC_FFDHE) && defined(HAVE_FFDHE_2048) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
    DhKey key;
    WC_RNG rng;
    const DhParams* params = NULL;
    byte priv[TEST_DH_BUF_SIZE], pub[TEST_DH_BUF_SIZE];
    word32 privSz = sizeof(priv), pubSz = sizeof(pub);
    byte zero[1] = { 0x00 };

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectNotNull(params = wc_Dh_ffdhe2048_Get());
    ExpectIntEQ(wc_InitDhKey(&key), 0);
    ExpectIntEQ(wc_DhSetNamedKey(&key, WC_FFDHE_2048), 0);
    ExpectIntEQ(wc_DhGenerateKeyPair(&key, &rng, priv, &privSz, pub, &pubSz),
        0);

    /* bad args */
    ExpectIntEQ(wc_DhCheckPrivKey(NULL, priv, privSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DhCheckPrivKey(&key, NULL, privSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DhCheckPrivKey_ex(NULL, priv, privSz, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DhCheckPrivKey_ex(&key, NULL, privSz, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* valid: key->q known */
    ExpectIntEQ(wc_DhCheckPrivKey(&key, priv, privSz), 0);
    /* invalid: priv == 0 */
    ExpectIntEQ(wc_DhCheckPrivKey(&key, zero, sizeof(zero)),
        WC_NO_ERR_TRACE(MP_CMP_E));

    if (params != NULL) {
    #ifdef HAVE_FFDHE_Q
        byte big[TEST_DH_BUF_SIZE];

        /* valid: explicit prime (q) override */
        ExpectIntEQ(wc_DhCheckPrivKey_ex(&key, priv, privSz, params->q,
            params->q_len), 0);

        /* invalid: priv > q - 1 (use q itself as priv, too big by 1) */
        XMEMSET(big, 0, sizeof(big));
        XMEMCPY(big, params->q, params->q_len);
        ExpectIntEQ(wc_DhCheckPrivKey(&key, big, params->q_len),
            WC_NO_ERR_TRACE(DH_CHECK_PRIV_E));
    #endif
    }

    wc_FreeDhKey(&key);

    if (params != NULL) {
        /* key with no q known: only the priv==0 sanity check applies. */
        ExpectIntEQ(wc_InitDhKey(&key), 0);
        ExpectIntEQ(wc_DhSetKey(&key, params->p, params->p_len, params->g,
            params->g_len), 0);
        ExpectIntEQ(wc_DhCheckPrivKey(&key, priv, privSz), 0);
        wc_FreeDhKey(&key);
    }

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
}

/*
 * Testing wc_DhCheckKeyPair() (the file-static _ffc_pairwise_consistency_
 * test) and the WOLFSSL_VALIDATE_DH_KEYGEN generate-time equivalent.
 */
int test_wc_DhCheckKeyPair(void)
{
    EXPECT_DECLS;
#if !defined(NO_DH) && defined(HAVE_FFDHE_2048) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
    DhKey key;
    WC_RNG rng;
    /* zero-initialized: wc_DhGenerateKeyPair fills pub at runtime, but the
     * later read-modify-write (pub[pubSz-1] ^= 0x01) reads as uninitialized
     * to clang-tidy without this. */
    byte priv[TEST_DH_BUF_SIZE] = {0}, pub[TEST_DH_BUF_SIZE] = {0};
    word32 privSz = sizeof(priv), pubSz = sizeof(pub);

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_InitDhKey(&key), 0);
    ExpectIntEQ(wc_DhSetNamedKey(&key, WC_FFDHE_2048), 0);
    ExpectIntEQ(wc_DhGenerateKeyPair(&key, &rng, priv, &privSz, pub, &pubSz),
        0);

    /* bad args */
    ExpectIntEQ(wc_DhCheckKeyPair(NULL, pub, pubSz, priv, privSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DhCheckKeyPair(&key, NULL, pubSz, priv, privSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DhCheckKeyPair(&key, pub, pubSz, NULL, privSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* valid pair */
    ExpectIntEQ(wc_DhCheckKeyPair(&key, pub, pubSz, priv, privSz), 0);

    /* mismatched pair: corrupt the public key */
    pub[pubSz - 1] ^= 0x01;
    ExpectIntEQ(wc_DhCheckKeyPair(&key, pub, pubSz, priv, privSz),
        WC_NO_ERR_TRACE(MP_CMP_E));

    wc_FreeDhKey(&key);

    /* wc_DhGenerateKeyPair / wc_DhGeneratePublic with
     * WOLFSSL_VALIDATE_DH_KEYGEN on: exercises _ffc_validate_public_key +
     * _ffc_pairwise_consistency_test from the generate path itself. */
    ExpectIntEQ(wc_InitDhKey(&key), 0);
    ExpectIntEQ(wc_DhSetNamedKey(&key, WC_FFDHE_2048), 0);
    privSz = sizeof(priv); pubSz = sizeof(pub);
    ExpectIntEQ(wc_DhGenerateKeyPair(&key, &rng, priv, &privSz, pub,
        &pubSz), 0);
    wc_FreeDhKey(&key);

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
}

/*
 * Testing wc_DhGenerateParams() and wc_DhExportParamsRaw() (WOLFSSL_KEY_GEN).
 */
int test_wc_DhGenerateParams_and_ExportRaw(void)
{
    EXPECT_DECLS;
/* Excludes bare WOLFSSL_SP_MATH: its reduced backend cannot generate DH
 * domain parameters (wc_DhGenerateParams returns PRIME_GEN_E), so the
 * generate-and-export flow below is only valid with the full SP math
 * (WOLFSSL_SP_MATH_ALL), fastmath or heapmath backends. */
#if !defined(NO_DH) && defined(WOLFSSL_KEY_GEN) && !defined(WOLFSSL_SP_MATH) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
    DhKey dh;
    WC_RNG rng;
    /* g is found by an unbounded incrementing search (wc_DhGenerateParams),
     * so size its buffer the same as p/q rather than assuming it stays
     * small. */
    byte pOut[TEST_DH_BUF_SIZE], qOut[TEST_DH_BUF_SIZE];
    byte gOut[TEST_DH_BUF_SIZE];
    word32 pSz, qSz, gSz;

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_InitDhKey(&dh), 0);

    /* bad args */
    ExpectIntEQ(wc_DhGenerateParams(NULL, 1024, &dh),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DhGenerateParams(&rng, 1024, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_DhGenerateParams(&rng, 1024, &dh), 0);

    /* bad args */
    pSz = sizeof(pOut); qSz = sizeof(qOut); gSz = sizeof(gOut);
    ExpectIntEQ(wc_DhExportParamsRaw(NULL, pOut, &pSz, qOut, &qSz, gOut,
        &gSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DhExportParamsRaw(&dh, pOut, NULL, qOut, &qSz, gOut,
        &gSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DhExportParamsRaw(&dh, pOut, &pSz, qOut, NULL, gOut,
        &gSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DhExportParamsRaw(&dh, pOut, &pSz, qOut, &qSz, gOut,
        NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* length-only query (all three buffer pointers NULL) */
    ExpectIntEQ(wc_DhExportParamsRaw(&dh, NULL, &pSz, NULL, &qSz, NULL,
        &gSz), WC_NO_ERR_TRACE(LENGTH_ONLY_E));

    /* mixed NULL (some but not all buffers NULL) -> BAD_FUNC_ARG */
    ExpectIntEQ(wc_DhExportParamsRaw(&dh, pOut, &pSz, NULL, &qSz, gOut,
        &gSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* buffer too small for each of p/q/g in turn. 0 (rather than a small
     * fixed literal) guarantees BUFFER_E regardless of the actual byte
     * length wc_DhGenerateParams happened to produce for p/q/g (g in
     * particular is found by an unbounded incrementing search, so its
     * length is not fixed). */
    pSz = 0; qSz = sizeof(qOut); gSz = sizeof(gOut);
    ExpectIntEQ(wc_DhExportParamsRaw(&dh, pOut, &pSz, qOut, &qSz, gOut,
        &gSz), WC_NO_ERR_TRACE(BUFFER_E));
    pSz = sizeof(pOut); qSz = 0; gSz = sizeof(gOut);
    ExpectIntEQ(wc_DhExportParamsRaw(&dh, pOut, &pSz, qOut, &qSz, gOut,
        &gSz), WC_NO_ERR_TRACE(BUFFER_E));
    pSz = sizeof(pOut); qSz = sizeof(qOut); gSz = 0;
    ExpectIntEQ(wc_DhExportParamsRaw(&dh, pOut, &pSz, qOut, &qSz, gOut,
        &gSz), WC_NO_ERR_TRACE(BUFFER_E));

    /* full valid export */
    pSz = sizeof(pOut); qSz = sizeof(qOut); gSz = sizeof(gOut);
    ExpectIntEQ(wc_DhExportParamsRaw(&dh, pOut, &pSz, qOut, &qSz, gOut,
        &gSz), 0);

    wc_FreeDhKey(&dh);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
}

/*
 * WOLFSSL_NO_DH186 axis coverage for CheckDhLN: a real FFDHE prime (so the
 * untrusted primality check fast-paths via the table memcmp, no expensive
 * search) paired with synthetic q sizes drives CheckDhLN's
 * "divLen==224 || divLen==256" MC/DC pair, plus the all-false rejection.
 * Compiled out entirely under WOLFSSL_NO_DH186 (CheckDhLN does not exist).
 */
int test_wc_DhGenerateKeyPair_CheckDhLN(void)
{
    EXPECT_DECLS;
/* WOLFSSL_VALIDATE_DH_KEYGEN is excluded: the synthetic q values below are
 * chosen only to hit CheckDhLN's bit-length arithmetic, not to be the real
 * subgroup order of the FFDHE-2048 (p, g) pair, so the pairwise-consistency
 * / public-key subgroup check that WOLFSSL_VALIDATE_DH_KEYGEN adds to
 * wc_DhGeneratePublic would (correctly) reject the generated key. */
#if !defined(NO_DH) && !defined(WOLFSSL_NO_DH186) && \
    !defined(WOLFSSL_VALIDATE_DH_KEYGEN) && \
    defined(HAVE_PUBLIC_FFDHE) && defined(HAVE_FFDHE_2048) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
    DhKey key;
    WC_RNG rng;
    const DhParams* params = NULL;
    byte priv[TEST_DH_BUF_SIZE], pub[TEST_DH_BUF_SIZE];
    word32 privSz, pubSz;
    byte q224[28];
    byte qBad[25];

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectNotNull(params = wc_Dh_ffdhe2048_Get());
    XMEMSET(q224, 0x01, sizeof(q224));
    XMEMSET(qBad, 0x01, sizeof(qBad));

    if (params != NULL) {
        /* real FFDHE-2048 prime + synthetic 224-bit q:
         * CheckDhLN(2048, 224) -> divLen==224 true, divLen==256 false. */
        ExpectIntEQ(wc_InitDhKey(&key), 0);
        ExpectIntEQ(wc_DhSetCheckKey(&key, params->p, params->p_len,
            params->g, params->g_len, q224, sizeof(q224), 0, &rng), 0);
        privSz = sizeof(priv); pubSz = sizeof(pub);
        ExpectIntEQ(wc_DhGenerateKeyPair(&key, &rng, priv, &privSz, pub,
            &pubSz), 0);
        wc_FreeDhKey(&key);

        /* same prime, q whose bit length is neither 224 nor 256:
         * CheckDhLN rejects (-1) -> BAD_FUNC_ARG (both operands false). */
        ExpectIntEQ(wc_InitDhKey(&key), 0);
        ExpectIntEQ(wc_DhSetCheckKey(&key, params->p, params->p_len,
            params->g, params->g_len, qBad, sizeof(qBad), 0, &rng), 0);
        privSz = sizeof(priv); pubSz = sizeof(pub);
        ExpectIntEQ(wc_DhGenerateKeyPair(&key, &rng, priv, &privSz, pub,
            &pubSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        wc_FreeDhKey(&key);
    }

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
}
