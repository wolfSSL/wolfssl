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
    (!defined(HAVE_FIPS) || FIPS_VERSION3_GT(7,0,0))
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

