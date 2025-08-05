/* test_ossl_dh.c
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

#include <wolfssl/openssl/dh.h>
#include <wolfssl/openssl/pem.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_ossl_dh.h>

/*******************************************************************************
 * DH OpenSSL compatibility API Testing
 ******************************************************************************/

int test_wolfSSL_DH(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_DH)
    DH *dh = NULL;
    BIGNUM* p;
    BIGNUM* q;
    BIGNUM* g;
    BIGNUM* pub = NULL;
    BIGNUM* priv = NULL;
#if defined(OPENSSL_ALL)
#if !defined(HAVE_FIPS) || \
        (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2))
    FILE* f = NULL;
    unsigned char buf[268];
    const unsigned char* pt = buf;
    long len = 0;

    dh = NULL;
    XMEMSET(buf, 0, sizeof(buf));
    /* Test 2048 bit parameters */
    ExpectTrue((f = XFOPEN("./certs/dh2048.der", "rb")) != XBADFILE);
    ExpectTrue((len = (long)XFREAD(buf, 1, sizeof(buf), f)) > 0);
    if (f != XBADFILE)
        XFCLOSE(f);

    ExpectNotNull(dh = d2i_DHparams(NULL, &pt, len));
    ExpectNotNull(dh->p);
    ExpectNotNull(dh->g);
    ExpectTrue(pt == buf);
    ExpectIntEQ(DH_generate_key(dh), 1);

    /* first, test for expected successful key agreement. */
    if (EXPECT_SUCCESS()) {
        DH *dh2 = NULL;
        unsigned char buf2[268];
        int sz1 = 0, sz2 = 0;

        ExpectNotNull(dh2 = d2i_DHparams(NULL, &pt, len));
        ExpectIntEQ(DH_generate_key(dh2), 1);

        ExpectIntGT(sz1=DH_compute_key(buf, dh2->pub_key, dh), 0);
        ExpectIntGT(sz2=DH_compute_key(buf2, dh->pub_key, dh2), 0);
        ExpectIntEQ(sz1, sz2);
        ExpectIntEQ(XMEMCMP(buf, buf2, (size_t)sz1), 0);

        ExpectIntNE(sz1 = DH_size(dh), 0);
        ExpectIntEQ(DH_compute_key_padded(buf, dh2->pub_key, dh), sz1);
        ExpectIntEQ(DH_compute_key_padded(buf2, dh->pub_key, dh2), sz1);
        ExpectIntEQ(XMEMCMP(buf, buf2, (size_t)sz1), 0);

        if (dh2 != NULL)
            DH_free(dh2);
    }

    ExpectIntEQ(DH_generate_key(dh), 1);
    ExpectIntEQ(DH_compute_key(NULL, NULL, NULL), -1);
    ExpectNotNull(pub = BN_new());
    ExpectIntEQ(BN_set_word(pub, 1), 1);
    ExpectIntEQ(DH_compute_key(buf, NULL, NULL), -1);
    ExpectIntEQ(DH_compute_key(NULL, pub, NULL), -1);
    ExpectIntEQ(DH_compute_key(NULL, NULL, dh), -1);
    ExpectIntEQ(DH_compute_key(buf, pub, NULL), -1);
    ExpectIntEQ(DH_compute_key(buf, NULL, dh), -1);
    ExpectIntEQ(DH_compute_key(NULL, pub, dh), -1);
    ExpectIntEQ(DH_compute_key(buf, pub, dh), -1);
    BN_free(pub);
    pub = NULL;

    DH_get0_pqg(dh, (const BIGNUM**)&p,
                    (const BIGNUM**)&q,
                    (const BIGNUM**)&g);
    ExpectPtrEq(p, dh->p);
    ExpectPtrEq(q, dh->q);
    ExpectPtrEq(g, dh->g);
    DH_get0_key(NULL, (const BIGNUM**)&pub, (const BIGNUM**)&priv);
    DH_get0_key(dh, (const BIGNUM**)&pub, (const BIGNUM**)&priv);
    ExpectPtrEq(pub, dh->pub_key);
    ExpectPtrEq(priv, dh->priv_key);
    DH_get0_key(dh, (const BIGNUM**)&pub, NULL);
    ExpectPtrEq(pub, dh->pub_key);
    DH_get0_key(dh, NULL, (const BIGNUM**)&priv);
    ExpectPtrEq(priv, dh->priv_key);
    pub = NULL;
    priv = NULL;
    ExpectNotNull(pub = BN_new());
    ExpectNotNull(priv = BN_new());
    ExpectIntEQ(DH_set0_key(NULL, pub, priv), 0);
    ExpectIntEQ(DH_set0_key(dh, pub, priv), 1);
    if (EXPECT_FAIL()) {
        BN_free(pub);
        BN_free(priv);
    }
    pub = NULL;
    priv = NULL;
    ExpectNotNull(pub = BN_new());
    ExpectIntEQ(DH_set0_key(dh, pub, NULL), 1);
    if (EXPECT_FAIL()) {
        BN_free(pub);
    }
    ExpectNotNull(priv = BN_new());
    ExpectIntEQ(DH_set0_key(dh, NULL, priv), 1);
    if (EXPECT_FAIL()) {
        BN_free(priv);
    }
    ExpectPtrEq(pub, dh->pub_key);
    ExpectPtrEq(priv, dh->priv_key);
    pub = NULL;
    priv = NULL;

    DH_free(dh);
    dh = NULL;

    ExpectNotNull(dh = DH_new());
    p = NULL;
    ExpectNotNull(p = BN_new());
    ExpectIntEQ(BN_set_word(p, 1), 1);
    ExpectIntEQ(DH_compute_key(buf, p, dh), -1);
    ExpectNotNull(pub = BN_new());
    ExpectNotNull(priv = BN_new());
    ExpectIntEQ(DH_set0_key(dh, pub, priv), 1);
    if (EXPECT_FAIL()) {
        BN_free(pub);
        BN_free(priv);
    }
    pub = NULL;
    priv = NULL;
    ExpectIntEQ(DH_compute_key(buf, p, dh), -1);
    BN_free(p);
    p = NULL;
    DH_free(dh);
    dh = NULL;

#ifdef WOLFSSL_KEY_GEN
    ExpectNotNull(dh = DH_generate_parameters(2048, 2, NULL, NULL));
    ExpectIntEQ(wolfSSL_DH_generate_parameters_ex(NULL, 2048, 2, NULL), 0);
    DH_free(dh);
    dh = NULL;
#endif
#endif /* !HAVE_FIPS || (HAVE_FIPS_VERSION && HAVE_FIPS_VERSION > 2) */
#endif /* OPENSSL_ALL */

    (void)dh;
    (void)p;
    (void)q;
    (void)g;
    (void)pub;
    (void)priv;

    ExpectNotNull(dh = wolfSSL_DH_new());

    /* invalid parameters test */
    DH_get0_pqg(NULL, (const BIGNUM**)&p,
                      (const BIGNUM**)&q,
                      (const BIGNUM**)&g);

    DH_get0_pqg(dh, NULL,
                    (const BIGNUM**)&q,
                    (const BIGNUM**)&g);

    DH_get0_pqg(dh, NULL, NULL, (const BIGNUM**)&g);

    DH_get0_pqg(dh, NULL, NULL, NULL);

    DH_get0_pqg(dh, (const BIGNUM**)&p,
                    (const BIGNUM**)&q,
                    (const BIGNUM**)&g);

    ExpectPtrEq(p, NULL);
    ExpectPtrEq(q, NULL);
    ExpectPtrEq(g, NULL);
    DH_free(dh);
    dh = NULL;

#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS) && !defined(WOLFSSL_DH_EXTRA)) \
 || (defined(HAVE_FIPS_VERSION) && FIPS_VERSION_GT(2,0))
#if defined(OPENSSL_ALL) || \
    defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L
    dh = wolfSSL_DH_new();
    ExpectNotNull(dh);
    p = wolfSSL_BN_new();
    ExpectNotNull(p);
    ExpectIntEQ(BN_set_word(p, 11), 1);
    g = wolfSSL_BN_new();
    ExpectNotNull(g);
    ExpectIntEQ(BN_set_word(g, 2), 1);
    q = wolfSSL_BN_new();
    ExpectNotNull(q);
    ExpectIntEQ(BN_set_word(q, 5), 1);
    ExpectIntEQ(wolfSSL_DH_set0_pqg(NULL, NULL, NULL, NULL), 0);
    ExpectIntEQ(wolfSSL_DH_set0_pqg(dh, NULL, NULL, NULL), 0);
    ExpectIntEQ(wolfSSL_DH_set0_pqg(NULL, p, NULL, NULL), 0);
    ExpectIntEQ(wolfSSL_DH_set0_pqg(NULL, NULL, q, NULL), 0);
    ExpectIntEQ(wolfSSL_DH_set0_pqg(NULL, NULL, NULL, g), 0);
    ExpectIntEQ(wolfSSL_DH_set0_pqg(NULL, p, q, g), 0);
    ExpectIntEQ(wolfSSL_DH_set0_pqg(dh, NULL, q, g), 0);
    ExpectIntEQ(wolfSSL_DH_set0_pqg(dh, p, q, NULL), 0);
    /* Don't need q. */
    ExpectIntEQ(wolfSSL_DH_set0_pqg(dh, p, NULL, g), 1);
    if (EXPECT_FAIL()) {
        BN_free(p);
        BN_free(g);
    }
    p = NULL;
    g = NULL;
    /* Setting again will free the p and g. */
    wolfSSL_BN_free(q);
    q = NULL;
    DH_free(dh);
    dh = NULL;

    dh = wolfSSL_DH_new();
    ExpectNotNull(dh);

    p = wolfSSL_BN_new();
    ExpectNotNull(p);
    ExpectIntEQ(BN_set_word(p, 11), 1);
    g = wolfSSL_BN_new();
    ExpectNotNull(g);
    ExpectIntEQ(BN_set_word(g, 2), 1);
    q = wolfSSL_BN_new();
    ExpectNotNull(q);
    ExpectIntEQ(BN_set_word(q, 5), 1);
    ExpectIntEQ(wolfSSL_DH_set0_pqg(dh, p, q, g), 1);
    /* p, q and g are now owned by dh - don't free. */
    if (EXPECT_FAIL()) {
        BN_free(p);
        BN_free(q);
        BN_free(g);
    }
    p = NULL;
    q = NULL;
    g = NULL;

    p = wolfSSL_BN_new();
    ExpectNotNull(p);
    ExpectIntEQ(BN_set_word(p, 11), 1);
    g = wolfSSL_BN_new();
    ExpectNotNull(g);
    ExpectIntEQ(BN_set_word(g, 2), 1);
    q = wolfSSL_BN_new();
    ExpectNotNull(q);
    ExpectIntEQ(wolfSSL_DH_set0_pqg(dh, p, NULL, NULL), 1);
    if (EXPECT_FAIL()) {
        BN_free(p);
    }
    p = NULL;
    ExpectIntEQ(wolfSSL_DH_set0_pqg(dh, NULL, q, NULL), 1);
    if (EXPECT_FAIL()) {
        BN_free(q);
    }
    q = NULL;
    ExpectIntEQ(wolfSSL_DH_set0_pqg(dh, NULL, NULL, g), 1);
    if (EXPECT_FAIL()) {
        BN_free(g);
    }
    g = NULL;
    ExpectIntEQ(wolfSSL_DH_set0_pqg(dh, NULL, NULL, NULL), 1);
    /* p, q and g are now owned by dh - don't free. */

    DH_free(dh);
    dh = NULL;

    ExpectIntEQ(DH_generate_key(NULL), 0);
    ExpectNotNull(dh = DH_new());
    ExpectIntEQ(DH_generate_key(dh), 0);
    p = wolfSSL_BN_new();
    ExpectNotNull(p);
    ExpectIntEQ(BN_set_word(p, 0), 1);
    g = wolfSSL_BN_new();
    ExpectNotNull(g);
    ExpectIntEQ(BN_set_word(g, 2), 1);
    ExpectIntEQ(wolfSSL_DH_set0_pqg(dh, p, NULL, g), 1);
    if (EXPECT_FAIL()) {
        BN_free(p);
        BN_free(g);
    }
    p = NULL;
    g = NULL;
    ExpectIntEQ(DH_generate_key(dh), 0);
    DH_free(dh);
    dh = NULL;
#endif
#endif

    /* Test DH_up_ref() */
    dh = wolfSSL_DH_new();
    ExpectNotNull(dh);
    ExpectIntEQ(wolfSSL_DH_up_ref(NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_DH_up_ref(dh), WOLFSSL_SUCCESS);
    DH_free(dh); /* decrease ref count */
    DH_free(dh); /* free WOLFSSL_DH */
    dh = NULL;
    q = NULL;

    ExpectNull((dh = DH_new_by_nid(NID_sha1)));
#if (defined(HAVE_PUBLIC_FFDHE) || (defined(HAVE_FIPS) && \
    FIPS_VERSION_EQ(2,0))) || (!defined(HAVE_PUBLIC_FFDHE) && \
    (!defined(HAVE_FIPS) || FIPS_VERSION_GT(2,0)))
#ifdef HAVE_FFDHE_2048
    ExpectNotNull((dh = DH_new_by_nid(NID_ffdhe2048)));
    DH_free(dh);
    dh = NULL;
    q = NULL;
#endif
#ifdef HAVE_FFDHE_3072
    ExpectNotNull((dh = DH_new_by_nid(NID_ffdhe3072)));
    DH_free(dh);
    dh = NULL;
    q = NULL;
#endif
#ifdef HAVE_FFDHE_4096
    ExpectNotNull((dh = DH_new_by_nid(NID_ffdhe4096)));
    DH_free(dh);
    dh = NULL;
    q = NULL;
#endif
#else
    ExpectNull((dh = DH_new_by_nid(NID_ffdhe2048)));
#endif /* (HAVE_PUBLIC_FFDHE || (HAVE_FIPS && HAVE_FIPS_VERSION == 2)) ||
        * (!HAVE_PUBLIC_FFDHE && (!HAVE_FIPS || HAVE_FIPS_VERSION > 2))*/

    ExpectIntEQ(wolfSSL_DH_size(NULL), -1);
#endif /* OPENSSL_EXTRA && !NO_DH */
    return EXPECT_RESULT();
}

int test_wolfSSL_DH_dup(void)
{
    EXPECT_DECLS;
#if !defined(NO_DH) && defined(WOLFSSL_DH_EXTRA)
#if defined(WOLFSSL_QT) || defined(OPENSSL_ALL) || defined(WOLFSSL_OPENSSH) || \
    defined(OPENSSL_EXTRA)
    DH *dh = NULL;
    DH *dhDup = NULL;

    ExpectNotNull(dh = wolfSSL_DH_new());

    ExpectNull(dhDup = wolfSSL_DH_dup(NULL));
    ExpectNull(dhDup = wolfSSL_DH_dup(dh));

#if defined(OPENSSL_ALL) || \
    defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L
    {
        WOLFSSL_BIGNUM* p = NULL;
        WOLFSSL_BIGNUM* g = NULL;

        ExpectNotNull(p = wolfSSL_BN_new());
        ExpectNotNull(g = wolfSSL_BN_new());
        ExpectIntEQ(wolfSSL_BN_set_word(p, 11), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_BN_set_word(g, 2), WOLFSSL_SUCCESS);

        ExpectIntEQ(wolfSSL_DH_set0_pqg(dh, p, NULL, g), 1);
        if (EXPECT_FAIL()) {
            wolfSSL_BN_free(p);
            wolfSSL_BN_free(g);
        }

        ExpectNotNull(dhDup = wolfSSL_DH_dup(dh));
        wolfSSL_DH_free(dhDup);
    }
#endif

    wolfSSL_DH_free(dh);
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_DH_check(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_ALL
#ifndef NO_DH
#ifndef NO_BIO
#ifndef NO_DSA
    byte buf[6000];
    char file[] = "./certs/dsaparams.pem";
    XFILE f = XBADFILE;
    int  bytes = 0;
    BIO* bio = NULL;
    DSA* dsa = NULL;
#elif !defined(HAVE_FIPS) || FIPS_VERSION_GT(2,0)
    static const byte dh2048[] = {
        0x30, 0x82, 0x01, 0x08, 0x02, 0x82, 0x01, 0x01,
        0x00, 0xb0, 0xa1, 0x08, 0x06, 0x9c, 0x08, 0x13,
        0xba, 0x59, 0x06, 0x3c, 0xbc, 0x30, 0xd5, 0xf5,
        0x00, 0xc1, 0x4f, 0x44, 0xa7, 0xd6, 0xef, 0x4a,
        0xc6, 0x25, 0x27, 0x1c, 0xe8, 0xd2, 0x96, 0x53,
        0x0a, 0x5c, 0x91, 0xdd, 0xa2, 0xc2, 0x94, 0x84,
        0xbf, 0x7d, 0xb2, 0x44, 0x9f, 0x9b, 0xd2, 0xc1,
        0x8a, 0xc5, 0xbe, 0x72, 0x5c, 0xa7, 0xe7, 0x91,
        0xe6, 0xd4, 0x9f, 0x73, 0x07, 0x85, 0x5b, 0x66,
        0x48, 0xc7, 0x70, 0xfa, 0xb4, 0xee, 0x02, 0xc9,
        0x3d, 0x9a, 0x4a, 0xda, 0x3d, 0xc1, 0x46, 0x3e,
        0x19, 0x69, 0xd1, 0x17, 0x46, 0x07, 0xa3, 0x4d,
        0x9f, 0x2b, 0x96, 0x17, 0x39, 0x6d, 0x30, 0x8d,
        0x2a, 0xf3, 0x94, 0xd3, 0x75, 0xcf, 0xa0, 0x75,
        0xe6, 0xf2, 0x92, 0x1f, 0x1a, 0x70, 0x05, 0xaa,
        0x04, 0x83, 0x57, 0x30, 0xfb, 0xda, 0x76, 0x93,
        0x38, 0x50, 0xe8, 0x27, 0xfd, 0x63, 0xee, 0x3c,
        0xe5, 0xb7, 0xc8, 0x09, 0xae, 0x6f, 0x50, 0x35,
        0x8e, 0x84, 0xce, 0x4a, 0x00, 0xe9, 0x12, 0x7e,
        0x5a, 0x31, 0xd7, 0x33, 0xfc, 0x21, 0x13, 0x76,
        0xcc, 0x16, 0x30, 0xdb, 0x0c, 0xfc, 0xc5, 0x62,
        0xa7, 0x35, 0xb8, 0xef, 0xb7, 0xb0, 0xac, 0xc0,
        0x36, 0xf6, 0xd9, 0xc9, 0x46, 0x48, 0xf9, 0x40,
        0x90, 0x00, 0x2b, 0x1b, 0xaa, 0x6c, 0xe3, 0x1a,
        0xc3, 0x0b, 0x03, 0x9e, 0x1b, 0xc2, 0x46, 0xe4,
        0x48, 0x4e, 0x22, 0x73, 0x6f, 0xc3, 0x5f, 0xd4,
        0x9a, 0xd6, 0x30, 0x07, 0x48, 0xd6, 0x8c, 0x90,
        0xab, 0xd4, 0xf6, 0xf1, 0xe3, 0x48, 0xd3, 0x58,
        0x4b, 0xa6, 0xb9, 0xcd, 0x29, 0xbf, 0x68, 0x1f,
        0x08, 0x4b, 0x63, 0x86, 0x2f, 0x5c, 0x6b, 0xd6,
        0xb6, 0x06, 0x65, 0xf7, 0xa6, 0xdc, 0x00, 0x67,
        0x6b, 0xbb, 0xc3, 0xa9, 0x41, 0x83, 0xfb, 0xc7,
        0xfa, 0xc8, 0xe2, 0x1e, 0x7e, 0xaf, 0x00, 0x3f,
        0x93, 0x02, 0x01, 0x02
    };
    const byte* params;
#endif
    DH*  dh = NULL;
    WOLFSSL_BIGNUM* p = NULL;
    WOLFSSL_BIGNUM* g = NULL;
    WOLFSSL_BIGNUM* pTmp = NULL;
    WOLFSSL_BIGNUM* gTmp = NULL;
    int codes = -1;

#ifndef NO_DSA
    /* Initialize DH */
    ExpectTrue((f = XFOPEN(file, "rb")) != XBADFILE);
    ExpectIntGT(bytes = (int)XFREAD(buf, 1, sizeof(buf), f), 0);
    if (f != XBADFILE)
        XFCLOSE(f);

    ExpectNotNull(bio = BIO_new_mem_buf((void*)buf, bytes));

    ExpectNotNull(dsa = wolfSSL_PEM_read_bio_DSAparams(bio, NULL, NULL, NULL));

    ExpectNotNull(dh = wolfSSL_DSA_dup_DH(dsa));
    ExpectNotNull(dh);

    BIO_free(bio);
    DSA_free(dsa);
#elif !defined(HAVE_FIPS) || FIPS_VERSION_GT(2,0)
    params = dh2048;
    ExpectNotNull(dh = wolfSSL_d2i_DHparams(NULL, &params,
        (long)sizeof(dh2048)));
#else
    ExpectNotNull(dh = wolfSSL_DH_new_by_nid(NID_ffdhe2048));
#endif

    /* Test assumed to be valid dh.
     * Should return WOLFSSL_SUCCESS
     * codes should be 0
     * Invalid codes = {DH_NOT_SUITABLE_GENERATOR, DH_CHECK_P_NOT_PRIME}
     */
    ExpectIntEQ(wolfSSL_DH_check(dh, &codes), 1);
    ExpectIntEQ(codes, 0);

    /* Test NULL dh: expected BAD_FUNC_ARG */
    ExpectIntEQ(wolfSSL_DH_check(NULL, &codes), 0);

    /* Break dh prime to test if codes = DH_CHECK_P_NOT_PRIME */
    if (dh != NULL) {
        pTmp = dh->p;
        dh->p  = NULL;
    }
    ExpectIntEQ(wolfSSL_DH_check(dh, &codes), 1);
    ExpectIntEQ(wolfSSL_DH_check(dh, NULL), 0);
    ExpectIntEQ(codes, DH_CHECK_P_NOT_PRIME);
    /* set dh->p back to normal so it won't fail on next tests */
    if (dh != NULL) {
        dh->p = pTmp;
        pTmp = NULL;
    }

    /* Break dh generator to test if codes = DH_NOT_SUITABLE_GENERATOR */
    if (dh != NULL) {
        gTmp = dh->g;
        dh->g = NULL;
    }
    ExpectIntEQ(wolfSSL_DH_check(dh, &codes), 1);
    ExpectIntEQ(wolfSSL_DH_check(dh, NULL), 0);
    ExpectIntEQ(codes, DH_NOT_SUITABLE_GENERATOR);
    if (dh != NULL) {
        dh->g = gTmp;
        gTmp = NULL;
    }

    /* Cleanup */
    DH_free(dh);
    dh = NULL;

    dh = DH_new();
    ExpectNotNull(dh);
    /* Check empty DH. */
    ExpectIntEQ(wolfSSL_DH_check(dh, &codes), 1);
    ExpectIntEQ(wolfSSL_DH_check(dh, NULL), 0);
    ExpectIntEQ(codes, DH_NOT_SUITABLE_GENERATOR | DH_CHECK_P_NOT_PRIME);
    /* Check non-prime valued p. */
    ExpectNotNull(p = BN_new());
    ExpectIntEQ(BN_set_word(p, 4), 1);
    ExpectNotNull(g = BN_new());
    ExpectIntEQ(BN_set_word(g, 2), 1);
    ExpectIntEQ(DH_set0_pqg(dh, p, NULL, g), 1);
    if (EXPECT_FAIL()) {
        wolfSSL_BN_free(p);
        wolfSSL_BN_free(g);
    }
    ExpectIntEQ(wolfSSL_DH_check(dh, &codes), 1);
    ExpectIntEQ(wolfSSL_DH_check(dh, NULL), 0);
    ExpectIntEQ(codes, DH_CHECK_P_NOT_PRIME);
    DH_free(dh);
    dh = NULL;
#endif
#endif /* !NO_DH  && !NO_DSA */
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_DH_prime(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_DH)
    WOLFSSL_BIGNUM* bn = NULL;
#if WOLFSSL_MAX_BN_BITS >= 768
    WOLFSSL_BIGNUM* bn2 = NULL;
#endif

    bn = wolfSSL_DH_768_prime(NULL);
#if WOLFSSL_MAX_BN_BITS >= 768
    ExpectNotNull(bn);
    bn2 = wolfSSL_DH_768_prime(bn);
    ExpectNotNull(bn2);
    ExpectTrue(bn == bn2);
    wolfSSL_BN_free(bn);
    bn = NULL;
#else
    ExpectNull(bn);
#endif

    bn = wolfSSL_DH_1024_prime(NULL);
#if WOLFSSL_MAX_BN_BITS >= 1024
    ExpectNotNull(bn);
    wolfSSL_BN_free(bn);
    bn = NULL;
#else
    ExpectNull(bn);
#endif
    bn = wolfSSL_DH_2048_prime(NULL);
#if WOLFSSL_MAX_BN_BITS >= 2048
    ExpectNotNull(bn);
    wolfSSL_BN_free(bn);
    bn = NULL;
#else
    ExpectNull(bn);
#endif
    bn = wolfSSL_DH_3072_prime(NULL);
#if WOLFSSL_MAX_BN_BITS >= 3072
    ExpectNotNull(bn);
    wolfSSL_BN_free(bn);
    bn = NULL;
#else
    ExpectNull(bn);
#endif
    bn = wolfSSL_DH_4096_prime(NULL);
#if WOLFSSL_MAX_BN_BITS >= 4096
    ExpectNotNull(bn);
    wolfSSL_BN_free(bn);
    bn = NULL;
#else
    ExpectNull(bn);
#endif
    bn = wolfSSL_DH_6144_prime(NULL);
#if WOLFSSL_MAX_BN_BITS >= 6144
    ExpectNotNull(bn);
    wolfSSL_BN_free(bn);
    bn = NULL;
#else
    ExpectNull(bn);
#endif
    bn = wolfSSL_DH_8192_prime(NULL);
#if WOLFSSL_MAX_BN_BITS >= 8192
    ExpectNotNull(bn);
    wolfSSL_BN_free(bn);
    bn = NULL;
#else
    ExpectNull(bn);
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_DH_1536_prime(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_DH)
    BIGNUM* bn = NULL;
    unsigned char bits[200];
    int sz = 192; /* known binary size */
    const byte expected[] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xC9,0x0F,0xDA,0xA2,0x21,0x68,0xC2,0x34,
        0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1,
        0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,
        0x02,0x0B,0xBE,0xA6,0x3B,0x13,0x9B,0x22,
        0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
        0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B,
        0x30,0x2B,0x0A,0x6D,0xF2,0x5F,0x14,0x37,
        0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45,
        0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,
        0xF4,0x4C,0x42,0xE9,0xA6,0x37,0xED,0x6B,
        0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,
        0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5,
        0xAE,0x9F,0x24,0x11,0x7C,0x4B,0x1F,0xE6,
        0x49,0x28,0x66,0x51,0xEC,0xE4,0x5B,0x3D,
        0xC2,0x00,0x7C,0xB8,0xA1,0x63,0xBF,0x05,
        0x98,0xDA,0x48,0x36,0x1C,0x55,0xD3,0x9A,
        0x69,0x16,0x3F,0xA8,0xFD,0x24,0xCF,0x5F,
        0x83,0x65,0x5D,0x23,0xDC,0xA3,0xAD,0x96,
        0x1C,0x62,0xF3,0x56,0x20,0x85,0x52,0xBB,
        0x9E,0xD5,0x29,0x07,0x70,0x96,0x96,0x6D,
        0x67,0x0C,0x35,0x4E,0x4A,0xBC,0x98,0x04,
        0xF1,0x74,0x6C,0x08,0xCA,0x23,0x73,0x27,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    };

    ExpectNotNull(bn = get_rfc3526_prime_1536(NULL));
    ExpectIntEQ(sz, BN_bn2bin((const BIGNUM*)bn, bits));
    ExpectIntEQ(0, XMEMCMP(expected, bits, sz));

    BN_free(bn);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_DH_get_2048_256(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_DH)
    WOLFSSL_DH* dh = NULL;
    const WOLFSSL_BIGNUM* pBn;
    const WOLFSSL_BIGNUM* gBn;
    const WOLFSSL_BIGNUM* qBn;
    const byte pExpected[] = {
        0x87, 0xA8, 0xE6, 0x1D, 0xB4, 0xB6, 0x66, 0x3C, 0xFF, 0xBB, 0xD1, 0x9C,
        0x65, 0x19, 0x59, 0x99, 0x8C, 0xEE, 0xF6, 0x08, 0x66, 0x0D, 0xD0, 0xF2,
        0x5D, 0x2C, 0xEE, 0xD4, 0x43, 0x5E, 0x3B, 0x00, 0xE0, 0x0D, 0xF8, 0xF1,
        0xD6, 0x19, 0x57, 0xD4, 0xFA, 0xF7, 0xDF, 0x45, 0x61, 0xB2, 0xAA, 0x30,
        0x16, 0xC3, 0xD9, 0x11, 0x34, 0x09, 0x6F, 0xAA, 0x3B, 0xF4, 0x29, 0x6D,
        0x83, 0x0E, 0x9A, 0x7C, 0x20, 0x9E, 0x0C, 0x64, 0x97, 0x51, 0x7A, 0xBD,
        0x5A, 0x8A, 0x9D, 0x30, 0x6B, 0xCF, 0x67, 0xED, 0x91, 0xF9, 0xE6, 0x72,
        0x5B, 0x47, 0x58, 0xC0, 0x22, 0xE0, 0xB1, 0xEF, 0x42, 0x75, 0xBF, 0x7B,
        0x6C, 0x5B, 0xFC, 0x11, 0xD4, 0x5F, 0x90, 0x88, 0xB9, 0x41, 0xF5, 0x4E,
        0xB1, 0xE5, 0x9B, 0xB8, 0xBC, 0x39, 0xA0, 0xBF, 0x12, 0x30, 0x7F, 0x5C,
        0x4F, 0xDB, 0x70, 0xC5, 0x81, 0xB2, 0x3F, 0x76, 0xB6, 0x3A, 0xCA, 0xE1,
        0xCA, 0xA6, 0xB7, 0x90, 0x2D, 0x52, 0x52, 0x67, 0x35, 0x48, 0x8A, 0x0E,
        0xF1, 0x3C, 0x6D, 0x9A, 0x51, 0xBF, 0xA4, 0xAB, 0x3A, 0xD8, 0x34, 0x77,
        0x96, 0x52, 0x4D, 0x8E, 0xF6, 0xA1, 0x67, 0xB5, 0xA4, 0x18, 0x25, 0xD9,
        0x67, 0xE1, 0x44, 0xE5, 0x14, 0x05, 0x64, 0x25, 0x1C, 0xCA, 0xCB, 0x83,
        0xE6, 0xB4, 0x86, 0xF6, 0xB3, 0xCA, 0x3F, 0x79, 0x71, 0x50, 0x60, 0x26,
        0xC0, 0xB8, 0x57, 0xF6, 0x89, 0x96, 0x28, 0x56, 0xDE, 0xD4, 0x01, 0x0A,
        0xBD, 0x0B, 0xE6, 0x21, 0xC3, 0xA3, 0x96, 0x0A, 0x54, 0xE7, 0x10, 0xC3,
        0x75, 0xF2, 0x63, 0x75, 0xD7, 0x01, 0x41, 0x03, 0xA4, 0xB5, 0x43, 0x30,
        0xC1, 0x98, 0xAF, 0x12, 0x61, 0x16, 0xD2, 0x27, 0x6E, 0x11, 0x71, 0x5F,
        0x69, 0x38, 0x77, 0xFA, 0xD7, 0xEF, 0x09, 0xCA, 0xDB, 0x09, 0x4A, 0xE9,
        0x1E, 0x1A, 0x15, 0x97
    };
    const byte gExpected[] = {
        0x3F, 0xB3, 0x2C, 0x9B, 0x73, 0x13, 0x4D, 0x0B, 0x2E, 0x77, 0x50, 0x66,
        0x60, 0xED, 0xBD, 0x48, 0x4C, 0xA7, 0xB1, 0x8F, 0x21, 0xEF, 0x20, 0x54,
        0x07, 0xF4, 0x79, 0x3A, 0x1A, 0x0B, 0xA1, 0x25, 0x10, 0xDB, 0xC1, 0x50,
        0x77, 0xBE, 0x46, 0x3F, 0xFF, 0x4F, 0xED, 0x4A, 0xAC, 0x0B, 0xB5, 0x55,
        0xBE, 0x3A, 0x6C, 0x1B, 0x0C, 0x6B, 0x47, 0xB1, 0xBC, 0x37, 0x73, 0xBF,
        0x7E, 0x8C, 0x6F, 0x62, 0x90, 0x12, 0x28, 0xF8, 0xC2, 0x8C, 0xBB, 0x18,
        0xA5, 0x5A, 0xE3, 0x13, 0x41, 0x00, 0x0A, 0x65, 0x01, 0x96, 0xF9, 0x31,
        0xC7, 0x7A, 0x57, 0xF2, 0xDD, 0xF4, 0x63, 0xE5, 0xE9, 0xEC, 0x14, 0x4B,
        0x77, 0x7D, 0xE6, 0x2A, 0xAA, 0xB8, 0xA8, 0x62, 0x8A, 0xC3, 0x76, 0xD2,
        0x82, 0xD6, 0xED, 0x38, 0x64, 0xE6, 0x79, 0x82, 0x42, 0x8E, 0xBC, 0x83,
        0x1D, 0x14, 0x34, 0x8F, 0x6F, 0x2F, 0x91, 0x93, 0xB5, 0x04, 0x5A, 0xF2,
        0x76, 0x71, 0x64, 0xE1, 0xDF, 0xC9, 0x67, 0xC1, 0xFB, 0x3F, 0x2E, 0x55,
        0xA4, 0xBD, 0x1B, 0xFF, 0xE8, 0x3B, 0x9C, 0x80, 0xD0, 0x52, 0xB9, 0x85,
        0xD1, 0x82, 0xEA, 0x0A, 0xDB, 0x2A, 0x3B, 0x73, 0x13, 0xD3, 0xFE, 0x14,
        0xC8, 0x48, 0x4B, 0x1E, 0x05, 0x25, 0x88, 0xB9, 0xB7, 0xD2, 0xBB, 0xD2,
        0xDF, 0x01, 0x61, 0x99, 0xEC, 0xD0, 0x6E, 0x15, 0x57, 0xCD, 0x09, 0x15,
        0xB3, 0x35, 0x3B, 0xBB, 0x64, 0xE0, 0xEC, 0x37, 0x7F, 0xD0, 0x28, 0x37,
        0x0D, 0xF9, 0x2B, 0x52, 0xC7, 0x89, 0x14, 0x28, 0xCD, 0xC6, 0x7E, 0xB6,
        0x18, 0x4B, 0x52, 0x3D, 0x1D, 0xB2, 0x46, 0xC3, 0x2F, 0x63, 0x07, 0x84,
        0x90, 0xF0, 0x0E, 0xF8, 0xD6, 0x47, 0xD1, 0x48, 0xD4, 0x79, 0x54, 0x51,
        0x5E, 0x23, 0x27, 0xCF, 0xEF, 0x98, 0xC5, 0x82, 0x66, 0x4B, 0x4C, 0x0F,
        0x6C, 0xC4, 0x16, 0x59
    };
    const byte qExpected[] = {
        0x8C, 0xF8, 0x36, 0x42, 0xA7, 0x09, 0xA0, 0x97, 0xB4, 0x47, 0x99, 0x76,
        0x40, 0x12, 0x9D, 0xA2, 0x99, 0xB1, 0xA4, 0x7D, 0x1E, 0xB3, 0x75, 0x0B,
        0xA3, 0x08, 0xB0, 0xFE, 0x64, 0xF5, 0xFB, 0xD3
    };
    int pSz = 0;
    int qSz = 0;
    int gSz = 0;
    byte* pReturned = NULL;
    byte* qReturned = NULL;
    byte* gReturned = NULL;

    ExpectNotNull((dh = wolfSSL_DH_get_2048_256()));
    wolfSSL_DH_get0_pqg(dh, &pBn, &qBn, &gBn);

    ExpectIntGT((pSz = wolfSSL_BN_num_bytes(pBn)), 0);
    ExpectNotNull(pReturned = (byte*)XMALLOC(pSz, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    ExpectIntGT((pSz = wolfSSL_BN_bn2bin(pBn, pReturned)), 0);
    ExpectIntEQ(pSz, sizeof(pExpected));
    ExpectIntEQ(XMEMCMP(pExpected, pReturned, pSz), 0);

    ExpectIntGT((qSz = wolfSSL_BN_num_bytes(qBn)), 0);
    ExpectNotNull(qReturned = (byte*)XMALLOC(qSz, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    ExpectIntGT((qSz = wolfSSL_BN_bn2bin(qBn, qReturned)), 0);
    ExpectIntEQ(qSz, sizeof(qExpected));
    ExpectIntEQ(XMEMCMP(qExpected, qReturned, qSz), 0);

    ExpectIntGT((gSz = wolfSSL_BN_num_bytes(gBn)), 0);
    ExpectNotNull(gReturned = (byte*)XMALLOC(gSz, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    ExpectIntGT((gSz = wolfSSL_BN_bn2bin(gBn, gReturned)), 0);
    ExpectIntEQ(gSz, sizeof(gExpected));
    ExpectIntEQ(XMEMCMP(gExpected, gReturned, gSz), 0);

    wolfSSL_DH_free(dh);
    XFREE(pReturned, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(gReturned, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(qReturned, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_PEM_read_DHparams(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_DH) && defined(WOLFSSL_DH_EXTRA) && \
    !defined(NO_FILESYSTEM)
    DH* dh = NULL;
    XFILE fp = XBADFILE;
    unsigned char derOut[300];
    unsigned char* derOutBuf = derOut;
    int derOutSz = 0;

    unsigned char derExpected[300];
    int derExpectedSz = 0;

    XMEMSET(derOut, 0, sizeof(derOut));
    XMEMSET(derExpected, 0, sizeof(derExpected));

    /* open DH param file, read into DH struct */
    ExpectTrue((fp = XFOPEN(dhParamFile, "rb")) != XBADFILE);

    /* bad args */
    ExpectNull(dh = PEM_read_DHparams(NULL, &dh, NULL, NULL));
    ExpectNull(dh = PEM_read_DHparams(NULL, NULL, NULL, NULL));

    /* good args */
    ExpectNotNull(dh = PEM_read_DHparams(fp, &dh, NULL, NULL));
    if (fp != XBADFILE) {
        XFCLOSE(fp);
        fp = XBADFILE;
    }

    /* read in certs/dh2048.der for comparison against exported params */
    ExpectTrue((fp = XFOPEN("./certs/dh2048.der", "rb")) != XBADFILE);
    ExpectIntGT(derExpectedSz = (int)XFREAD(derExpected, 1, sizeof(derExpected),
        fp), 0);
    if (fp != XBADFILE) {
        XFCLOSE(fp);
        fp = XBADFILE;
    }

    /* export DH back to DER and compare */
    derOutSz = wolfSSL_i2d_DHparams(dh, &derOutBuf);
    ExpectIntEQ(derOutSz, derExpectedSz);
    ExpectIntEQ(XMEMCMP(derOut, derExpected, derOutSz), 0);

    DH_free(dh);
    dh = NULL;

    /* Test parsing with X9.42 header */
    ExpectTrue((fp = XFOPEN("./certs/x942dh2048.pem", "rb")) != XBADFILE);
    ExpectNotNull(dh = PEM_read_DHparams(fp, &dh, NULL, NULL));
    if (fp != XBADFILE)
        XFCLOSE(fp);

    DH_free(dh);
    dh = NULL;
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_PEM_write_DHparams(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_BIO) && \
    !defined(NO_DH) && defined(WOLFSSL_DH_EXTRA) && !defined(NO_FILESYSTEM)
    DH* dh = NULL;
    BIO* bio = NULL;
    XFILE fp = XBADFILE;
    byte pem[2048];
    int  pemSz = 0;
    const char expected[] =
        "-----BEGIN DH PARAMETERS-----\n"
        "MIIBCAKCAQEAsKEIBpwIE7pZBjy8MNX1AMFPRKfW70rGJScc6NKWUwpckd2iwpSE\n"
        "v32yRJ+b0sGKxb5yXKfnkebUn3MHhVtmSMdw+rTuAsk9mkraPcFGPhlp0RdGB6NN\n"
        "nyuWFzltMI0q85TTdc+gdebykh8acAWqBINXMPvadpM4UOgn/WPuPOW3yAmub1A1\n"
        "joTOSgDpEn5aMdcz/CETdswWMNsM/MVipzW477ewrMA29tnJRkj5QJAAKxuqbOMa\n"
        "wwsDnhvCRuRITiJzb8Nf1JrWMAdI1oyQq9T28eNI01hLprnNKb9oHwhLY4YvXGvW\n"
        "tgZl96bcAGdru8OpQYP7x/rI4h5+rwA/kwIBAg==\n"
        "-----END DH PARAMETERS-----\n";
    const char badPem[] =
        "-----BEGIN DH PARAMETERS-----\n"
        "-----END DH PARAMETERS-----\n";
    const char emptySeqPem[] =
        "-----BEGIN DH PARAMETERS-----\n"
        "MAA=\n"
        "-----END DH PARAMETERS-----\n";

    ExpectTrue((fp = XFOPEN(dhParamFile, "rb")) != XBADFILE);
    ExpectIntGT((pemSz = (int)XFREAD(pem, 1, sizeof(pem), fp)), 0);
    if (fp != XBADFILE) {
        XFCLOSE(fp);
        fp = XBADFILE;
    }

    ExpectNull(PEM_read_bio_DHparams(NULL, NULL, NULL, NULL));

    ExpectNotNull(bio = BIO_new(BIO_s_mem()));
    ExpectNull(dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL));
    ExpectIntEQ(BIO_write(bio, badPem, (int)sizeof(badPem)),
        (int)sizeof(badPem));
    ExpectNull(dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL));
    BIO_free(bio);
    bio = NULL;

    ExpectNotNull(bio = BIO_new(BIO_s_mem()));
    ExpectNull(dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL));
    ExpectIntEQ(BIO_write(bio, emptySeqPem, (int)sizeof(emptySeqPem)),
        (int)sizeof(emptySeqPem));
    ExpectNull(dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL));
    BIO_free(bio);
    bio = NULL;

    ExpectNotNull(bio = BIO_new(BIO_s_mem()));
    ExpectIntEQ(BIO_write(bio, pem, pemSz), pemSz);
    ExpectNotNull(dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL));
    BIO_free(bio);
    bio = NULL;

    ExpectNotNull(fp = XFOPEN("./test-write-dhparams.pem", "wb"));
    ExpectIntEQ(PEM_write_DHparams(fp, dh), WOLFSSL_SUCCESS);
    ExpectIntEQ(PEM_write_DHparams(fp, NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    DH_free(dh);
    dh = NULL;

    dh = wolfSSL_DH_new();
    ExpectIntEQ(PEM_write_DHparams(fp, dh), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    if (fp != XBADFILE) {
        XFCLOSE(fp);
        fp = XBADFILE;
    }
    wolfSSL_DH_free(dh);
    dh = NULL;

    /* check results */
    XMEMSET(pem, 0, sizeof(pem));
    ExpectTrue((fp = XFOPEN("./test-write-dhparams.pem", "rb")) != XBADFILE);
    ExpectIntGT((pemSz = (int)XFREAD(pem, 1, sizeof(pem), fp)), 0);
    ExpectIntEQ(XMEMCMP(pem, expected, pemSz), 0);
    if (fp != XBADFILE)
        XFCLOSE(fp);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_d2i_DHparams(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_ALL
#if !defined(NO_DH) && (defined(HAVE_FFDHE_2048) || defined(HAVE_FFDHE_3072))
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
    XFILE f = XBADFILE;
    unsigned char buf[4096];
    const unsigned char* pt = buf;
#ifdef HAVE_FFDHE_2048
    const char* params1 = "./certs/dh2048.der";
#endif
#ifdef HAVE_FFDHE_3072
    const char* params2 = "./certs/dh3072.der";
#endif
    long len = 0;
    WOLFSSL_DH* dh = NULL;
    XMEMSET(buf, 0, sizeof(buf));

    /* Test 2048 bit parameters */
#ifdef HAVE_FFDHE_2048
    ExpectTrue((f = XFOPEN(params1, "rb")) != XBADFILE);
    ExpectTrue((len = (long)XFREAD(buf, 1, sizeof(buf), f)) > 0);
    if (f != XBADFILE) {
        XFCLOSE(f);
        f = XBADFILE;
    }

    /* Valid case */
    ExpectNotNull(dh = wolfSSL_d2i_DHparams(NULL, &pt, len));
    ExpectNotNull(dh->p);
    ExpectNotNull(dh->g);
    ExpectTrue(pt == buf);
    ExpectIntEQ(DH_set_length(NULL, BN_num_bits(dh->p)), 0);
    ExpectIntEQ(DH_set_length(dh, BN_num_bits(dh->p)), 1);
    ExpectIntEQ(DH_generate_key(dh), WOLFSSL_SUCCESS);

    /* Invalid cases */
    ExpectNull(wolfSSL_d2i_DHparams(NULL, NULL, len));
    ExpectNull(wolfSSL_d2i_DHparams(NULL, &pt, -1));
    ExpectNull(wolfSSL_d2i_DHparams(NULL, &pt, 10));

    DH_free(dh);
    dh = NULL;

    *buf = 0;
    pt = buf;
#endif /* HAVE_FFDHE_2048 */

    /* Test 3072 bit parameters */
#ifdef HAVE_FFDHE_3072
    ExpectTrue((f = XFOPEN(params2, "rb")) != XBADFILE);
    ExpectTrue((len = (long)XFREAD(buf, 1, sizeof(buf), f)) > 0);
    if (f != XBADFILE) {
        XFCLOSE(f);
        f = XBADFILE;
    }

    /* Valid case */
    ExpectNotNull(dh = wolfSSL_d2i_DHparams(&dh, &pt, len));
    ExpectNotNull(dh->p);
    ExpectNotNull(dh->g);
    ExpectTrue(pt != buf);
    ExpectIntEQ(DH_generate_key(dh), 1);

    /* Invalid cases */
    ExpectNull(wolfSSL_d2i_DHparams(NULL, NULL, len));
    ExpectNull(wolfSSL_d2i_DHparams(NULL, &pt, -1));

    DH_free(dh);
    dh = NULL;
#endif /* HAVE_FFDHE_3072 */

#endif /* !HAVE_FIPS || HAVE_FIPS_VERSION > 2 */
#endif /* !NO_DH */
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_DH_LoadDer(void)
{
    EXPECT_DECLS;
#if !defined(NO_DH) && (!defined(HAVE_FIPS) || FIPS_VERSION_GT(2,0)) && \
    defined(OPENSSL_EXTRA)
    static const byte dh2048[] = {
        0x30, 0x82, 0x01, 0x08, 0x02, 0x82, 0x01, 0x01,
        0x00, 0xb0, 0xa1, 0x08, 0x06, 0x9c, 0x08, 0x13,
        0xba, 0x59, 0x06, 0x3c, 0xbc, 0x30, 0xd5, 0xf5,
        0x00, 0xc1, 0x4f, 0x44, 0xa7, 0xd6, 0xef, 0x4a,
        0xc6, 0x25, 0x27, 0x1c, 0xe8, 0xd2, 0x96, 0x53,
        0x0a, 0x5c, 0x91, 0xdd, 0xa2, 0xc2, 0x94, 0x84,
        0xbf, 0x7d, 0xb2, 0x44, 0x9f, 0x9b, 0xd2, 0xc1,
        0x8a, 0xc5, 0xbe, 0x72, 0x5c, 0xa7, 0xe7, 0x91,
        0xe6, 0xd4, 0x9f, 0x73, 0x07, 0x85, 0x5b, 0x66,
        0x48, 0xc7, 0x70, 0xfa, 0xb4, 0xee, 0x02, 0xc9,
        0x3d, 0x9a, 0x4a, 0xda, 0x3d, 0xc1, 0x46, 0x3e,
        0x19, 0x69, 0xd1, 0x17, 0x46, 0x07, 0xa3, 0x4d,
        0x9f, 0x2b, 0x96, 0x17, 0x39, 0x6d, 0x30, 0x8d,
        0x2a, 0xf3, 0x94, 0xd3, 0x75, 0xcf, 0xa0, 0x75,
        0xe6, 0xf2, 0x92, 0x1f, 0x1a, 0x70, 0x05, 0xaa,
        0x04, 0x83, 0x57, 0x30, 0xfb, 0xda, 0x76, 0x93,
        0x38, 0x50, 0xe8, 0x27, 0xfd, 0x63, 0xee, 0x3c,
        0xe5, 0xb7, 0xc8, 0x09, 0xae, 0x6f, 0x50, 0x35,
        0x8e, 0x84, 0xce, 0x4a, 0x00, 0xe9, 0x12, 0x7e,
        0x5a, 0x31, 0xd7, 0x33, 0xfc, 0x21, 0x13, 0x76,
        0xcc, 0x16, 0x30, 0xdb, 0x0c, 0xfc, 0xc5, 0x62,
        0xa7, 0x35, 0xb8, 0xef, 0xb7, 0xb0, 0xac, 0xc0,
        0x36, 0xf6, 0xd9, 0xc9, 0x46, 0x48, 0xf9, 0x40,
        0x90, 0x00, 0x2b, 0x1b, 0xaa, 0x6c, 0xe3, 0x1a,
        0xc3, 0x0b, 0x03, 0x9e, 0x1b, 0xc2, 0x46, 0xe4,
        0x48, 0x4e, 0x22, 0x73, 0x6f, 0xc3, 0x5f, 0xd4,
        0x9a, 0xd6, 0x30, 0x07, 0x48, 0xd6, 0x8c, 0x90,
        0xab, 0xd4, 0xf6, 0xf1, 0xe3, 0x48, 0xd3, 0x58,
        0x4b, 0xa6, 0xb9, 0xcd, 0x29, 0xbf, 0x68, 0x1f,
        0x08, 0x4b, 0x63, 0x86, 0x2f, 0x5c, 0x6b, 0xd6,
        0xb6, 0x06, 0x65, 0xf7, 0xa6, 0xdc, 0x00, 0x67,
        0x6b, 0xbb, 0xc3, 0xa9, 0x41, 0x83, 0xfb, 0xc7,
        0xfa, 0xc8, 0xe2, 0x1e, 0x7e, 0xaf, 0x00, 0x3f,
        0x93, 0x02, 0x01, 0x02
    };
    WOLFSSL_DH* dh = NULL;

    ExpectNotNull(dh = wolfSSL_DH_new());

    ExpectIntEQ(wolfSSL_DH_LoadDer(NULL, NULL, 0), -1);
    ExpectIntEQ(wolfSSL_DH_LoadDer(dh, NULL, 0), -1);
    ExpectIntEQ(wolfSSL_DH_LoadDer(NULL, dh2048, sizeof(dh2048)), -1);

    ExpectIntEQ(wolfSSL_DH_LoadDer(dh, dh2048, sizeof(dh2048)), 1);

    wolfSSL_DH_free(dh);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_i2d_DHparams(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_ALL
#if !defined(NO_DH) && (defined(HAVE_FFDHE_2048) || defined(HAVE_FFDHE_3072))
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
    XFILE f = XBADFILE;
    unsigned char buf[4096];
    const unsigned char* pt;
    unsigned char* pt2;
#ifdef HAVE_FFDHE_2048
    const char* params1 = "./certs/dh2048.der";
#endif
#ifdef HAVE_FFDHE_3072
    const char* params2 = "./certs/dh3072.der";
#endif
    long len = 0;
    WOLFSSL_DH* dh = NULL;

    /* Test 2048 bit parameters */
#ifdef HAVE_FFDHE_2048
    pt = buf;
    pt2 = buf;

    ExpectTrue((f = XFOPEN(params1, "rb")) != XBADFILE);
    ExpectTrue((len = (long)XFREAD(buf, 1, sizeof(buf), f)) > 0);
    if (f != XBADFILE) {
        XFCLOSE(f);
        f = XBADFILE;
    }

    /* Valid case */
    ExpectNotNull(dh = wolfSSL_d2i_DHparams(NULL, &pt, len));
    ExpectTrue(pt == buf);
    ExpectIntEQ(DH_generate_key(dh), 1);
    ExpectIntEQ(wolfSSL_i2d_DHparams(dh, &pt2), 268);

    /* Invalid case */
    ExpectIntEQ(wolfSSL_i2d_DHparams(NULL, &pt2), 0);

    /* Return length only */
    ExpectIntEQ(wolfSSL_i2d_DHparams(dh, NULL), 268);

    DH_free(dh);
    dh = NULL;

    *buf = 0;
#endif

    /* Test 3072 bit parameters */
#ifdef HAVE_FFDHE_3072
    pt = buf;
    pt2 = buf;

    ExpectTrue((f = XFOPEN(params2, "rb")) != XBADFILE);
    ExpectTrue((len = (long)XFREAD(buf, 1, sizeof(buf), f)) > 0);
    if (f != XBADFILE) {
        XFCLOSE(f);
        f = XBADFILE;
    }

    /* Valid case */
    ExpectNotNull(dh = wolfSSL_d2i_DHparams(NULL, &pt, len));
    ExpectTrue(pt == buf);
    ExpectIntEQ(DH_generate_key(dh), 1);
    ExpectIntEQ(wolfSSL_i2d_DHparams(dh, &pt2), 396);

    /* Invalid case */
    ExpectIntEQ(wolfSSL_i2d_DHparams(NULL, &pt2), 0);

    /* Return length only */
    ExpectIntEQ(wolfSSL_i2d_DHparams(dh, NULL), 396);

    DH_free(dh);
    dh = NULL;
#endif

    dh = DH_new();
    ExpectNotNull(dh);
    pt2 = buf;
    ExpectIntEQ(wolfSSL_i2d_DHparams(dh, &pt2), 0);
    DH_free(dh);
    dh = NULL;
#endif /* !HAVE_FIPS || HAVE_FIPS_VERSION > 2 */
#endif /* !NO_DH && (HAVE_FFDHE_2048 || HAVE_FFDHE_3072) */
#endif
    return EXPECT_RESULT();
}

