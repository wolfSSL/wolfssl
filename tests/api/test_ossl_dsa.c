/* test_ossl_dsa.c
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

#include <wolfssl/openssl/dsa.h>
#include <wolfssl/openssl/pem.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_ossl_dsa.h>

/*******************************************************************************
 * DSA OpenSSL compatibility API Testing
 ******************************************************************************/

int test_DSA_do_sign_verify(void)
{
    EXPECT_DECLS;
#if !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
#if defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM) && \
    !defined(NO_DSA)
    unsigned char digest[WC_SHA_DIGEST_SIZE];
    DSA_SIG* sig = NULL;
    DSA* dsa = NULL;
    word32  bytes;
    byte sigBin[DSA_SIG_SIZE];
    int dsacheck;

#ifdef USE_CERT_BUFFERS_1024
    byte    tmp[ONEK_BUF];

    XMEMSET(tmp, 0, sizeof(tmp));
    XMEMCPY(tmp, dsa_key_der_1024, sizeof_dsa_key_der_1024);
    bytes = sizeof_dsa_key_der_1024;
#elif defined(USE_CERT_BUFFERS_2048)
    byte    tmp[TWOK_BUF];

    XMEMSET(tmp, 0, sizeof(tmp));
    XMEMCPY(tmp, dsa_key_der_2048, sizeof_dsa_key_der_2048);
    bytes = sizeof_dsa_key_der_2048;
#else
    byte    tmp[TWOK_BUF];
    XFILE   fp = XBADFILE;

    XMEMSET(tmp, 0, sizeof(tmp));
    ExpectTrue((fp = XFOPEN("./certs/dsa2048.der", "rb") != XBADFILE);
    ExpectIntGT(bytes = (word32) XFREAD(tmp, 1, sizeof(tmp), fp), 0);
    if (fp != XBADFILE)
        XFCLOSE(fp);
#endif /* END USE_CERT_BUFFERS_1024 */

    XMEMSET(digest, 202, sizeof(digest));

    ExpectNotNull(dsa = DSA_new());
    ExpectIntEQ(DSA_LoadDer(dsa, tmp, (int)bytes), 1);

    ExpectIntEQ(wolfSSL_DSA_do_sign(digest, sigBin, dsa), 1);
    ExpectIntEQ(wolfSSL_DSA_do_verify(digest, sigBin, dsa, &dsacheck), 1);

    ExpectNotNull(sig = DSA_do_sign(digest, WC_SHA_DIGEST_SIZE, dsa));
    ExpectIntEQ(DSA_do_verify(digest, WC_SHA_DIGEST_SIZE, sig, dsa), 1);

    DSA_SIG_free(sig);
    DSA_free(dsa);
#endif
#endif /* !HAVE_SELFTEST && !HAVE_FIPS */
    return EXPECT_RESULT();
}

int test_wolfSSL_DSA_generate_parameters(void)
{
    EXPECT_DECLS;
#if !defined(NO_DSA) && !defined(HAVE_SELFTEST) && defined(WOLFSSL_KEY_GEN) && \
    !defined(HAVE_FIPS) && defined(OPENSSL_ALL)
    DSA *dsa = NULL;

    ExpectNotNull(dsa = DSA_generate_parameters(2048, NULL, 0, NULL, NULL, NULL,
        NULL));
    DSA_free(dsa);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_DSA_SIG(void)
{
    EXPECT_DECLS;
#if !defined(NO_DSA) && !defined(HAVE_SELFTEST) && defined(WOLFSSL_KEY_GEN) && \
    !defined(HAVE_FIPS) && defined(OPENSSL_ALL)
    DSA          *dsa      = NULL;
    DSA          *dsa2     = NULL;
    DSA_SIG      *sig      = NULL;
    const BIGNUM *p        = NULL;
    const BIGNUM *q        = NULL;
    const BIGNUM *g        = NULL;
    const BIGNUM *pub      = NULL;
    const BIGNUM *priv     = NULL;
    BIGNUM       *dup_p    = NULL;
    BIGNUM       *dup_q    = NULL;
    BIGNUM       *dup_g    = NULL;
    BIGNUM       *dup_pub  = NULL;
    BIGNUM       *dup_priv = NULL;
    const byte digest[WC_SHA_DIGEST_SIZE] = {0};

    ExpectNotNull(dsa = DSA_new());
    ExpectIntEQ(DSA_generate_parameters_ex(dsa, 2048, NULL, 0, NULL, NULL,
         NULL), 1);
    ExpectIntEQ(DSA_generate_key(dsa), 1);
    DSA_get0_pqg(dsa, &p, &q, &g);
    DSA_get0_key(dsa, &pub, &priv);
    ExpectNotNull(dup_p    = BN_dup(p));
    ExpectNotNull(dup_q    = BN_dup(q));
    ExpectNotNull(dup_g    = BN_dup(g));
    ExpectNotNull(dup_pub  = BN_dup(pub));
    ExpectNotNull(dup_priv = BN_dup(priv));

    ExpectNotNull(sig = DSA_do_sign(digest, sizeof(digest), dsa));
    ExpectNotNull(dsa2 = DSA_new());
    ExpectIntEQ(DSA_set0_pqg(dsa2, dup_p, dup_q, dup_g), 1);
    if (EXPECT_FAIL()) {
        BN_free(dup_p);
        BN_free(dup_q);
        BN_free(dup_g);
    }
    ExpectIntEQ(DSA_set0_key(dsa2, dup_pub, dup_priv), 1);
    if (EXPECT_FAIL()) {
        BN_free(dup_pub);
        BN_free(dup_priv);
    }
    ExpectIntEQ(DSA_do_verify(digest, sizeof(digest), sig, dsa2), 1);

    DSA_free(dsa);
    DSA_free(dsa2);
    DSA_SIG_free(sig);
#endif
    return EXPECT_RESULT();
}

