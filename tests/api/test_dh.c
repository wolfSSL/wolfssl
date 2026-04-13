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
 * test_wc_DhBadArgCoverage
 *
 * Targets MC/DC decisions in:
 *   wc_DhExportParamsRaw  L3259 (dh==NULL||pSz==NULL||qSz==NULL||gSz==NULL)
 *                         L3269 (p==NULL&&q==NULL&&g==NULL  -> LENGTH_ONLY_E)
 *                         L3278 (p==NULL||q==NULL||g==NULL  -> BAD_FUNC_ARG)
 *   wc_DhCopyNamedKey     L2978 (p!=NULL&&pC!=NULL)
 *                         L2982 (pSz!=NULL)
 *                         L2986 (q!=NULL&&qC!=NULL)
 *   wc_DhCmpNamedKey      L2832 compound condition (goodName branch + all
 *                         sub-comparisons: pSz==pCmpSz, gSz==gCmpSz, noQ,
 *                         qCmp!=NULL, qSz==qCmpSz, XMEMCMP q, XMEMCMP p,
 *                         XMEMCMP g)
 */
int test_wc_DhBadArgCoverage(void)
{
    EXPECT_DECLS;
#if !defined(NO_DH) && !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
#ifdef HAVE_FFDHE_2048
    DhKey  key;
    /* Buffers large enough for FFDHE-2048 p (256 bytes), g (1 byte),
     * q (32 bytes per RFC 7919). */
    byte   pBuf[256], gBuf[4], qBuf[32];
    word32 pSz, gSz, qSz;

    XMEMSET(&key, 0, sizeof(DhKey));
    ExpectIntEQ(wc_InitDhKey(&key), 0);
    ExpectIntEQ(wc_DhSetNamedKey(&key, WC_FFDHE_2048), 0);

    /* --- wc_DhExportParamsRaw NULL-arg matrix (L3259) --- */
    /* dh == NULL */
    pSz = sizeof(pBuf); qSz = sizeof(qBuf); gSz = sizeof(gBuf);
    ExpectIntEQ(wc_DhExportParamsRaw(NULL, pBuf, &pSz, qBuf, &qSz,
                                     gBuf, &gSz),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* pSz == NULL */
    ExpectIntEQ(wc_DhExportParamsRaw(&key, pBuf, NULL, qBuf, &qSz,
                                     gBuf, &gSz),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* qSz == NULL */
    pSz = sizeof(pBuf);
    ExpectIntEQ(wc_DhExportParamsRaw(&key, pBuf, &pSz, qBuf, NULL,
                                     gBuf, &gSz),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* gSz == NULL */
    pSz = sizeof(pBuf); qSz = sizeof(qBuf);
    ExpectIntEQ(wc_DhExportParamsRaw(&key, pBuf, &pSz, qBuf, &qSz,
                                     gBuf, NULL),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* --- wc_DhExportParamsRaw length-only query (L3269): all buffers NULL
     *     -> returns sizes via *pSz/*qSz/*gSz and LENGTH_ONLY_E --- */
    pSz = 0; qSz = 0; gSz = 0;
    ExpectIntEQ(wc_DhExportParamsRaw(&key, NULL, &pSz, NULL, &qSz,
                                     NULL, &gSz),
                WC_NO_ERR_TRACE(LENGTH_ONLY_E));
    ExpectIntGT((int)pSz, 0);
    ExpectIntGT((int)gSz, 0);

    /* --- wc_DhExportParamsRaw partial-NULL (L3278): exactly one buf NULL
     *     while not all three are NULL -> BAD_FUNC_ARG --- */
    pSz = sizeof(pBuf); qSz = sizeof(qBuf); gSz = sizeof(gBuf);
    /* p==NULL but q and g are not NULL */
    ExpectIntEQ(wc_DhExportParamsRaw(&key, NULL, &pSz, qBuf, &qSz,
                                     gBuf, &gSz),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* q==NULL but p and g are not NULL */
    pSz = sizeof(pBuf); qSz = sizeof(qBuf); gSz = sizeof(gBuf);
    ExpectIntEQ(wc_DhExportParamsRaw(&key, pBuf, &pSz, NULL, &qSz,
                                     gBuf, &gSz),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* g==NULL but p and q are not NULL */
    pSz = sizeof(pBuf); qSz = sizeof(qBuf); gSz = sizeof(gBuf);
    ExpectIntEQ(wc_DhExportParamsRaw(&key, pBuf, &pSz, qBuf, &qSz,
                                     NULL, &gSz),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* --- wc_DhExportParamsRaw undersized buffer (L3284 pSz < pLen) --- */
    pSz = 1; qSz = sizeof(qBuf); gSz = sizeof(gBuf);
    ExpectIntEQ(wc_DhExportParamsRaw(&key, pBuf, &pSz, qBuf, &qSz,
                                     gBuf, &gSz),
                WC_NO_ERR_TRACE(BUFFER_E));

    /* --- wc_DhExportParamsRaw success path --- */
    pSz = sizeof(pBuf); qSz = sizeof(qBuf); gSz = sizeof(gBuf);
    /* wc_DhExportParamsRaw requires q; FFDHE-2048 has q only with
     * HAVE_FFDHE_Q; skip success check if q is empty (qSz == 0 after
     * length query) to avoid a false BUFFER_E on the q export. */
    {
        word32 qLenCheck = 0;
        (void)wc_DhExportParamsRaw(&key, NULL, &pSz, NULL, &qLenCheck,
                                   NULL, &gSz);
        pSz = sizeof(pBuf); gSz = sizeof(gBuf);
        if (qLenCheck == 0) {
            /* q is zero-length; raw export still works (exports zero bytes) */
            qSz = 0;
            ExpectIntEQ(wc_DhExportParamsRaw(&key, pBuf, &pSz, qBuf, &qSz,
                                             gBuf, &gSz), 0);
        }
        else {
            qSz = sizeof(qBuf);
            ExpectIntEQ(wc_DhExportParamsRaw(&key, pBuf, &pSz, qBuf, &qSz,
                                             gBuf, &gSz), 0);
        }
    }

    /* --- wc_DhCopyNamedKey: size-query (all out buffers NULL, sizes filled)
     *     Covers L2980/L2982/L2986 pSz-only / gSz-only branches --- */
    pSz = 0; gSz = 0; qSz = 0;
    ExpectIntEQ(wc_DhCopyNamedKey(WC_FFDHE_2048,
                                  NULL, &pSz, NULL, &gSz, NULL, &qSz), 0);
    ExpectIntGT((int)pSz, 0);
    ExpectIntGT((int)gSz, 0);

    /* --- wc_DhCopyNamedKey: full copy (L2978 p!=NULL&&pC!=NULL) --- */
    ExpectIntEQ(wc_DhCopyNamedKey(WC_FFDHE_2048,
                                  pBuf, &pSz, gBuf, &gSz, qBuf, &qSz), 0);

    /* --- wc_DhCopyNamedKey: unknown name (default case, pC stays NULL) --- */
    pSz = sizeof(pBuf); gSz = sizeof(gBuf); qSz = sizeof(qBuf);
    ExpectIntEQ(wc_DhCopyNamedKey(0 /* invalid */,
                                  pBuf, &pSz, gBuf, &gSz, qBuf, &qSz), 0);
    /* sizes should be zero because no named group matched */
    ExpectIntEQ((int)pSz, 0);
    ExpectIntEQ((int)gSz, 0);

    /* --- wc_DhCmpNamedKey: unknown name -> goodName=0 -> returns 0 (L2832) */
    ExpectIntEQ(wc_DhCmpNamedKey(0 /* invalid */, 1,
                                 pBuf, pSz, gBuf, gSz, NULL, 0), 0);

    /* --- wc_DhCmpNamedKey: FFDHE_2048, noQ=1, correct params -> 1 --- */
    {
        byte   p2[256], g2[4];
        word32 p2Sz = sizeof(p2), g2Sz = sizeof(g2), q2Sz = 0;
        ExpectIntEQ(wc_DhCopyNamedKey(WC_FFDHE_2048,
                                      p2, &p2Sz, g2, &g2Sz, NULL, &q2Sz), 0);
        ExpectIntEQ(wc_DhCmpNamedKey(WC_FFDHE_2048, 1 /* noQ */,
                                     p2, p2Sz, g2, g2Sz, NULL, 0), 1);
    }

    /* --- wc_DhCmpNamedKey: correct name, wrong pSz -> cmp==0 --- */
    {
        byte   p2[256], g2[4];
        word32 p2Sz = sizeof(p2), g2Sz = sizeof(g2), q2Sz = 0;
        ExpectIntEQ(wc_DhCopyNamedKey(WC_FFDHE_2048,
                                      p2, &p2Sz, g2, &g2Sz, NULL, &q2Sz), 0);
        /* Pass a deliberately wrong size */
        ExpectIntEQ(wc_DhCmpNamedKey(WC_FFDHE_2048, 1,
                                     p2, p2Sz - 1, g2, g2Sz, NULL, 0), 0);
    }

    /* --- wc_DhCmpNamedKey: correct params but corrupt p -> cmp==0 --- */
    {
        byte   p2[256], g2[4];
        word32 p2Sz = sizeof(p2), g2Sz = sizeof(g2), q2Sz = 0;
        ExpectIntEQ(wc_DhCopyNamedKey(WC_FFDHE_2048,
                                      p2, &p2Sz, g2, &g2Sz, NULL, &q2Sz), 0);
        p2[0] ^= 0xFF; /* corrupt first byte */
        ExpectIntEQ(wc_DhCmpNamedKey(WC_FFDHE_2048, 1,
                                     p2, p2Sz, g2, g2Sz, NULL, 0), 0);
    }

#ifdef HAVE_FFDHE_Q
    /* --- wc_DhCmpNamedKey: noQ=0, correct q -> 1 --- */
    {
        byte   p2[256], g2[4], q2[32];
        word32 p2Sz = sizeof(p2), g2Sz = sizeof(g2), q2Sz = sizeof(q2);
        ExpectIntEQ(wc_DhCopyNamedKey(WC_FFDHE_2048,
                                      p2, &p2Sz, g2, &g2Sz, q2, &q2Sz), 0);
        if (q2Sz > 0)
            ExpectIntEQ(wc_DhCmpNamedKey(WC_FFDHE_2048, 0 /* noQ=false */,
                                         p2, p2Sz, g2, g2Sz, q2, q2Sz), 1);
    }

    /* --- wc_DhCmpNamedKey: noQ=0, wrong qSz -> cmp==0 --- */
    {
        byte   p2[256], g2[4], q2[32];
        word32 p2Sz = sizeof(p2), g2Sz = sizeof(g2), q2Sz = sizeof(q2);
        ExpectIntEQ(wc_DhCopyNamedKey(WC_FFDHE_2048,
                                      p2, &p2Sz, g2, &g2Sz, q2, &q2Sz), 0);
        if (q2Sz > 0)
            ExpectIntEQ(wc_DhCmpNamedKey(WC_FFDHE_2048, 0,
                                         p2, p2Sz, g2, g2Sz, q2,
                                         q2Sz - 1), 0);
    }
#endif /* HAVE_FFDHE_Q */

    DoExpectIntEQ(wc_FreeDhKey(&key), 0);
#endif /* HAVE_FFDHE_2048 */
#endif /* !NO_DH && !HAVE_FIPS && !HAVE_SELFTEST */
    return EXPECT_RESULT();
}

/*
 * test_wc_DhBadArgCoverage2
 *
 * Targets MC/DC decisions in:
 *   wc_DhGeneratePublic   L1386 (key==NULL||priv==NULL||privSz==0
 *                                ||pub==NULL||pubSz==NULL)
 *   wc_DhAgree            L2291 (key==NULL||agree==NULL||agreeSz==NULL
 *                                ||priv==NULL||otherPub==NULL)
 *   wc_DhAgree_ct         L2322 (same NULL matrix) + L2328 (size check)
 *   wc_DhCheckPrivKey_ex  L1744 (key==NULL||priv==NULL)
 *   GeneratePublicDh      L1355 (*pubSz < mp_unsigned_bin_size(&key->p))
 *                         L1358  (implicit: privSz==0 guard above)
 */
int test_wc_DhBadArgCoverage2(void)
{
    EXPECT_DECLS;
#if !defined(NO_DH) && !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
#ifdef HAVE_FFDHE_2048
    DhKey   key;
    WC_RNG  rng;
    byte    priv[256], pub[256], agree[256];
    word32  privSz = sizeof(priv), pubSz = sizeof(pub), agreeSz = sizeof(agree);
    XMEMSET(&key,  0, sizeof(DhKey));
    XMEMSET(&rng,  0, sizeof(WC_RNG));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_InitDhKey(&key), 0);
    ExpectIntEQ(wc_DhSetNamedKey(&key, WC_FFDHE_2048), 0);

    /* Generate a valid key pair for the agree tests */
    privSz = sizeof(priv); pubSz = sizeof(pub);
    ExpectIntEQ(wc_DhGenerateKeyPair(&key, &rng, priv, &privSz, pub, &pubSz),
                0);

    /* --- wc_DhGeneratePublic NULL-arg matrix (L1386) --- */
    {
        byte   pub2[256];
        word32 pub2Sz = sizeof(pub2);

        /* key == NULL */
        ExpectIntEQ(wc_DhGeneratePublic(NULL, priv, privSz, pub2, &pub2Sz),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* priv == NULL */
        ExpectIntEQ(wc_DhGeneratePublic(&key, NULL, privSz, pub2, &pub2Sz),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* privSz == 0 */
        ExpectIntEQ(wc_DhGeneratePublic(&key, priv, 0, pub2, &pub2Sz),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* pub == NULL */
        ExpectIntEQ(wc_DhGeneratePublic(&key, priv, privSz, NULL, &pub2Sz),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* pubSz == NULL */
        ExpectIntEQ(wc_DhGeneratePublic(&key, priv, privSz, pub2, NULL),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* GeneratePublicDh L1355: pubSz too small for the prime */
        pub2Sz = 1;
        ExpectIntEQ(wc_DhGeneratePublic(&key, priv, privSz, pub2, &pub2Sz),
                    WC_NO_ERR_TRACE(WC_KEY_SIZE_E));

        /* Success path */
        pub2Sz = sizeof(pub2);
        ExpectIntEQ(wc_DhGeneratePublic(&key, priv, privSz, pub2, &pub2Sz), 0);
    }

    /* --- wc_DhAgree NULL-arg matrix (L2291) --- */
    agreeSz = sizeof(agree);
    /* key == NULL */
    ExpectIntEQ(wc_DhAgree(NULL, agree, &agreeSz, priv, privSz, pub, pubSz),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* agree == NULL */
    ExpectIntEQ(wc_DhAgree(&key, NULL, &agreeSz, priv, privSz, pub, pubSz),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* agreeSz == NULL */
    ExpectIntEQ(wc_DhAgree(&key, agree, NULL, priv, privSz, pub, pubSz),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* priv == NULL */
    ExpectIntEQ(wc_DhAgree(&key, agree, &agreeSz, NULL, privSz, pub, pubSz),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* otherPub == NULL */
    ExpectIntEQ(wc_DhAgree(&key, agree, &agreeSz, priv, privSz, NULL, pubSz),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Success path for wc_DhAgree */
    agreeSz = sizeof(agree);
    ExpectIntEQ(wc_DhAgree(&key, agree, &agreeSz, priv, privSz, pub, pubSz),
                0);

    /* --- wc_DhAgree_ct NULL-arg matrix (L2322) --- */
    agreeSz = sizeof(agree);
    /* key == NULL */
    ExpectIntEQ(wc_DhAgree_ct(NULL, agree, &agreeSz, priv, privSz, pub, pubSz),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* agree == NULL */
    ExpectIntEQ(wc_DhAgree_ct(&key, NULL, &agreeSz, priv, privSz, pub, pubSz),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* agreeSz == NULL */
    ExpectIntEQ(wc_DhAgree_ct(&key, agree, NULL, priv, privSz, pub, pubSz),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* priv == NULL */
    ExpectIntEQ(wc_DhAgree_ct(&key, agree, &agreeSz, NULL, privSz, pub, pubSz),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* otherPub == NULL */
    ExpectIntEQ(wc_DhAgree_ct(&key, agree, &agreeSz, priv, privSz, NULL,
                              pubSz),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* wc_DhAgree_ct L2328: *agreeSz too small (must be >= p-size == 256) */
    agreeSz = 1;
    ExpectIntEQ(wc_DhAgree_ct(&key, agree, &agreeSz, priv, privSz, pub, pubSz),
                WC_NO_ERR_TRACE(BUFFER_E));

    /* Success path for wc_DhAgree_ct */
    agreeSz = sizeof(agree);
    ExpectIntEQ(wc_DhAgree_ct(&key, agree, &agreeSz, priv, privSz, pub, pubSz),
                0);

    /* --- wc_DhCheckPrivKey_ex NULL-arg matrix (L1744) --- */
    /* key == NULL */
    ExpectIntEQ(wc_DhCheckPrivKey_ex(NULL, priv, privSz, NULL, 0),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* priv == NULL */
    ExpectIntEQ(wc_DhCheckPrivKey_ex(&key, NULL, privSz, NULL, 0),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Success: valid private key, no prime supplied */
    ExpectIntEQ(wc_DhCheckPrivKey_ex(&key, priv, privSz, NULL, 0), 0);

    /* --- wc_DhCheckPrivKey_ex: priv == { 0x00 } (zero value -> MP_CMP_E) --- */
    {
        static const byte kZeroPriv[] = { 0x00 };
        ExpectIntEQ(wc_DhCheckPrivKey_ex(&key, kZeroPriv, sizeof(kZeroPriv),
                                         NULL, 0),
                    WC_NO_ERR_TRACE(MP_CMP_E));
    }

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    DoExpectIntEQ(wc_FreeDhKey(&key), 0);
#endif /* HAVE_FFDHE_2048 */
#endif /* !NO_DH && !HAVE_FIPS && !HAVE_SELFTEST */
    return EXPECT_RESULT();
}

/*
 * test_wc_DhBadArgCoverage3
 *
 * Targets MC/DC decisions in:
 *   _ffc_validate_public_key  L1525 (key==NULL||pub==NULL)
 *                             L1573 (mp_cmp_d(y,2)==MP_LT: pub<=1)
 *                             L1578 (mp_copy(&key->p,p) error path, reached
 *                                    by valid flow)
 *                             L1581 (mp_cmp(y,p)==MP_GT: pub>=p-1)
 *                             L1636 (mp_cmp_d(y,1)!=MP_EQ after exptmod)
 *   Reached via wc_DhCheckPubKey (partial=1) and wc_DhCheckPubKey_ex
 *   (partial=0, prime supplied for full order-check).
 */
int test_wc_DhBadArgCoverage3(void)
{
    EXPECT_DECLS;
#if !defined(NO_DH) && !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
#ifdef HAVE_FFDHE_2048
    DhKey  key;
    /* FFDHE-2048 prime p is 256 bytes.  We build edge-case public keys from
     * the actual prime bytes retrieved via wc_DhCopyNamedKey. */
    byte   pBuf[256], gBuf[4], qBuf[32];
    word32 pSz = sizeof(pBuf), gSz = sizeof(gBuf), qSz = sizeof(qBuf);

    XMEMSET(&key, 0, sizeof(DhKey));
    ExpectIntEQ(wc_InitDhKey(&key), 0);
    ExpectIntEQ(wc_DhSetNamedKey(&key, WC_FFDHE_2048), 0);

    /* Fetch the raw prime for constructing edge-case inputs */
    ExpectIntEQ(wc_DhCopyNamedKey(WC_FFDHE_2048,
                                  pBuf, &pSz, gBuf, &gSz, qBuf, &qSz), 0);

    /* --- _ffc_validate_public_key L1525: key==NULL or pub==NULL ---
     *     Reached via wc_DhCheckPubKey_ex. */
    {
        byte pub1[] = { 0x02 };
        ExpectIntEQ(wc_DhCheckPubKey_ex(NULL, pub1, sizeof(pub1), NULL, 0),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_DhCheckPubKey_ex(&key, NULL, 1, NULL, 0),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }

    /* --- L1573: pub == 0 (y < 2) --- */
    {
        static const byte kPub0[] = { 0x00 };
        ExpectIntEQ(wc_DhCheckPubKey(&key, kPub0, sizeof(kPub0)),
                    WC_NO_ERR_TRACE(MP_CMP_E));
    }

    /* --- L1573: pub == 1 (y < 2) --- */
    {
        static const byte kPub1[] = { 0x01 };
        ExpectIntEQ(wc_DhCheckPubKey(&key, kPub1, sizeof(kPub1)),
                    WC_NO_ERR_TRACE(MP_CMP_E));
    }

    /* --- L1584: pub == p (y > p-2, i.e. y >= p-1) ---
     *     Pass the raw prime as the public key; p > p-2 */
    ExpectIntEQ(wc_DhCheckPubKey(&key, pBuf, pSz),
                WC_NO_ERR_TRACE(MP_CMP_E));

    /* --- L1584: pub == p-1 (y == p-2+1 == p-1, still > p-2) ---
     *     Decrement last byte of p by 1 to get p-1. */
    {
        byte pMinus1[256];
        XMEMCPY(pMinus1, pBuf, pSz);
        pMinus1[pSz - 1] -= 1; /* p-1 */
        ExpectIntEQ(wc_DhCheckPubKey(&key, pMinus1, pSz),
                    WC_NO_ERR_TRACE(MP_CMP_E));
    }

    /* --- Valid public key (y == 2, exactly at the lower bound) ---
     *     wc_DhCheckPubKey (partial=1) should accept y==2 even without q. */
    {
        byte pub2[256];
        XMEMSET(pub2, 0, sizeof(pub2));
        pub2[sizeof(pub2) - 1] = 0x02;
        ExpectIntEQ(wc_DhCheckPubKey(&key, pub2, sizeof(pub2)), 0);
    }

#ifdef HAVE_FFDHE_Q
    /* --- Full validation (partial=0) via wc_DhCheckPubKey_ex with prime ---
     *     y==2 with prime supplied: y^q mod p must equal 1 for the subgroup
     *     check (L1636).  y=2 is not in the FFDHE-2048 subgroup so this
     *     should fail the order check. */
    if (qSz > 0) {
        byte pub2[256];
        XMEMSET(pub2, 0, sizeof(pub2));
        pub2[sizeof(pub2) - 1] = 0x02;
        /* expected: MP_CMP_E (y^q mod p != 1) */
        ExpectIntEQ(wc_DhCheckPubKey_ex(&key, pub2, sizeof(pub2),
                                         qBuf, qSz),
                    WC_NO_ERR_TRACE(MP_CMP_E));
    }
#endif /* HAVE_FFDHE_Q */

    DoExpectIntEQ(wc_FreeDhKey(&key), 0);
#endif /* HAVE_FFDHE_2048 */
#endif /* !NO_DH && !HAVE_FIPS && !HAVE_SELFTEST */
    return EXPECT_RESULT();
}

/*
 * test_wc_DhBadArgCoverage4
 *
 * Targets MC/DC decisions in:
 *   wc_DhGenerateKeyPair_Sync  L1412 (key==NULL||rng==NULL||priv==NULL
 *                                     ||privSz==NULL||pub==NULL||pubSz==NULL)
 *                              - 6-condition OR chain; each NULL tested
 *                                independently so each sub-condition flips
 *                                the overall outcome.
 *   GeneratePrivateDh          L1238 (mp_iszero(&key->q)==MP_NO, DH186 path)
 *   CheckDhLN                  L1063 (bad (L,N) pair -> -1 vs good pair -> 0)
 *                              - reached from GeneratePrivateDh186 when
 *                                key->trustedGroup == 0.
 *
 * Note: _ffc_pairwise_consistency_test (L1852/L1888) is only compiled when
 *   FIPS_VERSION_GE(5,0) || WOLFSSL_VALIDATE_DH_KEYGEN.  The standard
 *   non-FIPS build does not define WOLFSSL_VALIDATE_DH_KEYGEN so those
 *   branches are unreachable in the target binary; skipped per strategy para 6.
 */
int test_wc_DhBadArgCoverage4(void)
{
    EXPECT_DECLS;
#if !defined(NO_DH) && !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
#ifdef HAVE_FFDHE_2048
    DhKey  key;
    WC_RNG rng;
    byte   priv[256], pub[256];
    word32 privSz = sizeof(priv), pubSz = sizeof(pub);

    XMEMSET(&key, 0, sizeof(DhKey));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_InitDhKey(&key), 0);
    ExpectIntEQ(wc_DhSetNamedKey(&key, WC_FFDHE_2048), 0);

    /* --- wc_DhGenerateKeyPair_Sync L1412: 6-cond NULL OR chain ---
     * Reached via the public wc_DhGenerateKeyPair API.
     * Each call flips exactly one sub-condition from FALSE to TRUE,
     * isolating its independent effect on the decision outcome.        */

    /* key == NULL */
    privSz = sizeof(priv); pubSz = sizeof(pub);
    ExpectIntEQ(wc_DhGenerateKeyPair(NULL, &rng, priv, &privSz, pub, &pubSz),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* rng == NULL */
    privSz = sizeof(priv); pubSz = sizeof(pub);
    ExpectIntEQ(wc_DhGenerateKeyPair(&key, NULL, priv, &privSz, pub, &pubSz),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* priv == NULL */
    privSz = sizeof(priv); pubSz = sizeof(pub);
    ExpectIntEQ(wc_DhGenerateKeyPair(&key, &rng, NULL, &privSz, pub, &pubSz),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* privSz == NULL */
    privSz = sizeof(priv); pubSz = sizeof(pub);
    ExpectIntEQ(wc_DhGenerateKeyPair(&key, &rng, priv, NULL, pub, &pubSz),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* pub == NULL */
    privSz = sizeof(priv); pubSz = sizeof(pub);
    ExpectIntEQ(wc_DhGenerateKeyPair(&key, &rng, priv, &privSz, NULL, &pubSz),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* pubSz == NULL */
    privSz = sizeof(priv); pubSz = sizeof(pub);
    ExpectIntEQ(wc_DhGenerateKeyPair(&key, &rng, priv, &privSz, pub, NULL),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Happy-path: all valid => success (FALSE branch for whole L1412 cond) */
    privSz = sizeof(priv); pubSz = sizeof(pub);
    ExpectIntEQ(wc_DhGenerateKeyPair(&key, &rng, priv, &privSz, pub, &pubSz),
                0);

#ifndef WOLFSSL_NO_DH186
    /* --- CheckDhLN L1063: valid (L,N) pair => ret==0 ---
     * FFDHE-2048: p is 2048-bit, q is 256-bit => (2048,256) is in the
     * allowed set.  Set key with p, g, and q via wc_DhSetKey_ex.
     * GeneratePrivateDh detects q!=0 and calls GeneratePrivateDh186,
     * which calls CheckDhLN.  Good pair passes; bad pair returns
     * BAD_FUNC_ARG.                                                     */
    {
        byte   pBuf[256], gBuf[4], qBuf[32];
        word32 pSz2 = sizeof(pBuf), gSz2 = sizeof(gBuf), qSz2 = sizeof(qBuf);
        DhKey  key2;
        byte   priv2[32], pub2[256];
        word32 priv2Sz = sizeof(priv2), pub2Sz = sizeof(pub2);

        XMEMSET(&key2, 0, sizeof(DhKey));
        ExpectIntEQ(wc_InitDhKey(&key2), 0);

        /* Fetch raw FFDHE-2048 p/g/q */
        ExpectIntEQ(wc_DhCopyNamedKey(WC_FFDHE_2048,
                                      pBuf, &pSz2, gBuf, &gSz2,
                                      qBuf, &qSz2), 0);

        if (qSz2 > 0) {
            /* Load p, g, q -- wc_DhSetKey_ex, trusted=0 implied */
            ExpectIntEQ(wc_DhSetKey_ex(&key2, pBuf, pSz2, gBuf, gSz2,
                                       qBuf, qSz2), 0);

            /* Key-gen via DH186 path: CheckDhLN sees (2048,256) => valid */
            priv2Sz = sizeof(priv2); pub2Sz = sizeof(pub2);
            ExpectIntEQ(wc_DhGenerateKeyPair(&key2, &rng,
                                             priv2, &priv2Sz,
                                             pub2,  &pub2Sz), 0);

            /* CheckDhLN bad (L,N): re-init key2 with a 20-byte (160-bit) q.
             * (2048, 160) is NOT in the allowed set per SP 800-56A =>
             * BAD_FUNC_ARG from GeneratePrivateDh186.                      */
            DoExpectIntEQ(wc_FreeDhKey(&key2), 0);
            XMEMSET(&key2, 0, sizeof(DhKey));
            ExpectIntEQ(wc_InitDhKey(&key2), 0);

            {
                byte badQ[20];
                XMEMSET(badQ, 0xAB, sizeof(badQ));
                badQ[0] = 0x01; /* non-zero MSB so mp_iszero returns NO */

                ExpectIntEQ(wc_DhSetKey_ex(&key2, pBuf, pSz2, gBuf, gSz2,
                                           badQ, (word32)sizeof(badQ)), 0);

                /* trustedGroup==0 so CheckDhLN rejects (2048,160) */
                priv2Sz = sizeof(priv2); pub2Sz = sizeof(pub2);
                ExpectIntEQ(wc_DhGenerateKeyPair(&key2, &rng,
                                                 priv2, &priv2Sz,
                                                 pub2,  &pub2Sz),
                            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            }
        }

        DoExpectIntEQ(wc_FreeDhKey(&key2), 0);
    }
#endif /* !WOLFSSL_NO_DH186 */

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    DoExpectIntEQ(wc_FreeDhKey(&key), 0);
#endif /* HAVE_FFDHE_2048 */
#endif /* !NO_DH && !HAVE_FIPS && !HAVE_SELFTEST */
    return EXPECT_RESULT();
}

/*
 * test_wc_DhBadArgCoverage5
 *
 * Targets MC/DC decisions in:
 *   _DhSetKey       L2493 (key==NULL||p==NULL||g==NULL||pSz==0||gSz==0)
 *                   - 5-condition OR chain; each sub-condition tested
 *                     independently.
 *                   L2583 (mp_init(&key->g) != MP_OKAY) - FALSE arm covered
 *                   by the success path; TRUE arm requires memory fault
 *                   injection (not applicable in functional testing).
 *   wc_DhAgree_Sync L2036 (wc_DhCheckPubKey fails => DH_CHECK_PUB_E)
 *                   - peer public key < 2 triggers the TRUE branch.
 *                   L2166 (mp_read_unsigned_bin y) - FALSE arm covered by
 *                   the happy-path agree call below.
 *                   L2198 (mp_cmp_d(z,1)==MP_EQ => MP_VAL) - TRUE arm not
 *                   achievable with standard FFDHE groups without a
 *                   degenerate public key that would fail CheckPubKey first;
 *                   FALSE arm covered by happy-path agree.
 */
int test_wc_DhBadArgCoverage5(void)
{
    EXPECT_DECLS;
#if !defined(NO_DH) && !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
#ifdef HAVE_FFDHE_2048
    DhKey  key;
    WC_RNG rng;
    byte   priv[256], pub[256], agree[256];
    word32 privSz = sizeof(priv), pubSz = sizeof(pub), agreeSz = sizeof(agree);

    XMEMSET(&key, 0, sizeof(DhKey));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_InitDhKey(&key), 0);
    ExpectIntEQ(wc_DhSetNamedKey(&key, WC_FFDHE_2048), 0);

    /* Generate a valid key pair for use in agree tests */
    privSz = sizeof(priv); pubSz = sizeof(pub);
    ExpectIntEQ(wc_DhGenerateKeyPair(&key, &rng, priv, &privSz, pub, &pubSz),
                0);

    /* --- _DhSetKey L2493: NULL-arg matrix (reached via wc_DhSetKey) ---
     * Each call isolates one sub-condition in the 5-term OR.            */
    {
        byte   pBuf[256], gBuf[4];
        word32 pSz2 = sizeof(pBuf), gSz2 = sizeof(gBuf), qSz2 = 0;
        DhKey  key2;

        ExpectIntEQ(wc_DhCopyNamedKey(WC_FFDHE_2048,
                                      pBuf, &pSz2, gBuf, &gSz2,
                                      NULL, &qSz2), 0);

        XMEMSET(&key2, 0, sizeof(DhKey));
        ExpectIntEQ(wc_InitDhKey(&key2), 0);

        /* key == NULL */
        ExpectIntEQ(wc_DhSetKey(NULL, pBuf, pSz2, gBuf, gSz2),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* p == NULL */
        ExpectIntEQ(wc_DhSetKey(&key2, NULL, pSz2, gBuf, gSz2),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* g == NULL */
        ExpectIntEQ(wc_DhSetKey(&key2, pBuf, pSz2, NULL, gSz2),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* pSz == 0 */
        ExpectIntEQ(wc_DhSetKey(&key2, pBuf, 0, gBuf, gSz2),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* gSz == 0 */
        ExpectIntEQ(wc_DhSetKey(&key2, pBuf, pSz2, gBuf, 0),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* Success path: covers _DhSetKey L2583 FALSE branch */
        ExpectIntEQ(wc_DhSetKey(&key2, pBuf, pSz2, gBuf, gSz2), 0);

        DoExpectIntEQ(wc_FreeDhKey(&key2), 0);
    }

    /* --- wc_DhAgree_Sync L2036: peer pub out of range => DH_CHECK_PUB_E --- */
    {
        static const byte kPubOne[] = { 0x01 };
        agreeSz = sizeof(agree);
        ExpectIntEQ(wc_DhAgree(&key, agree, &agreeSz,
                               priv, privSz, kPubOne, sizeof(kPubOne)),
                    WC_NO_ERR_TRACE(DH_CHECK_PUB_E));
    }

    /* --- wc_DhAgree_Sync happy path: L2166 FALSE arm (mp_read y succeeds) --- */
    agreeSz = sizeof(agree);
    ExpectIntEQ(wc_DhAgree(&key, agree, &agreeSz, priv, privSz, pub, pubSz),
                0);

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    DoExpectIntEQ(wc_FreeDhKey(&key), 0);
#endif /* HAVE_FFDHE_2048 */
#endif /* !NO_DH && !HAVE_FIPS && !HAVE_SELFTEST */
    return EXPECT_RESULT();
}

/*
 * test_wc_DhBadArgCoverage6
 *
 * Targets MC/DC decisions in:
 *   wc_DhCopyNamedKey  L2986 (q!=NULL && qC!=NULL - the q-copy branch).
 *                      When HAVE_FFDHE_Q is defined, qC is non-NULL for
 *                      standard named groups; providing a non-NULL q output
 *                      makes both conditions TRUE, triggering the XMEMCPY.
 *                      When HAVE_FFDHE_Q is absent, qC is always NULL so
 *                      the TRUE arm is not reachable (noted in summary).
 *   _ffc_validate_public_key  L1578/L1581 (mp_copy/mp_sub_d success path):
 *                             pub == p-2 (exact upper valid boundary) must
 *                             PASS the check (y <= p-2).
 *                   L1636 TRUE arm  - y^q mod p != 1 via wc_DhCheckPubKey_ex
 *                             with y = p-2 (non-subgroup element).
 *                   L1636 FALSE arm - y^q mod p == 1 via a legitimately
 *                             generated public key.
 */
int test_wc_DhBadArgCoverage6(void)
{
    EXPECT_DECLS;
#if !defined(NO_DH) && !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
#ifdef HAVE_FFDHE_2048
    DhKey  key;
    byte   pBuf[256], gBuf[4], qBuf[32];
    word32 pSz = sizeof(pBuf), gSz = sizeof(gBuf), qSz = sizeof(qBuf);

    XMEMSET(&key, 0, sizeof(DhKey));
    ExpectIntEQ(wc_InitDhKey(&key), 0);
    ExpectIntEQ(wc_DhSetNamedKey(&key, WC_FFDHE_2048), 0);

    /* Fetch raw p/g/q for boundary key construction */
    ExpectIntEQ(wc_DhCopyNamedKey(WC_FFDHE_2048,
                                  pBuf, &pSz, gBuf, &gSz, qBuf, &qSz), 0);

#ifdef HAVE_FFDHE_Q
    /* --- wc_DhCopyNamedKey L2986: q!=NULL && qC!=NULL (TRUE arm) ---
     * Both conditions TRUE: output q buffer non-NULL, qC set by the case
     * branch for WC_FFDHE_2048.  Verify the copy produced a non-zero qSz
     * and that a second call yields identical bytes.                     */
    ExpectIntGT((int)qSz, 0);
    {
        byte   p2[256], g2[4], q2[32];
        word32 p2Sz = sizeof(p2), g2Sz = sizeof(g2), q2Sz = sizeof(q2);
        ExpectIntEQ(wc_DhCopyNamedKey(WC_FFDHE_2048,
                                      p2, &p2Sz, g2, &g2Sz, q2, &q2Sz), 0);
        ExpectIntGT((int)q2Sz, 0);
        ExpectIntEQ((int)q2Sz, (int)qSz);
        ExpectIntEQ(XMEMCMP(q2, qBuf, qSz), 0);
    }
#endif /* HAVE_FFDHE_Q */

    /* --- _ffc_validate_public_key L1578/L1581: pub == p-2 (boundary pass) ---
     * p-2 satisfies y <= p-2 => wc_DhCheckPubKey should return 0.
     * Subtract 2 from the big-endian byte array working from the last byte. */
    {
        byte pMinus2[256];
        int  borrow, idx;
        XMEMCPY(pMinus2, pBuf, pSz);
        borrow = 2;
        idx = (int)pSz - 1;
        while (idx >= 0 && borrow > 0) {
            int v = (int)pMinus2[idx] - borrow;
            if (v < 0) { pMinus2[idx] = (byte)(v + 256); borrow = 1; }
            else        { pMinus2[idx] = (byte)v;         borrow = 0; }
            idx--;
        }
        /* y == p-2: exactly on the valid upper boundary => should pass */
        ExpectIntEQ(wc_DhCheckPubKey(&key, pMinus2, pSz), 0);

#ifdef HAVE_FFDHE_Q
        /* --- L1636 TRUE: y = p-2 is not in the FFDHE-2048 subgroup ---
         * Full order check via wc_DhCheckPubKey_ex must fail.          */
        if (qSz > 0) {
            ExpectIntEQ(wc_DhCheckPubKey_ex(&key, pMinus2, pSz, qBuf, qSz),
                        WC_NO_ERR_TRACE(MP_CMP_E));
        }
#endif /* HAVE_FFDHE_Q */
    }

#ifdef HAVE_FFDHE_Q
    /* --- L1636 FALSE: legitimately generated pub key is in the subgroup --- */
    if (qSz > 0) {
        DhKey  key2;
        WC_RNG rng2;
        byte   priv2[32], pub2[256];
        word32 priv2Sz = sizeof(priv2), pub2Sz = sizeof(pub2);

        XMEMSET(&key2, 0, sizeof(DhKey));
        XMEMSET(&rng2, 0, sizeof(WC_RNG));
        ExpectIntEQ(wc_InitRng(&rng2), 0);
        ExpectIntEQ(wc_InitDhKey(&key2), 0);
        ExpectIntEQ(wc_DhSetKey_ex(&key2, pBuf, pSz, gBuf, gSz,
                                   qBuf, qSz), 0);
        priv2Sz = sizeof(priv2); pub2Sz = sizeof(pub2);
        ExpectIntEQ(wc_DhGenerateKeyPair(&key2, &rng2,
                                         priv2, &priv2Sz,
                                         pub2,  &pub2Sz), 0);
        /* y^q mod p == 1 for a legitimate DH public key => pass */
        ExpectIntEQ(wc_DhCheckPubKey_ex(&key2, pub2, pub2Sz, qBuf, qSz), 0);

        DoExpectIntEQ(wc_FreeRng(&rng2), 0);
        DoExpectIntEQ(wc_FreeDhKey(&key2), 0);
    }
#endif /* HAVE_FFDHE_Q */

    DoExpectIntEQ(wc_FreeDhKey(&key), 0);
#endif /* HAVE_FFDHE_2048 */
#endif /* !NO_DH && !HAVE_FIPS && !HAVE_SELFTEST */
    return EXPECT_RESULT();
}
