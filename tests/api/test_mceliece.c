/* test_mceliece.c
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

#ifdef WOLFSSL_HAVE_MCELIECE
    #include <wolfssl/wolfcrypt/wc_mceliece.h>
    /* Internal header: exposes McElieceParams so the implicit-rejection tests
     * can read params->sBytes (the trailing private-key value s), which has no
     * public accessor. */
    #include <wolfssl/wolfcrypt/wc_mceliece_mat.h>
#endif
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_mceliece.h>

#ifdef WOLFSSL_HAVE_MCELIECE

/* Under WC_NO_CONSTRUCTORS the wc_McElieceKey_New/_Delete helpers are not
 * built, but the tests below use them throughout. Provide thin test-local
 * shims over Init/Free that mirror the real semantics (see wc_McElieceKey_New
 * and wc_McElieceKey_Delete in wolfcrypt/src/wc_mceliece.c). */
#ifdef WC_NO_CONSTRUCTORS
static McElieceKey* wc_McElieceKey_New(int type, void* heap, int devId)
{
    McElieceKey* key = (McElieceKey*)XMALLOC(sizeof(McElieceKey), heap,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (key != NULL) {
        if (wc_McElieceKey_Init(key, type, heap, devId) != 0) {
            XFREE(key, heap, DYNAMIC_TYPE_TMP_BUFFER);
            key = NULL;
        }
    }
    return key;
}
static int wc_McElieceKey_Delete(McElieceKey* key, McElieceKey** key_p)
{
    int ret = 0;
    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        void* heap = key->heap;
        wc_McElieceKey_Free(key);
        XFREE(key, heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (key_p != NULL) {
            *key_p = NULL;
        }
    }
    return ret;
}
#endif /* WC_NO_CONSTRUCTORS */

/* A variant is compiled in only when its base parameter set is enabled AND its
 * form (plain / f / pc / pcf) is not disabled - this mirrors exactly what
 * wc_mceliece_get_params() accepts. Gating the test tables on the base alone
 * (as before) referenced disabled forms, whose wc_McElieceKey_New() returns
 * NULL, failing every test in a form-restricted build (e.g. f-only). */
#ifndef WOLFSSL_MCELIECE_NO_PLAIN
    #define MCELIECE_FORM_PLAIN
#endif
#ifndef WOLFSSL_MCELIECE_NO_F
    #define MCELIECE_FORM_F
#endif
#ifndef WOLFSSL_MCELIECE_NO_PC
    #define MCELIECE_FORM_PC
#endif
#ifndef WOLFSSL_MCELIECE_NO_PCF
    #define MCELIECE_FORM_PCF
#endif

/* Reference known-answer vectors for the KAT tests below. Included after the
 * MCELIECE_FORM_* macros as the per-set vectors are gated on the plain form; the
 * vectors within are further gated per operation (decapsulate / make-key), so
 * only the arrays a compiled-in KAT table references are defined. */
#include <tests/api/test_mceliece_kats.h>

#ifndef WOLFSSL_MCELIECE_NO_DECAPSULATE
/* One decapsulation conformance KAT: the reference private key and ciphertext
 * for a compiled-in plain-form parameter set, plus the expected shared secret. */
typedef struct McElieceDecKat {
    int         type;
    const byte* sk;
    word32      skLen;
    const byte* ct;
    word32      ctLen;
    const byte* ss;
    word32      ssLen;
} McElieceDecKat;

#define MCELIECE_DEC_KAT(bits, t)                                              \
    { (t), mceliece_kat_##bits##_dec_sk,                                       \
      (word32)sizeof(mceliece_kat_##bits##_dec_sk),                            \
      mceliece_kat_##bits##_dec_ct,                                            \
      (word32)sizeof(mceliece_kat_##bits##_dec_ct),                            \
      mceliece_kat_##bits##_dec_ss,                                            \
      (word32)sizeof(mceliece_kat_##bits##_dec_ss) },

static const McElieceDecKat mceliece_dec_kats[] = {
#if defined(WOLFSSL_WC_MCELIECE_6688128) && defined(MCELIECE_FORM_PLAIN)
    MCELIECE_DEC_KAT(6688128, WC_MCELIECE_6688128)
#endif
#if defined(WOLFSSL_WC_MCELIECE_6960119) && defined(MCELIECE_FORM_PLAIN)
    MCELIECE_DEC_KAT(6960119, WC_MCELIECE_6960119)
#endif
#if defined(WOLFSSL_WC_MCELIECE_8192128) && defined(MCELIECE_FORM_PLAIN)
    MCELIECE_DEC_KAT(8192128, WC_MCELIECE_8192128)
#endif
    { 0, NULL, 0, NULL, 0, NULL, 0 } /* sentinel so the array is never empty */
};
#define MCELIECE_DEC_KAT_CNT \
    ((int)(sizeof(mceliece_dec_kats) / sizeof(mceliece_dec_kats[0])) - 1)
#endif /* !WOLFSSL_MCELIECE_NO_DECAPSULATE */

#ifndef WOLFSSL_MCELIECE_NO_MAKE_KEY
/* One keygen + encapsulation regression KAT: the delta seed that drives keygen
 * (with the expected SHA-256 digests of the encoded public and private keys),
 * and the fixed encapsulation randomness (with the expected ciphertext and
 * shared secret). These are generated from this implementation, not an external
 * reference - see the header for why. */
typedef struct McElieceKeKat {
    int         type;
    const byte* delta;
    word32      deltaLen;
    const byte* hpk;    /* SHA-256 of the encoded public key.  */
    const byte* hsk;    /* SHA-256 of the encoded private key. */
    const byte* rand;
    word32      randLen;
    const byte* ct;
    word32      ctLen;
    const byte* ss;
    word32      ssLen;
} McElieceKeKat;

#define MCELIECE_KE_KAT(bits, t)                                               \
    { (t), mceliece_kat_##bits##_kg_delta,                                     \
      (word32)sizeof(mceliece_kat_##bits##_kg_delta),                          \
      mceliece_kat_##bits##_kg_hpk, mceliece_kat_##bits##_kg_hsk,              \
      mceliece_kat_##bits##_enc_rand,                                          \
      (word32)sizeof(mceliece_kat_##bits##_enc_rand),                          \
      mceliece_kat_##bits##_enc_ct,                                            \
      (word32)sizeof(mceliece_kat_##bits##_enc_ct),                            \
      mceliece_kat_##bits##_enc_ss,                                            \
      (word32)sizeof(mceliece_kat_##bits##_enc_ss) },

static const McElieceKeKat mceliece_ke_kats[] = {
#if defined(WOLFSSL_WC_MCELIECE_6688128) && defined(MCELIECE_FORM_PLAIN)
    MCELIECE_KE_KAT(6688128, WC_MCELIECE_6688128)
#endif
#if defined(WOLFSSL_WC_MCELIECE_6960119) && defined(MCELIECE_FORM_PLAIN)
    MCELIECE_KE_KAT(6960119, WC_MCELIECE_6960119)
#endif
#if defined(WOLFSSL_WC_MCELIECE_8192128) && defined(MCELIECE_FORM_PLAIN)
    MCELIECE_KE_KAT(8192128, WC_MCELIECE_8192128)
#endif
    { 0, NULL, 0, NULL, NULL, NULL, 0, NULL, 0, NULL, 0 } /* sentinel */
};
#define MCELIECE_KE_KAT_CNT \
    ((int)(sizeof(mceliece_ke_kats) / sizeof(mceliece_ke_kats[0])) - 1)
#endif /* !WOLFSSL_MCELIECE_NO_MAKE_KEY */

/* The set of compiled-in key types, used to drive the functional tests. */
static const int mceliece_types[] = {
#ifdef WOLFSSL_WC_MCELIECE_6688128
    #ifdef MCELIECE_FORM_PLAIN
    WC_MCELIECE_6688128,
    #endif
    #ifdef MCELIECE_FORM_F
    WC_MCELIECE_6688128F,
    #endif
    #ifdef MCELIECE_FORM_PC
    WC_MCELIECE_6688128PC,
    #endif
    #ifdef MCELIECE_FORM_PCF
    WC_MCELIECE_6688128PCF,
    #endif
#endif
#ifdef WOLFSSL_WC_MCELIECE_6960119
    #ifdef MCELIECE_FORM_PLAIN
    WC_MCELIECE_6960119,
    #endif
    #ifdef MCELIECE_FORM_F
    WC_MCELIECE_6960119F,
    #endif
    #ifdef MCELIECE_FORM_PC
    WC_MCELIECE_6960119PC,
    #endif
    #ifdef MCELIECE_FORM_PCF
    WC_MCELIECE_6960119PCF,
    #endif
#endif
#ifdef WOLFSSL_WC_MCELIECE_8192128
    #ifdef MCELIECE_FORM_PLAIN
    WC_MCELIECE_8192128,
    #endif
    #ifdef MCELIECE_FORM_F
    WC_MCELIECE_8192128F,
    #endif
    #ifdef MCELIECE_FORM_PC
    WC_MCELIECE_8192128PC,
    #endif
    #ifdef MCELIECE_FORM_PCF
    WC_MCELIECE_8192128PCF,
    #endif
#endif
    0 /* sentinel so the array is never empty */
};
#define MCELIECE_TYPE_CNT \
    ((int)(sizeof(mceliece_types) / sizeof(mceliece_types[0])) - 1)

/* A representative compiled variant for single-set tests: first available of
 * (base x form). At least one is compiled whenever the feature is enabled. */
#if   defined(WOLFSSL_WC_MCELIECE_6688128) && defined(MCELIECE_FORM_PLAIN)
    #define MCELIECE_T0     WC_MCELIECE_6688128
#elif defined(WOLFSSL_WC_MCELIECE_6688128) && defined(MCELIECE_FORM_F)
    #define MCELIECE_T0     WC_MCELIECE_6688128F
#elif defined(WOLFSSL_WC_MCELIECE_6688128) && defined(MCELIECE_FORM_PC)
    #define MCELIECE_T0     WC_MCELIECE_6688128PC
#elif defined(WOLFSSL_WC_MCELIECE_6688128) && defined(MCELIECE_FORM_PCF)
    #define MCELIECE_T0     WC_MCELIECE_6688128PCF
#elif defined(WOLFSSL_WC_MCELIECE_6960119) && defined(MCELIECE_FORM_PLAIN)
    #define MCELIECE_T0     WC_MCELIECE_6960119
#elif defined(WOLFSSL_WC_MCELIECE_6960119) && defined(MCELIECE_FORM_F)
    #define MCELIECE_T0     WC_MCELIECE_6960119F
#elif defined(WOLFSSL_WC_MCELIECE_6960119) && defined(MCELIECE_FORM_PC)
    #define MCELIECE_T0     WC_MCELIECE_6960119PC
#elif defined(WOLFSSL_WC_MCELIECE_6960119) && defined(MCELIECE_FORM_PCF)
    #define MCELIECE_T0     WC_MCELIECE_6960119PCF
#elif defined(WOLFSSL_WC_MCELIECE_8192128) && defined(MCELIECE_FORM_PLAIN)
    #define MCELIECE_T0     WC_MCELIECE_8192128
#elif defined(WOLFSSL_WC_MCELIECE_8192128) && defined(MCELIECE_FORM_F)
    #define MCELIECE_T0     WC_MCELIECE_8192128F
#elif defined(WOLFSSL_WC_MCELIECE_8192128) && defined(MCELIECE_FORM_PC)
    #define MCELIECE_T0     WC_MCELIECE_8192128PC
#elif defined(WOLFSSL_WC_MCELIECE_8192128) && defined(MCELIECE_FORM_PCF)
    #define MCELIECE_T0     WC_MCELIECE_8192128PCF
#endif

/* A representative plaintext-confirmation (pc or pcf) variant, if any is
 * compiled; tests that need one gate on MCELIECE_T0_PC being defined. */
#if   defined(WOLFSSL_WC_MCELIECE_6688128) && defined(MCELIECE_FORM_PC)
    #define MCELIECE_T0_PC  WC_MCELIECE_6688128PC
#elif defined(WOLFSSL_WC_MCELIECE_6688128) && defined(MCELIECE_FORM_PCF)
    #define MCELIECE_T0_PC  WC_MCELIECE_6688128PCF
#elif defined(WOLFSSL_WC_MCELIECE_6960119) && defined(MCELIECE_FORM_PC)
    #define MCELIECE_T0_PC  WC_MCELIECE_6960119PC
#elif defined(WOLFSSL_WC_MCELIECE_6960119) && defined(MCELIECE_FORM_PCF)
    #define MCELIECE_T0_PC  WC_MCELIECE_6960119PCF
#elif defined(WOLFSSL_WC_MCELIECE_8192128) && defined(MCELIECE_FORM_PC)
    #define MCELIECE_T0_PC  WC_MCELIECE_8192128PC
#elif defined(WOLFSSL_WC_MCELIECE_8192128) && defined(MCELIECE_FORM_PCF)
    #define MCELIECE_T0_PC  WC_MCELIECE_8192128PCF
#endif

#endif /* WOLFSSL_HAVE_MCELIECE */

/* keygen->encap->decap round trip over every compiled variant. */
int test_wc_mceliece_roundtrip(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_MCELIECE) && !defined(WC_NO_RNG) && \
    !defined(WOLFSSL_MCELIECE_NO_MAKE_KEY) && \
    !defined(WOLFSSL_MCELIECE_NO_ENCAPSULATE) && \
    !defined(WOLFSSL_MCELIECE_NO_DECAPSULATE)
    int i;
    McElieceKey* key = NULL;
    WC_RNG rng;
    byte ct[MCELIECE_MAX_CIPHER_TEXT_SIZE];
    byte ss[MCELIECE_SS_SZ];
    byte ssDec[MCELIECE_SS_SZ];
    word32 ctLen = 0;
    word32 ssLen = 0;
    int rngInit = 0;

    XMEMSET(&rng, 0, sizeof(rng));
    ExpectIntEQ(wc_InitRng(&rng), 0);
    if (EXPECT_SUCCESS()) {
        rngInit = 1;
    }

    for (i = 0; (i < MCELIECE_TYPE_CNT) && EXPECT_SUCCESS(); i++) {
        key = wc_McElieceKey_New(mceliece_types[i], NULL, INVALID_DEVID);
        ExpectNotNull(key);
        ExpectIntEQ(wc_McElieceKey_CipherTextSize(key, &ctLen), 0);
        ExpectIntEQ(wc_McElieceKey_SharedSecretSize(key, &ssLen), 0);
        /* Pin the reported length: a regression returning 0 would make the
         * XMEMCMP below trivially pass for a zero-length compare. */
        ExpectIntEQ(ssLen, MCELIECE_SS_SZ);
        ExpectIntEQ(wc_McElieceKey_MakeKey(key, &rng), 0);
        ExpectIntEQ(wc_McElieceKey_Encapsulate(key, ct, ss, &rng), 0);
        ExpectIntEQ(wc_McElieceKey_Decapsulate(key, ssDec, ct, ctLen), 0);
        ExpectIntEQ(XMEMCMP(ss, ssDec, ssLen), 0);
        wc_McElieceKey_Delete(key, &key);
    }

    if (rngInit) {
        DoExpectIntEQ(wc_FreeRng(&rng), 0);
    }
#endif
    return EXPECT_RESULT();
}

/* Export the public and private keys, import them into a fresh key, and check
 * an encapsulation to the decoded public key is decapsulated by the decoded
 * private key. */
int test_wc_mceliece_encode_decode(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_MCELIECE) && !defined(WC_NO_RNG) && \
    !defined(WOLFSSL_MCELIECE_NO_MAKE_KEY) && \
    !defined(WOLFSSL_MCELIECE_NO_ENCAPSULATE) && \
    !defined(WOLFSSL_MCELIECE_NO_DECAPSULATE)
    McElieceKey* key = NULL;
    McElieceKey* key2 = NULL;
    WC_RNG rng;
    byte* pub = NULL;
    byte* priv = NULL;
    byte ct[MCELIECE_MAX_CIPHER_TEXT_SIZE];
    byte ss[MCELIECE_SS_SZ];
    byte ssDec[MCELIECE_SS_SZ];
    word32 pubLen = 0;
    word32 privLen = 0;
    word32 ctLen = 0;
    int rngInit = 0;

    XMEMSET(&rng, 0, sizeof(rng));
    pub = (byte*)XMALLOC(MCELIECE_MAX_PUBLIC_KEY_SIZE, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(pub);
    priv = (byte*)XMALLOC(MCELIECE_MAX_PRIVATE_KEY_SIZE, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(priv);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    if (EXPECT_SUCCESS()) {
        rngInit = 1;
    }

    key = wc_McElieceKey_New(MCELIECE_T0, NULL, INVALID_DEVID);
    ExpectNotNull(key);
    ExpectIntEQ(wc_McElieceKey_PublicKeySize(key, &pubLen), 0);
    ExpectIntEQ(wc_McElieceKey_PrivateKeySize(key, &privLen), 0);
    ExpectIntEQ(wc_McElieceKey_CipherTextSize(key, &ctLen), 0);
    ExpectIntEQ(wc_McElieceKey_MakeKey(key, &rng), 0);
    ExpectIntEQ(wc_McElieceKey_EncodePublicKey(key, pub, pubLen), 0);
    ExpectIntEQ(wc_McElieceKey_EncodePrivateKey(key, priv, privLen), 0);

    key2 = wc_McElieceKey_New(MCELIECE_T0, NULL, INVALID_DEVID);
    ExpectNotNull(key2);
    ExpectIntEQ(wc_McElieceKey_DecodePublicKey(key2, pub, pubLen), 0);
    ExpectIntEQ(wc_McElieceKey_DecodePrivateKey(key2, priv, privLen), 0);
    ExpectIntEQ(wc_McElieceKey_Encapsulate(key2, ct, ss, &rng), 0);
    ExpectIntEQ(wc_McElieceKey_Decapsulate(key2, ssDec, ct, ctLen), 0);
    ExpectIntEQ(XMEMCMP(ss, ssDec, MCELIECE_SS_SZ), 0);

    wc_McElieceKey_Delete(key2, &key2);
    wc_McElieceKey_Delete(key, &key);
    if (rngInit) {
        DoExpectIntEQ(wc_FreeRng(&rng), 0);
    }
    XFREE(pub, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(priv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}

/* KAT: decapsulation against the reference implementation. For each compiled
 * plain-form parameter set, decode the reference private key, decapsulate the
 * reference ciphertext and check the shared secret matches byte-for-byte. This
 * exercises the whole decode path - private-key parse, syndrome, Berlekamp-
 * Massey, error location and the Fujisaki-Okamoto hash / implicit rejection -
 * against the official Classic McEliece NIST-submission vectors, catching a
 * deterministic-but-non-interoperable implementation that the self-consistency
 * tests could not. Vectors are in test_mceliece_kats.h. */
int test_wc_mceliece_kat_decap(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_MCELIECE) && !defined(WOLFSSL_MCELIECE_NO_DECAPSULATE)
    int i;
    McElieceKey* key = NULL;
    byte ss[MCELIECE_SS_SZ];
    word32 ssLen = 0;

    for (i = 0; (i < MCELIECE_DEC_KAT_CNT) && EXPECT_SUCCESS(); i++) {
        const McElieceDecKat* k = &mceliece_dec_kats[i];

        key = wc_McElieceKey_New(k->type, NULL, INVALID_DEVID);
        ExpectNotNull(key);
        ExpectIntEQ(wc_McElieceKey_SharedSecretSize(key, &ssLen), 0);
        /* Pin the reported length so the XMEMCMP below is a full compare and a
         * regression to 0 cannot make it trivially pass. */
        ExpectIntEQ(ssLen, MCELIECE_SS_SZ);
        ExpectIntEQ(ssLen, k->ssLen);
        ExpectIntEQ(wc_McElieceKey_DecodePrivateKey(key, k->sk, k->skLen), 0);
        ExpectIntEQ(wc_McElieceKey_Decapsulate(key, ss, k->ct, k->ctLen), 0);
        ExpectIntEQ(XMEMCMP(ss, k->ss, ssLen), 0);
        wc_McElieceKey_Delete(key, &key);
    }
#endif
    return EXPECT_RESULT();
}

/* KAT: key generation and encapsulation regression against this implementation.
 * For each compiled plain-form parameter set: run SeededKeyGen from the fixed
 * delta and check the SHA-256 digests of the encoded public and private keys;
 * then encapsulate from the fixed randomness and check the ciphertext and shared
 * secret; then decapsulate that ciphertext back to the same secret. Unlike the
 * decapsulation KAT above (official reference vectors), these vectors are
 * generated from wolfSSL and pin its keygen/encap output against regressions -
 * the reference KAT rng could not be reproduced for these paths. Vectors are in
 * test_mceliece_kats.h. */
int test_wc_mceliece_kat_keygen_encap(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_MCELIECE) && !defined(WOLFSSL_MCELIECE_NO_MAKE_KEY)
    int i;
    McElieceKey* key = NULL;
    byte* pub = NULL;
    byte* priv = NULL;
    word32 pubLen = 0;
    word32 privLen = 0;
#ifndef NO_SHA256
    byte hash[WC_SHA256_DIGEST_SIZE];
#endif
#ifndef WOLFSSL_MCELIECE_NO_ENCAPSULATE
    byte ct[MCELIECE_MAX_CIPHER_TEXT_SIZE];
    byte ss[MCELIECE_SS_SZ];
    word32 ctLen = 0;
#ifndef WOLFSSL_MCELIECE_NO_DECAPSULATE
    byte ssDec[MCELIECE_SS_SZ];
#endif
#endif

    pub = (byte*)XMALLOC(MCELIECE_MAX_PUBLIC_KEY_SIZE, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(pub);
    priv = (byte*)XMALLOC(MCELIECE_MAX_PRIVATE_KEY_SIZE, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(priv);

    for (i = 0; (i < MCELIECE_KE_KAT_CNT) && EXPECT_SUCCESS(); i++) {
        const McElieceKeKat* k = &mceliece_ke_kats[i];

        key = wc_McElieceKey_New(k->type, NULL, INVALID_DEVID);
        ExpectNotNull(key);
        /* Key generation from the fixed delta seed. */
        ExpectIntEQ(wc_McElieceKey_MakeKeyWithRandom(key, k->delta,
            (int)k->deltaLen), 0);
        ExpectIntEQ(wc_McElieceKey_PublicKeySize(key, &pubLen), 0);
        ExpectIntEQ(wc_McElieceKey_PrivateKeySize(key, &privLen), 0);
        ExpectIntEQ(wc_McElieceKey_EncodePublicKey(key, pub, pubLen), 0);
        ExpectIntEQ(wc_McElieceKey_EncodePrivateKey(key, priv, privLen), 0);
    #ifndef NO_SHA256
        /* Encoded public and private keys hash to the pinned digests. */
        ExpectIntEQ(wc_Sha256Hash(pub, pubLen, hash), 0);
        ExpectIntEQ(XMEMCMP(hash, k->hpk, WC_SHA256_DIGEST_SIZE), 0);
        ExpectIntEQ(wc_Sha256Hash(priv, privLen, hash), 0);
        ExpectIntEQ(XMEMCMP(hash, k->hsk, WC_SHA256_DIGEST_SIZE), 0);
    #endif
    #ifndef WOLFSSL_MCELIECE_NO_ENCAPSULATE
        /* Encapsulation from the fixed randomness yields the pinned ct and ss. */
        ExpectIntEQ(wc_McElieceKey_CipherTextSize(key, &ctLen), 0);
        ExpectIntEQ(ctLen, k->ctLen);
        ExpectIntEQ(wc_McElieceKey_EncapsulateWithRandom(key, ct, ss, k->rand,
            (int)k->randLen), 0);
        ExpectIntEQ(XMEMCMP(ct, k->ct, k->ctLen), 0);
        ExpectIntEQ(XMEMCMP(ss, k->ss, k->ssLen), 0);
    #ifndef WOLFSSL_MCELIECE_NO_DECAPSULATE
        /* And that ciphertext decapsulates back to the same secret. */
        ExpectIntEQ(wc_McElieceKey_Decapsulate(key, ssDec, ct, ctLen), 0);
        ExpectIntEQ(XMEMCMP(ssDec, k->ss, k->ssLen), 0);
    #endif
    #endif
        wc_McElieceKey_Delete(key, &key);
    }

    XFREE(pub, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(priv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}

/* SeededKeyGen is deterministic: the same delta seed yields byte-identical
 * public and private keys. */
int test_wc_mceliece_make_key_deterministic(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_MCELIECE) && \
    !defined(WOLFSSL_MCELIECE_NO_MAKE_KEY)
    McElieceKey* key = NULL;
    McElieceKey* key2 = NULL;
    byte* pub1 = NULL;
    byte* pub2 = NULL;
    byte* priv1 = NULL;
    byte* priv2 = NULL;
    word32 pubLen = 0;
    word32 privLen = 0;
    int i;
    byte delta[MCELIECE_SEED_SZ];

    for (i = 0; i < MCELIECE_SEED_SZ; i++) {
        delta[i] = (byte)i;
    }

    pub1 = (byte*)XMALLOC(MCELIECE_MAX_PUBLIC_KEY_SIZE, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    pub2 = (byte*)XMALLOC(MCELIECE_MAX_PUBLIC_KEY_SIZE, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    priv1 = (byte*)XMALLOC(MCELIECE_MAX_PRIVATE_KEY_SIZE, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    priv2 = (byte*)XMALLOC(MCELIECE_MAX_PRIVATE_KEY_SIZE, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(pub1);
    ExpectNotNull(pub2);
    ExpectNotNull(priv1);
    ExpectNotNull(priv2);

    key = wc_McElieceKey_New(MCELIECE_T0, NULL, INVALID_DEVID);
    ExpectNotNull(key);
    ExpectIntEQ(wc_McElieceKey_PublicKeySize(key, &pubLen), 0);
    ExpectIntEQ(wc_McElieceKey_PrivateKeySize(key, &privLen), 0);
    ExpectIntEQ(wc_McElieceKey_MakeKeyWithRandom(key, delta,
        MCELIECE_SEED_SZ), 0);
    ExpectIntEQ(wc_McElieceKey_EncodePublicKey(key, pub1, pubLen), 0);
    ExpectIntEQ(wc_McElieceKey_EncodePrivateKey(key, priv1, privLen), 0);

    key2 = wc_McElieceKey_New(MCELIECE_T0, NULL, INVALID_DEVID);
    ExpectNotNull(key2);
    ExpectIntEQ(wc_McElieceKey_MakeKeyWithRandom(key2, delta,
        MCELIECE_SEED_SZ), 0);
    ExpectIntEQ(wc_McElieceKey_EncodePublicKey(key2, pub2, pubLen), 0);
    ExpectIntEQ(wc_McElieceKey_EncodePrivateKey(key2, priv2, privLen), 0);

    ExpectIntEQ(XMEMCMP(pub1, pub2, pubLen), 0);
    ExpectIntEQ(XMEMCMP(priv1, priv2, privLen), 0);

    wc_McElieceKey_Delete(key2, &key2);
    wc_McElieceKey_Delete(key, &key);
    XFREE(pub1, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(pub2, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(priv1, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(priv2, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}

/* Encapsulation from a fixed randomness buffer is deterministic, and the
 * resulting ciphertext decapsulates to the same shared secret. */
int test_wc_mceliece_encapsulate_deterministic(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_MCELIECE) && !defined(WC_NO_RNG) && \
    !defined(WOLFSSL_MCELIECE_NO_MAKE_KEY) && \
    !defined(WOLFSSL_MCELIECE_NO_ENCAPSULATE) && \
    !defined(WOLFSSL_MCELIECE_NO_DECAPSULATE)
    McElieceKey* key = NULL;
    WC_RNG rng;
    byte ct1[MCELIECE_MAX_CIPHER_TEXT_SIZE];
    byte ct2[MCELIECE_MAX_CIPHER_TEXT_SIZE];
    byte ss1[MCELIECE_SS_SZ];
    byte ss2[MCELIECE_SS_SZ];
    byte ssDec[MCELIECE_SS_SZ];
    byte* rand = NULL;
    const int randLen = 8192;
    word32 ctLen = 0;
    int i;
    int rngInit = 0;

    XMEMSET(&rng, 0, sizeof(rng));
    rand = (byte*)XMALLOC(randLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(rand);
    if (rand != NULL) {
        /* Deterministic but well-distributed fill (xorshift32) so FixedWeight
         * finds a valid weight-t error vector quickly. */
        word32 x = 0x12345678u;

        for (i = 0; i < randLen; i++) {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            rand[i] = (byte)x;
        }
    }
    ExpectIntEQ(wc_InitRng(&rng), 0);
    if (EXPECT_SUCCESS()) {
        rngInit = 1;
    }

    key = wc_McElieceKey_New(MCELIECE_T0, NULL, INVALID_DEVID);
    ExpectNotNull(key);
    ExpectIntEQ(wc_McElieceKey_CipherTextSize(key, &ctLen), 0);
    ExpectIntEQ(wc_McElieceKey_MakeKey(key, &rng), 0);

    ExpectIntEQ(wc_McElieceKey_EncapsulateWithRandom(key, ct1, ss1, rand,
        randLen), 0);
    ExpectIntEQ(wc_McElieceKey_EncapsulateWithRandom(key, ct2, ss2, rand,
        randLen), 0);
    ExpectIntEQ(XMEMCMP(ct1, ct2, ctLen), 0);
    ExpectIntEQ(XMEMCMP(ss1, ss2, MCELIECE_SS_SZ), 0);

    ExpectIntEQ(wc_McElieceKey_Decapsulate(key, ssDec, ct1, ctLen), 0);
    ExpectIntEQ(XMEMCMP(ss1, ssDec, MCELIECE_SS_SZ), 0);

    wc_McElieceKey_Delete(key, &key);
    if (rngInit) {
        DoExpectIntEQ(wc_FreeRng(&rng), 0);
    }
    XFREE(rand, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}

/* For a pc (plaintext confirmation) variant, corrupting the confirmation hash
 * C1 must trigger implicit rejection: decapsulation succeeds but yields a
 * shared secret different from the encapsulated one. */
int test_wc_mceliece_decap_pc_reject(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_MCELIECE) && !defined(WC_NO_RNG) && \
    !defined(WOLFSSL_MCELIECE_NO_MAKE_KEY) && \
    !defined(WOLFSSL_MCELIECE_NO_ENCAPSULATE) && \
    !defined(WOLFSSL_MCELIECE_NO_DECAPSULATE) && defined(MCELIECE_T0_PC)
    McElieceKey* key = NULL;
    WC_RNG rng;
    byte ct[MCELIECE_MAX_CIPHER_TEXT_SIZE];
    byte ss[MCELIECE_SS_SZ];
    byte ssBad[MCELIECE_SS_SZ];
    byte expected[MCELIECE_SS_SZ];
    byte* priv = NULL;
    const byte* s = NULL;
    wc_Shake shake;
    byte prefix = 0x00;
    word32 ctLen = 0;
    word32 privLen = 0;
    word32 sBytes = 0;
    int rngInit = 0;
    int shakeInit = 0;

    XMEMSET(&rng, 0, sizeof(rng));
    priv = (byte*)XMALLOC(MCELIECE_MAX_PRIVATE_KEY_SIZE, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(priv);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    if (EXPECT_SUCCESS()) {
        rngInit = 1;
    }

    key = wc_McElieceKey_New(MCELIECE_T0_PC, NULL, INVALID_DEVID);
    ExpectNotNull(key);
    ExpectIntEQ(wc_McElieceKey_CipherTextSize(key, &ctLen), 0);
    ExpectIntEQ(wc_McElieceKey_MakeKey(key, &rng), 0);
    ExpectIntEQ(wc_McElieceKey_Encapsulate(key, ct, ss, &rng), 0);

    /* Flip a bit in the trailing confirmation hash C1. */
    if (EXPECT_SUCCESS()) {
        ct[ctLen - 1] ^= 0x01;
    }
    ExpectIntEQ(wc_McElieceKey_Decapsulate(key, ssBad, ct, ctLen), 0);
    ExpectIntNE(XMEMCMP(ss, ssBad, MCELIECE_SS_SZ), 0);

    /* Pin the EXACT implicit-rejection secret: SHAKE256(0x00 || s || ct), where
     * s is the trailing sBytes of the encoded private key and ct is the
     * corrupted ciphertext. The ExpectIntNE above only proves ssBad changed -
     * which any altered ct byte causes since the whole ct is hashed into the
     * secret - so it would still pass if the pc check were removed. This check
     * proves the pc mismatch actually drove decapsulation onto the reject
     * path. */
    ExpectIntEQ(wc_McElieceKey_PrivateKeySize(key, &privLen), 0);
    ExpectIntEQ(wc_McElieceKey_EncodePrivateKey(key, priv, privLen), 0);
    if (EXPECT_SUCCESS()) {
        sBytes = key->params->sBytes;
        s = priv + (privLen - sBytes);
    }
    ExpectIntEQ(wc_InitShake256(&shake, NULL, INVALID_DEVID), 0);
    if (EXPECT_SUCCESS()) {
        shakeInit = 1;
    }
    ExpectIntEQ(wc_Shake256_Update(&shake, &prefix, 1), 0);
    ExpectIntEQ(wc_Shake256_Update(&shake, s, sBytes), 0);
    ExpectIntEQ(wc_Shake256_Update(&shake, ct, ctLen), 0);
    ExpectIntEQ(wc_Shake256_Final(&shake, expected, MCELIECE_SS_SZ), 0);
    ExpectIntEQ(XMEMCMP(ssBad, expected, MCELIECE_SS_SZ), 0);

    if (shakeInit) {
        wc_Shake256_Free(&shake);
    }
    wc_McElieceKey_Delete(key, &key);
    if (rngInit) {
        DoExpectIntEQ(wc_FreeRng(&rng), 0);
    }
    XFREE(priv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}

/* Corrupting the syndrome C0 makes decoding fail its weight check, so
 * decapsulation must implicitly reject: it still returns success but yields a
 * shared secret unrelated to the original. Exercises the decode-failure path
 * for a plain (non-pc) variant. */
int test_wc_mceliece_decap_corrupt_reject(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_MCELIECE) && !defined(WC_NO_RNG) && \
    !defined(WOLFSSL_MCELIECE_NO_MAKE_KEY) && \
    !defined(WOLFSSL_MCELIECE_NO_ENCAPSULATE) && \
    !defined(WOLFSSL_MCELIECE_NO_DECAPSULATE)
    McElieceKey* key = NULL;
    WC_RNG rng;
    byte ct[MCELIECE_MAX_CIPHER_TEXT_SIZE];
    byte ss[MCELIECE_SS_SZ];
    byte ssBad[MCELIECE_SS_SZ];
    word32 ctLen = 0;
    int rngInit = 0;

    XMEMSET(&rng, 0, sizeof(rng));
    ExpectIntEQ(wc_InitRng(&rng), 0);
    if (EXPECT_SUCCESS()) {
        rngInit = 1;
    }

    key = wc_McElieceKey_New(MCELIECE_T0, NULL, INVALID_DEVID);
    ExpectNotNull(key);
    ExpectIntEQ(wc_McElieceKey_CipherTextSize(key, &ctLen), 0);
    ExpectIntEQ(wc_McElieceKey_MakeKey(key, &rng), 0);
    ExpectIntEQ(wc_McElieceKey_Encapsulate(key, ct, ss, &rng), 0);

    /* Flip a bit in the syndrome C0 (first ciphertext byte). */
    if (EXPECT_SUCCESS()) {
        ct[0] ^= 0x01;
    }
    /* Decapsulation succeeds (constant-time implicit rejection) but the shared
     * secret differs from the original. */
    ExpectIntEQ(wc_McElieceKey_Decapsulate(key, ssBad, ct, ctLen), 0);
    ExpectIntNE(XMEMCMP(ss, ssBad, MCELIECE_SS_SZ), 0);

    wc_McElieceKey_Delete(key, &key);
    if (rngInit) {
        DoExpectIntEQ(wc_FreeRng(&rng), 0);
    }
#endif
    return EXPECT_RESULT();
}

/* Implicit rejection must be DETERMINISTIC: by design the reject secret is
 * Hash(0, s, C), a pure function of the private value s and the ciphertext C,
 * so decapsulating the same corrupted ciphertext twice must yield the same
 * secret - proving the reject path draws no fresh randomness and reads no
 * uninitialised data - and that secret must differ from the valid one. Run
 * over every enabled variant. */
int test_wc_mceliece_decap_reject_deterministic(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_MCELIECE) && !defined(WC_NO_RNG) && \
    !defined(WOLFSSL_MCELIECE_NO_MAKE_KEY) && \
    !defined(WOLFSSL_MCELIECE_NO_ENCAPSULATE) && \
    !defined(WOLFSSL_MCELIECE_NO_DECAPSULATE)
    int i;
    McElieceKey* key = NULL;
    WC_RNG rng;
    byte ct[MCELIECE_MAX_CIPHER_TEXT_SIZE];
    byte ss[MCELIECE_SS_SZ];
    byte ssBad1[MCELIECE_SS_SZ];
    byte ssBad2[MCELIECE_SS_SZ];
    word32 ctLen = 0;
    int rngInit = 0;

    XMEMSET(&rng, 0, sizeof(rng));
    ExpectIntEQ(wc_InitRng(&rng), 0);
    if (EXPECT_SUCCESS()) {
        rngInit = 1;
    }

    for (i = 0; (i < MCELIECE_TYPE_CNT) && EXPECT_SUCCESS(); i++) {
        key = wc_McElieceKey_New(mceliece_types[i], NULL, INVALID_DEVID);
        ExpectNotNull(key);
        ExpectIntEQ(wc_McElieceKey_CipherTextSize(key, &ctLen), 0);
        ExpectIntEQ(wc_McElieceKey_MakeKey(key, &rng), 0);
        ExpectIntEQ(wc_McElieceKey_Encapsulate(key, ct, ss, &rng), 0);

        /* Corrupt the syndrome C0 so decoding fails its weight check. */
        if (EXPECT_SUCCESS()) {
            ct[0] ^= 0x01;
        }
        /* Two decapsulations of the identical corrupted ciphertext. */
        ExpectIntEQ(wc_McElieceKey_Decapsulate(key, ssBad1, ct, ctLen), 0);
        ExpectIntEQ(wc_McElieceKey_Decapsulate(key, ssBad2, ct, ctLen), 0);
        /* Reject is deterministic (ssBad1 == ssBad2) and unrelated to valid. */
        ExpectIntEQ(XMEMCMP(ssBad1, ssBad2, MCELIECE_SS_SZ), 0);
        ExpectIntNE(XMEMCMP(ss, ssBad1, MCELIECE_SS_SZ), 0);

        wc_McElieceKey_Delete(key, &key);
    }

    if (rngInit) {
        DoExpectIntEQ(wc_FreeRng(&rng), 0);
    }
#endif
    return EXPECT_RESULT();
}

/* Because the rejected secret is bound to the ciphertext (Hash(0, s, C)), two
 * DIFFERENT corrupted ciphertexts reject to two DIFFERENT secrets, and neither
 * matches the valid one. Guards against a reject path that ignores C. */
int test_wc_mceliece_decap_reject_distinct(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_MCELIECE) && !defined(WC_NO_RNG) && \
    !defined(WOLFSSL_MCELIECE_NO_MAKE_KEY) && \
    !defined(WOLFSSL_MCELIECE_NO_ENCAPSULATE) && \
    !defined(WOLFSSL_MCELIECE_NO_DECAPSULATE)
    McElieceKey* key = NULL;
    WC_RNG rng;
    byte ct1[MCELIECE_MAX_CIPHER_TEXT_SIZE];
    byte ct2[MCELIECE_MAX_CIPHER_TEXT_SIZE];
    byte ss[MCELIECE_SS_SZ];
    byte ssBad1[MCELIECE_SS_SZ];
    byte ssBad2[MCELIECE_SS_SZ];
    word32 ctLen = 0;
    int rngInit = 0;

    XMEMSET(&rng, 0, sizeof(rng));
    ExpectIntEQ(wc_InitRng(&rng), 0);
    if (EXPECT_SUCCESS()) {
        rngInit = 1;
    }

    key = wc_McElieceKey_New(MCELIECE_T0, NULL, INVALID_DEVID);
    ExpectNotNull(key);
    ExpectIntEQ(wc_McElieceKey_CipherTextSize(key, &ctLen), 0);
    ExpectIntEQ(wc_McElieceKey_MakeKey(key, &rng), 0);
    ExpectIntEQ(wc_McElieceKey_Encapsulate(key, ct1, ss, &rng), 0);

    /* Two distinct corruptions of the same valid ciphertext. */
    if (EXPECT_SUCCESS()) {
        XMEMCPY(ct2, ct1, ctLen);
        ct1[0] ^= 0x01;
        ct2[0] ^= 0x02;
    }
    ExpectIntEQ(wc_McElieceKey_Decapsulate(key, ssBad1, ct1, ctLen), 0);
    ExpectIntEQ(wc_McElieceKey_Decapsulate(key, ssBad2, ct2, ctLen), 0);
    ExpectIntNE(XMEMCMP(ssBad1, ssBad2, MCELIECE_SS_SZ), 0);
    ExpectIntNE(XMEMCMP(ss, ssBad1, MCELIECE_SS_SZ), 0);
    ExpectIntNE(XMEMCMP(ss, ssBad2, MCELIECE_SS_SZ), 0);

    wc_McElieceKey_Delete(key, &key);
    if (rngInit) {
        DoExpectIntEQ(wc_FreeRng(&rng), 0);
    }
#endif
    return EXPECT_RESULT();
}

/* A ciphertext whose C0 padding bits (the unused high bits of the last syndrome
 * byte, present only when mt is not a multiple of 8 - e.g. 6960119, mt=1547)
 * are non-zero must be implicitly rejected, even though decoding ignores those
 * bits. Exercises the padding branch of the constant-time reject mask. */
int test_wc_mceliece_decap_padding_reject(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_MCELIECE) && !defined(WC_NO_RNG) && \
    !defined(WOLFSSL_MCELIECE_NO_MAKE_KEY) && \
    !defined(WOLFSSL_MCELIECE_NO_ENCAPSULATE) && \
    !defined(WOLFSSL_MCELIECE_NO_DECAPSULATE) && \
    defined(WOLFSSL_WC_MCELIECE_6960119) && defined(MCELIECE_FORM_PLAIN)
    McElieceKey* key = NULL;
    WC_RNG rng;
    byte ct[MCELIECE_MAX_CIPHER_TEXT_SIZE];
    byte ss[MCELIECE_SS_SZ];
    byte ssBad[MCELIECE_SS_SZ];
    byte expected[MCELIECE_SS_SZ];
    byte* priv = NULL;
    const byte* s = NULL;
    wc_Shake shake;
    byte prefix = 0x00;
    word32 ctLen = 0;
    word32 privLen = 0;
    word32 sBytes = 0;
    int rngInit = 0;
    int shakeInit = 0;

    XMEMSET(&rng, 0, sizeof(rng));
    priv = (byte*)XMALLOC(MCELIECE_MAX_PRIVATE_KEY_SIZE, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(priv);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    if (EXPECT_SUCCESS()) {
        rngInit = 1;
    }

    key = wc_McElieceKey_New(WC_MCELIECE_6960119, NULL, INVALID_DEVID);
    ExpectNotNull(key);
    ExpectIntEQ(wc_McElieceKey_CipherTextSize(key, &ctLen), 0);
    ExpectIntEQ(wc_McElieceKey_MakeKey(key, &rng), 0);
    ExpectIntEQ(wc_McElieceKey_Encapsulate(key, ct, ss, &rng), 0);

    /* For the plain form the whole ciphertext is the syndrome C0. 6960119 has
     * mt=13*119=1547, 1547 & 7 == 3, so bit 3 of the last byte is the first
     * padding bit. Setting it must trigger implicit rejection. */
    if (EXPECT_SUCCESS()) {
        ct[ctLen - 1] |= (byte)0x08;
    }
    ExpectIntEQ(wc_McElieceKey_Decapsulate(key, ssBad, ct, ctLen), 0);
    ExpectIntNE(XMEMCMP(ss, ssBad, MCELIECE_SS_SZ), 0);

    /* Pin the EXACT implicit-rejection secret: SHAKE256(0x00 || s || ct), where
     * s is the trailing sBytes of the encoded private key and ct is the
     * corrupted ciphertext. The ExpectIntNE above only proves ssBad changed -
     * which any altered ct byte causes since the whole ct is hashed into the
     * secret - so it would still pass if the padding check were removed. This
     * check proves the non-zero padding bit actually drove decapsulation onto
     * the reject path. */
    ExpectIntEQ(wc_McElieceKey_PrivateKeySize(key, &privLen), 0);
    ExpectIntEQ(wc_McElieceKey_EncodePrivateKey(key, priv, privLen), 0);
    if (EXPECT_SUCCESS()) {
        sBytes = key->params->sBytes;
        s = priv + (privLen - sBytes);
    }
    ExpectIntEQ(wc_InitShake256(&shake, NULL, INVALID_DEVID), 0);
    if (EXPECT_SUCCESS()) {
        shakeInit = 1;
    }
    ExpectIntEQ(wc_Shake256_Update(&shake, &prefix, 1), 0);
    ExpectIntEQ(wc_Shake256_Update(&shake, s, sBytes), 0);
    ExpectIntEQ(wc_Shake256_Update(&shake, ct, ctLen), 0);
    ExpectIntEQ(wc_Shake256_Final(&shake, expected, MCELIECE_SS_SZ), 0);
    ExpectIntEQ(XMEMCMP(ssBad, expected, MCELIECE_SS_SZ), 0);

    if (shakeInit) {
        wc_Shake256_Free(&shake);
    }
    wc_McElieceKey_Delete(key, &key);
    if (rngInit) {
        DoExpectIntEQ(wc_FreeRng(&rng), 0);
    }
    XFREE(priv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}

/* FixedWeight draws tau samples per attempt, and tau = t (not 2t) when n == q -
 * which holds only for mceliece8192128. So one attempt is exactly 2*t bytes of
 * randomness, not 4t. Feed 128 distinct 13-bit samples (0..127, all < n): a
 * single 2*t-byte attempt must succeed, and one byte short must deplete. This
 * pins the 8192128 randomness-consumption (it fails if tau reverts to 2t). */
int test_wc_mceliece_encap_tau_8192128(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_MCELIECE) && !defined(WC_NO_RNG) && \
    !defined(WOLFSSL_MCELIECE_NO_MAKE_KEY) && \
    !defined(WOLFSSL_MCELIECE_NO_ENCAPSULATE) && \
    defined(WOLFSSL_WC_MCELIECE_8192128) && defined(MCELIECE_FORM_PLAIN)
    McElieceKey* key = NULL;
    WC_RNG rng;
    byte ct[MCELIECE_MAX_CIPHER_TEXT_SIZE];
    byte ss[MCELIECE_SS_SZ];
    byte rand[2 * WC_MCELIECE_8192128_T]; /* one attempt = 2*tau = 2*t bytes */
    int i;
    int rngInit = 0;

    XMEMSET(&rng, 0, sizeof(rng));
    ExpectIntEQ(wc_InitRng(&rng), 0);
    if (EXPECT_SUCCESS()) {
        rngInit = 1;
    }

    /* t distinct samples 0..t-1 (each a 13-bit value < n = q = 8192), so one
     * FixedWeight attempt yields t in-range, duplicate-free indices. */
    for (i = 0; i < WC_MCELIECE_8192128_T; i++) {
        rand[2 * i]     = (byte)i;
        rand[2 * i + 1] = 0;
    }

    key = wc_McElieceKey_New(WC_MCELIECE_8192128, NULL, INVALID_DEVID);
    ExpectNotNull(key);
    ExpectIntEQ(wc_McElieceKey_MakeKey(key, &rng), 0);
    /* Exactly 2*t bytes (one attempt, tau = t) must suffice. */
    ExpectIntEQ(wc_McElieceKey_EncapsulateWithRandom(key, ct, ss, rand,
        2 * WC_MCELIECE_8192128_T), 0);
    /* One byte short of an attempt must deplete -> BUFFER_E. */
    ExpectIntEQ(wc_McElieceKey_EncapsulateWithRandom(key, ct, ss, rand,
        2 * WC_MCELIECE_8192128_T - 1), WC_NO_ERR_TRACE(BUFFER_E));

    wc_McElieceKey_Delete(key, &key);
    if (rngInit) {
        DoExpectIntEQ(wc_FreeRng(&rng), 0);
    }
#endif
    return EXPECT_RESULT();
}

/* Decapsulation requires a private key: a key holding only a decoded public key
 * must not decapsulate. */
int test_wc_mceliece_decapsulate_pubonly_fails(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_MCELIECE) && !defined(WC_NO_RNG) && \
    !defined(WOLFSSL_MCELIECE_NO_MAKE_KEY) && \
    !defined(WOLFSSL_MCELIECE_NO_ENCAPSULATE) && \
    !defined(WOLFSSL_MCELIECE_NO_DECAPSULATE)
    McElieceKey* key = NULL;
    McElieceKey* key2 = NULL;
    WC_RNG rng;
    byte* pub = NULL;
    byte ct[MCELIECE_MAX_CIPHER_TEXT_SIZE];
    byte ss[MCELIECE_SS_SZ];
    byte ssDec[MCELIECE_SS_SZ];
    word32 pubLen = 0;
    word32 ctLen = 0;
    int rngInit = 0;

    XMEMSET(&rng, 0, sizeof(rng));
    pub = (byte*)XMALLOC(MCELIECE_MAX_PUBLIC_KEY_SIZE, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(pub);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    if (EXPECT_SUCCESS()) {
        rngInit = 1;
    }

    key = wc_McElieceKey_New(MCELIECE_T0, NULL, INVALID_DEVID);
    ExpectNotNull(key);
    ExpectIntEQ(wc_McElieceKey_PublicKeySize(key, &pubLen), 0);
    ExpectIntEQ(wc_McElieceKey_CipherTextSize(key, &ctLen), 0);
    ExpectIntEQ(wc_McElieceKey_MakeKey(key, &rng), 0);
    ExpectIntEQ(wc_McElieceKey_EncodePublicKey(key, pub, pubLen), 0);

    key2 = wc_McElieceKey_New(MCELIECE_T0, NULL, INVALID_DEVID);
    ExpectNotNull(key2);
    ExpectIntEQ(wc_McElieceKey_DecodePublicKey(key2, pub, pubLen), 0);
    /* Public key only: encapsulation works, decapsulation is rejected. */
    ExpectIntEQ(wc_McElieceKey_Encapsulate(key2, ct, ss, &rng), 0);
    ExpectIntEQ(wc_McElieceKey_Decapsulate(key2, ssDec, ct, ctLen),
        WC_NO_ERR_TRACE(BAD_STATE_E));

    wc_McElieceKey_Delete(key2, &key2);
    wc_McElieceKey_Delete(key, &key);
    if (rngInit) {
        DoExpectIntEQ(wc_FreeRng(&rng), 0);
    }
    XFREE(pub, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}

/* NULL and out-of-range argument handling for the always-compiled entry
 * points: constructors, size queries and key encode/decode. */
int test_wc_mceliece_bad_args(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_MCELIECE)
    McElieceKey* key = NULL;
    word32 len = 0;
    word32 pubLen = 0;
    word32 privLen = 0;
    byte buf[8];

    XMEMSET(buf, 0, sizeof(buf));

    /* New rejects a type with bits outside the base/modifier ranges. */
    ExpectNull(wc_McElieceKey_New(0x40, NULL, INVALID_DEVID));

    /* Init rejects NULL key. */
    ExpectIntEQ(wc_McElieceKey_Init(NULL, MCELIECE_T0, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Free rejects a NULL key. */
    ExpectIntEQ(wc_McElieceKey_Free(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    key = wc_McElieceKey_New(MCELIECE_T0, NULL, INVALID_DEVID);
    ExpectNotNull(key);

    /* A type with bits outside the base/modifier ranges is a bad argument. */
    ExpectIntEQ(wc_McElieceKey_Init(key, 0x40, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* An undefined base parameter set is a bad argument. */
    ExpectIntEQ(wc_McElieceKey_Init(key, 0x03, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Re-initialise to a valid type for the remaining checks. */
    ExpectIntEQ(wc_McElieceKey_Init(key, MCELIECE_T0, NULL, INVALID_DEVID), 0);

    ExpectIntEQ(wc_McElieceKey_PublicKeySize(key, &pubLen), 0);
    ExpectIntEQ(wc_McElieceKey_PrivateKeySize(key, &privLen), 0);

    /* Size queries reject a NULL key and a NULL output. */
    ExpectIntEQ(wc_McElieceKey_CipherTextSize(NULL, &len),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_McElieceKey_CipherTextSize(key, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_McElieceKey_SharedSecretSize(NULL, &len),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_McElieceKey_SharedSecretSize(key, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_McElieceKey_PublicKeySize(NULL, &len),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_McElieceKey_PublicKeySize(key, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_McElieceKey_PrivateKeySize(NULL, &len),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_McElieceKey_PrivateKeySize(key, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Public-key encode: NULL key/out, then unset-state, are rejected. */
    ExpectIntEQ(wc_McElieceKey_EncodePublicKey(NULL, buf, pubLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_McElieceKey_EncodePublicKey(key, NULL, pubLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_McElieceKey_EncodePublicKey(key, buf, (word32)sizeof(buf)),
        WC_NO_ERR_TRACE(BAD_STATE_E));
    /* Public-key decode: NULL key/in, then wrong length, are rejected. */
    ExpectIntEQ(wc_McElieceKey_DecodePublicKey(NULL, buf, pubLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_McElieceKey_DecodePublicKey(key, NULL, pubLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_McElieceKey_DecodePublicKey(key, buf, 1),
        WC_NO_ERR_TRACE(BUFFER_E));

    /* Private-key encode: NULL key/out, then unset-state, are rejected. */
    ExpectIntEQ(wc_McElieceKey_EncodePrivateKey(NULL, buf, privLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_McElieceKey_EncodePrivateKey(key, NULL, privLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_McElieceKey_EncodePrivateKey(key, buf, (word32)sizeof(buf)),
        WC_NO_ERR_TRACE(BAD_STATE_E));
    /* Private-key decode: NULL key/in, then wrong length, are rejected. */
    ExpectIntEQ(wc_McElieceKey_DecodePrivateKey(NULL, buf, privLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_McElieceKey_DecodePrivateKey(key, NULL, privLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_McElieceKey_DecodePrivateKey(key, buf, 1),
        WC_NO_ERR_TRACE(BUFFER_E));

    wc_McElieceKey_Delete(key, &key);
#endif
    return EXPECT_RESULT();
}

/* NULL and state argument handling for the per-operation entry points
 * (make-key, encapsulate, decapsulate). Each block is gated by the same macro
 * that compiles the operation in, so single-operation builds are covered too. */
int test_wc_mceliece_op_bad_args(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_MCELIECE) && !defined(WC_NO_RNG)
    McElieceKey* key = NULL;
    WC_RNG rng;
    int rngInit = 0;
#if !defined(WOLFSSL_MCELIECE_NO_MAKE_KEY) || \
    !defined(WOLFSSL_MCELIECE_NO_ENCAPSULATE)
    byte rand[MCELIECE_SEED_SZ];
#endif
#if !defined(WOLFSSL_MCELIECE_NO_ENCAPSULATE) || \
    !defined(WOLFSSL_MCELIECE_NO_DECAPSULATE)
    byte ct[MCELIECE_MAX_CIPHER_TEXT_SIZE];
    byte ss[MCELIECE_SS_SZ];
#endif
#if !defined(WOLFSSL_MCELIECE_NO_DECAPSULATE)
    word32 ctLen = 0;
#endif

    XMEMSET(&rng, 0, sizeof(rng));
#if !defined(WOLFSSL_MCELIECE_NO_MAKE_KEY) || \
    !defined(WOLFSSL_MCELIECE_NO_ENCAPSULATE)
    XMEMSET(rand, 0, sizeof(rand));
#endif
#if !defined(WOLFSSL_MCELIECE_NO_ENCAPSULATE) || \
    !defined(WOLFSSL_MCELIECE_NO_DECAPSULATE)
    XMEMSET(ct, 0, sizeof(ct));
#endif
    ExpectIntEQ(wc_InitRng(&rng), 0);
    if (EXPECT_SUCCESS()) {
        rngInit = 1;
    }

    key = wc_McElieceKey_New(MCELIECE_T0, NULL, INVALID_DEVID);
    ExpectNotNull(key);
#if !defined(WOLFSSL_MCELIECE_NO_DECAPSULATE)
    ExpectIntEQ(wc_McElieceKey_CipherTextSize(key, &ctLen), 0);
#endif

#if !defined(WOLFSSL_MCELIECE_NO_MAKE_KEY)
    /* MakeKey rejects a NULL key and a NULL rng. */
    ExpectIntEQ(wc_McElieceKey_MakeKey(NULL, &rng),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_McElieceKey_MakeKey(key, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* MakeKeyWithRandom rejects NULL key/rand and a wrong seed length. */
    ExpectIntEQ(wc_McElieceKey_MakeKeyWithRandom(NULL, rand, MCELIECE_SEED_SZ),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_McElieceKey_MakeKeyWithRandom(key, NULL, MCELIECE_SEED_SZ),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_McElieceKey_MakeKeyWithRandom(key, rand,
        MCELIECE_SEED_SZ - 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif

#if !defined(WOLFSSL_MCELIECE_NO_ENCAPSULATE)
    /* Encapsulate rejects a NULL key, ct, ss or rng. */
    ExpectIntEQ(wc_McElieceKey_Encapsulate(NULL, ct, ss, &rng),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_McElieceKey_Encapsulate(key, NULL, ss, &rng),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_McElieceKey_Encapsulate(key, ct, NULL, &rng),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_McElieceKey_Encapsulate(key, ct, ss, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* No public key set yet: encapsulation is rejected. */
    ExpectIntEQ(wc_McElieceKey_Encapsulate(key, ct, ss, &rng),
        WC_NO_ERR_TRACE(BAD_STATE_E));
    /* EncapsulateWithRandom rejects NULL args and a negative length. */
    ExpectIntEQ(wc_McElieceKey_EncapsulateWithRandom(NULL, ct, ss, rand,
        MCELIECE_SEED_SZ), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_McElieceKey_EncapsulateWithRandom(key, NULL, ss, rand,
        MCELIECE_SEED_SZ), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_McElieceKey_EncapsulateWithRandom(key, ct, NULL, rand,
        MCELIECE_SEED_SZ), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_McElieceKey_EncapsulateWithRandom(key, ct, ss, NULL,
        MCELIECE_SEED_SZ), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_McElieceKey_EncapsulateWithRandom(key, ct, ss, rand, -1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* No public key set yet: encapsulation is rejected. */
    ExpectIntEQ(wc_McElieceKey_EncapsulateWithRandom(key, ct, ss, rand,
        MCELIECE_SEED_SZ), WC_NO_ERR_TRACE(BAD_STATE_E));
#endif

#if !defined(WOLFSSL_MCELIECE_NO_DECAPSULATE)
    /* Decapsulate rejects a NULL key, ss or ct. */
    ExpectIntEQ(wc_McElieceKey_Decapsulate(NULL, ss, ct, ctLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_McElieceKey_Decapsulate(key, NULL, ct, ctLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_McElieceKey_Decapsulate(key, ss, NULL, ctLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* No private key set yet: decapsulation is rejected. */
    ExpectIntEQ(wc_McElieceKey_Decapsulate(key, ss, ct, ctLen),
        WC_NO_ERR_TRACE(BAD_STATE_E));
#endif

    wc_McElieceKey_Delete(key, &key);
    if (rngInit) {
        DoExpectIntEQ(wc_FreeRng(&rng), 0);
    }
#endif
    return EXPECT_RESULT();
}

/* Length-argument handling for encode/decode and decapsulate. */
int test_wc_mceliece_op_len_checks(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_MCELIECE) && !defined(WC_NO_RNG) && \
    !defined(WOLFSSL_MCELIECE_NO_MAKE_KEY) && \
    !defined(WOLFSSL_MCELIECE_NO_ENCAPSULATE) && \
    !defined(WOLFSSL_MCELIECE_NO_DECAPSULATE)
    McElieceKey* key = NULL;
    WC_RNG rng;
    byte* pub = NULL;
    byte ss[MCELIECE_SS_SZ];
    byte ct[MCELIECE_MAX_CIPHER_TEXT_SIZE];
    word32 pubLen = 0;
    word32 privLen = 0;
    word32 ctLen = 0;
    int rngInit = 0;

    XMEMSET(&rng, 0, sizeof(rng));
    pub = (byte*)XMALLOC(MCELIECE_MAX_PUBLIC_KEY_SIZE, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(pub);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    if (EXPECT_SUCCESS()) {
        rngInit = 1;
    }

    key = wc_McElieceKey_New(MCELIECE_T0, NULL, INVALID_DEVID);
    ExpectNotNull(key);
    ExpectIntEQ(wc_McElieceKey_PublicKeySize(key, &pubLen), 0);
    ExpectIntEQ(wc_McElieceKey_PrivateKeySize(key, &privLen), 0);
    ExpectIntEQ(wc_McElieceKey_CipherTextSize(key, &ctLen), 0);
    ExpectIntEQ(wc_McElieceKey_MakeKey(key, &rng), 0);

    /* Encode into a too-small buffer is rejected. */
    ExpectIntEQ(wc_McElieceKey_EncodePublicKey(key, pub, pubLen - 1),
        WC_NO_ERR_TRACE(BUFFER_E));
    /* Full-length encode succeeds. */
    ExpectIntEQ(wc_McElieceKey_EncodePublicKey(key, pub, pubLen), 0);
    /* Private-key encode into a too-small buffer is rejected (pub is large
     * enough to double as the output buffer here). */
    ExpectIntEQ(wc_McElieceKey_EncodePrivateKey(key, pub, privLen - 1),
        WC_NO_ERR_TRACE(BUFFER_E));
    /* Decode with the wrong length is rejected. */
    ExpectIntEQ(wc_McElieceKey_DecodePublicKey(key, pub, pubLen - 1),
        WC_NO_ERR_TRACE(BUFFER_E));
    /* Decapsulate with the wrong ciphertext length is rejected. */
    ExpectIntEQ(wc_McElieceKey_Decapsulate(key, ss, ct, ctLen - 1),
        WC_NO_ERR_TRACE(BUFFER_E));

    wc_McElieceKey_Delete(key, &key);
    if (rngInit) {
        DoExpectIntEQ(wc_FreeRng(&rng), 0);
    }
    XFREE(pub, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}

/* New / Delete life cycle. */
int test_wc_mceliece_new_delete(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_MCELIECE)
    McElieceKey* key = NULL;

    key = wc_McElieceKey_New(MCELIECE_T0, NULL, INVALID_DEVID);
    ExpectNotNull(key);
    ExpectIntEQ(wc_McElieceKey_Delete(key, &key), 0);
    ExpectNull(key);
    /* A second New/Delete; Delete NULLs the holder on success. */
    key = wc_McElieceKey_New(MCELIECE_T0, NULL, INVALID_DEVID);
    ExpectNotNull(key);
    ExpectIntEQ(wc_McElieceKey_Delete(key, &key), 0);
    /* Delete tolerates a NULL key. */
    ExpectIntEQ(wc_McElieceKey_Delete(NULL, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Unconditional teardown: the Expect-wrapped deletes above are skipped
     * once an earlier expectation fails, so free any key still allocated. */
    wc_McElieceKey_Delete(key, &key);
#endif
    return EXPECT_RESULT();
}

/* A public key whose unused row padding bits are non-zero is rejected at
 * import. Only mceliece6960119 has such bits (k % 8 == 5); byte-aligned sets
 * have none, so this check is guarded to that variant. */
int test_wc_mceliece_pk_padding_reject(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_MCELIECE) && defined(WOLFSSL_WC_MCELIECE_6960119) && \
    !defined(WC_NO_RNG) && !defined(WOLFSSL_MCELIECE_NO_MAKE_KEY) && \
    defined(MCELIECE_FORM_PLAIN)
    McElieceKey* key = NULL;
    McElieceKey* key2 = NULL;
    WC_RNG rng;
    byte* pub = NULL;
    word32 pubLen = 0;
    int rngInit = 0;

    XMEMSET(&rng, 0, sizeof(rng));
    pub = (byte*)XMALLOC(MCELIECE_MAX_PUBLIC_KEY_SIZE, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(pub);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    if (EXPECT_SUCCESS()) {
        rngInit = 1;
    }

    key = wc_McElieceKey_New(WC_MCELIECE_6960119, NULL, INVALID_DEVID);
    ExpectNotNull(key);
    ExpectIntEQ(wc_McElieceKey_PublicKeySize(key, &pubLen), 0);
    ExpectIntEQ(wc_McElieceKey_MakeKey(key, &rng), 0);
    ExpectIntEQ(wc_McElieceKey_EncodePublicKey(key, pub, pubLen), 0);

    key2 = wc_McElieceKey_New(WC_MCELIECE_6960119, NULL, INVALID_DEVID);
    ExpectNotNull(key2);
    /* The clean encoding imports without error. */
    ExpectIntEQ(wc_McElieceKey_DecodePublicKey(key2, pub, pubLen), 0);

    /* Set a padding bit: for 6960119 (k % 8 == 5) bit 7 of every row's last
     * byte is unused and must be zero. The final byte of the whole key is the
     * last row's last byte, so this makes an otherwise valid key invalid. */
    if (EXPECT_SUCCESS()) {
        pub[pubLen - 1] |= 0x80;
    }
    ExpectIntEQ(wc_McElieceKey_DecodePublicKey(key2, pub, pubLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_McElieceKey_Delete(key2, &key2);
    wc_McElieceKey_Delete(key, &key);
    if (rngInit) {
        DoExpectIntEQ(wc_FreeRng(&rng), 0);
    }
    XFREE(pub, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}

/* Compiled variants initialise; valid but excluded variants report
 * NOT_COMPILED_IN. */
int test_wc_mceliece_not_compiled_in(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_MCELIECE)
    static const int allTypes[] = {
        WC_MCELIECE_6688128, WC_MCELIECE_6688128F,
        WC_MCELIECE_6688128PC, WC_MCELIECE_6688128PCF,
        WC_MCELIECE_6960119, WC_MCELIECE_6960119F,
        WC_MCELIECE_6960119PC, WC_MCELIECE_6960119PCF,
        WC_MCELIECE_8192128, WC_MCELIECE_8192128F,
        WC_MCELIECE_8192128PC, WC_MCELIECE_8192128PCF
    };
    McElieceKey* key = NULL;
    int i, j, compiled;

    key = (McElieceKey*)XMALLOC(sizeof(*key), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(key);

    for (i = 0; (i < (int)(sizeof(allTypes) / sizeof(allTypes[0]))) &&
            EXPECT_SUCCESS(); i++) {
        compiled = 0;
        for (j = 0; j < MCELIECE_TYPE_CNT; j++) {
            if (mceliece_types[j] == allTypes[i]) {
                compiled = 1;
                break;
            }
        }
        if (compiled) {
            ExpectIntEQ(wc_McElieceKey_Init(key, allTypes[i], NULL,
                INVALID_DEVID), 0);
            wc_McElieceKey_Free(key);
        }
        else {
            ExpectIntEQ(wc_McElieceKey_Init(key, allTypes[i], NULL,
                INVALID_DEVID), WC_NO_ERR_TRACE(NOT_COMPILED_IN));
        }
    }

    XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}
