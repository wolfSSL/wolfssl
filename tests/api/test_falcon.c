/* test_falcon.c
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

#ifdef HAVE_FALCON
    #include <wolfssl/wolfcrypt/falcon.h>
#endif
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <tests/api/api.h>
#include <tests/api/test_falcon.h>

/*
 * Coverage note: which of Falcon-512 (NIST L1) and Falcon-1024 (NIST L5) is
 * compiled depends on WOLFSSL_NO_FALCON_LEVEL1 / WOLFSSL_NO_FALCON_LEVEL5, so
 * a test must iterate falcon_levels[] / FALCON_NUM_LEVELS below, and a block
 * naming one level has to be #ifdef-guarded.
 *
 * Tests that need key generation or signing are gated on
 * WC_FALCON_HAVE_NATIVE_SIGN; argument-sanitising tests only need the
 * always-present entry points and run under HAVE_FALCON.
 */

#ifdef HAVE_FALCON

/* The levels this build actually has. Disabling one with
 * WOLFSSL_NO_FALCON_LEVEL1 / _LEVEL5 drops it from every loop below. */
static const byte falcon_levels[] = {
#ifndef WOLFSSL_NO_FALCON_LEVEL1
    FALCON_LEVEL1,
#endif
#ifndef WOLFSSL_NO_FALCON_LEVEL5
    FALCON_LEVEL5
#endif
};
#define FALCON_NUM_LEVELS ((int)(sizeof(falcon_levels) / sizeof(byte)))

/* Encoded sizes per the Falcon specification (Table 3.3), keyed by level. */
static word32 falcon_exp_pub(byte level)
{
    return (level == FALCON_LEVEL1) ? (word32)FALCON_LEVEL1_PUB_KEY_SIZE
                                    : (word32)FALCON_LEVEL5_PUB_KEY_SIZE;
}
static word32 falcon_exp_key(byte level)
{
    return (level == FALCON_LEVEL1) ? (word32)FALCON_LEVEL1_KEY_SIZE
                                    : (word32)FALCON_LEVEL5_KEY_SIZE;
}
static word32 falcon_exp_prv(byte level)
{
    return (level == FALCON_LEVEL1) ? (word32)FALCON_LEVEL1_PRV_KEY_SIZE
                                    : (word32)FALCON_LEVEL5_PRV_KEY_SIZE;
}
static int falcon_exp_sig(byte level)
{
    return (level == FALCON_LEVEL1) ? FALCON_LEVEL1_SIG_SIZE
                                    : FALCON_LEVEL5_SIG_SIZE;
}

#endif /* HAVE_FALCON */

/*
 * Size-query and level APIs. Runs in every HAVE_FALCON build (no key
 * generation needed): a key only needs its level set to answer size queries.
 */
int test_wc_falcon_sizes(void)
{
    EXPECT_DECLS;
#ifdef HAVE_FALCON
    falcon_key key;
    int li;

    /* NULL key -> BAD_FUNC_ARG for every size query. */
    ExpectIntEQ(wc_falcon_size(NULL),      WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_falcon_priv_size(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_falcon_pub_size(NULL),  WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_falcon_sig_size(NULL),  WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Valid key but level not set yet -> BAD_FUNC_ARG. */
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_falcon_init(&key), 0);
    ExpectIntEQ(wc_falcon_size(&key),      WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_falcon_priv_size(&key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_falcon_pub_size(&key),  WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_falcon_sig_size(&key),  WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    wc_falcon_free(&key);

    for (li = 0; li < FALCON_NUM_LEVELS; li++) {
        byte level = falcon_levels[li];
        byte gl = 0;

        XMEMSET(&key, 0, sizeof(key));
        ExpectIntEQ(wc_falcon_init(&key), 0);
        ExpectIntEQ(wc_falcon_set_level(&key, level), 0);

        ExpectIntEQ(wc_falcon_size(&key),      (int)falcon_exp_key(level));
        ExpectIntEQ(wc_falcon_priv_size(&key), (int)falcon_exp_prv(level));
        ExpectIntEQ(wc_falcon_pub_size(&key),  (int)falcon_exp_pub(level));
        ExpectIntEQ(wc_falcon_sig_size(&key),  falcon_exp_sig(level));

        /* get_level round-trips the level that was set. */
        ExpectIntEQ(wc_falcon_get_level(&key, &gl), 0);
        ExpectIntEQ(gl, level);

        wc_falcon_free(&key);
    }

    /* Pin the spec constants so an edit to falcon.h surfaces here. */
    ExpectIntEQ(FALCON_LEVEL1_PUB_KEY_SIZE, 897);
    ExpectIntEQ(FALCON_LEVEL1_SIG_SIZE,     666);
    ExpectIntEQ(FALCON_LEVEL5_PUB_KEY_SIZE, 1793);
    ExpectIntEQ(FALCON_LEVEL5_SIG_SIZE,     1280);
    ExpectIntEQ(FALCON_NONCE_SIZE,          40);
#endif /* HAVE_FALCON */
    return EXPECT_RESULT();
}

/*
 * Key generation: NULL/bad-arg handling and a real keygen for both levels
 * whose output passes check_key.
 */
int test_wc_falcon_make_key(void)
{
    EXPECT_DECLS;
#ifdef WC_FALCON_HAVE_NATIVE_SIGN
    falcon_key key;
    WC_RNG rng;
    int li;

    XMEMSET(&rng, 0, sizeof(rng));
    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* NULL parameter handling. */
    ExpectIntEQ(wc_falcon_make_key(NULL, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_falcon_init(&key), 0);
    ExpectIntEQ(wc_falcon_make_key(&key, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Level must be set before generating. */
    ExpectIntEQ(wc_falcon_make_key(&key, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    wc_falcon_free(&key);

    for (li = 0; li < FALCON_NUM_LEVELS; li++) {
        byte level = falcon_levels[li];

        XMEMSET(&key, 0, sizeof(key));
        ExpectIntEQ(wc_falcon_init(&key), 0);
        ExpectIntEQ(wc_falcon_set_level(&key, level), 0);
        ExpectIntEQ(wc_falcon_make_key(&key, &rng), 0);
        /* A freshly generated key pair is internally consistent. */
        ExpectIntEQ(wc_falcon_check_key(&key), 0);
        wc_falcon_free(&key);
    }

    wc_FreeRng(&rng);
#endif /* WC_FALCON_HAVE_NATIVE_SIGN */
    return EXPECT_RESULT();
}

/*
 * Sign then verify, both levels: genuine signature accepted, wrong message and
 * single-byte tamper rejected, too-small buffer reports BUFFER_E with the
 * required length, and verify on a public-key-less key is rejected.
 */
int test_wc_falcon_sign_vfy(void)
{
    EXPECT_DECLS;
#ifdef WC_FALCON_HAVE_NATIVE_SIGN
    falcon_key key;
    WC_RNG rng;
    byte* sig = NULL;
    word32 sigLen;
    int res;
    int li;
    static const byte msg[] = "wolfSSL Falcon sign/verify unit test";

    sig = (byte*)XMALLOC(FALCON_MAX_SIG_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(sig);

    XMEMSET(&rng, 0, sizeof(rng));
    ExpectIntEQ(wc_InitRng(&rng), 0);

    for (li = 0; li < FALCON_NUM_LEVELS; li++) {
        byte level = falcon_levels[li];

        XMEMSET(&key, 0, sizeof(key));
        ExpectIntEQ(wc_falcon_init(&key), 0);
        ExpectIntEQ(wc_falcon_set_level(&key, level), 0);
        ExpectIntEQ(wc_falcon_make_key(&key, &rng), 0);

        /* Too-small output buffer -> BUFFER_E, outLen set to the max size. */
        sigLen = 1;
        ExpectIntEQ(wc_falcon_sign_msg(msg, (word32)sizeof(msg), sig, &sigLen,
            &key, &rng), WC_NO_ERR_TRACE(BUFFER_E));
        ExpectIntEQ((int)sigLen, falcon_exp_sig(level));

        /* Genuine signature: compressed length is variable but never exceeds
         * the level maximum, and it must verify. */
        sigLen = FALCON_MAX_SIG_SIZE;
        ExpectIntEQ(wc_falcon_sign_msg(msg, (word32)sizeof(msg), sig, &sigLen,
            &key, &rng), 0);
        ExpectIntGT((int)sigLen, 0);
        ExpectIntLE((int)sigLen, falcon_exp_sig(level));
        res = 0;
        ExpectIntEQ(wc_falcon_verify_msg(sig, sigLen, msg, (word32)sizeof(msg),
            &res, &key), 0);
        ExpectIntEQ(res, 1);

        /* A different message must not verify. */
        res = 1;
        ExpectIntEQ(wc_falcon_verify_msg(sig, sigLen, (const byte*)"x", 1,
            &res, &key), 0);
        ExpectIntNE(res, 1);

        /* A one-byte tamper in the signature body must not verify. */
        sig[sigLen - 1] ^= 0x01;
        res = 1;
        (void)wc_falcon_verify_msg(sig, sigLen, msg, (word32)sizeof(msg), &res,
            &key);
        ExpectIntNE(res, 1);
        sig[sigLen - 1] ^= 0x01;

        wc_falcon_free(&key);
    }

    /* Verify against a key with no public key set -> BAD_FUNC_ARG. */
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_falcon_init(&key), 0);
    ExpectIntEQ(wc_falcon_set_level(&key, falcon_levels[0]), 0);
    res = 0;
    ExpectIntEQ(wc_falcon_verify_msg(sig, (word32)falcon_exp_sig(
        falcon_levels[0]), msg, (word32)sizeof(msg), &res, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    wc_falcon_free(&key);

    wc_FreeRng(&rng);
    XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif /* WC_FALCON_HAVE_NATIVE_SIGN */
    return EXPECT_RESULT();
}

/*
 * Raw import/export round-trips: public, private-only (raw), private (concat
 * priv+pub), and the combined export_key. Each imported form is exercised via
 * sign or verify. NULL, too-small, and wrong-size arguments are checked.
 */
int test_wc_falcon_import_export(void)
{
    EXPECT_DECLS;
#ifdef WC_FALCON_HAVE_NATIVE_SIGN
    falcon_key key;
    falcon_key key2;
    WC_RNG rng;
    byte* pub = NULL;
    byte* prv = NULL;      /* raw private, KEY_SIZE            */
    byte* prvpub = NULL;   /* concat(priv,pub), PRV_KEY_SIZE   */
    byte* sig = NULL;
    word32 pubLen;
    word32 prvLen;
    word32 prvpubLen;
    word32 sigLen;
    int res;
    int li;
    static const byte msg[] = "wolfSSL Falcon import/export unit test";

    pub    = (byte*)XMALLOC(FALCON_MAX_PUB_KEY_SIZE, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    prv    = (byte*)XMALLOC(FALCON_MAX_KEY_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    prvpub = (byte*)XMALLOC(FALCON_MAX_PRV_KEY_SIZE, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    sig    = (byte*)XMALLOC(FALCON_MAX_SIG_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(pub);
    ExpectNotNull(prv);
    ExpectNotNull(prvpub);
    ExpectNotNull(sig);

    XMEMSET(&rng, 0, sizeof(rng));
    ExpectIntEQ(wc_InitRng(&rng), 0);

    for (li = 0; li < FALCON_NUM_LEVELS; li++) {
        byte level = falcon_levels[li];
        word32 expPub = falcon_exp_pub(level);
        word32 expKey = falcon_exp_key(level);
        word32 expPrv = falcon_exp_prv(level);

        XMEMSET(&key, 0, sizeof(key));
        ExpectIntEQ(wc_falcon_init(&key), 0);
        ExpectIntEQ(wc_falcon_set_level(&key, level), 0);
        ExpectIntEQ(wc_falcon_make_key(&key, &rng), 0);

        /* export_public: too-small -> BUFFER_E with needed length, then OK. */
        pubLen = 1;
        ExpectIntEQ(wc_falcon_export_public(&key, pub, &pubLen),
            WC_NO_ERR_TRACE(BUFFER_E));
        ExpectIntEQ((int)pubLen, (int)expPub);
        pubLen = FALCON_MAX_PUB_KEY_SIZE;
        ExpectIntEQ(wc_falcon_export_public(&key, pub, &pubLen), 0);
        ExpectIntEQ((int)pubLen, (int)expPub);

        /* export_private_only: raw KEY_SIZE. */
        prvLen = 1;
        ExpectIntEQ(wc_falcon_export_private_only(&key, prv, &prvLen),
            WC_NO_ERR_TRACE(BUFFER_E));
        ExpectIntEQ((int)prvLen, (int)expKey);
        prvLen = FALCON_MAX_KEY_SIZE;
        ExpectIntEQ(wc_falcon_export_private_only(&key, prv, &prvLen), 0);
        ExpectIntEQ((int)prvLen, (int)expKey);

        /* export_private: concat(priv,pub), PRV_KEY_SIZE. */
        prvpubLen = 1;
        ExpectIntEQ(wc_falcon_export_private(&key, prvpub, &prvpubLen),
            WC_NO_ERR_TRACE(BUFFER_E));
        ExpectIntEQ((int)prvpubLen, (int)expPrv);
        prvpubLen = FALCON_MAX_PRV_KEY_SIZE;
        ExpectIntEQ(wc_falcon_export_private(&key, prvpub, &prvpubLen), 0);
        ExpectIntEQ((int)prvpubLen, (int)expPrv);

        /* Reference signature from the original key. */
        sigLen = FALCON_MAX_SIG_SIZE;
        ExpectIntEQ(wc_falcon_sign_msg(msg, (word32)sizeof(msg), sig, &sigLen,
            &key, &rng), 0);

        /* import_public into a fresh key and verify. Wrong length rejected. */
        XMEMSET(&key2, 0, sizeof(key2));
        ExpectIntEQ(wc_falcon_init(&key2), 0);
        ExpectIntEQ(wc_falcon_set_level(&key2, level), 0);
        ExpectIntEQ(wc_falcon_import_public(pub, expPub - 1, &key2),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_falcon_import_public(pub, pubLen, &key2), 0);
        res = 0;
        ExpectIntEQ(wc_falcon_verify_msg(sig, sigLen, msg, (word32)sizeof(msg),
            &res, &key2), 0);
        ExpectIntEQ(res, 1);
        wc_falcon_free(&key2);

        /* import_private_only (raw) + re-attach public, then sign & verify. */
        XMEMSET(&key2, 0, sizeof(key2));
        ExpectIntEQ(wc_falcon_init(&key2), 0);
        ExpectIntEQ(wc_falcon_set_level(&key2, level), 0);
        ExpectIntEQ(wc_falcon_import_private_only(prv, expKey - 1, &key2),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_falcon_import_private_only(prv, prvLen, &key2), 0);
        ExpectIntEQ(wc_falcon_import_public(pub, pubLen, &key2), 0);
        sigLen = FALCON_MAX_SIG_SIZE;
        ExpectIntEQ(wc_falcon_sign_msg(msg, (word32)sizeof(msg), sig, &sigLen,
            &key2, &rng), 0);
        res = 0;
        ExpectIntEQ(wc_falcon_verify_msg(sig, sigLen, msg, (word32)sizeof(msg),
            &res, &key), 0);
        ExpectIntEQ(res, 1);
        wc_falcon_free(&key2);

        /* import_private_only with the legacy concat(priv,pub) layout must
         * recover the public key on its own (pubKeySet), so a signature can be
         * produced and verified from that single import with no separate
         * public-key import. */
        XMEMSET(&key2, 0, sizeof(key2));
        ExpectIntEQ(wc_falcon_init(&key2), 0);
        ExpectIntEQ(wc_falcon_set_level(&key2, level), 0);
        ExpectIntEQ(wc_falcon_import_private_only(prvpub, prvpubLen, &key2), 0);
        ExpectIntEQ(wc_falcon_check_key(&key2), 0);
        sigLen = FALCON_MAX_SIG_SIZE;
        ExpectIntEQ(wc_falcon_sign_msg(msg, (word32)sizeof(msg), sig, &sigLen,
            &key2, &rng), 0);
        res = 0;
        ExpectIntEQ(wc_falcon_verify_msg(sig, sigLen, msg, (word32)sizeof(msg),
            &res, &key2), 0);
        ExpectIntEQ(res, 1);
        wc_falcon_free(&key2);

        /* import_private_key with the concat layout recovers the public key. */
        XMEMSET(&key2, 0, sizeof(key2));
        ExpectIntEQ(wc_falcon_init(&key2), 0);
        ExpectIntEQ(wc_falcon_set_level(&key2, level), 0);
        ExpectIntEQ(wc_falcon_import_private_key(prvpub, prvpubLen, NULL, 0,
            &key2), 0);
        ExpectIntEQ(wc_falcon_check_key(&key2), 0);
        wc_falcon_free(&key2);

        /* import_private_key with separate raw private + public buffers. */
        XMEMSET(&key2, 0, sizeof(key2));
        ExpectIntEQ(wc_falcon_init(&key2), 0);
        ExpectIntEQ(wc_falcon_set_level(&key2, level), 0);
        ExpectIntEQ(wc_falcon_import_private_key(prv, prvLen, pub, pubLen,
            &key2), 0);
        ExpectIntEQ(wc_falcon_check_key(&key2), 0);
        wc_falcon_free(&key2);

        /* export_key: private (concat) and public in one call. */
        prvpubLen = FALCON_MAX_PRV_KEY_SIZE;
        pubLen = FALCON_MAX_PUB_KEY_SIZE;
        ExpectIntEQ(wc_falcon_export_key(&key, prvpub, &prvpubLen, pub,
            &pubLen), 0);
        ExpectIntEQ((int)prvpubLen, (int)expPrv);
        ExpectIntEQ((int)pubLen, (int)expPub);

        wc_falcon_free(&key);
    }

    wc_FreeRng(&rng);
    XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(prvpub, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(prv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(pub, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif /* WC_FALCON_HAVE_NATIVE_SIGN */
    return EXPECT_RESULT();
}

/*
 * check_key: valid key passes; a public-only key, a private-only key, and a
 * mismatched public/private pair (which must fail the h*f == g cross-check)
 * all fail; NULL is rejected.
 */
int test_wc_falcon_check_key(void)
{
    EXPECT_DECLS;
#ifdef WC_FALCON_HAVE_NATIVE_SIGN
    falcon_key key;
    WC_RNG rng;
    byte* pub = NULL;
    byte* prv = NULL;
    word32 pubLen;
    word32 prvLen;
    int li;

    pub = (byte*)XMALLOC(FALCON_MAX_PUB_KEY_SIZE, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    prv = (byte*)XMALLOC(FALCON_MAX_KEY_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(pub);
    ExpectNotNull(prv);

    XMEMSET(&rng, 0, sizeof(rng));
    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* NULL key. */
    ExpectIntEQ(wc_falcon_check_key(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    for (li = 0; li < FALCON_NUM_LEVELS; li++) {
        byte level = falcon_levels[li];

        XMEMSET(&key, 0, sizeof(key));
        ExpectIntEQ(wc_falcon_init(&key), 0);
        ExpectIntEQ(wc_falcon_set_level(&key, level), 0);

        /* Neither half present -> PUBLIC_KEY_E. */
        ExpectIntEQ(wc_falcon_check_key(&key), WC_NO_ERR_TRACE(PUBLIC_KEY_E));

        ExpectIntEQ(wc_falcon_make_key(&key, &rng), 0);
        ExpectIntEQ(wc_falcon_check_key(&key), 0);

        pubLen = FALCON_MAX_PUB_KEY_SIZE;
        ExpectIntEQ(wc_falcon_export_public(&key, pub, &pubLen), 0);
        prvLen = FALCON_MAX_KEY_SIZE;
        ExpectIntEQ(wc_falcon_export_private_only(&key, prv, &prvLen), 0);

        wc_falcon_free(&key);

        /* Public only (no private) -> PUBLIC_KEY_E. */
        XMEMSET(&key, 0, sizeof(key));
        ExpectIntEQ(wc_falcon_init(&key), 0);
        ExpectIntEQ(wc_falcon_set_level(&key, level), 0);
        ExpectIntEQ(wc_falcon_import_public(pub, pubLen, &key), 0);
        ExpectIntEQ(wc_falcon_check_key(&key), WC_NO_ERR_TRACE(PUBLIC_KEY_E));
        wc_falcon_free(&key);

        /* Raw private only (no public) -> PUBLIC_KEY_E. */
        XMEMSET(&key, 0, sizeof(key));
        ExpectIntEQ(wc_falcon_init(&key), 0);
        ExpectIntEQ(wc_falcon_set_level(&key, level), 0);
        ExpectIntEQ(wc_falcon_import_private_only(prv, prvLen, &key), 0);
        ExpectIntEQ(wc_falcon_check_key(&key), WC_NO_ERR_TRACE(PUBLIC_KEY_E));
        wc_falcon_free(&key);

        /* Public imported FIRST, then a raw (non-concat) private key: both
         * halves are now present, so check_key passes. */
        XMEMSET(&key, 0, sizeof(key));
        ExpectIntEQ(wc_falcon_init(&key), 0);
        ExpectIntEQ(wc_falcon_set_level(&key, level), 0);
        ExpectIntEQ(wc_falcon_import_public(pub, pubLen, &key), 0);
        ExpectIntEQ(wc_falcon_import_private_only(prv, prvLen, &key), 0);
        ExpectIntEQ(wc_falcon_check_key(&key), 0);
        wc_falcon_free(&key);

        /* Mismatched pair: the public half of a DIFFERENT key of the same
         * level together with the original private key must fail the
         * cryptographic h*f == g (mod q) cross-check. */
        XMEMSET(&key, 0, sizeof(key));
        ExpectIntEQ(wc_falcon_init(&key), 0);
        ExpectIntEQ(wc_falcon_set_level(&key, level), 0);
        ExpectIntEQ(wc_falcon_make_key(&key, &rng), 0);
        pubLen = FALCON_MAX_PUB_KEY_SIZE;
        ExpectIntEQ(wc_falcon_export_public(&key, pub, &pubLen), 0);
        wc_falcon_free(&key);

        XMEMSET(&key, 0, sizeof(key));
        ExpectIntEQ(wc_falcon_init(&key), 0);
        ExpectIntEQ(wc_falcon_set_level(&key, level), 0);
        ExpectIntEQ(wc_falcon_import_public(pub, pubLen, &key), 0);
        ExpectIntEQ(wc_falcon_import_private_only(prv, prvLen, &key), 0);
        ExpectIntEQ(wc_falcon_check_key(&key), WC_NO_ERR_TRACE(PUBLIC_KEY_E));
        wc_falcon_free(&key);
    }

    wc_FreeRng(&rng);
    XFREE(prv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(pub, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif /* WC_FALCON_HAVE_NATIVE_SIGN */
    return EXPECT_RESULT();
}

/*
 * DER (RFC 5958 / SubjectPublicKeyInfo) round-trips for both levels:
 *   - KeyToDer (priv+pub) -> PrivateKeyDecode -> verify
 *   - PrivateKeyToDer (priv only) -> PrivateKeyDecode -> re-sign -> verify
 *   - PublicKeyToDer -> PublicKeyDecode -> verify
 * plus the size-query (NULL output) and BUFFER_E contracts.
 */
int test_wc_falcon_der(void)
{
    EXPECT_DECLS;
#ifdef WC_FALCON_HAVE_NATIVE_SIGN
    falcon_key key;
    falcon_key key2;
    WC_RNG rng;
    byte* der = NULL;
    byte* sig = NULL;
    const word32 derSz = 8 * 1024;
    word32 derLen;
    word32 idx;
    word32 sigLen;
    int res;
    int qsize;
    int li;
    static const byte msg[] = "wolfSSL Falcon DER round-trip";

    der = (byte*)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    sig = (byte*)XMALLOC(FALCON_MAX_SIG_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(der);
    ExpectNotNull(sig);

    XMEMSET(&rng, 0, sizeof(rng));
    ExpectIntEQ(wc_InitRng(&rng), 0);

    for (li = 0; li < FALCON_NUM_LEVELS; li++) {
        byte level = falcon_levels[li];

        XMEMSET(&key, 0, sizeof(key));
        ExpectIntEQ(wc_falcon_init(&key), 0);
        ExpectIntEQ(wc_falcon_set_level(&key, level), 0);
        ExpectIntEQ(wc_falcon_make_key(&key, &rng), 0);

        /* Reference signature from the generated key. */
        sigLen = FALCON_MAX_SIG_SIZE;
        ExpectIntEQ(wc_falcon_sign_msg(msg, (word32)sizeof(msg), sig, &sigLen,
            &key, &rng), 0);

        /* --- KeyToDer (private + public) --- */
        /* Size query: NULL output returns the encoded length. */
        ExpectIntGT(qsize = wc_Falcon_KeyToDer(&key, NULL, 0), 0);
        derLen = (word32)wc_Falcon_KeyToDer(&key, der, derSz);
        ExpectIntGT((int)derLen, 0);
        ExpectIntEQ((int)derLen, qsize);
        /* Buffer one byte too small: SetAsymKeyDer reports an insufficient
         * output buffer as BAD_FUNC_ARG (not BUFFER_E). */
        ExpectIntEQ(wc_Falcon_KeyToDer(&key, der, (word32)(qsize - 1)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* Decode into a fresh key and verify the reference signature. */
        XMEMSET(&key2, 0, sizeof(key2));
        ExpectIntEQ(wc_falcon_init(&key2), 0);
        ExpectIntEQ(wc_falcon_set_level(&key2, level), 0);
        idx = 0;
        ExpectIntEQ(wc_Falcon_PrivateKeyDecode(der, &idx, &key2, derLen), 0);
        res = 0;
        ExpectIntEQ(wc_falcon_verify_msg(sig, sigLen, msg, (word32)sizeof(msg),
            &res, &key2), 0);
        ExpectIntEQ(res, 1);
        wc_falcon_free(&key2);

        /* --- PrivateKeyToDer (private only) --- */
        derLen = (word32)wc_Falcon_PrivateKeyToDer(&key, der, derSz);
        ExpectIntGT((int)derLen, 0);
        XMEMSET(&key2, 0, sizeof(key2));
        ExpectIntEQ(wc_falcon_init(&key2), 0);
        ExpectIntEQ(wc_falcon_set_level(&key2, level), 0);
        idx = 0;
        ExpectIntEQ(wc_Falcon_PrivateKeyDecode(der, &idx, &key2, derLen), 0);
        /* Re-sign with the decoded private key; verify with the original. */
        sigLen = FALCON_MAX_SIG_SIZE;
        ExpectIntEQ(wc_falcon_sign_msg(msg, (word32)sizeof(msg), sig, &sigLen,
            &key2, &rng), 0);
        res = 0;
        ExpectIntEQ(wc_falcon_verify_msg(sig, sigLen, msg, (word32)sizeof(msg),
            &res, &key), 0);
        ExpectIntEQ(res, 1);
        wc_falcon_free(&key2);

        /* --- PublicKeyToDer (SubjectPublicKeyInfo) --- */
        derLen = (word32)wc_Falcon_PublicKeyToDer(&key, der, derSz, 1);
        ExpectIntGT((int)derLen, 0);
        XMEMSET(&key2, 0, sizeof(key2));
        ExpectIntEQ(wc_falcon_init(&key2), 0);
        ExpectIntEQ(wc_falcon_set_level(&key2, level), 0);
        idx = 0;
        ExpectIntEQ(wc_Falcon_PublicKeyDecode(der, &idx, &key2, derLen), 0);
        res = 0;
        ExpectIntEQ(wc_falcon_verify_msg(sig, sigLen, msg, (word32)sizeof(msg),
            &res, &key2), 0);
        ExpectIntEQ(res, 1);
        wc_falcon_free(&key2);

        wc_falcon_free(&key);
    }

    wc_FreeRng(&rng);
    XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif /* WC_FALCON_HAVE_NATIVE_SIGN */
    return EXPECT_RESULT();
}

/*
 * Exhaustive argument sanitising for the always-present entry points. Runs in
 * every HAVE_FALCON build (including verify-only / crypto-cb-only); make_key is
 * only referenced where it is compiled.
 */
int test_wc_falcon_error_paths(void)
{
    EXPECT_DECLS;
#ifdef HAVE_FALCON
    falcon_key key;
    byte buf[64];
    byte out[64];
    word32 outLen;
    word32 idx;
    byte level = 0;
    int res = 0;

    XMEMSET(buf, 0, sizeof(buf));

    /* init / init_ex */
    ExpectIntEQ(wc_falcon_init(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_falcon_init_ex(NULL, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* set_level / get_level */
    ExpectIntEQ(wc_falcon_set_level(NULL, FALCON_LEVEL1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_falcon_init(&key), 0);
    ExpectIntEQ(wc_falcon_set_level(&key, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_falcon_set_level(&key, 2), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_falcon_set_level(&key, 3), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_falcon_set_level(&key, 255), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifdef WOLFSSL_NO_FALCON_LEVEL1
    ExpectIntEQ(wc_falcon_set_level(&key, FALCON_LEVEL1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
#ifdef WOLFSSL_NO_FALCON_LEVEL5
    ExpectIntEQ(wc_falcon_set_level(&key, FALCON_LEVEL5),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wc_falcon_get_level(NULL, &level),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_falcon_get_level(&key, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Level not set on key yet. */
    ExpectIntEQ(wc_falcon_get_level(&key, &level),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    wc_falcon_free(&key);

    /* sign_msg: NULL in / out / outLen / key (present in every config). */
    outLen = (word32)sizeof(out);
    ExpectIntEQ(wc_falcon_sign_msg(NULL, 1, out, &outLen, &key, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_falcon_sign_msg(buf, 1, NULL, &outLen, &key, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_falcon_sign_msg(buf, 1, out, NULL, &key, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_falcon_sign_msg(buf, 1, out, &outLen, NULL, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* verify_msg: NULL sig / msg / res / key. */
    ExpectIntEQ(wc_falcon_verify_msg(NULL, 1, buf, 1, &res, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_falcon_verify_msg(buf, 1, NULL, 1, &res, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_falcon_verify_msg(buf, 1, buf, 1, NULL, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_falcon_verify_msg(buf, 1, buf, 1, &res, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

#ifndef WOLFSSL_FALCON_VERIFY_ONLY
    /* make_key is not compiled in verify-only builds. */
    {
        WC_RNG rng;
        XMEMSET(&rng, 0, sizeof(rng));
        ExpectIntEQ(wc_falcon_make_key(NULL, NULL),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        XMEMSET(&key, 0, sizeof(key));
        ExpectIntEQ(wc_falcon_init(&key), 0);
        ExpectIntEQ(wc_falcon_make_key(&key, NULL),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        wc_falcon_free(&key);
    }
#endif

    /* import: NULL, unset-level, wrong-size. Level checks precede any buffer
     * read, so a short buf with a large declared length is safe here. */
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_falcon_init(&key), 0);
    ExpectIntEQ(wc_falcon_import_public(NULL, FALCON_LEVEL1_PUB_KEY_SIZE, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_falcon_import_public(buf, FALCON_LEVEL1_PUB_KEY_SIZE, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* key level not set -> BAD_FUNC_ARG. */
    ExpectIntEQ(wc_falcon_import_public(buf, FALCON_LEVEL1_PUB_KEY_SIZE, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_falcon_import_private_only(NULL, FALCON_LEVEL1_KEY_SIZE,
        &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_falcon_import_private_only(buf, FALCON_LEVEL1_KEY_SIZE,
        &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG)); /* level unset */
    ExpectIntEQ(wc_falcon_import_private_key(NULL, FALCON_LEVEL1_KEY_SIZE,
        NULL, 0, &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* pub == NULL but pubSz != 0 -> BAD_FUNC_ARG. */
    ExpectIntEQ(wc_falcon_import_private_key(buf, FALCON_LEVEL1_KEY_SIZE,
        NULL, FALCON_LEVEL1_PUB_KEY_SIZE, &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    wc_falcon_free(&key);

    /* export: NULL, unset-level, no-key-set. */
    outLen = (word32)sizeof(out);
    ExpectIntEQ(wc_falcon_export_public(NULL, out, &outLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_falcon_export_private_only(NULL, out, &outLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_falcon_export_private(NULL, out, &outLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_falcon_init(&key), 0);
    ExpectIntEQ(wc_falcon_set_level(&key, falcon_levels[0]), 0);
    ExpectIntEQ(wc_falcon_export_public(&key, NULL, &outLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_falcon_export_public(&key, out, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* level set but no public key -> BAD_FUNC_ARG. */
    outLen = (word32)sizeof(out);
    ExpectIntEQ(wc_falcon_export_public(&key, out, &outLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* level set but no private key -> BAD_FUNC_ARG. */
    outLen = (word32)sizeof(out);
    ExpectIntEQ(wc_falcon_export_private_only(&key, out, &outLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    outLen = (word32)sizeof(out);
    ExpectIntEQ(wc_falcon_export_private(&key, out, &outLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    wc_falcon_free(&key);

    /* check_key / size: NULL. */
    ExpectIntEQ(wc_falcon_check_key(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* DER decode/encode NULL-argument validation. Falcon always pulls in the
     * asymmetric-key ASN.1 machinery, so these entry points are present. */
    idx = 0;
    ExpectIntEQ(wc_Falcon_PrivateKeyDecode(NULL, &idx, &key, 10),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Falcon_PrivateKeyDecode(buf, NULL, &key, 10),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Falcon_PrivateKeyDecode(buf, &idx, NULL, 10),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Falcon_PrivateKeyDecode(buf, &idx, &key, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    idx = 0;
    ExpectIntEQ(wc_Falcon_PublicKeyDecode(NULL, &idx, &key, 10),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Falcon_PublicKeyDecode(buf, NULL, &key, 10),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Falcon_PublicKeyDecode(buf, &idx, NULL, 10),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Falcon_PublicKeyDecode(buf, &idx, &key, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Falcon_KeyToDer(NULL, out, (word32)sizeof(out)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Falcon_PrivateKeyToDer(NULL, out, (word32)sizeof(out)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Falcon_PublicKeyToDer(NULL, out, (word32)sizeof(out), 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif /* HAVE_FALCON */
    return EXPECT_RESULT();
}

/* The pinned digests only reproduce under the DRBG they were produced with:
 * SHA-256 and SHA-512 Hash_DRBG take different seed sizes, so one seed gives
 * two unrelated streams. Hence the SHA-512 requirement below and the run-time
 * check for wc_Sha512Drbg_Disable(); anything bypassing the DRBG is excluded. */
#if defined(WC_FALCON_HAVE_NATIVE_SIGN) && defined(WC_RNG_SEED_CB) && \
    defined(HAVE_HASHDRBG) && !defined(NO_SHA256) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS) && \
    !defined(HAVE_INTEL_RDRAND) && !defined(CUSTOM_RAND_GENERATE_BLOCK) && \
    !defined(WOLFSSL_RNG_USE_FULL_SEED) && defined(WOLFSSL_DRBG_SHA512)

/* Fixed seed so the DRBG, and with it key generation and signing, is
 * reproducible. A constant fill would be rejected by the seed health test, so
 * the bytes come from a fixed linear congruential stream. */
static int falcon_det_seed_cb(OS_Seed* os, byte* seed, word32 sz)
{
    word32 i;
    word32 s = 0x5A5A5A5AU;

    (void)os;
    for (i = 0; i < sz; i++) {
        s = (s * 1103515245U) + 12345U;
        seed[i] = (byte)(s >> 24);
    }
    return 0;
}

/* SHA-256 of buf, for pinning a key or signature without embedding it. */
static int falcon_det_digest(const byte* buf, word32 sz, byte* out)
{
    wc_Sha256 sha;
    int ret;

    /* Only free what was initialized: wc_Sha256Free reads members that a
     * failed wc_InitSha256 leaves indeterminate. */
    ret = wc_InitSha256(&sha);
    if (ret != 0) {
        return ret;
    }
    ret = wc_Sha256Update(&sha, buf, sz);
    if (ret == 0) {
        ret = wc_Sha256Final(&sha, out);
    }
    wc_Sha256Free(&sha);
    return ret;
}
#endif

/*
 * Deterministic key generation and signing, pinned by digest: the key digests
 * cover key generation, the signature digest covers signing. The integer
 * emulation, native double and assembly fpr backends are bit-exact with each
 * other, so one seed pins all three.
 *
 * AVX2 and NEON fuse multiply-add and falcon.c disclaims bit-identical output
 * for them; the digests still hold empirically, so a mismatch seen only there
 * is a rounding change to investigate before it is called a defect.
 */
int test_wc_falcon_deterministic(void)
{
    EXPECT_DECLS;
#if defined(WC_FALCON_HAVE_NATIVE_SIGN) && defined(WC_RNG_SEED_CB) && \
    defined(HAVE_HASHDRBG) && !defined(NO_SHA256) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS) && \
    !defined(HAVE_INTEL_RDRAND) && !defined(CUSTOM_RAND_GENERATE_BLOCK) && \
    !defined(WOLFSSL_RNG_USE_FULL_SEED) && defined(WOLFSSL_DRBG_SHA512)
    /* SHA-256 of the encoded public key, private key and signature the fixed
     * seed produces, indexed by level. Verified identical across the emulated,
     * asm, double, avx2, neon and small-mem builds. */
    static const byte expPub[2][WC_SHA256_DIGEST_SIZE] = {
        { 0x82, 0x67, 0x64, 0xA9, 0x6D, 0xAB, 0x82, 0xA0,
          0xC2, 0xD5, 0x38, 0x7E, 0xDF, 0x4F, 0xAC, 0x1C,
          0x62, 0xB0, 0x94, 0x2A, 0xEE, 0xA9, 0x50, 0x4E,
          0x3F, 0x3A, 0x95, 0x81, 0x44, 0x06, 0x85, 0x23 },
        { 0xFB, 0xA2, 0xEC, 0x57, 0x66, 0x98, 0xFA, 0x87,
          0x6D, 0xE4, 0x64, 0x21, 0x7F, 0x49, 0x82, 0x70,
          0xEA, 0x8B, 0x0D, 0x0F, 0x7C, 0xED, 0xAC, 0xA8,
          0x05, 0x20, 0x71, 0x0B, 0x49, 0xC4, 0xF3, 0x8E }
    };
    static const byte expPrv[2][WC_SHA256_DIGEST_SIZE] = {
        { 0x5B, 0x09, 0xEF, 0xE6, 0x49, 0xBF, 0x12, 0x5C,
          0x86, 0x7F, 0xEF, 0xC3, 0xC7, 0x0F, 0xA9, 0x3F,
          0x88, 0x31, 0x03, 0xC1, 0xFD, 0xDF, 0x28, 0x01,
          0x9E, 0xD1, 0x72, 0x74, 0x01, 0xE9, 0x06, 0x2C },
        { 0xFD, 0x4D, 0xB3, 0xB1, 0x96, 0x0F, 0x80, 0xEB,
          0x7E, 0x37, 0x49, 0x9E, 0x03, 0x3D, 0x53, 0x68,
          0x0B, 0x12, 0x16, 0xA9, 0xF6, 0x92, 0x76, 0xFA,
          0xCD, 0x89, 0x91, 0x3B, 0xE7, 0xEB, 0x11, 0x29 }
    };
    static const byte expSig[2][WC_SHA256_DIGEST_SIZE] = {
        { 0x52, 0x37, 0x4D, 0x5B, 0xFC, 0x1A, 0xCE, 0x05,
          0x86, 0xFA, 0x76, 0x9F, 0x07, 0xE6, 0x7D, 0x46,
          0xC9, 0x1D, 0x5A, 0xF9, 0x5B, 0x3E, 0x37, 0xDE,
          0x34, 0x58, 0x5E, 0x7E, 0xC0, 0xD3, 0xDB, 0x7F },
        { 0x78, 0x32, 0xB7, 0xB5, 0xDB, 0xA6, 0x65, 0x56,
          0x8B, 0x3E, 0x9D, 0xB4, 0xD7, 0x7D, 0x99, 0xD7,
          0x28, 0x85, 0x2B, 0x4D, 0xC4, 0x96, 0x26, 0xE9,
          0x08, 0x49, 0x91, 0x4A, 0x6D, 0x16, 0x6C, 0xC0 }
    };
    static const byte msg[] = "wolfSSL Falcon deterministic vector";
    falcon_key key;
    WC_RNG rng;
    byte* buf = NULL;
    byte* pub = NULL;
    byte* prv = NULL;
    byte* sig = NULL;
    byte dig[WC_SHA256_DIGEST_SIZE];
    int li;
    int seedCbSet = 0;

    buf = (byte*)XMALLOC(FALCON_MAX_PUB_KEY_SIZE + FALCON_MAX_KEY_SIZE +
        FALCON_MAX_SIG_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(buf);
    if (buf != NULL) {
        pub = buf;
        prv = pub + FALCON_MAX_PUB_KEY_SIZE;
        sig = prv + FALCON_MAX_KEY_SIZE;
    }

    /* The random group can leave the SHA-512 DRBG disabled process-wide, which
     * silently switches the stream. Skip rather than report six digest
     * mismatches for a reason that has nothing to do with Falcon. */
    if ((buf != NULL) && wc_Sha512Drbg_IsDisabled()) {
        XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return TEST_SKIPPED;
    }

    /* DoExpect, not ExpectIntEQ: the latter evaluates its argument only while
     * no earlier expectation has failed, so the restore at the end would be
     * skipped by the very failure it has to clean up after. */
    if (buf != NULL) {
        DoExpectIntEQ(wc_SetSeed_Cb(falcon_det_seed_cb), 0);
        seedCbSet = 1;
    }

    for (li = 0; (buf != NULL) && (li < FALCON_NUM_LEVELS); li++) {
        byte level = falcon_levels[li];
        /* The vectors are per level; the loop index is not, once a level can
         * be compiled out. */
        int gi = (level == FALCON_LEVEL1) ? 0 : 1;
        word32 pubLen = FALCON_MAX_PUB_KEY_SIZE;
        word32 prvLen = FALCON_MAX_KEY_SIZE;
        word32 sigLen = FALCON_MAX_SIG_SIZE;
        int res = 0;
        int rngInited = 0;

        XMEMSET(&key, 0, sizeof(key));
        XMEMSET(&rng, 0, sizeof(rng));

        /* Same reason: pair the free with an init that actually ran. */
        if (wc_InitRng(&rng) == 0) {
            rngInited = 1;
        }
        ExpectIntEQ(rngInited, 1);
        ExpectIntEQ(wc_falcon_init(&key), 0);
        ExpectIntEQ(wc_falcon_set_level(&key, level), 0);
        ExpectIntEQ(wc_falcon_make_key(&key, &rng), 0);

        ExpectIntEQ(wc_falcon_export_public(&key, pub, &pubLen), 0);
        ExpectIntEQ(falcon_det_digest(pub, pubLen, dig), 0);
        ExpectBufEQ(dig, expPub[gi], WC_SHA256_DIGEST_SIZE);

        ExpectIntEQ(wc_falcon_export_private_only(&key, prv, &prvLen), 0);
        ExpectIntEQ(falcon_det_digest(prv, prvLen, dig), 0);
        ExpectBufEQ(dig, expPrv[gi], WC_SHA256_DIGEST_SIZE);

        ExpectIntEQ(wc_falcon_sign_msg(msg, (word32)sizeof(msg), sig, &sigLen,
            &key, &rng), 0);
        ExpectIntEQ(falcon_det_digest(sig, sigLen, dig), 0);
        ExpectBufEQ(dig, expSig[gi], WC_SHA256_DIGEST_SIZE);

        /* The pinned signature must still verify, so a stale digest cannot
         * hide a signature that no longer works. */
        ExpectIntEQ(wc_falcon_verify_msg(sig, sigLen, msg, (word32)sizeof(msg),
            &res, &key), 0);
        ExpectIntEQ(res, 1);

        wc_falcon_free(&key);
        if (rngInited) {
            DoExpectIntEQ(wc_FreeRng(&rng), 0);
        }
    }

    if (seedCbSet) {
        DoExpectIntEQ(wc_SetSeed_Cb(WC_GENERATE_SEED_DEFAULT), 0);
    }

    if (buf != NULL) {
        /* Holds an exported private key. */
        ForceZero(buf, FALCON_MAX_PUB_KEY_SIZE + FALCON_MAX_KEY_SIZE +
            FALCON_MAX_SIG_SIZE);
    }
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}

/*
 * Signing the same key repeatedly, and reusing one key structure for different
 * keys and levels. With the per-key caches this covers the reuse and the three
 * points that have to drop the cache - key generation, private-key import and
 * a level change - which the verify against the current public key catches.
 */
int test_wc_falcon_key_reuse(void)
{
    EXPECT_DECLS;
#ifdef WC_FALCON_HAVE_NATIVE_SIGN
    falcon_key key;
    falcon_key other;
    WC_RNG rng;
    byte* sig = NULL;
    byte* prv = NULL;
    byte* pub = NULL;
    word32 sigLen;
    word32 prvLen;
    word32 pubLen;
    static const byte msg[] = "wolfSSL Falcon key reuse";
    int res = 0;
    int rngInited = 0;

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&other, 0, sizeof(other));
    XMEMSET(&rng, 0, sizeof(rng));

    sig = (byte*)XMALLOC(FALCON_MAX_SIG_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    prv = (byte*)XMALLOC(FALCON_MAX_KEY_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    pub = (byte*)XMALLOC(FALCON_MAX_PUB_KEY_SIZE, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(sig);
    ExpectNotNull(prv);
    ExpectNotNull(pub);

    /* Pair the free below with an init that actually ran: ExpectIntEQ skips its
     * argument once an earlier expectation has failed. */
    if (wc_InitRng(&rng) == 0) {
        rngInited = 1;
    }
    ExpectIntEQ(rngInited, 1);
    ExpectIntEQ(wc_falcon_init(&key), 0);
    ExpectIntEQ(wc_falcon_set_level(&key, falcon_levels[0]), 0);
    ExpectIntEQ(wc_falcon_make_key(&key, &rng), 0);

    /* Two signatures with one key: the second runs off the cache. */
    sigLen = FALCON_MAX_SIG_SIZE;
    ExpectIntEQ(wc_falcon_sign_msg(msg, (word32)sizeof(msg), sig, &sigLen,
        &key, &rng), 0);
    ExpectIntEQ(wc_falcon_verify_msg(sig, sigLen, msg, (word32)sizeof(msg),
        &res, &key), 0);
    ExpectIntEQ(res, 1);

    res = 0;
    sigLen = FALCON_MAX_SIG_SIZE;
    ExpectIntEQ(wc_falcon_sign_msg(msg, (word32)sizeof(msg), sig, &sigLen,
        &key, &rng), 0);
    ExpectIntEQ(wc_falcon_verify_msg(sig, sigLen, msg, (word32)sizeof(msg),
        &res, &key), 0);
    ExpectIntEQ(res, 1);

    /* A different key imported over the same structure must be the one that
     * signs from then on. */
    ExpectIntEQ(wc_falcon_init(&other), 0);
    ExpectIntEQ(wc_falcon_set_level(&other, falcon_levels[0]), 0);
    ExpectIntEQ(wc_falcon_make_key(&other, &rng), 0);
    prvLen = FALCON_MAX_KEY_SIZE;
    pubLen = FALCON_MAX_PUB_KEY_SIZE;
    ExpectIntEQ(wc_falcon_export_private_only(&other, prv, &prvLen), 0);
    ExpectIntEQ(wc_falcon_export_public(&other, pub, &pubLen), 0);
    ExpectIntEQ(wc_falcon_import_private_key(prv, prvLen, pub, pubLen, &key),
        0);

    res = 0;
    sigLen = FALCON_MAX_SIG_SIZE;
    ExpectIntEQ(wc_falcon_sign_msg(msg, (word32)sizeof(msg), sig, &sigLen,
        &key, &rng), 0);
    ExpectIntEQ(wc_falcon_verify_msg(sig, sigLen, msg, (word32)sizeof(msg),
        &res, &other), 0);
    ExpectIntEQ(res, 1);

#if !defined(WOLFSSL_NO_FALCON_LEVEL1) && !defined(WOLFSSL_NO_FALCON_LEVEL5)
    /* Switching the level resizes everything the cache holds. */
    ExpectIntEQ(wc_falcon_set_level(&key, FALCON_LEVEL5), 0);
    ExpectIntEQ(wc_falcon_make_key(&key, &rng), 0);
    res = 0;
    sigLen = FALCON_MAX_SIG_SIZE;
    ExpectIntEQ(wc_falcon_sign_msg(msg, (word32)sizeof(msg), sig, &sigLen,
        &key, &rng), 0);
    ExpectIntEQ(wc_falcon_verify_msg(sig, sigLen, msg, (word32)sizeof(msg),
        &res, &key), 0);
    ExpectIntEQ(res, 1);

    /* Back down to the smaller level, to cover shrinking as well. */
    ExpectIntEQ(wc_falcon_set_level(&key, FALCON_LEVEL1), 0);
    ExpectIntEQ(wc_falcon_make_key(&key, &rng), 0);
    res = 0;
    sigLen = FALCON_MAX_SIG_SIZE;
    ExpectIntEQ(wc_falcon_sign_msg(msg, (word32)sizeof(msg), sig, &sigLen,
        &key, &rng), 0);
    ExpectIntEQ(wc_falcon_verify_msg(sig, sigLen, msg, (word32)sizeof(msg),
        &res, &key), 0);
    ExpectIntEQ(res, 1);
#endif /* both levels */

    wc_falcon_free(&other);
    wc_falcon_free(&key);
    if (rngInited) {
        DoExpectIntEQ(wc_FreeRng(&rng), 0);
    }
    XFREE(pub, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (prv != NULL) {
        /* Holds an exported private key. */
        ForceZero(prv, FALCON_MAX_KEY_SIZE);
    }
    XFREE(prv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}

#if defined(WOLFSSL_FALCON_DYNAMIC_KEYS) && \
    defined(WC_FALCON_HAVE_NATIVE_SIGN) && defined(USE_WOLFSSL_MEMORY) && \
    !defined(WOLFSSL_STATIC_MEMORY) && !defined(WOLFSSL_DEBUG_MEMORY) && \
    !defined(NO_TLS) && !defined(NO_CERTS) && \
    (!defined(NO_WOLFSSL_CLIENT) || !defined(NO_WOLFSSL_SERVER))
#define FALCON_OOM_TEST

static wolfSSL_Malloc_cb  falcon_oom_mf;
static wolfSSL_Free_cb    falcon_oom_ff;
static wolfSSL_Realloc_cb falcon_oom_rf;
static int falcon_oom_failAt = -1;
static int falcon_oom_kCount;
static int falcon_oom_live;

/* Only wc_falcon_set_level allocates exactly a level's private key size. */
static int falcon_oom_is_kbuf(size_t n)
{
    int i;

    for (i = 0; i < FALCON_NUM_LEVELS; i++) {
        if (n == (size_t)falcon_exp_key(falcon_levels[i])) {
            return 1;
        }
    }
    return 0;
}

static void* falcon_oom_malloc(size_t n)
{
    void* p;

    if (falcon_oom_is_kbuf(n) && (falcon_oom_kCount++ == falcon_oom_failAt)) {
        return NULL;
    }
    p = (falcon_oom_mf != NULL) ? falcon_oom_mf(n) : malloc(n);
    if (p != NULL) {
        falcon_oom_live++;
    }
    return p;
}

static void falcon_oom_free(void* p)
{
    if (p != NULL) {
        falcon_oom_live--;
    }
    if (falcon_oom_ff != NULL) {
        falcon_oom_ff(p);
    }
    else {
        free(p);
    }
}

static void* falcon_oom_realloc(void* p, size_t n)
{
    void* r = (falcon_oom_rf != NULL) ? falcon_oom_rf(p, n) : realloc(p, n);

    if ((p == NULL) && (r != NULL)) {
        falcon_oom_live++;
    }
    return r;
}

static int falcon_oom_save(void)
{
    return wolfSSL_GetAllocators(&falcon_oom_mf, &falcon_oom_ff,
        &falcon_oom_rf);
}

/* failAt -1 only counts the private key buffer allocations. */
static int falcon_oom_install(int failAt)
{
    falcon_oom_failAt = failAt;
    falcon_oom_kCount = 0;
    falcon_oom_live = 0;
    return wolfSSL_SetAllocators(falcon_oom_malloc, falcon_oom_free,
        falcon_oom_realloc);
}

static void falcon_oom_restore(void)
{
    (void)wolfSSL_SetAllocators(falcon_oom_mf, falcon_oom_ff, falcon_oom_rf);
}

/* Runs one caller of wc_falcon_set_level; returns 1 when it accepted the key. */
static int falcon_oom_run(int which, const byte* der, word32 derSz,
    const byte* pub, word32 pubSz)
{
    int ok = 0;

    if (which == 0) {
        WOLFSSL_CTX* ctx;

    #ifndef NO_WOLFSSL_CLIENT
        ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    #elif !defined(NO_WOLFSSL_SERVER)
        ctx = wolfSSL_CTX_new(wolfSSLv23_server_method());
    #endif
        if (ctx != NULL) {
            ok = (wolfSSL_CTX_use_PrivateKey_buffer(ctx, der, (long)derSz,
                WOLFSSL_FILETYPE_ASN1) == WOLFSSL_SUCCESS);
            wolfSSL_CTX_free(ctx);
        }
    }
#ifdef OPENSSL_EXTRA
    else {
        const unsigned char* p = pub;
        WOLFSSL_EVP_PKEY* pkey = wolfSSL_d2i_PUBKEY(NULL, &p, (long)pubSz);

        ok = (pkey != NULL);
        wolfSSL_EVP_PKEY_free(pkey);
    }
#endif
#if defined(OPENSSL_EXTRA) || defined(DEBUG_WOLFSSL_VERBOSE)
    wolfSSL_ERR_clear_error();
#endif
    (void)pub;
    (void)pubSz;
    return ok;
}
#endif

/* A failed wc_falcon_set_level allocation must fail its caller outright:
 * nothing leaked, and no further level tried. */
int test_wc_falcon_set_level_oom_callers(void)
{
    EXPECT_DECLS;
#ifdef FALCON_OOM_TEST
    falcon_key key;
    WC_RNG rng;
    byte* der = NULL;
    byte pub[FALCON_MAX_PUB_KEY_SIZE];
    word32 pubSz;
    int derSz = 0;
    int li;
    int which;
    int n;
    int total;
    int ok;
    const word32 derMax = 2 * FALCON_MAX_PRV_KEY_SIZE;
#ifdef OPENSSL_EXTRA
    const int numCallers = 2;
#else
    const int numCallers = 1;
#endif

    XMEMSET(&rng, 0, sizeof(rng));
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectNotNull(der = (byte*)XMALLOC(derMax, NULL, DYNAMIC_TYPE_TMP_BUFFER));
    ExpectIntEQ(falcon_oom_save(), 0);

    for (li = 0; EXPECT_SUCCESS() && (li < FALCON_NUM_LEVELS); li++) {
        XMEMSET(&key, 0, sizeof(key));
        ExpectIntEQ(wc_falcon_init(&key), 0);
        ExpectIntEQ(wc_falcon_set_level(&key, falcon_levels[li]), 0);
        ExpectIntEQ(wc_falcon_make_key(&key, &rng), 0);
        ExpectIntGT(derSz = wc_Falcon_KeyToDer(&key, der, derMax), 0);
        pubSz = (word32)sizeof(pub);
        ExpectIntEQ(wc_falcon_export_public(&key, pub, &pubSz), 0);
        wc_falcon_free(&key);

        for (which = 0; EXPECT_SUCCESS() && (which < numCallers); which++) {
            ExpectIntEQ(falcon_oom_install(-1), 0);
            ok = falcon_oom_run(which, der, (word32)derSz, pub, pubSz);
            total = falcon_oom_kCount;
            falcon_oom_restore();
            ExpectIntEQ(ok, 1);
            ExpectIntGT(total, 0);
            ExpectIntEQ(falcon_oom_live, 0);

            for (n = 0; EXPECT_SUCCESS() && (n < total); n++) {
                ExpectIntEQ(falcon_oom_install(n), 0);
                ok = falcon_oom_run(which, der, (word32)derSz, pub, pubSz);
                falcon_oom_restore();
                ExpectIntEQ(ok, 0);
                ExpectIntEQ(falcon_oom_kCount, n + 1);
                ExpectIntEQ(falcon_oom_live, 0);
            }
        }
    }

    falcon_oom_failAt = -1;
    if (der != NULL) {
        ForceZero(der, derMax);
    }
    XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
}

/*
 * MC/DC decision coverage for the public wc_falcon_* wrapper decisions that the
 * functional tests above leave with an unshown independence pair. Each block
 * targets one decision and supplies the operand combinations that flip exactly
 * one condition at a time while the others are held non-determining (the MC/DC
 * requirement), using cheap negative/edge inputs that stop at the guard under
 * test. No key generation is performed here (the positive fall-through half of
 * each guard is owned by test_wc_falcon_make_key / _sign_vfy above, which run a
 * real key).
 *
 * Documented residuals (operands whose determined half is unreachable in this
 * software build): the `ret == 0` operands guarding the !prvKeySet and
 * rng==NULL tests in wc_falcon_sign_msg, and the !pubKeySet test in
 * wc_falcon_verify_msg, are only ever 0 on the software path, where ret is
 * assigned non-zero solely by a WOLF_CRYPTO_CB callback error, absent here, so
 * their FALSE half cannot be demonstrated without a crypto-callback harness
 * (same residual class as the rsa/mldsa `ret==0`-chain guards).
 */
int test_wc_FalconDecisionCoverage(void)
{
    EXPECT_DECLS;
#ifdef HAVE_FALCON
    falcon_key key;
    byte out[64];
    word32 outLen;
    /* Buffers sized for a raw Falcon-512 private/public import so the ret==0
     * arm of wc_falcon_import_private_key is reachable without keygen. */
    /* Sized for the largest level built; the imports below use the exact size
     * of the level actually in use, since a mismatch is itself rejected. */
    static byte prv[FALCON_MAX_KEY_SIZE];
    static byte pub[FALCON_MAX_PUB_KEY_SIZE];

    XMEMSET(prv, 0, sizeof(prv));
    XMEMSET(pub, 0, sizeof(pub));

    /* ---- (key->level != 1) && (key->level != 5) -------------------------
     * export_public / export_private_only / export_private / check_key each
     * open with this AND. Three levels flip each operand independently:
     *   level 1 -> (F, .)  op0 determines the result false
     *   level 5 -> (T, F)  op1 determines the result false
     *   level 2 -> (T, T)  both true -> BAD_FUNC_ARG
     * level 2 is not settable via wc_falcon_set_level (it rejects non-1/5), so
     * it is written directly on the public struct. With no key material set,
     * level 1/5 fall through the AND to the key-not-set guard (which returns
     * BAD_FUNC_ARG for export, PUBLIC_KEY_E for check_key); no buffer copy
     * occurs, so the small out[] buffer is never touched. */
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_falcon_init(&key), 0);
#ifndef WOLFSSL_NO_FALCON_LEVEL1
    ExpectIntEQ(wc_falcon_set_level(&key, FALCON_LEVEL1), 0);
    outLen = (word32)sizeof(out);
    ExpectIntEQ(wc_falcon_export_public(&key, out, &outLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));       /* level ok, pubKey unset */
    outLen = (word32)sizeof(out);
    ExpectIntEQ(wc_falcon_export_private_only(&key, out, &outLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    outLen = (word32)sizeof(out);
    ExpectIntEQ(wc_falcon_export_private(&key, out, &outLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_falcon_check_key(&key),
        WC_NO_ERR_TRACE(PUBLIC_KEY_E));        /* level ok, halves unset */
#endif

#ifndef WOLFSSL_NO_FALCON_LEVEL5
    ExpectIntEQ(wc_falcon_set_level(&key, FALCON_LEVEL5), 0);
    outLen = (word32)sizeof(out);
    ExpectIntEQ(wc_falcon_export_public(&key, out, &outLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    outLen = (word32)sizeof(out);
    ExpectIntEQ(wc_falcon_export_private_only(&key, out, &outLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    outLen = (word32)sizeof(out);
    ExpectIntEQ(wc_falcon_export_private(&key, out, &outLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_falcon_check_key(&key), WC_NO_ERR_TRACE(PUBLIC_KEY_E));
#endif

    key.level = 2; /* invalid -> (level!=1)&&(level!=5) both true */
    outLen = (word32)sizeof(out);
    ExpectIntEQ(wc_falcon_export_public(&key, out, &outLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    outLen = (word32)sizeof(out);
    ExpectIntEQ(wc_falcon_export_private_only(&key, out, &outLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    outLen = (word32)sizeof(out);
    ExpectIntEQ(wc_falcon_export_private(&key, out, &outLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_falcon_check_key(&key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    wc_falcon_free(&key);

    /* ---- export NULL-argument independence -----------------------------
     * (key==NULL) || (out==NULL) || (outLen==NULL): the key==NULL half is
     * shown by test_wc_falcon_error_paths; here we flip the middle and last
     * operands with the earlier ones held false (valid key, level set). */
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_falcon_init(&key), 0);
    ExpectIntEQ(wc_falcon_set_level(&key, falcon_levels[0]), 0);
    outLen = (word32)sizeof(out);
    ExpectIntEQ(wc_falcon_export_private_only(&key, NULL, &outLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));        /* out==NULL determines */
    ExpectIntEQ(wc_falcon_export_private_only(&key, out, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));        /* outLen==NULL determines */
    outLen = (word32)sizeof(out);
    ExpectIntEQ(wc_falcon_export_private(&key, NULL, &outLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_falcon_export_private(&key, out, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    wc_falcon_free(&key);

    /* ---- import (priv==NULL) || (key==NULL) ----------------------------
     * priv==NULL shown by error_paths; here flip key==NULL with priv held
     * non-NULL. */
    ExpectIntEQ(wc_falcon_import_private_only(prv,
        falcon_exp_key(falcon_levels[0]), NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_falcon_import_private_key(prv,
        falcon_exp_key(falcon_levels[0]),
        NULL, 0, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* ---- wc_falcon_import_private_key: (ret==0) && (pub != NULL) --------
     * A correctly sized raw private import returns 0 without keygen, so the
     * ret==0 operand is genuinely true here. Flip pub between NULL and set:
     *   valid priv, pub==NULL  -> ret==0, pub!=NULL F -> import stops, 0
     *   valid priv, pub set    -> ret==0, pub!=NULL T -> public import runs
     *   bad priv size, pub NULL-> ret!=0 (op0 F) short-circuits the AND */
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_falcon_init(&key), 0);
    ExpectIntEQ(wc_falcon_set_level(&key, falcon_levels[0]), 0);
    ExpectIntEQ(wc_falcon_import_private_key(prv,
        falcon_exp_key(falcon_levels[0]),
        NULL, 0, &key), 0);                    /* pub!=NULL F */
    wc_falcon_free(&key);
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_falcon_init(&key), 0);
    ExpectIntEQ(wc_falcon_set_level(&key, falcon_levels[0]), 0);
    ExpectIntEQ(wc_falcon_import_private_key(prv,
        falcon_exp_key(falcon_levels[0]),
        pub, falcon_exp_pub(falcon_levels[0]), &key), 0); /* pub!=NULL T */
    wc_falcon_free(&key);
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_falcon_init(&key), 0);
    ExpectIntEQ(wc_falcon_set_level(&key, falcon_levels[0]), 0);
    ExpectIntEQ(wc_falcon_import_private_key(prv, 1 /* bad size */,
        NULL, 0, &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG)); /* ret!=0 (op0 F) */
    wc_falcon_free(&key);

#ifdef WC_FALCON_HAVE_NATIVE_SIGN
    /* ---- wc_falcon_sign_msg: (ret==0) && (!prvKeySet), then
     *      (ret==0) && (rng==NULL) --------------------------------------
     * All of in/out/outLen/key are non-NULL so the front guard falls through.
     *   level set, prvKeySet=0        -> (!prvKeySet) T -> BAD
     *   prvKeySet forced, rng==NULL   -> (!prvKeySet) F (falls through),
     *                                    (rng==NULL) T -> BAD (native signer
     *                                    never entered, so the unset key
     *                                    material is never dereferenced).
     * The (!prvKeySet) F + valid-rng fall-through into the native signer is
     * owned by test_wc_falcon_sign_vfy (real key). */
    {
        WC_RNG rng;
        byte msg[4];
        XMEMSET(&rng, 0, sizeof(rng));
        XMEMSET(msg, 0, sizeof(msg));
        XMEMSET(&key, 0, sizeof(key));
        ExpectIntEQ(wc_falcon_init(&key), 0);
        ExpectIntEQ(wc_falcon_set_level(&key, falcon_levels[0]), 0);
        outLen = (word32)sizeof(out);
        ExpectIntEQ(wc_falcon_sign_msg(msg, (word32)sizeof(msg), out, &outLen,
            &key, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));   /* !prvKeySet T */
        key.prvKeySet = 1;                                 /* !prvKeySet F */
        outLen = (word32)sizeof(out);
        ExpectIntEQ(wc_falcon_sign_msg(msg, (word32)sizeof(msg), out, &outLen,
            &key, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));   /* rng==NULL T */
        wc_falcon_free(&key);
    }
#endif /* WC_FALCON_HAVE_NATIVE_SIGN */

#ifndef WOLF_CRYPTO_CB_ONLY_FALCON
    /* ---- wc_falcon_verify_msg: (ret==0) && (!pubKeySet) ----------------
     * Valid args, level set, pubKeySet=0 -> (!pubKeySet) T -> BAD. The
     * (!pubKeySet) F fall-through into the native verifier is owned by
     * test_wc_falcon_sign_vfy (real key). */
    {
        byte msg[4];
        int res = 0;
        XMEMSET(msg, 0, sizeof(msg));
        XMEMSET(&key, 0, sizeof(key));
        ExpectIntEQ(wc_falcon_init(&key), 0);
        ExpectIntEQ(wc_falcon_set_level(&key, falcon_levels[0]), 0);
        ExpectIntEQ(wc_falcon_verify_msg(msg, (word32)sizeof(msg), msg,
            (word32)sizeof(msg), &res, &key),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));                /* !pubKeySet T */
        wc_falcon_free(&key);
    }
#endif /* !WOLF_CRYPTO_CB_ONLY_FALCON */

#ifdef WOLF_PRIVATE_KEY_ID
    /* ---- wc_falcon_init_id: ret==0 && (len<0 || len>FALCON_MAX_ID_LEN),
     *      then ret==0 && id!=NULL && len!=0 ----------------------------- */
    {
        falcon_key idkey;
        static const byte idbytes[FALCON_MAX_ID_LEN] = { 0 };

        /* The frees below are unconditional; ExpectIntEQ skips the paired init
         * once an earlier expectation has failed. */
        XMEMSET(&idkey, 0, sizeof(idkey));

        /* key==NULL -> ret!=0 before the length AND -> ret==0 operand F */
        ExpectIntEQ(wc_falcon_init_id(NULL, idbytes, 4, NULL, INVALID_DEVID),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* valid len: length test all-false, then id!=NULL && len!=0 all-true.
         * A successful init sets the level, which owns two allocations with
         * WOLFSSL_FALCON_DYNAMIC_KEYS, and re-initializing drops the pointers
         * to them - so each one is released before the next init runs. */
        ExpectIntEQ(wc_falcon_init_id(&idkey, idbytes, 4, NULL, INVALID_DEVID),
            0);
        wc_falcon_free(&idkey);
        /* len < 0 -> first length operand determines */
        ExpectIntEQ(wc_falcon_init_id(&idkey, idbytes, -1, NULL, INVALID_DEVID),
            WC_NO_ERR_TRACE(BUFFER_E));
        /* len > FALCON_MAX_ID_LEN -> second length operand determines */
        ExpectIntEQ(wc_falcon_init_id(&idkey, idbytes, FALCON_MAX_ID_LEN + 1,
            NULL, INVALID_DEVID), WC_NO_ERR_TRACE(BUFFER_E));
        /* id==NULL with a positive len -> no identifier to store */
        ExpectIntEQ(wc_falcon_init_id(&idkey, NULL, 4, NULL, INVALID_DEVID),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* id==NULL with len==0 -> (id!=NULL) operand F, skips copy */
        ExpectIntEQ(wc_falcon_init_id(&idkey, NULL, 0, NULL, INVALID_DEVID), 0);
        wc_falcon_free(&idkey);
        /* len==0 with non-NULL id -> (len!=0) operand F, skips copy */
        ExpectIntEQ(wc_falcon_init_id(&idkey, idbytes, 0, NULL, INVALID_DEVID),
            0);
        wc_falcon_free(&idkey);
    }

    /* ---- wc_falcon_init_label: (key==NULL)||(label==NULL), then
     *      (labelLen==0)||(labelLen>FALCON_MAX_LABEL_LEN) ---------------- */
    {
        falcon_key lblkey;
        char toolong[FALCON_MAX_LABEL_LEN + 2];
        XMEMSET(&lblkey, 0, sizeof(lblkey));
        XMEMSET(toolong, 'a', sizeof(toolong));
        toolong[sizeof(toolong) - 1] = '\0';

        /* key==NULL determines the first OR */
        ExpectIntEQ(wc_falcon_init_label(NULL, "lbl", NULL, INVALID_DEVID),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* key ok, label==NULL determines the first OR */
        ExpectIntEQ(wc_falcon_init_label(&lblkey, NULL, NULL, INVALID_DEVID),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* both non-NULL -> falls through to the length OR; "" -> len==0 T */
        ExpectIntEQ(wc_falcon_init_label(&lblkey, "", NULL, INVALID_DEVID),
            WC_NO_ERR_TRACE(BUFFER_E));
        /* valid label -> length OR all-false -> success. Released for the same
         * reason as the init_id block above. */
        ExpectIntEQ(wc_falcon_init_label(&lblkey, "lbl", NULL, INVALID_DEVID),
            0);
        wc_falcon_free(&lblkey);
        /* over-long label -> (labelLen>MAX) operand determines */
        ExpectIntEQ(wc_falcon_init_label(&lblkey, toolong, NULL, INVALID_DEVID),
            WC_NO_ERR_TRACE(BUFFER_E));
    }
#endif /* WOLF_PRIVATE_KEY_ID */
#endif /* HAVE_FALCON */
    return EXPECT_RESULT();
}

#if defined(HAVE_FALCON) && defined(WOLF_CRYPTO_CB) && \
    defined(WOLF_CRYPTO_CB_FREE)
    #define TEST_FALCON_CB_FREE
    #define TEST_FALCON_CB_FREE_DEVID 0x46414C43
#endif

#ifdef TEST_FALCON_CB_FREE
/* What the free callback saw, so the test can check the contract rather than
 * just that something fired. */
typedef struct {
    int frees;        /* matching free callbacks seen */
    int badObj;       /* callback was handed the wrong object */
    int wiped;        /* callback saw a key already cleaned up */
    int ret;          /* what the callback returns */
    const void* obj;  /* object the free is expected to name */
} FalconCbFreeCtx;

/* Stands in for a device holding state for the key. Counting the call proves
 * wc_falcon_free told the device rather than only cleaning up in software,
 * which would leave the device side of the key behind. */
static int falcon_cb_free_cb(int devIdArg, wc_CryptoInfo* info, void* ctx)
{
    FalconCbFreeCtx* seen = (FalconCbFreeCtx*)ctx;

    (void)devIdArg;

    if ((seen != NULL) && (info != NULL) &&
            (info->algo_type == WC_ALGO_TYPE_FREE) &&
            (info->free.algo == WC_ALGO_TYPE_PK) &&
            (info->free.type == WC_PK_TYPE_PQC_SIG_KEYGEN) &&
            (info->free.subType == WC_PQC_SIG_TYPE_FALCON)) {
        const falcon_key* fk = (const falcon_key*)info->free.obj;

        seen->frees++;
        if ((fk == NULL) || ((const void*)fk != seen->obj)) {
            seen->badObj++;
        }
        /* The device gets the key while it is still whole: it may need to
         * read it to release the right resource, so the software wipe has
         * to come after this call, not before. */
        else if (fk->devId != TEST_FALCON_CB_FREE_DEVID) {
            seen->wiped++;
        }
        return seen->ret;
    }

    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}
#endif /* TEST_FALCON_CB_FREE */

/* Freeing a key that names a device has to tell that device, so it can
 * release what it holds. A key with no device must not, and neither must a
 * second free of a key already freed: a freed key names no device. A device
 * that reports an error does not stop the software cleanup. */
int test_falcon_cb_free(void)
{
    EXPECT_DECLS;
#ifdef TEST_FALCON_CB_FREE
    falcon_key key;
    FalconCbFreeCtx seen;

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&seen, 0, sizeof(seen));
    seen.obj = &key;

    /* No key to free, and nothing to tell a device about. */
    wc_falcon_free(NULL);

    ExpectIntEQ(wc_CryptoCb_RegisterDevice(TEST_FALCON_CB_FREE_DEVID,
        falcon_cb_free_cb, &seen), 0);

    ExpectIntEQ(wc_falcon_init_ex(&key, NULL, TEST_FALCON_CB_FREE_DEVID), 0);
    wc_falcon_free(&key);
    ExpectIntEQ(seen.frees, 1);
    ExpectIntEQ(seen.badObj, 0);
    ExpectIntEQ(seen.wiped, 0);
    ExpectIntEQ(key.devId, INVALID_DEVID);

    wc_falcon_free(&key);
    ExpectIntEQ(seen.frees, 1);

    /* A device that fails still leaves the key cleaned up locally. */
    seen.ret = WC_NO_ERR_TRACE(WC_HW_E);
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_falcon_init_ex(&key, NULL, TEST_FALCON_CB_FREE_DEVID), 0);
    ExpectIntEQ(wc_falcon_set_level(&key, falcon_levels[0]), 0);
    wc_falcon_free(&key);
    ExpectIntEQ(seen.frees, 2);
    ExpectIntEQ(key.devId, INVALID_DEVID);
    ExpectIntEQ(key.level, 0);
    seen.ret = 0;

    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_falcon_init_ex(&key, NULL, INVALID_DEVID), 0);
    wc_falcon_free(&key);
    ExpectIntEQ(seen.frees, 2);

    wc_CryptoCb_UnRegisterDevice(TEST_FALCON_CB_FREE_DEVID);
#endif
    return EXPECT_RESULT();
}
