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
 * Coverage note: Falcon-512 (NIST L1) and Falcon-1024 (NIST L5) are always both
 * compiled when HAVE_FALCON is set, so every test iterates both levels. Tests
 * that need key generation or signing are gated on WC_FALCON_HAVE_NATIVE_SIGN
 * (undefined in WOLFSSL_FALCON_VERIFY_ONLY / WOLF_CRYPTO_CB_ONLY_FALCON builds).
 * Argument-sanitising (NULL, bad level, buffer-too-small, wrong-size) tests only
 * need the always-present entry points and run under HAVE_FALCON.
 */

#ifdef HAVE_FALCON

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
    static const byte levels[2] = { FALCON_LEVEL1, FALCON_LEVEL5 };

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

    for (li = 0; li < 2; li++) {
        byte level = levels[li];
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

    /* Pin the spec constants so an accidental edit to falcon.h surfaces here. */
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
    static const byte levels[2] = { FALCON_LEVEL1, FALCON_LEVEL5 };

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

    for (li = 0; li < 2; li++) {
        byte level = levels[li];

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
    static const byte levels[2] = { FALCON_LEVEL1, FALCON_LEVEL5 };

    sig = (byte*)XMALLOC(FALCON_MAX_SIG_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(sig);

    XMEMSET(&rng, 0, sizeof(rng));
    ExpectIntEQ(wc_InitRng(&rng), 0);

    for (li = 0; li < 2; li++) {
        byte level = levels[li];

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
    ExpectIntEQ(wc_falcon_set_level(&key, FALCON_LEVEL1), 0);
    res = 0;
    ExpectIntEQ(wc_falcon_verify_msg(sig, FALCON_LEVEL1_SIG_SIZE, msg,
        (word32)sizeof(msg), &res, &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
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
    static const byte levels[2] = { FALCON_LEVEL1, FALCON_LEVEL5 };

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

    for (li = 0; li < 2; li++) {
        byte level = levels[li];
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
    static const byte levels[2] = { FALCON_LEVEL1, FALCON_LEVEL5 };

    pub = (byte*)XMALLOC(FALCON_MAX_PUB_KEY_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    prv = (byte*)XMALLOC(FALCON_MAX_KEY_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(pub);
    ExpectNotNull(prv);

    XMEMSET(&rng, 0, sizeof(rng));
    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* NULL key. */
    ExpectIntEQ(wc_falcon_check_key(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    for (li = 0; li < 2; li++) {
        byte level = levels[li];

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
    static const byte levels[2] = { FALCON_LEVEL1, FALCON_LEVEL5 };

    der = (byte*)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    sig = (byte*)XMALLOC(FALCON_MAX_SIG_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(der);
    ExpectNotNull(sig);

    XMEMSET(&rng, 0, sizeof(rng));
    ExpectIntEQ(wc_InitRng(&rng), 0);

    for (li = 0; li < 2; li++) {
        byte level = levels[li];

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
    ExpectIntEQ(wc_falcon_set_level(&key, FALCON_LEVEL1), 0);
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

/*
 * MC/DC decision coverage for the public wc_falcon_* wrapper decisions that the
 * functional tests above leave with an unshown independence pair. Each block
 * targets one decision and supplies the operand combinations that flip exactly
 * one condition at a time while the others are held non-determining (the MC/DC
 * requirement), using cheap negative/edge inputs that stop at the guard under
 * test -- no key generation is performed here (the positive fall-through half of
 * each guard is owned by test_wc_falcon_make_key / _sign_vfy above, which run a
 * real key).
 *
 * Documented residuals (operands whose determined half is unreachable in this
 * software build): the `ret == 0` operands in wc_falcon_sign_msg (8748/8751) and
 * wc_falcon_verify_msg (8801) are only ever 0 on the software path -- ret is
 * assigned non-zero solely by a WOLF_CRYPTO_CB callback error, absent here -- so
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
    static byte prv[FALCON_LEVEL1_KEY_SIZE];
    static byte pub[FALCON_LEVEL1_PUB_KEY_SIZE];

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
    ExpectIntEQ(wc_falcon_set_level(&key, FALCON_LEVEL1), 0);
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
    ExpectIntEQ(wc_falcon_import_private_only(prv, FALCON_LEVEL1_KEY_SIZE, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_falcon_import_private_key(prv, FALCON_LEVEL1_KEY_SIZE,
        NULL, 0, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* ---- wc_falcon_import_private_key: (ret==0) && (pub != NULL) --------
     * A correctly sized raw private import returns 0 without keygen, so the
     * ret==0 operand is genuinely true here. Flip pub between NULL and set:
     *   valid priv, pub==NULL  -> ret==0, pub!=NULL F -> import stops, 0
     *   valid priv, pub set    -> ret==0, pub!=NULL T -> public import runs
     *   bad priv size, pub NULL-> ret!=0 (op0 F) short-circuits the AND */
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_falcon_init(&key), 0);
    ExpectIntEQ(wc_falcon_set_level(&key, FALCON_LEVEL1), 0);
    ExpectIntEQ(wc_falcon_import_private_key(prv, FALCON_LEVEL1_KEY_SIZE,
        NULL, 0, &key), 0);                    /* pub!=NULL F */
    wc_falcon_free(&key);
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_falcon_init(&key), 0);
    ExpectIntEQ(wc_falcon_set_level(&key, FALCON_LEVEL1), 0);
    ExpectIntEQ(wc_falcon_import_private_key(prv, FALCON_LEVEL1_KEY_SIZE,
        pub, FALCON_LEVEL1_PUB_KEY_SIZE, &key), 0); /* pub!=NULL T */
    wc_falcon_free(&key);
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_falcon_init(&key), 0);
    ExpectIntEQ(wc_falcon_set_level(&key, FALCON_LEVEL1), 0);
    ExpectIntEQ(wc_falcon_import_private_key(prv, 1 /* bad size */,
        NULL, 0, &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG)); /* ret!=0 (op0 F) */
    wc_falcon_free(&key);

#ifdef WC_FALCON_HAVE_NATIVE_SIGN
    /* ---- wc_falcon_sign_msg: (ret==0) && (!prvKeySet), then
     *      (ret==0) && (rng==NULL) --------------------------------------
     * All of in/out/outLen/key are non-NULL so the front guard falls through.
     *   level set, prvKeySet=0        -> 8748 (!prvKeySet) T -> BAD
     *   prvKeySet forced, rng==NULL   -> 8748 (!prvKeySet) F (falls through),
     *                                    8751 (rng==NULL) T -> BAD (native
     *                                    signer never entered, so the unset
     *                                    key material is never dereferenced).
     * The (!prvKeySet) F + valid-rng fall-through into the native signer is
     * owned by test_wc_falcon_sign_vfy (real key). */
    {
        WC_RNG rng;
        byte msg[4];
        XMEMSET(&rng, 0, sizeof(rng));
        XMEMSET(msg, 0, sizeof(msg));
        XMEMSET(&key, 0, sizeof(key));
        ExpectIntEQ(wc_falcon_init(&key), 0);
        ExpectIntEQ(wc_falcon_set_level(&key, FALCON_LEVEL1), 0);
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
        ExpectIntEQ(wc_falcon_set_level(&key, FALCON_LEVEL1), 0);
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

        /* key==NULL -> ret!=0 before the length AND -> ret==0 operand F */
        ExpectIntEQ(wc_falcon_init_id(NULL, idbytes, 4, NULL, INVALID_DEVID),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* valid len -> length test all-false, then id!=NULL && len!=0 all-true */
        ExpectIntEQ(wc_falcon_init_id(&idkey, idbytes, 4, NULL, INVALID_DEVID),
            0);
        /* len < 0 -> first length operand determines */
        ExpectIntEQ(wc_falcon_init_id(&idkey, idbytes, -1, NULL, INVALID_DEVID),
            WC_NO_ERR_TRACE(BUFFER_E));
        /* len > FALCON_MAX_ID_LEN -> second length operand determines */
        ExpectIntEQ(wc_falcon_init_id(&idkey, idbytes, FALCON_MAX_ID_LEN + 1,
            NULL, INVALID_DEVID), WC_NO_ERR_TRACE(BUFFER_E));
        /* id==NULL with valid len -> (id!=NULL) operand F, skips copy */
        ExpectIntEQ(wc_falcon_init_id(&idkey, NULL, 4, NULL, INVALID_DEVID), 0);
        /* len==0 with non-NULL id -> (len!=0) operand F, skips copy */
        ExpectIntEQ(wc_falcon_init_id(&idkey, idbytes, 0, NULL, INVALID_DEVID),
            0);
    }

    /* ---- wc_falcon_init_label: (key==NULL)||(label==NULL), then
     *      (labelLen==0)||(labelLen>FALCON_MAX_LABEL_LEN) ---------------- */
    {
        falcon_key lblkey;
        char toolong[FALCON_MAX_LABEL_LEN + 2];
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
        /* valid label -> length OR all-false -> success */
        ExpectIntEQ(wc_falcon_init_label(&lblkey, "lbl", NULL, INVALID_DEVID),
            0);
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
    ExpectIntEQ(wc_falcon_set_level(&key, 1), 0);
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
