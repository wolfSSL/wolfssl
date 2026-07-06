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
 * check_key: valid key passes; a corrupted public copy, a public-only key, and
 * a private-only key all fail; NULL is rejected.
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
