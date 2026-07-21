/* test_hpke.c
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

#include <wolfssl/wolfcrypt/hpke.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_hpke.h>

/*
 * MC/DC: argument/length-validation decisions in wolfcrypt/src/hpke.c's
 * public (WOLFSSL_API) functions. Only the DHKEM_X25519_HKDF_SHA256 /
 * HKDF_SHA256 / HPKE_AES_128_GCM suite is exercised (matching the "e.g."
 * suite suggested for this file); the ECC (P256/P384/P521) and X448 switch
 * cases inside wc_HpkeInit()/wc_HpkeGenerateKeyPair()/
 * wc_HpkeSerializePublicKey()/wc_HpkeDeserializePublicKey()/
 * wc_HpkeFreeKey() remain covered only by the existing hpke_test() KAT in
 * wolfcrypt/test/test.c; they are not argument-validation decisions and are
 * out of scope here.
 *
 * wc_HpkeInit()'s guard (hpke.c ~line 112):
 *     hpke == NULL || kem == 0 || kdf == 0 || aead == 0
 *   c0 = hpke == NULL, c1 = kem == 0, c2 = kdf == 0, c3 = aead == 0
 * Followed by three independent unsupported-id switch-default decisions
 * (hpke.c ~lines 219-221, 248-250, 272-274), each also BAD_FUNC_ARG.
 *
 * wc_HpkeGenerateKeyPair()'s guard (hpke.c ~line 287):
 *     hpke == NULL || keypair == NULL || rng == NULL
 *   c0 = hpke == NULL, c1 = keypair == NULL, c2 = rng == NULL
 *
 * wc_HpkeSerializePublicKey()'s guard (hpke.c ~line 358):
 *     hpke == NULL || key == NULL || out == NULL || outSz == NULL
 *   c0 = hpke == NULL, c1 = key == NULL, c2 = out == NULL, c3 = outSz==NULL
 *
 * wc_HpkeDeserializePublicKey()'s guard (hpke.c ~line 400):
 *     hpke == NULL || key == NULL || in == NULL
 *   c0 = hpke == NULL, c1 = key == NULL, c2 = in == NULL
 * plus an independent bounds decision (hpke.c ~line 404):
 *     inSz < (word32)hpke->Npk  ->  BUFFER_E
 *
 * wc_HpkeInitSealContext()'s guard (hpke.c ~line 924):
 *     hpke == NULL || context == NULL || ephemeralKey == NULL ||
 *         receiverKey == NULL || (info == NULL && infoSz != 0)
 *   c0 = hpke==NULL, c1 = context==NULL, c2 = ephemeralKey==NULL,
 *   c3 = receiverKey==NULL, c4 = info==NULL, c5 = infoSz!=0
 *
 * wc_HpkeContextSealBase()'s guard (hpke.c ~line 943):
 *     hpke == NULL || context == NULL || (aad == NULL && aadSz != 0) ||
 *         plaintext == NULL || out == NULL
 *   c0 = hpke==NULL, c1 = context==NULL, c2 = aad==NULL, c3 = aadSz!=0,
 *   c4 = plaintext==NULL, c5 = out==NULL
 * plus an independent sequence-overflow decision (hpke.c ~line 949):
 *     context->seq == WC_MAX_SINT_OF(int)  ->  SEQ_OVERFLOW_E
 *
 * wc_HpkeSealBase()'s guard (hpke.c ~lines 984-987):
 *     hpke == NULL || ephemeralKey == NULL || receiverKey == NULL ||
 *         (info == NULL && infoSz != 0) || (aad == NULL && aadSz != 0) ||
 *         plaintext == NULL || ciphertext == NULL
 *   c0 = hpke==NULL, c1 = ephemeralKey==NULL, c2 = receiverKey==NULL,
 *   c3 = info==NULL, c4 = infoSz!=0, c5 = aad==NULL, c6 = aadSz!=0,
 *   c7 = plaintext==NULL, c8 = ciphertext==NULL
 *
 * wc_HpkeInitOpenContext()'s guard (hpke.c ~lines 1172-1174):
 *     hpke == NULL || context == NULL || receiverKey == NULL ||
 *         pubKey == NULL || (info == NULL && infoSz != 0)
 *   c0 = hpke==NULL, c1 = context==NULL, c2 = receiverKey==NULL,
 *   c3 = pubKey==NULL, c4 = info==NULL, c5 = infoSz!=0
 *
 * wc_HpkeContextOpenBase()'s guard (hpke.c ~lines 1188-1190):
 *     hpke == NULL || context == NULL || (aad == NULL && aadSz != 0) ||
 *         ciphertext == NULL || out == NULL
 *   c0 = hpke==NULL, c1 = context==NULL, c2 = aad==NULL, c3 = aadSz!=0,
 *   c4 = ciphertext==NULL, c5 = out==NULL
 * plus an independent sequence-overflow decision (hpke.c ~line 1194):
 *     context->seq == WC_MAX_SINT_OF(int)  ->  SEQ_OVERFLOW_E
 *
 * wc_HpkeOpenBase()'s guard (hpke.c ~lines 1230-1234):
 *     hpke == NULL || receiverKey == NULL || pubKey == NULL ||
 *         pubKeySz == 0 || (info == NULL && infoSz != 0) ||
 *         (aad == NULL && aadSz != 0) || plaintext == NULL ||
 *         ciphertext == NULL
 *   c0 = hpke==NULL, c1 = receiverKey==NULL, c2 = pubKey==NULL,
 *   c3 = pubKeySz==0, c4 = info==NULL, c5 = infoSz!=0, c6 = aad==NULL,
 *   c7 = aadSz!=0, c8 = plaintext==NULL, c9 = ciphertext==NULL
 *
 * wc_HpkeFreeKey() has no argument-validation decision of its own (it does
 * not dereference hpke; it only switches on the kem id) -- it is exercised
 * functionally below but has nothing to cover here.
 *
 * NOTE (whitebox candidates, not attempted here): wc_HpkeLabeledExtract(),
 * wc_HpkeLabeledExpand(), wc_HpkeContextComputeNonce(),
 * wc_HpkeExtractAndExpand(), wc_HpkeKeyScheduleBase(), wc_HpkeEncap() and
 * wc_HpkeSetupBaseSender(), and wc_HpkeDecap() each carry their own
 * "hpke == NULL" guard (hpke.c ~lines 494, 563, 632, 654, 698, 794/888,
 * 1032). Every public entry point above already rejects a NULL hpke before
 * calling into these statics, so those inner guards are structurally
 * unreachable from tests/api and would need a white-box (direct static-
 * function call) test to cover.
 */
int test_wc_Hpke_DecisionCoverage(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE25519) && !defined(NO_SHA256) && defined(WOLFSSL_AES_128)
    Hpke hpke[1];
    HpkeBaseContext sealCtx[1];
    HpkeBaseContext openCtx[1];
    WC_RNG rng[1];
    void* ephemeralKey = NULL;
    void* receiverKey = NULL;
    void* deserializedKey = NULL;
    byte receiverPubKey[HPKE_Npk_MAX];
    word16 receiverPubKeySz;
    byte ephemeralPubKey[HPKE_Npk_MAX];
    word16 ephemeralPubKeySz;
    byte tmpPubKey[HPKE_Npk_MAX];
    word16 tmpPubKeySz;
    const char* info_text = "info";
    const char* aad_text = "aad";
    const char* pt_text = "hpke decision coverage message";
    byte ciphertext[MAX_HPKE_LABEL_SZ];
    byte noAadCiphertext[MAX_HPKE_LABEL_SZ];
    byte plaintext[MAX_HPKE_LABEL_SZ];
    byte oneShotCiphertext[MAX_HPKE_LABEL_SZ];
    byte infoMaskedCiphertext[MAX_HPKE_LABEL_SZ];
    byte aadMaskedCiphertext[MAX_HPKE_LABEL_SZ];
    byte oneShotPlaintext[MAX_HPKE_LABEL_SZ];

    XMEMSET(hpke, 0, sizeof(*hpke));
    XMEMSET(sealCtx, 0, sizeof(*sealCtx));
    XMEMSET(openCtx, 0, sizeof(*openCtx));
    XMEMSET(receiverPubKey, 0, sizeof(receiverPubKey));
    XMEMSET(ephemeralPubKey, 0, sizeof(ephemeralPubKey));
    XMEMSET(tmpPubKey, 0, sizeof(tmpPubKey));
    XMEMSET(ciphertext, 0, sizeof(ciphertext));
    XMEMSET(noAadCiphertext, 0, sizeof(noAadCiphertext));
    XMEMSET(plaintext, 0, sizeof(plaintext));
    XMEMSET(oneShotCiphertext, 0, sizeof(oneShotCiphertext));
    XMEMSET(infoMaskedCiphertext, 0, sizeof(infoMaskedCiphertext));
    XMEMSET(aadMaskedCiphertext, 0, sizeof(aadMaskedCiphertext));
    XMEMSET(oneShotPlaintext, 0, sizeof(oneShotPlaintext));

    ExpectIntEQ(wc_InitRng(rng), 0);

    /* --- wc_HpkeInit() --- */

    /* c0 true: isolates hpke==NULL against the baseline below. */
    ExpectIntEQ(wc_HpkeInit(NULL, DHKEM_X25519_HKDF_SHA256, HKDF_SHA256,
        HPKE_AES_128_GCM, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* c1 true: kem==0. */
    ExpectIntEQ(wc_HpkeInit(hpke, 0, HKDF_SHA256, HPKE_AES_128_GCM, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* c2 true: kdf==0. */
    ExpectIntEQ(wc_HpkeInit(hpke, DHKEM_X25519_HKDF_SHA256, 0,
        HPKE_AES_128_GCM, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* c3 true: aead==0. */
    ExpectIntEQ(wc_HpkeInit(hpke, DHKEM_X25519_HKDF_SHA256, HKDF_SHA256, 0,
        NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Baseline: c0..c3 all false, all three switch selections supported. */
    ExpectIntEQ(wc_HpkeInit(hpke, DHKEM_X25519_HKDF_SHA256, HKDF_SHA256,
        HPKE_AES_128_GCM, NULL), 0);

    /* kem switch default (hpke.c ~line 219): non-zero but unsupported id. */
    ExpectIntEQ(wc_HpkeInit(hpke, 9999, HKDF_SHA256, HPKE_AES_128_GCM, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* kdf switch default (hpke.c ~line 248). */
    ExpectIntEQ(wc_HpkeInit(hpke, DHKEM_X25519_HKDF_SHA256, 9999,
        HPKE_AES_128_GCM, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* aead switch default (hpke.c ~line 272). */
    ExpectIntEQ(wc_HpkeInit(hpke, DHKEM_X25519_HKDF_SHA256, HKDF_SHA256,
        9999, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Re-establish a valid hpke state: every failing call above zeroes the
     * struct (hpke.c XMEMSET's it before running the id switches). */
    ExpectIntEQ(wc_HpkeInit(hpke, DHKEM_X25519_HKDF_SHA256, HKDF_SHA256,
        HPKE_AES_128_GCM, NULL), 0);

    /* --- wc_HpkeGenerateKeyPair() --- */

    ExpectIntEQ(wc_HpkeGenerateKeyPair(NULL, &receiverKey, rng),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HpkeGenerateKeyPair(hpke, NULL, rng),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HpkeGenerateKeyPair(hpke, &receiverKey, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Baseline: c0..c2 all false -- produces the receiver and ephemeral
     * keypairs used by every function below. */
    ExpectIntEQ(wc_HpkeGenerateKeyPair(hpke, &receiverKey, rng), 0);
    ExpectNotNull(receiverKey);
    ExpectIntEQ(wc_HpkeGenerateKeyPair(hpke, &ephemeralKey, rng), 0);
    ExpectNotNull(ephemeralKey);

    /* --- wc_HpkeSerializePublicKey() --- */

    tmpPubKeySz = (word16)sizeof(tmpPubKey);
    ExpectIntEQ(wc_HpkeSerializePublicKey(NULL, receiverKey, tmpPubKey,
        &tmpPubKeySz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HpkeSerializePublicKey(hpke, NULL, tmpPubKey,
        &tmpPubKeySz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HpkeSerializePublicKey(hpke, receiverKey, NULL,
        &tmpPubKeySz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HpkeSerializePublicKey(hpke, receiverKey, tmpPubKey,
        NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Baseline: c0..c3 all false -- serializes the receiver and ephemeral
     * public keys reused by the tests below. */
    receiverPubKeySz = (word16)sizeof(receiverPubKey);
    ExpectIntEQ(wc_HpkeSerializePublicKey(hpke, receiverKey, receiverPubKey,
        &receiverPubKeySz), 0);
    ephemeralPubKeySz = (word16)sizeof(ephemeralPubKey);
    ExpectIntEQ(wc_HpkeSerializePublicKey(hpke, ephemeralKey, ephemeralPubKey,
        &ephemeralPubKeySz), 0);

    /* --- wc_HpkeDeserializePublicKey() --- */

    ExpectIntEQ(wc_HpkeDeserializePublicKey(NULL, &deserializedKey,
        receiverPubKey, receiverPubKeySz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HpkeDeserializePublicKey(hpke, NULL, receiverPubKey,
        receiverPubKeySz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HpkeDeserializePublicKey(hpke, &deserializedKey, NULL,
        receiverPubKeySz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Bounds decision true (inSz(0) < Npk): pairs against the baseline
     * below (inSz == Npk) to isolate the bounds check. */
    ExpectIntEQ(wc_HpkeDeserializePublicKey(hpke, &deserializedKey,
        receiverPubKey, 0), WC_NO_ERR_TRACE(BUFFER_E));
    /* Baseline: c0..c2 false, inSz >= Npk. */
    ExpectIntEQ(wc_HpkeDeserializePublicKey(hpke, &deserializedKey,
        receiverPubKey, receiverPubKeySz), 0);
    ExpectNotNull(deserializedKey);
    if (deserializedKey != NULL) {
        wc_HpkeFreeKey(hpke, hpke->kem, deserializedKey, hpke->heap);
        deserializedKey = NULL;
    }

    /* --- wc_HpkeInitSealContext() --- */

    ExpectIntEQ(wc_HpkeInitSealContext(NULL, sealCtx, ephemeralKey,
        receiverKey, (byte*)info_text, (word32)XSTRLEN(info_text)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HpkeInitSealContext(hpke, NULL, ephemeralKey, receiverKey,
        (byte*)info_text, (word32)XSTRLEN(info_text)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HpkeInitSealContext(hpke, sealCtx, NULL, receiverKey,
        (byte*)info_text, (word32)XSTRLEN(info_text)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HpkeInitSealContext(hpke, sealCtx, ephemeralKey, NULL,
        (byte*)info_text, (word32)XSTRLEN(info_text)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* c4 true, c5 false (info==NULL, infoSz==0): term false, masked -- a
     * valid no-info call. */
    ExpectIntEQ(wc_HpkeInitSealContext(hpke, sealCtx, ephemeralKey,
        receiverKey, NULL, 0), 0);
    /* c4 true, c5 true (info==NULL, infoSz!=0): term true -> BAD_FUNC_ARG.
     * Isolates c5 against the previous call (info held NULL); isolates c4
     * against the baseline below (infoSz held nonzero). */
    ExpectIntEQ(wc_HpkeInitSealContext(hpke, sealCtx, ephemeralKey,
        receiverKey, NULL, (word32)XSTRLEN(info_text)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Baseline: c0..c5 all false -- leaves sealCtx correctly derived
     * (seq==0) for the wc_HpkeContextSealBase() tests below. */
    ExpectIntEQ(wc_HpkeInitSealContext(hpke, sealCtx, ephemeralKey,
        receiverKey, (byte*)info_text, (word32)XSTRLEN(info_text)), 0);

    /* --- wc_HpkeContextSealBase() --- */

    ExpectIntEQ(wc_HpkeContextSealBase(NULL, sealCtx, (byte*)aad_text,
        (word32)XSTRLEN(aad_text), (byte*)pt_text, (word32)XSTRLEN(pt_text),
        ciphertext), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HpkeContextSealBase(hpke, NULL, (byte*)aad_text,
        (word32)XSTRLEN(aad_text), (byte*)pt_text, (word32)XSTRLEN(pt_text),
        ciphertext), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* c2 true, c3 true (aad==NULL, aadSz!=0): term true -> BAD_FUNC_ARG. */
    ExpectIntEQ(wc_HpkeContextSealBase(hpke, sealCtx, NULL,
        (word32)XSTRLEN(aad_text), (byte*)pt_text, (word32)XSTRLEN(pt_text),
        ciphertext), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HpkeContextSealBase(hpke, sealCtx, (byte*)aad_text,
        (word32)XSTRLEN(aad_text), NULL, (word32)XSTRLEN(pt_text),
        ciphertext), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HpkeContextSealBase(hpke, sealCtx, (byte*)aad_text,
        (word32)XSTRLEN(aad_text), (byte*)pt_text, (word32)XSTRLEN(pt_text),
        NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Baseline: c0..c5 all false (aad!=NULL, aadSz!=0 -> term false) -- a
     * real seal at seq==0, consumed by the matching
     * wc_HpkeContextOpenBase() baseline below. Isolates c2 against the
     * aad==NULL,aadSz!=0 case above (aadSz held nonzero). */
    ExpectIntEQ(wc_HpkeContextSealBase(hpke, sealCtx, (byte*)aad_text,
        (word32)XSTRLEN(aad_text), (byte*)pt_text, (word32)XSTRLEN(pt_text),
        ciphertext), 0);
    /* c2 true, c3 false (aad==NULL, aadSz==0): term false, masked -- a real
     * seal at seq==1. Isolates c3 against the aad==NULL,aadSz!=0 case
     * above (aad held NULL). Consumed by the matching masked-aad
     * wc_HpkeContextOpenBase() call below. */
    ExpectIntEQ(wc_HpkeContextSealBase(hpke, sealCtx, NULL, 0,
        (byte*)pt_text, (word32)XSTRLEN(pt_text), noAadCiphertext), 0);
    /* Sequence-overflow, isolated from the argument-validation guard above
     * (all other args remain valid). */
    sealCtx->seq = WC_MAX_SINT_OF(int);
    ExpectIntEQ(wc_HpkeContextSealBase(hpke, sealCtx, (byte*)aad_text,
        (word32)XSTRLEN(aad_text), (byte*)pt_text, (word32)XSTRLEN(pt_text),
        ciphertext), WC_NO_ERR_TRACE(SEQ_OVERFLOW_E));

    /* --- wc_HpkeInitOpenContext() --- */

    ExpectIntEQ(wc_HpkeInitOpenContext(NULL, openCtx, receiverKey,
        ephemeralPubKey, ephemeralPubKeySz, (byte*)info_text,
        (word32)XSTRLEN(info_text)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HpkeInitOpenContext(hpke, NULL, receiverKey,
        ephemeralPubKey, ephemeralPubKeySz, (byte*)info_text,
        (word32)XSTRLEN(info_text)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HpkeInitOpenContext(hpke, openCtx, NULL, ephemeralPubKey,
        ephemeralPubKeySz, (byte*)info_text, (word32)XSTRLEN(info_text)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HpkeInitOpenContext(hpke, openCtx, receiverKey, NULL,
        ephemeralPubKeySz, (byte*)info_text, (word32)XSTRLEN(info_text)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* c4 true, c5 false: term false, masked -- a valid no-info call. */
    ExpectIntEQ(wc_HpkeInitOpenContext(hpke, openCtx, receiverKey,
        ephemeralPubKey, ephemeralPubKeySz, NULL, 0), 0);
    /* c4 true, c5 true: term true -> BAD_FUNC_ARG. Isolates c5 (info held
     * NULL); isolates c4 against the baseline below (infoSz held
     * nonzero). */
    ExpectIntEQ(wc_HpkeInitOpenContext(hpke, openCtx, receiverKey,
        ephemeralPubKey, ephemeralPubKeySz, NULL,
        (word32)XSTRLEN(info_text)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Baseline: c0..c5 all false -- leaves openCtx correctly derived
     * (seq==0), matching sealCtx's derivation, for the
     * wc_HpkeContextOpenBase() tests below. */
    ExpectIntEQ(wc_HpkeInitOpenContext(hpke, openCtx, receiverKey,
        ephemeralPubKey, ephemeralPubKeySz, (byte*)info_text,
        (word32)XSTRLEN(info_text)), 0);

    /* --- wc_HpkeContextOpenBase() --- */

    ExpectIntEQ(wc_HpkeContextOpenBase(NULL, openCtx, (byte*)aad_text,
        (word32)XSTRLEN(aad_text), ciphertext, (word32)XSTRLEN(pt_text),
        plaintext), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HpkeContextOpenBase(hpke, NULL, (byte*)aad_text,
        (word32)XSTRLEN(aad_text), ciphertext, (word32)XSTRLEN(pt_text),
        plaintext), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* c2 true, c3 true (aad==NULL, aadSz!=0): term true -> BAD_FUNC_ARG. */
    ExpectIntEQ(wc_HpkeContextOpenBase(hpke, openCtx, NULL,
        (word32)XSTRLEN(aad_text), ciphertext, (word32)XSTRLEN(pt_text),
        plaintext), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HpkeContextOpenBase(hpke, openCtx, (byte*)aad_text,
        (word32)XSTRLEN(aad_text), NULL, (word32)XSTRLEN(pt_text),
        plaintext), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HpkeContextOpenBase(hpke, openCtx, (byte*)aad_text,
        (word32)XSTRLEN(aad_text), ciphertext, (word32)XSTRLEN(pt_text),
        NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Baseline: c0..c5 all false -- decrypts the matching seq==0
     * ciphertext from wc_HpkeContextSealBase() above. Isolates c2 against
     * the aad==NULL,aadSz!=0 case above (aadSz held nonzero). */
    ExpectIntEQ(wc_HpkeContextOpenBase(hpke, openCtx, (byte*)aad_text,
        (word32)XSTRLEN(aad_text), ciphertext, (word32)XSTRLEN(pt_text),
        plaintext), 0);
    ExpectBufEQ(plaintext, pt_text, XSTRLEN(pt_text));
    /* c2 true, c3 false: term false, masked -- decrypts the matching
     * seq==1 no-AAD ciphertext. Isolates c3 against the
     * aad==NULL,aadSz!=0 case above (aad held NULL). */
    ExpectIntEQ(wc_HpkeContextOpenBase(hpke, openCtx, NULL, 0,
        noAadCiphertext, (word32)XSTRLEN(pt_text), plaintext), 0);
    ExpectBufEQ(plaintext, pt_text, XSTRLEN(pt_text));
    /* Sequence-overflow, isolated from the argument-validation guard. */
    openCtx->seq = WC_MAX_SINT_OF(int);
    ExpectIntEQ(wc_HpkeContextOpenBase(hpke, openCtx, (byte*)aad_text,
        (word32)XSTRLEN(aad_text), ciphertext, (word32)XSTRLEN(pt_text),
        plaintext), WC_NO_ERR_TRACE(SEQ_OVERFLOW_E));

    /* --- wc_HpkeSealBase() (one-shot) --- */

    ExpectIntEQ(wc_HpkeSealBase(NULL, ephemeralKey, receiverKey,
        (byte*)info_text, (word32)XSTRLEN(info_text), (byte*)aad_text,
        (word32)XSTRLEN(aad_text), (byte*)pt_text, (word32)XSTRLEN(pt_text),
        oneShotCiphertext), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HpkeSealBase(hpke, NULL, receiverKey, (byte*)info_text,
        (word32)XSTRLEN(info_text), (byte*)aad_text,
        (word32)XSTRLEN(aad_text), (byte*)pt_text, (word32)XSTRLEN(pt_text),
        oneShotCiphertext), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HpkeSealBase(hpke, ephemeralKey, NULL, (byte*)info_text,
        (word32)XSTRLEN(info_text), (byte*)aad_text,
        (word32)XSTRLEN(aad_text), (byte*)pt_text, (word32)XSTRLEN(pt_text),
        oneShotCiphertext), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* c3 true, c4 true (info==NULL, infoSz!=0): term true -> BAD_FUNC_ARG.*/
    ExpectIntEQ(wc_HpkeSealBase(hpke, ephemeralKey, receiverKey, NULL,
        (word32)XSTRLEN(info_text), (byte*)aad_text,
        (word32)XSTRLEN(aad_text), (byte*)pt_text, (word32)XSTRLEN(pt_text),
        oneShotCiphertext), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* c5 true, c6 true (aad==NULL, aadSz!=0): term true -> BAD_FUNC_ARG. */
    ExpectIntEQ(wc_HpkeSealBase(hpke, ephemeralKey, receiverKey,
        (byte*)info_text, (word32)XSTRLEN(info_text), NULL,
        (word32)XSTRLEN(aad_text), (byte*)pt_text, (word32)XSTRLEN(pt_text),
        oneShotCiphertext), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HpkeSealBase(hpke, ephemeralKey, receiverKey,
        (byte*)info_text, (word32)XSTRLEN(info_text), (byte*)aad_text,
        (word32)XSTRLEN(aad_text), NULL, (word32)XSTRLEN(pt_text),
        oneShotCiphertext), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HpkeSealBase(hpke, ephemeralKey, receiverKey,
        (byte*)info_text, (word32)XSTRLEN(info_text), (byte*)aad_text,
        (word32)XSTRLEN(aad_text), (byte*)pt_text, (word32)XSTRLEN(pt_text),
        NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Baseline: c0..c8 all false -- also the ciphertext consumed by the
     * matching wc_HpkeOpenBase() baseline below. Isolates c3 and c5
     * (paired against the info==NULL,infoSz!=0 and aad==NULL,aadSz!=0
     * cases above, respectively). */
    ExpectIntEQ(wc_HpkeSealBase(hpke, ephemeralKey, receiverKey,
        (byte*)info_text, (word32)XSTRLEN(info_text), (byte*)aad_text,
        (word32)XSTRLEN(aad_text), (byte*)pt_text, (word32)XSTRLEN(pt_text),
        oneShotCiphertext), 0);
    /* c3 true, c4 false (info==NULL, infoSz==0): term false, masked --
     * holding aad valid isolates info from aad. Consumed by the matching
     * masked-info wc_HpkeOpenBase() call below. Isolates c4 against the
     * info==NULL,infoSz!=0 case above (info held NULL). */
    ExpectIntEQ(wc_HpkeSealBase(hpke, ephemeralKey, receiverKey, NULL, 0,
        (byte*)aad_text, (word32)XSTRLEN(aad_text), (byte*)pt_text,
        (word32)XSTRLEN(pt_text), infoMaskedCiphertext), 0);
    /* c5 true, c6 false (aad==NULL, aadSz==0): term false, masked --
     * holding info valid isolates aad from info. Consumed by the matching
     * masked-aad wc_HpkeOpenBase() call below. Isolates c6 against the
     * aad==NULL,aadSz!=0 case above (aad held NULL). */
    ExpectIntEQ(wc_HpkeSealBase(hpke, ephemeralKey, receiverKey,
        (byte*)info_text, (word32)XSTRLEN(info_text), NULL, 0,
        (byte*)pt_text, (word32)XSTRLEN(pt_text), aadMaskedCiphertext), 0);

    /* --- wc_HpkeOpenBase() (one-shot) --- */

    ExpectIntEQ(wc_HpkeOpenBase(NULL, receiverKey, ephemeralPubKey,
        ephemeralPubKeySz, (byte*)info_text, (word32)XSTRLEN(info_text),
        (byte*)aad_text, (word32)XSTRLEN(aad_text), oneShotCiphertext,
        (word32)XSTRLEN(pt_text), oneShotPlaintext),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HpkeOpenBase(hpke, NULL, ephemeralPubKey,
        ephemeralPubKeySz, (byte*)info_text, (word32)XSTRLEN(info_text),
        (byte*)aad_text, (word32)XSTRLEN(aad_text), oneShotCiphertext,
        (word32)XSTRLEN(pt_text), oneShotPlaintext),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HpkeOpenBase(hpke, receiverKey, NULL, ephemeralPubKeySz,
        (byte*)info_text, (word32)XSTRLEN(info_text), (byte*)aad_text,
        (word32)XSTRLEN(aad_text), oneShotCiphertext,
        (word32)XSTRLEN(pt_text), oneShotPlaintext),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* c3 true: pubKeySz==0. */
    ExpectIntEQ(wc_HpkeOpenBase(hpke, receiverKey, ephemeralPubKey, 0,
        (byte*)info_text, (word32)XSTRLEN(info_text), (byte*)aad_text,
        (word32)XSTRLEN(aad_text), oneShotCiphertext,
        (word32)XSTRLEN(pt_text), oneShotPlaintext),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* c4 true, c5 true (info==NULL, infoSz!=0): term true -> BAD_FUNC_ARG.*/
    ExpectIntEQ(wc_HpkeOpenBase(hpke, receiverKey, ephemeralPubKey,
        ephemeralPubKeySz, NULL, (word32)XSTRLEN(info_text),
        (byte*)aad_text, (word32)XSTRLEN(aad_text), oneShotCiphertext,
        (word32)XSTRLEN(pt_text), oneShotPlaintext),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* c6 true, c7 true (aad==NULL, aadSz!=0): term true -> BAD_FUNC_ARG. */
    ExpectIntEQ(wc_HpkeOpenBase(hpke, receiverKey, ephemeralPubKey,
        ephemeralPubKeySz, (byte*)info_text, (word32)XSTRLEN(info_text),
        NULL, (word32)XSTRLEN(aad_text), oneShotCiphertext,
        (word32)XSTRLEN(pt_text), oneShotPlaintext),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HpkeOpenBase(hpke, receiverKey, ephemeralPubKey,
        ephemeralPubKeySz, (byte*)info_text, (word32)XSTRLEN(info_text),
        (byte*)aad_text, (word32)XSTRLEN(aad_text), NULL,
        (word32)XSTRLEN(pt_text), oneShotPlaintext),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HpkeOpenBase(hpke, receiverKey, ephemeralPubKey,
        ephemeralPubKeySz, (byte*)info_text, (word32)XSTRLEN(info_text),
        (byte*)aad_text, (word32)XSTRLEN(aad_text), oneShotCiphertext,
        (word32)XSTRLEN(pt_text), NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Baseline: c0..c9 all false -- decrypts the matching
     * wc_HpkeSealBase() baseline ciphertext above. Isolates c4 and c6. */
    ExpectIntEQ(wc_HpkeOpenBase(hpke, receiverKey, ephemeralPubKey,
        ephemeralPubKeySz, (byte*)info_text, (word32)XSTRLEN(info_text),
        (byte*)aad_text, (word32)XSTRLEN(aad_text), oneShotCiphertext,
        (word32)XSTRLEN(pt_text), oneShotPlaintext), 0);
    ExpectBufEQ(oneShotPlaintext, pt_text, XSTRLEN(pt_text));
    /* c4 true, c5 false: term false, masked -- decrypts the matching
     * masked-info ciphertext. Isolates c5 against the
     * info==NULL,infoSz!=0 case above (info held NULL). */
    ExpectIntEQ(wc_HpkeOpenBase(hpke, receiverKey, ephemeralPubKey,
        ephemeralPubKeySz, NULL, 0, (byte*)aad_text,
        (word32)XSTRLEN(aad_text), infoMaskedCiphertext,
        (word32)XSTRLEN(pt_text), oneShotPlaintext), 0);
    ExpectBufEQ(oneShotPlaintext, pt_text, XSTRLEN(pt_text));
    /* c6 true, c7 false: term false, masked -- decrypts the matching
     * masked-aad ciphertext. Isolates c7 against the aad==NULL,aadSz!=0
     * case above (aad held NULL). */
    ExpectIntEQ(wc_HpkeOpenBase(hpke, receiverKey, ephemeralPubKey,
        ephemeralPubKeySz, (byte*)info_text, (word32)XSTRLEN(info_text),
        NULL, 0, aadMaskedCiphertext, (word32)XSTRLEN(pt_text),
        oneShotPlaintext), 0);
    ExpectBufEQ(oneShotPlaintext, pt_text, XSTRLEN(pt_text));

    if (ephemeralKey != NULL)
        wc_HpkeFreeKey(hpke, hpke->kem, ephemeralKey, hpke->heap);
    if (receiverKey != NULL)
        wc_HpkeFreeKey(hpke, hpke->kem, receiverKey, hpke->heap);
    wc_FreeRng(rng);
#endif
    return EXPECT_RESULT();
}

/*
 * Positive coverage: wc_HpkeInit() (DHKEM_X25519_HKDF_SHA256 /
 * HKDF_SHA256 / HPKE_AES_128_GCM) -> wc_HpkeGenerateKeyPair() for the
 * receiver and an ephemeral (sender) keypair -> round-trip the receiver's
 * public key through wc_HpkeSerializePublicKey()/
 * wc_HpkeDeserializePublicKey() -> wc_HpkeSealBase() against the
 * deserialized (public-only) receiver key -> wc_HpkeOpenBase() with the
 * original receiver key -> verify the recovered plaintext matches the
 * original message -> wc_HpkeFreeKey(). Also exercises the context
 * (streaming) API, wc_HpkeInitSealContext()/wc_HpkeContextSealBase() and
 * wc_HpkeInitOpenContext()/wc_HpkeContextOpenBase(), across two sequential
 * messages. Modeled on hpke_test_single()/hpke_test_multi() in
 * wolfcrypt/test/test.c.
 */
int test_wc_Hpke_FeatureCoverage(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE25519) && !defined(NO_SHA256) && defined(WOLFSSL_AES_128)
    Hpke hpke[1];
    HpkeBaseContext context[1];
    WC_RNG rng[1];
    void* receiverKey = NULL;
    void* ephemeralKey = NULL;
    void* deserializedKey = NULL;
    byte receiverPubKey[HPKE_Npk_MAX];
    word16 receiverPubKeySz;
    byte ephemeralPubKey[HPKE_Npk_MAX];
    word16 ephemeralPubKeySz;
    const char* info_text = "hpke feature coverage info";
    const char* aad_text = "hpke feature coverage aad";
    const char* pt_text = "the quick brown fox jumps over the lazy dog";
    byte ciphertext[MAX_HPKE_LABEL_SZ];
    byte plaintext[MAX_HPKE_LABEL_SZ];
    byte ciphertexts[2][MAX_HPKE_LABEL_SZ];

    XMEMSET(hpke, 0, sizeof(*hpke));
    XMEMSET(context, 0, sizeof(*context));
    XMEMSET(receiverPubKey, 0, sizeof(receiverPubKey));
    XMEMSET(ephemeralPubKey, 0, sizeof(ephemeralPubKey));
    XMEMSET(ciphertext, 0, sizeof(ciphertext));
    XMEMSET(plaintext, 0, sizeof(plaintext));
    XMEMSET(ciphertexts, 0, sizeof(ciphertexts));

    ExpectIntEQ(wc_InitRng(rng), 0);

    /* wc_HpkeInit(): RFC 9180 base suite with the X25519 KEM, matching
     * hpke_test_single()'s curve25519/aes-256 leg in shape (aes-128 here,
     * per this file's suggested example suite). */
    ExpectIntEQ(wc_HpkeInit(hpke, DHKEM_X25519_HKDF_SHA256, HKDF_SHA256,
        HPKE_AES_128_GCM, NULL), 0);

    /* wc_HpkeGenerateKeyPair(): receiver and ephemeral (sender) keypairs.*/
    ExpectIntEQ(wc_HpkeGenerateKeyPair(hpke, &receiverKey, rng), 0);
    ExpectNotNull(receiverKey);
    ExpectIntEQ(wc_HpkeGenerateKeyPair(hpke, &ephemeralKey, rng), 0);
    ExpectNotNull(ephemeralKey);

    /* wc_HpkeSerializePublicKey()/wc_HpkeDeserializePublicKey(): round
     * trip the receiver's public key through the wire format and recover
     * a usable (public-only) key object. */
    receiverPubKeySz = (word16)sizeof(receiverPubKey);
    ExpectIntEQ(wc_HpkeSerializePublicKey(hpke, receiverKey, receiverPubKey,
        &receiverPubKeySz), 0);
    ExpectIntEQ(wc_HpkeDeserializePublicKey(hpke, &deserializedKey,
        receiverPubKey, receiverPubKeySz), 0);
    ExpectNotNull(deserializedKey);

    ephemeralPubKeySz = (word16)sizeof(ephemeralPubKey);
    ExpectIntEQ(wc_HpkeSerializePublicKey(hpke, ephemeralKey,
        ephemeralPubKey, &ephemeralPubKeySz), 0);

    /* wc_HpkeSealBase(): seal against the deserialized (public-only)
     * receiver key, proving it is fully interchangeable with the original
     * for encapsulation. */
    ExpectIntEQ(wc_HpkeSealBase(hpke, ephemeralKey, deserializedKey,
        (byte*)info_text, (word32)XSTRLEN(info_text), (byte*)aad_text,
        (word32)XSTRLEN(aad_text), (byte*)pt_text, (word32)XSTRLEN(pt_text),
        ciphertext), 0);

    /* wc_HpkeOpenBase(): open with the original (private) receiver key and
     * the serialized ephemeral public key, then confirm the recovered
     * plaintext matches the original message. */
    ExpectIntEQ(wc_HpkeOpenBase(hpke, receiverKey, ephemeralPubKey,
        ephemeralPubKeySz, (byte*)info_text, (word32)XSTRLEN(info_text),
        (byte*)aad_text, (word32)XSTRLEN(aad_text), ciphertext,
        (word32)XSTRLEN(pt_text), plaintext), 0);
    ExpectBufEQ(plaintext, pt_text, XSTRLEN(pt_text));

    /* Context (streaming) API: two sequential messages sealed and opened
     * in order, each advancing the sequence-derived nonce. */
    ExpectIntEQ(wc_HpkeInitSealContext(hpke, context, ephemeralKey,
        receiverKey, (byte*)info_text, (word32)XSTRLEN(info_text)), 0);
    ExpectIntEQ(wc_HpkeContextSealBase(hpke, context, (byte*)aad_text,
        (word32)XSTRLEN(aad_text), (byte*)pt_text, (word32)XSTRLEN(pt_text),
        ciphertexts[0]), 0);
    ExpectIntEQ(wc_HpkeContextSealBase(hpke, context, (byte*)aad_text,
        (word32)XSTRLEN(aad_text), (byte*)pt_text, (word32)XSTRLEN(pt_text),
        ciphertexts[1]), 0);

    ExpectIntEQ(wc_HpkeInitOpenContext(hpke, context, receiverKey,
        ephemeralPubKey, ephemeralPubKeySz, (byte*)info_text,
        (word32)XSTRLEN(info_text)), 0);
    ExpectIntEQ(wc_HpkeContextOpenBase(hpke, context, (byte*)aad_text,
        (word32)XSTRLEN(aad_text), ciphertexts[0], (word32)XSTRLEN(pt_text),
        plaintext), 0);
    ExpectBufEQ(plaintext, pt_text, XSTRLEN(pt_text));
    ExpectIntEQ(wc_HpkeContextOpenBase(hpke, context, (byte*)aad_text,
        (word32)XSTRLEN(aad_text), ciphertexts[1], (word32)XSTRLEN(pt_text),
        plaintext), 0);
    ExpectBufEQ(plaintext, pt_text, XSTRLEN(pt_text));

    if (deserializedKey != NULL)
        wc_HpkeFreeKey(hpke, hpke->kem, deserializedKey, hpke->heap);
    if (ephemeralKey != NULL)
        wc_HpkeFreeKey(hpke, hpke->kem, ephemeralKey, hpke->heap);
    if (receiverKey != NULL)
        wc_HpkeFreeKey(hpke, hpke->kem, receiverKey, hpke->heap);
    wc_FreeRng(rng);
#endif
    return EXPECT_RESULT();
}
