/* test_eccsi.c
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

#include <wolfssl/wolfcrypt/eccsi.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_eccsi.h>

/*
 * MC/DC: argument/bounds/state-validation decisions in
 * wolfcrypt/src/eccsi.c's public (WOLFSSL_API) functions.  All curve
 * work uses NIST P-256 (key size 32 bytes), matching wolfcrypt/test's
 * eccsi_test().
 *
 * Two persistent EccsiKey objects are used through most of this test to
 * reach the "ECC_PRIVATEKEY" and "ECC_PUBLICKEY" halves of the repeated
 *     (key->ecc.type != ECC_PRIVATEKEY) && (key->ecc.type != ECC_PUBLICKEY)
 * state-validation pattern:
 *   keyPriv - wc_InitEccsiKey() + wc_MakeEccsiKey() -> type ECC_PRIVATEKEY
 *   keyPub  - wc_InitEccsiKey() + wc_ImportEccsiPublicKey() -> ECC_PUBLICKEY
 * A third, keyState0, is only wc_InitEccsiKey()'d (type left at 0 by the
 * XMEMSET in Init) so it is neither, isolating the state check's true
 * (BAD_STATE_E) leg.
 *
 * Two decisions are structurally unreachable through the public API and
 * are not exercised here (see the closing notes in the assistant's
 * report rather than forced/whiteboxed):
 *   - wc_HashEccsiId()'s "curveSz < 0" leg (eccsi.c ~line 1645): dp->id
 *     is always a curve that wc_ecc_get_curve_size_from_id() accepts
 *     once wc_ecc_set_curve() has succeeded.
 *   - wc_ValidateEccsiPair()'s and wc_VerifyEccsiHash()'s trailing
 *     "if (valid/verified != NULL)" (eccsi.c ~lines 1547, 2303): both
 *     functions already return early via a prior "== NULL" check on the
 *     same out-param, so by the time these lines run the pointer is
 *     always non-NULL.
 */
int test_wc_Eccsi_DecisionCoverage(void)
{
    EXPECT_DECLS;
#ifdef WOLFCRYPT_HAVE_ECCSI
    EccsiKey keyPriv;
    EccsiKey keyPub;
    EccsiKey keyState0;
    EccsiKey keyScratch;
    WC_RNG rng;
    mp_int ssk;
    mp_int decSsk;
    ecc_point* pvt = NULL;
    ecc_point* badPvt = NULL;
    ecc_point* decPvt = NULL;
    char mail[] = "test@wolfssl.com";
    byte* id = (byte*)mail;
    word32 idSz;
    byte data[256];
    word32 sz;
    byte keyBuf[32 * 3];
    word32 keyBufSz;
    byte privBuf[32];
    word32 privBufSz;
    byte pubKeyData[32 * 2];
    word32 pubKeySz;
    byte dataRaw[32 * 2];
    word32 szRaw;
    byte dataDesc[32 * 2 + 1];
    word32 szDesc;
    byte sigLike[32 * 4 + 1];
    byte hashBuf[WC_MAX_DIGEST_SIZE];
    byte hBSz;
    byte msg[1] = { 0x00 };
    word32 msgSz = (word32)sizeof(msg);
    byte sigBuf[32 * 4 + 1];
    word32 realSigSz;
    int valid = 0;
    int verified = 0;

    XMEMSET(&keyPriv, 0, sizeof(keyPriv));
    XMEMSET(&keyPub, 0, sizeof(keyPub));
    XMEMSET(&keyState0, 0, sizeof(keyState0));
    XMEMSET(&keyScratch, 0, sizeof(keyScratch));
    XMEMSET(data, 0, sizeof(data));
    XMEMSET(keyBuf, 0, sizeof(keyBuf));
    XMEMSET(privBuf, 0, sizeof(privBuf));
    XMEMSET(pubKeyData, 0, sizeof(pubKeyData));
    XMEMSET(dataRaw, 0, sizeof(dataRaw));
    XMEMSET(dataDesc, 0, sizeof(dataDesc));
    XMEMSET(sigLike, 0, sizeof(sigLike));
    XMEMSET(hashBuf, 0, sizeof(hashBuf));
    XMEMSET(sigBuf, 0, sizeof(sigBuf));

    idSz = (word32)XSTRLEN(mail);

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectNotNull(pvt = wc_ecc_new_point());
    ExpectNotNull(badPvt = wc_ecc_new_point());
    ExpectNotNull(decPvt = wc_ecc_new_point());
    ExpectIntEQ(mp_init(&ssk), MP_OKAY);
    ExpectIntEQ(mp_init(&decSsk), MP_OKAY);

    /* --- wc_InitEccsiKey_ex() / wc_InitEccsiKey() / wc_FreeEccsiKey() ---
     * eccsi.c ~line 65:  if (key == NULL) err = BAD_FUNC_ARG;
     * eccsi.c ~line 137: if (key != NULL) { ...free... }
     */
    ExpectIntEQ(wc_InitEccsiKey_ex(NULL, 32, ECC_SECP256R1, HEAP_HINT,
        INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitEccsiKey(NULL, HEAP_HINT, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitEccsiKey_ex(&keyScratch, 32, ECC_SECP256R1, HEAP_HINT,
        INVALID_DEVID), 0);
    wc_FreeEccsiKey(NULL);          /* key == NULL: false branch, no-op   */
    wc_FreeEccsiKey(&keyScratch);   /* key != NULL: true branch, frees it */

    ExpectIntEQ(wc_InitEccsiKey(&keyPriv, HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_InitEccsiKey(&keyState0, HEAP_HINT, INVALID_DEVID), 0);
    /* keyPub must be initialized (sets the ECC curve, so key->ecc.dp is
     * non-NULL) before wc_ImportEccsiPublicKey() reads key->ecc.dp->size. */
    ExpectIntEQ(wc_InitEccsiKey(&keyPub, HEAP_HINT, INVALID_DEVID), 0);

    /* --- wc_MakeEccsiKey() (KMS): (key==NULL) || (rng==NULL) --- */
    ExpectIntEQ(wc_MakeEccsiKey(NULL, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_MakeEccsiKey(&keyPriv, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Baseline: all valid -- keyPriv becomes type ECC_PRIVATEKEY. */
    ExpectIntEQ(wc_MakeEccsiKey(&keyPriv, &rng), 0);

    /* --- wc_ExportEccsiKey() / wc_ImportEccsiKey() (KMS) ---
     * eccsi.c ~line 627: (key==NULL) || (sz==NULL)
     * eccsi.c ~line 631: (err==0) && (key->ecc.type != ECC_PRIVATEKEY)
     * eccsi.c ~line 636: data==NULL -> LENGTH_ONLY_E; else *sz < needed
     *                    -> BUFFER_E; else success.
     * eccsi.c ~line 706 (Import): (key==NULL) || (data==NULL)
     * eccsi.c ~line 709 (Import): sz != key->ecc.dp->size * 3
     */
    ExpectIntEQ(wc_ExportEccsiKey(NULL, data, &sz), WC_NO_ERR_TRACE(
        BAD_FUNC_ARG));
    ExpectIntEQ(wc_ExportEccsiKey(&keyPriv, data, NULL), WC_NO_ERR_TRACE(
        BAD_FUNC_ARG));
    /* State check: keyState0 has not been wc_MakeEccsiKey()'d. */
    sz = sizeof(data);
    ExpectIntEQ(wc_ExportEccsiKey(&keyState0, data, &sz),
        WC_NO_ERR_TRACE(BAD_STATE_E));
    /* data == NULL -> LENGTH_ONLY_E, size query. */
    ExpectIntEQ(wc_ExportEccsiKey(&keyPriv, NULL, &sz),
        WC_NO_ERR_TRACE(LENGTH_ONLY_E));
    ExpectIntEQ(sz, (word32)(32 * 3));
    /* *sz too small -> BUFFER_E. */
    sz = 32 * 3 - 1;
    ExpectIntEQ(wc_ExportEccsiKey(&keyPriv, keyBuf, &sz),
        WC_NO_ERR_TRACE(BUFFER_E));
    /* Success. */
    keyBufSz = sizeof(keyBuf);
    ExpectIntEQ(wc_ExportEccsiKey(&keyPriv, keyBuf, &keyBufSz), 0);
    ExpectIntEQ(keyBufSz, (word32)(32 * 3));

    ExpectIntEQ(wc_ImportEccsiKey(NULL, keyBuf, keyBufSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ImportEccsiKey(&keyPriv, NULL, keyBufSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ImportEccsiKey(&keyPriv, keyBuf, keyBufSz - 1),
        WC_NO_ERR_TRACE(BUFFER_E));
    ExpectIntEQ(wc_ImportEccsiKey(&keyPriv, keyBuf, keyBufSz), 0);

    /* --- wc_ExportEccsiPrivateKey() / wc_ImportEccsiPrivateKey() (KMS) ---
     * Same shape as wc_Export/ImportEccsiKey() above, size == key size.
     */
    ExpectIntEQ(wc_ExportEccsiPrivateKey(NULL, data, &sz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ExportEccsiPrivateKey(&keyPriv, data, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    sz = sizeof(data);
    ExpectIntEQ(wc_ExportEccsiPrivateKey(&keyState0, data, &sz),
        WC_NO_ERR_TRACE(BAD_STATE_E));
    ExpectIntEQ(wc_ExportEccsiPrivateKey(&keyPriv, NULL, &sz),
        WC_NO_ERR_TRACE(LENGTH_ONLY_E));
    ExpectIntEQ(sz, (word32)32);
    sz = 31;
    ExpectIntEQ(wc_ExportEccsiPrivateKey(&keyPriv, privBuf, &sz),
        WC_NO_ERR_TRACE(BUFFER_E));
    privBufSz = sizeof(privBuf);
    ExpectIntEQ(wc_ExportEccsiPrivateKey(&keyPriv, privBuf, &privBufSz), 0);
    ExpectIntEQ(privBufSz, (word32)32);

    ExpectIntEQ(wc_ImportEccsiPrivateKey(NULL, privBuf, privBufSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ImportEccsiPrivateKey(&keyPriv, NULL, privBufSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ImportEccsiPrivateKey(&keyPriv, privBuf, privBufSz - 1),
        WC_NO_ERR_TRACE(BUFFER_E));
    ExpectIntEQ(wc_ImportEccsiPrivateKey(&keyPriv, privBuf, privBufSz), 0);

    /* --- wc_ExportEccsiPublicKey() (KMS) ---
     * eccsi.c ~line 835: (key==NULL) || (sz==NULL)
     * eccsi.c ~line 838: (err==0) && (type!=PRIVATEKEY) && (type!=PUBLICKEY)
     * eccsi.c ~line 843: (err==0) && (data != NULL)
     * (delegates to eccsi_encode_point(): data==NULL -> LENGTH_ONLY_E;
     *  *sz < needed -> BUFFER_E)
     */
    ExpectIntEQ(wc_ExportEccsiPublicKey(NULL, data, &sz, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ExportEccsiPublicKey(&keyPriv, data, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* State: keyState0 is neither PRIVATEKEY nor PUBLICKEY -> BAD_STATE_E */
    sz = sizeof(data);
    ExpectIntEQ(wc_ExportEccsiPublicKey(&keyState0, data, &sz, 1),
        WC_NO_ERR_TRACE(BAD_STATE_E));
    /* State: keyPriv is PRIVATEKEY (first term false) -> valid. */
    ExpectIntEQ(wc_ExportEccsiPublicKey(&keyPriv, NULL, &sz, 1),
        WC_NO_ERR_TRACE(LENGTH_ONLY_E));
    ExpectIntEQ(sz, (word32)(32 * 2));
    /* data != NULL branch + *sz too small -> BUFFER_E. */
    sz = 32 * 2 - 1;
    ExpectIntEQ(wc_ExportEccsiPublicKey(&keyPriv, pubKeyData, &sz, 1),
        WC_NO_ERR_TRACE(BUFFER_E));
    /* Success (raw == 1, no descriptor byte). */
    pubKeySz = sizeof(pubKeyData);
    ExpectIntEQ(wc_ExportEccsiPublicKey(&keyPriv, pubKeyData, &pubKeySz, 1),
        0);
    ExpectIntEQ(pubKeySz, (word32)(32 * 2));

    /* --- wc_ImportEccsiPublicKey() (CLIENT) ---
     * eccsi.c ~line 1301: (key==NULL) || (data==NULL)
     * eccsi.c ~line 1315: (err==0) && (!trusted)
     */
    ExpectIntEQ(wc_ImportEccsiPublicKey(NULL, pubKeyData, pubKeySz, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ImportEccsiPublicKey(&keyPub, NULL, pubKeySz, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* trusted == 1: !trusted false, wc_ecc_check_key() skipped. */
    ExpectIntEQ(wc_ImportEccsiPublicKey(&keyPub, pubKeyData, pubKeySz, 1),
        0);
    /* trusted == 0: !trusted true, wc_ecc_check_key() run (valid point). */
    ExpectIntEQ(wc_ImportEccsiPublicKey(&keyPub, pubKeyData, pubKeySz, 0),
        0);
    /* keyPub is now type ECC_PUBLICKEY: complete the state-check triple
     * deferred from wc_ExportEccsiPublicKey() above (second term false). */
    sz = sizeof(data);
    ExpectIntEQ(wc_ExportEccsiPublicKey(&keyPub, data, &sz, 1), 0);

    /* --- wc_MakeEccsiPair() (KMS) ---
     * eccsi.c ~line 954: (key==NULL)||(rng==NULL)||(id==NULL)||(ssk==NULL)
     *                    ||(pvt==NULL)  [5-operand OR]
     * eccsi.c ~line 958: (err==0) && (key->ecc.type != ECC_PRIVATEKEY)
     */
    ExpectIntEQ(wc_MakeEccsiPair(NULL, &rng, WC_HASH_TYPE_SHA256, id, idSz,
        &ssk, pvt), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_MakeEccsiPair(&keyPriv, NULL, WC_HASH_TYPE_SHA256, id,
        idSz, &ssk, pvt), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_MakeEccsiPair(&keyPriv, &rng, WC_HASH_TYPE_SHA256, NULL,
        idSz, &ssk, pvt), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_MakeEccsiPair(&keyPriv, &rng, WC_HASH_TYPE_SHA256, id,
        idSz, NULL, pvt), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_MakeEccsiPair(&keyPriv, &rng, WC_HASH_TYPE_SHA256, id,
        idSz, &ssk, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* State: keyState0 not wc_MakeEccsiKey()'d -> BAD_STATE_E. */
    ExpectIntEQ(wc_MakeEccsiPair(&keyState0, &rng, WC_HASH_TYPE_SHA256, id,
        idSz, &ssk, pvt), WC_NO_ERR_TRACE(BAD_STATE_E));
    /* Baseline: all valid, state PRIVATEKEY -> success; generates the
     * real (ssk, pvt) pair reused for the rest of this test. */
    ExpectIntEQ(wc_MakeEccsiPair(&keyPriv, &rng, WC_HASH_TYPE_SHA256, id,
        idSz, &ssk, pvt), 0);

    /* --- wc_EncodeEccsiPair() (KMS) ---
     * eccsi.c ~line 993: (key==NULL)||(ssk==NULL)||(pvt==NULL)||(sz==NULL)
     * eccsi.c ~line 997: (err==0) && (data==NULL) -> LENGTH_ONLY_E
     * eccsi.c ~line 1001: (err==0) && (*sz < needed) -> BUFFER_E
     */
    sz = sizeof(data);
    ExpectIntEQ(wc_EncodeEccsiPair(NULL, &ssk, pvt, data, &sz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_EncodeEccsiPair(&keyPriv, NULL, pvt, data, &sz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_EncodeEccsiPair(&keyPriv, &ssk, NULL, data, &sz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_EncodeEccsiPair(&keyPriv, &ssk, pvt, data, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_EncodeEccsiPair(&keyPriv, &ssk, pvt, NULL, &sz),
        WC_NO_ERR_TRACE(LENGTH_ONLY_E));
    ExpectIntEQ(sz, (word32)(32 * 3));
    sz = 32 * 3 - 1;
    ExpectIntEQ(wc_EncodeEccsiPair(&keyPriv, &ssk, pvt, keyBuf, &sz),
        WC_NO_ERR_TRACE(BUFFER_E));
    keyBufSz = sizeof(keyBuf);
    ExpectIntEQ(wc_EncodeEccsiPair(&keyPriv, &ssk, pvt, keyBuf, &keyBufSz),
        0);
    ExpectIntEQ(keyBufSz, (word32)(32 * 3));

    /* --- wc_DecodeEccsiPair() (CLIENT) ---
     * eccsi.c ~line 1173: (key==NULL)||(data==NULL)||(ssk==NULL)||(pvt==NULL)
     * eccsi.c ~line 1176: (err==0) && (sz != key size * 3)
     */
    ExpectIntEQ(wc_DecodeEccsiPair(NULL, keyBuf, keyBufSz, &decSsk, decPvt),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DecodeEccsiPair(&keyPriv, NULL, keyBufSz, &decSsk, decPvt),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DecodeEccsiPair(&keyPriv, keyBuf, keyBufSz, NULL, decPvt),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DecodeEccsiPair(&keyPriv, keyBuf, keyBufSz, &decSsk, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DecodeEccsiPair(&keyPriv, keyBuf, keyBufSz - 1, &decSsk,
        decPvt), WC_NO_ERR_TRACE(BUFFER_E));
    ExpectIntEQ(wc_DecodeEccsiPair(&keyPriv, keyBuf, keyBufSz, &decSsk,
        decPvt), 0);
    ExpectIntEQ(mp_cmp(&ssk, &decSsk), MP_EQ);
    ExpectIntEQ(wc_ecc_cmp_point(pvt, decPvt), MP_EQ);

    /* --- wc_EncodeEccsiSsk() (KMS) ---
     * eccsi.c ~line 1049: (key==NULL)||(ssk==NULL)||(sz==NULL)
     * eccsi.c ~line 1053: (err==0) && (type != ECC_PRIVATEKEY)
     * eccsi.c ~line 1057: data==NULL -> LENGTH_ONLY_E; *sz<needed -> BUFFER_E
     */
    sz = sizeof(data);
    ExpectIntEQ(wc_EncodeEccsiSsk(NULL, &ssk, data, &sz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_EncodeEccsiSsk(&keyPriv, NULL, data, &sz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_EncodeEccsiSsk(&keyPriv, &ssk, data, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_EncodeEccsiSsk(&keyState0, &ssk, data, &sz),
        WC_NO_ERR_TRACE(BAD_STATE_E));
    ExpectIntEQ(wc_EncodeEccsiSsk(&keyPriv, &ssk, NULL, &sz),
        WC_NO_ERR_TRACE(LENGTH_ONLY_E));
    ExpectIntEQ(sz, (word32)32);
    sz = 31;
    ExpectIntEQ(wc_EncodeEccsiSsk(&keyPriv, &ssk, privBuf, &sz),
        WC_NO_ERR_TRACE(BUFFER_E));
    privBufSz = sizeof(privBuf);
    ExpectIntEQ(wc_EncodeEccsiSsk(&keyPriv, &ssk, privBuf, &privBufSz), 0);
    ExpectIntEQ(privBufSz, (word32)32);

    /* --- wc_DecodeEccsiSsk() (KMS) ---
     * eccsi.c ~line 1097: (key==NULL)||(data==NULL)||(ssk==NULL)
     * eccsi.c ~line 1100: (err==0) && (sz != key size)
     */
    ExpectIntEQ(wc_DecodeEccsiSsk(NULL, privBuf, privBufSz, &decSsk),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DecodeEccsiSsk(&keyPriv, NULL, privBufSz, &decSsk),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DecodeEccsiSsk(&keyPriv, privBuf, privBufSz, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DecodeEccsiSsk(&keyPriv, privBuf, privBufSz - 1, &decSsk),
        WC_NO_ERR_TRACE(BUFFER_E));
    ExpectIntEQ(wc_DecodeEccsiSsk(&keyPriv, privBuf, privBufSz, &decSsk), 0);
    ExpectIntEQ(mp_cmp(&ssk, &decSsk), MP_EQ);

    /* --- wc_EncodeEccsiPvt() (KMS) ---
     * eccsi.c ~line 1138: (key==NULL)||(pvt==NULL)||(sz==NULL)
     * (delegates to eccsi_encode_point(): data==NULL -> LENGTH_ONLY_E;
     *  *sz<needed -> BUFFER_E; raw selects the descriptor byte)
     */
    sz = sizeof(data);
    ExpectIntEQ(wc_EncodeEccsiPvt(NULL, pvt, data, &sz, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_EncodeEccsiPvt(&keyPriv, NULL, data, &sz, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_EncodeEccsiPvt(&keyPriv, pvt, data, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_EncodeEccsiPvt(&keyPriv, pvt, NULL, &sz, 1),
        WC_NO_ERR_TRACE(LENGTH_ONLY_E));
    ExpectIntEQ(sz, (word32)(32 * 2));
    sz = 32 * 2 - 1;
    ExpectIntEQ(wc_EncodeEccsiPvt(&keyPriv, pvt, dataRaw, &sz, 1),
        WC_NO_ERR_TRACE(BUFFER_E));
    /* raw == 1: success, no descriptor byte. */
    szRaw = sizeof(dataRaw);
    ExpectIntEQ(wc_EncodeEccsiPvt(&keyPriv, pvt, dataRaw, &szRaw, 1), 0);
    ExpectIntEQ(szRaw, (word32)(32 * 2));
    /* raw == 0: success, descriptor byte 0x04 prepended. */
    szDesc = sizeof(dataDesc);
    ExpectIntEQ(wc_EncodeEccsiPvt(&keyPriv, pvt, dataDesc, &szDesc, 0), 0);
    ExpectIntEQ(szDesc, (word32)(32 * 2 + 1));
    ExpectIntEQ(dataDesc[0], 0x04);

    /* --- wc_DecodeEccsiPvt() (CLIENT) ---
     * eccsi.c ~line 1225: (key==NULL)||(data==NULL)||(pvt==NULL)
     * (delegates to eccsi_decode_point():
     *   ~line 547: (sz != size*2) && (sz != size*2+1)     -> BUFFER_E
     *   ~line 551: (err==0) && (sz & 1)                   -> descriptor byte
     *   ~line 552: data[0] != 0x04                         -> ASN_PARSE_E)
     */
    ExpectIntEQ(wc_DecodeEccsiPvt(NULL, dataRaw, szRaw, decPvt),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DecodeEccsiPvt(&keyPriv, NULL, szRaw, decPvt),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DecodeEccsiPvt(&keyPriv, dataRaw, szRaw, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* sz == size*2 (even, no descriptor): first term false -> success. */
    ExpectIntEQ(wc_DecodeEccsiPvt(&keyPriv, dataRaw, szRaw, decPvt), 0);
    ExpectIntEQ(wc_ecc_cmp_point(pvt, decPvt), MP_EQ);
    /* sz == size*2+1 (odd, valid 0x04 descriptor): both terms false for
     * the BUFFER_E check; sz&1 true -> descriptor path; data[0]==0x04. */
    ExpectIntEQ(wc_DecodeEccsiPvt(&keyPriv, dataDesc, szDesc, decPvt), 0);
    ExpectIntEQ(wc_ecc_cmp_point(pvt, decPvt), MP_EQ);
    /* sz neither size*2 nor size*2+1: both terms true -> BUFFER_E. */
    ExpectIntEQ(wc_DecodeEccsiPvt(&keyPriv, dataDesc, szDesc + 4, decPvt),
        WC_NO_ERR_TRACE(BUFFER_E));
    /* sz == size*2+1 but bad descriptor byte -> ASN_PARSE_E. */
    dataDesc[0] = 0xFF;
    ExpectIntEQ(wc_DecodeEccsiPvt(&keyPriv, dataDesc, szDesc, decPvt),
        WC_NO_ERR_TRACE(ASN_PARSE_E));
    dataDesc[0] = 0x04; /* restore for later reuse below */

    /* --- wc_DecodeEccsiPvtFromSig() (CLIENT) ---
     * eccsi.c ~line 1261: (key==NULL)||(sig==NULL)||(pvt==NULL)
     */
    XMEMSET(sigLike, 0, sizeof(sigLike));
    XMEMCPY(sigLike + 32 * 2, dataDesc, sizeof(dataDesc));
    ExpectIntEQ(wc_DecodeEccsiPvtFromSig(NULL, sigLike, sizeof(sigLike),
        decPvt), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DecodeEccsiPvtFromSig(&keyPriv, NULL, sizeof(sigLike),
        decPvt), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DecodeEccsiPvtFromSig(&keyPriv, sigLike, sizeof(sigLike),
        NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DecodeEccsiPvtFromSig(&keyPriv, sigLike, sizeof(sigLike),
        decPvt), 0);
    ExpectIntEQ(wc_ecc_cmp_point(pvt, decPvt), MP_EQ);

    /* --- wc_ValidateEccsiPair() (CLIENT) ---
     * eccsi.c ~line 1489: (key==NULL)||(id==NULL)||(ssk==NULL)||(pvt==NULL)
     *                     ||(valid==NULL)  [5-operand OR]
     * eccsi.c ~line 1494: (err==0) && (type!=PRIVATEKEY) && (type!=PUBLICKEY)
     * eccsi.c ~line 1518: err == -1 (from wc_ecc_is_point()) -> IS_POINT_E
     */
    ExpectIntEQ(wc_ValidateEccsiPair(NULL, WC_HASH_TYPE_SHA256, id, idSz,
        &ssk, pvt, &valid), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ValidateEccsiPair(&keyPub, WC_HASH_TYPE_SHA256, NULL, idSz,
        &ssk, pvt, &valid), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ValidateEccsiPair(&keyPub, WC_HASH_TYPE_SHA256, id, idSz,
        NULL, pvt, &valid), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ValidateEccsiPair(&keyPub, WC_HASH_TYPE_SHA256, id, idSz,
        &ssk, NULL, &valid), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ValidateEccsiPair(&keyPub, WC_HASH_TYPE_SHA256, id, idSz,
        &ssk, pvt, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* State: keyState0 is neither -> BAD_STATE_E. */
    ExpectIntEQ(wc_ValidateEccsiPair(&keyState0, WC_HASH_TYPE_SHA256, id,
        idSz, &ssk, pvt, &valid), WC_NO_ERR_TRACE(BAD_STATE_E));
    /* State: keyPub is PUBLICKEY (second term false) -> success. */
    ExpectIntEQ(wc_ValidateEccsiPair(&keyPub, WC_HASH_TYPE_SHA256, id, idSz,
        &ssk, pvt, &valid), 0);
    ExpectIntEQ(valid, 1);
    /* State: keyPriv is PRIVATEKEY (first term false) -> success. */
    ExpectIntEQ(wc_ValidateEccsiPair(&keyPriv, WC_HASH_TYPE_SHA256, id, idSz,
        &ssk, pvt, &valid), 0);
    ExpectIntEQ(valid, 1);
    /* PVT not on the curve -> wc_ecc_is_point() fails -> IS_POINT_E. */
    ExpectIntEQ(mp_set(badPvt->x, 1), MP_OKAY);
    ExpectIntEQ(mp_set(badPvt->y, 1), MP_OKAY);
    ExpectIntEQ(mp_set(badPvt->z, 1), MP_OKAY);
    ExpectIntEQ(wc_ValidateEccsiPair(&keyPub, WC_HASH_TYPE_SHA256, id, idSz,
        &ssk, badPvt, &valid), WC_NO_ERR_TRACE(IS_POINT_E));

    /* --- wc_ValidateEccsiPvt() (CLIENT) ---
     * eccsi.c ~line 1579: (key==NULL) | (pvt==NULL) || (valid==NULL)
     * (first two operands are combined with a bitwise '|', not '&&'/'||',
     *  so both are always evaluated; MC/DC's baseline+single-flip pattern
     *  still applies since the result is the same 0/1 boolean algebra.)
     */
    ExpectIntEQ(wc_ValidateEccsiPvt(NULL, pvt, &valid),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ValidateEccsiPvt(&keyPub, NULL, &valid),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ValidateEccsiPvt(&keyPub, pvt, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ValidateEccsiPvt(&keyPub, pvt, &valid), 0);
    ExpectIntEQ(valid, 1);

    /* --- wc_HashEccsiId() (CLIENT) ---
     * eccsi.c ~line 1628: (key==NULL)||(id==NULL)||(pvt==NULL)||(hash==NULL)
     *                     ||(hashSz==NULL)  [5-operand OR]
     * eccsi.c ~line 1632: (err==0) && (type!=PRIVATEKEY) && (type!=PUBLICKEY)
     * eccsi.c ~line 1639: dgstSz < 0 (invalid hashType)
     * eccsi.c ~line 1649: (err==0) && (dgstSz != curveSz)
     * (the "curveSz < 0" leg at ~line 1645 is not reachable via the public
     *  API once wc_ecc_set_curve() has succeeded -- see file header note)
     */
    ExpectIntEQ(wc_HashEccsiId(NULL, WC_HASH_TYPE_SHA256, id, idSz, pvt,
        hashBuf, &hBSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HashEccsiId(&keyPriv, WC_HASH_TYPE_SHA256, NULL, idSz, pvt,
        hashBuf, &hBSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HashEccsiId(&keyPriv, WC_HASH_TYPE_SHA256, id, idSz, NULL,
        hashBuf, &hBSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HashEccsiId(&keyPriv, WC_HASH_TYPE_SHA256, id, idSz, pvt,
        NULL, &hBSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HashEccsiId(&keyPriv, WC_HASH_TYPE_SHA256, id, idSz, pvt,
        hashBuf, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* State: keyState0 is neither -> BAD_STATE_E. */
    ExpectIntEQ(wc_HashEccsiId(&keyState0, WC_HASH_TYPE_SHA256, id, idSz, pvt,
        hashBuf, &hBSz), WC_NO_ERR_TRACE(BAD_STATE_E));
    /* Invalid hashType: wc_HashGetDigestSize() returns BAD_FUNC_ARG < 0. */
    ExpectIntEQ(wc_HashEccsiId(&keyPriv, WC_HASH_TYPE_NONE, id, idSz, pvt,
        hashBuf, &hBSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifdef WOLFSSL_SHA384
    /* Digest size (48, SHA-384) != curve size (32, P-256) -> BAD_FUNC_ARG. */
    ExpectIntEQ(wc_HashEccsiId(&keyPriv, WC_HASH_TYPE_SHA384, id, idSz, pvt,
        hashBuf, &hBSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    /* State: keyPub is PUBLICKEY (second term false) + matching digest
     * size (32 == 32) -> success. */
    ExpectIntEQ(wc_HashEccsiId(&keyPub, WC_HASH_TYPE_SHA256, id, idSz, pvt,
        hashBuf, &hBSz), 0);
    ExpectIntEQ(hBSz, (byte)32);
    /* State: keyPriv is PRIVATEKEY (first term false) -> success; this is
     * the hash reused below for signing/verifying. */
    ExpectIntEQ(wc_HashEccsiId(&keyPriv, WC_HASH_TYPE_SHA256, id, idSz, pvt,
        hashBuf, &hBSz), 0);
    ExpectIntEQ(hBSz, (byte)32);

    /* --- wc_SetEccsiHash() (CLIENT) ---
     * eccsi.c ~line 1681: (key==NULL)||(hash==NULL)||(hashSz>WC_MAX_DIGEST_SIZE)
     */
    ExpectIntEQ(wc_SetEccsiHash(NULL, hashBuf, hBSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SetEccsiHash(&keyPriv, NULL, hBSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SetEccsiHash(&keyPriv, hashBuf,
        (byte)(WC_MAX_DIGEST_SIZE + 1)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Baseline: all valid, hashSz well within bound -> success. Leaves
     * keyPriv's idHash set for wc_SignEccsiHash() below. */
    ExpectIntEQ(wc_SetEccsiHash(&keyPriv, hashBuf, hBSz), 0);

    /* --- wc_SetEccsiPair() (CLIENT) ---
     * eccsi.c ~line 1706: (key==NULL)||(ssk==NULL)||(pvt==NULL)
     */
    ExpectIntEQ(wc_SetEccsiPair(NULL, &ssk, pvt),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SetEccsiPair(&keyPriv, NULL, pvt),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SetEccsiPair(&keyPriv, &ssk, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SetEccsiPair(&keyPriv, &ssk, pvt), 0);

    /* --- wc_SignEccsiHash() (CLIENT) ---
     * eccsi.c ~line 1964: (key==NULL)||(rng==NULL)||(msg==NULL)||(sigSz==NULL)
     * eccsi.c ~line 1967: (err==0) && (type!=PUBLICKEY) && (type!=PRIVATEKEY)
     * eccsi.c ~line 1971: (err==0) && (sig!=NULL) && (idHashSz==0)
     * eccsi.c ~line 1977: sig==NULL -> LENGTH_ONLY_E
     * eccsi.c ~line 1982: (err==0) && (*sigSz < needed)
     */
    ExpectIntEQ(wc_SignEccsiHash(NULL, &rng, WC_HASH_TYPE_SHA256, msg, msgSz,
        sigBuf, &realSigSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SignEccsiHash(&keyPriv, NULL, WC_HASH_TYPE_SHA256, msg,
        msgSz, sigBuf, &realSigSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SignEccsiHash(&keyPriv, &rng, WC_HASH_TYPE_SHA256, NULL,
        msgSz, sigBuf, &realSigSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SignEccsiHash(&keyPriv, &rng, WC_HASH_TYPE_SHA256, msg,
        msgSz, sigBuf, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* State: keyState0 is neither -> BAD_STATE_E (sig==NULL here too, but
     * the state check runs first and short-circuits before it matters). */
    realSigSz = sizeof(sigBuf);
    ExpectIntEQ(wc_SignEccsiHash(&keyState0, &rng, WC_HASH_TYPE_SHA256, msg,
        msgSz, NULL, &realSigSz), WC_NO_ERR_TRACE(BAD_STATE_E));
    /* State: keyPub is PUBLICKEY (first term false); sig==NULL keeps the
     * idHashSz-check's "sig!=NULL" term false -> LENGTH_ONLY_E. */
    ExpectIntEQ(wc_SignEccsiHash(&keyPub, &rng, WC_HASH_TYPE_SHA256, msg,
        msgSz, NULL, &realSigSz), WC_NO_ERR_TRACE(LENGTH_ONLY_E));
    ExpectIntEQ(realSigSz, (word32)(32 * 4 + 1));
    /* keyPub's idHash was already set by wc_HashEccsiId() above, so it
     * cannot isolate the idHashSz==0 leg here. Use a freshly made scratch
     * key (valid PRIVATEKEY type, idHash never set) instead: sig != NULL,
     * idHashSz == 0 -> (sig!=NULL) && (idHashSz==0) both true ->
     * BAD_STATE_E. (If keyPub were used here, its idHashSz != 0 would
     * make this decision false and fall through into real signing, which
     * fails since keyPub has no SSK set -- an easy trap to fall into.) */
    ExpectIntEQ(wc_InitEccsiKey(&keyScratch, HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_MakeEccsiKey(&keyScratch, &rng), 0);
    realSigSz = sizeof(sigBuf);
    ExpectIntEQ(wc_SignEccsiHash(&keyScratch, &rng, WC_HASH_TYPE_SHA256, msg,
        msgSz, sigBuf, &realSigSz), WC_NO_ERR_TRACE(BAD_STATE_E));
    wc_FreeEccsiKey(&keyScratch);
    /* sig != NULL, idHashSz != 0 (keyPriv, set above): (sig!=NULL) true,
     * (idHashSz==0) false -> AND false; *sigSz too small -> BAD_FUNC_ARG. */
    realSigSz = 4;
    ExpectIntEQ(wc_SignEccsiHash(&keyPriv, &rng, WC_HASH_TYPE_SHA256, msg,
        msgSz, sigBuf, &realSigSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Success: full valid call, also used for wc_VerifyEccsiHash() below. */
    realSigSz = sizeof(sigBuf);
    ExpectIntEQ(wc_SignEccsiHash(&keyPriv, &rng, WC_HASH_TYPE_SHA256, msg,
        msgSz, sigBuf, &realSigSz), 0);
    ExpectIntEQ(realSigSz, (word32)(32 * 4 + 1));

    /* Set keyPub's idHash (same value as keyPriv's) so it can verify. */
    ExpectIntEQ(wc_SetEccsiHash(&keyPub, hashBuf, hBSz), 0);

    /* --- wc_VerifyEccsiHash() (CLIENT) ---
     * eccsi.c ~line 2208: (key==NULL)||(msg==NULL)||(sig==NULL)
     *                     ||(verified==NULL)  [4-operand OR]
     * eccsi.c ~line 2211: (err==0) && (type!=PRIVATEKEY) && (type!=PUBLICKEY)
     * eccsi.c ~line 2215: (err==0) && (idHashSz==0)
     * eccsi_decode_sig_r_pvt() ~line 2067: sigSz != key size * 4 + 1
     * eccsi.c ~line 2244/2247 (r range): mp_iszero(r); mp_cmp(r,order)
     * eccsi_calc_j() ~line 2155/2158 (s range): mp_iszero(s); mp_cmp(s,order)
     */
    ExpectIntEQ(wc_VerifyEccsiHash(NULL, WC_HASH_TYPE_SHA256, msg, msgSz,
        sigBuf, realSigSz, &verified), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_VerifyEccsiHash(&keyPub, WC_HASH_TYPE_SHA256, NULL, msgSz,
        sigBuf, realSigSz, &verified), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_VerifyEccsiHash(&keyPub, WC_HASH_TYPE_SHA256, msg, msgSz,
        NULL, realSigSz, &verified), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_VerifyEccsiHash(&keyPub, WC_HASH_TYPE_SHA256, msg, msgSz,
        sigBuf, realSigSz, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* State: keyState0 is neither -> BAD_STATE_E. */
    ExpectIntEQ(wc_VerifyEccsiHash(&keyState0, WC_HASH_TYPE_SHA256, msg,
        msgSz, sigBuf, realSigSz, &verified), WC_NO_ERR_TRACE(BAD_STATE_E));
    /* keyScratch: valid type but never had wc_SetEccsiHash()/wc_HashEccsiId()
     * called -> idHashSz == 0 -> BAD_STATE_E. Re-init and make it a real
     * PRIVATEKEY so the type check's "false" leg is taken and the idHashSz
     * check is isolated. */
    ExpectIntEQ(wc_InitEccsiKey(&keyScratch, HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_MakeEccsiKey(&keyScratch, &rng), 0);
    ExpectIntEQ(wc_VerifyEccsiHash(&keyScratch, WC_HASH_TYPE_SHA256, msg,
        msgSz, sigBuf, realSigSz, &verified), WC_NO_ERR_TRACE(BAD_STATE_E));
    wc_FreeEccsiKey(&keyScratch);
    /* eccsi_decode_sig_r_pvt(): sigSz mismatch -> BAD_FUNC_ARG. */
    ExpectIntEQ(wc_VerifyEccsiHash(&keyPub, WC_HASH_TYPE_SHA256, msg, msgSz,
        sigBuf, realSigSz - 1, &verified), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* State: keyPub is PUBLICKEY (second term false), idHashSz != 0
     * (set above) -> success, genuine signature verifies. */
    ExpectIntEQ(wc_VerifyEccsiHash(&keyPub, WC_HASH_TYPE_SHA256, msg, msgSz,
        sigBuf, realSigSz, &verified), 0);
    ExpectIntEQ(verified, 1);
    /* State: keyPriv is PRIVATEKEY (first term false) -> success too. */
    ExpectIntEQ(wc_VerifyEccsiHash(&keyPriv, WC_HASH_TYPE_SHA256, msg, msgSz,
        sigBuf, realSigSz, &verified), 0);
    ExpectIntEQ(verified, 1);
    /* r == 0 -> MP_ZERO_E (checked before pvt/HE/Y are ever touched). */
    {
        byte badSig[32 * 4 + 1];
        XMEMCPY(badSig, sigBuf, sizeof(badSig));
        XMEMSET(badSig, 0x00, 32);
        ExpectIntEQ(wc_VerifyEccsiHash(&keyPub, WC_HASH_TYPE_SHA256, msg,
            msgSz, badSig, sizeof(badSig), &verified),
            WC_NO_ERR_TRACE(MP_ZERO_E));
    }
    /* r >= order -> ECC_OUT_OF_RANGE_E. */
    {
        byte badSig[32 * 4 + 1];
        XMEMCPY(badSig, sigBuf, sizeof(badSig));
        XMEMSET(badSig, 0xFF, 32);
        ExpectIntEQ(wc_VerifyEccsiHash(&keyPub, WC_HASH_TYPE_SHA256, msg,
            msgSz, badSig, sizeof(badSig), &verified),
            WC_NO_ERR_TRACE(ECC_OUT_OF_RANGE_E));
    }
    /* s == 0 (r/pvt left valid) -> MP_ZERO_E from eccsi_calc_j(). */
    {
        byte badSig[32 * 4 + 1];
        XMEMCPY(badSig, sigBuf, sizeof(badSig));
        XMEMSET(badSig + 32, 0x00, 32);
        ExpectIntEQ(wc_VerifyEccsiHash(&keyPub, WC_HASH_TYPE_SHA256, msg,
            msgSz, badSig, sizeof(badSig), &verified),
            WC_NO_ERR_TRACE(MP_ZERO_E));
    }
    /* s >= order -> ECC_OUT_OF_RANGE_E from eccsi_calc_j(). */
    {
        byte badSig[32 * 4 + 1];
        XMEMCPY(badSig, sigBuf, sizeof(badSig));
        XMEMSET(badSig + 32, 0xFF, 32);
        ExpectIntEQ(wc_VerifyEccsiHash(&keyPub, WC_HASH_TYPE_SHA256, msg,
            msgSz, badSig, sizeof(badSig), &verified),
            WC_NO_ERR_TRACE(ECC_OUT_OF_RANGE_E));
    }

    if (decPvt != NULL) {
        wc_ecc_del_point(decPvt);
    }
    if (badPvt != NULL) {
        wc_ecc_del_point(badPvt);
    }
    if (pvt != NULL) {
        wc_ecc_del_point(pvt);
    }
    mp_free(&decSsk);
    mp_free(&ssk);
    wc_FreeRng(&rng);
    wc_FreeEccsiKey(&keyState0);
    wc_FreeEccsiKey(&keyPub);
    wc_FreeEccsiKey(&keyPriv);
#endif
    return EXPECT_RESULT();
}

/*
 * Positive ECCSI flow, modeled on wolfcrypt/test/test.c's eccsi_test():
 * wc_InitEccsiKey() -> wc_MakeEccsiKey() -> wc_MakeEccsiPair() ->
 * wc_ValidateEccsiPair() / wc_ValidateEccsiPvt() ->
 * wc_EncodeEccsiPair()/Ssk()/Pvt() + wc_DecodeEccsiPair()/Ssk()/Pvt()
 * round-trips -> wc_HashEccsiId() -> wc_SetEccsiHash()/wc_SetEccsiPair() ->
 * wc_SignEccsiHash() -> wc_VerifyEccsiHash() -> wc_FreeEccsiKey().
 * Uses NIST P-256, WC_HASH_TYPE_SHA256 and the "test@wolfssl.com" identity,
 * matching the KAT helper's conventions.
 */
int test_wc_Eccsi_FeatureCoverage(void)
{
    EXPECT_DECLS;
#ifdef WOLFCRYPT_HAVE_ECCSI
    EccsiKey priv;
    EccsiKey pub;
    WC_RNG rng;
    mp_int ssk;
    mp_int decSsk;
    ecc_point* pvt = NULL;
    ecc_point* decPvt = NULL;
    char mail[] = "test@wolfssl.com";
    byte* id = (byte*)mail;
    word32 idSz;
    int valid = 0;
    int verified = 0;
    byte pairData[32 * 3];
    word32 pairSz;
    byte sskData[32];
    word32 sskSz;
    byte pvtData[32 * 2];
    word32 pvtSz;
    byte hashPriv[WC_MAX_DIGEST_SIZE];
    byte hashPub[WC_MAX_DIGEST_SIZE];
    byte hashSz;
    byte sig[32 * 4 + 1];
    word32 sigSz;
    byte msg[1] = { 0x00 };
    word32 msgSz = (word32)sizeof(msg);

    XMEMSET(&priv, 0, sizeof(priv));
    XMEMSET(&pub, 0, sizeof(pub));
    XMEMSET(pairData, 0, sizeof(pairData));
    XMEMSET(sskData, 0, sizeof(sskData));
    XMEMSET(pvtData, 0, sizeof(pvtData));
    XMEMSET(hashPriv, 0, sizeof(hashPriv));
    XMEMSET(hashPub, 0, sizeof(hashPub));
    XMEMSET(sig, 0, sizeof(sig));

    idSz = (word32)XSTRLEN(mail);

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectNotNull(pvt = wc_ecc_new_point());
    ExpectNotNull(decPvt = wc_ecc_new_point());
    ExpectIntEQ(mp_init(&ssk), MP_OKAY);
    ExpectIntEQ(mp_init(&decSsk), MP_OKAY);

    /* KMS key: generates the (KSAK, KPAK) pair and the client's (SSK,PVT). */
    ExpectIntEQ(wc_InitEccsiKey(&priv, HEAP_HINT, INVALID_DEVID), 0);
    /* Client/verifier key: only ever holds the public KPAK. */
    ExpectIntEQ(wc_InitEccsiKey(&pub, HEAP_HINT, INVALID_DEVID), 0);

    ExpectIntEQ(wc_MakeEccsiKey(&priv, &rng), 0);
    ExpectIntEQ(wc_MakeEccsiPair(&priv, &rng, WC_HASH_TYPE_SHA256, id, idSz,
        &ssk, pvt), 0);

    /* Import the KPAK into the client's key (as a trusted value) so it can
     * validate/verify independently of the KMS key. */
    {
        byte pubKeyData[32 * 2];
        word32 pubKeySz = sizeof(pubKeyData);

        ExpectIntEQ(wc_ExportEccsiPublicKey(&priv, pubKeyData, &pubKeySz,
            1), 0);
        ExpectIntEQ(wc_ImportEccsiPublicKey(&pub, pubKeyData, pubKeySz, 1),
            0);
    }

    /* Client validates the (SSK, PVT) pair and PVT it received. */
    ExpectIntEQ(wc_ValidateEccsiPair(&pub, WC_HASH_TYPE_SHA256, id, idSz,
        &ssk, pvt, &valid), 0);
    ExpectIntEQ(valid, 1);
    ExpectIntEQ(wc_ValidateEccsiPvt(&pub, pvt, &valid), 0);
    ExpectIntEQ(valid, 1);

    /* Encode/decode (SSK, PVT) pair, SSK alone, and PVT alone; verify each
     * round-trips back to the original values. */
    pairSz = sizeof(pairData);
    ExpectIntEQ(wc_EncodeEccsiPair(&priv, &ssk, pvt, pairData, &pairSz), 0);
    ExpectIntEQ(wc_DecodeEccsiPair(&priv, pairData, pairSz, &decSsk, decPvt),
        0);
    ExpectIntEQ(mp_cmp(&ssk, &decSsk), MP_EQ);
    ExpectIntEQ(wc_ecc_cmp_point(pvt, decPvt), MP_EQ);

    sskSz = sizeof(sskData);
    ExpectIntEQ(wc_EncodeEccsiSsk(&priv, &ssk, sskData, &sskSz), 0);
    ExpectIntEQ(wc_DecodeEccsiSsk(&priv, sskData, sskSz, &decSsk), 0);
    ExpectIntEQ(mp_cmp(&ssk, &decSsk), MP_EQ);

    pvtSz = sizeof(pvtData);
    ExpectIntEQ(wc_EncodeEccsiPvt(&priv, pvt, pvtData, &pvtSz, 1), 0);
    ExpectIntEQ(wc_DecodeEccsiPvt(&priv, pvtData, pvtSz, decPvt), 0);
    ExpectIntEQ(wc_ecc_cmp_point(pvt, decPvt), MP_EQ);

    /* Both the signer and verifier compute the same identity hash. */
    ExpectIntEQ(wc_HashEccsiId(&priv, WC_HASH_TYPE_SHA256, id, idSz, pvt,
        hashPriv, &hashSz), 0);
    ExpectIntEQ(hashSz, (byte)32);
    ExpectIntEQ(wc_HashEccsiId(&pub, WC_HASH_TYPE_SHA256, id, idSz, pvt,
        hashPub, &hashSz), 0);
    ExpectIntEQ(hashSz, (byte)32);
    ExpectBufEQ(hashPriv, hashPub, hashSz);

    ExpectIntEQ(wc_SetEccsiHash(&priv, hashPriv, hashSz), 0);
    ExpectIntEQ(wc_SetEccsiPair(&priv, &ssk, pvt), 0);

    /* Length-query then real sign. */
    sigSz = sizeof(sig);
    ExpectIntEQ(wc_SignEccsiHash(&priv, &rng, WC_HASH_TYPE_SHA256, msg,
        msgSz, NULL, &sigSz), WC_NO_ERR_TRACE(LENGTH_ONLY_E));
    ExpectIntEQ(sigSz, (word32)(32 * 4 + 1));
    ExpectIntEQ(wc_SignEccsiHash(&priv, &rng, WC_HASH_TYPE_SHA256, msg,
        msgSz, sig, &sigSz), 0);

    ExpectIntEQ(wc_SetEccsiHash(&pub, hashPub, hashSz), 0);
    ExpectIntEQ(wc_VerifyEccsiHash(&pub, WC_HASH_TYPE_SHA256, msg, msgSz,
        sig, sigSz, &verified), 0);
    ExpectIntEQ(verified, 1);
    /* Verifying with the KMS key itself also works. */
    ExpectIntEQ(wc_VerifyEccsiHash(&priv, WC_HASH_TYPE_SHA256, msg, msgSz,
        sig, sigSz, &verified), 0);
    ExpectIntEQ(verified, 1);

    if (decPvt != NULL) {
        wc_ecc_del_point(decPvt);
    }
    if (pvt != NULL) {
        wc_ecc_del_point(pvt);
    }
    mp_free(&decSsk);
    mp_free(&ssk);
    wc_FreeRng(&rng);
    wc_FreeEccsiKey(&pub);
    wc_FreeEccsiKey(&priv);
#endif
    return EXPECT_RESULT();
}
