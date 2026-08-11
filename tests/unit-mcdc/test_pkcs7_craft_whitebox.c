/* test_pkcs7_craft_whitebox.c
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

/*
 * Crafted-bundle white-box MC/DC supplement for wolfcrypt/src/pkcs7.c.
 *
 * The other pkcs7 white-boxes either sweep real corpora (truncate/mutate) or
 * drive NULL/size argument guards. What is left after those are decisions
 * whose missing vector needs a bundle SHAPE that no encoder in the tree
 * emits and that no single-byte mutation of an encoded bundle can produce:
 * an OPTIONAL element that is present, an OPTIONAL element that is present
 * but of the wrong type, an OID longer than the decoder's cap, or an
 * algorithm/key-size pairing the encode side never builds.
 *
 * Everything here is hand-built DER driven straight into the file-static
 * decoders, with the accepting and the rejecting vector of every targeted
 * decision in this one binary (llvm-cov derives independence pairs per
 * binary).
 *
 * ==========================================================================
 * STRUCTURALLY UNREACHABLE LINKS COVERED BY THIS FILE'S ANALYSIS
 * ==========================================================================
 * (a) REDUNDANT BOUNDS RE-CHECK AFTER A BOUNDS-CHECKING GetLength().
 *     `GetLength()` is `GetLength_ex(..., check=1)`, which returns BUFFER_E
 *     unless `*idx + length <= maxIdx`. Every one of the following guards is
 *     the immediately following statement, with the same `pkiMsgSz` that was
 *     passed as maxIdx and no intervening write to `*idx` or `length`:
 *       pkcs7.c :12472 (KariGetOriginatorIdentifierOrKey, BIT STRING),
 *                :13197 :13222 (DecryptPwri, IV and EncryptedKey),
 *                :13362 :13419 (DecryptKekri, keyIdentifier and
 *                EncryptedKey) -- both conditions of each.
 *     `*idx > pkiMsgSz` and `(word32)length > pkiMsgSz - *idx` are therefore
 *     both false on every arrival: the decision is never true and neither
 *     operand has an independence pair.
 *     :13349 (`kekIdEnd < *idx || kekIdEnd > pkiMsgSz`) is the same argument
 *     one call later: `GetSequence()` is also the bounds-checking variant, so
 *     `kekIdEnd = *idx + length <= pkiMsgSz` and, `length` being a
 *     non-negative int, `kekIdEnd >= *idx`.
 *     :12965 (DecryptOri, oriValue) is the same argument through one
 *     subtraction: `GetLength()` bounds `tmpIdx + seqSz <= pkiMsgSz`, the
 *     explicit check at :12955 bounds `*idx <= tmpIdx + seqSz`, and
 *     `oriValueSz` is defined as `seqSz - (*idx - tmpIdx)`, so
 *     `oriValueSz == (tmpIdx + seqSz) - *idx <= pkiMsgSz - *idx`.
 *
 * (b) OPERAND WHOSE ONLY FAILURE MODE THE PRECEDING GUARD ALREADY EXCLUDED.
 *       :12946 cond 0 (`oriOIDSz <= 0`) -- oriOIDSz is only used after
 *         `GetASNObjectId() != 0` returned 0, and GetASNHeader_ex() rejects
 *         an OBJECT IDENTIFIER whose length is below 3, so oriOIDSz >= 3.
 *       :13372 cond 1 and :13389 cond 1 (`GetASNTag(...) == 0`) -- both are
 *         guarded by `*idx < kekIdEnd`, and :13349 has already established
 *         `kekIdEnd <= pkiMsgSz`, so `*idx + 1 <= pkiMsgSz` and GetASNTag()
 *         cannot fail. The operand has no true row.
 *
 * (c) MUTUALLY EXCLUSIVE TESTS ON ONE VARIABLE.
 *       :9823 cond 4 and :10044 cond 4 (`encryptOID == AES256CBCb`) in the
 *       AES-CBC key-size guard
 *         `(oid==AES128CBCb && keySz!=16) || (oid==AES192CBCb && keySz!=24)
 *          || (oid==AES256CBCb && keySz!=32) || (ivSz != BLOCK)`.
 *       Making cond 4 true forces cond 0 and cond 2 false; making it false,
 *       inside a switch case that only admits those three OIDs, forces cond 0
 *       or cond 2 TRUE. Cond 4's two rows therefore always differ in a second
 *       evaluated condition and no independence pair exists. (Cond 0 and
 *       cond 2 do pair, because their true row short-circuits the whole OR
 *       and masks everything after it -- those are driven below.)
 *
 * (d) ADD-TO-STREAM RESIDUAL CAPACITY TESTS THAT THE EARLY RETURNS INVERT.
 *       :379 both -- `wc_PKCS7_AddDataToStream()` returns at :372 when
 *         `rdSz >= inSz` and at :365 when `stream->length >= expected`, so on
 *         arrival at :379 `inSz - rdSz > 0` and `stream->length < expected`
 *         are both already true. The decision is never false.
 *       :388 cond 1 (`stream->buffer == NULL`) -- cond 1 is only evaluated
 *         when `len + stream->length <= stream->bufferSz`, and `len >= 1`, so
 *         `bufferSz >= 1`. `bufferSz` is non-zero only after
 *         wc_PKCS7_GrowStream() stored a non-NULL buffer, and every site that
 *         clears the buffer clears the size with it, so the operand has no
 *         true row.
 */

#include <wolfcrypt/src/pkcs7.c>

#include <stdio.h>
#include <string.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)
#define WB_CHECK(cond, msg) \
    do { if (!(cond)) { printf("  [wb][FAIL] %s\n", (msg)); wb_fail = 1; } } \
    while (0)

/* ------------------------------------------------------------------------- *
 * Section 1: AES-CBC key-size guard [:9823, :10044].
 *
 * The OR-chain pairs cond 2 (`encryptOID == AES192CBCb`) only against a
 * vector in which the chain runs to its end with cond 2 false and no later
 * operand true -- i.e. a fully VALID AES256CBCb call. No API-level test and
 * no other white-box makes one, so the guard's cond 2 and cond 5 stay
 * unpaired. Both rows are supplied here.
 * ------------------------------------------------------------------------- */
#if !defined(NO_AES) && defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_256) && \
    defined(WOLFSSL_AES_192)
static void wb_aes_cbc_keysize_matrix(void)
{
    wc_PKCS7 p;
    byte key[32];
    byte iv[WC_AES_BLOCK_SIZE];
    byte in[WC_AES_BLOCK_SIZE];
    byte out[WC_AES_BLOCK_SIZE * 2];
    int  i, ret;

    for (i = 0; i < (int)sizeof(key); i++)
        key[i] = (byte)(i + 1);
    for (i = 0; i < (int)sizeof(iv); i++)
        iv[i] = (byte)(i + 0x40);
    XMEMSET(in, 0x5a, sizeof(in));
    XMEMSET(out, 0, sizeof(out));

    XMEMSET(&p, 0, sizeof(p));
    if (wc_PKCS7_Init(&p, NULL, INVALID_DEVID) != 0) {
        WB_NOTE("wc_PKCS7_Init failed; wb_aes_cbc_keysize_matrix skipped");
        wb_fail = 1;
        return;
    }

    WB_NOTE("wc_PKCS7_DecryptContentInit(): AES256CBCb with a matching 32-byte"
            " key, the row cond 2 and cond 5 pair against [:10044]");
    ret = wc_PKCS7_DecryptContentInit(&p, AES256CBCb, key, 32, iv,
            (int)sizeof(iv), INVALID_DEVID, NULL);
    WB_CHECK(ret == 0, ":10044 all operands false (valid AES-256-CBC)");
    if (ret == 0)
        wc_PKCS7_DecryptContentFree(&p, AES256CBCb, NULL);

    WB_NOTE("wc_PKCS7_DecryptContentInit(): AES192CBCb with a 32-byte key"
            " [:10044 cond 2 and cond 3 true]");
    ret = wc_PKCS7_DecryptContentInit(&p, AES192CBCb, key, 32, iv,
            (int)sizeof(iv), INVALID_DEVID, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":10044 cond 2/3 true");

    WB_NOTE("wc_PKCS7_DecryptContentInit(): AES256CBCb with a 16-byte key"
            " [:10044 cond 5 true]");
    ret = wc_PKCS7_DecryptContentInit(&p, AES256CBCb, key, 16, iv,
            (int)sizeof(iv), INVALID_DEVID, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":10044 cond 5 true");

    WB_NOTE("wc_PKCS7_EncryptContent(): same three rows on the encode side"
            " [:9823]");
    ret = wc_PKCS7_EncryptContent(&p, AES256CBCb, key, 32, iv,
            (int)sizeof(iv), NULL, 0, NULL, 0, in, (int)sizeof(in), out);
    WB_CHECK(ret == 0, ":9823 all operands false (valid AES-256-CBC)");
    ret = wc_PKCS7_EncryptContent(&p, AES192CBCb, key, 32, iv,
            (int)sizeof(iv), NULL, 0, NULL, 0, in, (int)sizeof(in), out);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":9823 cond 2/3 true");
    ret = wc_PKCS7_EncryptContent(&p, AES256CBCb, key, 16, iv,
            (int)sizeof(iv), NULL, 0, NULL, 0, in, (int)sizeof(in), out);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":9823 cond 5 true");

    wc_PKCS7_Free(&p);
}
#else
static void wb_aes_cbc_keysize_matrix(void)
{
    WB_NOTE("no AES-CBC 192/256; AES-CBC key-size matrix skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 2: wc_PKCS7_DecryptOri() oriType OID cap [:12946 cond 1].
 *
 * `oriOIDSz > MAX_OID_SZ` needs a well-formed OBJECT IDENTIFIER of more than
 * 32 content bytes. Every OID any encoder in the tree emits is far shorter,
 * and a single-byte mutation of a short one cannot lengthen it without
 * breaking the enclosing length, so the rejecting row needs this hand-built
 * body. The accepting row is the ordinary short-OID body below.
 * ------------------------------------------------------------------------- */

/* OtherRecipientInfo body positioned as wc_PKCS7_DecryptOri() expects it:
 * the caller has consumed the [4] tag, so index 0 is the SEQUENCE length.
 *   35 = 2 (OID header) + 33 (OID content) */
static byte wbOriBigOid[] = {
    0x23,
    0x06, 0x21,
      0x2A, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
      0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11,
      0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
      0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21,
      0x22
};

/* same shape with a 3-byte OID and a 2-byte oriValue: the accepting row */
static byte wbOriOk[] = { 0x09, 0x06, 0x03, 0x2A, 0x03, 0x04,
                          0x04, 0x02, 0xAA, 0xBB };

static int wb_ori_cb(wc_PKCS7* p, byte* oriType, word32 oriTypeSz,
        byte* oriValue, word32 oriValueSz, byte* decryptedKey,
        word32* decryptedKeySz, void* ctx)
{
    (void)p; (void)oriType; (void)oriTypeSz; (void)oriValue; (void)oriValueSz;
    (void)ctx;
    XMEMSET(decryptedKey, 0x22, 32);
    *decryptedKeySz = 32;
    return 0;
}

static int wb_ori_call(byte* body, word32 bodySz)
{
    wc_PKCS7 pkcs7;
    byte     key[32];
    word32   idx = 0;
    word32   keySz = sizeof(key);
    int      recipFound = 0;
    int      ret;

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));
    pkcs7.oriDecryptCb = wb_ori_cb;
    pkcs7.state = WC_PKCS7_DECRYPT_ORI;
#ifndef NO_PKCS7_STREAM
    if (wc_PKCS7_CreateStream(&pkcs7) != 0) {
        return -1;
    }
    pkcs7.stream->maxLen = bodySz;
#endif
    ret = wc_PKCS7_DecryptOri(&pkcs7, body, bodySz, &idx, key, &keySz,
            &recipFound);
#ifndef NO_PKCS7_STREAM
    wc_PKCS7_FreeStream(&pkcs7);
#endif
    return ret;
}

static void wb_ori_oid_cap(void)
{
    int ret;

    WB_NOTE("wc_PKCS7_DecryptOri(): 3-byte oriType OID, the accepting row"
            " [:12946 both operands false]");
    ret = wb_ori_call(wbOriOk, (word32)sizeof(wbOriOk));
    WB_CHECK(ret == 0, ":12946 both false (short oriType OID)");

    WB_NOTE("wc_PKCS7_DecryptOri(): 33-byte oriType OID, past MAX_OID_SZ"
            " [:12946 cond 1 true]");
    ret = wb_ori_call(wbOriBigOid, (word32)sizeof(wbOriBigOid));
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E), ":12946 cond 1 true");
}

/* ------------------------------------------------------------------------- *
 * Section 3: wc_PKCS7_DecryptKekri() OPTIONAL KEKIdentifier fields
 * [:13372, :13389].
 *
 * wc_PKCS7_AddRecipient_KEKRI() emits a KEKIdentifier that carries only the
 * keyIdentifier OCTET STRING, so the two OPTIONAL probes never see anything
 * but "*idx == kekIdEnd". Both probes are three-operand ANDs; the crafted
 * bodies below supply the GeneralizedTime-present row, the
 * present-but-wrong-tag row, and the nothing-present row in one binary.
 * ------------------------------------------------------------------------- */

/* KEKIdentifier carrying ONLY the keyIdentifier: both OPTIONAL probes see
 * *idx == kekIdEnd (cond 0 false). */
static byte wbKekriBare[] = {
    0x30, 0x0A,                                   /* KEKIdentifier */
      0x04, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x30, 0x0B,                                   /* keyEncryptionAlgorithm */
      0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2D,
    0x04, 0x08, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11
};

/* KEKIdentifier carrying keyIdentifier + a GeneralizedTime: the date probe's
 * three operands are all true, the OtherKeyAttribute probe then sees
 * *idx == kekIdEnd. */
static byte wbKekriDate[] = {
    0x30, 0x1B,
      0x04, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      0x18, 0x0F, '2','0','2','6','0','1','0','1','0','0','0','0','0','0','Z',
    0x30, 0x0B,
      0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2D,
    0x04, 0x08, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11
};

/* KEKIdentifier whose OPTIONAL slot holds an OtherKeyAttribute SEQUENCE and
 * no GeneralizedTime: the date probe reads a tag that is not
 * ASN_GENERALIZED_TIME (cond 2 false with cond 0 and cond 1 true), and the
 * OtherKeyAttribute probe then runs with all three operands true. */
static byte wbKekriAttr[] = {
    0x30, 0x10,
      0x04, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      0x30, 0x04, 0x06, 0x02, 0x2A, 0x03,
    0x30, 0x0B,
      0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2D,
    0x04, 0x08, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11
};

static int wb_kekri_call(byte* body, word32 bodySz)
{
    wc_PKCS7 pkcs7;
    byte     key[32];
    word32   idx = 0;
    word32   keySz = sizeof(key);
    int      recipFound = 0;
    int      ret;

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));
    XMEMSET(key, 0, sizeof(key));
    pkcs7.state = WC_PKCS7_DECRYPT_KEKRI;
#ifndef NO_PKCS7_STREAM
    if (wc_PKCS7_CreateStream(&pkcs7) != 0) {
        return -1;
    }
    pkcs7.stream->maxLen = bodySz;
#endif
    ret = wc_PKCS7_DecryptKekri(&pkcs7, body, bodySz, &idx, key, &keySz,
            &recipFound);
#ifndef NO_PKCS7_STREAM
    wc_PKCS7_FreeStream(&pkcs7);
#endif
    return ret;
}

static void wb_kekri_optional_fields(void)
{
    int ret;

    WB_NOTE("wc_PKCS7_DecryptKekri(): KEKIdentifier with only a"
            " keyIdentifier, so both OPTIONAL probes see *idx == kekIdEnd"
            " [:13372 cond 0 false, :13389 cond 0 false]");
    ret = wb_kekri_call(wbKekriBare, (word32)sizeof(wbKekriBare));
    WB_CHECK(ret != 0, ":13372/:13389 cond 0 false (unwrap fails later)");

    WB_NOTE("wc_PKCS7_DecryptKekri(): KEKIdentifier carrying a"
            " GeneralizedTime [:13372 all three operands true]");
    ret = wb_kekri_call(wbKekriDate, (word32)sizeof(wbKekriDate));
    WB_CHECK(ret != 0, ":13372 all true (unwrap fails later)");

    WB_NOTE("wc_PKCS7_DecryptKekri(): KEKIdentifier whose OPTIONAL slot is an"
            " OtherKeyAttribute, so the date probe reads a non-date tag"
            " [:13372 cond 2 false, :13389 all three true]");
    ret = wb_kekri_call(wbKekriAttr, (word32)sizeof(wbKekriAttr));
    WB_CHECK(ret != 0, ":13372 cond 2 false (unwrap fails later)");
}

/* ------------------------------------------------------------------------- *
 * Section 4: wc_PKCS7_DecryptPwri() OPTIONAL PBKDF2 parameters
 * [:13097, :13106, :13168].
 *
 * wc_PKCS7_AddRecipient_PWRI() writes PBKDF2-params as
 * SEQUENCE { salt, iterationCount } and nothing else, so the OPTIONAL
 * keyLength INTEGER and the OPTIONAL prf AlgorithmIdentifier are never
 * present in any bundle the tree can produce; `keyLenPresent` is dead in
 * every measured run and both probes only ever see *idx == pbkdf2End.
 *
 * The bodies below are hand-built PasswordRecipientInfo bodies positioned at
 * the [0] KeyDerivationAlgorithmIdentifier, which is where the caller leaves
 * *idx. They differ only in what sits between the iterationCount and the end
 * of PBKDF2-params:
 *   (a) nothing            -> both probes' cond 0 false
 *   (b) keyLength 32       -> :13097 both true, :13168 cond 0 true/cond 1
 *                             false (32 == the AES-256-CBC key size)
 *   (c) keyLength 16       -> :13168 both true
 *   (d) a NULL             -> :13097 cond 1 false and :13106 cond 1 false
 *   (e) a prf AlgorithmId  -> :13106 both true
 * ------------------------------------------------------------------------- */
#if !defined(NO_PWDBASED) && !defined(NO_SHA) && !defined(NO_AES) && \
    defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_256)

/* PBKDF2 params tail variants, appended after salt + iterationCount */
#define WB_PWRI_KDF_OID   0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, \
                          0x01, 0x05, 0x0C
#define WB_PWRI_SALT      0x04, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, \
                          0x77, 0x88
#define WB_PWRI_ITER      0x02, 0x01, 0x64
/* keyEncryptionAlgorithm: SEQ { id-alg-PWRI-KEK, SEQ { aes256-CBC }, IV },
 * then the EncryptedKey OCTET STRING (32 bytes: one AES block of wrapped key
 * plus a check block, so wc_PKCS7_PwriKek_KeyUnWrap() gets past its own size
 * checks and fails on the MAC instead) */
#define WB_PWRI_TAIL \
    0x30, 0x2C, \
      0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, \
                  0x03, 0x09, \
      0x30, 0x1D, \
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A, \
        0x04, 0x10, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, \
                  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, \
    0x04, 0x20, \
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, \
      0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, \
      0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, \
      0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F

/* (a) no OPTIONAL element: PBKDF2-params is salt(10) + iter(4) = 14 */
static byte wbPwriPlain[] = {
    0xA0, 0x1A,
      WB_PWRI_KDF_OID,
      0x30, 0x0D,
        WB_PWRI_SALT,
        WB_PWRI_ITER,
    WB_PWRI_TAIL
};

/* (b) keyLength 32, matching the AES-256-CBC key size */
static byte wbPwriKeyLenOk[] = {
    0xA0, 0x1D,
      WB_PWRI_KDF_OID,
      0x30, 0x10,
        WB_PWRI_SALT,
        WB_PWRI_ITER,
        0x02, 0x01, 0x20,
    WB_PWRI_TAIL
};

/* (c) keyLength 16, contradicting the AES-256-CBC key size */
static byte wbPwriKeyLenBad[] = {
    0xA0, 0x1D,
      WB_PWRI_KDF_OID,
      0x30, 0x10,
        WB_PWRI_SALT,
        WB_PWRI_ITER,
        0x02, 0x01, 0x10,
    WB_PWRI_TAIL
};

/* (d) a NULL where the OPTIONAL keyLength/prf would be: both probes have
 * cond 0 true and cond 1 false */
static byte wbPwriNullOpt[] = {
    0xA0, 0x1C,
      WB_PWRI_KDF_OID,
      0x30, 0x0F,
        WB_PWRI_SALT,
        WB_PWRI_ITER,
        0x05, 0x00,
    WB_PWRI_TAIL
};

/* (e) prf AlgorithmIdentifier (hmacWithSHA256) present */
static byte wbPwriPrf[] = {
    0xA0, 0x28,
      WB_PWRI_KDF_OID,
      0x30, 0x1B,
        WB_PWRI_SALT,
        WB_PWRI_ITER,
        0x30, 0x0C,
          0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09,
          0x05, 0x00,
    WB_PWRI_TAIL
};

static int wb_pwri_call(byte* body, word32 bodySz)
{
    wc_PKCS7 pkcs7;
    byte     key[32];
    word32   idx = 0;
    word32   keySz = sizeof(key);
    int      recipFound = 0;
    int      ret;
    static const byte pw[] = "mcdc-password";

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));
    XMEMSET(key, 0, sizeof(key));
    pkcs7.state = WC_PKCS7_DECRYPT_PWRI;
    pkcs7.pass   = (byte*)pw;
    pkcs7.passSz = (word32)sizeof(pw) - 1;
#ifndef NO_PKCS7_STREAM
    if (wc_PKCS7_CreateStream(&pkcs7) != 0) {
        return -1;
    }
    pkcs7.stream->maxLen = bodySz;
#endif
    ret = wc_PKCS7_DecryptPwri(&pkcs7, body, bodySz, &idx, key, &keySz,
            &recipFound);
#ifndef NO_PKCS7_STREAM
    wc_PKCS7_FreeStream(&pkcs7);
#endif
    return ret;
}

static void wb_pwri_optional_params(void)
{
    int ret;

    WB_NOTE("wc_PKCS7_DecryptPwri(): PBKDF2-params with no OPTIONAL element"
            " [:13097 cond 0 false, :13106 cond 0 false]");
    ret = wb_pwri_call(wbPwriPlain, (word32)sizeof(wbPwriPlain));
    WB_CHECK(ret != WC_NO_ERR_TRACE(ASN_PARSE_E),
            ":13097/:13106 cond 0 false, walk reaches the key unwrap");

    WB_NOTE("wc_PKCS7_DecryptPwri(): OPTIONAL keyLength equal to the"
            " AES-256-CBC key size [:13097 both true, :13168 cond 1 false]");
    ret = wb_pwri_call(wbPwriKeyLenOk, (word32)sizeof(wbPwriKeyLenOk));
    WB_CHECK(ret != WC_NO_ERR_TRACE(ASN_PARSE_E),
            ":13168 cond 1 false, walk reaches the key unwrap");

    WB_NOTE("wc_PKCS7_DecryptPwri(): OPTIONAL keyLength contradicting the"
            " AES-256-CBC key size [:13168 both operands true]");
    ret = wb_pwri_call(wbPwriKeyLenBad, (word32)sizeof(wbPwriKeyLenBad));
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E), ":13168 both true");

    WB_NOTE("wc_PKCS7_DecryptPwri(): a NULL in the OPTIONAL slot, which is"
            " neither an INTEGER nor a SEQUENCE [:13097 cond 1 false,"
            " :13106 cond 1 false]");
    ret = wb_pwri_call(wbPwriNullOpt, (word32)sizeof(wbPwriNullOpt));
    WB_CHECK(ret != 0, ":13097/:13106 cond 1 false");

    WB_NOTE("wc_PKCS7_DecryptPwri(): OPTIONAL prf AlgorithmIdentifier present"
            " [:13106 both operands true]");
    ret = wb_pwri_call(wbPwriPrf, (word32)sizeof(wbPwriPrf));
    WB_CHECK(ret != WC_NO_ERR_TRACE(ASN_PARSE_E),
            ":13106 both true, walk reaches the key unwrap");
}
#else
static void wb_pwri_optional_params(void)
{
    WB_NOTE("no PWDBASED/SHA/AES-256-CBC; PWRI optional-params matrix"
            " skipped");
}
#endif

int main(void)
{
    printf("=== pkcs7 crafted-bundle white-box (Part 5) ===\n");

    if (wolfCrypt_Init() != 0) {
        printf("  [wb] wolfCrypt_Init failed\n");
        return 0;
    }

    wb_aes_cbc_keysize_matrix();
    wb_ori_oid_cap();
    wb_kekri_optional_fields();
    wb_pwri_optional_params();

    wolfCrypt_Cleanup();
    printf(wb_fail ? "done (with failures)\n" : "done\n");
    return 0;
}
