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

/* The detached header/footer pair in Section 6 is signed here rather than
 * loaded from ./certs, and RSA blinding draws from the RNG. Pin the stream so
 * the bundle is byte-identical on every run. */
#include "mcdc_seed_rng.h"

#include <wolfcrypt/src/pkcs7.c>

#define MCDC_SR_IMPL
#include "mcdc_seed_rng.h"

#include <stdio.h>
#include <string.h>
#include <wolfssl/certs_test.h>

#define WB_HEADFOOT_SEED 0x7c7a5f70UL

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

#define WB_CORPUS_SZ 8192
static byte wbCorpus[WB_CORPUS_SZ];

static word32 wb_load_file(const char* path, byte* buf, word32 bufSz)
{
    FILE* f;
    size_t n;

    f = fopen(path, "rb");
    if (f == NULL) {
        printf("  [wb] corpus not found, skip: %s\n", path);
        return 0;
    }
    n = fread(buf, 1, bufSz, f);
    fclose(f);
    return (word32)n;
}

/* ------------------------------------------------------------------------- *
 * Section 5: PKCS7_VerifySignedData() multi-part eContent walk
 * [:7543, :7556, :7559, :7562, :7565, :7582, :7602, :7605].
 *
 * These lines live in the NO_PKCS7_STREAM arm of WC_PKCS7_VERIFY_STAGE3 and
 * only run when `multiPart` is set, i.e. when eContent is a CONSTRUCTED
 * OCTET STRING holding more than one definite-length OCTET STRING. Every
 * multi-part corpus in ./certs is BER with an indefinite-length outer
 * ContentInfo, and the NO_PKCS7_STREAM build converts those with
 * wc_BerToDer() at :6986 before the eContent is ever looked at -- the
 * conversion collapses the segments, so `multiPart` is 0 by the time
 * STAGE3 runs and the whole block is dead for the whole corpus.
 *
 * The shells below therefore carry DEFINITE outer lengths with a
 * CONSTRUCTED OCTET STRING inside, which is the one shape that survives to
 * STAGE3 with multiPart set. The inner segment lengths deliberately lie in
 * some variants: GetLength_ex() is called with NO_USER_CHECK at :7308 and
 * :7329, so a declared content length larger than the buffer is accepted
 * there and the STAGE3 loop is what has to notice.
 * ------------------------------------------------------------------------- */
#ifndef NO_RSA

#define WB_SD_BUF_SZ 256
static byte wbSdBuf[WB_SD_BUF_SZ];
/* offset one past the eContent blob in wbSdBuf, so a caller can truncate the
 * message exactly there */
static word32 wbSdBlobEnd;

/* id-signedData / id-data, DER encoded */
static const byte wbSignedDataOid[] =
    { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02 };
static const byte wbDataOid[] =
    { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01 };
/* SET { SEQUENCE { id-sha1, NULL } } */
static const byte wbDigestAlgs[] =
    { 0x31, 0x0B, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A,
      0x05, 0x00 };
static const byte wbVersion[]  = { 0x02, 0x01, 0x01 };
/* empty signerInfos SET: makes the bundle degenerate at :8091, which is what
 * lets these shells run to the end of the state machine without a signer */
static const byte wbNoSigners[] = { 0x31, 0x00 };

static word32 wb_hdr_len(word32 len)
{
    return (len < 0x80) ? 2 : ((len < 0x100) ? 3 : 4);
}

static word32 wb_put_hdr(byte* out, word32 idx, byte tag, word32 len)
{
    out[idx++] = tag;
    if (len < 0x80) {
        out[idx++] = (byte)len;
    }
    else if (len < 0x100) {
        out[idx++] = 0x81;
        out[idx++] = (byte)len;
    }
    else {
        out[idx++] = 0x82;
        out[idx++] = (byte)(len >> 8);
        out[idx++] = (byte)len;
    }
    return idx;
}

/* Wraps a ready-made eContent blob (a complete OCTET STRING TLV, whose own
 * declared length may lie) in a degenerate SignedData ContentInfo. Every
 * wrapper length is the true byte count, so only the innermost declaration
 * can be inconsistent. Returns the total message size. */
static word32 wb_wrap_signed(const byte* eblob, word32 eblobSz)
{
    word32 eciBody, sdBody, a0OutSz, ciBody, idx = 0;

    eciBody = (word32)sizeof(wbDataOid) + wb_hdr_len(eblobSz) + eblobSz;
    sdBody  = (word32)sizeof(wbVersion) + (word32)sizeof(wbDigestAlgs) +
              wb_hdr_len(eciBody) + eciBody + (word32)sizeof(wbNoSigners);
    a0OutSz = wb_hdr_len(sdBody) + sdBody;
    ciBody  = (word32)sizeof(wbSignedDataOid) + wb_hdr_len(a0OutSz) + a0OutSz;

    if (wb_hdr_len(ciBody) + ciBody > WB_SD_BUF_SZ) {
        return 0;
    }

    idx = wb_put_hdr(wbSdBuf, idx, ASN_SEQUENCE | ASN_CONSTRUCTED, ciBody);
    XMEMCPY(wbSdBuf + idx, wbSignedDataOid, sizeof(wbSignedDataOid));
    idx += (word32)sizeof(wbSignedDataOid);
    idx = wb_put_hdr(wbSdBuf, idx,
            ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0, a0OutSz);
    idx = wb_put_hdr(wbSdBuf, idx, ASN_SEQUENCE | ASN_CONSTRUCTED, sdBody);
    XMEMCPY(wbSdBuf + idx, wbVersion, sizeof(wbVersion));
    idx += (word32)sizeof(wbVersion);
    XMEMCPY(wbSdBuf + idx, wbDigestAlgs, sizeof(wbDigestAlgs));
    idx += (word32)sizeof(wbDigestAlgs);
    idx = wb_put_hdr(wbSdBuf, idx, ASN_SEQUENCE | ASN_CONSTRUCTED, eciBody);
    XMEMCPY(wbSdBuf + idx, wbDataOid, sizeof(wbDataOid));
    idx += (word32)sizeof(wbDataOid);
    idx = wb_put_hdr(wbSdBuf, idx,
            ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0, eblobSz);
    XMEMCPY(wbSdBuf + idx, eblob, eblobSz);
    idx += eblobSz;
    wbSdBlobEnd = idx;
    XMEMCPY(wbSdBuf + idx, wbNoSigners, sizeof(wbNoSigners));
    idx += (word32)sizeof(wbNoSigners);

    return idx;
}

/* two definite OCTET STRINGs inside a CONSTRUCTED OCTET STRING: multiPart */
static const byte wbEcMulti[] = {
    0x24, 0x0C,
      0x04, 0x04, 'A', 'A', 'A', 'A',
      0x04, 0x04, 'B', 'B', 'B', 'B'
};
/* same, but the second segment's tag is not an OCTET STRING */
static const byte wbEcBadTag[] = {
    0x24, 0x0C,
      0x04, 0x04, 'A', 'A', 'A', 'A',
      0x05, 0x04, 'B', 'B', 'B', 'B'
};
/* CONSTRUCTED OCTET STRING declaring far more content than is present: with
 * the message truncated at the end of the blob, the loop runs off the end and
 * the segment tag read itself fails */
static const byte wbEcRunOff[] = {
    0x24, 0x7F,
      0x04, 0x04, 'A', 'A', 'A', 'A',
      0x04, 0x04, 'B', 'B', 'B', 'B'
};
/* same, but the last segment is a bare tag plus a long-form length prefix
 * with no length bytes behind it */
static const byte wbEcCutLen[] = {
    0x24, 0x7F,
      0x04, 0x04, 'A', 'A', 'A', 'A',
      0x04, 0x82
};
/* second segment declares more content than the CONSTRUCTED OCTET STRING it
 * sits in, while still fitting inside the message buffer */
static const byte wbEcOverrun[] = {
    0x24, 0x0C,
      0x04, 0x04, 'A', 'A', 'A', 'A',
      0x04, 0x20,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
/* single definite OCTET STRING whose declared length runs past the message:
 * not multiPart, so STAGE3 takes the single-part arm and its size check
 * rejects, which is the only way :7605's leading operand is ever false */
static const byte wbEcSingleLong[] = {
    0x04, 0x7F, 'A', 'A', 'A', 'A'
};

static int wb_verify_shell(word32 msgSz, byte* in2, word32 in2Sz,
        byte* hashBuf, word32 hashSz)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    int ret;

    if (p == NULL) {
        return -1;
    }
    if (wc_PKCS7_InitWithCert(p, NULL, 0) != 0) {
        wc_PKCS7_Free(p);
        return -1;
    }
    ret = wc_PKCS7_VerifySignedData_ex(p, hashBuf, hashSz, wbSdBuf, msgSz,
            in2, in2Sz);
    wc_PKCS7_Free(p);
    return ret;
}

static void wb_multipart_walk(void)
{
    byte   dummyFoot[8];
    byte   dummyHash[WC_SHA_DIGEST_SIZE];
    word32 msgSz;

    XMEMSET(dummyFoot, 0, sizeof(dummyFoot));
    XMEMSET(dummyHash, 0x5a, sizeof(dummyHash));

    WB_NOTE("PKCS7_VerifySignedData(): two-segment eContent, the walk that"
            " parses cleanly [:7556 both true, :7602 cond 1 false,"
            " :7605 both true]");
    msgSz = wb_wrap_signed(wbEcMulti, (word32)sizeof(wbEcMulti));
    WB_CHECK(msgSz > 0, "multi-part shell built");
    if (msgSz == 0) {
        return;
    }
    (void)wb_verify_shell(msgSz, NULL, 0, NULL, 0);

    WB_NOTE("PKCS7_VerifySignedData(): the four operands of the multi-part"
            " keepContent expression, each isolated false against the"
            " all-true row [:7543]");
    (void)wb_verify_shell(msgSz, dummyFoot, (word32)sizeof(dummyFoot), NULL, 0);
    (void)wb_verify_shell(msgSz, dummyFoot, 0, dummyHash,
            (word32)sizeof(dummyHash));
    (void)wb_verify_shell(msgSz, dummyFoot, (word32)sizeof(dummyFoot),
            dummyHash, 0);
    (void)wb_verify_shell(msgSz, dummyFoot, (word32)sizeof(dummyFoot),
            dummyHash, (word32)sizeof(dummyHash));

    WB_NOTE("PKCS7_VerifySignedData(): second segment carries a tag that is"
            " not an OCTET STRING [:7559 cond 1 true, :7556 cond 0 false]");
    msgSz = wb_wrap_signed(wbEcBadTag, (word32)sizeof(wbEcBadTag));
    if (msgSz > 0) {
        (void)wb_verify_shell(msgSz, NULL, 0, NULL, 0);
    }

    WB_NOTE("PKCS7_VerifySignedData(): declared segment run longer than the"
            " message, truncated at the last segment, so the segment tag read"
            " runs out of input [:7559/:7562/:7565 cond 0 false]");
    msgSz = wb_wrap_signed(wbEcRunOff, (word32)sizeof(wbEcRunOff));
    if (msgSz > 0) {
        (void)wb_verify_shell(wbSdBlobEnd, NULL, 0, NULL, 0);
    }

    WB_NOTE("PKCS7_VerifySignedData(): last segment is a tag plus a long-form"
            " length prefix with no length bytes [:7562 cond 1 true]");
    msgSz = wb_wrap_signed(wbEcCutLen, (word32)sizeof(wbEcCutLen));
    if (msgSz > 0) {
        (void)wb_verify_shell(wbSdBlobEnd, NULL, 0, NULL, 0);
    }

    WB_NOTE("PKCS7_VerifySignedData(): segment longer than the CONSTRUCTED"
            " OCTET STRING that holds it [:7565 cond 1 true, :7582 cond 0"
            " false]");
    msgSz = wb_wrap_signed(wbEcOverrun, (word32)sizeof(wbEcOverrun));
    if (msgSz > 0) {
        (void)wb_verify_shell(msgSz, NULL, 0, NULL, 0);
    }

    WB_NOTE("PKCS7_VerifySignedData(): single-segment eContent declaring more"
            " than the message holds [:7605 cond 0 false]");
    msgSz = wb_wrap_signed(wbEcSingleLong, (word32)sizeof(wbEcSingleLong));
    if (msgSz > 0) {
        (void)wb_verify_shell(msgSz, NULL, 0, NULL, 0);
    }
}
#else
static void wb_multipart_walk(void)
{
    WB_NOTE("NO_RSA; multi-part eContent walk skipped");
}
#endif /* !NO_RSA */

/* ------------------------------------------------------------------------- *
 * Section 6: PKCS7_VerifySignedData() footer/hash argument matrix
 * [:7645, :7739, :7764, :8002, :8108, :8137].
 *
 * Each of these is `in2 && in2Sz > 0` (twice extended with
 * `&& hashBuf && hashSz > 0`) at the head of a streaming stage. Callers
 * either pass in2 == NULL (one-shot) or a real footer with a real hash, so
 * the trailing operands never get a false row: nobody hands the decoder a
 * footer POINTER with a zero footer SIZE, or a hash pointer with a zero hash
 * size. Both are supplied here over a complete bundle held entirely in `in`,
 * which keeps the state machine running to the last stage regardless of what
 * in2/hashBuf say.
 * ------------------------------------------------------------------------- */
#ifndef NO_RSA

static int wb_verify_corpus(word32 msgSz, byte* in2, word32 in2Sz,
        byte* hashBuf, word32 hashSz)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    int ret;

    if (p == NULL) {
        return -1;
    }
    if (wc_PKCS7_InitWithCert(p, NULL, 0) != 0) {
        wc_PKCS7_Free(p);
        return -1;
    }
    ret = wc_PKCS7_VerifySignedData_ex(p, hashBuf, hashSz, wbCorpus, msgSz,
            in2, in2Sz);
    wc_PKCS7_Free(p);
    return ret;
}

/* detached header/footer pair, so the `in2 && in2Sz > 0 && ...` guards can be
 * reached with a genuine two-buffer verify */
#ifdef USE_CERT_BUFFERS_2048
static byte wbHead[512 + 32];
static byte wbFoot[3072];
static word32 wbHeadSz, wbFootSz;
static byte wbDetContent[32];
static byte wbDetHash[WC_SHA256_DIGEST_SIZE];

static int wb_build_head_foot(void)
{
    wc_PKCS7* p;
    WC_RNG    rng;
    int       ret = -1;

    XMEMSET(wbDetContent, 0x37, sizeof(wbDetContent));
    wbHeadSz = (word32)sizeof(wbHead);
    wbFootSz = (word32)sizeof(wbFoot);

    mcdc_sr_arm(WB_HEADFOOT_SEED);
    if (wc_InitRng(&rng) != 0) {
        mcdc_sr_disarm();
        return -1;
    }
    if (wc_Hash(WC_HASH_TYPE_SHA256, wbDetContent, (word32)sizeof(wbDetContent),
            wbDetHash, (word32)sizeof(wbDetHash)) != 0) {
        wc_FreeRng(&rng);
        mcdc_sr_disarm();
        return -1;
    }
    p = wc_PKCS7_New(NULL, INVALID_DEVID);
    if (p != NULL) {
        if (wc_PKCS7_InitWithCert(p, (byte*)client_cert_der_2048,
                (word32)sizeof_client_cert_der_2048) == 0) {
            p->content      = NULL;
            p->contentSz    = (word32)sizeof(wbDetContent);
            p->contentOID   = DATA;
            p->hashOID      = SHA256h;
            p->privateKey   = (byte*)client_key_der_2048;
            p->privateKeySz = (word32)sizeof_client_key_der_2048;
            p->encryptOID   = RSAk;
            p->rng          = &rng;
            (void)wc_PKCS7_NoDefaultSignedAttribs(p);
            (void)wc_PKCS7_SetDetached(p, (word16)1);
            ret = wc_PKCS7_EncodeSignedData_ex(p, wbDetHash,
                    (word32)sizeof(wbDetHash), wbHead, &wbHeadSz, wbFoot,
                    &wbFootSz);
            if (ret >= 0) {
                XMEMCPY(wbHead + wbHeadSz, wbDetContent,
                        sizeof(wbDetContent));
            }
        }
        wc_PKCS7_Free(p);
    }
    wc_FreeRng(&rng);
    mcdc_sr_disarm();
    return ret;
}

/* `withContent` appends the signed content to the header buffer, which is the
 * shape a real two-buffer caller feeds in: header, then content, then footer.
 * Without it the header alone is too short for the stage-3 content read and
 * the state machine stops before the footer stages are ever entered. */
/* Non-detached header/footer pair: the header carries an eContent HEADER
 * whose content the caller supplies out of band, which is the shape that runs
 * the whole state machine to completion (`pkiMsg2 && pkiMsg2Sz > 0 &&
 * hashBuf && hashSz > 0` all true) and so is the row every isolated-false row
 * below pairs against. */
static byte wbHeadN[512 + 32];
static byte wbFootN[3072];
static word32 wbHeadNSz, wbFootNSz;

static int wb_build_head_foot_plain(void)
{
    wc_PKCS7* p;
    WC_RNG    rng;
    int       ret = -1;

    wbHeadNSz = (word32)sizeof(wbHeadN);
    wbFootNSz = (word32)sizeof(wbFootN);

    mcdc_sr_arm(WB_HEADFOOT_SEED);
    if (wc_InitRng(&rng) != 0) {
        mcdc_sr_disarm();
        return -1;
    }
    p = wc_PKCS7_New(NULL, INVALID_DEVID);
    if (p != NULL) {
        if (wc_PKCS7_InitWithCert(p, (byte*)client_cert_der_2048,
                (word32)sizeof_client_cert_der_2048) == 0) {
            p->content      = wbDetContent;
            p->contentSz    = (word32)sizeof(wbDetContent);
            p->contentOID   = DATA;
            p->hashOID      = SHA256h;
            p->privateKey   = (byte*)client_key_der_2048;
            p->privateKeySz = (word32)sizeof_client_key_der_2048;
            p->encryptOID   = RSAk;
            p->rng          = &rng;
            (void)wc_PKCS7_NoDefaultSignedAttribs(p);
            ret = wc_PKCS7_EncodeSignedData_ex(p, wbDetHash,
                    (word32)sizeof(wbDetHash), wbHeadN, &wbHeadNSz, wbFootN,
                    &wbFootNSz);
            if (ret >= 0) {
                XMEMCPY(wbHeadN + wbHeadNSz, wbDetContent,
                        sizeof(wbDetContent));
            }
        }
        wc_PKCS7_Free(p);
    }
    wc_FreeRng(&rng);
    mcdc_sr_disarm();
    return ret;
}

static int wb_verify_head_foot_plain(word32 footSz, byte* hashBuf,
        word32 hashSz, int withContent)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    int ret;

    if (p == NULL) {
        return -1;
    }
    if (wc_PKCS7_InitWithCert(p, NULL, 0) != 0) {
        wc_PKCS7_Free(p);
        return -1;
    }
    p->contentSz = (word32)sizeof(wbDetContent);
    ret = wc_PKCS7_VerifySignedData_ex(p, hashBuf, hashSz, wbHeadN,
            withContent ? wbHeadNSz + (word32)sizeof(wbDetContent) : wbHeadNSz,
            wbFootN, footSz);
    wc_PKCS7_Free(p);
    return ret;
}

static int wb_verify_head_foot(word32 footSz, byte* hashBuf, word32 hashSz,
        int setContent, int withContent)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    int ret;

    if (p == NULL) {
        return -1;
    }
    if (wc_PKCS7_InitWithCert(p, NULL, 0) != 0) {
        wc_PKCS7_Free(p);
        return -1;
    }
    if (setContent) {
        p->content   = wbDetContent;
        p->contentSz = (word32)sizeof(wbDetContent);
    }
    ret = wc_PKCS7_VerifySignedData_ex(p, hashBuf, hashSz, wbHead,
            withContent ? wbHeadSz + (word32)sizeof(wbDetContent) : wbHeadSz,
            wbFoot, footSz);
    wc_PKCS7_Free(p);
    return ret;
}
#endif /* USE_CERT_BUFFERS_2048 */

static void wb_footer_hash_matrix(void)
{
    byte   dummyFoot[8];
    byte   dummyHash[WC_SHA256_DIGEST_SIZE];
    word32 msgSz;

    XMEMSET(dummyFoot, 0, sizeof(dummyFoot));
    XMEMSET(dummyHash, 0x5a, sizeof(dummyHash));

    WB_NOTE("PKCS7_VerifySignedData(): complete bundle in `in` with a footer"
            " POINTER of zero size, so every stage takes the `in` arm with the"
            " leading operand true [:7645/:7764/:8002/:8137 cond 1 false]");
    msgSz = wb_load_file("./certs/test-stream-sign.p7b", wbCorpus,
            sizeof(wbCorpus));
    if (msgSz > 0) {
        (void)wb_verify_corpus(msgSz, dummyFoot, 0, NULL, 0);
        (void)wb_verify_corpus(msgSz, dummyFoot, 0, dummyHash,
                (word32)sizeof(dummyHash));
        (void)wb_verify_corpus(msgSz, dummyFoot, (word32)sizeof(dummyFoot),
                dummyHash, (word32)sizeof(dummyHash));
        (void)wb_verify_corpus(msgSz, NULL, 0, NULL, 0);
    }
    msgSz = wb_load_file("./certs/test-degenerate.p7b", wbCorpus,
            sizeof(wbCorpus));
    if (msgSz > 0) {
        (void)wb_verify_corpus(msgSz, dummyFoot, 0, NULL, 0);
        (void)wb_verify_corpus(msgSz, dummyFoot, 0, dummyHash,
                (word32)sizeof(dummyHash));
    }
    msgSz = wb_load_file("./certs/test-ber-exp02-05-2022.p7b", wbCorpus,
            sizeof(wbCorpus));
    if (msgSz > 0) {
        (void)wb_verify_corpus(msgSz, dummyFoot, 0, NULL, 0);
        (void)wb_verify_corpus(msgSz, dummyFoot, 0, dummyHash,
                (word32)sizeof(dummyHash));
    }

#ifdef USE_CERT_BUFFERS_2048
    if (wb_build_head_foot() < 0) {
        WB_NOTE("detached head/footer encode failed; two-buffer rows skipped");
        wb_fail = 1;
        return;
    }

    WB_NOTE("PKCS7_VerifySignedData(): genuine two-buffer verify, the all-true"
            " row [:7739/:8108]");
    (void)wb_verify_head_foot(wbFootSz, wbDetHash, (word32)sizeof(wbDetHash),
            1, 0);
    (void)wb_verify_head_foot(wbFootSz, wbDetHash, (word32)sizeof(wbDetHash),
            0, 1);

    WB_NOTE("PKCS7_VerifySignedData(): same footer, hash POINTER with a zero"
            " hash size [:7739/:8108 cond 3 false]");
    (void)wb_verify_head_foot(wbFootSz, wbDetHash, 0, 1, 0);
    (void)wb_verify_head_foot(wbFootSz, wbDetHash, 0, 0, 1);

    WB_NOTE("PKCS7_VerifySignedData(): same footer, no hash at all"
            " [:7739/:8108 cond 2 false]");
    (void)wb_verify_head_foot(wbFootSz, NULL, 0, 1, 0);
    (void)wb_verify_head_foot(wbFootSz, NULL, 0, 0, 1);

    WB_NOTE("PKCS7_VerifySignedData(): footer POINTER with a zero footer size"
            " [:7739/:8108 cond 1 false]");
    (void)wb_verify_head_foot(0, wbDetHash, (word32)sizeof(wbDetHash), 1, 0);
    (void)wb_verify_head_foot(0, wbDetHash, (word32)sizeof(wbDetHash), 0, 1);

    if (wb_build_head_foot_plain() < 0) {
        WB_NOTE("non-detached head/footer encode failed");
        wb_fail = 1;
        return;
    }
    WB_NOTE("PKCS7_VerifySignedData(): non-detached two-buffer verify that"
            " runs the state machine to completion -- the all-true row for the"
            " late stages [:8108/:8137]");
    (void)wb_verify_head_foot_plain(wbFootNSz, wbDetHash,
            (word32)sizeof(wbDetHash), 0);
    (void)wb_verify_head_foot_plain(0, wbDetHash, (word32)sizeof(wbDetHash), 0);
    (void)wb_verify_head_foot_plain(wbFootNSz, wbDetHash, 0, 0);
    (void)wb_verify_head_foot_plain(wbFootNSz, NULL, 0, 0);
    /* content carried inline in the header buffer, so stage 3 can read it
     * without a caller-supplied hash: the only shape that reaches the end of
     * stage 6 with hashSz == 0 and a real footer */
    (void)wb_verify_head_foot_plain(wbFootNSz, wbDetHash,
            (word32)sizeof(wbDetHash), 1);
    (void)wb_verify_head_foot_plain(wbFootNSz, wbDetHash, 0, 1);
    (void)wb_verify_head_foot_plain(wbFootNSz, NULL, 0, 1);
#endif
}
#else
static void wb_footer_hash_matrix(void)
{
    WB_NOTE("NO_RSA; footer/hash argument matrix skipped");
}
#endif /* !NO_RSA */

/* ------------------------------------------------------------------------- *
 * Section 7: PKCS7_VerifySignedData() BER-to-DER handoff [:6929].
 *
 * `pkcs7->derSz > 0 && pkcs7->der` at the top of the function only sees a
 * non-zero derSz when the SAME wc_PKCS7 has already converted a BER bundle,
 * i.e. on a second call. Every caller in the tree allocates a fresh handle
 * per verify, so the guard is evaluated all-false forever. The three calls
 * below are on one handle: a plain call (cond 0 false), a call after the
 * fields have been set to a real buffer (both true) and one with the size set
 * but the pointer cleared (cond 0 true, cond 1 false).
 * ------------------------------------------------------------------------- */
#ifndef NO_RSA
static void wb_der_handoff(void)
{
    wc_PKCS7* p;
    word32    msgSz;

    msgSz = wb_load_file("./certs/test-degenerate.p7b", wbCorpus,
            sizeof(wbCorpus));
    if (msgSz == 0) {
        return;
    }

    WB_NOTE("PKCS7_VerifySignedData(): derSz == 0 [:6929 cond 0 false]");
    (void)wb_verify_corpus(msgSz, NULL, 0, NULL, 0);

    WB_NOTE("PKCS7_VerifySignedData(): derSz > 0 with a real der buffer"
            " [:6929 both true]");
    p = wc_PKCS7_New(NULL, INVALID_DEVID);
    if (p != NULL) {
        if (wc_PKCS7_InitWithCert(p, NULL, 0) == 0) {
            p->der   = (byte*)XMALLOC(msgSz, p->heap, DYNAMIC_TYPE_PKCS7);
            if (p->der != NULL) {
                XMEMCPY(p->der, wbCorpus, msgSz);
                p->derSz = msgSz;
                (void)wc_PKCS7_VerifySignedData_ex(p, NULL, 0, wbCorpus,
                        msgSz, NULL, 0);
            }
        }
        wc_PKCS7_Free(p);
    }

    WB_NOTE("PKCS7_VerifySignedData(): derSz > 0 with no der buffer"
            " [:6929 cond 1 false]");
    p = wc_PKCS7_New(NULL, INVALID_DEVID);
    if (p != NULL) {
        if (wc_PKCS7_InitWithCert(p, NULL, 0) == 0) {
            p->der   = NULL;
            p->derSz = msgSz;
            (void)wc_PKCS7_VerifySignedData_ex(p, NULL, 0, wbCorpus, msgSz,
                    NULL, 0);
            p->derSz = 0;
        }
        wc_PKCS7_Free(p);
    }
}
#else
static void wb_der_handoff(void)
{
    WB_NOTE("NO_RSA; BER-to-DER handoff matrix skipped");
}
#endif /* !NO_RSA */

/* ------------------------------------------------------------------------- *
 * Section 8: signer/recipient key-OID matrices [:1352, :9531] and the two
 * small state probes [:1096, :6644].
 *
 * :1352 and :9531 branch on the key algorithm of the certificate handed to
 * wc_PKCS7_InitWithCert()/wc_PKCS7_AddRecipient_KTRI(). Every pkcs7 test in
 * the tree uses an rsaEncryption or an ECDSA certificate, so the RSASSA-PSS
 * arm of each is never taken. certs/rsapss/ carries a real RSA-PSS
 * certificate; certs/ed25519/ carries one whose key is neither RSA-family nor
 * ECDSA, which is the all-false row :1352 needs.
 * ------------------------------------------------------------------------- */
static void wb_key_oid_matrix(void)
{
    wc_PKCS7* p;
    word32    certSz;
    static byte otherCert[2048];
    word32    otherSz;

    certSz = wb_load_file("./certs/rsapss/client-rsapss.der", wbCorpus,
            sizeof(wbCorpus));
    otherSz = wb_load_file("./certs/ed25519/client-ed25519.der", otherCert,
            sizeof(otherCert));

    if (certSz > 0) {
        WB_NOTE("wc_PKCS7_InitWithCert(): RSASSA-PSS signer certificate"
                " [:1352 cond 1 true]");
        p = wc_PKCS7_New(NULL, INVALID_DEVID);
        if (p != NULL) {
            (void)wc_PKCS7_InitWithCert(p, wbCorpus, certSz);
            wc_PKCS7_Free(p);
        }
    }
    if (otherSz > 0) {
        WB_NOTE("wc_PKCS7_InitWithCert(): certificate whose key is neither"
                " RSA-family nor ECDSA [:1352 all operands false]");
        p = wc_PKCS7_New(NULL, INVALID_DEVID);
        if (p != NULL) {
            (void)wc_PKCS7_InitWithCert(p, otherCert, otherSz);
            wc_PKCS7_Free(p);
        }
    }

#if !defined(NO_RSA) && defined(USE_CERT_BUFFERS_2048)
    if (certSz > 0) {
        WB_NOTE("wc_PKCS7_AddRecipient_KTRI(): RSASSA-PSS recipient"
                " certificate, so the RSA-family check passes on its second"
                " operand [:9531 cond 1 false]");
        p = wc_PKCS7_New(NULL, INVALID_DEVID);
        if (p != NULL) {
            if (wc_PKCS7_InitWithCert(p, (byte*)client_cert_der_2048,
                    (word32)sizeof_client_cert_der_2048) == 0) {
                p->contentOID = DATA;
                p->encryptOID = AES256CBCb;
                (void)wc_PKCS7_AddRecipient_KTRI(p, wbCorpus, certSz, 0);
            }
            wc_PKCS7_Free(p);
        }
    }
    if (otherSz > 0) {
        WB_NOTE("wc_PKCS7_AddRecipient_KTRI(): non-RSA recipient certificate,"
                " the row cond 1 pairs against [:9531 both operands true]");
        p = wc_PKCS7_New(NULL, INVALID_DEVID);
        if (p != NULL) {
            if (wc_PKCS7_InitWithCert(p, (byte*)client_cert_der_2048,
                    (word32)sizeof_client_cert_der_2048) == 0) {
                p->contentOID = DATA;
                p->encryptOID = AES256CBCb;
                (void)wc_PKCS7_AddRecipient_KTRI(p, otherCert, otherSz, 0);
            }
            wc_PKCS7_Free(p);
        }
    }
#endif
}

/* wc_PKCS7_DigestParamsAbsent() [:1096]: the SHAKE arm is decided purely by
 * pkcs7->hashOID, and no pkcs7 API path ever sets it to SHAKE128h -- the OID
 * is only reachable through a caller that asks for SHAKE-128 digests, which
 * the encode side does not offer. Set it directly. */
static void wb_digest_params_absent(void)
{
    wc_PKCS7 p;

    XMEMSET(&p, 0, sizeof(p));

    WB_NOTE("wc_PKCS7_DigestParamsAbsent(): hashOID matrix [:1096]");
#if defined(WOLFSSL_SHA3) && \
    (defined(WOLFSSL_SHAKE256) || defined(WOLFSSL_SHAKE128))
    p.hashOID = SHA256h;
    WB_CHECK(wc_PKCS7_DigestParamsAbsent(&p) == 0, ":1096 both false");
    p.hashOID = SHAKE256h;
    WB_CHECK(wc_PKCS7_DigestParamsAbsent(&p) == 1, ":1096 cond 0 true");
    p.hashOID = SHAKE128h;
    WB_CHECK(wc_PKCS7_DigestParamsAbsent(&p) == 1, ":1096 cond 1 true");
#else
    (void)p;
    WB_NOTE("no SHA3/SHAKE; :1096 not compiled");
#endif
}

/* wc_PKCS7_HandleOctetStrings() no-content arm [:6644]: `pkcs7->content &&
 * pkcs7->contentSz > 0`. A caller that sets pkcs7->content always sets
 * contentSz with it, so the trailing operand's false row has to be seeded. */
#ifndef NO_PKCS7_STREAM
static void wb_octet_nocontent(word32 contentSz)
{
    wc_PKCS7 pkcs7;
    byte     content[8];
    byte     in[16];
    word32   idx = 0, tmpIdx = 0;

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));
    XMEMSET(content, 0x11, sizeof(content));
    XMEMSET(in, 0, sizeof(in));

    if (wc_PKCS7_CreateStream(&pkcs7) != 0) {
        return;
    }
    pkcs7.content   = content;
    pkcs7.contentSz = contentSz;
    pkcs7.stream->noContent = 1;
    (void)wc_PKCS7_HandleOctetStrings(&pkcs7, in, (word32)sizeof(in), &tmpIdx,
            &idx, 1);
    wc_PKCS7_FreeStream(&pkcs7);
}

static void wb_octet_nocontent_matrix(void)
{
    WB_NOTE("wc_PKCS7_HandleOctetStrings(): content pointer with a zero"
            " content size [:6644 cond 1 false]");
    wb_octet_nocontent(0);
    WB_NOTE("wc_PKCS7_HandleOctetStrings(): content pointer with a non-zero"
            " content size [:6644 both true]");
    wb_octet_nocontent(8);
}
#else
static void wb_octet_nocontent_matrix(void)
{
    WB_NOTE("NO_PKCS7_STREAM; HandleOctetStrings no-content matrix skipped");
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
    wb_multipart_walk();
    wb_footer_hash_matrix();
    wb_der_handoff();
    wb_key_oid_matrix();
    wb_digest_params_absent();
    wb_octet_nocontent_matrix();

    wolfCrypt_Cleanup();
    printf(wb_fail ? "done (with failures)\n" : "done\n");
    return 0;
}
