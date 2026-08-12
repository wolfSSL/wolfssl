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
 *
 * (e) PKCS7_VerifySignedData() FOOTER POINTER AND CERTIFICATE-SET WALK.
 *       :7675 both (`pkiMsg2 == NULL || pkiMsg2Sz == 0`) -- in the streaming
 *         build :7646-:7653 assigns pkiMsg2 to in2 or in and pkiMsg2Sz to
 *         stream->length/srcSz/derSz, none of which is NULL or zero when the
 *         caller passed a non-empty `in`. In the NO_PKCS7_STREAM build every
 *         path out of stage 2 and stage 3 that reaches :7675 has already run
 *         `pkiMsg2 = pkiMsg; pkiMsg2Sz = pkiMsgSz;` (:7418, :7610, :7615), and
 *         the one branch that does not (:7588) is entered only when
 *         pkiMsg2Sz > 0 is already true. Neither operand is ever true.
 *       :7903 cond 0 -- the statement immediately before it is
 *         `if (ret != 0) break;` at :7899.
 *       :7917 cond 0 (`certSetEnd < idx`) -- certSetEnd is `idx + length`;
 *         `length` is a non-negative int bounded by INT_MAX (GetLength_ex()
 *         reports negatives as errors that already set ret) and idx is bounded
 *         by the message size, so the word32 sum cannot wrap.
 *       :7929 both -- ret is 0 on entry (:7899) and the loop body breaks the
 *         moment it sets ret, so no iteration arrives with ret non-zero; and
 *         the loop condition `certIdx + 1 < pkiMsg2Sz` is exactly the
 *         precondition GetASNTag() needs, so it cannot fail.
 *       :7935 cond 0 -- same, the :7929 failure path breaks.
 *       :7967 all three -- `pkcs7->stream->flagOne` is written in exactly one
 *         place, :17074 inside wc_PKCS7_DecodeEncryptedData(), and cleared by
 *         wc_PKCS7_ResetStream(). It is 0 for the whole of a SignedData
 *         verify, so the decision is never true and no operand pairs.
 *       :8071 cond 1 -- :8067 sets BUFFER_E when `idx >= maxIdx`, and maxIdx
 *         is capped at pkiMsg2Sz (:8026 streaming, :8034 otherwise), so with
 *         ret == 0 the GetASNTag() at :8071 always succeeds.
 *       :8166 cond 2 (`degenerate == 0`) -- degenerate is assigned
 *         `(length == 0)` at :8091 from the same `length` this decision tests,
 *         and nothing rewrites either between there and :8166, so cond 2 is
 *         true whenever cond 1 is.
 *       :8173 cond 1 -- :8168 sets BUFFER_E when `idx >= pkiMsg2Sz`, which is
 *         exactly GetASNTag()'s failure precondition.
 *
 * (f) AuthEnvelopedData / EncryptedData tail.
 *       :15634 cond 1 (`authAttribsSz > 0`) -- flatAuthAttribs is NULL at
 *         :15143 and assigned only at :15382, inside
 *         `if (authAttribsSz > 0 && authAttribsCount > 0)`, so a non-NULL
 *         pointer implies a non-zero size.
 *       :17106 cond 0 -- ret is 0 throughout WC_PKCS7_STAGE6 up to this point:
 *         wc_PKCS7_AddDataToStream() returns on a non-zero result and :17100
 *         breaks on one.
 *       :17115 both -- :17100 has already rejected
 *         `encryptedContentSz > (int)(pkiMsgSz - idx)` and
 *         `encryptedContentSz <= 0`, so `idx + encryptedContentSz` neither
 *         wraps nor exceeds pkiMsgSz.
 *       :17199 cond 3 (`haveAttribs == 1`) -- cond 1 of the same decision is
 *         `haveAttribs == 0` and haveAttribs only ever holds 0 or 1, so cond 3
 *         cannot change without cond 1 changing with it; the two rows always
 *         differ in a second evaluated condition. Same family as (c).
 *
 * (g) FOUND WHILE DRIVING SECTIONS 9 AND 10 (attempted, then proved).
 *       :16086 both -- the NO_PKCS7_STREAM build rejects
 *         `encryptedContentSz > (int)(pkiMsgSz - idx)` at :16005, and the
 *         streaming build cannot arrive here at all unless
 *         wc_PKCS7_AddDataToStream() at :16044 returned 0 for
 *         `expected == encryptedContentSz + MAX_LENGTH_SZ + 2*ASN_TAG_SZ`,
 *         whose every success path leaves `pkiMsgSz - idx >= expected`. `idx`
 *         is not advanced between there and :16086, so `idx +
 *         encryptedContentSz` neither wraps nor exceeds pkiMsgSz. Driven with
 *         a length byte inflated to 0x7F: the streaming build answered
 *         WC_PKCS7_WANT_READ_E and the non-streaming one BUFFER_E at :16005,
 *         neither reaching the guard.
 *       :17005 cond 1 and :17007 cond 0 -- stage 4 reads the IV, which is the
 *         OPTIONAL parameter INSIDE the content-encryption
 *         AlgorithmIdentifier. GetAlgoId() at :16969 has already parsed that
 *         SEQUENCE with the bounds-checking GetSequence(), so its declared
 *         length -- which covers the IV -- is known to fit in pkiMsgSz, and
 *         the streaming build additionally re-buffers ASN_TAG_SZ +
 *         MAX_LENGTH_SZ bytes at :16996. The GetASNTag() at :17005 therefore
 *         cannot fail, so :17005 cond 1 has no true row and :17007 cond 0 no
 *         false row. Attempted by cutting the message exactly at the IV tag;
 *         that makes GetAlgoId() fail one stage earlier instead.
 *       :17100 cond 0 (`encryptedContentSz <= 0`) -- :17053 already rejected
 *         a GetLength_ex() result of `<= 0`, and the value is only carried
 *         through `stream->varThree` untouched, so it is at least 1 here.
 *       :15861 both -- GetAlgoId(oidBlkType) at :15835 can only yield an
 *         AES-CBC/GCM/CCM 128/192/256, DESb or DES3b OID (asn.c's oidBlkType
 *         table holds nothing else; the AES key-wrap OIDs live in
 *         oidKeyWrapType), and wc_PKCS7_GetOIDKeySize() and
 *         wc_PKCS7_GetOIDBlockSize() both answer for every one of them, so
 *         :15843/:15851 never set ret and cond 0 has no false row. Cond 1
 *         cannot fail either: SetAlgoID() writes the SEQUENCE length to cover
 *         the algorithm parameters, and GetAlgoId() parses that SEQUENCE with
 *         the bounds-checking GetSequence(), so the byte :15861 reads is known
 *         to be inside pkiMsgSz.
 *       :15946 cond 2 (`nonceSz > nonceMax`) -- :15909 has already rejected
 *         `nonceSz > (int)sizeof(nonce)` and `nonce` is
 *         `byte nonce[GCM_NONCE_MID_SZ]`, i.e. 12 bytes, while nonceMax is 12
 *         for GCM and CCM_NONCE_MAX_SZ (13) for CCM. A nonce large enough to
 *         exceed nonceMax has already been rejected by the buffer check.
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

/* Same shell, but the caller supplies the WHOLE encapContentInfo element --
 * header included -- so its length byte can be a definite zero or an
 * indefinite 0x80, which is what the stage-2 encapContentInfo probes branch
 * on. Returns the total message size. */
static word32 wb_wrap_signed_eci_tail(const byte* eci, word32 eciSz,
        const byte* tail, word32 tailSz)
{
    word32 sdBody, a0OutSz, ciBody, idx = 0;

    sdBody  = (word32)sizeof(wbVersion) + (word32)sizeof(wbDigestAlgs) +
              eciSz + tailSz;
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
    XMEMCPY(wbSdBuf + idx, eci, eciSz);
    idx += eciSz;
    wbSdBlobEnd = idx;
    XMEMCPY(wbSdBuf + idx, tail, tailSz);
    idx += tailSz;

    return idx;
}

/* the ordinary tail: an empty signerInfos SET */
static word32 wb_wrap_signed_eci(const byte* eci, word32 eciSz)
{
    return wb_wrap_signed_eci_tail(eci, eciSz, wbNoSigners,
            (word32)sizeof(wbNoSigners));
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

/* ---- stage-2 encapContentInfo shells [:7173, :7194, :7274, :7408] -------
 * `wc_PKCS7_EncodeSignedData()` always writes a definite, non-zero
 * encapContentInfo length and always writes an eContent, so the three probes
 * that branch on a zero/indefinite length or on a missing eContent only ever
 * see one side. GetSequence_ex() is called with NO_USER_CHECK at :7165, so a
 * declared length of zero and an indefinite 0x80 are both accepted there and
 * the shells below reach the probes. */

/* definite length zero: encapContentInfoLen == 0 with a 0x00 length byte */
static const byte wbEciZero[] = { 0x30, 0x00 };

/* indefinite length, OID, then the two end-of-contents bytes */
static const byte wbEciIndefEoc[] = {
    0x30, 0x80,
      0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
      0x00, 0x00,
      0xA0, 0x04, 0x04, 0x02, 'A', 'A'
};

/* indefinite length, OID, then a byte that is not ASN_EOC */
static const byte wbEciIndefNoEoc[] = {
    0x30, 0x80,
      0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
      0xA0, 0x04, 0x04, 0x02, 'A', 'A'
};

/* indefinite length, OID, then ASN_EOC followed by a non-zero byte */
static const byte wbEciIndefHalfEoc[] = {
    0x30, 0x80,
      0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
      0x00, 0x01,
      0xA0, 0x04, 0x04, 0x02, 'A', 'A'
};

/* definite length holding ONLY the contentType OID, so
 * encapContentInfoLen - contentTypeSz == 0 and noContent is set at :7219 */
static const byte wbEciNoContent[] = {
    0x30, 0x0B,
      0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01
};

/* definite length, OID, then an eContent [0] whose indefinite-length byte is
 * the last byte of the message: the multi-part tag read at :7274 then has no
 * input left, with ret still 0 */
static const byte wbEciCutIndef[] = {
    0x30, 0x0E,
      0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
      0xA0, 0x80
};

/* definite length, OID, then an eContent [0] whose length is a long-form
 * prefix with no length bytes behind it: :7249's GetLength_ex fails, so
 * :7274 is reached with ret already non-zero */
static const byte wbEciBadLen[] = {
    0x30, 0x0F,
      0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
      0xA0, 0x84, 0x01
};

/* Same shell verify, but with pkcs7->content set: :7396's detached-signature
 * probe reads `pkcs7->content != NULL && pkcs7->contentSz != 0`, and no caller
 * ever presents a content POINTER with a zero content SIZE. */
static byte wbShellContent[8];

static int wb_verify_shell_content(word32 msgSz, word32 contentSz)
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
    XMEMSET(wbShellContent, 0x41, sizeof(wbShellContent));
    p->content   = wbShellContent;
    p->contentSz = contentSz;
    ret = wc_PKCS7_VerifySignedData_ex(p, NULL, 0, wbSdBuf, msgSz, NULL, 0);
    p->content   = NULL;
    wc_PKCS7_Free(p);
    return ret;
}

/* ---- stage-4 certificate-set tails [:7699, :7708] -----------------------
 * The certificates [0] element is OPTIONAL and every encoder writes it whole,
 * so the two probes that read past its tag never see the tag as the last byte
 * of the message. These tails put it there. */

/* an eContent that parses cleanly, so stage 3 completes and stage 4 runs */
static const byte wbEciPlain[] = {
    0x30, 0x13,
      0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
      0xA0, 0x06, 0x04, 0x04, 'A', 'A', 'A', 'A'
};

/* certificates [0] tag as the last byte: :7692 sets BUFFER_E, so :7699 is
 * reached with ret already non-zero */
static const byte wbTailCertTag[]   = { 0xA0 };
/* certificates [0] of indefinite length, ending the message: the SEQUENCE tag
 * read at :7707 runs out of input, so :7708 sees a non-zero ret */
static const byte wbTailCertIndef[] = { 0xA0, 0x80 };
/* the accepting shape both of the above pair against */
static const byte wbTailCertOk[]    = { 0xA0, 0x80, 0x30, 0x03, 0x02, 0x01,
                                        0x01, 0x00, 0x00, 0x31, 0x00 };

static void wb_stage4_cert_tails(void)
{
    word32 msgSz;

    WB_NOTE("PKCS7_VerifySignedData(): certificates [0] of indefinite length"
            " holding one SEQUENCE [:7699 and :7708 accepting rows]");
    msgSz = wb_wrap_signed_eci_tail(wbEciPlain, (word32)sizeof(wbEciPlain),
            wbTailCertOk, (word32)sizeof(wbTailCertOk));
    WB_CHECK(msgSz > 0, "certificate-set shell built");
    if (msgSz > 0) {
        (void)wb_verify_shell(msgSz, NULL, 0, NULL, 0);
    }

    WB_NOTE("PKCS7_VerifySignedData(): certificates [0] tag as the last byte"
            " of the message [:7699 cond 0 false]");
    msgSz = wb_wrap_signed_eci_tail(wbEciPlain, (word32)sizeof(wbEciPlain),
            wbTailCertTag, (word32)sizeof(wbTailCertTag));
    if (msgSz > 0) {
        (void)wb_verify_shell(msgSz, NULL, 0, NULL, 0);
    }

    WB_NOTE("PKCS7_VerifySignedData(): certificates [0] of indefinite length"
            " ending the message [:7708 cond 0 false]");
    msgSz = wb_wrap_signed_eci_tail(wbEciPlain, (word32)sizeof(wbEciPlain),
            wbTailCertIndef, (word32)sizeof(wbTailCertIndef));
    if (msgSz > 0) {
        (void)wb_verify_shell(msgSz, NULL, 0, NULL, 0);
    }
}

static void wb_stage2_shells(void)
{
    word32 msgSz;

    WB_NOTE("PKCS7_VerifySignedData(): encapContentInfo of definite length"
            " zero [:7173 cond 1 false]");
    msgSz = wb_wrap_signed_eci(wbEciZero, (word32)sizeof(wbEciZero));
    WB_CHECK(msgSz > 0, "zero-length encapContentInfo shell built");
    if (msgSz > 0) {
        (void)wb_verify_shell(msgSz, NULL, 0, NULL, 0);
    }

    WB_NOTE("PKCS7_VerifySignedData(): encapContentInfo of indefinite length,"
            " end-of-contents present [:7173 cond 1 true, :7194 both true]");
    msgSz = wb_wrap_signed_eci(wbEciIndefEoc, (word32)sizeof(wbEciIndefEoc));
    if (msgSz > 0) {
        (void)wb_verify_shell(msgSz, NULL, 0, NULL, 0);
    }

    WB_NOTE("PKCS7_VerifySignedData(): indefinite length, no end-of-contents"
            " [:7194 cond 0 false]");
    msgSz = wb_wrap_signed_eci(wbEciIndefNoEoc,
            (word32)sizeof(wbEciIndefNoEoc));
    if (msgSz > 0) {
        (void)wb_verify_shell(msgSz, NULL, 0, NULL, 0);
    }

    WB_NOTE("PKCS7_VerifySignedData(): indefinite length, ASN_EOC followed by"
            " a non-zero byte [:7194 cond 1 false]");
    msgSz = wb_wrap_signed_eci(wbEciIndefHalfEoc,
            (word32)sizeof(wbEciIndefHalfEoc));
    if (msgSz > 0) {
        (void)wb_verify_shell(msgSz, NULL, 0, NULL, 0);
    }

    WB_NOTE("PKCS7_VerifySignedData(): encapContentInfo holding only the"
            " contentType, so eContent is genuinely absent [:7408 cond 2"
            " true]");
    msgSz = wb_wrap_signed_eci(wbEciNoContent,
            (word32)sizeof(wbEciNoContent));
    if (msgSz > 0) {
        (void)wb_verify_shell(msgSz, NULL, 0, NULL, 0);
    }

    WB_NOTE("PKCS7_VerifySignedData(): eContent indefinite-length byte at the"
            " end of the message [:7274 cond 1 true]");
    msgSz = wb_wrap_signed_eci(wbEciCutIndef, (word32)sizeof(wbEciCutIndef));
    if (msgSz > 0) {
        (void)wb_verify_shell(wbSdBlobEnd, NULL, 0, NULL, 0);
    }

    WB_NOTE("PKCS7_VerifySignedData(): eContent length prefix with no length"
            " bytes, so the multi-part tag read is reached with ret already"
            " set [:7274 cond 0 false]");
    msgSz = wb_wrap_signed_eci(wbEciBadLen, (word32)sizeof(wbEciBadLen));
    if (msgSz > 0) {
        (void)wb_verify_shell(wbSdBlobEnd, NULL, 0, NULL, 0);

        WB_NOTE("PKCS7_VerifySignedData(): same shell with a content POINTER"
                " and a zero content SIZE, then with both set [:7396 cond 2"
                " false, then true]");
        (void)wb_verify_shell_content(wbSdBlobEnd, 0);
        (void)wb_verify_shell_content(wbSdBlobEnd,
                (word32)sizeof(wbShellContent));
    }
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

/* Streaming flow: WC_PKCS7_WANT_READ_E means "hand me the next chunk". Feeding
 * the header and then the content as successive `in` chunks, with the footer
 * held in `in2` throughout, is the only shape that reaches the END of stage 6
 * while `hashSz` is 0 -- a single-buffer call cannot, because stage 3 has to
 * read the content out of the stream itself and answers WANT_READ instead.
 * Bounded by a chunk count, never by elapsed time. */
static int wb_verify_head_foot_chunked(word32 hashSz)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    int ret = -1;
    int i;

    if (p == NULL) {
        return -1;
    }
    if (wc_PKCS7_InitWithCert(p, NULL, 0) != 0) {
        wc_PKCS7_Free(p);
        return -1;
    }
    p->contentSz = (word32)sizeof(wbDetContent);
    for (i = 0; i < 8; i++) {
        if (i == 0) {
            ret = wc_PKCS7_VerifySignedData_ex(p, wbDetHash, hashSz, wbHeadN,
                    wbHeadNSz, wbFootN, wbFootNSz);
        }
        else {
            ret = wc_PKCS7_VerifySignedData_ex(p, wbDetHash, hashSz,
                    wbDetContent, (word32)sizeof(wbDetContent), wbFootN,
                    wbFootNSz);
        }
        if (ret != WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E)) {
            break;
        }
    }
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

#ifndef NO_PKCS7_STREAM
    /* :8108 exists only in the streaming build, and so does the resume the
     * chunked flow depends on -- NO_PKCS7_STREAM has no WC_PKCS7_WANT_READ_E
     * path to answer with. */
    WB_NOTE("PKCS7_VerifySignedData(): chunked two-buffer verify, header then"
            " content, with a hash POINTER of zero size [:8108 cond 3 false]");
    WB_CHECK(wb_verify_head_foot_chunked(0) == 0,
            ":8108 cond 3 false, chunked verify completes");
    WB_CHECK(wb_verify_head_foot_chunked((word32)sizeof(wbDetHash)) == 0,
            ":8108 all operands true, chunked verify completes");
#endif
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

/* ------------------------------------------------------------------------- *
 * Section 9: wc_PKCS7_DecodeEncryptedData() version reconciliation
 * [:17194, :17199] and the stage-4 IV header [:17005, :17007].
 *
 * The two version checks at the very end of the decode only run after a
 * successful decrypt, so they need real bundles, and the FirmwareEncryptedData
 * arm needs a bundle encoded with `pkcs7->version == 3` (which drops the outer
 * ContentInfo, so the same bytes cannot serve both arms). The version INTEGER
 * itself is written as 0 by wc_PKCS7_EncodeEncryptedData() whenever there are
 * no unprotected attributes, so the mismatching row has to be patched in.
 *
 * The patch site is located by walking the same elements the decoder walks,
 * not by scanning for a byte pattern, so it stays correct if the encoder
 * changes its lengths.
 * ------------------------------------------------------------------------- */
#if !defined(NO_PKCS7_ENCRYPTED_DATA) && !defined(NO_AES) && \
    defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_128)
#define WB_ED_SEED 0x1d5a7c31UL
#define WB_ED_BUF_SZ 512
static byte wbEdBuf[WB_ED_BUF_SZ];
static const byte wbEdKey[] = {
    0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77
};

/* Encodes an EncryptedData bundle into wbEdBuf. `v3` selects the
 * FirmwareEncryptedData shape (no outer ContentInfo). */
static word32 wb_build_encrypted(int v3)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    WC_RNG    rng;
    byte      data[32];
    int       sz = 0;

    XMEMSET(data, 0x61, sizeof(data));
    if (p == NULL) {
        return 0;
    }
    mcdc_sr_arm(WB_ED_SEED);
    if (wc_InitRng(&rng) != 0) {
        mcdc_sr_disarm();
        wc_PKCS7_Free(p);
        return 0;
    }
    if (wc_PKCS7_Init(p, NULL, INVALID_DEVID) == 0) {
        p->content         = data;
        p->contentSz       = (word32)sizeof(data);
        p->contentOID      = v3 ? FIRMWARE_PKG_DATA : DATA;
        p->encryptOID      = AES128CBCb;
        p->encryptionKey   = (byte*)wbEdKey;
        p->encryptionKeySz = (word32)sizeof(wbEdKey);
        p->rng             = &rng;
        p->version         = v3 ? 3 : 0;
        sz = wc_PKCS7_EncodeEncryptedData(p, wbEdBuf, (word32)sizeof(wbEdBuf));
    }
    wc_PKCS7_Free(p);
    wc_FreeRng(&rng);
    mcdc_sr_disarm();
    return (sz > 0) ? (word32)sz : 0;
}

/* Walks wbEdBuf the way wc_PKCS7_DecodeEncryptedData() walks it in stages 1-3.
 * On success *verIdx is the index of the CMSVersion value byte and the return
 * value is the index of the IV OCTET STRING tag that stage 4 reads. Returns 0
 * on any mismatch, so a caller never patches or cuts at a guessed offset. */
static word32 wb_encrypted_walk(word32 msgSz, int v3, word32* verIdx)
{
    word32 idx = 0, contentType, encOID;
    int    length;
    byte   tag;

    *verIdx = 0;
    if (!v3) {
        if (GetSequence(wbEdBuf, &idx, &length, msgSz) < 0)
            return 0;
        if (wc_GetContentType(wbEdBuf, &idx, &contentType, msgSz) < 0)
            return 0;
        if (GetASNTag(wbEdBuf, &idx, &tag, msgSz) < 0 ||
                tag != (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0))
            return 0;
        if (GetLength(wbEdBuf, &idx, &length, msgSz) < 0)
            return 0;
    }
    if (GetSequence(wbEdBuf, &idx, &length, msgSz) < 0)
        return 0;
    if (idx + 3 > msgSz || wbEdBuf[idx] != ASN_INTEGER || wbEdBuf[idx+1] != 1)
        return 0;
    *verIdx = idx + 2;
    if (GetMyVersion(wbEdBuf, &idx, &length, msgSz) < 0)
        return 0;
    if (GetSequence(wbEdBuf, &idx, &length, msgSz) < 0)
        return 0;
    if (wc_GetContentType(wbEdBuf, &idx, &contentType, msgSz) < 0)
        return 0;
    if (GetAlgoId(wbEdBuf, &idx, &encOID, oidBlkType, msgSz) < 0)
        return 0;
    if (idx >= msgSz || wbEdBuf[idx] != ASN_OCTET_STRING)
        return 0;
    return idx;
}

static int wb_decode_encrypted(word32 msgSz, int v3)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    static byte out[WB_ED_BUF_SZ];
    int ret;

    if (p == NULL) {
        return -1;
    }
    if (wc_PKCS7_Init(p, NULL, INVALID_DEVID) != 0) {
        wc_PKCS7_Free(p);
        return -1;
    }
    p->encryptionKey   = (byte*)wbEdKey;
    p->encryptionKeySz = (word32)sizeof(wbEdKey);
    p->version         = v3 ? 3 : 0;
    ret = wc_PKCS7_DecodeEncryptedData(p, wbEdBuf, msgSz, out, sizeof(out));
    wc_PKCS7_Free(p);
    return ret;
}

static void wb_encrypted_version_matrix(void)
{
    word32 msgSz, verIdx;
    int    ret;

    WB_NOTE("wc_PKCS7_DecodeEncryptedData(): plain EncryptedData, version 0,"
            " no unprotected attributes [:17194 cond 0 false, :17199 cond 2"
            " false]");
    msgSz = wb_build_encrypted(0);
    WB_CHECK(msgSz > 0, "plain EncryptedData encoded");
    if (msgSz == 0) {
        return;
    }
    ret = wb_decode_encrypted(msgSz, 0);
    WB_CHECK(ret > 0, ":17199 cond 2 false (version 0, no attribs)");

    WB_CHECK(wb_encrypted_walk(msgSz, 0, &verIdx) > 0 && verIdx > 0,
            "plain EncryptedData walked to the IV parameter");
    if (verIdx > 0) {
        WB_NOTE("wc_PKCS7_DecodeEncryptedData(): version 1 with no"
                " unprotected attributes [:17199 cond 2 true]");
        wbEdBuf[verIdx] = 1;
        ret = wb_decode_encrypted(msgSz, 0);
        WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_VERSION_E), ":17199 cond 2 true");
        wbEdBuf[verIdx] = 0;
    }

    WB_NOTE("wc_PKCS7_DecodeEncryptedData(): FirmwareEncryptedData shape,"
            " version 0 [:17194 cond 1 false, :17199 cond 0 false]");
    msgSz = wb_build_encrypted(1);
    WB_CHECK(msgSz > 0, "FirmwareEncryptedData encoded");
    if (msgSz == 0) {
        return;
    }
    ret = wb_decode_encrypted(msgSz, 1);
    WB_CHECK(ret > 0, ":17194 cond 1 false (firmware bundle, version 0)");

    WB_CHECK(wb_encrypted_walk(msgSz, 1, &verIdx) > 0 && verIdx > 0,
            "FirmwareEncryptedData walked to the IV parameter");
    if (verIdx > 0) {
        WB_NOTE("wc_PKCS7_DecodeEncryptedData(): FirmwareEncryptedData with a"
                " non-zero version [:17194 both operands true]");
        wbEdBuf[verIdx] = 1;
        ret = wb_decode_encrypted(msgSz, 1);
        WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_VERSION_E), ":17194 both true");
        wbEdBuf[verIdx] = 0;
    }

}
#else
static void wb_encrypted_version_matrix(void)
{
    WB_NOTE("no EncryptedData/AES-128-CBC; EncryptedData version matrix"
            " skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 10: wc_PKCS7_DecodeAuthEnvelopedData() encryptedContent shapes
 * [:15991, :15994, :15998, :16086, :16274].
 *
 * wc_PKCS7_EncodeAuthEnvelopedData() writes encryptedContent with
 * SetImplicit(ASN_OCTET_STRING, 0, ...), i.e. a PRIMITIVE [0] header, so
 * `explicitOctet` is 0 for every bundle the tree can produce and the whole
 * :15990-:16002 block is dead. It also always writes a full-length ICV, so
 * the CCM minimum-tag check at :16274 never fires and its three OID operands
 * never see a decision that is true.
 *
 * The patches below are applied to a self-built bundle at a site located by
 * arithmetic that is checked before use: wc_PKCS7_EncodeAuthEnvelopedData()
 * emits `macInt`, then the [0] encryptedContent header, then the ciphertext,
 * then `04 10` and the 16-byte ICV, so with a content size below 128 the
 * header is exactly 18 + contentSz + 2 bytes from the end and `macInt` is the
 * three bytes in front of it. Both are asserted.
 * ------------------------------------------------------------------------- */
#if defined(HAVE_AESGCM) && defined(HAVE_AESCCM) && !defined(NO_RSA) && \
    defined(WOLFSSL_AES_128) && defined(WOLFSSL_AES_192) && \
    defined(WOLFSSL_AES_256) && defined(USE_CERT_BUFFERS_2048)
#define WB_AE_SEED 0x4ae09c17UL
#define WB_AE_BUF_SZ 2048
#define WB_AE_CONTENT_SZ 32
static byte wbAeBuf[WB_AE_BUF_SZ];
static word32 wbAeSz;
static word32 wbAeHdr;      /* index of the [0] encryptedContent tag */

static int wb_build_auth_env(int encryptOID)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    WC_RNG    rng;
    byte      data[WB_AE_CONTENT_SZ];
    int       sz = 0;

    XMEMSET(data, 0x62, sizeof(data));
    wbAeSz = 0;
    wbAeHdr = 0;
    if (p == NULL) {
        return -1;
    }
    mcdc_sr_arm(WB_AE_SEED);
    if (wc_InitRng(&rng) != 0) {
        mcdc_sr_disarm();
        wc_PKCS7_Free(p);
        return -1;
    }
    if (wc_PKCS7_InitWithCert(p, (byte*)client_cert_der_2048,
            (word32)sizeof_client_cert_der_2048) == 0) {
        p->content    = data;
        p->contentSz  = (word32)sizeof(data);
        p->contentOID = DATA;
        p->encryptOID = encryptOID;
        p->rng        = &rng;
        sz = wc_PKCS7_EncodeAuthEnvelopedData(p, wbAeBuf,
                (word32)sizeof(wbAeBuf));
    }
    wc_PKCS7_Free(p);
    wc_FreeRng(&rng);
    mcdc_sr_disarm();
    if (sz <= 0) {
        return -1;
    }
    wbAeSz = (word32)sz;
    /* 18 = the trailing `04 10` plus the 16-byte ICV; 2 = the [0] header */
    if (wbAeSz < 18 + WB_AE_CONTENT_SZ + 2) {
        return -1;
    }
    wbAeHdr = wbAeSz - 18 - WB_AE_CONTENT_SZ - 2;
    if (wbAeBuf[wbAeHdr] != (ASN_CONTEXT_SPECIFIC | 0) ||
            wbAeBuf[wbAeHdr + 1] != WB_AE_CONTENT_SZ ||
            wbAeBuf[wbAeSz - 18] != ASN_OCTET_STRING ||
            wbAeBuf[wbAeSz - 17] != 16 ||
            wbAeHdr < 3 || wbAeBuf[wbAeHdr - 3] != ASN_INTEGER ||
            wbAeBuf[wbAeHdr - 2] != 1) {
        wbAeHdr = 0;
        return -1;
    }
    return 0;
}

static int wb_decode_auth_env(word32 msgSz)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    static byte out[WB_AE_BUF_SZ];
    int ret;

    if (p == NULL) {
        return -1;
    }
    if (wc_PKCS7_InitWithCert(p, (byte*)client_cert_der_2048,
            (word32)sizeof_client_cert_der_2048) != 0) {
        wc_PKCS7_Free(p);
        return -1;
    }
    p->privateKey   = (byte*)client_key_der_2048;
    p->privateKeySz = (word32)sizeof_client_key_der_2048;
    ret = wc_PKCS7_DecodeAuthEnvelopedData(p, wbAeBuf, msgSz, out, sizeof(out));
    wc_PKCS7_Free(p);
    return ret;
}

/* Rewrites the ICV length in both places the decoder cross-checks them
 * (:16253 requires authTagSz == macSz), so a bundle can claim a short tag. */
static void wb_auth_env_set_tag_sz(byte sz)
{
    wbAeBuf[wbAeHdr - 1] = sz;   /* macInt value */
    wbAeBuf[wbAeSz - 17] = sz;   /* ICV OCTET STRING length */
}

/* Only macInt's value is rewritten: :15963 runs long before the ICV length is
 * read, so the two do not have to agree for that check. */
static void wb_auth_env_set_mac_sz(byte sz)
{
    wbAeBuf[wbAeHdr - 1] = sz;
}

/* The nonce OCTET STRING sits between the algorithm-parameters SEQUENCE and
 * macInt, so its length byte is `3 + nonceSz + 1` back from the encryptedContent
 * header. Returns 0 unless the tag and the current length are what the encoder
 * wrote. */
static word32 wb_auth_env_nonce_len_idx(byte nonceSz)
{
    word32 i;

    if (wbAeHdr < (word32)nonceSz + 5u) {
        return 0;
    }
    i = wbAeHdr - 3u - (word32)nonceSz - 1u;
    if (wbAeBuf[i - 1] != ASN_OCTET_STRING || wbAeBuf[i] != nonceSz) {
        return 0;
    }
    return i;
}

/* Index of the last byte of the content-encryption OID, found by searching for
 * the NIST AES arc `2.16.840.1.101.3.4.1` and confirming the algorithm byte
 * behind it. Returns 0 if the arc is absent or the byte is not the expected
 * one, so a caller never patches a byte it has not identified. */
static const byte wbAesArc[] =
    { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01 };

static word32 wb_auth_env_alg_byte(byte expect)
{
    word32 i;

    if (wbAeSz <= (word32)sizeof(wbAesArc)) {
        return 0;
    }
    for (i = 0; i + (word32)sizeof(wbAesArc) < wbAeSz; i++) {
        if (XMEMCMP(wbAeBuf + i, wbAesArc, sizeof(wbAesArc)) == 0 &&
                wbAeBuf[i + sizeof(wbAesArc)] == expect) {
            return i + (word32)sizeof(wbAesArc);
        }
    }
    return 0;
}

static void wb_auth_env_shapes(void)
{
    int ret;

    if (wb_build_auth_env(AES128GCMb) != 0) {
        WB_NOTE("AES-128-GCM AuthEnvelopedData encode/layout check failed;"
                " encryptedContent shapes skipped");
        wb_fail = 1;
        return;
    }

    WB_NOTE("wc_PKCS7_DecodeAuthEnvelopedData(): pristine AES-128-GCM bundle,"
            " the accepting row every patch below pairs against");
    ret = wb_decode_auth_env(wbAeSz);
    WB_CHECK(ret > 0, "pristine AuthEnvelopedData decodes");

    WB_NOTE("wc_PKCS7_DecodeAuthEnvelopedData(): CONSTRUCTED [0]"
            " encryptedContent, so the explicit OCTET STRING block runs; its"
            " first byte is not an OCTET STRING tag [:15994 cond 1 true]");
    wbAeBuf[wbAeHdr] = (byte)(ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 0);
    (void)wb_decode_auth_env(wbAeSz);

    WB_NOTE("wc_PKCS7_DecodeAuthEnvelopedData(): CONSTRUCTED [0] header of"
            " length zero, which the explicit-octet length parse rejects"
            " [:15991 cond 0 false]");
    wbAeBuf[wbAeHdr + 1] = 0;
    (void)wb_decode_auth_env(wbAeSz);
    wbAeBuf[wbAeHdr + 1] = WB_AE_CONTENT_SZ;

    WB_NOTE("wc_PKCS7_DecodeAuthEnvelopedData(): same, with a well-formed"
            " inner OCTET STRING [:15994 cond 1 false, :15998 both operands"
            " evaluated]");
    {
        byte c0 = wbAeBuf[wbAeHdr + 2];
        byte c1 = wbAeBuf[wbAeHdr + 3];

        wbAeBuf[wbAeHdr + 2] = ASN_OCTET_STRING;
        wbAeBuf[wbAeHdr + 3] = 0x08;
        (void)wb_decode_auth_env(wbAeSz);

        WB_NOTE("wc_PKCS7_DecodeAuthEnvelopedData(): inner OCTET STRING with a"
                " long-form length prefix and no length bytes behind it"
                " [:15998 cond 1 true]");
        wbAeBuf[wbAeHdr + 3] = 0x84;
        (void)wb_decode_auth_env(wbAeHdr + 4);

        WB_NOTE("wc_PKCS7_DecodeAuthEnvelopedData(): message cut immediately"
                " after the CONSTRUCTED [0] header [:15991 cond 1 true,"
                " :15994 cond 0 false]");
        (void)wb_decode_auth_env(wbAeHdr + 2);

        wbAeBuf[wbAeHdr + 2] = c0;
        wbAeBuf[wbAeHdr + 3] = c1;
    }
    wbAeBuf[wbAeHdr] = (byte)(ASN_CONTEXT_SPECIFIC | 0);

    WB_NOTE("wc_PKCS7_DecodeAuthEnvelopedData(): ICV length of zero and ICV"
            " length above WC_AES_BLOCK_SIZE [:15963 cond 1 and cond 2 true]");
    wb_auth_env_set_mac_sz(0);
    (void)wb_decode_auth_env(wbAeSz);
    wb_auth_env_set_mac_sz(0x20);
    (void)wb_decode_auth_env(wbAeSz);
    wb_auth_env_set_mac_sz(16);

    {
        word32 nonceIdx = wb_auth_env_nonce_len_idx(GCM_NONCE_MID_SZ);

        WB_CHECK(nonceIdx > 0, "content-encryption nonce located");
        if (nonceIdx > 0) {
            WB_NOTE("wc_PKCS7_DecodeAuthEnvelopedData(): AES-GCM nonce one"
                    " byte short of the mandated 12 [:15946 cond 1 true, so"
                    " cond 0 has a decision-true row to pair against]");
            wbAeBuf[nonceIdx] = GCM_NONCE_MID_SZ - 1;
            (void)wb_decode_auth_env(wbAeSz);
            wbAeBuf[nonceIdx] = GCM_NONCE_MID_SZ;
        }
    }

    {
        word32 algIdx = wb_auth_env_alg_byte(0x06);  /* aes128-GCM */

        WB_CHECK(algIdx > 0, "content-encryption OID located");
        if (algIdx > 0) {
            WB_NOTE("wc_PKCS7_DecodeAuthEnvelopedData(): content-encryption"
                    " algorithm rewritten to AES-128-CBC, which has a key size"
                    " and a block size but is not an AEAD, so the nonce-bounds"
                    " switch falls to its default [:15946 cond 0 false]");
            wbAeBuf[algIdx] = 0x02;                  /* aes128-CBC */
            (void)wb_decode_auth_env(wbAeSz);
            wbAeBuf[algIdx] = 0x06;
        }
    }

    WB_NOTE("wc_PKCS7_DecodeAuthEnvelopedData(): AES-GCM bundle claiming a"
            " 3-byte ICV, which the GCM tag-size check rejects [:16274 cond 0"
            " false]");
    wb_auth_env_set_tag_sz(3);
    (void)wb_decode_auth_env(wbAeSz);
    wb_auth_env_set_tag_sz(16);

    WB_NOTE("wc_PKCS7_DecodeAuthEnvelopedData(): AES-CCM bundles claiming an"
            " 8-byte ICV, below WOLFSSL_MIN_AUTH_TAG_SZ [:16274 cond 1/2/3 and"
            " cond 4 true]");
    if (wb_build_auth_env(AES128CCMb) == 0) {
        (void)wb_decode_auth_env(wbAeSz);   /* full ICV: cond 4 false */
        wb_auth_env_set_tag_sz(8);
        (void)wb_decode_auth_env(wbAeSz);
    }
    if (wb_build_auth_env(AES192CCMb) == 0) {
        wb_auth_env_set_tag_sz(8);
        (void)wb_decode_auth_env(wbAeSz);
    }
    if (wb_build_auth_env(AES256CCMb) == 0) {
        wb_auth_env_set_tag_sz(8);
        (void)wb_decode_auth_env(wbAeSz);
    }
}
#else
static void wb_auth_env_shapes(void)
{
    WB_NOTE("no AES-GCM/CCM 128/192/256 or RSA; AuthEnvelopedData"
            " encryptedContent shapes skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 11: wc_PKCS7_AddRecipient_KEKRI() wrapped-key size guard [:11192].
 *
 * `encryptedKeySz == 0 || encryptedKeySz > MAX_ENCRYPTED_KEY_SZ` sits on the
 * result of wc_PKCS7_KeyWrap(). With the built-in AES key wrap the result is
 * always between 1 and the output buffer size, so neither operand can be
 * true -- but wc_PKCS7_SetAESKeyWrapUnwrapCb() lets an application replace the
 * wrap, and this guard is precisely the check on what that application returns.
 * The three callbacks below are the three rows: a wrap that reports nothing
 * written, one that reports more than the buffer holds, and the real wrap.
 * ------------------------------------------------------------------------- */
#if !defined(NO_AES) && defined(HAVE_AES_KEYWRAP) && defined(WOLFSSL_AES_256)
#define WB_KEKRI_SEED 0x2b1e7a44UL

static int wb_kw_zero(const byte* key, word32 keySz, const byte* in,
        word32 inSz, int wrap, byte* out, word32 outSz)
{
    (void)key; (void)keySz; (void)in; (void)inSz; (void)wrap; (void)out;
    (void)outSz;
    return 0;
}

static int wb_kw_toobig(const byte* key, word32 keySz, const byte* in,
        word32 inSz, int wrap, byte* out, word32 outSz)
{
    (void)key; (void)keySz; (void)in; (void)inSz; (void)wrap; (void)out;
    (void)outSz;
    return MAX_ENCRYPTED_KEY_SZ + 1;
}

static int wb_kekri_add(CallbackAESKeyWrapUnwrap cb)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    WC_RNG    rng;
    byte      kek[32];
    byte      keyId[8];
    int       ret = -1;

    if (p == NULL) {
        return -1;
    }
    XMEMSET(kek, 0x5c, sizeof(kek));
    XMEMSET(keyId, 0x11, sizeof(keyId));

    mcdc_sr_arm(WB_KEKRI_SEED);
    if (wc_InitRng(&rng) != 0) {
        mcdc_sr_disarm();
        wc_PKCS7_Free(p);
        return -1;
    }
    if (wc_PKCS7_Init(p, NULL, INVALID_DEVID) == 0) {
        p->encryptOID = AES256CBCb;
        p->rng        = &rng;
        if (cb != NULL) {
            (void)wc_PKCS7_SetAESKeyWrapUnwrapCb(p, cb);
        }
        ret = wc_PKCS7_AddRecipient_KEKRI(p, AES256_WRAP, kek,
                (word32)sizeof(kek), keyId, (word32)sizeof(keyId), NULL, NULL,
                0, NULL, 0, 0);
    }
    wc_PKCS7_Free(p);
    wc_FreeRng(&rng);
    mcdc_sr_disarm();
    return ret;
}

static void wb_kekri_keysize_guard(void)
{
    int ret;

    WB_NOTE("wc_PKCS7_AddRecipient_KEKRI(): real AES key wrap [:11192 both"
            " operands false]");
    ret = wb_kekri_add(NULL);
    WB_CHECK(ret > 0, ":11192 both false (real wrap returns the recipient"
            " size)");

    WB_NOTE("wc_PKCS7_AddRecipient_KEKRI(): key-wrap callback reporting a"
            " zero-length wrapped key [:11192 cond 0 true]");
    ret = wb_kekri_add(wb_kw_zero);
    WB_CHECK(ret == WC_NO_ERR_TRACE(WC_KEY_SIZE_E), ":11192 cond 0 true");

    WB_NOTE("wc_PKCS7_AddRecipient_KEKRI(): key-wrap callback reporting more"
            " than the output buffer holds [:11192 cond 1 true]");
    ret = wb_kekri_add(wb_kw_toobig);
    WB_CHECK(ret == WC_NO_ERR_TRACE(WC_KEY_SIZE_E), ":11192 cond 1 true");
}
#else
static void wb_kekri_keysize_guard(void)
{
    WB_NOTE("no AES-256 key wrap; KEKRI wrapped-key size guard skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 12: two decode helpers driven straight, with the buffer ending on
 * the element they are about to read [:6468, :12422, :12432].
 *
 * Each of these is `GetASNTag(...) == 0 && tag == <expected>`; the leading
 * operand's false row needs the read index to sit exactly at the end of the
 * buffer, which no encoder-produced message provides because every element it
 * writes is followed by the next one.
 * ------------------------------------------------------------------------- */

/* v3 SignerInfo whose buffer ends right after the version, so :6441 sets
 * BUFFER_E, the SKID probe at :6445 is skipped and the IssuerAndSerial
 * fallback at :6468 reads past the end */
static byte wbSiEndsOnVersion[] = {
    0x30, 0x03, 0x02, 0x01, 0x03
};

/* v3 SignerInfo carrying a PRIMITIVE [0] SubjectKeyIdentifier, which is the
 * shape the :6468 fallback accepts */
static byte wbSiPrimSkid[] = {
    0x30, 0x0D,
      0x02, 0x01, 0x03,
      0x80, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};

static int wb_parse_signer_info(byte* in, word32 inSz)
{
    wc_PKCS7 pkcs7;
    word32   idx = 0;
    byte*    signedAttrib = NULL;
    int      signedAttribSz = 0;
    int      ret;

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));
    pkcs7.version = 3;
    ret = wc_PKCS7_ParseSignerInfo(&pkcs7, in, inSz, &idx, 0, &signedAttrib,
            &signedAttribSz);
    wc_PKCS7_SignerInfoFree(&pkcs7);
    return ret;
}

#ifdef HAVE_ECC
/* [0] OriginatorIdentifierOrKey of length zero, so the [1] OriginatorPublicKey
 * probe that follows starts at the end of the buffer */
static byte wbKariOriEmpty[] = { 0xA0, 0x00 };
/* both wrappers present, which is the accepting shape for both probes */
static byte wbKariOriBoth[]  = { 0xA0, 0x02, 0xA1, 0x00 };

static int wb_kari_originator_call(byte* in, word32 inSz)
{
    wc_PKCS7       pkcs7;
    WC_PKCS7_KARI* kari;
    word32         idx = 0;
    int            ret;

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));
    if (wc_PKCS7_Init(&pkcs7, NULL, INVALID_DEVID) != 0) {
        return -1;
    }
    kari = wc_PKCS7_KariNew(&pkcs7, WC_PKCS7_DECODE);
    if (kari == NULL) {
        wc_PKCS7_Free(&pkcs7);
        return -1;
    }
    ret = wc_PKCS7_KariGetOriginatorIdentifierOrKey(kari, in, inSz, &idx);
    (void)wc_PKCS7_KariFree(kari);
    wc_PKCS7_Free(&pkcs7);
    return ret;
}
#endif /* HAVE_ECC */

/* ---- SignerInfo signatureAlgorithm parameters [:6566] --------------------
 * `(word32)sigOID == CTC_RSASSAPSS && paramTag == (ASN_SEQUENCE |
 * ASN_CONSTRUCTED)` decides whether the AlgorithmIdentifier parameters are
 * decoded as RSASSA-PSS parameters. wolfSSL's own encoder always writes the
 * PSS parameters as a SEQUENCE, so the trailing operand's false row needs a
 * SignerInfo that names id-RSASSA-PSS and then supplies something else --
 * here a NULL, which is what an RSA PKCS#1 v1.5 signer would have written.
 *
 * The two blobs are complete up to the signature algorithm: version 1, an
 * IssuerAndSerialNumber the parser only records, and a SHA-256
 * digestAlgorithm. Parsing stops on the missing signature afterwards, which
 * is past both decisions. */
#define WB_SI_PREFIX \
    0x02, 0x01, 0x01,                                      /* version 1 */   \
    0x30, 0x04, 0x05, 0x00, 0x05, 0x00,                    /* sid */         \
    0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,  /* sha256 */      \
                0x03, 0x04, 0x02, 0x01, 0x05, 0x00
#define WB_SI_PSS_OID \
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A

/* id-RSASSA-PSS with NULL parameters */
static byte wbSiPssNullParams[] = {
    0x30, 0x27,
      WB_SI_PREFIX,
      0x30, 0x0D, WB_SI_PSS_OID, 0x05, 0x00
};

/* id-RSASSA-PSS with SEQUENCE parameters */
static byte wbSiPssSeqParams[] = {
    0x30, 0x29,
      WB_SI_PREFIX,
      0x30, 0x0F, WB_SI_PSS_OID, 0x30, 0x02, 0x05, 0x00
};

static void wb_short_buffer_probes(void)
{
    int ret;

    WB_NOTE("wc_PKCS7_ParseSignerInfo(): v3 SignerInfo ending on the version,"
            " so the IssuerAndSerial fallback tag read runs out of input"
            " [:6468 cond 0 false]");
    ret = wb_parse_signer_info(wbSiEndsOnVersion,
            (word32)sizeof(wbSiEndsOnVersion));
    WB_CHECK(ret != 0, ":6468 cond 0 false");

    WB_NOTE("wc_PKCS7_ParseSignerInfo(): v3 SignerInfo with a primitive [0]"
            " SubjectKeyIdentifier [:6468 both operands true]");
    ret = wb_parse_signer_info(wbSiPrimSkid, (word32)sizeof(wbSiPrimSkid));
    WB_CHECK(ret != 0, ":6468 both true (fails later on digestAlgorithm)");

    WB_NOTE("wc_PKCS7_ParseSignerInfo(): id-RSASSA-PSS signature algorithm"
            " with SEQUENCE parameters [:6566 both operands true]");
    ret = wb_parse_signer_info(wbSiPssSeqParams,
            (word32)sizeof(wbSiPssSeqParams));
    WB_CHECK(ret != 0, ":6566 both true (fails on the PSS parameters)");

    WB_NOTE("wc_PKCS7_ParseSignerInfo(): id-RSASSA-PSS signature algorithm"
            " with NULL parameters [:6566 cond 1 false]");
    ret = wb_parse_signer_info(wbSiPssNullParams,
            (word32)sizeof(wbSiPssNullParams));
    /* ParseSignerInfo stops after the signature algorithm; the signature
     * itself is read by the caller, so a SignerInfo that ends here parses. */
    WB_CHECK(ret == 0, ":6566 cond 1 false (NULL parameters, no PSS decode)");

#ifdef HAVE_ECC
    WB_NOTE("wc_PKCS7_KariGetOriginatorIdentifierOrKey(): empty buffer, so the"
            " OriginatorIdentifierOrKey tag read runs out of input [:12422"
            " cond 0 false]");
    ret = wb_kari_originator_call(wbKariOriEmpty, 0);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E), ":12422 cond 0 false");

    WB_NOTE("wc_PKCS7_KariGetOriginatorIdentifierOrKey(): [0] wrapper of"
            " length zero, so the OriginatorPublicKey tag read runs out of"
            " input [:12432 cond 0 false]");
    ret = wb_kari_originator_call(wbKariOriEmpty,
            (word32)sizeof(wbKariOriEmpty));
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E), ":12432 cond 0 false");

    WB_NOTE("wc_PKCS7_KariGetOriginatorIdentifierOrKey(): both wrappers"
            " present [:12422 and :12432 accepting rows]");
    ret = wb_kari_originator_call(wbKariOriBoth,
            (word32)sizeof(wbKariOriBoth));
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
            ":12422/:12432 accepted, fails later on the algorithm identifier");
#endif
}

/* ------------------------------------------------------------------------- *
 * Section 13: wc_PKCS7_DecodeEnvelopedData() content-info walk
 * [:14498, :14549, :14594].
 *
 * These three sit between the content-encryption AlgorithmIdentifier and the
 * encryptedContent, on elements the encoder always writes in full. Driving
 * them needs the message cut at an exact element boundary, or the [0]
 * encryptedContent rewritten from PRIMITIVE (what wc_PKCS7_EncodeEnvelopedData
 * writes, via SetImplicit) to CONSTRUCTED, which is what turns `explicitOctet`
 * on and enables the inner-OCTET-STRING peek at :14594.
 *
 * The offsets are found by walking the message with the same calls the decoder
 * uses, and every step is checked, so nothing is patched or cut at a guessed
 * position.
 * ------------------------------------------------------------------------- */
#if !defined(NO_RSA) && defined(USE_CERT_BUFFERS_2048) && !defined(NO_AES) && \
    defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_128)
#define WB_EV_SEED   0x6ed4a91cUL
#define WB_EV_BUF_SZ 2048
static byte wbEvBuf[WB_EV_BUF_SZ];
static word32 wbEvSz;
static word32 wbEvAlgLen;   /* index of the AlgorithmIdentifier length byte */
static word32 wbEvIvTag;    /* index of the IV OCTET STRING tag */
static word32 wbEvContTag;  /* index of the [0] encryptedContent tag */

static int wb_build_enveloped(void)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    WC_RNG    rng;
    byte      data[32];
    int       sz = 0;

    XMEMSET(data, 0x63, sizeof(data));
    wbEvSz = 0;
    if (p == NULL) {
        return -1;
    }
    mcdc_sr_arm(WB_EV_SEED);
    if (wc_InitRng(&rng) != 0) {
        mcdc_sr_disarm();
        wc_PKCS7_Free(p);
        return -1;
    }
    if (wc_PKCS7_InitWithCert(p, (byte*)client_cert_der_2048,
            (word32)sizeof_client_cert_der_2048) == 0) {
        p->content    = data;
        p->contentSz  = (word32)sizeof(data);
        p->contentOID = DATA;
        p->encryptOID = AES128CBCb;
        p->rng        = &rng;
        sz = wc_PKCS7_EncodeEnvelopedData(p, wbEvBuf, (word32)sizeof(wbEvBuf));
    }
    wc_PKCS7_Free(p);
    wc_FreeRng(&rng);
    mcdc_sr_disarm();
    if (sz <= 0) {
        return -1;
    }
    wbEvSz = (word32)sz;
    return 0;
}

/* Walks wbEvBuf the way wc_PKCS7_DecodeEnvelopedData() walks it, filling in
 * wbEvIvTag and wbEvContTag. Returns 0 on success. */
static int wb_enveloped_walk(void)
{
    word32 idx = 0, contentType, encOID;
    int    length;
    byte   tag;

    wbEvIvTag = 0;
    wbEvContTag = 0;
    if (GetSequence(wbEvBuf, &idx, &length, wbEvSz) < 0)
        return -1;
    if (wc_GetContentType(wbEvBuf, &idx, &contentType, wbEvSz) < 0)
        return -1;
    if (GetASNTag(wbEvBuf, &idx, &tag, wbEvSz) < 0 ||
            tag != (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0))
        return -1;
    if (GetLength(wbEvBuf, &idx, &length, wbEvSz) < 0)
        return -1;
    if (GetSequence(wbEvBuf, &idx, &length, wbEvSz) < 0)
        return -1;
    if (GetMyVersion(wbEvBuf, &idx, &length, wbEvSz) < 0)
        return -1;
    /* recipientInfos SET: skip its whole body */
    if (GetSet(wbEvBuf, &idx, &length, wbEvSz) < 0)
        return -1;
    idx += (word32)length;
    if (GetSequence(wbEvBuf, &idx, &length, wbEvSz) < 0)
        return -1;
    if (wc_GetContentType(wbEvBuf, &idx, &contentType, wbEvSz) < 0)
        return -1;
    /* the AlgorithmIdentifier SEQUENCE: remember its length byte before
     * GetAlgoId() consumes the element */
    if (idx + 1 >= wbEvSz ||
            wbEvBuf[idx] != (ASN_SEQUENCE | ASN_CONSTRUCTED) ||
            wbEvBuf[idx + 1] >= 0x80)
        return -1;
    wbEvAlgLen = idx + 1;
    if (GetAlgoId(wbEvBuf, &idx, &encOID, oidBlkType, wbEvSz) < 0)
        return -1;
    if (idx >= wbEvSz || wbEvBuf[idx] != ASN_OCTET_STRING)
        return -1;
    wbEvIvTag = idx;
    idx += 2 + (word32)wbEvBuf[idx + 1];      /* tag + length + IV bytes */
    if (idx >= wbEvSz || wbEvBuf[idx] != (ASN_CONTEXT_SPECIFIC | 0))
        return -1;
    wbEvContTag = idx;
    return 0;
}

static int wb_decode_enveloped(word32 msgSz)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    static byte out[WB_EV_BUF_SZ];
    int ret;

    if (p == NULL) {
        return -1;
    }
    if (wc_PKCS7_InitWithCert(p, (byte*)client_cert_der_2048,
            (word32)sizeof_client_cert_der_2048) != 0) {
        wc_PKCS7_Free(p);
        return -1;
    }
    p->privateKey   = (byte*)client_key_der_2048;
    p->privateKeySz = (word32)sizeof_client_key_der_2048;
    ret = wc_PKCS7_DecodeEnvelopedData(p, wbEvBuf, msgSz, out, sizeof(out));
    wc_PKCS7_Free(p);
    return ret;
}

/* A registered content-decryption callback replaces the built-in cipher at
 * :14759. No API-level pkcs7 test registers one, so both rows of that guard
 * have to come from here. Returning 0 without writing output is enough: the
 * guard is what is under test, and the padding check downstream rejects the
 * result either way. */
static int wb_decrypt_cb(wc_PKCS7* p, int encryptOID, byte* iv, int ivSz,
        byte* aad, word32 aadSz, byte* authTag, word32 authTagSz, byte* in,
        int inSz, byte* out, void* ctx)
{
    (void)p; (void)encryptOID; (void)iv; (void)ivSz; (void)aad; (void)aadSz;
    (void)authTag; (void)authTagSz; (void)ctx;
    if (out != NULL && in != NULL && inSz > 0) {
        XMEMCPY(out, in, (word32)inSz);
    }
    return 0;
}

static int wb_decode_enveloped_cb(word32 msgSz)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    static byte out[WB_EV_BUF_SZ];
    int ret;

    if (p == NULL) {
        return -1;
    }
    if (wc_PKCS7_InitWithCert(p, (byte*)client_cert_der_2048,
            (word32)sizeof_client_cert_der_2048) != 0) {
        wc_PKCS7_Free(p);
        return -1;
    }
    p->privateKey   = (byte*)client_key_der_2048;
    p->privateKeySz = (word32)sizeof_client_key_der_2048;
    (void)wc_PKCS7_SetDecodeEncryptedCb(p, wb_decrypt_cb);
    ret = wc_PKCS7_DecodeEnvelopedData(p, wbEvBuf, msgSz, out, sizeof(out));
    wc_PKCS7_Free(p);
    return ret;
}

static void wb_enveloped_content_walk(void)
{
    byte saveTag, saveLen;
    int  ret;

    if (wb_build_enveloped() != 0 || wb_enveloped_walk() != 0) {
        WB_NOTE("EnvelopedData encode/walk failed; content walk skipped");
        wb_fail = 1;
        return;
    }

    WB_NOTE("wc_PKCS7_DecodeEnvelopedData(): pristine AES-128-CBC/RSA bundle,"
            " the accepting row the cuts below pair against");
    ret = wb_decode_enveloped(wbEvSz);
    WB_CHECK(ret > 0, "pristine EnvelopedData decodes");

    /* Shrinking the AlgorithmIdentifier length so it covers only the OID
     * makes GetAlgoId() stop at the IV instead of swallowing it, which is
     * what lets the message end exactly on the IV element. Without this the
     * cut is caught by GetAlgoId's own bounds-checked GetSequence() one step
     * earlier and neither guard below is reached. */
    saveLen = wbEvBuf[wbEvAlgLen];
    wbEvBuf[wbEvAlgLen] = (byte)(wbEvIvTag - (wbEvAlgLen + 1));

    WB_NOTE("wc_PKCS7_DecodeEnvelopedData(): message ends on the IV element"
            " [:14498 cond 1 true]");
    (void)wb_decode_enveloped(wbEvIvTag);

    WB_NOTE("wc_PKCS7_DecodeEnvelopedData(): message ends after the IV length"
            " byte, so the IV bytes themselves are missing [:14549 cond 2"
            " true]");
    (void)wb_decode_enveloped(wbEvIvTag + 2);

    wbEvBuf[wbEvAlgLen] = saveLen;

    WB_NOTE("wc_PKCS7_DecodeEnvelopedData(): content-encryption algorithm"
            " rewritten to an OID that is not a block cipher, so the"
            " AlgorithmIdentifier parse fails [:14498 cond 0 false]");
    saveTag = wbEvBuf[wbEvIvTag - 1];
    wbEvBuf[wbEvIvTag - 1] = (byte)(saveTag ^ 0x40);
    (void)wb_decode_enveloped(wbEvSz);
    wbEvBuf[wbEvIvTag - 1] = saveTag;

    /* A CONSTRUCTED [0] wrapping ONE definite OCTET STRING is the Go
     * crypto/pkcs7 shape the peek exists for; wolfSSL's encoder never writes
     * it. Built in place: the [0] length loses the two bytes the inner header
     * takes, and the first two ciphertext bytes become that header, so
     * innerSz + (peekIdx - idx) still equals the [0] length. */
    WB_NOTE("wc_PKCS7_DecodeEnvelopedData(): CONSTRUCTED [0] wrapping a single"
            " OCTET STRING [:14594 all four operands true]");
    saveTag = wbEvBuf[wbEvContTag];
    saveLen = wbEvBuf[wbEvContTag + 1];
    {
        byte inner = (byte)(saveLen - 2);
        byte c0 = wbEvBuf[wbEvContTag + 2];
        byte c1 = wbEvBuf[wbEvContTag + 3];

        wbEvBuf[wbEvContTag] =
                (byte)(ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 0);
        wbEvBuf[wbEvContTag + 2] = ASN_OCTET_STRING;
        wbEvBuf[wbEvContTag + 3] = inner;
        (void)wb_decode_enveloped(wbEvSz);
        wbEvBuf[wbEvContTag + 2] = c0;
        wbEvBuf[wbEvContTag + 3] = c1;
    }

    WB_NOTE("wc_PKCS7_DecodeEnvelopedData(): same, cut immediately after the"
            " CONSTRUCTED [0] header [:14594 cond 0 false]");
    (void)wb_decode_enveloped(wbEvContTag + 2);

    WB_NOTE("wc_PKCS7_DecodeEnvelopedData(): same, inner OCTET STRING with a"
            " long-form length prefix and no length bytes [:14594 cond 2"
            " false]");
    wbEvBuf[wbEvContTag + 2] = ASN_OCTET_STRING;
    wbEvBuf[wbEvContTag + 3] = 0x84;
    (void)wb_decode_enveloped(wbEvContTag + 4);

    /* BER-fragmented content: an INDEFINITE-length constructed [0] holding one
     * OCTET STRING chunk and the end-of-contents pair. wolfSSL's encoder only
     * writes this shape when streaming out, which the decode-side tests never
     * exercise, so the whole fragment loop is otherwise unreached. Built in
     * place: the [0] length byte becomes 0x80, the first two ciphertext bytes
     * become the chunk header and the last two become the EOC. */
    {
        byte chunk = (byte)(saveLen - 4);
        byte c0 = wbEvBuf[wbEvContTag + 2];
        byte c1 = wbEvBuf[wbEvContTag + 3];
        word32 eoc = wbEvContTag + 2 + (word32)saveLen - 2;
        byte e0 = wbEvBuf[eoc];
        byte e1 = wbEvBuf[eoc + 1];

        wbEvBuf[wbEvContTag] =
                (byte)(ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 0);
        wbEvBuf[wbEvContTag + 1] = ASN_INDEF_LENGTH;
        wbEvBuf[wbEvContTag + 2] = ASN_OCTET_STRING;
        wbEvBuf[wbEvContTag + 3] = chunk;
        wbEvBuf[eoc]     = ASN_EOC;
        wbEvBuf[eoc + 1] = ASN_EOC;

        WB_NOTE("wc_PKCS7_DecodeEnvelopedData(): BER-fragmented content, one"
                " OCTET STRING chunk then end-of-contents [:14707/:14711"
                " accepting rows, :14790 both true]");
        (void)wb_decode_enveloped(wbEvSz);

        WB_NOTE("wc_PKCS7_DecodeEnvelopedData(): same, second EOC byte is not"
                " zero [:14790 cond 1 false]");
        wbEvBuf[eoc + 1] = 0x01;
        (void)wb_decode_enveloped(wbEvSz);
        wbEvBuf[eoc + 1] = ASN_EOC;

        /* Ending the message one byte past the chunk tag puts it inside the
         * loop's look-ahead window, so :14698 raises BUFFER_E while the tag
         * read at :14703 still succeeds -- the only way :14707 is reached
         * with ret already non-zero. */
        WB_NOTE("wc_PKCS7_DecodeEnvelopedData(): same, message ends inside the"
                " fragment loop's look-ahead window [:14707 and :14711 cond 0"
                " false]");
        (void)wb_decode_enveloped(wbEvContTag + 3);
        (void)wb_decode_enveloped(wbEvContTag + 4);

        WB_NOTE("wc_PKCS7_DecodeEnvelopedData(): same, chunk declaring a"
                " zero-length OCTET STRING [:14711 cond 1 true]");
        wbEvBuf[wbEvContTag + 3] = 0x00;
        (void)wb_decode_enveloped(wbEvSz);
        wbEvBuf[wbEvContTag + 3] = chunk;

        WB_NOTE("wc_PKCS7_DecodeEnvelopedData(): same, fragment tag that is"
                " not an OCTET STRING [:14707 cond 1 true, so cond 0 has a"
                " decision-true row to pair against]");
        wbEvBuf[wbEvContTag + 2] = 0x05;
        (void)wb_decode_enveloped(wbEvSz);
        wbEvBuf[wbEvContTag + 2] = ASN_OCTET_STRING;

        WB_NOTE("wc_PKCS7_DecodeEnvelopedData(): same, with a registered"
                " content-decryption callback [:14759 cond 1 true], and cut"
                " short so the callback guard is reached with ret already set"
                " [:14759 cond 0 false]");
        (void)wb_decode_enveloped_cb(wbEvSz);
        (void)wb_decode_enveloped_cb(wbEvContTag + 3);
        (void)wb_decode_enveloped_cb(wbEvContTag + 6);

        wbEvBuf[wbEvContTag + 2] = c0;
        wbEvBuf[wbEvContTag + 3] = c1;
        wbEvBuf[eoc]     = e0;
        wbEvBuf[eoc + 1] = e1;
    }

    wbEvBuf[wbEvContTag] = saveTag;
    wbEvBuf[wbEvContTag + 1] = saveLen;
}
#else
/* A registered content-decryption callback replaces the built-in cipher at
 * :14759. No API-level pkcs7 test registers one, so both rows of that guard
 * have to come from here. Returning 0 without writing output is enough: the
 * guard is what is under test, and the padding check downstream rejects the
 * result either way. */
static int wb_decrypt_cb(wc_PKCS7* p, int encryptOID, byte* iv, int ivSz,
        byte* aad, word32 aadSz, byte* authTag, word32 authTagSz, byte* in,
        int inSz, byte* out, void* ctx)
{
    (void)p; (void)encryptOID; (void)iv; (void)ivSz; (void)aad; (void)aadSz;
    (void)authTag; (void)authTagSz; (void)ctx;
    if (out != NULL && in != NULL && inSz > 0) {
        XMEMCPY(out, in, (word32)inSz);
    }
    return 0;
}

static int wb_decode_enveloped_cb(word32 msgSz)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    static byte out[WB_EV_BUF_SZ];
    int ret;

    if (p == NULL) {
        return -1;
    }
    if (wc_PKCS7_InitWithCert(p, (byte*)client_cert_der_2048,
            (word32)sizeof_client_cert_der_2048) != 0) {
        wc_PKCS7_Free(p);
        return -1;
    }
    p->privateKey   = (byte*)client_key_der_2048;
    p->privateKeySz = (word32)sizeof_client_key_der_2048;
    (void)wc_PKCS7_SetDecodeEncryptedCb(p, wb_decrypt_cb);
    ret = wc_PKCS7_DecodeEnvelopedData(p, wbEvBuf, msgSz, out, sizeof(out));
    wc_PKCS7_Free(p);
    return ret;
}

static void wb_enveloped_content_walk(void)
{
    WB_NOTE("no RSA/AES-128-CBC/2048-cert-buffers; EnvelopedData content walk"
            " skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 14: wc_PKCS7_AddRecipient_KTRI() raw-issuer guard [:9471 cond 1].
 *
 * `decoded->issuerRawLen == 0` needs a certificate whose issuer Name is an
 * EMPTY SEQUENCE. Every certificate in certs/ names an issuer, and the field
 * is filled in by GetCertName() from the certificate itself, so the row can
 * only come from a certificate built for it.
 *
 * Rather than hand-assemble a certificate, a real one is rewritten: the issuer
 * Name element is replaced by `30 00` and the two enclosing definite lengths
 * (Certificate and tbsCertificate) are reduced by the same amount. Both are
 * two-byte long-form lengths in a 2048-bit certificate, which is asserted
 * before anything is patched, so the rewrite cannot silently land on the
 * wrong bytes. The signature no longer matches, which is why the recipient
 * path is entered with NO_VERIFY semantics -- wc_PKCS7_AddRecipient_KTRI()
 * parses the certificate with ParseCert(..., NO_VERIFY, ...) itself.
 * ------------------------------------------------------------------------- */
#if !defined(NO_RSA) && defined(USE_CERT_BUFFERS_2048)
#define WB_EMPTY_ISSUER_SZ 2048
static byte wbEmptyIssuerCert[WB_EMPTY_ISSUER_SZ];

/* Returns the size of the rewritten certificate, or 0 if the original does not
 * have the shape this rewrite assumes. */
static word32 wb_build_empty_issuer_cert(void)
{
    DecodedCert dCert;
    word32      certSz = (word32)sizeof_client_cert_der_2048;
    word32      nameStart, hdrSz, oldSz, shrink, tailSz;
    word32      certLen, tbsLen;
    int         nameLen;

    if (certSz > (word32)sizeof(wbEmptyIssuerCert)) {
        return 0;
    }
    XMEMCPY(wbEmptyIssuerCert, client_cert_der_2048, certSz);

    InitDecodedCert(&dCert, wbEmptyIssuerCert, certSz, NULL);
    if (ParseCert(&dCert, CERT_TYPE, NO_VERIFY, NULL) != 0 ||
            dCert.issuerRaw == NULL || dCert.issuerRawLen <= 0) {
        FreeDecodedCert(&dCert);
        return 0;
    }
    nameLen   = dCert.issuerRawLen;
    nameStart = (word32)(dCert.issuerRaw - wbEmptyIssuerCert);
    FreeDecodedCert(&dCert);

    /* header in front of the Name content: 30 <len> in one of the three
     * definite forms */
    if (nameLen < 0x80)        hdrSz = 2;
    else if (nameLen < 0x100)  hdrSz = 3;
    else                       hdrSz = 4;
    if (nameStart < hdrSz ||
            wbEmptyIssuerCert[nameStart - hdrSz] !=
                (ASN_SEQUENCE | ASN_CONSTRUCTED)) {
        return 0;
    }

    /* both enclosing lengths must be the two-byte long form for the in-place
     * patch below to be a simple subtraction */
    if (wbEmptyIssuerCert[0] != (ASN_SEQUENCE | ASN_CONSTRUCTED) ||
            wbEmptyIssuerCert[1] != 0x82 ||
            wbEmptyIssuerCert[4] != (ASN_SEQUENCE | ASN_CONSTRUCTED) ||
            wbEmptyIssuerCert[5] != 0x82) {
        return 0;
    }
    certLen = ((word32)wbEmptyIssuerCert[2] << 8) | wbEmptyIssuerCert[3];
    tbsLen  = ((word32)wbEmptyIssuerCert[6] << 8) | wbEmptyIssuerCert[7];

    oldSz  = hdrSz + (word32)nameLen;
    shrink = oldSz - 2;                      /* replaced by `30 00` */
    if (shrink == 0 || shrink > certLen || shrink > tbsLen) {
        return 0;
    }

    /* write the empty Name, then close the gap */
    wbEmptyIssuerCert[nameStart - hdrSz]     = ASN_SEQUENCE | ASN_CONSTRUCTED;
    wbEmptyIssuerCert[nameStart - hdrSz + 1] = 0x00;
    tailSz = certSz - (nameStart + (word32)nameLen);
    XMEMMOVE(wbEmptyIssuerCert + nameStart - hdrSz + 2,
             wbEmptyIssuerCert + nameStart + (word32)nameLen, tailSz);

    certLen -= shrink;
    tbsLen  -= shrink;
    wbEmptyIssuerCert[2] = (byte)(certLen >> 8);
    wbEmptyIssuerCert[3] = (byte)certLen;
    wbEmptyIssuerCert[6] = (byte)(tbsLen >> 8);
    wbEmptyIssuerCert[7] = (byte)tbsLen;

    return certSz - shrink;
}

static int wb_add_ktri(const byte* cert, word32 certSz)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    WC_RNG    rng;
    int       ret = -1;

    if (p == NULL) {
        return -1;
    }
    mcdc_sr_arm(WB_EV_SEED);
    if (wc_InitRng(&rng) != 0) {
        mcdc_sr_disarm();
        wc_PKCS7_Free(p);
        return -1;
    }
    if (wc_PKCS7_Init(p, NULL, INVALID_DEVID) == 0) {
        p->contentOID = DATA;
        p->encryptOID = AES256CBCb;
        p->rng        = &rng;
        ret = wc_PKCS7_AddRecipient_KTRI(p, cert, certSz, 0);
    }
    wc_PKCS7_Free(p);
    wc_FreeRng(&rng);
    mcdc_sr_disarm();
    return ret;
}

static void wb_empty_issuer_recipient(void)
{
    word32 certSz;
    int    ret;

    WB_NOTE("wc_PKCS7_AddRecipient_KTRI(): ordinary recipient certificate"
            " [:9471 both operands false]");
    ret = wb_add_ktri((byte*)client_cert_der_2048,
            (word32)sizeof_client_cert_der_2048);
    WB_CHECK(ret > 0, ":9471 both false (recipient encoded)");

    certSz = wb_build_empty_issuer_cert();
    WB_CHECK(certSz > 0, "empty-issuer certificate rewritten");
    if (certSz == 0) {
        return;
    }
    WB_NOTE("wc_PKCS7_AddRecipient_KTRI(): recipient certificate whose issuer"
            " Name is an empty SEQUENCE [:9471 cond 1 true]");
    ret = wb_add_ktri(wbEmptyIssuerCert, certSz);
    WB_CHECK(ret < 0, ":9471 cond 1 true (recipient rejected)");
}
#else
static void wb_empty_issuer_recipient(void)
{
    WB_NOTE("no RSA or no 2048-bit cert buffers; empty-issuer recipient"
            " skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 15: RSASSA-PSS signer certificate [:5166, :5298].
 *
 * Both guards reject a sid-matched certificate that does not carry an
 * RSA-family key, and their `keyOID != RSAPSSk` operand only goes false for a
 * certificate whose SubjectPublicKeyInfo names id-RSASSA-PSS. Every signer in
 * certs/ except certs/rsapss/ names rsaEncryption, so the row needs a bundle
 * signed with the RSA-PSS credential.
 *
 * RESIDUAL: this supplies the operand's FALSE row only. Its true row needs a
 * certificate that is neither RSAk nor RSAPSSk to reach the same guard, and
 * :5155 lets only the sid-matched certificate through -- so the certificate
 * would have to carry a non-RSA key while still matching the SignerInfo sid.
 * Rewriting the embedded certificate's SubjectPublicKeyInfo algorithm was
 * considered and rejected: every key OID the oidKeyType table accepts has a
 * different encoded length from rsaEncryption, so the rewrite would have to
 * re-length six nested elements, and the resulting certificate then fails
 * ParseCert on the missing curve parameters before reaching the guard.
 * ------------------------------------------------------------------------- */
#if !defined(NO_RSA) && defined(WC_RSA_PSS) && !defined(NO_SHA256)
#define WB_PSS_BUF_SZ 4096
static byte wbPssCert[2048];
static byte wbPssKey[2048];
static byte wbPssBundle[WB_PSS_BUF_SZ];

static void wb_pss_signed_verify(void)
{
    wc_PKCS7* p;
    WC_RNG    rng;
    word32    certSz, keySz;
    byte      data[32];
    int       sz, ret;

    certSz = wb_load_file("./certs/rsapss/client-rsapss.der", wbPssCert,
            (word32)sizeof(wbPssCert));
    keySz  = wb_load_file("./certs/rsapss/client-rsapss-priv.der", wbPssKey,
            (word32)sizeof(wbPssKey));
    if (certSz == 0 || keySz == 0) {
        return;
    }
    XMEMSET(data, 0x64, sizeof(data));

    mcdc_sr_arm(WB_EV_SEED);
    if (wc_InitRng(&rng) != 0) {
        mcdc_sr_disarm();
        return;
    }
    sz = -1;
    p = wc_PKCS7_New(NULL, INVALID_DEVID);
    if (p != NULL) {
        if (wc_PKCS7_InitWithCert(p, wbPssCert, certSz) == 0) {
            p->content      = data;
            p->contentSz    = (word32)sizeof(data);
            p->contentOID   = DATA;
            p->hashOID      = SHA256h;
            p->privateKey   = wbPssKey;
            p->privateKeySz = keySz;
            p->encryptOID   = RSAPSSk;
            p->rng          = &rng;
            (void)wc_PKCS7_NoDefaultSignedAttribs(p);
            sz = wc_PKCS7_EncodeSignedData(p, wbPssBundle,
                    (word32)sizeof(wbPssBundle));
        }
        wc_PKCS7_Free(p);
    }
    wc_FreeRng(&rng);
    mcdc_sr_disarm();

    WB_CHECK(sz > 0, "RSA-PSS SignedData bundle encoded");
    if (sz <= 0) {
        return;
    }

    WB_NOTE("PKCS7_VerifySignedData(): signer certificate carrying an"
            " id-RSASSA-PSS public key [:5166 and :5298 cond 1 false]");
    p = wc_PKCS7_New(NULL, INVALID_DEVID);
    if (p != NULL) {
        if (wc_PKCS7_InitWithCert(p, NULL, 0) == 0) {
            ret = wc_PKCS7_VerifySignedData(p, wbPssBundle, (word32)sz);
            WB_CHECK(ret == 0, "RSA-PSS SignedData verifies");
        }
        wc_PKCS7_Free(p);
    }
}
#else
static void wb_pss_signed_verify(void)
{
    WB_NOTE("no RSA-PSS/SHA-256; RSA-PSS signer drive skipped");
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
    wb_stage2_shells();
    wb_stage4_cert_tails();
    wb_kekri_keysize_guard();
    wb_short_buffer_probes();
    wb_enveloped_content_walk();
    wb_empty_issuer_recipient();
    wb_pss_signed_verify();
    wb_footer_hash_matrix();
    wb_der_handoff();
    wb_key_oid_matrix();
    wb_digest_params_absent();
    wb_octet_nocontent_matrix();
    wb_encrypted_version_matrix();
    wb_auth_env_shapes();

    wolfCrypt_Cleanup();
    printf(wb_fail ? "done (with failures)\n" : "done\n");
    return 0;
}
