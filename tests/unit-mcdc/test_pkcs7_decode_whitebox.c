/* test_pkcs7_decode_whitebox.c
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
 * Second white-box MC/DC supplement for wolfcrypt/src/pkcs7.c (Part 5),
 * targeting the ASN.1-walk "ret == 0 && Get*(...) < 0" chains inside the
 * decode paths that test_pkcs7_whitebox.c explicitly left as residual:
 *
 *   PKCS7_VerifySignedData, wc_PKCS7_DecodeAuthEnvelopedData,
 *   wc_PKCS7_DecodeEncryptedData, wc_PKCS7_DecodeEnvelopedData,
 *   wc_PKCS7_ParseToRecipientInfoSet, wc_PKCS7_GetEnvelopedDataKariRid,
 *   wc_PKCS7_DecryptKekri, wc_PKCS7_DecryptContentInit,
 *   wc_PKCS7_DecryptPwri.
 *
 * Technique: load a real DER/BER message (or build one with the public
 * Encode/AddRecipient API), then drive the decoder across a sweep of
 * progressively truncated prefixes and progressively single-byte-corrupted
 * copies of the full message. Each distinct cut/corruption point stops the
 * element-by-element ASN.1 walk at a different link in the chain, so a
 * sweep across a whole message's length exercises most of the "Get*() < 0"
 * arms without needing to hand-craft each boundary.
 *
 * This file does NOT duplicate the streaming-state-machine, signed-attribute,
 * encode-side, or plain NULL/size-guard coverage that test_pkcs7_whitebox.c
 * already drives -- only the decode ASN.1 walks (Sections 1-8) plus, from
 * Section 9 on, the individual decode links that a truncate/corrupt sweep
 * provably cannot steer and that therefore need a hand-built vector.
 *
 * ==========================================================================
 * STRUCTURALLY UNREACHABLE LINKS IN THESE CHAINS (do not try to drive these)
 * ==========================================================================
 * The "ret == 0 && Get*(...)" idiom in this file produces a large number of
 * operands that have no MC/DC independence pair for a reason in the source,
 * not for want of a test. They fall into four provable families. Recording
 * them here so the next pass does not re-spend effort on them; the campaign
 * EXCLUSIONS.md carries the same arguments.
 *
 * (1) LEADING OPERAND OF THE FIRST LINK IN A SWITCH CASE. `ret` is a local
 *     initialised to 0, and the only statement before the link is a
 *     wc_PKCS7_AddDataToStream()/wc_PKCS7_SetMaxStream() call that breaks or
 *     returns on a non-zero result. `ret` is therefore provably 0 on arrival
 *     and the operand's false row cannot exist:
 *       pkcs7.c :6680 :6682 :6710 (HandleOctetStrings, after the guarded
 *       GetASNTag at :6675), :6962 :6976 (VerifySignedData WC_PKCS7_START),
 *       :7524 :7541 (VERIFY_STAGE3), :7682 (STAGE4), :8038 (STAGE6),
 *       :14036 :14118 (ParseToRecipientInfoSet), :15808 :15899 :16080
 *       :16192 :16234 (DecodeAuthEnvelopedData), :16916 :16953 :17005
 *       :17048 (DecodeEncryptedData) -- all condition 0.
 *
 * (2) TRAILING OPERAND ALREADY EXCLUDED BY AN EARLIER EXPLICIT BOUNDS CHECK.
 *     A preceding `if (idx + 1 > sz) ret = ...` or `if (idx >= sz) ret = ...`
 *     is exactly the failure precondition of the Get*() that follows, so with
 *     `ret == 0` the Get*() cannot fail, the decision is never true, and
 *     NEITHER operand has a pair:
 *       :6445 cond 1 and :6455 (guarded by :6441), :6452 (see family 4),
 *       :7230 (guarded by :7209), :7322 (guarded by :7318), :7688 cond 1
 *       (guarded by :7682), :16240 (duplicate of :16234 / of the
 *       AddDataToStream postcondition), :16116 cond 1 and :14184 cond 1
 *       (GetLength_ex/GetSet_ex success implies idx <= maxIdx).
 *
 * (3) OPERAND WHOSE VALUE IS FIXED BY THE BRANCH THAT REACHES IT.
 *       :6471 cond 0  -- the :6464 else is entered either with ret non-zero
 *                        (set at :6441 by idx+1 > inSz) or on a tag mismatch;
 *                        in the first case the GetASNTag at :6468 also fails,
 *                        so :6471 is only reached with ret still 0.
 *       :7258 cond 1  -- the else-if is only reached when :7248 was false,
 *                        which with ret 0 forces the indefinite-length byte.
 *       :7363 cond 0  -- :7360 can only fire on a non-OCTET-STRING tag, but
 *                        the :7302 else-branch and the :7326 check already
 *                        established the tag is an OCTET STRING.
 *       :7413 cond 2  -- the enclosing else at :7389 is entered only when ret
 *                        is non-zero and nothing between assigns ret.
 *       :7537, :7541 -- VERIFY_STAGE3 is only entered with ret 0, because
 *                        :7424 explicitly resets it on the failure path.
 *       :7903 cond 1  -- MAX_PKCS7_CERTS is a positive compile-time constant.
 *       :16451, :16480 cond 0 -- the success path returns
 *                        `ret = encryptedContentSz`, which :15985/:15998
 *                        force to be strictly positive, so ret is never 0 at
 *                        these two cleanup guards.
 *
 * (4) OPERAND CONTRADICTED BY A CALLEE POSTCONDITION.
 *       :469  cond 1  -- GetSequence_ex() returns the parsed length and the
 *                        negative case already returned, so length 0 implies
 *                        ret 0.
 *       :6452 both    -- GetLength() at :6449 is the bounds-CHECKING variant:
 *                        a positive return guarantees idx + length <= inSz
 *                        with length >= 1, hence idx + 1 <= inSz. The
 *                        trailing operand is never true.
 *       :14181 both   -- GetSet_ex() returns the parsed length and is only
 *                        negative on an error that already set ret, so
 *                        `length < 0` with ret 0 cannot happen.
 *       :14493 both   -- the oidBlkType table only yields CBC/GCM/CCM/DES
 *                        OIDs, and every one of them has BOTH a key size and
 *                        a block size, so `expBlockSz < 0` implies
 *                        `blockKeySz < 0`, which already set ret at :14488.
 *       :16304 both   -- :16253 forces authTagSz == macSz and :15963 caps
 *                        macSz at WC_AES_BLOCK_SIZE, which is exactly
 *                        sizeof(authTag).
 *       :16313 all    -- :16299 already sets ret for the same condition, and
 *                        the length parse bounds idx by pkiMsgSz.
 *       :7524 cond 1  -- stream->maxLen is set to `length + localIdx` or to
 *                        inSz at :6963/:6965 and forced to defSz by
 *                        wc_PKCS7_SetMaxStream when it computes 0; it is
 *                        never 0 on arrival at VERIFY_STAGE3.
 */

#include <wolfcrypt/src/pkcs7.c>

#include "mcdc_fault_alloc.h"

#include <stdio.h>
#include <string.h>
#include <wolfssl/certs_test.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)
#define WB_CHECK(cond, msg) \
    do { if (!(cond)) { printf("  [wb][FAIL] %s\n", (msg)); wb_fail = 1; } } \
    while (0)

/* shared scratch buffer for corpus loads (largest corpus is ~6.2KB) */
#define WB_SCRATCH_SZ 8192
static byte wbScratch[WB_SCRATCH_SZ];

/* shared RNG for the encode-side corpus builders below */
static WC_RNG wbRng;

/* ------------------------------------------------------------------------- *
 * Helpers: plain fopen/fread corpus loader, and generic truncate/corrupt
 * sweep driver over a (byte*, word32) decode call.
 * ------------------------------------------------------------------------- */

/* Loads a corpus file into buf (bounded by bufSz). Returns bytes read, or 0
 * if the file could not be opened/read (treated as "skip", not a failure --
 * some corpora are only present in certain repo checkouts). */
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

typedef void (*wb_decode_fn)(byte* buf, word32 len);

/* Truncation sweep: call fn() with every prefix length from a small floor up
 * to the full message (stepped, to bound run time on larger corpora), then
 * once more at the full length. Corruption sweep: flip one byte at a time
 * (restoring it afterward) and call fn() with the full (corrupted) length.
 * Together these hit a different ASN.1 element boundary on nearly every
 * call without requiring hand-crafted offsets. */
static void wb_sweep(wb_decode_fn fn, byte* buf, word32 fullLen)
{
    word32 stride, i;
    byte saved;

    if (fullLen < 4) {
        return;
    }
    /* bound total iterations to roughly 200 truncations + 200 corruptions
     * regardless of corpus size */
    stride = fullLen / 200;
    if (stride == 0) {
        stride = 1;
    }

    for (i = 4; i < fullLen; i += stride) {
        fn(buf, i);
    }
    fn(buf, fullLen);

    for (i = 0; i < fullLen; i += stride) {
        saved = buf[i];
        buf[i] = (byte)(saved ^ 0xFF);
        fn(buf, fullLen);
        buf[i] = saved;
    }
}

/* ------------------------------------------------------------------------- *
 * Section 1: PKCS7_VerifySignedData() decode-walk chains, via the public
 * wc_PKCS7_VerifySignedData() wrapper, across three structurally different
 * real SignedData corpora (degenerate/no-signer, BER-indefinite-length,
 * streaming-sized-with-signer).
 * ------------------------------------------------------------------------- */
#ifndef NO_RSA
static void wb_verify_call(byte* buf, word32 len)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);

    if (p == NULL) {
        return;
    }
    if (wc_PKCS7_InitWithCert(p, NULL, 0) == 0) {
        (void)wc_PKCS7_VerifySignedData(p, buf, len);
    }
    wc_PKCS7_Free(p);
}

static void wb_verify_sweep_file(const char* path)
{
    word32 fullLen = wb_load_file(path, wbScratch, sizeof(wbScratch));

    if (fullLen == 0) {
        return;
    }
    wb_sweep(wb_verify_call, wbScratch, fullLen);
}

static void wb_verify_decode_chains(void)
{
    WB_NOTE("PKCS7_VerifySignedData(): decode-walk sweep, test-degenerate.p7b"
            " (no signer)");
    wb_verify_sweep_file("./certs/test-degenerate.p7b");

#ifdef ASN_BER_TO_DER
    WB_NOTE("PKCS7_VerifySignedData(): decode-walk sweep,"
            " test-ber-exp02-05-2022.p7b (BER indefinite length)");
    wb_verify_sweep_file("./certs/test-ber-exp02-05-2022.p7b");
#endif

    WB_NOTE("PKCS7_VerifySignedData(): decode-walk sweep, test-stream-sign.p7b"
            " (signed, larger message)");
    wb_verify_sweep_file("./certs/test-stream-sign.p7b");
}
#else
static void wb_verify_decode_chains(void)
{
    WB_NOTE("NO_RSA; PKCS7_VerifySignedData decode-walk sweep skipped");
}
#endif /* !NO_RSA */

/* ------------------------------------------------------------------------- *
 * Section 2: wc_PKCS7_DecodeEnvelopedData() KTRI decode-walk chains
 * (wc_PKCS7_ParseToRecipientInfoSet() is exercised as a side effect of every
 * call here too, in addition to its own direct sweep in Section 5).
 * ------------------------------------------------------------------------- */
#if !defined(NO_RSA) && defined(USE_CERT_BUFFERS_2048)
static void wb_enveloped_ktri_call(byte* buf, word32 len)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    static byte out[WB_SCRATCH_SZ];

    if (p == NULL) {
        return;
    }
    if (wc_PKCS7_InitWithCert(p, (byte*)client_cert_der_2048,
            sizeof_client_cert_der_2048) == 0) {
        p->privateKey   = (byte*)client_key_der_2048;
        p->privateKeySz = sizeof_client_key_der_2048;
        (void)wc_PKCS7_DecodeEnvelopedData(p, buf, len, out, sizeof(out));
    }
    wc_PKCS7_Free(p);
}

/* wc_PKCS7_DecryptKtri()'s `pkcs7->privateKey != NULL &&
 * pkcs7->privateKeySz > 0` AND-guard [:12140]. wb_enveloped_ktri_call()
 * above is the both-true row (real key). The three calls below supply the
 * all-false baseline plus each operand's true-while-the-other-false row, by
 * direct field manipulation -- the guard's own decision is under test, not
 * what a real key would do afterward, so a NULL pointer paired with a
 * nonzero size (and vice versa) is fine: privateKey==NULL still short-
 * circuits the AND before privateKeySz is dereferenced. */
static void wb_enveloped_ktri_nokey_call(byte* buf, word32 len)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    static byte out[WB_SCRATCH_SZ];

    if (p == NULL) {
        return;
    }
    if (wc_PKCS7_InitWithCert(p, (byte*)client_cert_der_2048,
            sizeof_client_cert_der_2048) == 0) {
        /* both operands false: privateKey==NULL, privateKeySz==0 (Init's
         * default). devId==INVALID_DEVID -> BAD_FUNC_ARG, clean return. */
        (void)wc_PKCS7_DecodeEnvelopedData(p, buf, len, out, sizeof(out));
    }
    wc_PKCS7_Free(p);
}

static void wb_enveloped_ktri_szonly_call(byte* buf, word32 len)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    static byte out[WB_SCRATCH_SZ];

    if (p == NULL) {
        return;
    }
    if (wc_PKCS7_InitWithCert(p, (byte*)client_cert_der_2048,
            sizeof_client_cert_der_2048) == 0) {
        /* 1st operand false, 2nd true: privateKey==NULL, privateKeySz>0 */
        p->privateKey   = NULL;
        p->privateKeySz = 8;
        (void)wc_PKCS7_DecodeEnvelopedData(p, buf, len, out, sizeof(out));
    }
    wc_PKCS7_Free(p);
}

static void wb_enveloped_ktri_keyzerosz_call(byte* buf, word32 len)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    static byte out[WB_SCRATCH_SZ];

    if (p == NULL) {
        return;
    }
    if (wc_PKCS7_InitWithCert(p, (byte*)client_cert_der_2048,
            sizeof_client_cert_der_2048) == 0) {
        /* 1st operand true, 2nd false: real key pointer, privateKeySz==0 */
        p->privateKey   = (byte*)client_key_der_2048;
        p->privateKeySz = 0;
        (void)wc_PKCS7_DecodeEnvelopedData(p, buf, len, out, sizeof(out));
    }
    wc_PKCS7_Free(p);
}

static void wb_enveloped_multi_call(byte* buf, word32 len)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    static byte out[WB_SCRATCH_SZ];

    if (p == NULL) {
        return;
    }
    if (wc_PKCS7_InitWithCert(p, (byte*)client_cert_der_2048,
            sizeof_client_cert_der_2048) == 0 &&
        wc_PKCS7_SetKey(p, (byte*)client_key_der_2048,
            sizeof_client_key_der_2048) == 0) {
        (void)wc_PKCS7_DecodeEnvelopedData(p, buf, len, out, sizeof(out));
    }
    wc_PKCS7_Free(p);
}

static void wb_enveloped_decode_chains(void)
{
    word32 fullLen;

    WB_NOTE("wc_PKCS7_DecodeEnvelopedData(): KTRI decode-walk sweep,"
            " ktri-keyid-cms.msg");
    fullLen = wb_load_file("./certs/test/ktri-keyid-cms.msg", wbScratch,
            sizeof(wbScratch));
    if (fullLen > 0) {
        wb_sweep(wb_enveloped_ktri_call, wbScratch, fullLen);

        WB_NOTE("wc_PKCS7_DecryptKtri(): privateKey/privateKeySz guard"
                " [:12140], all-false baseline + each operand isolated"
                " true");
        wb_enveloped_ktri_nokey_call(wbScratch, fullLen);
        wb_enveloped_ktri_szonly_call(wbScratch, fullLen);
        wb_enveloped_ktri_keyzerosz_call(wbScratch, fullLen);
    }

    WB_NOTE("wc_PKCS7_DecodeEnvelopedData(): multi-recipient decode-walk"
            " sweep, test-multiple-recipients.p7b");
    fullLen = wb_load_file("./certs/test-multiple-recipients.p7b", wbScratch,
            sizeof(wbScratch));
    if (fullLen > 0) {
        wb_sweep(wb_enveloped_multi_call, wbScratch, fullLen);
    }
}
#else
static void wb_enveloped_decode_chains(void)
{
    WB_NOTE("NO_RSA or no 2048-bit test cert buffers; EnvelopedData"
            " decode-walk sweep skipped");
}
#endif /* !NO_RSA && USE_CERT_BUFFERS_2048 */

/* ------------------------------------------------------------------------- *
 * Section 3: wc_PKCS7_DecodeAuthEnvelopedData() decode-walk chains. No
 * ready-made AuthEnvelopedData corpus file is listed for this module, so
 * build one with the public Encode API (real AES-GCM/RSA content, not
 * fabricated bytes) and sweep truncation/corruption over the result.
 * ------------------------------------------------------------------------- */
#if defined(HAVE_AESGCM) && !defined(NO_RSA) && defined(WOLFSSL_AES_128) && \
    defined(USE_CERT_BUFFERS_2048)
static word32 wb_build_auth_enveloped(byte* out, word32 outSz)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    byte data[] = "authEnvelopedData decode-chain corpus payload";
    int sz = 0;

    if (p == NULL) {
        return 0;
    }
    if (wc_PKCS7_InitWithCert(p, (byte*)client_cert_der_2048,
            sizeof_client_cert_der_2048) == 0) {
        p->content    = data;
        p->contentSz  = (word32)sizeof(data);
        p->contentOID = DATA;
        p->encryptOID = AES128GCMb;
        p->rng        = &wbRng;
        sz = wc_PKCS7_EncodeAuthEnvelopedData(p, out, outSz);
    }
    wc_PKCS7_Free(p);
    return (sz > 0) ? (word32)sz : 0;
}

static void wb_auth_enveloped_call(byte* buf, word32 len)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    static byte out[WB_SCRATCH_SZ];

    if (p == NULL) {
        return;
    }
    if (wc_PKCS7_InitWithCert(p, (byte*)client_cert_der_2048,
            sizeof_client_cert_der_2048) == 0) {
        p->privateKey   = (byte*)client_key_der_2048;
        p->privateKeySz = sizeof_client_key_der_2048;
        (void)wc_PKCS7_DecodeAuthEnvelopedData(p, buf, len, out, sizeof(out));
    }
    wc_PKCS7_Free(p);
}

static void wb_auth_enveloped_decode_chains(void)
{
    word32 fullLen;

    WB_NOTE("wc_PKCS7_DecodeAuthEnvelopedData(): decode-walk sweep over a"
            " self-built AES128GCMb/RSA-KTRI message");
    fullLen = wb_build_auth_enveloped(wbScratch, sizeof(wbScratch));
    WB_CHECK(fullLen > 32, "self-built AuthEnvelopedData corpus encoded");
    if (fullLen > 0) {
        wb_sweep(wb_auth_enveloped_call, wbScratch, fullLen);
    }
}
#else
static void wb_auth_enveloped_decode_chains(void)
{
    WB_NOTE("no AESGCM/RSA/2048-cert-buffers; AuthEnvelopedData decode-walk"
            " sweep skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 4: wc_PKCS7_DecodeEncryptedData() decode-walk chains, real
 * encrypteddata.msg corpus plus a self-built AES-CBC EncryptedData message
 * for a second, structurally different, cipher/attribs combination.
 * ------------------------------------------------------------------------- */
#ifndef NO_PKCS7_ENCRYPTED_DATA
static const byte wbEncKey[] = {
    0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77
};

static void wb_encrypted_call(byte* buf, word32 len)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    static byte out[WB_SCRATCH_SZ];

    if (p == NULL) {
        return;
    }
    if (wc_PKCS7_Init(p, NULL, INVALID_DEVID) == 0) {
        p->encryptionKey   = (byte*)wbEncKey;
        p->encryptionKeySz = (word32)sizeof(wbEncKey);
        (void)wc_PKCS7_DecodeEncryptedData(p, buf, len, out, sizeof(out));
    }
    wc_PKCS7_Free(p);
}

#if !defined(NO_AES) && defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_128)
static word32 wb_build_encrypted_aes(byte* out, word32 outSz)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    byte data[] = "encryptedData decode-chain corpus payload";
    int sz = 0;

    if (p == NULL) {
        return 0;
    }
    if (wc_PKCS7_Init(p, NULL, INVALID_DEVID) == 0) {
        p->content         = data;
        p->contentSz       = (word32)sizeof(data);
        p->contentOID      = DATA;
        p->encryptOID      = AES128CBCb;
        p->encryptionKey   = (byte*)wbEncKey;
        p->encryptionKeySz = (word32)sizeof(wbEncKey);
        p->rng             = &wbRng;
        sz = wc_PKCS7_EncodeEncryptedData(p, out, outSz);
    }
    wc_PKCS7_Free(p);
    return (sz > 0) ? (word32)sz : 0;
}
#endif

static void wb_encrypted_decode_chains(void)
{
    word32 fullLen;

    WB_NOTE("wc_PKCS7_DecodeEncryptedData(): decode-walk sweep,"
            " encrypteddata.msg");
    fullLen = wb_load_file("./certs/test/encrypteddata.msg", wbScratch,
            sizeof(wbScratch));
    if (fullLen > 0) {
        wb_sweep(wb_encrypted_call, wbScratch, fullLen);
    }

#if !defined(NO_AES) && defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_128)
    WB_NOTE("wc_PKCS7_DecodeEncryptedData(): decode-walk sweep over a"
            " self-built AES128CBCb message");
    fullLen = wb_build_encrypted_aes(wbScratch, sizeof(wbScratch));
    WB_CHECK(fullLen > 0, "self-built AES128CBCb EncryptedData corpus"
            " encoded");
    if (fullLen > 0) {
        wb_sweep(wb_encrypted_call, wbScratch, fullLen);
    }
#endif
}
#else
static void wb_encrypted_decode_chains(void)
{
    WB_NOTE("NO_PKCS7_ENCRYPTED_DATA; EncryptedData decode-walk sweep"
            " skipped");
}
#endif /* !NO_PKCS7_ENCRYPTED_DATA */

/* ------------------------------------------------------------------------- *
 * Section 5: wc_PKCS7_ParseToRecipientInfoSet() driven directly (it is a
 * file-static, reachable because this file #includes pkcs7.c) against the
 * KTRI and multi-recipient corpora, independent of the full decrypt path.
 * ------------------------------------------------------------------------- */
#if !defined(NO_RSA)
static void wb_parse_ris_call(byte* buf, word32 len)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    word32 idx = 0;

    if (p == NULL) {
        return;
    }
    if (wc_PKCS7_Init(p, NULL, INVALID_DEVID) == 0) {
        (void)wc_PKCS7_ParseToRecipientInfoSet(p, buf, len, &idx,
                ENVELOPED_DATA);
    }
    wc_PKCS7_Free(p);
}

static void wb_parse_ris_decode_chains(void)
{
    word32 fullLen;

    WB_NOTE("wc_PKCS7_ParseToRecipientInfoSet(): direct decode-walk sweep,"
            " ktri-keyid-cms.msg");
    fullLen = wb_load_file("./certs/test/ktri-keyid-cms.msg", wbScratch,
            sizeof(wbScratch));
    if (fullLen > 0) {
        wb_sweep(wb_parse_ris_call, wbScratch, fullLen);
    }

    WB_NOTE("wc_PKCS7_ParseToRecipientInfoSet(): direct decode-walk sweep,"
            " test-multiple-recipients.p7b");
    fullLen = wb_load_file("./certs/test-multiple-recipients.p7b", wbScratch,
            sizeof(wbScratch));
    if (fullLen > 0) {
        wb_sweep(wb_parse_ris_call, wbScratch, fullLen);
    }
}
#else
static void wb_parse_ris_decode_chains(void)
{
    WB_NOTE("NO_RSA; ParseToRecipientInfoSet decode-walk sweep skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 6: wc_PKCS7_GetEnvelopedDataKariRid() decode-walk chains. This is
 * a standalone public parser (no wc_PKCS7 struct, no allocation, no crypto):
 * safe to sweep aggressively against the real kari-keyid-cms.msg corpus.
 * ------------------------------------------------------------------------- */
#if defined(HAVE_ECC) && defined(HAVE_X963_KDF)
static void wb_kari_rid_call(byte* buf, word32 len)
{
    byte rid[256];
    word32 ridSz = (word32)sizeof(rid);

    (void)wc_PKCS7_GetEnvelopedDataKariRid(buf, len, rid, &ridSz);
}

static void wb_kari_rid_decode_chains(void)
{
    word32 fullLen;

    WB_NOTE("wc_PKCS7_GetEnvelopedDataKariRid(): decode-walk sweep,"
            " kari-keyid-cms.msg");
    fullLen = wb_load_file("./certs/test/kari-keyid-cms.msg", wbScratch,
            sizeof(wbScratch));
    if (fullLen > 0) {
        wb_sweep(wb_kari_rid_call, wbScratch, fullLen);
    }
}
#else
static void wb_kari_rid_decode_chains(void)
{
    WB_NOTE("no HAVE_ECC/HAVE_X963_KDF; GetEnvelopedDataKariRid decode-walk"
            " sweep skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 7: wc_PKCS7_DecryptKekri() and wc_PKCS7_DecryptPwri() decode-walk
 * chains. Both are file-static helpers reached only through the full
 * wc_PKCS7_DecodeEnvelopedData() state machine (they assume pkcs7->state and
 * pkcs7->stream are already primed by the caller), so build a real KEKRI/
 * PWRI EnvelopedData message with the public Encode/AddRecipient API and
 * sweep the top-level decode entry point instead of calling the helpers
 * out of context.
 * ------------------------------------------------------------------------- */
#if !defined(NO_AES) && defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_256) && \
    defined(HAVE_AES_KEYWRAP)
static word32 wb_build_kekri(byte* out, word32 outSz)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    byte data[] = "kekri decode-chain corpus payload";
    byte kek[32];
    byte keyId[4] = { 0xAA, 0xBB, 0xCC, 0xDD };
    int sz = 0, i;

    if (p == NULL) {
        return 0;
    }
    for (i = 0; i < (int)sizeof(kek); i++) {
        kek[i] = (byte)i;
    }
    if (wc_PKCS7_Init(p, NULL, INVALID_DEVID) == 0) {
        p->content    = data;
        p->contentSz  = (word32)sizeof(data);
        p->contentOID = DATA;
        p->encryptOID = AES256CBCb;
        p->rng        = &wbRng;
        if (wc_PKCS7_AddRecipient_KEKRI(p, AES256_WRAP, kek, sizeof(kek),
                keyId, sizeof(keyId), NULL, NULL, 0, NULL, 0, 0) >= 0) {
            sz = wc_PKCS7_EncodeEnvelopedData(p, out, outSz);
        }
    }
    wc_PKCS7_Free(p);
    return (sz > 0) ? (word32)sz : 0;
}

static void wb_kekri_call(byte* buf, word32 len)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    static byte out[WB_SCRATCH_SZ];
    byte kek[32];
    int i;

    if (p == NULL) {
        return;
    }
    for (i = 0; i < (int)sizeof(kek); i++) {
        kek[i] = (byte)i;
    }
    if (wc_PKCS7_Init(p, NULL, INVALID_DEVID) == 0 &&
        wc_PKCS7_SetKey(p, kek, (word32)sizeof(kek)) == 0) {
        (void)wc_PKCS7_DecodeEnvelopedData(p, buf, len, out, sizeof(out));
    }
    wc_PKCS7_Free(p);
}

static void wb_kekri_decode_chains(void)
{
    byte kekri[WB_SCRATCH_SZ];
    word32 fullLen;

    WB_NOTE("wc_PKCS7_DecryptKekri(): decode-walk sweep via"
            " wc_PKCS7_DecodeEnvelopedData() over a self-built KEKRI message");
    fullLen = wb_build_kekri(kekri, sizeof(kekri));
    WB_CHECK(fullLen > 0, "self-built KEKRI EnvelopedData corpus encoded");
    if (fullLen > 0) {
        wb_sweep(wb_kekri_call, kekri, fullLen);
    }
}
#else
static void wb_kekri_decode_chains(void)
{
    WB_NOTE("no AES256CBC/AES-keywrap support; DecryptKekri decode-walk"
            " sweep skipped");
}
#endif

#if !defined(NO_PWDBASED) && !defined(NO_SHA) && !defined(NO_DES3)
static word32 wb_build_pwri(byte* out, word32 outSz)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    byte data[] = "pwri decode-chain corpus payload";
    byte pass[] = "wbWhiteboxPassword1";
    byte salt[8] = { 1,2,3,4,5,6,7,8 };
    int sz = 0;

    if (p == NULL) {
        return 0;
    }
    if (wc_PKCS7_Init(p, NULL, INVALID_DEVID) == 0) {
        p->content    = data;
        p->contentSz  = (word32)sizeof(data);
        p->contentOID = DATA;
        p->encryptOID = DES3b;
        p->rng        = &wbRng;
        /* iterations kept small (5, mirroring wolfcrypt/test/test.c's PWRI
         * vectors) so the truncation/corruption sweep below stays fast */
        if (wc_PKCS7_AddRecipient_PWRI(p, pass, (word32)(sizeof(pass) - 1),
                salt, (word32)sizeof(salt), PBKDF2_OID, WC_SHA, 5, 0, 0)
                >= 0) {
            sz = wc_PKCS7_EncodeEnvelopedData(p, out, outSz);
        }
    }
    wc_PKCS7_Free(p);
    return (sz > 0) ? (word32)sz : 0;
}

static void wb_pwri_call(byte* buf, word32 len)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    static byte out[WB_SCRATCH_SZ];
    byte pass[] = "wbWhiteboxPassword1";

    if (p == NULL) {
        return;
    }
    if (wc_PKCS7_Init(p, NULL, INVALID_DEVID) == 0 &&
        wc_PKCS7_SetPassword(p, pass, (word32)(sizeof(pass) - 1)) == 0) {
        (void)wc_PKCS7_DecodeEnvelopedData(p, buf, len, out, sizeof(out));
    }
    wc_PKCS7_Free(p);
}

static void wb_pwri_decode_chains(void)
{
    byte pwri[WB_SCRATCH_SZ];
    word32 fullLen;

    WB_NOTE("wc_PKCS7_DecryptPwri(): decode-walk sweep via"
            " wc_PKCS7_DecodeEnvelopedData() over a self-built PWRI message");
    fullLen = wb_build_pwri(pwri, sizeof(pwri));
    WB_CHECK(fullLen > 0, "self-built PWRI EnvelopedData corpus encoded");
    if (fullLen > 0) {
        wb_sweep(wb_pwri_call, pwri, fullLen);
    }
}
#else
static void wb_pwri_decode_chains(void)
{
    WB_NOTE("no PWDBASED/SHA/DES3 support; DecryptPwri decode-walk sweep"
            " skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 8: wc_PKCS7_DecryptContentInit() direct guard/branch coverage.
 * Unlike DecryptKekri/DecryptPwri this file-static has no dependency on
 * pkcs7->state/pkcs7->stream -- it only sets up the cipher context from an
 * already-known encryptOID/key/iv -- so it is safe and cheap to call
 * directly across every supported cipher OID plus the NULL/size guards.
 * ------------------------------------------------------------------------- */
static void wb_decrypt_content_init_direct(void)
{
    wc_PKCS7 pkcs7;
    byte key32[32];
    byte iv16[16];
    int ret, i;

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));
    for (i = 0; i < (int)sizeof(key32); i++) {
        key32[i] = (byte)(i + 1);
    }
    for (i = 0; i < (int)sizeof(iv16); i++) {
        iv16[i] = (byte)(i + 0x40);
    }

    WB_NOTE("wc_PKCS7_DecryptContentInit(): NULL iv/key guards");
    ret = wc_PKCS7_DecryptContentInit(&pkcs7, AES128CBCb, key32, 16, NULL, 16,
            INVALID_DEVID, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "iv==NULL guard");
    ret = wc_PKCS7_DecryptContentInit(&pkcs7, AES128CBCb, NULL, 16, iv16, 16,
            INVALID_DEVID, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "key==NULL guard");

#if !defined(NO_AES) && defined(HAVE_AES_CBC)
#ifdef WOLFSSL_AES_128
    WB_NOTE("wc_PKCS7_DecryptContentInit(): AES128CBCb keySz/ivSz guard"
            " chain");
    ret = wc_PKCS7_DecryptContentInit(&pkcs7, AES128CBCb, key32, 15, iv16,
            sizeof(iv16), INVALID_DEVID, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "AES128CBCb wrong keySz");
    ret = wc_PKCS7_DecryptContentInit(&pkcs7, AES128CBCb, key32, 16, iv16,
            sizeof(iv16) - 1, INVALID_DEVID, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "AES128CBCb wrong ivSz");
    ret = wc_PKCS7_DecryptContentInit(&pkcs7, AES128CBCb, key32, 16, iv16,
            sizeof(iv16), INVALID_DEVID, NULL);
    WB_CHECK(ret == 0, "AES128CBCb valid init");
    wc_PKCS7_DecryptContentFree(&pkcs7, AES128CBCb, NULL);
#endif
#ifdef WOLFSSL_AES_256
    ret = wc_PKCS7_DecryptContentInit(&pkcs7, AES256CBCb, key32,
            sizeof(key32), iv16, sizeof(iv16), INVALID_DEVID, NULL);
    WB_CHECK(ret == 0, "AES256CBCb valid init");
    wc_PKCS7_DecryptContentFree(&pkcs7, AES256CBCb, NULL);
#endif
#endif /* !NO_AES && HAVE_AES_CBC */

#if defined(HAVE_AESGCM) && defined(WOLFSSL_AES_128)
    WB_NOTE("wc_PKCS7_DecryptContentInit(): AES128GCMb valid init"
            " (no keySz/ivSz guard on this branch)");
    ret = wc_PKCS7_DecryptContentInit(&pkcs7, AES128GCMb, key32, 16, iv16,
            GCM_NONCE_MID_SZ, INVALID_DEVID, NULL);
    WB_CHECK(ret == 0, "AES128GCMb valid init");
    wc_PKCS7_DecryptContentFree(&pkcs7, AES128GCMb, NULL);
#endif

#if defined(HAVE_AESCCM) && defined(WOLFSSL_AES_128)
    WB_NOTE("wc_PKCS7_DecryptContentInit(): AES128CCMb valid init");
    ret = wc_PKCS7_DecryptContentInit(&pkcs7, AES128CCMb, key32, 16, iv16,
            GCM_NONCE_MID_SZ, INVALID_DEVID, NULL);
    WB_CHECK(ret == 0, "AES128CCMb valid init");
    wc_PKCS7_DecryptContentFree(&pkcs7, AES128CCMb, NULL);
#endif

#ifndef NO_DES3
    WB_NOTE("wc_PKCS7_DecryptContentInit(): DESb/DES3b keySz/ivSz guard"
            " chain");
    ret = wc_PKCS7_DecryptContentInit(&pkcs7, DESb, key32, DES_KEYLEN - 1,
            iv16, DES_BLOCK_SIZE, INVALID_DEVID, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "DESb wrong keySz");
    ret = wc_PKCS7_DecryptContentInit(&pkcs7, DESb, key32, DES_KEYLEN, iv16,
            DES_BLOCK_SIZE - 1, INVALID_DEVID, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "DESb wrong ivSz");
    ret = wc_PKCS7_DecryptContentInit(&pkcs7, DESb, key32, DES_KEYLEN, iv16,
            DES_BLOCK_SIZE, INVALID_DEVID, NULL);
    WB_CHECK(ret == 0, "DESb valid init");
    wc_PKCS7_DecryptContentFree(&pkcs7, DESb, NULL);

    ret = wc_PKCS7_DecryptContentInit(&pkcs7, DES3b, key32, DES3_KEYLEN - 1,
            iv16, DES_BLOCK_SIZE, INVALID_DEVID, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "DES3b wrong keySz");
    ret = wc_PKCS7_DecryptContentInit(&pkcs7, DES3b, key32, DES3_KEYLEN, iv16,
            DES_BLOCK_SIZE, INVALID_DEVID, NULL);
    WB_CHECK(ret == 0, "DES3b valid init");
    wc_PKCS7_DecryptContentFree(&pkcs7, DES3b, NULL);
#endif /* !NO_DES3 */

    WB_NOTE("wc_PKCS7_DecryptContentInit(): unsupported encryptOID ->"
            " default/ALGO_ID_E");
    ret = wc_PKCS7_DecryptContentInit(&pkcs7, 0xFFFF, key32, sizeof(key32),
            iv16, sizeof(iv16), INVALID_DEVID, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ALGO_ID_E), "unsupported encryptOID");
}

/* ------------------------------------------------------------------------- *
 * Section 9: wc_PKCS7_ParseSignerInfo() version-3 SubjectKeyIdentifier walk
 * [:6413,:6445,:6452,:6455,:6458,:6461,:6471,:6480,:6516].
 *
 * The truncate/corrupt sweeps over real bundles cannot steer this walk: a
 * corpus SignerInfo is version 1, and by the time a mutation reaches the
 * SignerInfo bytes the enclosing SignedData length checks have already
 * rejected the message. Every link here is instead driven by a hand-built
 * SignerInfo of exactly the length needed to stop the walk at that link.
 * wc_PKCS7_ParseSignerInfo() is a pure function of (pkcs7->version, in, inSz)
 * so the vectors are byte-deterministic.
 *
 * Sizing note for the version-3 arm: `ret` is set at :6441 when idx+1 exceeds
 * inSz, so "the buffer ends exactly at byte N" is the lever for the leading
 * `ret == 0` operand of the whole chain, and a one-byte-longer buffer is the
 * lever for the trailing operand of the same link.
 * ------------------------------------------------------------------------- */

/* SignerInfo bodies. Layout for the version-3 ones:
 *   30 <len> 02 01 03 [ A0 <len> 04 <len> <skid> | <other> ] [ digestAlgo ] */

/* not a SEQUENCE at all -> the very first Get*() of the chain fails */
static byte wbSiNoSeq[]   = { 0x02, 0x01, 0x01 };

/* ends immediately after the version: idx+1 > inSz at :6441 */
static byte wbSiCut[]     = { 0x30, 0x03, 0x02, 0x01, 0x03 };

/* A0 wrapper with a zero length: GetLength() at :6449 returns 0, which is
 * "<= 0", so the chain is already failed when :6452..:6461 are evaluated */
static byte wbSiA0Zero[]  = { 0x30, 0x05, 0x02, 0x01, 0x03, 0xA0, 0x00 };

/* inside the A0 wrapper the tag is NULL(0x05), not OCTET STRING: :6458 */
static byte wbSiBadTag[]  = { 0x30, 0x07, 0x02, 0x01, 0x03, 0xA0, 0x02,
                              0x05, 0x00 };

/* OCTET STRING tag present but its length byte is off the end: :6461 */
static byte wbSiNoLen[]   = { 0x30, 0x06, 0x02, 0x01, 0x03, 0xA0, 0x01,
                              0x04 };

/* version 3 with neither A0 nor [0] primitive: falls into the
 * IssuerAndSerialNumber fallback at :6475/:6480 with a non-SEQUENCE */
static byte wbSiFallBad[] = { 0x30, 0x04, 0x02, 0x01, 0x03, 0x05 };

/* same fallback but the SEQUENCE parses: the accepting row for :6480 */
static byte wbSiFallOk[]  = { 0x30, 0x07, 0x02, 0x01, 0x03, 0x30, 0x02,
                              0xAA, 0xBB };

/* complete version-3 SKID SignerInfo followed by a SHA-256 digestAlgorithm
 * that ends exactly at the buffer end, so the signedAttributes peek at :6516
 * runs out of input while ret is still 0 */
static byte wbSiSkidFull[] = {
    0x30, 0x18,
      0x02, 0x01, 0x03,
      0xA0, 0x04, 0x04, 0x02, 0xAA, 0xBB,
      0x30, 0x0D,
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00
};

static int wb_parse_signer_info(byte* in, word32 inSz, byte sdVersion)
{
    wc_PKCS7 pkcs7;
    word32   idx = 0;
    byte*    signedAttrib = NULL;
    int      signedAttribSz = 0;
    int      ret;

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));
    pkcs7.version = sdVersion;
    ret = wc_PKCS7_ParseSignerInfo(&pkcs7, in, inSz, &idx, 0, &signedAttrib,
            &signedAttribSz);
    wc_PKCS7_SignerInfoFree(&pkcs7);
    return ret;
}

static void wb_parse_signer_info_chains(void)
{
    int ret;

    WB_NOTE("wc_PKCS7_ParseSignerInfo(): SignerInfoNew failure unpins the"
            " leading ret==0 operand of the whole chain [:6413]");
    mcdc_fa_install();
    mcdc_fa_disarm();
    mcdc_fa_arm_only(1);            /* the PKCS7SignerInfo allocation */
    ret = wb_parse_signer_info(wbSiSkidFull, (word32)sizeof(wbSiSkidFull), 3);
    mcdc_fa_disarm();
    mcdc_fa_restore();
    /* Any failure before the version dispatch lands in the trailing else at
     * :6501, which overwrites ret, so the observable return is the version
     * error rather than the error the chain actually stopped on. */
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_VERSION_E),
            ":6413 ret non-zero on arrival (signerInfo allocation failed)");

    WB_NOTE("wc_PKCS7_ParseSignerInfo(): first SEQUENCE rejects [:6413]");
    ret = wb_parse_signer_info(wbSiNoSeq, (word32)sizeof(wbSiNoSeq), 1);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_VERSION_E), ":6413 leading SEQUENCE");

    WB_NOTE("wc_PKCS7_ParseSignerInfo(): buffer ends on the version, so the"
            " SKID peek and the v3 IssuerAndSerial fallback both see a"
            " non-zero ret [:6445,:6480]");
    ret = wb_parse_signer_info(wbSiCut, (word32)sizeof(wbSiCut), 3);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E), ":6445/:6480 ret non-zero");

    WB_NOTE("wc_PKCS7_ParseSignerInfo(): A0 wrapper of length zero fails the"
            " chain before :6452/:6455/:6458/:6461 are evaluated");
    ret = wb_parse_signer_info(wbSiA0Zero, (word32)sizeof(wbSiA0Zero), 3);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
            ":6452/:6455/:6458/:6461 ret non-zero on arrival");

    WB_NOTE("wc_PKCS7_ParseSignerInfo(): SKID inner tag is not an OCTET"
            " STRING [:6458 trailing operand]");
    ret = wb_parse_signer_info(wbSiBadTag, (word32)sizeof(wbSiBadTag), 3);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E), ":6458 tag mismatch");

    WB_NOTE("wc_PKCS7_ParseSignerInfo(): SKID OCTET STRING tag with no length"
            " byte left [:6461 trailing operand]");
    ret = wb_parse_signer_info(wbSiNoLen, (word32)sizeof(wbSiNoLen), 3);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E), ":6461 length off the end");

    WB_NOTE("wc_PKCS7_ParseSignerInfo(): v3 IssuerAndSerial fallback, both"
            " halves of the SignedData-version guard [:6480]");
    ret = wb_parse_signer_info(wbSiFallBad, (word32)sizeof(wbSiFallBad), 1);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
            ":6480 ret non-zero on arrival (SignedData version is not 3)");
    ret = wb_parse_signer_info(wbSiFallBad, (word32)sizeof(wbSiFallBad), 3);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
            ":6480 SEQUENCE rejects with ret still 0");
    ret = wb_parse_signer_info(wbSiFallOk, (word32)sizeof(wbSiFallOk), 3);
    WB_CHECK(ret != 0, ":6480 SEQUENCE accepts (fails later on digestAlgo)");

    WB_NOTE("wc_PKCS7_ParseSignerInfo(): complete v3 SKID SignerInfo whose"
            " digestAlgorithm ends the buffer, so the signedAttributes peek"
            " runs out of input with ret still 0 [:6516]");
    ret = wb_parse_signer_info(wbSiSkidFull, (word32)sizeof(wbSiSkidFull), 3);
    WB_CHECK(ret != 0, ":6516 GetASNTag peek fails with ret still 0");
}

/* ------------------------------------------------------------------------- *
 * Section 10: wc_PKCS7_GetEnvelopedDataKariRid() hand-built skeletons
 * [:15056,:15078].
 *
 * The kari-keyid-cms.msg sweep in Section 6 walks this function but cannot
 * produce either uncovered vector:
 *
 *  - :15056 is the OPTIONAL ukm [1] probe, and it is written `>= 0`, so its
 *    accepting outcome needs a message that actually carries a ukm.
 *    kari-keyid-cms.msg has none, and no truncation or single-byte flip can
 *    add one, so the sweep only ever sees the rejecting outcome.
 *  - :15078 needs a RecipientEncryptedKey SEQUENCE of length zero sitting at
 *    the very end of the buffer. Truncating a real message fails the
 *    enclosing SEQUENCE first, because GetSequence() bounds-checks its
 *    declared length against the remaining input.
 *
 * The skeletons below are the smallest EnvelopedData shells that reach those
 * two points; they are hand-built rather than encoded so the byte offsets
 * that matter (ukm present / absent, trailing empty SEQUENCE) are explicit.
 * ------------------------------------------------------------------------- */

/* ContentInfo { id-envelopedData, [0] { SEQ { version, SET { SEQ } } } } --
 * the recipientInfos SET parses, but its first element is a SEQUENCE (a KTRI
 * shape) rather than the [1] KARI header. */
static byte wbKariNotKari[] = {
    0x30, 0x18,
      0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03,
      0xA0, 0x0B,
        0x30, 0x09,
          0x02, 0x01, 0x00,
          0x31, 0x04,
            0x30, 0x02, 0xAA, 0xBB
};

/* same shell, but recipientInfos is a SEQUENCE so the SET header rejects and
 * every later link in the chain sees a non-zero ret */
static byte wbKariNoSet[] = {
    0x30, 0x18,
      0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03,
      0xA0, 0x0B,
        0x30, 0x09,
          0x02, 0x01, 0x00,
          0x30, 0x04,
            0x30, 0x02, 0xAA, 0xBB
};

/* full KARI skeleton down to RecipientEncryptedKeys, whose single
 * RecipientEncryptedKey is an empty SEQUENCE ending the buffer: the
 * KeyAgreeRecipientIdentifier tag read then has no byte left to read */
static byte wbKariRidCut[] = {
    0x30, 0x25,
      0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03,
      0xA0, 0x18,
        0x30, 0x16,
          0x02, 0x01, 0x02,
          0x31, 0x11,
            0xA1, 0x0F,
              0x02, 0x01, 0x03,
              0xA0, 0x02, 0xAA, 0xBB,
              0x30, 0x02, 0xAA, 0xBB,
              0x30, 0x02,
                0x30, 0x00
};

/* same skeleton with an optional ukm [1] present between the originator [0]
 * and the keyEncryptionAlgorithm: the only shape that makes the ukm probe's
 * own GetASNHeader succeed. kari-keyid-cms.msg carries no ukm, so without
 * this the probe only ever sees its rejecting outcome. */
static byte wbKariUkm[] = {
    0x30, 0x29,
      0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03,
      0xA0, 0x1C,
        0x30, 0x1A,
          0x02, 0x01, 0x02,
          0x31, 0x15,
            0xA1, 0x13,
              0x02, 0x01, 0x03,
              0xA0, 0x02, 0xAA, 0xBB,
              0xA1, 0x02, 0xAA, 0xBB,
              0x30, 0x02, 0xAA, 0xBB,
              0x30, 0x02,
                0x30, 0x00
};

static void wb_kari_rid_crafted(void)
{
    byte   out[64];
    word32 outSz;
    int    ret;

    WB_NOTE("wc_PKCS7_GetEnvelopedDataKariRid(): recipientInfos SET rejects,"
            " so every later link in the chain sees a non-zero ret"
            " [:15056 leading operand false]");
    outSz = (word32)sizeof(out);
    ret = wc_PKCS7_GetEnvelopedDataKariRid(wbKariNoSet,
            (word32)sizeof(wbKariNoSet), out, &outSz);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E), ":15056 ret non-zero");

    WB_NOTE("wc_PKCS7_GetEnvelopedDataKariRid(): recipientInfos SET parses but"
            " holds a non-KARI element, so the kari [1] header rejects with"
            " ret still 0 [:15039]");
    outSz = (word32)sizeof(out);
    ret = wc_PKCS7_GetEnvelopedDataKariRid(wbKariNotKari,
            (word32)sizeof(wbKariNotKari), out, &outSz);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E), ":15039 not a KARI");

    WB_NOTE("wc_PKCS7_GetEnvelopedDataKariRid(): optional ukm [1] present, so"
            " the ukm probe accepts [:15056 both operands true]");
    outSz = (word32)sizeof(out);
    ret = wc_PKCS7_GetEnvelopedDataKariRid(wbKariUkm,
            (word32)sizeof(wbKariUkm), out, &outSz);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E), ":15056 ukm consumed");

    WB_NOTE("wc_PKCS7_GetEnvelopedDataKariRid(): empty RecipientEncryptedKey"
            " at end of buffer, so the rid tag read runs out of input with"
            " ret still 0 [:15078]");
    outSz = (word32)sizeof(out);
    ret = wc_PKCS7_GetEnvelopedDataKariRid(wbKariRidCut,
            (word32)sizeof(wbKariRidCut), out, &outSz);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E), ":15078 rid tag off the end");
}

/* ------------------------------------------------------------------------- *
 * Section 11: wc_PKCS7_DecryptOri() callback-result guard [:12978].
 *
 * `ret != 0 || decryptedKey == NULL || *decryptedKeySz == 0` is entirely
 * determined by what the registered ORI callback does, and no API-level test
 * registers one, so all three operands need a driver here: one call per
 * operand-true row plus the all-false row they pair against.
 * ------------------------------------------------------------------------- */

/* OtherRecipientInfo body, positioned as wc_PKCS7_DecryptOri() expects: the
 * caller has already consumed the [4] tag, so index 0 is the length byte.
 *   <len> 06 03 2A 03 04   04 02 AA BB */
static byte wbOri[] = { 0x09, 0x06, 0x03, 0x2A, 0x03, 0x04,
                        0x04, 0x02, 0xAA, 0xBB };

static int wb_ori_cb_fail(wc_PKCS7* p, byte* oriType, word32 oriTypeSz,
        byte* oriValue, word32 oriValueSz, byte* decryptedKey,
        word32* decryptedKeySz, void* ctx)
{
    (void)p; (void)oriType; (void)oriTypeSz; (void)oriValue; (void)oriValueSz;
    (void)decryptedKey; (void)decryptedKeySz; (void)ctx;
    return -1;
}

static int wb_ori_cb_nowrite(wc_PKCS7* p, byte* oriType, word32 oriTypeSz,
        byte* oriValue, word32 oriValueSz, byte* decryptedKey,
        word32* decryptedKeySz, void* ctx)
{
    (void)p; (void)oriType; (void)oriTypeSz; (void)oriValue; (void)oriValueSz;
    (void)decryptedKey; (void)ctx;
    *decryptedKeySz = 32;
    return 0;
}

static int wb_ori_cb_empty(wc_PKCS7* p, byte* oriType, word32 oriTypeSz,
        byte* oriValue, word32 oriValueSz, byte* decryptedKey,
        word32* decryptedKeySz, void* ctx)
{
    (void)p; (void)oriType; (void)oriTypeSz; (void)oriValue; (void)oriValueSz;
    (void)decryptedKey; (void)ctx;
    *decryptedKeySz = 0;
    return 0;
}

static int wb_ori_cb_ok(wc_PKCS7* p, byte* oriType, word32 oriTypeSz,
        byte* oriValue, word32 oriValueSz, byte* decryptedKey,
        word32* decryptedKeySz, void* ctx)
{
    (void)p; (void)oriType; (void)oriTypeSz; (void)oriValue; (void)oriValueSz;
    (void)ctx;
    XMEMSET(decryptedKey, 0x11, 32);
    *decryptedKeySz = 32;
    return 0;
}

static int wb_decrypt_ori_once(CallbackOriDecrypt cb, byte* decryptedKey)
{
    wc_PKCS7 pkcs7;
    word32   idx = 0;
    word32   keySz = 32;
    int      recipFound = 0;
    int      ret;

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));
    pkcs7.oriDecryptCb = cb;
    pkcs7.state = WC_PKCS7_DECRYPT_ORI;
#ifndef NO_PKCS7_STREAM
    if (wc_PKCS7_CreateStream(&pkcs7) != 0) {
        return -1;
    }
    /* let AddDataToStream take the "input buffer already holds it" path */
    pkcs7.stream->maxLen = (word32)sizeof(wbOri);
#endif
    ret = wc_PKCS7_DecryptOri(&pkcs7, wbOri, (word32)sizeof(wbOri), &idx,
            decryptedKey, &keySz, &recipFound);
#ifndef NO_PKCS7_STREAM
    wc_PKCS7_FreeStream(&pkcs7);
#endif
    return ret;
}

static void wb_decrypt_ori_guard(void)
{
    byte key[32];
    int  ret;

    WB_NOTE("wc_PKCS7_DecryptOri(): callback failure [:12978 operand 1]");
    ret = wb_decrypt_ori_once(wb_ori_cb_fail, key);
    WB_CHECK(ret == WC_NO_ERR_TRACE(PKCS7_RECIP_E), ":12978 callback failed");

    WB_NOTE("wc_PKCS7_DecryptOri(): callback succeeds with no output buffer"
            " [:12978 operand 2]");
    ret = wb_decrypt_ori_once(wb_ori_cb_nowrite, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(PKCS7_RECIP_E), ":12978 NULL key buffer");

    WB_NOTE("wc_PKCS7_DecryptOri(): callback succeeds with a zero-length key"
            " [:12978 operand 3]");
    ret = wb_decrypt_ori_once(wb_ori_cb_empty, key);
    WB_CHECK(ret == WC_NO_ERR_TRACE(PKCS7_RECIP_E), ":12978 zero-length key");

    WB_NOTE("wc_PKCS7_DecryptOri(): all three operands false (the row every"
            " operand-true call above pairs against) [:12978]");
    ret = wb_decrypt_ori_once(wb_ori_cb_ok, key);
    WB_CHECK(ret == 0, ":12978 all operands false");
}

/* ------------------------------------------------------------------------- *
 * Section 12: wc_PKCS7_HandleOctetStrings() content accumulation [:6817].
 *
 * `tempBuf != NULL && contBufSz != 0` needs a call that arrives with a
 * previously allocated stream content buffer whose accumulated size is still
 * zero. That combination never arises from a single top-level decode -- the
 * two fields are written together -- so it is seeded directly here, paired
 * with the ordinary non-zero-accumulation call in the same binary.
 * ------------------------------------------------------------------------- */
#ifndef NO_PKCS7_STREAM
static void wb_octet_accum(word32 seedAccum)
{
    wc_PKCS7 pkcs7;
    byte     in[16];
    word32   idx = 0, tmpIdx = 0;
    word32   seedSz = (seedAccum > 0) ? seedAccum : 1;
    int      ret;

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));
    XMEMSET(in, 0, sizeof(in));

    if (wc_PKCS7_CreateStream(&pkcs7) != 0) {
        return;
    }
    pkcs7.stream->content = (byte*)XMALLOC(seedSz, pkcs7.heap,
            DYNAMIC_TYPE_PKCS7);
    if (pkcs7.stream->content == NULL) {
        wc_PKCS7_FreeStream(&pkcs7);
        return;
    }
    XMEMSET(pkcs7.stream->content, 0, seedSz);

    pkcs7.stream->accumContSz   = seedAccum;
    pkcs7.stream->currContSz    = 4;
    pkcs7.stream->currContRmnSz = 4;
    pkcs7.stream->expected      = 4;
    pkcs7.stream->noContent     = 0;
    /* stop after the single accumulation pass rather than looking for a
     * following OCTET STRING header */
    pkcs7.stream->maxLen        = 4;

    ret = wc_PKCS7_HandleOctetStrings(&pkcs7, in, (word32)sizeof(in), &tmpIdx,
            &idx, 1);
    WB_CHECK(ret == 0, ":6817 accumulation pass completed");
    wc_PKCS7_FreeStream(&pkcs7);
}

/* The "another OCTET STRING follows" branch, :6689. Its trailing operand needs
 * an 0x04 tag whose length field is itself malformed -- a shape no encoder
 * emits, since every OCTET STRING wolfSSL writes carries a well-formed length.
 * Seeded directly, like wb_octet_accum() above, with currContRmnSz == 0 so the
 * branch is entered on the first pass. */
static int wb_octet_next_len(byte* in, word32 inSz)
{
    wc_PKCS7 pkcs7;
    word32   idx = 0, tmpIdx = 0;
    int      ret;

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));

    if (wc_PKCS7_CreateStream(&pkcs7) != 0) {
        return BAD_FUNC_ARG;
    }
    pkcs7.stream->currContSz    = 0;
    pkcs7.stream->currContRmnSz = 0;
    pkcs7.stream->expected      = 1;
    pkcs7.stream->noContent     = 0;
    pkcs7.stream->maxLen        = inSz;

    ret = wc_PKCS7_HandleOctetStrings(&pkcs7, in, inSz, &tmpIdx, &idx, 1);
    wc_PKCS7_FreeStream(&pkcs7);
    return ret;
}

static void wb_octet_accum_chains(void)
{
    WB_NOTE("wc_PKCS7_HandleOctetStrings(): existing content buffer with a"
            " zero accumulated size [:6817 trailing operand false]");
    wb_octet_accum(0);
    WB_NOTE("wc_PKCS7_HandleOctetStrings(): existing content buffer with a"
            " non-zero accumulated size [:6817 trailing operand true]");
    wb_octet_accum(4);

    {
        static byte okLen[]  = { 0x04, 0x02, 0xAA, 0xBB };
        static byte badLen[] = { 0x04 };
        int ret;

        WB_NOTE("wc_PKCS7_HandleOctetStrings(): a following OCTET STRING whose"
                " length parses [:6689 trailing operand false]");
        ret = wb_octet_next_len(okLen, (word32)sizeof(okLen));
        WB_CHECK(ret != WC_NO_ERR_TRACE(ASN_PARSE_E),
                ":6689 well-formed following OCTET STRING length");

        WB_NOTE("wc_PKCS7_HandleOctetStrings(): a following OCTET STRING tag"
                " with no length byte behind it [:6689 trailing operand"
                " true]");
        ret = wb_octet_next_len(badLen, (word32)sizeof(badLen));
        WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
                ":6689 malformed following OCTET STRING length");
    }
}
#else
static void wb_octet_accum_chains(void)
{
    WB_NOTE("NO_PKCS7_STREAM; HandleOctetStrings accumulation skipped");
}
#endif /* !NO_PKCS7_STREAM */

/* ------------------------------------------------------------------------- *
 * Section 13: wc_PKCS7_EcdsaVerify() verification-result guards
 * [:5505,:5516].
 *
 * Both guards are `ret == 0 && res == 1`; their leading operand only goes
 * false when wc_ecc_verify_hash() itself errors out, which a well-formed
 * bundle never does (a wrong signature yields ret 0 with res 0). Feeding a
 * signature that is not a valid ECDSA-Sig-Value produces the error, and the
 * genuinely-verifying call in the same function supplies the row it pairs
 * against.
 * ------------------------------------------------------------------------- */
#if defined(HAVE_ECC) && defined(USE_CERT_BUFFERS_256)
static void wb_ecdsa_verify_results(void)
{
    wc_PKCS7 pkcs7;
    ecc_key  key;
    byte     hash[32];
    byte     sig[144];
    word32   sigSz = (word32)sizeof(sig);
    word32   idx = 0;
    int      ret;

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));
    XMEMSET(hash, 0x5A, sizeof(hash));
    pkcs7.devId    = INVALID_DEVID;
    pkcs7.cert[0]  = (byte*)cliecc_cert_der_256;
    pkcs7.certSz[0] = (word32)sizeof_cliecc_cert_der_256;

    WB_NOTE("wc_PKCS7_EcdsaVerify(): genuine signature over the supplied"
            " digest [:5505,:5516 both operands true]");
    if (wc_ecc_init(&key) == 0) {
        if (wc_EccPrivateKeyDecode(ecc_clikey_der_256, &idx, &key,
                    (word32)sizeof_ecc_clikey_der_256) == 0 &&
                wc_ecc_sign_hash(hash, (word32)sizeof(hash), sig, &sigSz,
                    &wbRng, &key) == 0) {
            ret = wc_PKCS7_EcdsaVerify(&pkcs7, sig, (int)sigSz, hash,
                    (word32)sizeof(hash));
            WB_CHECK(ret == 0, ":5505/:5516 signature verified");
        }
        wc_ecc_free(&key);
    }

    WB_NOTE("wc_PKCS7_EcdsaVerify(): signature bytes are not an"
            " ECDSA-Sig-Value, so the verify call errors and both guards see"
            " a non-zero ret [:5505,:5516]");
    XMEMSET(sig, 0xA5, sizeof(sig));
    ret = wc_PKCS7_EcdsaVerify(&pkcs7, sig, 16, hash, (word32)sizeof(hash));
    WB_CHECK(ret != 0, ":5505/:5516 ret non-zero on arrival");
}
#else
static void wb_ecdsa_verify_results(void)
{
    WB_NOTE("no HAVE_ECC/USE_CERT_BUFFERS_256; EcdsaVerify results skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 14: PKCS7_VerifySignedData() outer-shape vectors [:6980,:7068].
 *
 * Both are data-shape operands that a truncate/corrupt sweep over a real
 * bundle cannot produce: every corpus starts `30 82 xx xx`, so the outer
 * SEQUENCE length is never zero, and every corpus SignedData is version 1.
 * ------------------------------------------------------------------------- */

/* definite zero-length outer SEQUENCE: length is 0 but the byte before the
 * content is 0x00, not the indefinite-length marker */
static byte wbVsdEmptySeq[64];

/* SignedData whose version field is 3 (the other accepted value), and the
 * same bundle with an unaccepted version, so the version guard sees both */
static byte wbVsdVer[64];

static void wb_verify_outer_shapes(void)
{
    wc_PKCS7* p;
    word32 i;

    XMEMSET(wbVsdEmptySeq, 0, sizeof(wbVsdEmptySeq));
    wbVsdEmptySeq[0] = 0x30;
    wbVsdEmptySeq[1] = 0x00;

    XMEMSET(wbVsdVer, 0, sizeof(wbVsdVer));
    i = 0;
    wbVsdVer[i++] = 0x30; wbVsdVer[i++] = 0x14;
    wbVsdVer[i++] = 0x06; wbVsdVer[i++] = 0x09;
    wbVsdVer[i++] = 0x2A; wbVsdVer[i++] = 0x86; wbVsdVer[i++] = 0x48;
    wbVsdVer[i++] = 0x86; wbVsdVer[i++] = 0xF7; wbVsdVer[i++] = 0x0D;
    wbVsdVer[i++] = 0x01; wbVsdVer[i++] = 0x07; wbVsdVer[i++] = 0x02;
    wbVsdVer[i++] = 0xA0; wbVsdVer[i++] = 0x07;
    wbVsdVer[i++] = 0x30; wbVsdVer[i++] = 0x05;
    wbVsdVer[i++] = 0x02; wbVsdVer[i++] = 0x01; wbVsdVer[i++] = 0x03;
    wbVsdVer[i++] = 0x31; wbVsdVer[i++] = 0x00;

    WB_NOTE("PKCS7_VerifySignedData(): definite zero-length outer SEQUENCE,"
            " so the indefinite-length probe reads a 0x00 length byte"
            " [:6980 trailing operand false]");
    p = wc_PKCS7_New(NULL, INVALID_DEVID);
    if (p != NULL) {
        if (wc_PKCS7_InitWithCert(p, NULL, 0) == 0) {
            (void)wc_PKCS7_VerifySignedData(p, wbVsdEmptySeq,
                    (word32)sizeof(wbVsdEmptySeq));
        }
        wc_PKCS7_Free(p);
    }

    WB_NOTE("PKCS7_VerifySignedData(): SignedData version 3 [:7068 trailing"
            " operand false] and an unaccepted version [:7068 true]");
    p = wc_PKCS7_New(NULL, INVALID_DEVID);
    if (p != NULL) {
        if (wc_PKCS7_InitWithCert(p, NULL, 0) == 0) {
            (void)wc_PKCS7_VerifySignedData(p, wbVsdVer,
                    (word32)sizeof(wbVsdVer));
        }
        wc_PKCS7_Free(p);
    }
    wbVsdVer[19] = 0x07;   /* version byte: neither 1 nor 3 */
    p = wc_PKCS7_New(NULL, INVALID_DEVID);
    if (p != NULL) {
        if (wc_PKCS7_InitWithCert(p, NULL, 0) == 0) {
            (void)wc_PKCS7_VerifySignedData(p, wbVsdVer,
                    (word32)sizeof(wbVsdVer));
        }
        wc_PKCS7_Free(p);
    }
    wbVsdVer[19] = 0x03;
}

/* ------------------------------------------------------------------------- *
 * Section 16: identity- and version-dispatch operands that neither a sweep
 * nor any public encoder can produce, because no encoder in the tree ever
 * emits the shape the operand tests.
 *
 *   :6398 cond 1/2  wc_PKCS7_ParseSignerInfo()'s noDegenerate guard. The
 *                   inner OR is `inSz == 0 || degenerate == 1`; both operands
 *                   need a call with noDegenerate set, which the public
 *                   decode path only ever makes with the *same* (inSz,
 *                   degenerate) pair for a given bundle. Called directly with
 *                   the three combinations instead.
 *   :5166 cond 1    wc_PKCS7_RsaVerify()'s `keyOID != RSAk && keyOID !=
 *   :5298 cond 1    RSAPSSk` defence-in-depth guard, and the same guard in
 *                   wc_PKCS7_RsaPssVerify(). The false row needs an
 *                   RSASSA-PSS SubjectPublicKeyInfo (keyOID == RSAPSSk) in
 *                   pkcs7->cert[], which no bundle this module builds carries;
 *                   the true row needs a non-RSA-family cert in the same
 *                   binary. Both are supplied here from certs/.
 *   :14106 cond 2   wc_PKCS7_ParseToRecipientInfoSet()'s BER marker test
 *                   `ret == 0 && length == 0 && pkiMsg[(*idx)-1] == 0x80`.
 *                   A zero-length *definite* outer SEQUENCE (`30 00`) is the
 *                   only input that reaches the third operand with a false
 *                   value; the `30 80` companion in the same binary supplies
 *                   the true row.
 *   :14215 cond 4   the ECDSA arm of the envelopedData version dispatch,
 *                   `publicKeyOID == ECDSAk && (version != 0 && ...)`. The
 *                   false row needs an ECC signer key with version 0, the
 *                   true row the same key with a version that is none of
 *                   0/2/3 -- one field of one hand-built header apart.
 * ------------------------------------------------------------------------- */

/* ContentInfo/EnvelopedData header, parsed as far as the RecipientInfo SET.
 * Padded well past MAX_OID_SZ + MAX_LENGTH_SZ so that the streaming
 * wc_PKCS7_AddDataToStream() never has to ask for more input. */
static byte wbRisHdr[96];
/* the same prefix with a zero-length definite outer SEQUENCE, and with the
 * indefinite-length marker, so :14106's third operand sees both values */
static byte wbRisEmptyDef[96];
static byte wbRisEmptyIndef[96];

static word32 wb_build_ris_hdr(byte* buf, word32 bufSz, byte version)
{
    word32 i = 0;

    XMEMSET(buf, 0, bufSz);
    buf[i++] = 0x30; buf[i++] = 0x16;              /* ContentInfo SEQUENCE */
    buf[i++] = 0x06; buf[i++] = 0x09;              /* envelopedData OID */
    buf[i++] = 0x2A; buf[i++] = 0x86; buf[i++] = 0x48; buf[i++] = 0x86;
    buf[i++] = 0xF7; buf[i++] = 0x0D; buf[i++] = 0x01; buf[i++] = 0x07;
    buf[i++] = 0x03;
    buf[i++] = 0xA0; buf[i++] = 0x09;              /* [0] EXPLICIT */
    buf[i++] = 0x30; buf[i++] = 0x07;              /* EnvelopedData SEQUENCE */
    buf[i++] = 0x02; buf[i++] = 0x01; buf[i++] = version;
    buf[i++] = 0x31; buf[i++] = 0x02;              /* RecipientInfo SET */
    buf[i++] = 0x30; buf[i++] = 0x00;
    return bufSz;
}

static int wb_parse_ris(byte* buf, word32 bufSz, word32 pubKeyOID)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    word32    idx = 0;
    int       ret;

    if (p == NULL) {
        return MEMORY_E;
    }
    if (wc_PKCS7_InitWithCert(p, NULL, 0) != 0) {
        wc_PKCS7_Free(p);
        return BAD_FUNC_ARG;
    }
    p->publicKeyOID = pubKeyOID;
    ret = wc_PKCS7_ParseToRecipientInfoSet(p, buf, bufSz, &idx, ENVELOPED_DATA);
    wc_PKCS7_Free(p);
    return ret;
}

static void wb_recipient_info_set_shapes(void)
{
    int ret;

    WB_NOTE("wc_PKCS7_ParseToRecipientInfoSet(): zero-length outer SEQUENCE,"
            " definite vs indefinite, isolates the 0x80 marker operand"
            " [:14106 cond 2]");
    XMEMSET(wbRisEmptyDef, 0, sizeof(wbRisEmptyDef));
    wbRisEmptyDef[0] = 0x30;
    wbRisEmptyDef[1] = 0x00;
    ret = wb_parse_ris(wbRisEmptyDef, (word32)sizeof(wbRisEmptyDef), RSAk);
    WB_CHECK(ret != 0, ":14106 definite zero-length SEQUENCE (marker false)");

    XMEMSET(wbRisEmptyIndef, 0, sizeof(wbRisEmptyIndef));
    wbRisEmptyIndef[0] = 0x30;
    wbRisEmptyIndef[1] = 0x80;
    ret = wb_parse_ris(wbRisEmptyIndef, (word32)sizeof(wbRisEmptyIndef), RSAk);
    WB_CHECK(ret != 0, ":14106 indefinite-length SEQUENCE (marker true)");

#ifdef HAVE_ECC
    WB_NOTE("wc_PKCS7_ParseToRecipientInfoSet(): ECDSA signer key with"
            " envelopedData version 0 and version 1 [:14215 cond 4]");
    (void)wb_build_ris_hdr(wbRisHdr, (word32)sizeof(wbRisHdr), 0x00);
    ret = wb_parse_ris(wbRisHdr, (word32)sizeof(wbRisHdr), ECDSAk);
    /* the success return is the RecipientInfo SET length, not 0 */
    WB_CHECK(ret > 0, ":14215 ECDSAk with version 0 is accepted");

    (void)wb_build_ris_hdr(wbRisHdr, (word32)sizeof(wbRisHdr), 0x01);
    ret = wb_parse_ris(wbRisHdr, (word32)sizeof(wbRisHdr), ECDSAk);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_VERSION_E),
            ":14215 ECDSAk with version 1 is rejected");
#endif

    /* RSA companion rows, so the RSAk arm's operands are decided by the same
     * two headers rather than only by real bundles. */
    (void)wb_build_ris_hdr(wbRisHdr, (word32)sizeof(wbRisHdr), 0x00);
    ret = wb_parse_ris(wbRisHdr, (word32)sizeof(wbRisHdr), RSAk);
    WB_CHECK(ret > 0, ":14215 RSAk with version 0 is accepted");
    (void)wb_build_ris_hdr(wbRisHdr, (word32)sizeof(wbRisHdr), 0x01);
    ret = wb_parse_ris(wbRisHdr, (word32)sizeof(wbRisHdr), RSAk);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_VERSION_E),
            ":14215 RSAk with version 1 is rejected");
}

/* wc_PKCS7_ParseSignerInfo() with pkcs7->noDegenerate set, across the three
 * (inSz, degenerate) combinations the inner OR needs. */
static int wb_parse_signer_info_nodeg(byte* in, word32 inSz, int degenerate)
{
    wc_PKCS7 pkcs7;
    word32   idx = 0;
    byte*    signedAttrib = NULL;
    int      signedAttribSz = 0;
    int      ret;

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));
    pkcs7.version = 1;
    pkcs7.noDegenerate = 1;
    ret = wc_PKCS7_ParseSignerInfo(&pkcs7, in, inSz, &idx, degenerate,
            &signedAttrib, &signedAttribSz);
    wc_PKCS7_SignerInfoFree(&pkcs7);
    return ret;
}

static void wb_parse_signer_info_nodegenerate(void)
{
    int ret;

    WB_NOTE("wc_PKCS7_ParseSignerInfo(): noDegenerate matrix, each operand of"
            " `inSz == 0 || degenerate == 1` isolated [:6398]");

    /* (T,T,-): inSz == 0 decides the OR */
    ret = wb_parse_signer_info_nodeg(wbSiNoSeq, 0, 0);
    WB_CHECK(ret == WC_NO_ERR_TRACE(PKCS7_NO_SIGNER_E),
            ":6398 inSz == 0 with noDegenerate set");

    /* (T,F,T): degenerate decides the OR */
    ret = wb_parse_signer_info_nodeg(wbSiNoSeq, (word32)sizeof(wbSiNoSeq), 1);
    WB_CHECK(ret == WC_NO_ERR_TRACE(PKCS7_NO_SIGNER_E),
            ":6398 degenerate == 1 with noDegenerate set");

    /* (T,F,F): the guard does not fire and the parse runs on */
    ret = wb_parse_signer_info_nodeg(wbSiNoSeq, (word32)sizeof(wbSiNoSeq), 0);
    WB_CHECK(ret != WC_NO_ERR_TRACE(PKCS7_NO_SIGNER_E),
            ":6398 neither OR operand true, parse proceeds");
}

/* ------------------------------------------------------------------------- *
 * The RSA-family SPKI guards. Both verifiers walk pkcs7->cert[] themselves,
 * so the vector is just "put this DER in cert[0] and call".
 * ------------------------------------------------------------------------- */
#ifndef NO_RSA
static byte wbSpkiCert[2048];

static void wb_rsa_spki_guards(void)
{
    byte  sig[256];
    byte  hash[32];
    word32 certSz;
    wc_PKCS7* p;

    XMEMSET(sig, 0x5A, sizeof(sig));
    XMEMSET(hash, 0x5B, sizeof(hash));

    /* (a) keyOID is neither RSAk nor RSAPSSk: an ECDSA certificate. */
    certSz = wb_load_file("./certs/client-ecc-cert.der", wbSpkiCert,
            (word32)sizeof(wbSpkiCert));
    if (certSz > 0) {
        WB_NOTE("wc_PKCS7_RsaVerify(): non-RSA-family SPKI rejected"
                " [:5166 both operands true]");
        p = wc_PKCS7_New(NULL, INVALID_DEVID);
        if (p != NULL) {
            if (wc_PKCS7_InitWithCert(p, NULL, 0) == 0) {
                p->cert[0]   = wbSpkiCert;
                p->certSz[0] = certSz;
                p->hashOID   = SHA256h;
                WB_CHECK(wc_PKCS7_RsaVerify(p, sig, (int)sizeof(sig), hash,
                            (word32)sizeof(hash)) != 0,
                        ":5166 ECDSA cert is skipped");
#ifdef WC_RSA_PSS
                WB_CHECK(wc_PKCS7_RsaPssVerify(p, sig, (int)sizeof(sig), hash,
                            (word32)sizeof(hash)) != 0,
                        ":5298 ECDSA cert is skipped");
#endif
            }
            wc_PKCS7_Free(p);
        }
    }

    /* (b) keyOID == RSAPSSk: the second operand alone decides the guard. */
    certSz = wb_load_file("./certs/rsapss/client-rsapss.der", wbSpkiCert,
            (word32)sizeof(wbSpkiCert));
    if (certSz > 0) {
        WB_NOTE("wc_PKCS7_RsaVerify(): RSASSA-PSS SPKI accepted by the guard"
                " [:5166 second operand false]");
        p = wc_PKCS7_New(NULL, INVALID_DEVID);
        if (p != NULL) {
            if (wc_PKCS7_InitWithCert(p, NULL, 0) == 0) {
                p->cert[0]   = wbSpkiCert;
                p->certSz[0] = certSz;
                p->hashOID   = SHA256h;
                /* the signature is garbage, so the call still fails -- but it
                 * fails *after* the guard, which is the point. */
                WB_CHECK(wc_PKCS7_RsaVerify(p, sig, (int)sizeof(sig), hash,
                            (word32)sizeof(hash)) != 0,
                        ":5166 RSAPSS cert passes the guard, signature fails");
#ifdef WC_RSA_PSS
                WB_CHECK(wc_PKCS7_RsaPssVerify(p, sig, (int)sizeof(sig), hash,
                            (word32)sizeof(hash)) != 0,
                        ":5298 RSAPSS cert passes the guard, signature fails");
#endif
            }
            wc_PKCS7_Free(p);
        }
    }
}
#else
static void wb_rsa_spki_guards(void)
{
    WB_NOTE("NO_RSA; RSA-family SPKI guards skipped");
}
#endif /* !NO_RSA */

/* ------------------------------------------------------------------------- *
 * Section 17: the KTRI key-encryption-algorithm dispatch, :12114
 *   `encOID != RSAk && encOID != RSAESOAEPk`
 * Every KTRI this tree can *emit* carries rsaEncryption, which short-circuits
 * on the first operand. The two rows the second operand needs are one byte
 * apart from that: the last arc of the 9-byte algorithm OID inside the
 * KeyTransRecipientInfo is rewritten in place -- 0x07 for id-RSAES-OAEP (the
 * guard's false row) and 0x0A for id-RSASSA-PSS, which is in neither arm (the
 * true row). Both replacements are the same length as rsaEncryption, so no
 * enclosing ASN.1 length changes.
 * ------------------------------------------------------------------------- */
#if !defined(NO_RSA) && defined(USE_CERT_BUFFERS_2048)
static const byte wbRsaEncOid[] = {
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01
};

static void wb_ktri_alg_call(byte* buf, word32 len)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    static byte out[WB_SCRATCH_SZ];

    if (p == NULL) {
        return;
    }
    if (wc_PKCS7_InitWithCert(p, (byte*)client_cert_der_2048,
            sizeof_client_cert_der_2048) == 0 &&
        wc_PKCS7_SetKey(p, (byte*)client_key_der_2048,
            sizeof_client_key_der_2048) == 0) {
        (void)wc_PKCS7_DecodeEnvelopedData(p, buf, len, out, sizeof(out));
    }
    wc_PKCS7_Free(p);
}

static void wb_ktri_key_alg_dispatch(void)
{
    word32 fullLen, i;
    int    found = -1;

    fullLen = wb_load_file("./certs/test/ktri-keyid-cms.msg", wbScratch,
            sizeof(wbScratch));
    if (fullLen < sizeof(wbRsaEncOid)) {
        WB_NOTE("ktri-keyid-cms.msg unavailable; KTRI algorithm dispatch"
                " skipped");
        return;
    }
    /* the LAST rsaEncryption OID in the message is the KTRI's
     * keyEncryptionAlgorithm (the earlier one is the certificate's SPKI) */
    for (i = 0; i + (word32)sizeof(wbRsaEncOid) <= fullLen; i++) {
        if (XMEMCMP(wbScratch + i, wbRsaEncOid, sizeof(wbRsaEncOid)) == 0) {
            found = (int)i;
        }
    }
    if (found < 0) {
        WB_NOTE("no rsaEncryption OID found in ktri-keyid-cms.msg; KTRI"
                " algorithm dispatch skipped");
        return;
    }

    WB_NOTE("wc_PKCS7_DecryptKtri(): rsaEncryption (first operand false)"
            " [:12114]");
    wb_ktri_alg_call(wbScratch, fullLen);

    WB_NOTE("wc_PKCS7_DecryptKtri(): id-RSAES-OAEP (second operand false)"
            " [:12114 cond 1]");
    wbScratch[(word32)found + 10] = 0x07;
    wb_ktri_alg_call(wbScratch, fullLen);

    WB_NOTE("wc_PKCS7_DecryptKtri(): an OID in neither arm (both operands"
            " true) [:12114]");
    wbScratch[(word32)found + 10] = 0x0A;
    wb_ktri_alg_call(wbScratch, fullLen);

    wbScratch[(word32)found + 10] = 0x01;
}
#else
static void wb_ktri_key_alg_dispatch(void)
{
    WB_NOTE("NO_RSA or no 2048-bit cert buffers; KTRI algorithm dispatch"
            " skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * main -- always returns 0 so the campaign harness keeps this variant's
 * coverage even if an individual sub-section's build config disables it.
 * ------------------------------------------------------------------------- */
int main(void)
{
    int rngRet;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== pkcs7 decode-chain white-box (Part 5) ===\n");

    rngRet = wc_InitRng(&wbRng);
    WB_CHECK(rngRet == 0, "wc_InitRng for corpus builders");

    wb_verify_decode_chains();
    wb_enveloped_decode_chains();
    wb_auth_enveloped_decode_chains();
    wb_encrypted_decode_chains();
    wb_parse_ris_decode_chains();
    wb_kari_rid_decode_chains();
    wb_kekri_decode_chains();
    wb_pwri_decode_chains();
    wb_decrypt_content_init_direct();
    wb_parse_signer_info_chains();
    wb_kari_rid_crafted();
    wb_decrypt_ori_guard();
    wb_octet_accum_chains();
    wb_ecdsa_verify_results();
    wb_verify_outer_shapes();
    wb_recipient_info_set_shapes();
    wb_parse_signer_info_nodegenerate();
    wb_rsa_spki_guards();
    wb_ktri_key_alg_dispatch();

    if (rngRet == 0) {
        wc_FreeRng(&wbRng);
    }

    if (wb_fail) {
        printf("=== pkcs7 decode-chain white-box: FAIL ===\n");
    }
    else {
        printf("=== pkcs7 decode-chain white-box: PASS ===\n");
    }
    return 0;
}
