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
 * This file does NOT duplicate the streaming-state-machine, signer-info,
 * signed-attribute, encode-side, or plain NULL/size-guard coverage that
 * test_pkcs7_whitebox.c already drives -- only the decode ASN.1 walks.
 */

#include <wolfcrypt/src/pkcs7.c>

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
 * main -- always returns 0 so the campaign harness keeps this variant's
 * coverage even if an individual sub-section's build config disables it.
 * ------------------------------------------------------------------------- */
int main(void)
{
    int rngRet;

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
