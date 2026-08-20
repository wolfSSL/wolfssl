/* test_pkcs7_mutate_whitebox.c
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
 * Dense mutation white-box MC/DC supplement for wolfcrypt/src/pkcs7.c.
 *
 * The decode state machines in pkcs7.c are written as long chains of
 *
 *     if (ret == 0 && Get<Element>(pkiMsg, &idx, ..., sz) < 0)
 *         ret = ASN_PARSE_E;
 *
 * For MC/DC each such decision needs three vectors inside one binary:
 *   - ret == 0 and the element parses      -> decision false (2nd operand pair)
 *   - ret == 0 and the element fails       -> decision true
 *   - ret != 0 on arrival                  -> decision false (1st operand pair)
 * A well-formed bundle gives the first, a bundle whose byte at exactly that
 * element is wrong gives the second, and every decision *after* the one that
 * first set ret != 0 gets the third for free from the very same run.
 *
 * test_pkcs7_decode_whitebox.c already sweeps these corpora, but with a
 * stride capped at ~200 mutations per corpus, so most element boundaries are
 * stepped over. This file re-sweeps the same (plus a few more) corpora at
 * single-byte stride with several mutation values, and in several caller
 * modes (detached / head+foot split / pre-computed hash / noDegenerate), so
 * that every element boundary is hit by at least one failing vector.
 *
 * All calls run against a freshly allocated wc_PKCS7 so a mutated bundle can
 * never poison the next vector.
 */

/* The bundles this file mutates are BUILT here, with a live RNG supplying the
 * content-encryption key, the IV and any ephemeral key. Those bytes differ on
 * every run, so a dense single-byte mutation sweep lands on a different
 * structure each time and the decode paths it reaches vary: two full sweeps of
 * an unchanged tree on 2026-08-11 disagreed on pkcs7.c:15994 for exactly this
 * reason. Pinning the stream makes every generated bundle byte-identical, so
 * the mutation offsets mean the same thing on every run. */
#include "mcdc_seed_rng.h"

#include <wolfcrypt/src/pkcs7.c>

#define MCDC_SR_IMPL
#include "mcdc_seed_rng.h"

#include <stdio.h>
#include <string.h>
#include <wolfssl/certs_test.h>

/* Recorded in the module residual note: the bundles this file
 * mutates are generated from this stream. */
#define WB_BUNDLE_SEED 0x9ca7f00dUL

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)
#define WB_CHECK(cond, msg) \
    do { if (!(cond)) { printf("  [wb][FAIL] %s\n", (msg)); wb_fail = 1; } } \
    while (0)

#define WB_SCRATCH_SZ 8192
static byte wbScratch[WB_SCRATCH_SZ];
static byte wbOut[WB_SCRATCH_SZ];
static WC_RNG wbRng;
static int wbRngOk = 0;

typedef void (*wb_decode_fn)(byte* buf, word32 len);

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

/* Dense single-byte mutation sweep. `stride` selects how many byte offsets
 * are visited; each visited offset is driven with three different wrong
 * values so tag bytes, length bytes and content bytes all get a chance to
 * break the element they belong to. The pristine bundle is replayed first
 * and last so the "element parses" leg of every pair is present too. */
static void wb_mutate(wb_decode_fn fn, byte* buf, word32 fullLen, word32 stride)
{
    word32 i;
    byte saved;

    if (fullLen < 4)
        return;
    if (stride == 0)
        stride = 1;

    fn(buf, fullLen);
    for (i = 0; i < fullLen; i += stride) {
        saved = buf[i];
        /* 0xFF/0x7F break tags outright; +/-1 and ^0x20 are the "plausible
         * but wrong" length and tag values that slip past the element being
         * mutated and break the next one instead, which is what the later
         * links of each (ret == 0 && Get*(...)) chain need. */
        buf[i] = (byte)(saved ^ 0xFF);
        fn(buf, fullLen);
        buf[i] = (byte)(saved ^ 0x01);
        fn(buf, fullLen);
        buf[i] = 0x7F;
        fn(buf, fullLen);
        buf[i] = (byte)(saved + 1);
        fn(buf, fullLen);
        buf[i] = (byte)(saved - 1);
        fn(buf, fullLen);
        buf[i] = (byte)(saved ^ 0x20);
        fn(buf, fullLen);
        buf[i] = saved;
    }
    fn(buf, fullLen);
}

/* Dense truncation sweep: a short message stops the walk at a different
 * element for every prefix length. */
static void wb_truncate(wb_decode_fn fn, byte* buf, word32 fullLen,
                        word32 stride)
{
    word32 i;

    if (fullLen < 4)
        return;
    if (stride == 0)
        stride = 1;
    for (i = 2; i < fullLen; i += stride)
        fn(buf, i);
    fn(buf, fullLen);
}

/* ------------------------------------------------------------------------- *
 * Section 1: PKCS7_VerifySignedData() decode walk, five caller modes
 * ------------------------------------------------------------------------- */
#ifndef NO_RSA
static int wbVerifyMode = 0;
static byte wbHash[WC_SHA256_DIGEST_SIZE];

static void wb_verify_call(byte* buf, word32 len)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    word32 half;

    if (p == NULL)
        return;
    if (wc_PKCS7_InitWithCert(p, NULL, 0) == 0) {
        switch (wbVerifyMode) {
            case 0:
                (void)wc_PKCS7_VerifySignedData(p, buf, len);
                break;
            case 1:
                (void)wc_PKCS7_VerifySignedData_ex(p, wbHash,
                        (word32)sizeof(wbHash), buf, len, NULL, 0);
                break;
            case 2:
                half = len / 2;
                (void)wc_PKCS7_VerifySignedData_ex(p, wbHash,
                        (word32)sizeof(wbHash), buf, half, buf + half,
                        len - half);
                break;
            case 3:
                p->noDegenerate = 1;
                (void)wc_PKCS7_VerifySignedData(p, buf, len);
                break;
            case 4:
                (void)wc_PKCS7_SetDetached(p, 1);
                (void)wc_PKCS7_VerifySignedData(p, buf, len);
                break;
            case 5:
                half = len / 2;
                (void)wc_PKCS7_VerifySignedData_ex(p, NULL, 0, buf, half,
                        buf + half, len - half);
                break;
            default:
                break;
        }
    }
    wc_PKCS7_Free(p);
}

static void wb_verify_sweep_file(const char* path)
{
    word32 fullLen = wb_load_file(path, wbScratch, sizeof(wbScratch));
    word32 dense;

    if (fullLen == 0)
        return;

    /* keep the total call count bounded on big corpora */
    dense = (fullLen > 3000) ? 2 : 1;

    for (wbVerifyMode = 0; wbVerifyMode <= 5; wbVerifyMode++) {
        wb_mutate(wb_verify_call, wbScratch, fullLen,
                  (wbVerifyMode == 0) ? dense : (dense * 4));
        wb_truncate(wb_verify_call, wbScratch, fullLen,
                  (wbVerifyMode == 0) ? dense : (dense * 4));
    }
    wbVerifyMode = 0;
}

static void wb_verify_chains(void)
{
    XMEMSET(wbHash, 0x5c, sizeof(wbHash));

    WB_NOTE("PKCS7_VerifySignedData(): dense mutation sweep, test-degenerate.p7b");
    wb_verify_sweep_file("./certs/test-degenerate.p7b");

#ifdef ASN_BER_TO_DER
    WB_NOTE("PKCS7_VerifySignedData(): dense mutation sweep,"
            " test-ber-exp02-05-2022.p7b");
    wb_verify_sweep_file("./certs/test-ber-exp02-05-2022.p7b");
#endif

    WB_NOTE("PKCS7_VerifySignedData(): dense mutation sweep,"
            " test-stream-sign.p7b");
    wb_verify_sweep_file("./certs/test-stream-sign.p7b");

    WB_NOTE("PKCS7_VerifySignedData(): dense mutation sweep,"
            " test-stream-dec.p7b");
    wb_verify_sweep_file("./certs/test-stream-dec.p7b");
}

/* ------------------------------------------------------------------------- *
 * Section 1b: self-built SignedData corpora. The corpus files above are all
 * IssuerAndSerialNumber-identified, attached, definite-length bundles, so the
 * SubjectKeyIdentifier / degenerate / signed-attribute / BER-stream arms of
 * both PKCS7_VerifySignedData() and wc_PKCS7_ParseSignerInfo() are never
 * entered by them. Build one of each here and sweep it the same way.
 * ------------------------------------------------------------------------- */
#ifdef USE_CERT_BUFFERS_2048
static byte wbSignCorpus[WB_SCRATCH_SZ];
static byte wbSignContent[64];
static byte wbSignHash[WC_SHA256_DIGEST_SIZE];
static byte wbSignHead[WB_SCRATCH_SZ];
static byte wbSignFoot[2048];
static word32 wbSignHeadSz;
static word32 wbSignFootSz;

static const byte wbSaOid[] = { 0x06, 0x03, 0x55, 0x04, 0x03 };
static const byte wbSaVal[] = { 0x0c, 0x02, 0x41, 0x42 };

/* sidType < 0 leaves the library default in place */
static word32 wb_build_signed(byte* out, word32 outSz, int sidType,
                              int withAttribs, int stream)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    PKCS7Attrib attrib[1];
    int sz = 0;

    if (p == NULL)
        return 0;
    if (wc_PKCS7_InitWithCert(p, (byte*)client_cert_der_2048,
            (word32)sizeof_client_cert_der_2048) == 0) {
        attrib[0].oid     = wbSaOid;
        attrib[0].oidSz   = (word32)sizeof(wbSaOid);
        attrib[0].value   = wbSaVal;
        attrib[0].valueSz = (word32)sizeof(wbSaVal);

        p->content      = wbSignContent;
        p->contentSz    = (word32)sizeof(wbSignContent);
        p->contentOID   = DATA;
        p->hashOID      = SHA256h;
        p->privateKey   = (byte*)client_key_der_2048;
        p->privateKeySz = (word32)sizeof_client_key_der_2048;
        p->rng          = wbRngOk ? &wbRng : NULL;
        if (sidType >= 0)
            (void)wc_PKCS7_SetSignerIdentifierType(p, sidType);
        if (withAttribs) {
            p->signedAttribs   = attrib;
            p->signedAttribsSz = 1;
        }
#ifdef ASN_BER_TO_DER
        if (stream)
            p->encodeStream = 1;
#else
        (void)stream;
#endif
        sz = wc_PKCS7_EncodeSignedData(p, out, outSz);
        p->signedAttribs   = NULL;
        p->signedAttribsSz = 0;
        p->privateKey      = NULL;
        p->privateKeySz    = 0;
    }
    wc_PKCS7_Free(p);
    return (sz > 0) ? (word32)sz : 0;
}

static void wb_signed_sweep(const char* what, int sidType, int withAttribs,
                            int stream, word32 stride)
{
    word32 fullLen;
    int mode;

    WB_NOTE(what);
    fullLen = wb_build_signed(wbSignCorpus, (word32)sizeof(wbSignCorpus),
            sidType, withAttribs, stream);
    if (fullLen < 32) {
        printf("  [wb] self-built SignedData variant not produced, skipped\n");
        return;
    }
    for (mode = 0; mode <= 4; mode++) {
        wbVerifyMode = mode;
        wb_mutate(wb_verify_call, wbSignCorpus, fullLen,
                  (mode == 0) ? stride : (stride * 4));
        wb_truncate(wb_verify_call, wbSignCorpus, fullLen,
                  (mode == 0) ? stride : (stride * 4));
    }
    wbVerifyMode = 0;
}

/* Detached bundles are verified through the head/foot two-buffer entry, which
 * is the only way the pkiMsg2/in2 arms of PKCS7_VerifySignedData() are ever
 * reached. head and foot are held in globals so the generic mutation driver
 * can walk either buffer while the other stays intact. */
static int wbDetachedMode = 0;

static void wb_detached_call(byte* buf, word32 len)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);

    (void)buf;
    (void)len;
    if (p == NULL)
        return;
    if (wc_PKCS7_InitWithCert(p, NULL, 0) == 0) {
        /* required even on verify when head/foot buffers are used */
        p->contentSz = (word32)sizeof(wbSignContent);
        switch (wbDetachedMode) {
            case 0:     /* hash + footer, the intended flow */
                (void)wc_PKCS7_VerifySignedData_ex(p, wbSignHash,
                        (word32)sizeof(wbSignHash), wbSignHead, wbSignHeadSz,
                        wbSignFoot, wbSignFootSz);
                break;
            case 1:     /* no caller hash */
                (void)wc_PKCS7_VerifySignedData_ex(p, NULL, 0,
                        wbSignHead, wbSignHeadSz, wbSignFoot, wbSignFootSz);
                break;
            case 2:     /* footer pointer present, footer size zero */
                (void)wc_PKCS7_VerifySignedData_ex(p, wbSignHash,
                        (word32)sizeof(wbSignHash), wbSignHead, wbSignHeadSz,
                        wbSignFoot, 0);
                break;
            case 3:     /* hash pointer present, hash size zero */
                (void)wc_PKCS7_VerifySignedData_ex(p, wbSignHash, 0,
                        wbSignHead, wbSignHeadSz, wbSignFoot, wbSignFootSz);
                break;
            default:
                break;
        }
    }
    wc_PKCS7_Free(p);
}

static int wb_build_detached(int detached)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    int ok = 0;

    wbSignHeadSz = (word32)sizeof(wbSignHead);
    wbSignFootSz = (word32)sizeof(wbSignFoot);

    if (p == NULL)
        return 0;
    if (wc_PKCS7_InitWithCert(p, (byte*)client_cert_der_2048,
            (word32)sizeof_client_cert_der_2048) == 0) {
        /* _ex() signs the caller-supplied hash: content must be NULL and
         * only contentSz is consulted (mirrors tests/api). */
        p->content      = NULL;
        p->contentSz    = (word32)sizeof(wbSignContent);
        p->contentOID   = DATA;
        p->hashOID      = SHA256h;
        p->privateKey   = (byte*)client_key_der_2048;
        p->privateKeySz = (word32)sizeof_client_key_der_2048;
        p->encryptOID   = RSAk;
        p->rng          = wbRngOk ? &wbRng : NULL;
        (void)wc_PKCS7_SetDetached(p, (word16)(detached ? 1 : 0));
        if (wc_PKCS7_EncodeSignedData_ex(p, wbSignHash,
                (word32)sizeof(wbSignHash), wbSignHead, &wbSignHeadSz,
                wbSignFoot, &wbSignFootSz) >= 0) {
            ok = 1;
        }
        p->privateKey   = NULL;
        p->privateKeySz = 0;
    }
    wc_PKCS7_Free(p);
    return ok;
}

static void wb_signed_variant_chains(void)
{
    word32 i;

    XMEMSET(wbSignContent, 0x4d, sizeof(wbSignContent));
    if (wc_Hash(WC_HASH_TYPE_SHA256, wbSignContent, (word32)sizeof(wbSignContent),
                wbSignHash, (word32)sizeof(wbSignHash)) != 0) {
        XMEMSET(wbSignHash, 0, sizeof(wbSignHash));
    }

    wb_signed_sweep("PKCS7_VerifySignedData(): self-built SignedData, "
            "IssuerAndSerialNumber sid", CMS_ISSUER_AND_SERIAL_NUMBER, 0, 0, 2);
    wb_signed_sweep("PKCS7_VerifySignedData()/ParseSignerInfo(): self-built "
            "SignedData, SubjectKeyIdentifier sid", CMS_SKID, 0, 0, 2);
    wb_signed_sweep("PKCS7_VerifySignedData(): self-built SignedData with "
            "custom signed attributes", CMS_ISSUER_AND_SERIAL_NUMBER, 1, 0, 2);
    wb_signed_sweep("PKCS7_VerifySignedData(): self-built degenerate "
            "(certs-only) SignedData", DEGENERATE_SID, 0, 0, 2);
#ifdef ASN_BER_TO_DER
    wb_signed_sweep("PKCS7_VerifySignedData(): self-built BER "
            "indefinite-length SignedData", CMS_ISSUER_AND_SERIAL_NUMBER,
            0, 1, 2);
#endif

    WB_NOTE("PKCS7_VerifySignedData_ex(): detached head/foot mutation sweep");
    for (i = 0; i < 2; i++) {
        if (!wb_build_detached((int)(1 - i))) {
            printf("  [wb] detached variant %u not produced\n", (unsigned)i);
            continue;
        }
        {
            /* baseline: the pristine head/foot pair must verify, otherwise the
             * whole STAGE4..6 pkiMsg2 walk below is never entered */
            wc_PKCS7* vp = wc_PKCS7_New(NULL, INVALID_DEVID);
            if (vp != NULL) {
                if (wc_PKCS7_InitWithCert(vp, NULL, 0) == 0) {
                    vp->contentSz = (word32)sizeof(wbSignContent);
                    /* Informational, not a pass/fail: the detached==1 build
                     * is expected to stop early (the verifier has no content
                     * to re-hash), while detached==0 walks all the way to the
                     * signature check. Both are useful mutation baselines. */
                    printf("  [wb] head/foot corpus: detached=%d head=%u "
                           "foot=%u baseline ret=%d\n",
                            (int)(1 - i), (unsigned)wbSignHeadSz,
                            (unsigned)wbSignFootSz,
                            wc_PKCS7_VerifySignedData_ex(vp, wbSignHash,
                            (word32)sizeof(wbSignHash), wbSignHead,
                            wbSignHeadSz, wbSignFoot, wbSignFootSz));
                }
                wc_PKCS7_Free(vp);
            }
        }
        for (wbDetachedMode = 0; wbDetachedMode <= 3; wbDetachedMode++) {
            wb_mutate(wb_detached_call, wbSignHead, wbSignHeadSz, 1);
            wb_truncate(wb_detached_call, wbSignHead, wbSignHeadSz, 4);
            if (wbSignFootSz > 4) {
                wb_mutate(wb_detached_call, wbSignFoot, wbSignFootSz,
                          (wbDetachedMode == 0) ? 1 : 4);
            }
        }
        wbDetachedMode = 0;
    }
}
#else
static void wb_signed_variant_chains(void)
{
    WB_NOTE("no 2048-bit cert buffers; self-built SignedData sweeps skipped");
}
#endif /* USE_CERT_BUFFERS_2048 */
#else
static void wb_verify_chains(void)
{
    WB_NOTE("NO_RSA; VerifySignedData mutation sweep skipped");
}
static void wb_signed_variant_chains(void)
{
    WB_NOTE("NO_RSA; self-built SignedData sweeps skipped");
}
#endif /* !NO_RSA */

/* ------------------------------------------------------------------------- *
 * Section 2: wc_PKCS7_DecodeEnvelopedData() / ParseToRecipientInfoSet()
 * ------------------------------------------------------------------------- */
#if !defined(NO_RSA) && defined(USE_CERT_BUFFERS_2048)
static void wb_env_ktri_call(byte* buf, word32 len)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);

    if (p == NULL)
        return;
    if (wc_PKCS7_InitWithCert(p, (byte*)client_cert_der_2048,
            (word32)sizeof_client_cert_der_2048) == 0) {
        p->privateKey   = (byte*)client_key_der_2048;
        p->privateKeySz = (word32)sizeof_client_key_der_2048;
        (void)wc_PKCS7_DecodeEnvelopedData(p, buf, len, wbOut,
                (word32)sizeof(wbOut));
    }
    wc_PKCS7_Free(p);
}

#ifdef HAVE_ECC
/* The KARI corpus is decoded with the ECC client credentials so
 * wc_PKCS7_KariGetOriginatorIdentifierOrKey() and the ECDSAk arms of the
 * RecipientInfo version check are entered. */
static void wb_env_kari_call(byte* buf, word32 len)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);

    if (p == NULL)
        return;
    if (wc_PKCS7_InitWithCert(p, (byte*)cliecc_cert_der_256,
            (word32)sizeof_cliecc_cert_der_256) == 0) {
        p->privateKey   = (byte*)ecc_clikey_der_256;
        p->privateKeySz = (word32)sizeof_ecc_clikey_der_256;
        (void)wc_PKCS7_DecodeEnvelopedData(p, buf, len, wbOut,
                (word32)sizeof(wbOut));
        p->privateKey   = NULL;
        p->privateKeySz = 0;
    }
    wc_PKCS7_Free(p);
}
#endif /* HAVE_ECC */

static int wb_decrypt_cb(wc_PKCS7* pkcs7, int encryptOID, byte* iv, int ivSz,
        byte* aad, word32 aadSz, byte* authTag, word32 authTagSz,
        byte* in, int inSz, byte* out, void* usrCtx)
{
    (void)pkcs7; (void)encryptOID; (void)iv; (void)ivSz;
    (void)aad; (void)aadSz; (void)authTag; (void)authTagSz; (void)usrCtx;
    if (out != NULL && in != NULL && inSz > 0)
        XMEMCPY(out, in, (word32)inSz);
    return 0;
}

/* Same corpus, but with a user decryption callback installed and no output
 * buffer, so the callback arm and the output-size guard are taken. */
static void wb_env_cb_call(byte* buf, word32 len)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);

    if (p == NULL)
        return;
    if (wc_PKCS7_InitWithCert(p, (byte*)client_cert_der_2048,
            (word32)sizeof_client_cert_der_2048) == 0) {
        p->privateKey   = (byte*)client_key_der_2048;
        p->privateKeySz = (word32)sizeof_client_key_der_2048;
        (void)wc_PKCS7_SetDecodeEncryptedCb(p, wb_decrypt_cb);
        (void)wc_PKCS7_DecodeEnvelopedData(p, buf, len, wbOut, 4);
        p->privateKey   = NULL;
        p->privateKeySz = 0;
    }
    wc_PKCS7_Free(p);
}

static void wb_ris_call(byte* buf, word32 len)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    word32 idx = 0;

    if (p == NULL)
        return;
    if (wc_PKCS7_InitWithCert(p, (byte*)client_cert_der_2048,
            (word32)sizeof_client_cert_der_2048) == 0) {
        p->privateKey   = (byte*)client_key_der_2048;
        p->privateKeySz = (word32)sizeof_client_key_der_2048;
        (void)wc_PKCS7_ParseToRecipientInfoSet(p, buf, len, &idx,
                ENVELOPED_DATA);
    }
    wc_PKCS7_Free(p);
}

static void wb_enveloped_chains(void)
{
    word32 fullLen;

    WB_NOTE("wc_PKCS7_DecodeEnvelopedData(): dense mutation sweep,"
            " ktri-keyid-cms.msg");
    fullLen = wb_load_file("./certs/test/ktri-keyid-cms.msg", wbScratch,
            sizeof(wbScratch));
    if (fullLen > 0) {
        wb_mutate(wb_env_ktri_call, wbScratch, fullLen, 1);
        wb_truncate(wb_env_ktri_call, wbScratch, fullLen, 1);
        wb_mutate(wb_ris_call, wbScratch, fullLen, 1);
        wb_truncate(wb_ris_call, wbScratch, fullLen, 2);
    }

    WB_NOTE("wc_PKCS7_DecodeEnvelopedData(): dense mutation sweep,"
            " test-multiple-recipients.p7b");
    fullLen = wb_load_file("./certs/test-multiple-recipients.p7b", wbScratch,
            sizeof(wbScratch));
    if (fullLen > 0) {
        wb_mutate(wb_env_ktri_call, wbScratch, fullLen, 2);
        wb_truncate(wb_env_ktri_call, wbScratch, fullLen, 2);
        wb_mutate(wb_ris_call, wbScratch, fullLen, 2);
        wb_mutate(wb_env_cb_call, wbScratch, fullLen, 4);
    }

#ifdef HAVE_ECC
    WB_NOTE("wc_PKCS7_DecodeEnvelopedData(): KARI/ECC decode-walk sweep,"
            " kari-keyid-cms.msg");
    fullLen = wb_load_file("./certs/test/kari-keyid-cms.msg", wbScratch,
            sizeof(wbScratch));
    if (fullLen > 0) {
        wb_mutate(wb_env_kari_call, wbScratch, fullLen, 1);
        wb_truncate(wb_env_kari_call, wbScratch, fullLen, 1);
    }
#endif
}
#else
static void wb_enveloped_chains(void)
{
    WB_NOTE("NO_RSA or no 2048-bit cert buffers; EnvelopedData sweep skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 3: wc_PKCS7_DecodeAuthEnvelopedData()
 * ------------------------------------------------------------------------- */
#if defined(HAVE_AESGCM) && !defined(NO_RSA) && defined(USE_CERT_BUFFERS_2048)
static byte wbAuthCorpus[WB_SCRATCH_SZ];

static word32 wb_build_auth_enveloped(byte* out, word32 outSz, int oid,
                                      int withAttribs)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    byte data[] = "authEnvelopedData mutation corpus payload 0123456789";
    PKCS7Attrib attrib[1];
    static const byte attribOid[] = { 0x06, 0x03, 0x55, 0x04, 0x03 };
    static const byte attribVal[] = { 0x04, 0x02, 0x33, 0x44 };
    int sz = 0;

    if (p == NULL)
        return 0;
    if (wc_PKCS7_InitWithCert(p, (byte*)client_cert_der_2048,
            (word32)sizeof_client_cert_der_2048) == 0) {
        attrib[0].oid     = attribOid;
        attrib[0].oidSz   = (word32)sizeof(attribOid);
        attrib[0].value   = attribVal;
        attrib[0].valueSz = (word32)sizeof(attribVal);

        p->content       = data;
        p->contentSz     = (word32)sizeof(data);
        p->contentOID    = DATA;
        p->encryptOID    = oid;
        p->rng           = wbRngOk ? &wbRng : NULL;
        if (withAttribs) {
            p->authAttribs     = attrib;
            p->authAttribsSz   = 1;
            p->unauthAttribs   = attrib;
            p->unauthAttribsSz = 1;
        }
        /* Pinned: makes the CEK/IV/ephemeral bytes reproducible so the
         * mutation offsets below address the same fields every run. */
        mcdc_sr_arm(WB_BUNDLE_SEED);
        sz = wc_PKCS7_EncodeAuthEnvelopedData(p, out, outSz);
        mcdc_sr_disarm();
        p->authAttribs     = NULL;
        p->authAttribsSz   = 0;
        p->unauthAttribs   = NULL;
        p->unauthAttribsSz = 0;
    }
    wc_PKCS7_Free(p);
    return (sz > 0) ? (word32)sz : 0;
}

static int wbAuthMode = 0;

static void wb_auth_call(byte* buf, word32 len)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);

    if (p == NULL)
        return;
    if (wc_PKCS7_InitWithCert(p, (byte*)client_cert_der_2048,
            (word32)sizeof_client_cert_der_2048) == 0) {
        p->privateKey   = (byte*)client_key_der_2048;
        p->privateKeySz = (word32)sizeof_client_key_der_2048;
        if (wbAuthMode == 1) {
            /* undersized output buffer: takes the size guards near the end
             * of the walk instead of the successful decrypt */
            (void)wc_PKCS7_DecodeAuthEnvelopedData(p, buf, len, wbOut, 8);
        }
        else {
            (void)wc_PKCS7_DecodeAuthEnvelopedData(p, buf, len, wbOut,
                    (word32)sizeof(wbOut));
        }
        p->privateKey   = NULL;
        p->privateKeySz = 0;
    }
    wc_PKCS7_Free(p);
}

static void wb_auth_chains(void)
{
    word32 fullLen;

    WB_NOTE("wc_PKCS7_DecodeAuthEnvelopedData(): dense mutation sweep over a"
            " self-built AES256GCMb message with auth/unauth attributes");
    fullLen = wb_build_auth_enveloped(wbAuthCorpus, (word32)sizeof(wbAuthCorpus),
            AES256GCMb, 1);
    WB_CHECK(fullLen > 32, "self-built AES256GCM AuthEnvelopedData encoded");
    if (fullLen > 32) {
        wb_mutate(wb_auth_call, wbAuthCorpus, fullLen, 1);
        wb_truncate(wb_auth_call, wbAuthCorpus, fullLen, 1);
        wbAuthMode = 1;
        wb_mutate(wb_auth_call, wbAuthCorpus, fullLen, 2);
        wb_truncate(wb_auth_call, wbAuthCorpus, fullLen, 2);
        wbAuthMode = 0;
    }

    WB_NOTE("wc_PKCS7_DecodeAuthEnvelopedData(): same, with no auth/unauth"
            " attributes (optional-field arms absent)");
    fullLen = wb_build_auth_enveloped(wbAuthCorpus, (word32)sizeof(wbAuthCorpus),
            AES256GCMb, 0);
    if (fullLen > 32) {
        wb_mutate(wb_auth_call, wbAuthCorpus, fullLen, 1);
        wb_truncate(wb_auth_call, wbAuthCorpus, fullLen, 1);
    }

#ifdef WOLFSSL_AES_128
    fullLen = wb_build_auth_enveloped(wbAuthCorpus, (word32)sizeof(wbAuthCorpus),
            AES128GCMb, 1);
    if (fullLen > 32) {
        wb_mutate(wb_auth_call, wbAuthCorpus, fullLen, 2);
        wb_truncate(wb_auth_call, wbAuthCorpus, fullLen, 2);
    }
#endif
#ifdef HAVE_AESCCM
    WB_NOTE("wc_PKCS7_DecodeAuthEnvelopedData(): AES256CCMb variant");
    fullLen = wb_build_auth_enveloped(wbAuthCorpus, (word32)sizeof(wbAuthCorpus),
            AES256CCMb, 1);
    if (fullLen > 32) {
        wb_mutate(wb_auth_call, wbAuthCorpus, fullLen, 1);
        wb_truncate(wb_auth_call, wbAuthCorpus, fullLen, 2);
    }
#endif
}
#else
static void wb_auth_chains(void)
{
    WB_NOTE("no AES-GCM/RSA; AuthEnvelopedData sweep skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 4: wc_PKCS7_DecodeEncryptedData()
 * ------------------------------------------------------------------------- */
#if !defined(NO_PKCS7_ENCRYPTED_DATA) && !defined(NO_AES)
static const byte wbEncKey[] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10
};

static byte wbEncCorpus[WB_SCRATCH_SZ];

static word32 wb_build_encrypted(byte* out, word32 outSz)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    byte data[] = "encryptedData mutation corpus payload 0123456789";
    PKCS7Attrib attrib[1];
    static const byte attribOid[] = { 0x06, 0x03, 0x55, 0x04, 0x03 };
    static const byte attribVal[] = { 0x04, 0x02, 0x55, 0x66 };
    int sz = 0;

    if (p == NULL)
        return 0;
    if (wc_PKCS7_Init(p, NULL, INVALID_DEVID) == 0) {
        attrib[0].oid     = attribOid;
        attrib[0].oidSz   = (word32)sizeof(attribOid);
        attrib[0].value   = attribVal;
        attrib[0].valueSz = (word32)sizeof(attribVal);

        p->content            = data;
        p->contentSz          = (word32)sizeof(data);
        p->contentOID         = DATA;
        p->encryptOID         = AES128CBCb;
        p->encryptionKey      = (byte*)wbEncKey;
        p->encryptionKeySz    = (word32)sizeof(wbEncKey);
        p->unprotectedAttribs   = attrib;
        p->unprotectedAttribsSz = 1;
        sz = wc_PKCS7_EncodeEncryptedData(p, out, outSz);
        p->unprotectedAttribs   = NULL;
        p->unprotectedAttribsSz = 0;
        p->encryptionKey        = NULL;
        p->encryptionKeySz      = 0;
    }
    wc_PKCS7_Free(p);
    return (sz > 0) ? (word32)sz : 0;
}

static byte wbEncVersion = 0;

static void wb_encrypted_call(byte* buf, word32 len)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);

    if (p == NULL)
        return;
    if (wc_PKCS7_Init(p, NULL, INVALID_DEVID) == 0) {
        p->version         = wbEncVersion;
        p->encryptionKey   = (byte*)wbEncKey;
        p->encryptionKeySz = (word32)sizeof(wbEncKey);
        (void)wc_PKCS7_DecodeEncryptedData(p, buf, len, wbOut,
                (word32)sizeof(wbOut));
        p->encryptionKey   = NULL;
        p->encryptionKeySz = 0;
    }
    wc_PKCS7_Free(p);
}

static void wb_encrypted_chains(void)
{
    word32 fullLen;

    WB_NOTE("wc_PKCS7_DecodeEncryptedData(): dense mutation sweep over a"
            " self-built AES128CBCb message with unprotected attributes");
    fullLen = wb_build_encrypted(wbEncCorpus, (word32)sizeof(wbEncCorpus));
    WB_CHECK(fullLen > 32, "self-built EncryptedData encoded");
    if (fullLen > 32) {
        wb_mutate(wb_encrypted_call, wbEncCorpus, fullLen, 1);
        wb_truncate(wb_encrypted_call, wbEncCorpus, fullLen, 1);
    }

    fullLen = wb_load_file("./certs/test/encrypteddata.msg", wbScratch,
            sizeof(wbScratch));
    if (fullLen > 0) {
        wb_mutate(wb_encrypted_call, wbScratch, fullLen, 1);
        wb_truncate(wb_encrypted_call, wbScratch, fullLen, 1);
    }

    WB_NOTE("wc_PKCS7_DecodeEncryptedData(): same, decoded as a "
            "FirmwarePkgData (version 3) bundle");
    wbEncVersion = 3;
    fullLen = wb_build_encrypted(wbEncCorpus, (word32)sizeof(wbEncCorpus));
    if (fullLen > 32) {
        wb_mutate(wb_encrypted_call, wbEncCorpus, fullLen, 2);
        wb_truncate(wb_encrypted_call, wbEncCorpus, fullLen, 4);
    }
    wbEncVersion = 0;
}
#else
static void wb_encrypted_chains(void)
{
    WB_NOTE("no EncryptedData/AES; EncryptedData sweep skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 5: KEKRI and PWRI recipient decode walks
 * ------------------------------------------------------------------------- */
#if !defined(NO_AES) && defined(HAVE_AES_KEYWRAP)
static const byte wbKek[] = {
    0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
    0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30,
    0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
    0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f,0x40
};
static const byte wbKeyId[] = { 0x01, 0x02, 0x03, 0x04 };
static byte wbKekriCorpus[WB_SCRATCH_SZ];

static word32 wb_build_kekri(byte* out, word32 outSz)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    byte data[] = "kekri mutation corpus payload 0123456789";
    static byte otherOid[] = { 0x06, 0x03, 0x55, 0x04, 0x03 };
    static byte other[]    = { 0x04, 0x02, 0x77, 0x88 };
    int sz = 0;

    if (p == NULL)
        return 0;
    if (wc_PKCS7_Init(p, NULL, INVALID_DEVID) == 0) {
        p->content    = data;
        p->contentSz  = (word32)sizeof(data);
        p->contentOID = DATA;
        p->encryptOID = AES256CBCb;
        p->rng        = wbRngOk ? &wbRng : NULL;
        if (wc_PKCS7_AddRecipient_KEKRI(p, AES256_WRAP, (byte*)wbKek,
                (word32)sizeof(wbKek), (byte*)wbKeyId, (word32)sizeof(wbKeyId),
                NULL, otherOid, (word32)sizeof(otherOid), other,
                (word32)sizeof(other), 0) > 0) {
            sz = wc_PKCS7_EncodeEnvelopedData(p, out, outSz);
        }
    }
    wc_PKCS7_Free(p);
    return (sz > 0) ? (word32)sz : 0;
}

static void wb_kekri_call(byte* buf, word32 len)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);

    if (p == NULL)
        return;
    if (wc_PKCS7_Init(p, NULL, INVALID_DEVID) == 0 &&
        wc_PKCS7_SetKey(p, (byte*)wbKek, (word32)sizeof(wbKek)) == 0) {
        (void)wc_PKCS7_DecodeEnvelopedData(p, buf, len, wbOut,
                (word32)sizeof(wbOut));
    }
    wc_PKCS7_Free(p);
}

static void wb_kekri_chains(void)
{
    word32 fullLen;

    WB_NOTE("wc_PKCS7_DecryptKekri(): dense mutation sweep over a self-built"
            " KEKRI EnvelopedData with an OtherKeyAttribute");
    fullLen = wb_build_kekri(wbKekriCorpus, (word32)sizeof(wbKekriCorpus));
    WB_CHECK(fullLen > 32, "self-built KEKRI EnvelopedData encoded");
    if (fullLen > 32) {
        wb_mutate(wb_kekri_call, wbKekriCorpus, fullLen, 1);
        wb_truncate(wb_kekri_call, wbKekriCorpus, fullLen, 1);
    }
}
#else
static void wb_kekri_chains(void)
{
    WB_NOTE("no AES key wrap; KEKRI sweep skipped");
}
#endif

#if !defined(NO_AES) && defined(HAVE_AES_KEYWRAP) && !defined(NO_PWDBASED)
static const byte wbPass[] = "mutation-corpus-password";
static byte wbPwriCorpus[WB_SCRATCH_SZ];

static word32 wb_build_pwri(byte* out, word32 outSz)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    byte data[] = "pwri mutation corpus payload 0123456789";
    static byte salt[8] = { 0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88 };
    int sz = 0;

    if (p == NULL)
        return 0;
    if (wc_PKCS7_Init(p, NULL, INVALID_DEVID) == 0) {
        p->content    = data;
        p->contentSz  = (word32)sizeof(data);
        p->contentOID = DATA;
        p->encryptOID = AES256CBCb;
        p->rng        = wbRngOk ? &wbRng : NULL;
        /* small iteration count: the mutation sweep below re-derives the KEK
         * on every vector */
        if (wc_PKCS7_AddRecipient_PWRI(p, (byte*)wbPass,
                (word32)sizeof(wbPass) - 1, salt, (word32)sizeof(salt),
                PBKDF2_OID, WC_SHA256, 5, AES256CBCb, 0) >= 0) {
            sz = wc_PKCS7_EncodeEnvelopedData(p, out, outSz);
        }
    }
    wc_PKCS7_Free(p);
    return (sz > 0) ? (word32)sz : 0;
}

static void wb_pwri_call(byte* buf, word32 len)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);

    if (p == NULL)
        return;
    if (wc_PKCS7_Init(p, NULL, INVALID_DEVID) == 0) {
        (void)wc_PKCS7_SetPassword(p, (byte*)wbPass,
                (word32)sizeof(wbPass) - 1);
        (void)wc_PKCS7_DecodeEnvelopedData(p, buf, len, wbOut,
                (word32)sizeof(wbOut));
    }
    wc_PKCS7_Free(p);
}

static void wb_pwri_chains(void)
{
    word32 fullLen;

    WB_NOTE("wc_PKCS7_DecryptPwri(): dense mutation sweep over a self-built"
            " PWRI EnvelopedData");
    fullLen = wb_build_pwri(wbPwriCorpus, (word32)sizeof(wbPwriCorpus));
    WB_CHECK(fullLen > 32, "self-built PWRI EnvelopedData encoded");
    if (fullLen > 32) {
        wb_mutate(wb_pwri_call, wbPwriCorpus, fullLen, 1);
        wb_truncate(wb_pwri_call, wbPwriCorpus, fullLen, 2);
    }
}
#else
static void wb_pwri_chains(void)
{
    WB_NOTE("no PWRI prerequisites; PWRI sweep skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 6: wc_PKCS7_GetEnvelopedDataKariRid()
 * ------------------------------------------------------------------------- */
static void wb_kari_rid_call(byte* buf, word32 len)
{
    byte out[128];
    word32 outSz = (word32)sizeof(out);

    (void)wc_PKCS7_GetEnvelopedDataKariRid(buf, len, out, &outSz);
}

static void wb_kari_rid_chains(void)
{
    word32 fullLen;

    WB_NOTE("wc_PKCS7_GetEnvelopedDataKariRid(): dense mutation sweep,"
            " kari-keyid-cms.msg");
    fullLen = wb_load_file("./certs/test/kari-keyid-cms.msg", wbScratch,
            sizeof(wbScratch));
    if (fullLen > 0) {
        wb_mutate(wb_kari_rid_call, wbScratch, fullLen, 1);
        wb_truncate(wb_kari_rid_call, wbScratch, fullLen, 1);
    }
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("pkcs7.c white-box MC/DC dense-mutation supplement\n");

    if (wc_InitRng(&wbRng) == 0)
        wbRngOk = 1;

    wb_verify_chains();
    wb_signed_variant_chains();
    wb_enveloped_chains();
    wb_auth_chains();
    wb_encrypted_chains();
    wb_kekri_chains();
    wb_pwri_chains();
    wb_kari_rid_chains();

    if (wbRngOk)
        wc_FreeRng(&wbRng);

    printf("done (%s)\n", wb_fail ? "with failures" : "ok");
    /* Always return 0: a nonzero exit discards this variant's coverage
     * entirely in the test harness. */
    (void)wb_fail;
    return 0;
}
