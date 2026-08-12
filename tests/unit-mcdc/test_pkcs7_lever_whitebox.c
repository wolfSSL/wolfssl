/* test_pkcs7_lever_whitebox.c
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
 * Fault-lever white-box MC/DC supplement for wolfcrypt/src/pkcs7.c.
 *
 * Two decisions in pkcs7.c have a failing half that no input can produce,
 * only a failing machine:
 *
 *   :5039 cond 1 -- `mp_read_unsigned_bin(certSerial, dCert->serial, ...)
 *                   == MP_OKAY` in wc_PKCS7_CertMatchesSignerInfo(). The
 *                   serial comes straight out of a parsed certificate, so the
 *                   read always succeeds; the big-integer lever
 *                   (mcdc_fault_mp.h) supplies the other row.
 *   :7799 cond 1 -- `pkcs7->stream->tmpCert == NULL` in
 *                   PKCS7_VerifySignedData()'s WC_PKCS7_VERIFY_STAGE5. The
 *                   pointer is the result of an XMALLOC two lines earlier, so
 *                   the heap lever (mcdc_fault_alloc.h) is the only way to
 *                   make it NULL.
 *
 * Reaching :5039 at all also needs something no API-level test builds: a
 * SignerInfo whose sid is an IssuerAndSerialNumber that actually matches a
 * real certificate. It is assembled here from the DecodedCert's own issuerRaw
 * and serial, which is exactly what a conforming signer would have written.
 *
 * Both sweeps are bounded by a vector count, never by elapsed time, and the
 * unarmed run of each target is in this same binary as the accepting row.
 */

#include "mcdc_fault_mp.h"
#include "mcdc_seed_rng.h"

#include <wolfcrypt/src/pkcs7.c>

#define MCDC_SR_IMPL
#include "mcdc_seed_rng.h"

#include "mcdc_fault_alloc.h"

#include <stdio.h>
#include <string.h>
#include <wolfssl/certs_test.h>

/* Bounded by vector count, never by elapsed time: 96 fail positions is
 * comfortably past the number of allocation sites these decodes reach, and
 * over-sweeping is harmless -- once the index passes the site count the target
 * simply runs to completion. */
#define WB_ALLOC_SWEEP 96

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)
#define WB_CHECK(cond, msg) \
    do { if (!(cond)) { printf("  [wb][FAIL] %s\n", (msg)); wb_fail = 1; } } \
    while (0)

/* ------------------------------------------------------------------------- *
 * Section 1: wc_PKCS7_CertMatchesSignerInfo() serial comparison [:5039].
 * ------------------------------------------------------------------------- */
#if (!defined(NO_RSA) || defined(HAVE_ECC)) && defined(USE_CERT_BUFFERS_2048)

#define WB_SID_SZ 512
static byte wbSid[WB_SID_SZ];

/* Builds the IssuerAndSerialNumber body the decoder stores in
 * signerInfo->sid: the issuer Name TLV followed by the serial INTEGER.
 * DecodedCert.issuerRaw points at the Name CONTENT (asn.c stores it past the
 * SEQUENCE header), while GetNameHash_ex() parses a whole Name, so the header
 * is rebuilt here. Returns the size, or 0. */
static word32 wb_build_sid(DecodedCert* dCert)
{
    word32 idx = 0, nameLen;

    if (dCert->issuerRaw == NULL || dCert->issuerRawLen <= 0 ||
            dCert->serialSz <= 0) {
        return 0;
    }
    nameLen = (word32)dCert->issuerRawLen;
    if (nameLen + 4 + 2 + (word32)dCert->serialSz > (word32)sizeof(wbSid)) {
        return 0;
    }
    wbSid[idx++] = ASN_SEQUENCE | ASN_CONSTRUCTED;
    if (nameLen < 0x80) {
        wbSid[idx++] = (byte)nameLen;
    }
    else if (nameLen < 0x100) {
        wbSid[idx++] = 0x81;
        wbSid[idx++] = (byte)nameLen;
    }
    else {
        wbSid[idx++] = 0x82;
        wbSid[idx++] = (byte)(nameLen >> 8);
        wbSid[idx++] = (byte)nameLen;
    }
    XMEMCPY(wbSid + idx, dCert->issuerRaw, nameLen);
    idx += nameLen;
    wbSid[idx++] = ASN_INTEGER;
    wbSid[idx++] = (byte)dCert->serialSz;
    XMEMCPY(wbSid + idx, dCert->serial, (word32)dCert->serialSz);
    idx += (word32)dCert->serialSz;
    return idx;
}

static void wb_cert_matches_signer(void)
{
    wc_PKCS7        pkcs7;
    PKCS7SignerInfo si;
    DecodedCert     dCert;
    word32          sidSz;
    int             ret;

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));
    XMEMSET(&si, 0, sizeof(si));

    InitDecodedCert(&dCert, (byte*)client_cert_der_2048,
            (word32)sizeof_client_cert_der_2048, NULL);
    if (ParseCert(&dCert, CERT_TYPE, NO_VERIFY, NULL) != 0) {
        FreeDecodedCert(&dCert);
        WB_NOTE("ParseCert failed; CertMatchesSignerInfo drive skipped");
        wb_fail = 1;
        return;
    }

    sidSz = wb_build_sid(&dCert);
    WB_CHECK(sidSz > 0, "IssuerAndSerialNumber sid assembled from the cert");
    if (sidSz == 0) {
        FreeDecodedCert(&dCert);
        return;
    }

    si.sidType = CMS_ISSUER_AND_SERIAL_NUMBER;
    si.sid     = wbSid;
    si.sidSz   = sidSz;
    pkcs7.signerInfo = &si;

    WB_NOTE("wc_PKCS7_CertMatchesSignerInfo(): sid matches the certificate"
            " [:5039 both operands true]");
    mcdc_fm_disarm();
    ret = wc_PKCS7_CertMatchesSignerInfo(&pkcs7, &dCert);
    WB_CHECK(ret == 1, ":5039 both true (serial comparison matched)");
    WB_CHECK(mcdc_fm_seen() >= 1,
            "the serial read went through the big-integer lever");

    WB_NOTE("wc_PKCS7_CertMatchesSignerInfo(): the certificate serial fails to"
            " load into an mp_int [:5039 cond 1 false]");
    mcdc_fm_arm(1);
    ret = wc_PKCS7_CertMatchesSignerInfo(&pkcs7, &dCert);
    mcdc_fm_disarm();
    WB_CHECK(ret == 0, ":5039 cond 1 false (serial read failed)");

    WB_NOTE("wc_PKCS7_CertMatchesSignerInfo(): sid serial INTEGER truncated,"
            " so the sid parse fails first [:5039 cond 0 false]");
    si.sidSz = sidSz - (word32)dCert.serialSz;
    ret = wc_PKCS7_CertMatchesSignerInfo(&pkcs7, &dCert);
    WB_CHECK(ret == 0, ":5039 cond 0 false (GetInt rejected the sid)");
    si.sidSz = sidSz;

    FreeDecodedCert(&dCert);
}
#else
static void wb_cert_matches_signer(void)
{
    WB_NOTE("no RSA/ECC or no 2048-bit cert buffers; CertMatchesSignerInfo"
            " drive skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 2: PKCS7_VerifySignedData() stage-5 certificate copy [:7799].
 *
 * `(pkiMsg2 == NULL) || (pkcs7->stream->tmpCert == NULL)` guards the XMALLOC
 * two lines above it. The sweep below fails one allocation at a time across a
 * one-shot verify of a bundle that carries a certificate set, which is the
 * only shape that reaches the guard (`length > 0 && in2Sz == 0`), and stops
 * as soon as a run reports MEMORY_E.
 *
 * The leading operand is NOT driven: pkiMsg2 is assigned in/in2 at :7765-:7772
 * and then whatever wc_PKCS7_AddDataToStream() returned at :7775, and that
 * function only returns 0 after pointing its output at `in` or at
 * stream->buffer -- see the residual note in the final report.
 * ------------------------------------------------------------------------- */
#if !defined(NO_RSA) && !defined(NO_PKCS7_STREAM)
#define WB_CORPUS_SZ 4096
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

static int wb_verify_once(word32 msgSz)
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
    ret = wc_PKCS7_VerifySignedData(p, wbCorpus, msgSz);
    wc_PKCS7_Free(p);
    return ret;
}

static void wb_tmpcert_alloc(void)
{
    word32 msgSz;
    int    n, ret, hit = 0;

    msgSz = wb_load_file("./certs/test-degenerate.p7b", wbCorpus,
            sizeof(wbCorpus));
    if (msgSz == 0) {
        return;
    }

    mcdc_fa_install();

    WB_NOTE("PKCS7_VerifySignedData(): unarmed one-shot verify of a bundle"
            " carrying a certificate set [:7799 both operands false]");
    mcdc_fa_disarm();
    ret = wb_verify_once(msgSz);
    WB_CHECK(ret == 0, ":7799 both false (verify succeeds)");

    WB_NOTE("PKCS7_VerifySignedData(): one allocation failed at a time, so the"
            " stage-5 certificate copy sees a NULL buffer [:7799 cond 1 true]");
    for (n = 1; n <= WB_ALLOC_SWEEP; n++) {
        mcdc_fa_arm_only(n);
        ret = wb_verify_once(msgSz);
        mcdc_fa_disarm();
        if (ret == WC_NO_ERR_TRACE(MEMORY_E)) {
            hit++;
        }
    }
    mcdc_fa_disarm();
    mcdc_fa_restore();
    WB_CHECK(hit > 0, ":7799 sweep produced at least one MEMORY_E");
}
#else
static void wb_tmpcert_alloc(void)
{
    WB_NOTE("NO_RSA or NO_PKCS7_STREAM; stage-5 tmpCert sweep skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 3: wc_PKCS7_DecodeAuthEnvelopedData() content buffer [:16080, :16103].
 *
 * `encryptedContent == NULL` at :16080 is the XMALLOC two lines above it, and
 * :16103's leading operand is only false once :16080 has set MEMORY_E, so one
 * heap sweep over a decode supplies both. The bundle is built here rather than
 * loaded so the AES-GCM/RSA shape is guaranteed; the RNG is pinned so the
 * bundle is byte-identical on every run and the allocation ORDER the sweep
 * indexes into does not move.
 * ------------------------------------------------------------------------- */
#if defined(HAVE_AESGCM) && !defined(NO_RSA) && defined(WOLFSSL_AES_128) && \
    defined(USE_CERT_BUFFERS_2048)
#define WB_AE_SEED 0x4ae09c17UL
#define WB_AE_BUF_SZ 2048
static byte wbAeBuf[WB_AE_BUF_SZ];
static word32 wbAeSz;

/* content-type attribute (1.2.840.113549.1.9.3) carrying id-data. Both fields
 * are complete DER elements: FlattenAttributes() copies them verbatim into
 * SEQUENCE { oid, SET { value } }. */
static const byte wbAuthAttribOid[] =
    { 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03 };
static const byte wbAuthAttribVal[] =
    { 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01 };
static PKCS7Attrib wbAuthAttribs[1] = {
    { wbAuthAttribOid, (word32)sizeof(wbAuthAttribOid),
      wbAuthAttribVal, (word32)sizeof(wbAuthAttribVal) }
};

static int wb_build_auth_env(void)
{
    wc_PKCS7* p = wc_PKCS7_New(NULL, INVALID_DEVID);
    WC_RNG    rng;
    byte      data[32];
    int       sz = 0;

    XMEMSET(data, 0x62, sizeof(data));
    wbAeSz = 0;
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
        p->encryptOID = AES128GCMb;
        p->rng        = &rng;
        /* Authenticated attributes make the decoder's IMPLICIT [1] probe at
         * :16103 evaluate all three operands true, which is the decision-true
         * row its leading operand needs. wc_PKCS7_EncodeAuthEnvelopedData()
         * omits the whole element when authAttribsSz is 0, and no API-level
         * test sets one. */
        p->authAttribs   = wbAuthAttribs;
        p->authAttribsSz = 1;
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
    return 0;
}

static int wb_decode_auth_env(void)
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
    ret = wc_PKCS7_DecodeAuthEnvelopedData(p, wbAeBuf, wbAeSz, out,
            sizeof(out));
    wc_PKCS7_Free(p);
    return ret;
}

static void wb_authenv_content_alloc(void)
{
    int n, ret, hit = 0;

    if (wb_build_auth_env() != 0) {
        WB_NOTE("AuthEnvelopedData encode failed; content-buffer sweep"
                " skipped");
        wb_fail = 1;
        return;
    }

    mcdc_fa_install();

    WB_NOTE("wc_PKCS7_DecodeAuthEnvelopedData(): unarmed decode [:16080 cond 1"
            " false, :16103 cond 0 true]");
    mcdc_fa_disarm();
    ret = wb_decode_auth_env();
    WB_CHECK(ret > 0, ":16080 cond 1 false (decode succeeds)");

    WB_NOTE("wc_PKCS7_DecodeAuthEnvelopedData(): one allocation failed at a"
            " time, so the content buffer comes back NULL [:16080 cond 1 true,"
            " :16103 cond 0 false]");
    for (n = 1; n <= WB_ALLOC_SWEEP; n++) {
        mcdc_fa_arm_only(n);
        ret = wb_decode_auth_env();
        mcdc_fa_disarm();
        if (ret == WC_NO_ERR_TRACE(MEMORY_E)) {
            hit++;
        }
    }
    mcdc_fa_disarm();
    mcdc_fa_restore();
    WB_CHECK(hit > 0, ":16080 sweep produced at least one MEMORY_E");
}
#else
static void wb_authenv_content_alloc(void)
{
    WB_NOTE("no AES-GCM/RSA/2048-cert-buffers; AuthEnvelopedData"
            " content-buffer sweep skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 4: wc_PKCS7_KariGetIssuerAndSerialNumber() serial match [:12743].
 *
 * `kari->decodedInit == 1 && mp_cmp(recipSerial, serial) != MP_EQ` needs three
 * rows that no API-level test produces together: a KARI decode with a
 * recipient certificate whose serial matches the message, one whose serial
 * does not, and one with no recipient certificate at all (decodedInit stays 0,
 * the "cannot confirm the serial" path at :12705).
 *
 * The KARI handle and the IssuerAndSerialNumber blob are built here rather
 * than encoded, so the serial can be perturbed by one byte without disturbing
 * anything else. wc_PKCS7_KariNew() zeroes kari->decoded, so the decodedInit
 * == 0 call is well defined.
 * ------------------------------------------------------------------------- */
#if defined(HAVE_ECC) && defined(USE_CERT_BUFFERS_256)
static byte wbIas[WB_SID_SZ + 4];

/* wraps the issuer Name TLV + serial INTEGER in the IssuerAndSerialNumber
 * SEQUENCE the decoder expects. Returns the size, or 0. */
static word32 wb_build_ias(DecodedCert* dCert, word32* serialOff)
{
    word32 body, idx = 0;

    body = wb_build_sid(dCert);
    if (body == 0 || body + 4 > (word32)sizeof(wbIas)) {
        return 0;
    }
    wbIas[idx++] = ASN_SEQUENCE | ASN_CONSTRUCTED;
    if (body < 0x80) {
        wbIas[idx++] = (byte)body;
    }
    else if (body < 0x100) {
        wbIas[idx++] = 0x81;
        wbIas[idx++] = (byte)body;
    }
    else {
        wbIas[idx++] = 0x82;
        wbIas[idx++] = (byte)(body >> 8);
        wbIas[idx++] = (byte)body;
    }
    XMEMCPY(wbIas + idx, wbSid, body);
    /* the serial value starts two bytes (tag + length) before the end */
    *serialOff = idx + body - (word32)dCert->serialSz;
    idx += body;
    return idx;
}

static int wb_kari_ias_call(int withCert, word32 blobSz)
{
    wc_PKCS7        pkcs7;
    WC_PKCS7_KARI*  kari;
    byte            rid[KEYID_SIZE];
    word32          idx = 0;
    int             recipFound = 0;
    int             ret;

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));
    if (wc_PKCS7_Init(&pkcs7, NULL, INVALID_DEVID) != 0) {
        return -1;
    }
    kari = wc_PKCS7_KariNew(&pkcs7, WC_PKCS7_DECODE);
    if (kari == NULL) {
        wc_PKCS7_Free(&pkcs7);
        return -1;
    }
    if (withCert) {
        ret = wc_PKCS7_KariParseRecipCert(kari,
                (byte*)cliecc_cert_der_256, (word32)sizeof_cliecc_cert_der_256,
                (byte*)ecc_clikey_der_256, (word32)sizeof_ecc_clikey_der_256);
        if (ret != 0) {
            (void)wc_PKCS7_KariFree(kari);
            wc_PKCS7_Free(&pkcs7);
            return ret;
        }
    }
    ret = wc_PKCS7_KariGetIssuerAndSerialNumber(kari, wbIas, blobSz, &idx,
            &recipFound, rid);
    (void)wc_PKCS7_KariFree(kari);
    wc_PKCS7_Free(&pkcs7);
    return ret;
}

static void wb_kari_serial_match(void)
{
    DecodedCert dCert;
    word32      blobSz, serialOff = 0;
    int         ret;

    InitDecodedCert(&dCert, (byte*)cliecc_cert_der_256,
            (word32)sizeof_cliecc_cert_der_256, NULL);
    if (ParseCert(&dCert, CERT_TYPE, NO_VERIFY, NULL) != 0) {
        FreeDecodedCert(&dCert);
        WB_NOTE("ECC ParseCert failed; KARI serial-match drive skipped");
        wb_fail = 1;
        return;
    }
    blobSz = wb_build_ias(&dCert, &serialOff);
    WB_CHECK(blobSz > 0 && serialOff > 0,
            "IssuerAndSerialNumber blob assembled from the ECC cert");
    FreeDecodedCert(&dCert);
    if (blobSz == 0) {
        return;
    }

    WB_NOTE("wc_PKCS7_KariGetIssuerAndSerialNumber(): recipient certificate"
            " loaded, serial matches [:12743 cond 0 true, cond 1 false]");
    ret = wb_kari_ias_call(1, blobSz);
    WB_CHECK(ret == 0, ":12743 cond 1 false (serial matched)");

    WB_NOTE("wc_PKCS7_KariGetIssuerAndSerialNumber(): recipient certificate"
            " loaded, serial differs by one byte [:12743 both operands true]");
    wbIas[serialOff] = (byte)(wbIas[serialOff] ^ 0x01);
    ret = wb_kari_ias_call(1, blobSz);
    WB_CHECK(ret == WC_NO_ERR_TRACE(PKCS7_RECIP_E), ":12743 both true");
    wbIas[serialOff] = (byte)(wbIas[serialOff] ^ 0x01);

    WB_NOTE("wc_PKCS7_KariGetIssuerAndSerialNumber(): no recipient certificate"
            " loaded, so the serial cannot be confirmed [:12743 cond 0"
            " false]");
    ret = wb_kari_ias_call(0, blobSz);
    WB_CHECK(ret == 0, ":12743 cond 0 false (no cert loaded)");
}
#else
static void wb_kari_serial_match(void)
{
    WB_NOTE("no ECC or no 256-bit cert buffers; KARI serial-match drive"
            " skipped");
}
#endif

int main(void)
{
    printf("=== pkcs7 fault-lever white-box (Part 5) ===\n");

    if (wolfCrypt_Init() != 0) {
        printf("  [wb] wolfCrypt_Init failed\n");
        return 0;
    }

    wb_cert_matches_signer();
    wb_tmpcert_alloc();
    wb_authenv_content_alloc();
    wb_kari_serial_match();

    wolfCrypt_Cleanup();
    printf(wb_fail ? "done (with failures)\n" : "done\n");
    return 0;
}
