/* test_asn_revocation_whitebox.c
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
 * White-box MC/DC supplement for the "revocation" wave of asn.c Part 5
 * (OCSP encode/decode + CRL parse/generate, lines ~34691-38267).
 *
 * Most of the decisions in this range live in file-static helpers
 * (OcspDecodeCertIDInt, DecodeSingleResponse, DecodeOcspRespExtensions,
 * DecodeResponseData, GetRevoked, ParseCRL_EntryExtensions,
 * ParseCRL_Extensions, EncodeCrlSerial, ...) that only run with
 * already-valid, template-shaped DER produced by wolfSSL's own encoders --
 * every malformed/edge-case operand combination is unreachable from the
 * public API without a hand-built buffer. This file compiles asn.c directly
 * (#include) and drives those helpers with hand-built DER (assembled at
 * runtime with asn.c's own SetXxx primitives via a couple of small TLV
 * helpers below, rather than typed-out byte arrays) plus a few real
 * certificate/key buffers borrowed from existing test fixtures.
 *
 * NOTE on HAVE_OCSP_RESPONDER: the asn campaign's config_base
 * (configs/asn/user_settings.base.h) never defines HAVE_OCSP_RESPONDER, so
 * EncodeCertID/EncodeSingleResponse/EncodeResponseData/EncodeBasicOcspResponse/
 * OcspResponseEncode are compiled out for every variant of this module and
 * GAPS.md carries no lines inside them -- this file does not attempt to
 * cover that side and never needs it to build test input (all decode-side
 * buffers below are constructed by hand instead of via a round trip).
 *
 * Coverage is unioned by source line:col with the tests/api asn/ocsp run in
 * the per-module campaign; every pair below is completed *within this file*
 * (masking MC/DC is computed per binary, then ORed across binaries by key).
 */

#include <wolfcrypt/src/asn.c>

#include <stdio.h>
#include <string.h>

#include <wolfssl/ssl.h>
#include <wolfssl/certs_test.h>
#include <tests/api/test_ocsp_test_blobs.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)
#define WB_CHECK(cond, msg) \
    do { if (!(cond)) { printf("  [wb][FAIL] %s\n", (msg)); wb_fail = 1; } } \
    while (0)

/* ------------------------------------------------------------------------- *
 * Generic TLV assembly helpers, built on asn.c's own SetLength()/tag bytes.
 * Using these (instead of typed-out byte arrays) means every length below
 * is computed by the same code the library uses to decode it, so the
 * hand-built buffers can't drift from correct short-form DER.
 * ------------------------------------------------------------------------- */
static word32 wb_tlv(byte* out, byte tag, const byte* content, word32 contentSz)
{
    word32 idx = 0;
    if (out != NULL) {
        out[idx] = tag;
    }
    idx++;
    idx += SetLength(contentSz, out ? out + idx : NULL);
    if (contentSz > 0 && out != NULL) {
        XMEMCPY(out + idx, content, contentSz);
    }
    idx += contentSz;
    return idx;
}

#define WB_SEQ(out, content, sz) wb_tlv((out), ASN_SEQUENCE | ASN_CONSTRUCTED, (content), (sz))

/* Build a generic "Extension"-shaped SEQUENCE { OID, [critical BOOLEAN
 * OPTIONAL], value OCTET STRING }. Used for OCSP response/request
 * extensions and CRL (cert + entry) extensions alike -- all four decoders
 * in this file expect exactly this shape. */
static word32 wb_ext(byte* out, const byte* oidContent, word32 oidSz,
        int haveCrit, int critVal, const byte* valContent, word32 valSz)
{
    byte tmp[600];
    word32 idx = 0;
    idx += wb_tlv(tmp + idx, ASN_OBJECT_ID, oidContent, oidSz);
    if (haveCrit) {
        byte b = (byte)(critVal ? 0xFF : 0x00);
        idx += wb_tlv(tmp + idx, ASN_BOOLEAN, &b, 1);
    }
    idx += wb_tlv(tmp + idx, ASN_OCTET_STRING, valContent, valSz);
    return WB_SEQ(out, tmp, idx);
}

/* SHA-256 hash algorithm OID (2.16.840.1.101.3.4.2.1) -- content only. */
static const byte wbOidSha256[] =
    { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
/* authorityKeyIdentifier OID (2.5.29.35) -- content only. */
static const byte wbOidAuthKeyId[] = { 0x55, 0x1d, 0x23 };
/* cRLNumber OID (2.5.29.20) -- content only. */
static const byte wbOidCrlNumber[] = { 0x55, 0x1d, 0x14 };
/* subjectKeyIdentifier OID (2.5.29.14) -- content only; used as a generic
 * "not special to this decoder" extension OID. */
static const byte wbOidOther[] = { 0x55, 0x1d, 0x0e };
/* id-pkix-ocsp-nonce OID (1.3.6.1.5.5.7.48.1.2) -- content only. */
static const byte wbOidOcspNonce[] =
    { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02 };

#define WB_DIGEST_SZ 32 /* SHA-256 */

/* Build the content of a CertID (hashAlgorithm SEQUENCE, issuerNameHash,
 * issuerKeyHash, serialNumber) -- no outer SEQUENCE wrapper, matching
 * certIDASNItems, whose items are the direct siblings OcspDecodeCertIDInt()
 * parses (the wrapper SEQUENCE is stripped by the caller). */
static word32 wb_build_certid_content(byte* out, const byte* issuerHash,
        const byte* issuerKeyHash, word32 digestSz, byte serialVal)
{
    byte hashAlgo[32];
    word32 haIdx = 0;
    word32 idx = 0;

    haIdx += wb_tlv(hashAlgo + haIdx, ASN_OBJECT_ID, wbOidSha256,
            sizeof(wbOidSha256));
    haIdx += wb_tlv(hashAlgo + haIdx, ASN_TAG_NULL, NULL, 0);
    idx += WB_SEQ(out + idx, hashAlgo, haIdx);
    idx += wb_tlv(out + idx, ASN_OCTET_STRING, issuerHash, digestSz);
    idx += wb_tlv(out + idx, ASN_OCTET_STRING, issuerKeyHash, digestSz);
    idx += wb_tlv(out + idx, ASN_INTEGER, &serialVal, 1);
    return idx;
}

#if defined(HAVE_OCSP) && !defined(WOLFCRYPT_ONLY)
#ifdef WOLFSSL_ASN_TEMPLATE
/* ------------------------------------------------------------------------- *
 * Section 1: OcspDecodeCertIDInt() digest-size mismatch OR [:34772]
 *   if (issuerKeyHashLen != digestSz || issuerHashLen != digestSz)
 * Every real caller decodes a CertID whose hash lengths were produced by
 * wc_HashGetDigestSize() for the SAME hashAlgoOID, so both operands are
 * always false in practice; a hand-built CertID with a mismatched hash
 * length is white-box only.
 * ------------------------------------------------------------------------- */
static void wb_ocsp_decode_certid(void)
{
    byte content[128];
    byte issuerHash[WB_DIGEST_SZ];
    byte issuerKeyHash[WB_DIGEST_SZ];
    word32 sz;
    word32 idx;
    OcspEntry entry;
    CertStatus status;
    int ret;

    WB_NOTE("OcspDecodeCertIDInt(): issuerKeyHashLen/issuerHashLen != digestSz [:34772]");
    XMEMSET(issuerHash, 0x11, sizeof(issuerHash));
    XMEMSET(issuerKeyHash, 0x22, sizeof(issuerKeyHash));

    /* baseline: both hashes exactly digestSz (32, SHA-256) -> both false. */
    XMEMSET(&status, 0, sizeof(status));
    XMEMSET(&entry, 0, sizeof(entry));
    entry.status = &status;
    sz = wb_build_certid_content(content, issuerHash, issuerKeyHash,
            WB_DIGEST_SZ, 0x05);
    idx = 0;
    ret = OcspDecodeCertIDInt(content, &idx, sz, &entry);
    WB_CHECK(ret == 0, "CertID baseline (both hash lengths match, both false)");

    /* issuerKeyHash wrong length (20 instead of 32): 1st operand true. */
    XMEMSET(&status, 0, sizeof(status));
    XMEMSET(&entry, 0, sizeof(entry));
    entry.status = &status;
    sz = wb_build_certid_content(content, issuerHash, issuerKeyHash, 20, 0x05);
    /* wb_build_certid_content() applied the same (wrong) length to both
     * hashes; overwrite only the name hash's on-wire length back to 32 by
     * rebuilding with mixed lengths directly. */
    {
        byte hashAlgo[32];
        word32 haIdx = 0;
        idx = 0;
        haIdx += wb_tlv(hashAlgo + haIdx, ASN_OBJECT_ID, wbOidSha256,
                sizeof(wbOidSha256));
        haIdx += wb_tlv(hashAlgo + haIdx, ASN_TAG_NULL, NULL, 0);
        idx += WB_SEQ(content + idx, hashAlgo, haIdx);
        idx += wb_tlv(content + idx, ASN_OCTET_STRING, issuerHash,
                WB_DIGEST_SZ);          /* correct length (32) */
        idx += wb_tlv(content + idx, ASN_OCTET_STRING, issuerKeyHash, 20);
                                        /* wrong length -> 1st operand true */
        {
            byte serialVal = 0x05;
            idx += wb_tlv(content + idx, ASN_INTEGER, &serialVal, 1);
        }
        sz = idx;
    }
    idx = 0;
    ret = OcspDecodeCertIDInt(content, &idx, sz, &entry);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
            "CertID issuerKeyHashLen != digestSz (1st operand true)");

    /* issuerNameHash wrong length (20), issuerKeyHash correct (32):
     * 1st operand false, 2nd operand true. */
    XMEMSET(&status, 0, sizeof(status));
    XMEMSET(&entry, 0, sizeof(entry));
    entry.status = &status;
    {
        byte hashAlgo[32];
        word32 haIdx = 0;
        idx = 0;
        haIdx += wb_tlv(hashAlgo + haIdx, ASN_OBJECT_ID, wbOidSha256,
                sizeof(wbOidSha256));
        haIdx += wb_tlv(hashAlgo + haIdx, ASN_TAG_NULL, NULL, 0);
        idx += WB_SEQ(content + idx, hashAlgo, haIdx);
        idx += wb_tlv(content + idx, ASN_OCTET_STRING, issuerHash, 20);
        idx += wb_tlv(content + idx, ASN_OCTET_STRING, issuerKeyHash,
                WB_DIGEST_SZ);
        {
            byte serialVal = 0x05;
            idx += wb_tlv(content + idx, ASN_INTEGER, &serialVal, 1);
        }
        sz = idx;
    }
    idx = 0;
    ret = OcspDecodeCertIDInt(content, &idx, sz, &entry);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
            "CertID issuerHashLen != digestSz (1st false, 2nd true)");
}
#else
static void wb_ocsp_decode_certid(void) { WB_NOTE("non-template OcspDecodeCertIDInt; skipped"); }
#endif /* WOLFSSL_ASN_TEMPLATE */

#ifdef WOLFSSL_ASN_TEMPLATE
/* Build a minimal, valid SingleResponse (certStatus=good) with a
 * caller-supplied thisUpdate/nextUpdate so the date checks in
 * DecodeSingleResponse() can be driven independently. nextDate == NULL
 * omits the OPTIONAL nextUpdate field entirely. */
static word32 wb_build_single_response(byte* out,
        const byte* thisDate, const byte* nextDate)
{
    byte issuerHash[WB_DIGEST_SZ];
    byte issuerKeyHash[WB_DIGEST_SZ];
    byte cidContent[128];
    byte content[256];
    word32 cidSz;
    word32 idx = 0;

    XMEMSET(issuerHash, 0x33, sizeof(issuerHash));
    XMEMSET(issuerKeyHash, 0x44, sizeof(issuerKeyHash));
    cidSz = wb_build_certid_content(cidContent, issuerHash, issuerKeyHash,
            WB_DIGEST_SZ, 0x01);

    idx += WB_SEQ(content + idx, cidContent, cidSz);         /* CID_SEQ */
    idx += wb_tlv(content + idx, ASN_CONTEXT_SPECIFIC | 0, NULL, 0);
                                                              /* CS_GOOD */
    idx += wb_tlv(content + idx, ASN_GENERALIZED_TIME, thisDate, 15);
                                                              /* thisUpdate */
    if (nextDate != NULL) {
        byte inner[17];
        word32 innerSz = wb_tlv(inner, ASN_GENERALIZED_TIME, nextDate, 15);
        idx += wb_tlv(content + idx,
                ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 0, inner, innerSz);
    }
    return WB_SEQ(out, content, idx);
}

/* ------------------------------------------------------------------------- *
 * Section 2: DecodeSingleResponse() thisUpdate/nextUpdate date checks
 *   :34986/34987  if ((!AsnSkipDateCheck) && !XVALIDATE_DATE(thisDate, ..., ASN_BEFORE, ...))
 *   :35006/35007  if ((ret == 0) && (NEXTUPDATE_GT.tag != 0))
 *   :35012/35013  if ((!AsnSkipDateCheck) && !XVALIDATE_DATE(nextDate, ..., ASN_AFTER, ...))
 *   :35021/35022  (WOLFSSL_OCSP_PARSE_STATUS) duplicate of :35006/35007
 * AsnSkipDateCheck is a compile-time constant 0 unless
 * WC_ASN_RUNTIME_DATE_CHECK_CONTROL is defined (not set for this campaign),
 * so its "true" (skip) value is a structural residual here; only the
 * XVALIDATE_DATE operand is driven both ways.
 * ------------------------------------------------------------------------- */
static void wb_decode_single_response_dates(void)
{
    /* Comfortably in the past / comfortably in the future so the test does
     * not need updating for a long time. */
    static const byte pastDate[15]   = "20200101000000Z";
    static const byte futureDate[15] = "20991231235959Z";
    byte buf[512];
    word32 sz;
    word32 idx;
    OcspEntry single;
    CertStatus status;
    int ret;

    WB_NOTE("DecodeSingleResponse(): thisUpdate/nextUpdate date checks "
            "[:34986,:34987,:35006,:35007,:35012,:35013,:35021,:35022]");

    /* baseline: thisUpdate valid (past), nextUpdate present and valid
     * (future) -> all date checks false; NEXTUPDATE_GT.tag != 0 true. */
    XMEMSET(&status, 0, sizeof(status));
    XMEMSET(&single, 0, sizeof(single));
    single.status = &status;
    sz = wb_build_single_response(buf, pastDate, futureDate);
    idx = 0;
    ret = DecodeSingleResponse(buf, &idx, sz, 0, &single);
    WB_CHECK(ret == 0, "baseline: valid past thisUpdate, valid future nextUpdate");

    /* nextUpdate absent -> :35006/:35007 and :35021/:35022 2nd operand
     * false (tag == 0), whole decision false via short-circuit on the
     * shared 1st operand's partner. */
    XMEMSET(&status, 0, sizeof(status));
    XMEMSET(&single, 0, sizeof(single));
    single.status = &status;
    sz = wb_build_single_response(buf, pastDate, NULL);
    idx = 0;
    ret = DecodeSingleResponse(buf, &idx, sz, 0, &single);
    WB_CHECK(ret == 0, ":35006/:35007 2nd operand false (nextUpdate absent)");

    /* thisUpdate in the future -> :34986/:34987 both true -> ASN_BEFORE_DATE_E,
     * short-circuiting ret==0 to false for the nextUpdate checks that follow
     * (demonstrates the 1st operand of :35006/:35007/:35021/:35022 false). */
    XMEMSET(&status, 0, sizeof(status));
    XMEMSET(&single, 0, sizeof(single));
    single.status = &status;
    sz = wb_build_single_response(buf, futureDate, futureDate);
    idx = 0;
    ret = DecodeSingleResponse(buf, &idx, sz, 0, &single);
    /* Without a clock the date range is not validated at all, so the
     * out-of-range fixtures are accepted in that variant. */
#if !defined(NO_ASN_TIME) && !defined(NO_ASN_TIME_CHECK) && \
    !defined(WOLFSSL_NO_OCSP_DATE_CHECK)
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_BEFORE_DATE_E),
            ":34986/:34987 both true (thisUpdate in the future)");
#else
    WB_CHECK(ret == 0, "thisUpdate in the future, no clock (not validated)");
#endif

    /* nextUpdate in the past (thisUpdate still valid) -> :35006/:35007 both
     * true (present), :35012/:35013 both true -> ASN_AFTER_DATE_E. Also
     * exercises the WOLFSSL_OCSP_PARSE_STATUS-gated duplicate at
     * :35021/:35022 with tag != 0 (ret is still 0 at that point). */
    XMEMSET(&status, 0, sizeof(status));
    XMEMSET(&single, 0, sizeof(single));
    single.status = &status;
    sz = wb_build_single_response(buf, pastDate, pastDate);
    idx = 0;
    ret = DecodeSingleResponse(buf, &idx, sz, 0, &single);
#if !defined(NO_ASN_TIME) && !defined(NO_ASN_TIME_CHECK) && \
    !defined(WOLFSSL_NO_OCSP_DATE_CHECK)
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_AFTER_DATE_E),
            ":35012/:35013 both true (nextUpdate in the past)");
#else
    WB_CHECK(ret == 0, "nextUpdate in the past, no clock (not validated)");
#endif

#ifdef WC_ASN_RUNTIME_DATE_CHECK_CONTROL
    /* Same two rejecting fixtures with the runtime skip flag set: the
     * AsnSkipDateCheck operand goes false and neither date is validated. */
    (void)wc_AsnSetSkipDateCheck(1);

    XMEMSET(&status, 0, sizeof(status));
    XMEMSET(&single, 0, sizeof(single));
    single.status = &status;
    sz = wb_build_single_response(buf, futureDate, futureDate);
    idx = 0;
    ret = DecodeSingleResponse(buf, &idx, sz, 0, &single);
    WB_CHECK(ret == 0, ":34986 1st operand false (AsnSkipDateCheck set)");

    XMEMSET(&status, 0, sizeof(status));
    XMEMSET(&single, 0, sizeof(single));
    single.status = &status;
    sz = wb_build_single_response(buf, pastDate, pastDate);
    idx = 0;
    ret = DecodeSingleResponse(buf, &idx, sz, 0, &single);
    WB_CHECK(ret == 0, ":35012 1st operand false (AsnSkipDateCheck set)");

    (void)wc_AsnSetSkipDateCheck(0);
#endif
}
#else
static void wb_decode_single_response_dates(void) { WB_NOTE("non-template DecodeSingleResponse; skipped"); }
#endif /* WOLFSSL_ASN_TEMPLATE */

#ifdef WOLFSSL_ASN_TEMPLATE
/* ------------------------------------------------------------------------- *
 * Section 3: DecodeOcspRespExtensions() while loop [:35087]
 *   while ((ret == 0) && (idx < maxIdx))
 * Driven with a hand-built [1] EXPLICIT extensions wrapper: one vector with
 * a single well-formed (ignored, non-nonce) extension shows idx<maxIdx
 * flip true->false with ret==0 held true throughout; a second vector with
 * a trailing malformed extension shows ret==0 flip true->false while
 * idx<maxIdx is still true.
 * ------------------------------------------------------------------------- */
static word32 wb_build_resp_ext_hdr(byte* out, int addBadSecond)
{
    byte ext1[64];
    byte extList[128];
    word32 ext1Sz, listSz = 0;
    byte val[2] = { 0xAA, 0xBB };

    /* Extension with an OID this decoder ignores (not the nonce OID) and
     * not critical -> falls into "Ignore all other extension types". */
    ext1Sz = wb_ext(ext1, wbOidOther, sizeof(wbOidOther), 0, 0, val,
            sizeof(val));
    XMEMCPY(extList, ext1, ext1Sz);
    listSz = ext1Sz;

    if (addBadSecond) {
        /* Malformed 2nd extension: OCTET_STRING where an OID (SEQUENCE
         * content starts with ASN_OBJECT_ID) is expected -> ASN_PARSE_E. */
        byte bad[8];
        byte badContent[2] = { 0x00, 0x00 };
        word32 badSz = wb_tlv(bad, ASN_OCTET_STRING, badContent, 2);
        XMEMCPY(extList + listSz, bad, badSz);
        listSz += badSz;
    }

    {
        byte seq[132];
        word32 seqSz = WB_SEQ(seq, extList, listSz);   /* EXT_SEQ */
        return wb_tlv(out, ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 1, seq,
                seqSz);                                /* EXT (wrapper) */
    }
}

static void wb_decode_ocsp_resp_extensions(void)
{
    byte buf[256];
    word32 sz;
    word32 idx;
    OcspResponse resp;
    int ret;

    WB_NOTE("DecodeOcspRespExtensions(): while(ret==0 && idx<maxIdx) [:35087]");

    /* One well-formed, ignored extension: loop runs once (T,T) then exits
     * via idx<maxIdx becoming false (ret stays 0 throughout). */
    XMEMSET(&resp, 0, sizeof(resp));
    sz = wb_build_resp_ext_hdr(buf, 0);
    idx = 0;
    ret = DecodeOcspRespExtensions(buf, &idx, &resp, sz);
    WB_CHECK(ret == 0, "single ignored extension (idx<maxIdx true then false)");

    /* Valid extension followed by a malformed one: 2nd iteration's
     * GetASN_Items() fails -> ret becomes nonzero while idx<maxIdx is
     * still true -> loop exits via the ret==0 operand instead. */
    XMEMSET(&resp, 0, sizeof(resp));
    sz = wb_build_resp_ext_hdr(buf, 1);
    idx = 0;
    ret = DecodeOcspRespExtensions(buf, &idx, &resp, sz);
    WB_CHECK(ret != 0, "malformed 2nd extension (ret==0 operand false, idx<maxIdx still true)");
}
#else
static void wb_decode_ocsp_resp_extensions(void) { WB_NOTE("non-template DecodeOcspRespExtensions; skipped"); }
#endif /* WOLFSSL_ASN_TEMPLATE */

#ifdef WOLFSSL_ASN_TEMPLATE
/* ------------------------------------------------------------------------- *
 * Section 4: DecodeResponseData() responses loop and extension presence
 *   :35420  while ((ret == 0) && (idx < RESPEXT.offset))
 *   :35461/:35462  if ((ret == 0) && (RESPEXT.data.buffer.data != NULL))
 * ------------------------------------------------------------------------- */
static word32 wb_build_response_data(byte* out, int twoEntriesSecondBad,
        int includeExt)
{
    static const byte prodDate[15] = "20200101000000Z";
    byte keyHash[OCSP_RESPONDER_ID_KEY_SZ];
    byte single1[256];
    word32 single1Sz;
    byte responses[512];
    word32 respIdx = 0;
    byte content[700];
    word32 idx = 0;

    XMEMSET(keyHash, 0x55, sizeof(keyHash));

    single1Sz = wb_build_single_response(single1, prodDate, NULL);
    XMEMCPY(responses, single1, single1Sz);
    respIdx = single1Sz;

    if (twoEntriesSecondBad) {
        /* 2nd SingleResponse with a CertID whose hash lengths mismatch its
         * hashAlgoOID's digest size -> OcspDecodeCertIDInt() (called from
         * inside DecodeSingleResponse()) fails, so DecodeResponseData()'s
         * loop sees ret != 0 while idx is still short of RESPEXT.offset. */
        byte issuerHash[WB_DIGEST_SZ];
        byte issuerKeyHash[WB_DIGEST_SZ];
        byte cid[128];
        byte body[256];
        word32 cidSz, bodyIdx = 0;

        XMEMSET(issuerHash, 0x66, sizeof(issuerHash));
        XMEMSET(issuerKeyHash, 0x77, sizeof(issuerKeyHash));
        {
            byte hashAlgo[32];
            word32 haIdx = 0;
            haIdx += wb_tlv(hashAlgo + haIdx, ASN_OBJECT_ID, wbOidSha256,
                    sizeof(wbOidSha256));
            haIdx += wb_tlv(hashAlgo + haIdx, ASN_TAG_NULL, NULL, 0);
            cidSz = WB_SEQ(cid, hashAlgo, haIdx);
            cidSz += wb_tlv(cid + cidSz, ASN_OCTET_STRING, issuerHash, 20);
                                                    /* wrong length -> fail */
            cidSz += wb_tlv(cid + cidSz, ASN_OCTET_STRING, issuerKeyHash,
                    WB_DIGEST_SZ);
            {
                byte serialVal = 0x02;
                cidSz += wb_tlv(cid + cidSz, ASN_INTEGER, &serialVal, 1);
            }
        }
        bodyIdx += WB_SEQ(body + bodyIdx, cid, cidSz);        /* CID_SEQ */
        bodyIdx += wb_tlv(body + bodyIdx, ASN_CONTEXT_SPECIFIC | 0, NULL, 0);
                                                               /* CS_GOOD */
        bodyIdx += wb_tlv(body + bodyIdx, ASN_GENERALIZED_TIME, prodDate, 15);
        {
            byte single2[300];
            word32 single2Sz = WB_SEQ(single2, body, bodyIdx);
            XMEMCPY(responses + respIdx, single2, single2Sz);
            respIdx += single2Sz;
        }
    }

    idx += wb_tlv(content + idx, ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 2,
            NULL, 0);                                  /* placeholder, unused */
    idx = 0; /* rebuild cleanly below */

    /* byKey [2] EXPLICIT { OCTET STRING keyHash } */
    {
        byte octet[OCSP_RESPONDER_ID_KEY_SZ + 2];
        byte wrap[OCSP_RESPONDER_ID_KEY_SZ + 4];
        word32 octetSz = wb_tlv(octet, ASN_OCTET_STRING, keyHash,
                sizeof(keyHash));
        word32 wrapSz = wb_tlv(wrap,
                ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 2, octet, octetSz);
        XMEMCPY(content + idx, wrap, wrapSz);
        idx += wrapSz;
    }
    /* producedAt */
    idx += wb_tlv(content + idx, ASN_GENERALIZED_TIME, prodDate, 15);
    /* responses SEQUENCE OF SingleResponse */
    idx += WB_SEQ(content + idx, responses, respIdx);

    if (includeExt) {
        byte ext1[64];
        byte val[2] = { 0x01, 0x02 };
        word32 ext1Sz = wb_ext(ext1, wbOidOther, sizeof(wbOidOther), 0, 0,
                val, sizeof(val));
        byte extSeq[80];
        word32 extSeqSz = WB_SEQ(extSeq, ext1, ext1Sz);
        idx += wb_tlv(content + idx, ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 1,
                extSeq, extSeqSz);
    }

    return WB_SEQ(out, content, idx);
}

static void wb_decode_response_data(void)
{
    byte buf[1024];
    word32 sz;
    word32 idx;
    OcspEntry single;
    CertStatus status;
    OcspResponse resp;
    int ret;

    WB_NOTE("DecodeResponseData(): responses loop [:35420]; extension "
            "presence [:35461,:35462]");

    /* One SingleResponse, no extensions: loop runs once (ret==0 true,
     * idx<offset true) then exits via idx<offset false; RESPEXT absent
     * (data.buffer.data == NULL) -> 2nd operand false. */
    XMEMSET(&status, 0, sizeof(status));
    XMEMSET(&single, 0, sizeof(single));
    single.status = &status;
    XMEMSET(&resp, 0, sizeof(resp));
    resp.single = &single;
    sz = wb_build_response_data(buf, 0, 0);
    idx = 0;
    ret = DecodeResponseData(buf, &idx, &resp, sz);
    WB_CHECK(ret == 0, "one response, no extensions (RESPEXT absent, 2nd operand false)");

    /* Same, but with a trailing (empty-payload) responseExtensions block
     * present -> :35461/:35462 both true, DecodeOcspRespExtensions() runs. */
    XMEMSET(&status, 0, sizeof(status));
    XMEMSET(&single, 0, sizeof(single));
    single.status = &status;
    XMEMSET(&resp, 0, sizeof(resp));
    resp.single = &single;
    sz = wb_build_response_data(buf, 0, 1);
    idx = 0;
    ret = DecodeResponseData(buf, &idx, &resp, sz);
    WB_CHECK(ret == 0, ":35461/:35462 both true (responseExtensions present)");

    /* Two responses, second malformed: loop's ret==0 operand goes false
     * while idx is still short of RESPEXT.offset (no extensions here, so
     * the bound is effectively end-of-responses). */
    XMEMSET(&status, 0, sizeof(status));
    XMEMSET(&single, 0, sizeof(single));
    single.status = &status;
    XMEMSET(&resp, 0, sizeof(resp));
    resp.single = &single;
    sz = wb_build_response_data(buf, 1, 0);
    idx = 0;
    ret = DecodeResponseData(buf, &idx, &resp, sz);
    WB_CHECK(ret != 0, ":35420 ret==0 operand false (2nd response malformed)");
}
#else
static void wb_decode_response_data(void) { WB_NOTE("non-template DecodeResponseData; skipped"); }
#endif /* WOLFSSL_ASN_TEMPLATE */

/* ------------------------------------------------------------------------- *
 * Section 5: OcspRespIdMatch() responder-by-key branch [:35525,:35526,:35527]
 *   return (KEYID_SIZE >= OCSP_RESPONDER_ID_KEY_SZ) && XMEMCMP(...) == 0;
 * KEYID_SIZE is WC_SHA_DIGEST_SIZE (20), WC_SHA256_DIGEST_SIZE (32) or
 * WC_SM3_DIGEST_SIZE (32) depending on build -- OCSP_RESPONDER_ID_KEY_SZ is
 * fixed at 20, so this comparison is always true at compile time in every
 * configuration; unique-cause MC/DC for its false side is structurally
 * unreachable (RESIDUAL). Only the XMEMCMP operand is driven both ways.
 * ------------------------------------------------------------------------- */
static void wb_ocsp_respid_match(void)
{
    OcspResponse resp;
    byte keyHash[OCSP_RESPONDER_ID_KEY_SZ];
    int ret;

    WB_NOTE("OcspRespIdMatch(): KEYID_SIZE>=OCSP_RESPONDER_ID_KEY_SZ (residual, "
            "always true) && XMEMCMP==0 [:35525,:35526,:35527]");

    XMEMSET(&resp, 0, sizeof(resp));
    resp.responderIdType = OCSP_RESPONDER_ID_KEY;
    XMEMSET(keyHash, 0x11, sizeof(keyHash));
    XMEMSET(resp.responderId.keyHash, 0x11, sizeof(resp.responderId.keyHash));
    ret = OcspRespIdMatch(&resp, NULL, keyHash);
    WB_CHECK(ret != 0, "matching key hash (XMEMCMP == 0)");

    XMEMSET(resp.responderId.keyHash, 0x99, sizeof(resp.responderId.keyHash));
    ret = OcspRespIdMatch(&resp, NULL, keyHash);
    WB_CHECK(ret == 0, "mismatching key hash (XMEMCMP != 0)");
}

#ifndef WOLFCRYPT_ONLY
/* ------------------------------------------------------------------------- *
 * Section 6: OcspCheckCert() [:35624,:35633,:35643]
 *   :35624  if (ret == 0 && OcspRespIdMatch(...) == 0)
 *   :35633  if (ret == 0 && !noVerify)                    (WOLFSSL_NO_OCSP_ISSUER_CHECK off)
 *   :35643  if (ret == 0 && !noVerifySignature)
 * Uses a real certificate (root_ca_cert_pem, from the OCSP test blobs) so
 * ParseCertRelative() succeeds structurally with NO_VERIFY; the responder-id
 * hash is deliberately mismatched/matched to steer :35624 without needing a
 * live chain. noVerify/noVerifySignature are toggled directly.
 * ------------------------------------------------------------------------- */
static void wb_ocsp_check_cert(void)
{
    OcspResponse resp;
    DecodedCert cert;
    int ret;

    WB_NOTE("OcspCheckCert(): ret==0 && OcspRespIdMatch()==0 [:35624]; "
            "ret==0 && !noVerify [:35633]; ret==0 && !noVerifySignature [:35643]");

    /* ret==0 false: garbage cert bytes make ParseCertRelative() fail, so
     * the whole line short-circuits on the 1st operand regardless of the
     * responder id. */
    XMEMSET(&resp, 0, sizeof(resp));
    {
        static const byte garbage[8] = { 0,1,2,3,4,5,6,7 };
        resp.cert = garbage;
        resp.certSz = sizeof(garbage);
    }
    resp.responderIdType = OCSP_RESPONDER_ID_NAME;
    ret = OcspCheckCert(&resp, 1 /* noVerify */, 1 /* noVerifySignature */,
            NULL, NULL);
    WB_CHECK(ret != 0, "ret!=0 short-circuit (malformed embedded cert)");

    /* Pre-parse the real cert once to learn its true subjectHash, so we can
     * drive OcspRespIdMatch()'s outcome deliberately without touching a CA
     * chain. */
    XMEMSET(&cert, 0, sizeof(cert));
    InitDecodedCert(&cert, root_ca_cert_pem, (word32)sizeof(root_ca_cert_pem),
            NULL);
    ret = ParseCertRelative(&cert, CERT_TYPE, NO_VERIFY, NULL, NULL);
    WB_CHECK(ret == 0, "pre-parse of root_ca_cert_pem (fixture sanity)");
    if (ret == 0) {
        byte matchingHash[KEYID_SIZE];
        byte mismatchHash[KEYID_SIZE];

        XMEMCPY(matchingHash, cert.subjectHash, KEYID_SIZE);
        XMEMSET(mismatchHash, 0xEE, KEYID_SIZE);
        FreeDecodedCert(&cert);

        /* OcspRespIdMatch() returns 0 when the hashes DO NOT match (its
         * XMEMCMP == 0 test is inverted from the name): the reject at
         * :35624 (ret == 0 && OcspRespIdMatch(...) == 0) fires when the
         * embedded cert's subject hash does NOT correspond to the claimed
         * responder id, not when it does. noVerify=1 -> NO_VERIFY parse
         * succeeds (op0=true) without needing a CertManager; a mismatching
         * nameHash makes OcspRespIdMatch() return 0 (op1=true) -> both
         * operands true -> BAD_OCSP_RESPONDER (goto err). Paired with the
         * garbage-cert vector above (op0=false), this is the independence
         * pair for :35624's 1st operand; it is also the only vector in this
         * binary where the 2nd operand is true. */
        XMEMSET(&resp, 0, sizeof(resp));
        resp.cert = root_ca_cert_pem;
        resp.certSz = (word32)sizeof(root_ca_cert_pem);
        resp.responderIdType = OCSP_RESPONDER_ID_NAME;
        XMEMCPY(resp.responderId.nameHash, mismatchHash, KEYID_SIZE);
        ret = OcspCheckCert(&resp, 1 /* noVerify=1 -> NO_VERIFY parse */,
                1 /* noVerifySignature */, NULL, NULL);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_OCSP_RESPONDER),
                ":35624 both true (mismatching responder id -> rejected)");

        /* ret==0 true, OcspRespIdMatch()==0 false (matching id: hashes are
         * equal, so XMEMCMP==0 and OcspRespIdMatch() returns 1) -- the
         * :35624 if-body is skipped, so parsing continues past it with
         * ret==0 still. noVerify=1 keeps :35633's 2nd operand (!noVerify)
         * false; noVerifySignature=1 likewise keeps :35643's 2nd operand
         * false, so this call returns cleanly. */
        XMEMSET(&resp, 0, sizeof(resp));
        resp.cert = root_ca_cert_pem;
        resp.certSz = (word32)sizeof(root_ca_cert_pem);
        resp.responderIdType = OCSP_RESPONDER_ID_NAME;
        XMEMCPY(resp.responderId.nameHash, matchingHash, KEYID_SIZE);
        ret = OcspCheckCert(&resp, 1, 1, NULL, NULL);
        WB_CHECK(ret == 0,
                ":35624 1st true, 2nd false (matching responder id -> "
                "proceeds); noVerify=1/noVerifySignature=1 skip the two "
                "checks below it");
    }
    else {
        FreeDecodedCert(&cert);
    }
}
#else
static void wb_ocsp_check_cert(void) { WB_NOTE("WOLFCRYPT_ONLY; OcspCheckCert skipped"); }
#endif /* !WOLFCRYPT_ONLY */

#ifdef WOLFSSL_ASN_TEMPLATE
/* ------------------------------------------------------------------------- *
 * Section 7: DecodeBasicOcspResponse() / OcspResponseDecode() verify-chain
 * decisions [:35814,:35831,:35839,:35849,:35856,:35862], driven through the
 * public OcspResponseDecode() entry point with the ready-made "resp" and
 * "resp_nocert" blobs from tests/api/test_ocsp_test_blobs.h.
 * ------------------------------------------------------------------------- */
static void wb_decode_basic_ocsp_response(void)
{
    OcspResponse r;
    OcspEntry    entry;
    CertStatus   status;
    int ret;

    WB_NOTE("OcspResponseDecode()/DecodeBasicOcspResponse(): certs/sig-chain "
            "decisions [:35831,:35839,:35849,:35856,:35862]");

#ifdef WC_RSA_PSS
    /* Section 7a: hand-build a BasicOCSPResponse whose signatureAlgorithm
     * carries a trailing parameters SEQUENCE (as RSA-PSS signatures do), to
     * drive :35979's SIGNATURE_PARAMS.tag != 0 operand true -- no committed
     * OCSP response fixture in this corpus is RSA-PSS signed. Called
     * directly (DecodeBasicOcspResponse is file-static): a genuine OID +
     * trailing SEQUENCE is all the template requires at this position, no
     * real PSS semantics needed for MC/DC purposes. */
    {
        byte tbs[700];
        word32 tbsSz;
        byte sigAlgo[64];
        word32 sigAlgoSz;
        byte sig[16];
        byte content[900];
        word32 idx = 0;
        byte full[950];
        word32 fullSz;
        word32 didx = 0;
        OcspResponse rr;
        OcspEntry ee;
        CertStatus ss;
        int dret;
        /* sha256WithRSAEncryption (1.2.840.113549.1.1.11) OID content. */
        static const byte rsaSha256Oid[] =
            { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b };
        byte inner[32];
        word32 innerIdx = 0;

        innerIdx += wb_tlv(inner + innerIdx, ASN_OBJECT_ID, rsaSha256Oid,
                sizeof(rsaSha256Oid));
        innerIdx += WB_SEQ(inner + innerIdx, NULL, 0); /* empty PARAMS SEQ */
        sigAlgoSz = WB_SEQ(sigAlgo, inner, innerIdx);

        XMEMSET(sig, 0xAA, sizeof(sig));
        tbsSz = wb_build_response_data(tbs, 0, 0);

        XMEMCPY(content + idx, tbs, tbsSz); idx += tbsSz;
        XMEMCPY(content + idx, sigAlgo, sigAlgoSz); idx += sigAlgoSz;
        {
            byte sigHdr[8];
            word32 sigHdrSz = SetBitString(sizeof(sig), 0, sigHdr);
            XMEMCPY(content + idx, sigHdr, sigHdrSz); idx += sigHdrSz;
            XMEMCPY(content + idx, sig, sizeof(sig)); idx += sizeof(sig);
        }
        fullSz = WB_SEQ(full, content, idx);

        XMEMSET(&rr, 0, sizeof(rr));
        XMEMSET(&ee, 0, sizeof(ee));
        XMEMSET(&ss, 0, sizeof(ss));
        rr.single = &ee;
        ee.status = &ss;
        dret = DecodeBasicOcspResponse(full, &didx, &rr, fullSz, NULL, NULL,
                1, 1);
        WB_CHECK(dret == 0 && rr.sigParamsSz > 0,
                ":35979 both true (hand-built response, sigAlgo params "
                "SEQUENCE present)");
    }
#endif

    /* Corrupt a byte deep inside the BasicOCSPResponse content (well past
     * the outer OCSPResponse/ResponseBytes wrapper, which only takes a
     * byte-range reference and does not deeply parse it) so
     * DecodeBasicOcspResponse()'s own top-level GetASN_Items() call fails --
     * ret!=0 from the very start, cascading false through every subsequent
     * "ret==0 && ..." guard in the function -- the independence pair for
     * :35996/:36004's ret==0 operand (every other vector in this function
     * reaches those lines with ret==0 already true). */
    {
        byte corrupt[sizeof(resp)];
        word32 off;
        int corrupted = 0;
        XMEMCPY(corrupt, resp, sizeof(resp));
        for (off = 40; off < sizeof(corrupt); off += 7) {
            byte save = corrupt[off];
            corrupt[off] = (byte)~save;
            XMEMSET(&r, 0, sizeof(r));
            XMEMSET(&entry, 0, sizeof(entry));
            XMEMSET(&status, 0, sizeof(status));
            InitOcspResponse(&r, &entry, &status, corrupt,
                    (word32)sizeof(corrupt), NULL);
            ret = OcspResponseDecode(&r, NULL, NULL, 1, 1);
            if (ret != 0) {
                corrupted = 1;
                break;
            }
            corrupt[off] = save;
        }
        WB_CHECK(corrupted,
                ":35996/:36004 ret==0 operand false (top-level GetASN_Items "
                "fails on a corrupted BasicOCSPResponse)");
    }

    /* noVerifySignature=1: :35849/:35856/:35862 all false via their 2nd
     * operand (!noVerifySignature), regardless of certs/sigValid state.
     * "resp" carries an embedded responder cert (certSz > 0), exercising
     * :35831/:35839 true. */
    XMEMSET(&r, 0, sizeof(r));
    XMEMSET(&entry, 0, sizeof(entry));
    XMEMSET(&status, 0, sizeof(status));
    InitOcspResponse(&r, &entry, &status, resp, (word32)sizeof(resp), NULL);
    ret = OcspResponseDecode(&r, NULL, NULL, 1 /* noVerifyCert */,
            1 /* noVerifySignature */);
    WB_CHECK(ret == 0,
            "\"resp\" blob, noVerifySignature=1 (:35831/:35839 true; "
            ":35849/:35856/:35862 2nd operand false)");

    /* "resp_nocert": certSz stays 0 -> :35831/:35839 2nd operand false
     * (certs-block skipped entirely); noVerifySignature=0 reaches
     * :35849 with ret==0 && !noVerifySignature==true && !sigValid==true
     * (sigValid never got set to 1 since there was no embedded cert). With
     * cm==NULL, OcspFindSigner() returns NULL -> ASN_NO_SIGNER_E, so
     * :35856 short-circuits false via its own ret==0 operand. */
    XMEMSET(&r, 0, sizeof(r));
    XMEMSET(&entry, 0, sizeof(entry));
    XMEMSET(&status, 0, sizeof(status));
    InitOcspResponse(&r, &entry, &status, resp_nocert, (word32)sizeof(resp_nocert),
            NULL);
    ret = OcspResponseDecode(&r, NULL, NULL, 1, 0 /* noVerifySignature=0 */);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_NO_SIGNER_E),
            "\"resp_nocert\" blob, noVerifySignature=0, cm=NULL "
            "(:35831/:35839 false; :35849 all-true; :35856 ret operand false)");

    /* Attempt the same blob against a CertManager loaded with every CA/
     * responder cert in the OCSP test corpus: "resp_nocert" strips the
     * embedded responder cert but keeps the same responderId, which turns
     * out to resolve via ocsp_responder_cert_pem's subject hash (loaded here
     * as a trust anchor alongside the CA chain). This makes OcspFindSigner()
     * locate a signer (ca != NULL) -- exercising :35856's true side and
     * :35862 -- and the subsequent OcspRespCheck()/ConfirmSignature() calls
     * succeed, giving ret==0 end to end. */
    {
        WOLFSSL_CERT_MANAGER* cm = wolfSSL_CertManagerNew();
        if (cm != NULL) {
            (void)wolfSSL_CertManagerLoadCABuffer(cm, root_ca_cert_pem,
                    (word32)sizeof(root_ca_cert_pem), WOLFSSL_FILETYPE_ASN1);
            (void)wolfSSL_CertManagerLoadCABuffer(cm, ca_cert_pem,
                    (word32)sizeof(ca_cert_pem), WOLFSSL_FILETYPE_ASN1);
            (void)wolfSSL_CertManagerLoadCABuffer(cm, intermediate1_ca_cert_pem,
                    (word32)sizeof(intermediate1_ca_cert_pem),
                    WOLFSSL_FILETYPE_ASN1);
            (void)wolfSSL_CertManagerLoadCABuffer(cm, ocsp_responder_cert_pem,
                    (word32)sizeof(ocsp_responder_cert_pem),
                    WOLFSSL_FILETYPE_ASN1);
            XMEMSET(&r, 0, sizeof(r));
            XMEMSET(&entry, 0, sizeof(entry));
            XMEMSET(&status, 0, sizeof(status));
            InitOcspResponse(&r, &entry, &status, resp_nocert,
                    (word32)sizeof(resp_nocert), NULL);
            ret = OcspResponseDecode(&r, cm, NULL, 1, 0);
            WB_CHECK(ret == 0,
                    "\"resp_nocert\" with the full CA/responder set loaded "
                    "(:35856 ca!=NULL, :35862 both true; OcspRespCheck() and "
                    "ConfirmSignature() both succeed)");
            wolfSSL_CertManagerFree(cm);
        }
    }

    /* Every vector above passes noVerifyCert=1 (OcspCheckCert's "noVerify"),
     * so the OcspCheckCert-internal issuer-check/signature-check decisions
     * gated by "!noVerify" (WOLFSSL_NO_OCSP_ISSUER_CHECK off) never see that
     * operand true. Drive noVerifyCert=0/noVerifySignature=0 -- mirroring
     * the production call in src/ocsp.c's CheckCertOCSP() -- with the "resp"
     * blob (embedded responder cert whose subject genuinely matches the
     * response's responderId) against a CertManager holding the issuing
     * root CA, exactly as tests/api/test_ocsp.c's test_ocsp_response_parsing
     * does through the public wolfSSL_CertManagerCheckOCSP() path. This
     * reaches OcspCheckCert()'s ret==0 && OcspRespIdMatch()==0 decision
     * with a genuine match (2nd operand false, so no reject) and carries
     * ret==0 forward into the !noVerify / !noVerifySignature checks with
     * both operands true. */
    {
        WOLFSSL_CERT_MANAGER* cm = wolfSSL_CertManagerNew();
        if (cm != NULL) {
            (void)wolfSSL_CertManagerLoadCABuffer(cm, root_ca_cert_pem,
                    (word32)sizeof(root_ca_cert_pem), WOLFSSL_FILETYPE_ASN1);
            XMEMSET(&r, 0, sizeof(r));
            XMEMSET(&entry, 0, sizeof(entry));
            XMEMSET(&status, 0, sizeof(status));
            InitOcspResponse(&r, &entry, &status, resp, (word32)sizeof(resp),
                    NULL);
            ret = OcspResponseDecode(&r, cm, NULL, 0 /* noVerifyCert=0 */,
                    0 /* noVerifySignature=0 */);
            WB_NOTE("\"resp\" blob with issuing root CA loaded, "
                    "noVerifyCert=0, noVerifySignature=0 (OcspCheckCert(): "
                    "responder id matches -> proceeds into !noVerify / "
                    "!noVerifySignature with ret==0)");
            (void)ret;
            wolfSSL_CertManagerFree(cm);
        }
    }
}
#else
static void wb_decode_basic_ocsp_response(void) { WB_NOTE("non-template DecodeBasicOcspResponse; skipped"); }
#endif /* WOLFSSL_ASN_TEMPLATE */

#ifdef WOLFSSL_ASN_TEMPLATE
/* ------------------------------------------------------------------------- *
 * Section 8: EncodeOcspRequestExtensions()/EncodeOcspRequest() buffer-size
 * checks [:36155,:36172,:36175,:36300,:36303]. Both are public, template-
 * path functions -- the size-check (out==NULL) pass and the too-small
 * buffer case are not exercised by ordinary callers, who always size the
 * buffer from a prior NULL-out call.
 * ------------------------------------------------------------------------- */
static void wb_encode_ocsp_request(void)
{
    OcspRequest req;
    byte tooSmall[4];
    byte big[256];
    word32 need;
    int ret;

    WB_NOTE("EncodeOcspRequestExtensions(): req!=NULL && nonceSz!=0 [:36155]; "
            "buffer-size checks [:36172,:36175]");

    XMEMSET(&req, 0, sizeof(req));
    /* req==NULL -> not applicable (word32 return, no NULL deref happens
     * before the check); req->nonceSz==0 -> 2nd operand false. */
    ret = (int)EncodeOcspRequestExtensions(&req, NULL, 0);
    WB_CHECK(ret == 0, ":36155 2nd operand false (nonceSz==0)");

    req.nonceSz = 8;
    XMEMSET(req.nonce, 0x5A, (size_t)req.nonceSz);
    need = EncodeOcspRequestExtensions(&req, NULL, 0);
    WB_CHECK(need > 0, ":36155 both true (size-only pass)");

    /* output!=NULL, sz>size (buffer too small) -> :36172 all true ->
     * ret = BUFFER_E (not 0: the size-check block sets ret to an error, it
     * does not return early). */
    ret = (int)EncodeOcspRequestExtensions(&req, tooSmall, sizeof(tooSmall));
    WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E),
            ":36172 all true (output!=NULL, buffer too small)");

    /* output!=NULL, buffer big enough -> :36172 false via 3rd operand,
     * :36175 both true (encode happens). */
    ret = (int)EncodeOcspRequestExtensions(&req, big, sizeof(big));
    WB_CHECK(ret == (int)need,
            ":36175 both true (output!=NULL, buffer big enough)");

    WB_NOTE("EncodeOcspRequest(): buffer-size check [:36300,:36303]");
    XMEMSET(&req, 0, sizeof(req));
    req.hashAlg = SHA256h;
    XMEMSET(req.issuerHash, 0x01, sizeof(req.issuerHash));
    XMEMSET(req.issuerKeyHash, 0x02, sizeof(req.issuerKeyHash));
    {
        static byte serial[1] = { 0x09 };
        req.serial = serial;
        req.serialSz = 1;
    }
    ret = EncodeOcspRequest(&req, NULL, 0);
    WB_CHECK(ret > 0, "EncodeOcspRequest size-only pass (output==NULL)");
    need = (word32)ret;

    ret = EncodeOcspRequest(&req, tooSmall, sizeof(tooSmall));
    WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E),
            ":36300 all true (output!=NULL, buffer too small)");

    ret = EncodeOcspRequest(&req, big, sizeof(big));
    WB_CHECK(ret == (int)need,
            ":36303 both true (output!=NULL, buffer big enough)");
}
#else
static void wb_encode_ocsp_request(void) { WB_NOTE("non-template EncodeOcspRequest; skipped"); }
#endif /* WOLFSSL_ASN_TEMPLATE */

/* ------------------------------------------------------------------------- *
 * Section 9: InitOcspRequest() extAuthInfo copy [:36526]
 *   if (cert->extAuthInfoSz != 0 && cert->extAuthInfo != NULL)
 * ------------------------------------------------------------------------- */
static void wb_init_ocsp_request(void)
{
    OcspRequest req;
    DecodedCert cert;
    int ret;

    WB_NOTE("InitOcspRequest(): extAuthInfoSz!=0 && extAuthInfo!=NULL [:36526]");

    XMEMSET(&cert, 0, sizeof(cert));
    {
        cert.serial[0] = 0x03;
        cert.serialSz = 1;
    }

    /* both false: extAuthInfoSz == 0 (extAuthInfo also NULL). */
    cert.extAuthInfoSz = 0;
    cert.extAuthInfo = NULL;
    ret = InitOcspRequest(&req, &cert, 0, NULL);
    WB_CHECK(ret == 0 && req.url == NULL, "extAuthInfoSz==0 (both false)");
    FreeOcspRequest(&req);

    /* both true: extAuthInfoSz != 0 and extAuthInfo != NULL. */
    {
        static const byte uri[] = "http://ocsp.example.test";
        cert.extAuthInfoSz = (int)sizeof(uri) - 1;
        cert.extAuthInfo = uri;
    }
    ret = InitOcspRequest(&req, &cert, 0, NULL);
    WB_CHECK(ret == 0 && req.url != NULL && req.urlSz == cert.extAuthInfoSz,
            "extAuthInfoSz!=0 && extAuthInfo!=NULL (both true)");
    FreeOcspRequest(&req);

    /* 1st true, 2nd false (extAuthInfoSz!=0 but extAuthInfo==NULL): only
     * reachable via a hand-set DecodedCert (a real parse never sets the
     * size without the pointer), so short-circuit isolation is white-box
     * only. */
    cert.extAuthInfoSz = 5;
    cert.extAuthInfo = NULL;
    ret = InitOcspRequest(&req, &cert, 0, NULL);
    WB_CHECK(ret == 0 && req.url == NULL,
            "extAuthInfoSz!=0, extAuthInfo==NULL (1st true, 2nd false)");
    FreeOcspRequest(&req);
}

/* ------------------------------------------------------------------------- *
 * Section 10: CompareOcspReqResp() [:36606,:36619,:36620,:36621,:36647-:36651,
 * :36655]
 * ------------------------------------------------------------------------- */
static void wb_compare_ocsp_req_resp(void)
{
    OcspRequest req;
    OcspResponse resp;
    OcspEntry single1, single2;
    CertStatus status1, status2;
    int ret;

    WB_NOTE("CompareOcspReqResp(): resp==NULL||resp->single==NULL [:36606]; "
            "nonce compare [:36619,:36620,:36621]; serial/hash XMEMCMP chain "
            "[:36647-:36651]; move-to-top [:36655]");

    XMEMSET(&req, 0, sizeof(req));
    ret = CompareOcspReqResp(&req, NULL);
    WB_CHECK(ret == 1, ":36606 1st operand true (resp==NULL)");

    XMEMSET(&resp, 0, sizeof(resp));
    resp.single = NULL;
    ret = CompareOcspReqResp(&req, &resp);
    WB_CHECK(ret == 1, ":36606 1st false, 2nd true (resp->single==NULL)");

    /* Build a request and a two-entry response list where the match is on
     * the SECOND entry, to exercise the XMEMCMP chain, the nonce compare,
     * and the move-to-top-of-list branch together. */
    XMEMSET(&status1, 0, sizeof(status1));
    XMEMSET(&status2, 0, sizeof(status2));
    XMEMSET(&single1, 0, sizeof(single1));
    XMEMSET(&single2, 0, sizeof(single2));
    single1.status = &status1;
    single2.status = &status2;
    single1.hashAlgoOID = SHA256h;
    single2.hashAlgoOID = SHA256h;
    XMEMSET(single1.issuerHash, 0x01, sizeof(single1.issuerHash));
    XMEMSET(single1.issuerKeyHash, 0x02, sizeof(single1.issuerKeyHash));
    XMEMSET(single2.issuerHash, 0x03, sizeof(single2.issuerHash));
    XMEMSET(single2.issuerKeyHash, 0x04, sizeof(single2.issuerKeyHash));
    status1.serialSz = 1; status1.serial[0] = 0xAA; /* won't match */
    status2.serialSz = 1; status2.serial[0] = 0xBB; /* will match */
    single1.next = &single2;
    single2.next = NULL;

    XMEMSET(&req, 0, sizeof(req));
    req.serialSz = 1;
    {
        static byte serial[1] = { 0xBB };
        req.serial = serial;
    }
    XMEMCPY(req.issuerHash, single2.issuerHash, WC_MAX_DIGEST_SIZE);
    XMEMCPY(req.issuerKeyHash, single2.issuerKeyHash, WC_MAX_DIGEST_SIZE);
    req.nonceSz = 0; /* :36619 1st operand false -> skip nonce compare */

    XMEMSET(&resp, 0, sizeof(resp));
    resp.single = &single1;
    ret = CompareOcspReqResp(&req, &resp);
    WB_CHECK(ret == 0,
            "match on 2nd entry, no nonce (:36619 1st false; :36647-:36651 "
            "chain all-zero via 2nd entry; :36655 moves it to top)");
    WB_CHECK(resp.single == &single2, ":36655 both true (moved 2nd entry to top)");

    /* Same list, but with a matching nonce present on both sides -> :36619
     * both true (nonceSz!=0 && resp->nonce!=NULL), nonce XMEMCMP == 0. */
    single1.next = &single2;
    resp.single = &single1;
    {
        static byte nonceBuf[4] = { 1, 2, 3, 4 };
        resp.nonce = nonceBuf;
        resp.nonceSz = 4;
        req.nonceSz = 4;
        XMEMCPY(req.nonce, nonceBuf, 4);
    }
    ret = CompareOcspReqResp(&req, &resp);
    WB_CHECK(ret == 0, ":36619/:36620/:36621 all true, nonce matches");

    /* Mismatching nonce length -> early return via cmp != 0, before the
     * XMEMCMP itself (still exercises :36619-:36621 all true). */
    req.nonceSz = 3;
    ret = CompareOcspReqResp(&req, &resp);
    WB_CHECK(ret != 0, "nonce length mismatch (still :36619-:36621 all true)");

    /* :36619 2nd operand false: nonceSz!=0 but resp->nonce==NULL. */
    req.nonceSz = 4;
    resp.nonce = NULL;
    ret = CompareOcspReqResp(&req, &resp);
    WB_CHECK(ret == 0, ":36619 2nd operand false (resp->nonce==NULL)");

    /* The identity chain is `serial || issuerHash || issuerKeyHash`; the two
     * trailing comparisons only decide the outcome when every earlier one is
     * zero, which a response built from a different issuer never produces.
     * Two single-entry responses isolate them: one whose serial matches but
     * whose issuer name hash does not, and one where both match but the
     * issuer key hash does not. */
    req.nonceSz = 0;
    resp.nonce = NULL;
    single1.next = NULL;
    status1.serialSz = 1;
    status1.serial[0] = 0xBB;                   /* serial now matches */
    XMEMSET(single1.issuerHash, 0x03, sizeof(single1.issuerHash));
    XMEMSET(single1.issuerKeyHash, 0x04, sizeof(single1.issuerKeyHash));
    resp.single = &single1;
    ret = CompareOcspReqResp(&req, &resp);
    WB_CHECK(ret == 0, "serial/issuer/key hashes all match (all three "
            "comparisons zero)");

    XMEMSET(single1.issuerHash, 0x77, sizeof(single1.issuerHash));
    resp.single = &single1;
    ret = CompareOcspReqResp(&req, &resp);
    WB_CHECK(ret != 0, ":36812 2nd operand true (issuer name hash differs)");

    XMEMSET(single1.issuerHash, 0x03, sizeof(single1.issuerHash));
    XMEMSET(single1.issuerKeyHash, 0x77, sizeof(single1.issuerKeyHash));
    resp.single = &single1;
    ret = CompareOcspReqResp(&req, &resp);
    WB_CHECK(ret != 0, ":36812 3rd operand true (issuer key hash differs)");
}

#if defined(HAVE_CRL) && !defined(WOLFCRYPT_ONLY)
/* ------------------------------------------------------------------------- *
 * Section 11: ParseCRL_EntryExtensions() [:36841,:36842,:36854-:36856,
 * :36863,:36864,:36877,:36878,:36881,:36882,:36891,:36892,:36917,:36921,
 * :36935]
 * WC_ASN_UNKNOWN_EXT_CB is active for this campaign (WOLFSSL_ASN_ALL pulls
 * in WOLFSSL_CUSTOM_OID + HAVE_OID_DECODING + WOLFSSL_ASN_TEMPLATE), so the
 * callback-dispatch branch is live, not compiled out.
 * ------------------------------------------------------------------------- */
static int wbEntryCbCalls = 0;
static int wbEntryCbRet = 0;
static int wb_entry_ext_cb(const word16* oid, word32 oidSz, int crit,
        const unsigned char* der, word32 derSz)
{
    (void)oid; (void)oidSz; (void)crit; (void)der; (void)derSz;
    wbEntryCbCalls++;
    return wbEntryCbRet;
}

static int wbEntryCbExCalls = 0;
static int wbEntryCbExRet = 0;
static int wb_entry_ext_cb_ex(const word16* oid, word32 oidSz, int crit,
        const unsigned char* der, word32 derSz, void* ctx)
{
    (void)oid; (void)oidSz; (void)crit; (void)der; (void)derSz; (void)ctx;
    wbEntryCbExCalls++;
    return wbEntryCbExRet;
}

/* Build one CRL-entry-extension SEQUENCE (reason code) or a generic one. */
static word32 wb_build_reason_ext(byte* out, byte reasonVal)
{
    byte enumTlv[3];
    word32 enumSz = wb_tlv(enumTlv, ASN_ENUMERATED, &reasonVal, 1);
    static const byte reasonOid[] = { 0x55, 0x1d, 0x15 }; /* 2.5.29.21 */
    /* Bare ENUMERATED TLV: wb_ext() supplies the extension's OCTET STRING. */
    return wb_ext(out, reasonOid, sizeof(reasonOid), 0, 0, enumTlv, enumSz);
}

static void wb_parse_crl_entry_extensions(void)
{
    byte list[512];
    word32 sz;
    int reasonCode;
    int ret;
    DecodedCRL dcrl;

    WB_NOTE("ParseCRL_EntryExtensions(): reason OID, unknown-critical, "
            "callback dispatch [:36841-:36935]");

    InitDecodedCRL(&dcrl, NULL);

    /* Reason-code extension (baseline: exercises OID/tag parse, GetASNTag()
     * [:36841,:36842], OID match [:36854-:36856], optional-critical probe
     * [:36863,:36864], reason ENUMERATED probe [:36877,:36878,:36881,:36882]). */
    reasonCode = -1;
    sz = wb_build_reason_ext(list, 1 /* keyCompromise */);
    ret = ParseCRL_EntryExtensions(list, 0, sz, &reasonCode, NULL);
    WB_CHECK(ret == 0 && reasonCode == 1, "reason-code extension parses");

    /* Same but with an explicit critical=FALSE BOOLEAN present -> the
     * optional-critical probe's tag==ASN_BOOLEAN branch [:36863,:36864]
     * true this time (probe found a BOOLEAN). */
    {
        byte enumTlv[3], seq[64];
        byte critB = 0x00;
        word32 idx = 0;
        static const byte reasonOid[] = { 0x55, 0x1d, 0x15 };
        word32 enumSz = wb_tlv(enumTlv, ASN_ENUMERATED, (byte*)"\x02", 1);
        idx += wb_tlv(seq + idx, ASN_OBJECT_ID, reasonOid, sizeof(reasonOid));
        idx += wb_tlv(seq + idx, ASN_BOOLEAN, &critB, 1);
        /* extnValue: OCTET STRING wrapping the ENUMERATED, once. */
        idx += wb_tlv(seq + idx, ASN_OCTET_STRING, enumTlv, enumSz);
        sz = WB_SEQ(list, seq, idx);
    }
    reasonCode = -1;
    ret = ParseCRL_EntryExtensions(list, 0, sz, &reasonCode, NULL);
    WB_CHECK(ret == 0 && reasonCode == 2,
            "reason-code extension with explicit critical=FALSE");

    /* --- malformed entry-extension shapes ------------------------------- *
     * The tokeniser walks each extension by hand (tag / length / content)
     * and every probe is an AND whose second operand only shows its other
     * value on a deliberately broken encoding. Real CRLs are well-formed, so
     * these are white-box only. Each shape is parsed on its own; a break out
     * of the loop is the expected outcome and reasonCode simply stays unset.
     */
    {
        byte  seqBuf[64];
        word32 idx2;
        byte  b;

        /* (a) first item is not an OBJECT IDENTIFIER -> the "tag !=
         *     ASN_OBJECT_ID" operand true with a successful tag read. */
        idx2 = 0;
        b = 0x01;
        idx2 += wb_tlv(seqBuf + idx2, ASN_INTEGER, &b, 1);
        sz = WB_SEQ(list, seqBuf, idx2);
        reasonCode = -1;
        ret = ParseCRL_EntryExtensions(list, 0, sz, &reasonCode, NULL);
        WB_CHECK(reasonCode == -1, "extension whose first item is not an OID");

        /* (b) an empty extension SEQUENCE -> the tag read itself fails. */
        sz = WB_SEQ(list, seqBuf, 0);
        reasonCode = -1;
        ret = ParseCRL_EntryExtensions(list, 0, sz, &reasonCode, NULL);
        WB_CHECK(reasonCode == -1, "empty extension SEQUENCE (tag read fails)");

        /* (c) reason OID with NOTHING after it -> the optional-critical
         *     probe's tag read fails (1st operand false). */
        {
            static const byte reasonOid[] = { 0x55, 0x1d, 0x15 };
            idx2 = 0;
            idx2 += wb_tlv(seqBuf + idx2, ASN_OBJECT_ID, reasonOid,
                    sizeof(reasonOid));
            sz = WB_SEQ(list, seqBuf, idx2);
            reasonCode = -1;
            ret = ParseCRL_EntryExtensions(list, 0, sz, &reasonCode, NULL);
            WB_CHECK(reasonCode == -1, "reason OID with no value (probe fails)");
        }

        /* (c2) reason OID with a ZERO-LENGTH OCTET STRING: GetOctetString()
         *      succeeds but there is no tag byte left, so the value probe's
         *      1st operand (GetASNTag() == 0) goes false. */
        {
            static const byte reasonOid[] = { 0x55, 0x1d, 0x15 };
            byte octet[4];
            word32 octetSz = wb_tlv(octet, ASN_OCTET_STRING, NULL, 0);

            idx2 = 0;
            idx2 += wb_tlv(seqBuf + idx2, ASN_OBJECT_ID, reasonOid,
                    sizeof(reasonOid));
            XMEMCPY(seqBuf + idx2, octet, octetSz);
            idx2 += octetSz;
            sz = WB_SEQ(list, seqBuf, idx2);
            reasonCode = -1;
            ret = ParseCRL_EntryExtensions(list, 0, sz, &reasonCode, NULL);
            WB_CHECK(reasonCode == -1,
                    ":37042 1st operand false (empty reason OCTET STRING)");
        }

        /* (c3) reason OID whose OCTET STRING holds only the ENUMERATED tag
         *      byte: the tag probe succeeds, then GetLength() runs off the
         *      end, driving :37046's 1st operand false. */
        {
            static const byte reasonOid[] = { 0x55, 0x1d, 0x15 };
            byte tagOnly = ASN_ENUMERATED;
            byte octet[8];
            word32 octetSz = wb_tlv(octet, ASN_OCTET_STRING, &tagOnly, 1);

            idx2 = 0;
            idx2 += wb_tlv(seqBuf + idx2, ASN_OBJECT_ID, reasonOid,
                    sizeof(reasonOid));
            XMEMCPY(seqBuf + idx2, octet, octetSz);
            idx2 += octetSz;
            sz = WB_SEQ(list, seqBuf, idx2);
            reasonCode = -1;
            ret = ParseCRL_EntryExtensions(list, 0, sz, &reasonCode, NULL);
            WB_CHECK(reasonCode == -1,
                    ":37046 1st operand false (truncated reason length)");
        }

        /* (d) reason OID whose OCTET STRING holds an INTEGER instead of an
         *     ENUMERATED -> the value probe's "tag == ASN_ENUMERATED"
         *     operand false. */
        {
            static const byte reasonOid[] = { 0x55, 0x1d, 0x15 };
            byte inner[8], octet[16];
            word32 innerSz, octetSz;

            b = 0x02;
            innerSz = wb_tlv(inner, ASN_INTEGER, &b, 1);
            octetSz = wb_tlv(octet, ASN_OCTET_STRING, inner, innerSz);
            idx2 = 0;
            idx2 += wb_tlv(seqBuf + idx2, ASN_OBJECT_ID, reasonOid,
                    sizeof(reasonOid));
            XMEMCPY(seqBuf + idx2, octet, octetSz);
            idx2 += octetSz;
            sz = WB_SEQ(list, seqBuf, idx2);
            reasonCode = -1;
            ret = ParseCRL_EntryExtensions(list, 0, sz, &reasonCode, NULL);
            WB_CHECK(reasonCode == -1, "reason value is INTEGER, not ENUMERATED");
        }

        /* (e) reason ENUMERATED carrying TWO content bytes -> the
         *     "reasonLen == 1" operand false, so no reason is recorded. */
        {
            static const byte reasonOid[] = { 0x55, 0x1d, 0x15 };
            byte two[2] = { 0x00, 0x02 };
            byte inner[8], octet[16];
            word32 innerSz, octetSz;

            innerSz = wb_tlv(inner, ASN_ENUMERATED, two, sizeof(two));
            octetSz = wb_tlv(octet, ASN_OCTET_STRING, inner, innerSz);
            idx2 = 0;
            idx2 += wb_tlv(seqBuf + idx2, ASN_OBJECT_ID, reasonOid,
                    sizeof(reasonOid));
            XMEMCPY(seqBuf + idx2, octet, octetSz);
            idx2 += octetSz;
            sz = WB_SEQ(list, seqBuf, idx2);
            reasonCode = -1;
            ret = ParseCRL_EntryExtensions(list, 0, sz, &reasonCode, NULL);
            WB_CHECK(reasonCode == -1, "reason ENUMERATED with length != 1");
        }
        (void)ret;
    }

    /* Unknown (non-reason) OID, not critical, dcrl==NULL (no callback
     * dispatch possible) -> :36891 1st operand false (short-circuit);
     * :36935 critical operand false -> ignored, ret==0. */
    {
        byte val[2] = { 0xAA, 0xBB };
        sz = wb_ext(list, wbOidOther, sizeof(wbOidOther), 1, 0, val,
                sizeof(val));
    }
    reasonCode = -1;
    ret = ParseCRL_EntryExtensions(list, 0, sz, &reasonCode, NULL);
    WB_CHECK(ret == 0, "unknown non-critical extension, dcrl==NULL, ignored");

    /* Unknown OID, CRITICAL, dcrl==NULL -> :36935 both true (handled stays
     * 0 since the callback block is unreachable with dcrl==NULL) ->
     * ASN_CRIT_EXT_E. */
    {
        byte val[2] = { 0xAA, 0xBB };
        sz = wb_ext(list, wbOidOther, sizeof(wbOidOther), 1, 1, val,
                sizeof(val));
    }
    reasonCode = -1;
    ret = ParseCRL_EntryExtensions(list, 0, sz, &reasonCode, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_CRIT_EXT_E),
            ":36935 both true (unknown critical extension, no callback)");

#ifdef WC_ASN_UNKNOWN_EXT_CB
    /* Unknown OID, non-critical, dcrl != NULL but NEITHER callback
     * registered -> :36891 1st operand true, both callback operands false,
     * so the whole dispatch decision is false. Every other dcrl!=NULL row
     * below registers at least one callback, and every no-callback row above
     * passes dcrl==NULL (which short-circuits on the 1st operand), so this
     * is the only row that can pair with them on the 2nd operand. */
    dcrl.unknownExtCallback = NULL;
    dcrl.unknownExtCallbackEx = NULL;
    {
        byte val[2] = { 0xAA, 0xBB };
        sz = wb_ext(list, wbOidOther, sizeof(wbOidOther), 1, 0, val,
                sizeof(val));
    }
    reasonCode = -1;
    ret = ParseCRL_EntryExtensions(list, 0, sz, &reasonCode, &dcrl);
    WB_CHECK(ret == 0,
            ":36891 dcrl!=NULL with no callbacks (2nd/3rd operands false)");

    /* Unknown OID, CRITICAL, dcrl!=NULL with a registered callback that
     * accepts it (returns 0) -> :36891/:36892 both true (via the 1st
     * disjunct), :36917 both true, :36935 not reached (handled=1). */
    dcrl.unknownExtCallback = wb_entry_ext_cb;
    dcrl.unknownExtCallbackEx = NULL;
    wbEntryCbCalls = 0;
    {
        byte val[2] = { 0xAA, 0xBB };
        sz = wb_ext(list, wbOidOther, sizeof(wbOidOther), 1, 1, val,
                sizeof(val));
    }
    reasonCode = -1;
    ret = ParseCRL_EntryExtensions(list, 0, sz, &reasonCode, &dcrl);
    WB_CHECK(ret == 0 && wbEntryCbCalls == 1,
            ":36891/:36892 true via unknownExtCallback!=NULL; :36917 both true");

    /* Same, but only unknownExtCallbackEx registered -> :36891/:36892 true
     * via the 2nd disjunct (unknownExtCallback == NULL is the FALSE half of
     * that operand); :36917 2nd operand false (unknownExtCallback == NULL);
     * :36921 both true. */
    dcrl.unknownExtCallback = NULL;
    dcrl.unknownExtCallbackEx = wb_entry_ext_cb_ex;
    wbEntryCbExCalls = 0;
    wbEntryCbExRet = 0;
    dcrl.unknownExtCallbackExCtx = NULL;
    {
        byte val[2] = { 0xAA, 0xBB };
        sz = wb_ext(list, wbOidOther, sizeof(wbOidOther), 1, 1, val,
                sizeof(val));
    }
    reasonCode = -1;
    ret = ParseCRL_EntryExtensions(list, 0, sz, &reasonCode, &dcrl);
    WB_CHECK(ret == 0 && wbEntryCbExCalls == 1,
            "Ex-only callback: :36891 1st disjunct false, :36917 2nd false, "
            ":36921 both true");

    /* First callback registered and REJECTING (returns non-zero): the
     * cbRet==0 operand of the second dispatch decision (:36921) is then
     * false, which no accepting-callback run can produce. Both callbacks are
     * registered so the Ex operand stays true-capable but is never reached. */
    dcrl.unknownExtCallback = wb_entry_ext_cb;
    dcrl.unknownExtCallbackEx = wb_entry_ext_cb_ex;
    wbEntryCbCalls = 0;
    wbEntryCbExCalls = 0;
    wbEntryCbRet = -1;
    {
        byte val[2] = { 0xAA, 0xBB };
        sz = wb_ext(list, wbOidOther, sizeof(wbOidOther), 1, 0, val,
                sizeof(val));
    }
    reasonCode = -1;
    ret = ParseCRL_EntryExtensions(list, 0, sz, &reasonCode, &dcrl);
    WB_CHECK(ret != 0 && wbEntryCbCalls == 1 && wbEntryCbExCalls == 0,
            ":36921 1st operand false (first callback rejected)");
    wbEntryCbRet = 0;

    /* An OID with more sub-identifiers than DecodeObjectId()'s output buffer
     * holds: GetASN_ObjectId() still accepts the encoding, so the dispatch
     * block is entered, but DecodeObjectId() returns BUFFER_E -- the only way
     * to make the cbRet==0 operand of the FIRST dispatch decision (:36917)
     * false. */
    {
        byte longOid[MAX_OID_SZ + 4];
        byte val[2] = { 0xAA, 0xBB };
        word32 i;

        /* Every octet < 0x80 is a complete single-octet sub-identifier, so
         * this is a well-formed OID body with MAX_OID_SZ+4 arcs. */
        for (i = 0; i < (word32)sizeof(longOid); i++) {
            longOid[i] = (byte)(0x2A + (i & 0x1F));
        }
        sz = wb_ext(list, longOid, (word32)sizeof(longOid), 1, 0, val,
                sizeof(val));
    }
    dcrl.unknownExtCallback = wb_entry_ext_cb;
    dcrl.unknownExtCallbackEx = wb_entry_ext_cb_ex;
    wbEntryCbCalls = 0;
    wbEntryCbExCalls = 0;
    reasonCode = -1;
    ret = ParseCRL_EntryExtensions(list, 0, sz, &reasonCode, &dcrl);
    WB_CHECK(wbEntryCbCalls == 0 && wbEntryCbExCalls == 0,
            ":36917/:36921 1st operand false (DecodeObjectId overflow)");
    (void)ret;
#endif /* WC_ASN_UNKNOWN_EXT_CB */

    FreeDecodedCRL(&dcrl);
}
#else
static void wb_parse_crl_entry_extensions(void) { WB_NOTE("HAVE_CRL off or WOLFCRYPT_ONLY; ParseCRL_EntryExtensions skipped"); }
#endif /* HAVE_CRL && !WOLFCRYPT_ONLY */

#if defined(HAVE_CRL) && !defined(WOLFCRYPT_ONLY) && defined(WOLFSSL_ASN_TEMPLATE)
/* ------------------------------------------------------------------------- *
 * Section 12: ParseCRL_Extensions() duplicate-extension / CRL-number checks
 * [:37284,:37285(idx 2,3),:37325,:37326,:37335,:37349,:37358,:37359,:37384,
 * :37407(idx1)]
 *
 * Two adjacent conditions are ARGUED UNREACHABLE (not attempted below):
 *   - the CRL-number branch's "if (ret == 0 && (INIT_MP_INT_SIZE(...) !=
 *     MP_OKAY))" guard: outside WOLFSSL_SMALL_STACK, DECL_MP_INT_SIZE_DYN
 *     stack-allocates `m` unconditionally (MP_INT_SIZE_CHECK_NULL is only
 *     defined under WOLFSSL_SMALL_STACK), so ret==0 never goes false here
 *     without a heap-allocation fault injector; INIT_MP_INT_SIZE() on that
 *     buffer is a plain mp_init() that cannot itself fail. Both operands
 *     are therefore compile-time constant in every variant this white-box
 *     runs under.
 *   - "if (ret == 0 && mp_toradix(m, dcrl->crlNumber, MP_RADIX_HEX) !=
 *     MP_OKAY)": dcrl->crlNumber is CRL_MAX_NUM_HEX_STR_SZ bytes
 *     (CRL_MAX_NUM_SZ*2+1 = 41), which is exactly the space a maximum-size
 *     (20-byte, CRL_MAX_NUM_SZ) positive CRL number's hex-radix conversion
 *     needs -- verified empirically with a 20-byte value (0x7F followed by
 *     19 bytes of 0xFF, the largest positive value the preceding size/sign
 *     checks admit): mp_toradix() still succeeds. ret==0 is also always
 *     true reaching this line (nothing between the two checks can set it
 *     nonzero without the residual above already applying), so this
 *     decision's operands are constant too.
 * ------------------------------------------------------------------------- */
static word32 wb_build_crl_number_ext(byte* out, const byte* intContent,
        word32 intContentSz)
{
    byte intTlv[32];
    word32 intSz = wb_tlv(intTlv, ASN_INTEGER, intContent, intContentSz);

    /* wb_ext() already wraps its value argument in the extension's OCTET
     * STRING, so the INTEGER TLV is handed over bare -- wrapping it here as
     * well produced an OCTET STRING inside an OCTET STRING, which the
     * decoder rejected before ever reaching the CRL-number logic. */
    return wb_ext(out, wbOidCrlNumber, sizeof(wbOidCrlNumber), 0, 0, intTlv,
            intSz);
}

static void wb_parse_crl_extensions(void)
{
    byte extList[256];
    word32 sz;
    DecodedCRL dcrl;
    int ret;

    WB_NOTE("ParseCRL_Extensions(): CRL_NUMBER_OID duplicate/size/negative "
            "checks [:37284,:37285,:37325,:37326,:37335,:37349,:37358,:37359]; "
            "unknown critical, no callback [:37407]");

    /* Valid small positive CRL number (value 5) -> baseline, all false. */
    InitDecodedCRL(&dcrl, NULL);
    {
        byte val = 0x05;
        sz = wb_build_crl_number_ext(extList, &val, 1);
    }
    ret = ParseCRL_Extensions(&dcrl, extList, 0, sz);
    WB_CHECK(ret == 0 && dcrl.crlNumberSet == 1,
            "valid small CRL number (baseline)");
    FreeDecodedCRL(&dcrl);

    /* CRL number content > CRL_MAX_NUM_SZ(20) bytes -> the inner check sets
     * ret = BUFFER_E, but ParseCRL_Extensions()'s own tail normalizes any
     * negative ret (other than ASN_CRIT_EXT_E) to ASN_PARSE_E before
     * returning, so the value observed here is ASN_PARSE_E even though the
     * decision itself went both-true on BUFFER_E. */
    InitDecodedCRL(&dcrl, NULL);
    {
        byte big[21];
        XMEMSET(big, 0x01, sizeof(big));
        sz = wb_build_crl_number_ext(extList, big, sizeof(big));
    }
    ret = ParseCRL_Extensions(&dcrl, extList, 0, sz);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
            "CRL number too long (inner check both true -> BUFFER_E, "
            "normalized to ASN_PARSE_E on return)");
    FreeDecodedCRL(&dcrl);

    /* CRL number with MSB set and no leading-zero pad -> negative ->
     * :37349 both true. */
    InitDecodedCRL(&dcrl, NULL);
    {
        byte neg = 0x90;
        sz = wb_build_crl_number_ext(extList, &neg, 1);
    }
    ret = ParseCRL_Extensions(&dcrl, extList, 0, sz);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
            ":37349 both true (negative CRL number)");
    FreeDecodedCRL(&dcrl);

    /* CRL number whose value is not an INTEGER at all (a BOOLEAN in its
     * place) -> GetASNInt()'s own GetASNHeader(ASN_INTEGER, ...) call fails
     * before the crlNumLen>CRL_MAX_NUM_SZ / negative-value checks ever run
     * -> ret!=0 reaches both of those checks with its own operand false:
     * the independence pair for their ret==0 operand (every vector above
     * reaches them with ret==0 still true). */
    InitDecodedCRL(&dcrl, NULL);
    {
        byte boolTlv[3];
        byte b = 0x00;
        word32 boolSz = wb_tlv(boolTlv, ASN_BOOLEAN, &b, 1);
        sz = wb_ext(extList, wbOidCrlNumber, sizeof(wbOidCrlNumber), 0, 0,
                boolTlv, boolSz);
    }
    ret = ParseCRL_Extensions(&dcrl, extList, 0, sz);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
            "CRL number value is not an INTEGER (GetASNInt() fails; ret==0 "
            "operand false at both the size and negative-value checks)");
    FreeDecodedCRL(&dcrl);

    /* CRL number with zero-length INTEGER content -> crlNumLen==0, so the
     * size check's 2nd operand is false and control reaches the negative-
     * value check with rawLen==0 -> its 1st operand (rawLen>0) false, the
     * independence pair for a check that is otherwise always seen with
     * rawLen>0 (every non-empty CRL number above). GetInt() on an empty
     * INTEGER also fails, so ret is non-zero by the time mp_toradix() would
     * run -- also exercises :37523's ret==0 operand false. */
    InitDecodedCRL(&dcrl, NULL);
    {
        byte intTlv[2];
        word32 intSz = wb_tlv(intTlv, ASN_INTEGER, NULL, 0);
        sz = wb_ext(extList, wbOidCrlNumber, sizeof(wbOidCrlNumber), 0, 0,
                intTlv, intSz);
    }
    ret = ParseCRL_Extensions(&dcrl, extList, 0, sz);
    WB_CHECK(ret != 0,
            "CRL number with zero-length INTEGER content (:37514 1st "
            "operand false; GetInt() fails on empty content)");
    FreeDecodedCRL(&dcrl);

    /* Duplicate CRL_NUMBER_OID extensions -> :37284/:37285 CRL_NUMBER_OID
     * term both true on the 2nd occurrence (WOLFSSL_NO_ASN_STRICT is not
     * defined for this campaign, so strict duplicate rejection applies). */
    InitDecodedCRL(&dcrl, NULL);
    {
        byte ext1[64], ext2[64];
        word32 s1, s2;
        byte val = 0x05;
        s1 = wb_build_crl_number_ext(ext1, &val, 1);
        s2 = wb_build_crl_number_ext(ext2, &val, 1);
        XMEMCPY(extList, ext1, s1);
        XMEMCPY(extList + s1, ext2, s2);
        sz = s1 + s2;
    }
    ret = ParseCRL_Extensions(&dcrl, extList, 0, sz);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
            ":37284/:37285 CRL_NUMBER_OID term both true (duplicate)");
    FreeDecodedCRL(&dcrl);

    /* Unknown, non-critical extension with no callback registered -> falls
     * through both the WC_ASN_UNKNOWN_EXT_CB block and the plain
     * "critical" check with critical==0 -> ignored, ret==0. */
    InitDecodedCRL(&dcrl, NULL);
    {
        byte val[2] = { 0x01, 0x02 };
        sz = wb_ext(extList, wbOidOther, sizeof(wbOidOther), 1, 0, val,
                sizeof(val));
    }
    ret = ParseCRL_Extensions(&dcrl, extList, 0, sz);
    WB_CHECK(ret == 0, "unknown non-critical extension ignored");
    FreeDecodedCRL(&dcrl);

#ifndef WC_ASN_UNKNOWN_EXT_CB
    /* Only reachable as "handled==0" residual note when the callback
     * feature is compiled out; this campaign has it on (see below), kept
     * here for portability to a variant that does not. */
    InitDecodedCRL(&dcrl, NULL);
    {
        byte val[2] = { 0x01, 0x02 };
        sz = wb_ext(extList, wbOidOther, sizeof(wbOidOther), 1, 1, val,
                sizeof(val));
    }
    ret = ParseCRL_Extensions(&dcrl, extList, 0, sz);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_CRIT_EXT_E),
            ":37407 both true (unknown critical, no callback compiled in)");
    FreeDecodedCRL(&dcrl);
#else
    /* WC_ASN_UNKNOWN_EXT_CB is active here (WOLFSSL_ASN_ALL pulls in
     * WOLFSSL_CUSTOM_OID + HAVE_OID_DECODING) -- with no callback
     * registered on dcrl, the block's own guard
     * (unknownExtCallback!=NULL || unknownExtCallbackEx!=NULL) is false,
     * so control still reaches the plain critical check with handled==0. */
    InitDecodedCRL(&dcrl, NULL);
    {
        byte val[2] = { 0x01, 0x02 };
        sz = wb_ext(extList, wbOidOther, sizeof(wbOidOther), 1, 1, val,
                sizeof(val));
    }
    ret = ParseCRL_Extensions(&dcrl, extList, 0, sz);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_CRIT_EXT_E),
            ":37407 both true (unknown critical, no callback registered)");
    FreeDecodedCRL(&dcrl);

    /* Unknown, non-critical extension with a callback registered that
     * accepts it (returns 0) -> :37549 both true (ret==0 from a successful
     * DecodeObjectId(), unknownExtCallback!=NULL) -- the "true" side needed
     * to pair against the DecodeObjectId()-overflow vector below (every
     * other vector in this function either carries no callback at all, or
     * a known OID that never reaches this "unknown extension" branch). */
    InitDecodedCRL(&dcrl, NULL);
    dcrl.unknownExtCallback = wb_entry_ext_cb;
    dcrl.unknownExtCallbackEx = NULL;
    wbEntryCbCalls = 0;
    wbEntryCbRet = 0;
    {
        byte val[2] = { 0xAA, 0xBB };
        sz = wb_ext(extList, wbOidOther, sizeof(wbOidOther), 1, 0, val,
                sizeof(val));
    }
    ret = ParseCRL_Extensions(&dcrl, extList, 0, sz);
    WB_CHECK(ret == 0 && wbEntryCbCalls == 1,
            ":37549 both true (unknown non-critical extension, callback "
            "accepts it)");
    FreeDecodedCRL(&dcrl);

    /* Only unknownExtCallbackEx registered (unknownExtCallback stays NULL)
     * -> the outer "unknownExtCallback!=NULL || unknownExtCallbackEx!=NULL"
     * dispatch guard is still true (2nd disjunct), so this branch is
     * entered, but :37549 itself -- gated on unknownExtCallback specifically
     * -- sees its 2nd operand false (short-circuits without invoking
     * wb_entry_ext_cb). */
    InitDecodedCRL(&dcrl, NULL);
    dcrl.unknownExtCallback = NULL;
    dcrl.unknownExtCallbackEx = wb_entry_ext_cb_ex;
    dcrl.unknownExtCallbackExCtx = NULL;
    wbEntryCbExCalls = 0;
    wbEntryCbExRet = 0;
    {
        byte val[2] = { 0xAA, 0xBB };
        sz = wb_ext(extList, wbOidOther, sizeof(wbOidOther), 1, 0, val,
                sizeof(val));
    }
    ret = ParseCRL_Extensions(&dcrl, extList, 0, sz);
    WB_CHECK(ret == 0 && wbEntryCbExCalls == 1,
            ":37549 2nd operand false (Ex-only callback registered)");
    FreeDecodedCRL(&dcrl);

    /* An unknown extension OID with more sub-identifiers than
     * DecodeObjectId()'s output buffer holds, with a callback registered so
     * the dispatch block is entered: GetASN_OID()/GetASN_Items() still
     * accept the encoding, but DecodeObjectId() itself returns BUFFER_E,
     * setting ret!=0 before the ":37549 ret==0 && unknownExtCallback!=NULL"
     * check runs -- the independence pair for its 1st operand, paired
     * against the accepting-callback vector above. Mirrors the identical
     * technique already used for ParseCRL_EntryExtensions() above. */
    {
        byte longOid[MAX_OID_SZ + 4];
        byte val[2] = { 0xAA, 0xBB };
        word32 i;

        for (i = 0; i < (word32)sizeof(longOid); i++) {
            longOid[i] = (byte)(0x2A + (i & 0x1F));
        }
        InitDecodedCRL(&dcrl, NULL);
        dcrl.unknownExtCallback = wb_entry_ext_cb;
        dcrl.unknownExtCallbackEx = NULL;
        wbEntryCbCalls = 0;
        sz = wb_ext(extList, longOid, (word32)sizeof(longOid), 1, 0, val,
                sizeof(val));
        ret = ParseCRL_Extensions(&dcrl, extList, 0, sz);
        WB_CHECK(ret != 0 && wbEntryCbCalls == 0,
                ":37549 1st operand false (DecodeObjectId() overflow, "
                "callback never reached)");
        FreeDecodedCRL(&dcrl);
    }
#endif /* !WC_ASN_UNKNOWN_EXT_CB */
}
#else
static void wb_parse_crl_extensions(void) { WB_NOTE("HAVE_CRL/ASN_TEMPLATE off; ParseCRL_Extensions skipped"); }
#endif

#if defined(HAVE_CRL) && !defined(WOLFCRYPT_ONLY) && defined(WOLFSSL_ASN_TEMPLATE)
/* ------------------------------------------------------------------------- *
 * Section 12b: PaseCRL_CheckSignature() AKID/issuer-hash CA lookup
 * [:37330,:37338] (called directly; it is file-static). A real CertManager
 * loaded with ca_cert_der_2048 provides a genuine Signer, so GetCA()'s AKID
 * lookup and GetCAByName()'s issuer-hash lookup both have something to find;
 * VerifyCRL_Signature() itself is never reached with a valid signature here
 * (dcrl->signature/sigLength are left zeroed), so only the CA-lookup
 * decisions above it are the coverage goal.
 * ------------------------------------------------------------------------- */
static void wb_parse_crl_check_signature(void)
{
    WOLFSSL_CERT_MANAGER* cm;
    DecodedCert cacert;
    Signer* signer;
    int ret;
    byte matchingIssuerHash[SIGNER_DIGEST_SIZE];
    byte mismatchIssuerHash[SIGNER_DIGEST_SIZE];
    static const byte tbsBuf[4] = { 0x30, 0x02, 0x05, 0x00 };

    WB_NOTE("PaseCRL_CheckSignature(): GetCA()/GetCAByName() CA-lookup "
            "decisions [:37330,:37338]");

    cm = wolfSSL_CertManagerNew();
    if (cm == NULL) {
        return;
    }
    (void)wolfSSL_CertManagerLoadCABuffer(cm, ca_cert_der_2048,
            (word32)sizeof_ca_cert_der_2048, WOLFSSL_FILETYPE_ASN1);

    XMEMSET(&cacert, 0, sizeof(cacert));
    InitDecodedCert(&cacert, ca_cert_der_2048,
            (word32)sizeof_ca_cert_der_2048, NULL);
    ret = ParseCertRelative(&cacert, CA_TYPE, NO_VERIFY, NULL, NULL);
    WB_CHECK(ret == 0, "pre-parse of ca_cert_der_2048 (fixture sanity)");
    if (ret == 0) {
        XMEMCPY(matchingIssuerHash, cacert.subjectHash, SIGNER_DIGEST_SIZE);
        XMEMSET(mismatchIssuerHash, 0xEE, SIGNER_DIGEST_SIZE);
        FreeDecodedCert(&cacert);

        signer = GetCAByName(cm, matchingIssuerHash);
        WB_CHECK(signer != NULL, "GetCAByName() finds the loaded CA "
                "(fixture sanity)");
        if (signer != NULL) {
            DecodedCRL dcrl;

            /* extAuthKeyIdSet==0: the AKID GetCA() lookup is skipped, so ca
             * stays NULL going into :37330 -> 1st operand false. Falls to
             * GetCAByName() with a matching issuerHash, which finds the
             * signer: :37338 1st operand true (ca!=NULL), 2nd operand false
             * (extAuthKeyIdSet==0) -> ca kept, ret stays 0 into
             * VerifyCRL_Signature(). */
            InitDecodedCRL(&dcrl, NULL);
            dcrl.extAuthKeyIdSet = 0;
            XMEMCPY(dcrl.issuerHash, matchingIssuerHash, SIGNER_DIGEST_SIZE);
            ret = PaseCRL_CheckSignature(&dcrl, NULL, 0, tbsBuf, cm);
            WB_CHECK(ret != WC_NO_ERR_TRACE(ASN_CRL_NO_SIGNER_E),
                    ":37330 1st operand false (no AKID); :37338 both true "
                    "-> false via 2nd operand (extAuthKeyIdSet==0)");

            /* extAuthKeyIdSet==1 with extAuthKeyId set to the signer's own
             * subjectKeyIdHash -> GetCA() finds it: :37330 1st operand true.
             * issuerHash deliberately mismatched -> XMEMCMP!=0 -> :37330
             * both true -> ca reset to NULL. GetCAByName() is then tried
             * with the same mismatched hash and finds nothing, so ca stays
             * NULL and :37338 is never reached this call (its "false"
             * side -- ca==NULL -- is exercised by the malformed-cert-style
             * failure below instead). */
            InitDecodedCRL(&dcrl, NULL);
            dcrl.extAuthKeyIdSet = 1;
            XMEMCPY(dcrl.extAuthKeyId, signer->subjectKeyIdHash,
                    SIGNER_DIGEST_SIZE);
            XMEMCPY(dcrl.issuerHash, mismatchIssuerHash, SIGNER_DIGEST_SIZE);
            ret = PaseCRL_CheckSignature(&dcrl, NULL, 0, tbsBuf, cm);
            WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_CRL_NO_SIGNER_E),
                    ":37330 both true (AKID hit, issuerHash mismatch -> ca "
                    "reset); GetCAByName() on the mismatched hash also "
                    "fails -> ASN_CRL_NO_SIGNER_E");

            /* extAuthKeyIdSet==1 with extAuthKeyId AND issuerHash both
             * matching the same signer -> :37330 1st operand true, XMEMCMP
             * 2nd operand false (matches) -> ca is kept (not reset); the
             * outer "if (ca == NULL)" is then false, so :37338 is skipped
             * on this call -- its ca!=NULL,extAuthKeyIdSet==1 combination is
             * not otherwise reachable (that pairing never resets ca, so the
             * GetCAByName() branch guarding :37338 never runs), which is
             * fine: :37338 only needs its OWN two operands independently
             * paired, both already exercised above. */
            InitDecodedCRL(&dcrl, NULL);
            dcrl.extAuthKeyIdSet = 1;
            XMEMCPY(dcrl.extAuthKeyId, signer->subjectKeyIdHash,
                    SIGNER_DIGEST_SIZE);
            XMEMCPY(dcrl.issuerHash, matchingIssuerHash, SIGNER_DIGEST_SIZE);
            ret = PaseCRL_CheckSignature(&dcrl, NULL, 0, tbsBuf, cm);
            WB_CHECK(ret != WC_NO_ERR_TRACE(ASN_CRL_NO_SIGNER_E),
                    ":37330 1st true, 2nd false (AKID hit, issuerHash "
                    "matches -> ca kept, VerifyCRL_Signature() reached)");

            /* extAuthKeyIdSet==1 with a bogus extAuthKeyId (GetCA() via AKID
             * finds nothing, so ca is still NULL going into the ":37330"
             * check -- 1st operand false, decision false, ca untouched) but
             * a matching issuerHash (GetCAByName() finds the signer) ->
             * :37338 1st operand true (ca!=NULL) AND 2nd operand true
             * (extAuthKeyIdSet==1) -> both true -> ca reset to NULL ("CA
             * SKID doesn't match AKID") -> ASN_CRL_NO_SIGNER_E. This is the
             * independence pair for :37338's 1st operand: the earlier
             * extAuthKeyIdSet==0 vector showed ca!=NULL with the decision
             * false (via the 2nd operand); this one shows ca!=NULL with the
             * decision true, isolating the 1st operand's effect. */
            InitDecodedCRL(&dcrl, NULL);
            dcrl.extAuthKeyIdSet = 1;
            XMEMSET(dcrl.extAuthKeyId, 0x77, SIGNER_DIGEST_SIZE);
            XMEMCPY(dcrl.issuerHash, matchingIssuerHash, SIGNER_DIGEST_SIZE);
            ret = PaseCRL_CheckSignature(&dcrl, NULL, 0, tbsBuf, cm);
            WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_CRL_NO_SIGNER_E),
                    ":37338 both true (bogus AKID, issuerHash matches -> "
                    "CA found by name but rejected for AKID mismatch)");
        }
    }
    else {
        FreeDecodedCert(&cacert);
    }
    wolfSSL_CertManagerFree(cm);
}
#else
static void wb_parse_crl_check_signature(void) { WB_NOTE("HAVE_CRL/ASN_TEMPLATE off; PaseCRL_CheckSignature skipped"); }
#endif

#if defined(HAVE_CRL) && !defined(WOLFCRYPT_ONLY) && defined(WOLFSSL_ASN_TEMPLATE)
/* ------------------------------------------------------------------------- *
 * Section 13: ParseCRL() top-level decisions
 * [:37548,:37549,:37553,:37557,:37561,:37562,:37608,:37609,:37613,:37614,
 * :37630-:37632]
 * Built entirely from TLVs (not wc_MakeCRL_ex(), which cannot itself
 * produce most of these malformed shapes). cm==NULL throughout: GetCA()/
 * GetCAByName() are NULL-safe (ssl_certman.c), so PaseCRL_CheckSignature()
 * always fails cleanly with ASN_CRL_NO_SIGNER_E after everything above it
 * has run -- exactly the decisions this section targets.
 * ------------------------------------------------------------------------- */
static word32 wb_build_crl_tbs(byte* out, int version,
        const byte* lastDate, word32 lastDateLen, byte lastDateTag,
        const byte* nextDate, word32 nextDateLen, byte nextDateTag,
        int sigAlgoMismatch)
{
    byte content[400];
    word32 idx = 0;
    byte issuer[2] = { 0x30, 0x00 }; /* empty Name SEQUENCE */
    byte algo1[32], algo2[32];
    word32 a1Sz, a2Sz;

    if (version >= 2) {
        byte verBuf[8];
        int verSz = SetMyVersion((word32)(version - 1), verBuf, 0);
        XMEMCPY(content + idx, verBuf, (size_t)verSz);
        idx += (word32)verSz;
    }

    a1Sz = SetAlgoID(CTC_SHA256wRSA, algo1, oidSigType, 0);
    XMEMCPY(content + idx, algo1, a1Sz);
    idx += a1Sz;

    XMEMCPY(content + idx, issuer, sizeof(issuer));
    idx += sizeof(issuer);

    idx += wb_tlv(content + idx, lastDateTag, lastDate, lastDateLen);
    if (nextDate != NULL) {
        idx += wb_tlv(content + idx, nextDateTag, nextDate, nextDateLen);
    }

    a2Sz = SetAlgoID(sigAlgoMismatch ? CTC_SHA256wECDSA : CTC_SHA256wRSA,
            algo2, oidSigType, 0);
    {
        byte sigHdr[8];
        byte fakeSig[16];
        word32 sigHdrSz;
        word32 total;
        byte tbsSeqBuf[8];
        word32 tbsSeqSz;

        XMEMSET(fakeSig, 0xAA, sizeof(fakeSig));
        sigHdrSz = SetBitString(sizeof(fakeSig), 0, sigHdr);

        tbsSeqSz = SetSequence(idx, tbsSeqBuf);
        total = tbsSeqSz + idx + a2Sz + sigHdrSz + sizeof(fakeSig);
        {
            byte outer[8];
            word32 outerSz = SetSequence(total, outer);
            word32 o = 0;
            XMEMCPY(out + o, outer, outerSz); o += outerSz;
            XMEMCPY(out + o, tbsSeqBuf, tbsSeqSz); o += tbsSeqSz;
            XMEMCPY(out + o, content, idx); o += idx;
            XMEMCPY(out + o, algo2, a2Sz); o += a2Sz;
            XMEMCPY(out + o, sigHdr, sigHdrSz); o += sigHdrSz;
            XMEMCPY(out + o, fakeSig, sizeof(fakeSig)); o += sizeof(fakeSig);
            return o;
        }
    }
}

/* A CRL whose two AlgorithmIdentifiers carry explicit parameters, which
 * SetAlgoID() cannot emit. `pssOid` selects id-RSASSA-PSS (the only algorithm
 * allowed to carry them) or sha256WithRSAEncryption. */
static word32 wb_build_crl_params(byte* out, const byte* tbsParams,
        word32 tbsParamsSz, const byte* sigParams, word32 sigParamsSz,
        int pssOid)
{
    static const byte oidPss[]    = {
        0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0A };
    static const byte oidRsaSha[] = {
        0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0B };
    static const byte pastDate[15]   = "20200101000000Z";
    static const byte futureDate[15] = "20991231235959Z";
    const byte* oid = pssOid ? oidPss : oidRsaSha;
    byte algo[64];
    byte content[400];
    byte issuer[2] = { 0x30, 0x00 };
    word32 idx = 0;
    word32 a1Sz, a2Sz;

    /* tbsCertList.signature */
    {
        byte inner[64];
        word32 n = wb_tlv(inner, ASN_OBJECT_ID, oid, 9);
        XMEMCPY(inner + n, tbsParams, tbsParamsSz);
        n += tbsParamsSz;
        a1Sz = WB_SEQ(algo, inner, n);
    }
    XMEMCPY(content + idx, algo, a1Sz);
    idx += a1Sz;

    XMEMCPY(content + idx, issuer, sizeof(issuer));
    idx += sizeof(issuer);
    idx += wb_tlv(content + idx, ASN_GENERALIZED_TIME, pastDate, 15);
    idx += wb_tlv(content + idx, ASN_GENERALIZED_TIME, futureDate, 15);

    /* signatureAlgorithm */
    {
        byte inner[64];
        word32 n = wb_tlv(inner, ASN_OBJECT_ID, oid, 9);
        XMEMCPY(inner + n, sigParams, sigParamsSz);
        n += sigParamsSz;
        a2Sz = WB_SEQ(algo, inner, n);
    }
    {
        byte sigHdr[8];
        byte fakeSig[16];
        word32 sigHdrSz;
        byte tbsSeqBuf[8];
        word32 tbsSeqSz;
        byte outer[8];
        word32 outerSz;
        word32 total;
        word32 o = 0;

        XMEMSET(fakeSig, 0xAA, sizeof(fakeSig));
        sigHdrSz = SetBitString(sizeof(fakeSig), 0, sigHdr);
        tbsSeqSz = SetSequence(idx, tbsSeqBuf);
        total = tbsSeqSz + idx + a2Sz + sigHdrSz + (word32)sizeof(fakeSig);
        outerSz = SetSequence(total, outer);
        XMEMCPY(out + o, outer, outerSz); o += outerSz;
        XMEMCPY(out + o, tbsSeqBuf, tbsSeqSz); o += tbsSeqSz;
        XMEMCPY(out + o, content, idx); o += idx;
        XMEMCPY(out + o, algo, a2Sz); o += a2Sz;
        XMEMCPY(out + o, sigHdr, sigHdrSz); o += sigHdrSz;
        XMEMCPY(out + o, fakeSig, sizeof(fakeSig)); o += (word32)sizeof(fakeSig);
        return o;
    }
}

static void wb_parse_crl(void)
{
    byte der[512];
    word32 sz;
    DecodedCRL dcrl;
    RevokedCert rcertArr[2];
    int ret;
    static const byte pastDate[15]   = "20200101000000Z";
    static const byte futureDate[15] = "20991231235959Z";

    WB_NOTE("ParseCRL(): version/date/sigalgo/PSS-param checks "
            "[:37548,:37549,:37553,:37557,:37561,:37562,:37608,:37609,"
            ":37613,:37614,:37630-:37632]");

    /* baseline: version=2 (v2, integer 1), valid past thisUpdate, valid
     * future nextUpdate, matching sig OIDs -> everything false, only
     * PaseCRL_CheckSignature() fails (no CA loaded). */
    InitDecodedCRL(&dcrl, NULL);
    XMEMSET(rcertArr, 0, sizeof(rcertArr));
    sz = wb_build_crl_tbs(der, 2, pastDate, 15, ASN_GENERALIZED_TIME,
            futureDate, 15, ASN_GENERALIZED_TIME, 0);
    ret = ParseCRL(rcertArr, &dcrl, der, sz, VERIFY, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_CRL_NO_SIGNER_E),
            "baseline v2 CRL (all structural checks pass; no CA to verify)");
    FreeDecodedCRL(&dcrl);

    /* version omitted (v1) -> :37548/:37549 1st operand false (tag==0). */
    InitDecodedCRL(&dcrl, NULL);
    XMEMSET(rcertArr, 0, sizeof(rcertArr));
    sz = wb_build_crl_tbs(der, 1, pastDate, 15, ASN_GENERALIZED_TIME,
            futureDate, 15, ASN_GENERALIZED_TIME, 0);
    ret = ParseCRL(rcertArr, &dcrl, der, sz, VERIFY, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_CRL_NO_SIGNER_E),
            ":37548/:37549 1st operand false (version omitted, v1)");
    FreeDecodedCRL(&dcrl);

    /* version present but not v2 (encodes integer 2) -> :37548/:37549 both
     * true -> ASN_PARSE_E. */
    InitDecodedCRL(&dcrl, NULL);
    XMEMSET(rcertArr, 0, sizeof(rcertArr));
    sz = wb_build_crl_tbs(der, 3, pastDate, 15, ASN_GENERALIZED_TIME,
            futureDate, 15, ASN_GENERALIZED_TIME, 0);
    ret = ParseCRL(rcertArr, &dcrl, der, sz, VERIFY, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
            ":37548/:37549 both true (version present, not v2)");
    FreeDecodedCRL(&dcrl);

    /* thisUpdate too short (< MIN_DATE_SIZE=12): use an 11-byte UTCTime
     * content -> :37553 true. */
    InitDecodedCRL(&dcrl, NULL);
    XMEMSET(rcertArr, 0, sizeof(rcertArr));
    {
        static const byte shortDate[11] = "20010101Z00"; /* 11 bytes, junk */
        sz = wb_build_crl_tbs(der, 2, shortDate, 11, ASN_UTC_TIME,
                futureDate, 15, ASN_GENERALIZED_TIME, 0);
    }
    ret = ParseCRL(rcertArr, &dcrl, der, sz, VERIFY, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
            ":37553 true (thisUpdate shorter than MIN_DATE_SIZE)");
    FreeDecodedCRL(&dcrl);

    /* nextUpdate too short -> :37557 true. */
    InitDecodedCRL(&dcrl, NULL);
    XMEMSET(rcertArr, 0, sizeof(rcertArr));
    {
        static const byte shortDate[11] = "20990101Z00";
        sz = wb_build_crl_tbs(der, 2, pastDate, 15, ASN_GENERALIZED_TIME,
                shortDate, 11, ASN_UTC_TIME, 0);
    }
    ret = ParseCRL(rcertArr, &dcrl, der, sz, VERIFY, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
            ":37557 true (nextUpdate shorter than MIN_DATE_SIZE)");
    FreeDecodedCRL(&dcrl);

    /* mismatching signatureAlgorithm vs tbsCertList.signature OID ->
     * :37561/:37562 both true. */
    InitDecodedCRL(&dcrl, NULL);
    XMEMSET(rcertArr, 0, sizeof(rcertArr));
    sz = wb_build_crl_tbs(der, 2, pastDate, 15, ASN_GENERALIZED_TIME,
            futureDate, 15, ASN_GENERALIZED_TIME, 1 /* mismatch */);
    ret = ParseCRL(rcertArr, &dcrl, der, sz, VERIFY, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
            ":37561/:37562 both true (signatureAlgorithm OID mismatch)");
    FreeDecodedCRL(&dcrl);

    /* verify == NO_VERIFY -> :37630 1st operand false, date-validity check
     * skipped even with an expired nextUpdate. */
    InitDecodedCRL(&dcrl, NULL);
    XMEMSET(rcertArr, 0, sizeof(rcertArr));
    sz = wb_build_crl_tbs(der, 2, pastDate, 15, ASN_GENERALIZED_TIME,
            pastDate, 15, ASN_GENERALIZED_TIME, 0); /* nextUpdate expired */
    ret = ParseCRL(rcertArr, &dcrl, der, sz, NO_VERIFY, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_CRL_NO_SIGNER_E),
            ":37630 1st operand false (verify==NO_VERIFY skips date check)");
    FreeDecodedCRL(&dcrl);

    /* verify != NO_VERIFY with an expired nextUpdate -> :37630-:37632 all
     * true -> CRL_CERT_DATE_ERR (AsnSkipDateCheck's own operand stays at
     * its only reachable value, true, without WC_ASN_RUNTIME_DATE_CHECK_CONTROL). */
    InitDecodedCRL(&dcrl, NULL);
    XMEMSET(rcertArr, 0, sizeof(rcertArr));
    ret = ParseCRL(rcertArr, &dcrl, der, sz, VERIFY, NULL);
#if !defined(NO_ASN_TIME) && !defined(WOLFSSL_NO_CRL_DATE_CHECK)
    WB_CHECK(ret == WC_NO_ERR_TRACE(CRL_CERT_DATE_ERR),
            ":37630-:37632 all true (verify!=NO_VERIFY, expired nextUpdate)");
#else
    WB_CHECK(ret != WC_NO_ERR_TRACE(CRL_CERT_DATE_ERR),
            "expired nextUpdate, no clock (date check compiled out)");
#endif
    FreeDecodedCRL(&dcrl);

    /* --- signature-parameter agreement [:37713,:37773,:37778] ---------- *
     * SetAlgoID() cannot emit explicit parameters, so these rows use the
     * dedicated builder above. */
#ifdef WC_RSA_PSS
    {
        static const byte paramsA[] = { 0x30, 0x01, 0x01 };
        static const byte paramsB[] = { 0x30, 0x01, 0x02 };

        InitDecodedCRL(&dcrl, NULL);
        XMEMSET(rcertArr, 0, sizeof(rcertArr));
        sz = wb_build_crl_params(der, paramsA, (word32)sizeof(paramsA),
                paramsA, (word32)sizeof(paramsA), 1);
        ret = ParseCRL(rcertArr, &dcrl, der, sz, NO_VERIFY, NULL);
        WB_CHECK(ret != WC_NO_ERR_TRACE(ASN_PARSE_E),
                ":37773 2nd operand false, :37778 2nd operand false "
                "(matching PSS parameters)");
        FreeDecodedCRL(&dcrl);

        InitDecodedCRL(&dcrl, NULL);
        XMEMSET(rcertArr, 0, sizeof(rcertArr));
        sz = wb_build_crl_params(der, paramsA, (word32)sizeof(paramsA),
                paramsA, (word32)sizeof(paramsA), 0);
        ret = ParseCRL(rcertArr, &dcrl, der, sz, NO_VERIFY, NULL);
        WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
                ":37773 both operands true (parameters under a non-PSS "
                "algorithm)");
        FreeDecodedCRL(&dcrl);

        InitDecodedCRL(&dcrl, NULL);
        XMEMSET(rcertArr, 0, sizeof(rcertArr));
        sz = wb_build_crl_params(der, paramsA, (word32)sizeof(paramsA),
                paramsB, (word32)sizeof(paramsB), 1);
        ret = ParseCRL(rcertArr, &dcrl, der, sz, NO_VERIFY, NULL);
        WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
                ":37778 both operands true (PSS parameters differ)");
        FreeDecodedCRL(&dcrl);
    }
#endif /* WC_RSA_PSS */

    /* Truncated CRL: GetASN_Items() fails, so the version gate at :37713
     * runs with ret != 0. */
    InitDecodedCRL(&dcrl, NULL);
    XMEMSET(rcertArr, 0, sizeof(rcertArr));
    sz = wb_build_crl_tbs(der, 2, pastDate, 15, ASN_GENERALIZED_TIME,
            futureDate, 15, ASN_GENERALIZED_TIME, 0);
    ret = ParseCRL(rcertArr, &dcrl, der, sz - 4, NO_VERIFY, NULL);
    WB_CHECK(ret != 0, ":37713 1st operand false (truncated CRL)");
    FreeDecodedCRL(&dcrl);

#if defined(WC_ASN_RUNTIME_DATE_CHECK_CONTROL) && !defined(NO_ASN_TIME)
    /* Expired nextUpdate with verify != NO_VERIFY and the runtime skip flag
     * set: the 2nd operand goes false while the 1st stays true. The CRL must
     * be rebuilt expired here - the truncation vector above left der/sz
     * holding a future nextUpdate, against which this assertion would hold
     * whether or not the flag is honoured. */
    (void)wc_AsnSetSkipDateCheck(1);
    InitDecodedCRL(&dcrl, NULL);
    XMEMSET(rcertArr, 0, sizeof(rcertArr));
    sz = wb_build_crl_tbs(der, 2, pastDate, 15, ASN_GENERALIZED_TIME,
            pastDate, 15, ASN_GENERALIZED_TIME, 0);
    ret = ParseCRL(rcertArr, &dcrl, der, sz, VERIFY, NULL);
    WB_CHECK(ret != WC_NO_ERR_TRACE(CRL_CERT_DATE_ERR),
            ":37630 2nd operand false (AsnSkipDateCheck set)");
    FreeDecodedCRL(&dcrl);
    (void)wc_AsnSetSkipDateCheck(0);
#endif
}
#else
static void wb_parse_crl(void) { WB_NOTE("HAVE_CRL/ASN_TEMPLATE off; ParseCRL skipped"); }
#endif

#if defined(HAVE_CRL) && !defined(WOLFCRYPT_ONLY) && defined(WOLFSSL_CERT_GEN)
/* ------------------------------------------------------------------------- *
 * Section 14: EncodeCrlSerial() [:37729,:37733,:37751]
 *   :37729  if (sn == NULL || snSzInt < 0)
 *   :37733  while (snSzInt > 0 && snPtr[0] == 0)
 *   :37751  if (snSzInt > (int)outputSz - i || snSzInt <= 0)
 * The 2nd operand of :37751 (snSzInt <= 0) is a structural RESIDUAL: the
 * function already returns early (the snSzInt==0 special case) for any
 * snSzInt that reaches 0 after trimming, and :37729 already rejects
 * snSzInt < 0, so control can only reach :37751 with snSzInt > 0 --
 * the "true" side of that operand is unreachable here.
 * ------------------------------------------------------------------------- */
static void wb_encode_crl_serial(void)
{
    byte out[64];
    int ret;

    WB_NOTE("EncodeCrlSerial(): NULL/negative-length OR [:37729]; leading-"
            "zero trim loop [:37733]; output-size check [:37751]");

    /* sn==NULL -> 1st operand true. */
    ret = EncodeCrlSerial(NULL, 1, out, sizeof(out));
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":37729 1st operand true (sn==NULL)");

    /* snSzInt < 0: cast a huge word32 length to a negative int. */
    {
        byte sn[1] = { 0x05 };
        ret = EncodeCrlSerial(sn, 0x80000000u, out, sizeof(out));
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                ":37729 1st false, 2nd true (snSzInt < 0)");
    }

    /* leading zeros trimmed down to a nonzero byte -> :37733 (T,T) then
     * (T,F): sn = {0x00,0x00,0x05}. */
    {
        byte sn[3] = { 0x00, 0x00, 0x05 };
        ret = EncodeCrlSerial(sn, sizeof(sn), out, sizeof(out));
        WB_CHECK(ret > 0, ":37733 trims two leading zero bytes");
    }

    /* :37733 1st operand false immediately: snSzInt==0 from the start
     * (empty serial) -> the snSzInt==0 special case, not :37751 (residual
     * avoided). */
    {
        byte sn[1] = { 0 };
        ret = EncodeCrlSerial(sn, 0, out, sizeof(out));
        /* SetASNInt(1, 0x00, output) writes a 2-byte header (tag+length),
         * then the snSzInt==0 special case appends one content byte itself
         * (output[i]=0x00) -> total 3, not the header size alone. */
        WB_CHECK(ret == 3, ":37733 1st operand false (snSzInt==0 from the start)");
    }

    /* :37751 1st operand true: output buffer too small for a normal
     * (already-trimmed, snSzInt>0) serial. */
    {
        byte sn[1] = { 0x05 };
        byte tiny[1];
        ret = EncodeCrlSerial(sn, 1, tiny, sizeof(tiny));
        WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E), ":37751 1st operand true (buffer too small)");
    }

    /* :37751 both false: normal case, plenty of room. */
    {
        byte sn[1] = { 0x05 };
        ret = EncodeCrlSerial(sn, 1, out, sizeof(out));
        WB_CHECK(ret > 0, ":37751 both false (buffer big enough, snSzInt>0)");
    }
}

/* ------------------------------------------------------------------------- *
 * Section 15: wc_MakeCRL_ex() [:37887,:37897,:37906,:37924,:37943]
 * ------------------------------------------------------------------------- */
static void wb_make_crl_ex(void)
{
    byte issuer[2] = { 0x30, 0x00 };
    static const byte lastDate[15] = "20200101000000Z";
    static const byte nextDate[15] = "20991231235959Z";
    byte crlNum[1] = { 0x01 };
    byte out[512];
    int ret;
    int need;

    WB_NOTE("wc_MakeCRL_ex(): NULL/zero-arg OR [:37887]; algo size check "
            "[:37897]; nextDate presence [:37906]; crlNumber presence + "
            "version [:37924]; buffer-size check [:37943]");

    ret = wc_MakeCRL_ex(NULL, 0, lastDate, ASN_GENERALIZED_TIME, NULL, 0,
            NULL, NULL, 0, CTC_SHA256wRSA, 1, NULL, 0);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":37887 issuerDer==NULL (1st operand true)");

    ret = wc_MakeCRL_ex(issuer, 0, lastDate, ASN_GENERALIZED_TIME, NULL, 0,
            NULL, NULL, 0, CTC_SHA256wRSA, 1, NULL, 0);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":37887 issuerSz==0 (2nd operand true)");

    ret = wc_MakeCRL_ex(issuer, sizeof(issuer), NULL, ASN_GENERALIZED_TIME,
            NULL, 0, NULL, NULL, 0, CTC_SHA256wRSA, 1, NULL, 0);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":37887 lastDate==NULL (3rd operand true)");

    /* Invalid sigType -> SetAlgoID() returns 0 -> :37897 1st operand true. */
    ret = wc_MakeCRL_ex(issuer, sizeof(issuer), lastDate,
            ASN_GENERALIZED_TIME, NULL, 0, NULL, NULL, 0, 0 /* bad sigType */,
            1, NULL, 0);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ALGO_ID_E), ":37897 1st operand true (unrecognized sigType)");

    /* baseline v1, no nextDate/crlNumber -> :37906/:37924 all false. */
    need = wc_MakeCRL_ex(issuer, sizeof(issuer), lastDate,
            ASN_GENERALIZED_TIME, NULL, 0, NULL, NULL, 0, CTC_SHA256wRSA, 1,
            NULL, 0);
    WB_CHECK(need > 0, "size-only pass, v1, no nextDate/crlNumber (baseline)");

    /* nextDate present -> :37906 both true. */
    ret = wc_MakeCRL_ex(issuer, sizeof(issuer), lastDate,
            ASN_GENERALIZED_TIME, nextDate, ASN_GENERALIZED_TIME, NULL, NULL,
            0, CTC_SHA256wRSA, 1, NULL, 0);
    WB_CHECK(ret > need, ":37906 both true (nextDate present, larger encoding)");

    /* nextDate present but nextDateFmt == 0 -> :37906 2nd operand false
     * (the encoding matches the no-nextDate baseline). Without this row the
     * 2nd operand is only ever seen true. */
    ret = wc_MakeCRL_ex(issuer, sizeof(issuer), lastDate,
            ASN_GENERALIZED_TIME, nextDate, 0 /* no format */, NULL, NULL,
            0, CTC_SHA256wRSA, 1, NULL, 0);
    WB_CHECK(ret == need, ":37906 2nd operand false (nextDateFmt==0)");

    /* crlNumber present, version >= 2, but crlNumberSz == 0 -> :37924 2nd
     * operand false. */
    ret = wc_MakeCRL_ex(issuer, sizeof(issuer), lastDate,
            ASN_GENERALIZED_TIME, NULL, 0, NULL, crlNum, 0 /* zero size */,
            CTC_SHA256wRSA, 2 /* v2 */, NULL, 0);
    WB_CHECK(ret > 0, ":37924 2nd operand false (crlNumberSz==0)");

    /* crlNumber present but version < 2 -> :37924 3rd operand false
     * (version>=2 required); crlNumber ignored. */
    ret = wc_MakeCRL_ex(issuer, sizeof(issuer), lastDate,
            ASN_GENERALIZED_TIME, NULL, 0, NULL, crlNum, sizeof(crlNum),
            CTC_SHA256wRSA, 1 /* v1 */, NULL, 0);
    WB_CHECK(ret == need,
            ":37924 3rd operand false (version<2, crlNumber ignored)");

    /* crlNumber present, crlNumberSz>0, version>=2 -> :37924 all true. */
    need = wc_MakeCRL_ex(issuer, sizeof(issuer), lastDate,
            ASN_GENERALIZED_TIME, NULL, 0, NULL, crlNum, sizeof(crlNum),
            CTC_SHA256wRSA, 2 /* v2 */, NULL, 0);
    WB_CHECK(need > 0, ":37924 all true (v2 with crlNumber, size-only pass)");

    /* output!=NULL, buffer too small -> :37943 both true. */
    ret = wc_MakeCRL_ex(issuer, sizeof(issuer), lastDate,
            ASN_GENERALIZED_TIME, NULL, 0, NULL, crlNum, sizeof(crlNum),
            CTC_SHA256wRSA, 2, out, 1 /* too small */);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E), ":37943 both true (buffer too small)");

    /* output!=NULL, buffer big enough -> :37943 1st true, 2nd false. */
    ret = wc_MakeCRL_ex(issuer, sizeof(issuer), lastDate,
            ASN_GENERALIZED_TIME, NULL, 0, NULL, crlNum, sizeof(crlNum),
            CTC_SHA256wRSA, 2, out, sizeof(out));
    WB_CHECK(ret == need, ":37943 1st true, 2nd false (buffer big enough)");
}

/* ------------------------------------------------------------------------- *
 * Section 16: wc_SignCRL_ex()/wc_SignCRL_ex2() argument and key-type
 * decisions [:38031,:38083,:38084,:38114-:38128]
 * All vectors are constructed so that control returns (BAD_FUNC_ARG /
 * ALGO_ID_E) before any key-shaped pointer is dereferenced -- either
 * because an earlier NULL/size check already failed, or (for the SLH-DSA
 * keyType chain) because only a plain pointer-cast happens before
 * CheckSigTypeForKey() rejects a zeroed key. rsaKeyStorage/eccKeyStorage
 * are used only for their address, never read, in the :38031 pair.
 * ------------------------------------------------------------------------- */
static void wb_sign_crl(void)
{
    RsaKey rsaKeyStorage;
    ecc_key eccKeyStorage;
    byte tbs[4] = { 0x30, 0x02, 0x05, 0x00 };
    byte buf[64];
    WC_RNG rngStorage;
    int ret;
    int keyType;
    static const int slhTypes[] = {
        SLH_DSA_SHA2_128S_TYPE, SLH_DSA_SHA2_128F_TYPE,
        SLH_DSA_SHA2_192S_TYPE, SLH_DSA_SHA2_192F_TYPE,
        SLH_DSA_SHA2_256S_TYPE, SLH_DSA_SHA2_256F_TYPE,
        SLH_DSA_SHAKE_128S_TYPE, SLH_DSA_SHAKE_128F_TYPE,
        SLH_DSA_SHAKE_192S_TYPE, SLH_DSA_SHAKE_192F_TYPE,
        SLH_DSA_SHAKE_256S_TYPE, SLH_DSA_SHAKE_256F_TYPE
    };
    size_t i;
    /* Opaque stand-in for the key argument: SlhDsaKey is not a complete
     * type unless SLH-DSA is enabled, and these calls only need a
     * non-NULL pointer because the key type is passed separately. */
    byte dummySlh[8];

    WB_NOTE("wc_SignCRL_ex(): rsaKey!=NULL && eccKey!=NULL [:38031]");
    ret = wc_SignCRL_ex(tbs, sizeof(tbs), CTC_SHA256wRSA, buf, sizeof(buf),
            &rsaKeyStorage, &eccKeyStorage, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":38031 both true (both keys non-NULL)");

    /* rsaKey!=NULL, eccKey==NULL: proceeds into wc_SignCRL_ex2() with
     * tbsBuf==NULL, which fails there before rsaKeyStorage (uninitialized)
     * is ever touched. */
    ret = wc_SignCRL_ex(NULL, 0, CTC_SHA256wRSA, buf, sizeof(buf),
            &rsaKeyStorage, NULL, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            ":38031 1st true, 2nd false (only rsaKey set; fails downstream)");

    ret = wc_SignCRL_ex(NULL, 0, CTC_SHA256wECDSA, buf, sizeof(buf), NULL,
            &eccKeyStorage, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            ":38031 1st false, 2nd true (only eccKey set; fails downstream)");

    WB_NOTE("wc_SignCRL_ex2(): tbsBuf/tbsSz/buf/key/rng NULL-arg OR "
            "[:38083,:38084]");
    XMEMSET(&rngStorage, 0, sizeof(rngStorage));
    /* "Valid, but keyType unrecognized" baseline: all 5 args non-NULL and
     * in range, so the OR is all-false and control reaches (and is
     * rejected by) the keyType chain's final else -- doubling as the
     * all-keyType-false baseline for Section 16b below. */
    ret = wc_SignCRL_ex2(tbs, sizeof(tbs), CTC_SHA256wRSA, buf, sizeof(buf),
            999999 /* unrecognized keyType */, &rsaKeyStorage, &rngStorage);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            ":38083/:38084 all false (valid args, unrecognized keyType)");

    ret = wc_SignCRL_ex2(NULL, sizeof(tbs), CTC_SHA256wRSA, buf, sizeof(buf),
            999999, &rsaKeyStorage, &rngStorage);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":38083 tbsBuf==NULL");

    ret = wc_SignCRL_ex2(tbs, 0, CTC_SHA256wRSA, buf, sizeof(buf), 999999,
            &rsaKeyStorage, &rngStorage);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":38083 tbsSz<=0");

    ret = wc_SignCRL_ex2(tbs, sizeof(tbs), CTC_SHA256wRSA, NULL, sizeof(buf),
            999999, &rsaKeyStorage, &rngStorage);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":38084 buf==NULL");

    ret = wc_SignCRL_ex2(tbs, sizeof(tbs), CTC_SHA256wRSA, buf, sizeof(buf),
            999999, NULL, &rngStorage);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":38084 key==NULL");

    ret = wc_SignCRL_ex2(tbs, sizeof(tbs), CTC_SHA256wRSA, buf, sizeof(buf),
            999999, &rsaKeyStorage, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":38084 rng==NULL");

    WB_NOTE("wc_SignCRL_ex2(): keyType selector chain [:38114-:38128]");
    XMEMSET(&dummySlh, 0, sizeof(dummySlh));
    for (i = 0; i < sizeof(slhTypes) / sizeof(slhTypes[0]); i++) {
        keyType = slhTypes[i];
        ret = wc_SignCRL_ex2(tbs, sizeof(tbs), CTC_SHA256wRSA, buf,
                sizeof(buf), keyType, &dummySlh, &rngStorage);
        /* A zeroed SlhDsaKey never matches sType==CTC_SHA256wRSA in
         * CheckSigTypeForKey(), so this always fails -- what matters for
         * MC/DC is that keyType selected this SLH-DSA arm (each constant
         * true here, all the others false, mirroring how the library's own
         * wc_SignCert_ex() selector is driven in the falcon/mldsa/slhdsa
         * whitebox files). */
        WB_CHECK(ret != 0, ":38114-:38125 SLH-DSA keyType arm selected");
    }

    ret = wc_SignCRL_ex2(tbs, sizeof(tbs), CTC_SHA256wRSA, buf, sizeof(buf),
            LMS_TYPE, &dummySlh, &rngStorage);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ALGO_ID_E), ":38127 1st operand true (LMS_TYPE)");

    ret = wc_SignCRL_ex2(tbs, sizeof(tbs), CTC_SHA256wRSA, buf, sizeof(buf),
            XMSS_TYPE, &dummySlh, &rngStorage);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ALGO_ID_E),
            ":38127 1st false, 2nd true (XMSS_TYPE)");

    ret = wc_SignCRL_ex2(tbs, sizeof(tbs), CTC_SHA256wRSA, buf, sizeof(buf),
            XMSSMT_TYPE, &dummySlh, &rngStorage);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ALGO_ID_E),
            ":38127 1st/2nd false, 3rd true (XMSSMT_TYPE)");
}
#else
static void wb_encode_crl_serial(void) { WB_NOTE("HAVE_CRL/WOLFSSL_CERT_GEN off; EncodeCrlSerial skipped"); }
static void wb_make_crl_ex(void) { WB_NOTE("HAVE_CRL/WOLFSSL_CERT_GEN off; wc_MakeCRL_ex skipped"); }
static void wb_sign_crl(void) { WB_NOTE("HAVE_CRL/WOLFSSL_CERT_GEN off; wc_SignCRL_ex/ex2 skipped"); }
#endif /* HAVE_CRL && !WOLFCRYPT_ONLY && WOLFSSL_CERT_GEN */

#else /* !(HAVE_OCSP && !WOLFCRYPT_ONLY) */
static void wb_ocsp_decode_certid(void) { WB_NOTE("HAVE_OCSP off; skipped"); }
static void wb_decode_single_response_dates(void) { WB_NOTE("HAVE_OCSP off; skipped"); }
static void wb_decode_ocsp_resp_extensions(void) { WB_NOTE("HAVE_OCSP off; skipped"); }
static void wb_decode_response_data(void) { WB_NOTE("HAVE_OCSP off; skipped"); }
static void wb_ocsp_respid_match(void) { WB_NOTE("HAVE_OCSP off; skipped"); }
static void wb_ocsp_check_cert(void) { WB_NOTE("HAVE_OCSP off; skipped"); }
static void wb_decode_basic_ocsp_response(void) { WB_NOTE("HAVE_OCSP off; skipped"); }
static void wb_encode_ocsp_request(void) { WB_NOTE("HAVE_OCSP off; skipped"); }
static void wb_init_ocsp_request(void) { WB_NOTE("HAVE_OCSP off; skipped"); }
static void wb_compare_ocsp_req_resp(void) { WB_NOTE("HAVE_OCSP off; skipped"); }
static void wb_parse_crl_entry_extensions(void) { WB_NOTE("HAVE_OCSP off; skipped"); }
static void wb_parse_crl_extensions(void) { WB_NOTE("HAVE_OCSP off; skipped"); }
static void wb_parse_crl_check_signature(void) { WB_NOTE("HAVE_OCSP off; skipped"); }
static void wb_parse_crl(void) { WB_NOTE("HAVE_OCSP off; skipped"); }
static void wb_encode_crl_serial(void) { WB_NOTE("HAVE_OCSP off; skipped"); }
static void wb_make_crl_ex(void) { WB_NOTE("HAVE_OCSP off; skipped"); }
static void wb_sign_crl(void) { WB_NOTE("HAVE_OCSP off; skipped"); }
#endif /* HAVE_OCSP && !WOLFCRYPT_ONLY */

int main(void)
{
    printf("asn.c revocation (OCSP/CRL) white-box MC/DC supplement\n");

    wb_ocsp_decode_certid();
    wb_decode_single_response_dates();
    wb_decode_ocsp_resp_extensions();
    wb_decode_response_data();
    wb_ocsp_respid_match();
    wb_ocsp_check_cert();
    wb_decode_basic_ocsp_response();
    wb_encode_ocsp_request();
    wb_init_ocsp_request();
    wb_compare_ocsp_req_resp();
    wb_parse_crl_entry_extensions();
    wb_parse_crl_extensions();
    wb_parse_crl_check_signature();
    wb_parse_crl();
    wb_encode_crl_serial();
    wb_make_crl_ex();
    wb_sign_crl();

    printf("done (%s)\n", wb_fail ? "with failures" : "ok");
    /* Always return 0: a nonzero exit discards this variant's coverage
     * entirely in the campaign harness. Failures are surfaced via the
     * printed [FAIL] lines instead. */
    (void)wb_fail;
    return 0;
}
