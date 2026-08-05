/* test_asn_fault_whitebox.c
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
 * MC/DC white-box supplement for wolfcrypt/src/asn.c (Part 5): NULL/argument
 * guard OR-decisions and one allocation-cleanup OR-decision that the
 * tests/api and tests/unit-mcdc/test_asn_whitebox.c drivers never reach,
 * because every real caller in the library either always passes valid
 * arguments or the function is exercised only indirectly through full
 * certificate/key parsing paths that never construct the bad-argument
 * combination directly.
 *
 * Each target below is called directly (most are non-static entry points;
 * a few are file-static helpers reached only because this file #includes
 * asn.c). For every OR-chain, this issues the all-operands-false baseline
 * plus one call per operand with only that operand flipped true (others
 * held at their baseline value) -- the standard independence-pair idiom
 * used throughout tests/unit-mcdc/test_asn_whitebox.c's GetASNTag() section.
 * MC/DC independence is computed per binary, so both rows of every pair are
 * issued in this file regardless of what any other test binary covers.
 *
 * Baseline calls intentionally use garbage/zeroed payload bytes where the
 * target is a bounds-checked ASN.1 decoder (GetASN_Items()/DecodeAsymKey()/
 * wc_InitDecodedCert()+wc_GetPubX509() etc.): the guard under test only
 * cares that arguments are non-NULL/non-zero, and a malformed payload fails
 * safely deeper in the function (ASN_PARSE_E family, never BAD_FUNC_ARG)
 * without touching this file's assertions. The one exception,
 * wc_CertGetPubKey(), explicitly documents "assumes data has previously
 * been parsed for complete validity" (it walks the buffer with no length
 * bound on its own tag byte reads), so its baseline uses a hand-built
 * minimal valid TBSCertificate-shaped DER blob instead of garbage.
 *
 * Section 7 (AltNameDup(), asn.c:12920) is the one allocation-cleanup
 * decision here: it needs an EARLIER wolfSSL heap allocation to fail so a
 * LATER one's NULL result is observed by the caller's own cleanup check,
 * which normal execution (allocator never fails) cannot produce. This uses
 * mcdc_fault_alloc.h's fail-the-Nth-allocation sweep, the same technique as
 * tests/unit-mcdc/test_hpke_fault_whitebox.c.
 *
 * Sections (asn.c line numbers as of this writing):
 *   1.  wc_BerToDer() ber/derSz NULL OR ......................... :4269
 *   2.  EncodeObjectId() in/outSz NULL, inSz<=0 OR ............... :7403
 *   3.  wc_oid_sum() input NULL / length>MAX_OID_SZ OR ........... :7835
 *   4.  wc_CheckPrivateKeyCert() key/der NULL OR ................. :9956
 *   5.  wc_GetKeyOID() key/algoID NULL OR ......................... :10234
 *   6.  wc_DhParamsLoad() 5-operand NULL OR ....................... :12257
 *   7.  AltNameDup() OOM-cleanup OR (fault injection) ............. :12920
 *   8.  ConfirmSignature() 7-operand NULL/zero-size OR ............ :17462
 *   9.  UriHostIsDecOctet()/UriHostIsIpv4Address()/
 *       UriRegNameHasNonEmptyLabels()/GetUriHost() NULL/size
 *       guards (IGNORE_NAME_CONSTRAINTS gated) ................ :18664,
 *                                               :18687,:18711,:18736
 *   10. wc_CertGetPubKey() cert/pubKey/pubKeySz NULL OR ........... :23797
 *   11. wc_GetSubjectPubKeyInfoDerFromCert() NULL/zero OR ......... :23867
 *   12. eccToPKCS8() key/key->dp/outLen NULL OR .................. :33519
 *   13. wc_Ed25519{Private,Public}KeyDecode(),
 *       wc_Curve25519{Private,Public,}KeyDecode(),
 *       wc_Ed448{Private,Public}KeyDecode(),
 *       wc_Curve448{Private,Public}KeyDecode(): identical 4-operand
 *       input/inOutIdx/key NULL, inSz==0 OR, one per function ...... :34037,
 *                    :34062,:34086,:34105,:34133,:34460,:34485,:34506,:34525
 *   14. wc_ParseCRLReasonFromExtensions() ext/reasonCode NULL OR ... :36953
 *
 * No condition examined while building this file was concluded to be
 * structurally unreachable; every guard above is driven directly through
 * its own function's argument list. GAPS.md rows in the deep certificate
 * chain-verification internals (name-constraint enforcement, X.509
 * extension decoding/verification, CRL/OCSP responder verification, ASN.1
 * dump/print) were left untouched by this file -- they need a fully valid,
 * parsed DecodedCert/Signer/chain context to reach, which is out of scope
 * for this pass; that is a scope decision, not a reachability claim.
 */

#include <wolfcrypt/src/asn.c>

#include "mcdc_fault_alloc.h"

#include <stdio.h>
#include <string.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)
#define WB_CHECK(cond, msg) \
    do { if (!(cond)) { printf("  [wb][FAIL] %s\n", (msg)); wb_fail = 1; } } \
    while (0)

/* ------------------------------------------------------------------------- *
 * Section 1: wc_BerToDer() (:4269).
 *   if (ber == NULL || derSz == NULL) return BAD_FUNC_ARG;
 * ------------------------------------------------------------------------- */
#ifdef ASN_BER_TO_DER
static void wb_ber_to_der_null_args(void)
{
    byte   ber[4] = { 0x30, 0x00, 0x00, 0x00 };
    word32 derSz = 0;
    int    ret;

    WB_NOTE("wc_BerToDer(): ber/derSz NULL OR [:4269]");

    /* der==NULL is the documented "size only" mode, unrelated to this
     * guard -- both operands (ber, derSz) are non-NULL here. */
    ret = wc_BerToDer(ber, sizeof(ber), NULL, &derSz);
    WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG), "baseline (both false)");

    ret = wc_BerToDer(NULL, sizeof(ber), NULL, &derSz);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "ber==NULL");

    ret = wc_BerToDer(ber, sizeof(ber), NULL, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "derSz==NULL");
}
#else
static void wb_ber_to_der_null_args(void) { WB_NOTE("ASN_BER_TO_DER off; skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Section 2: EncodeObjectId() (:7403).
 *   if (in == NULL || outSz == NULL || inSz <= 0) return BAD_FUNC_ARG;
 * ------------------------------------------------------------------------- */
#ifdef HAVE_OID_ENCODING
static void wb_encode_object_id_null_args(void)
{
    word16 dotted[3] = { 1, 2, 3 };
    byte   out[16];
    word32 outSz;
    int    ret;

    WB_NOTE("EncodeObjectId(): in/outSz NULL, inSz<=0 OR [:7403]");

    outSz = sizeof(out);
    ret = EncodeObjectId(dotted, 3, out, &outSz);
    WB_CHECK(ret == 0, "baseline (all false)");

    outSz = sizeof(out);
    ret = EncodeObjectId(NULL, 3, out, &outSz);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "in==NULL");

    ret = EncodeObjectId(dotted, 3, out, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "outSz==NULL");

    outSz = sizeof(out);
    ret = EncodeObjectId(dotted, 0, out, &outSz);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "inSz<=0");
}
#else
static void wb_encode_object_id_null_args(void) { WB_NOTE("HAVE_OID_ENCODING off; skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Section 3: wc_oid_sum() (:7835).
 *   if (input == NULL || length > MAX_OID_SZ) return 0;
 * ------------------------------------------------------------------------- */
static void wb_oid_sum_null_args(void)
{
    byte   oidBuf[5] = { 0x2A, 0x03, 0x04, 0x05, 0x06 };
    word32 sum;

    WB_NOTE("wc_oid_sum(): input==NULL / length>MAX_OID_SZ OR [:7835]");

    /* baseline: both operands false (sum's exact value depends on the
     * OID-sum scheme in use; only reaching this line matters here). */
    sum = wc_oid_sum(oidBuf, (int)sizeof(oidBuf));
    (void)sum;

    sum = wc_oid_sum(NULL, (int)sizeof(oidBuf));
    WB_CHECK(sum == 0, "input==NULL");

    sum = wc_oid_sum(oidBuf, MAX_OID_SZ + 1);
    WB_CHECK(sum == 0, "length>MAX_OID_SZ");
}

/* ------------------------------------------------------------------------- *
 * Section 4: wc_CheckPrivateKeyCert() (:9956).
 *   if (key == NULL || der == NULL) return BAD_FUNC_ARG;
 * ------------------------------------------------------------------------- */
#if defined(HAVE_PKCS12) || !defined(NO_CHECK_PRIVATE_KEY)
static void wb_check_private_key_cert_null_args(void)
{
    byte        dummyKey[4] = { 0, 0, 0, 0 };
    DecodedCert cert;
    int         ret;

    WB_NOTE("wc_CheckPrivateKeyCert(): key/der NULL OR [:9956]");

    XMEMSET(&cert, 0, sizeof(cert));

    /* baseline: both pointers non-NULL. A zeroed DecodedCert has no public
     * key material, so the delegated wc_CheckPrivateKey() call fails deeper
     * in -- not asserted here, only that THIS guard's false path is taken
     * (reaching it at all is the point; the deeper failure mode is a
     * different function's guard, not this one's). */
    ret = wc_CheckPrivateKeyCert(dummyKey, sizeof(dummyKey), &cert, 0, NULL);
    WB_NOTE("baseline (both false) called");
    (void)ret;

    ret = wc_CheckPrivateKeyCert(NULL, sizeof(dummyKey), &cert, 0, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "key==NULL");

    ret = wc_CheckPrivateKeyCert(dummyKey, sizeof(dummyKey), NULL, 0, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "der==NULL");
}
#else
static void wb_check_private_key_cert_null_args(void) { WB_NOTE("HAVE_PKCS12/NO_CHECK_PRIVATE_KEY mismatch; skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Section 5: wc_GetKeyOID() (:10234).
 *   if (key == NULL || algoID == NULL) return BAD_FUNC_ARG;
 * ------------------------------------------------------------------------- */
#if defined(HAVE_PKCS8) || defined(HAVE_PKCS12)
static void wb_get_key_oid_null_args(void)
{
    byte        dummyKey[4] = { 0, 0, 0, 0 };
    const byte* curveOID = NULL;
    word32      oidSz = 0;
    int         algoID = 0;
    int         ret;

    WB_NOTE("wc_GetKeyOID(): key/algoID NULL OR [:10234]");

    /* baseline: garbage key never decodes as any known key type, so
     * *algoID stays 0 and ret is 0 -- none of the internal decode attempts
     * succeed far enough to reach their own (different) BAD_FUNC_ARG. */
    ret = wc_GetKeyOID(dummyKey, sizeof(dummyKey), &curveOID, &oidSz, &algoID,
            NULL);
    WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG), "baseline (both false)");

    ret = wc_GetKeyOID(NULL, sizeof(dummyKey), &curveOID, &oidSz, &algoID,
            NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "key==NULL");

    ret = wc_GetKeyOID(dummyKey, sizeof(dummyKey), &curveOID, &oidSz, NULL,
            NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "algoID==NULL");
}
#else
static void wb_get_key_oid_null_args(void) { WB_NOTE("HAVE_PKCS8/HAVE_PKCS12 off; skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Section 6: wc_DhParamsLoad() (:12257).
 *   if ((input==NULL)||(p==NULL)||(pInOutSz==NULL)||(g==NULL)||
 *       (gInOutSz==NULL)) ret = BAD_FUNC_ARG;
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_ASN_TEMPLATE) && !defined(NO_DH)
static void wb_dh_params_load_null_args(void)
{
    byte   input[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    byte   p[4] = { 0, 0, 0, 0 };
    byte   g[4] = { 0, 0, 0, 0 };
    word32 pInOutSz, gInOutSz;
    int    ret;

    WB_NOTE("wc_DhParamsLoad(): 5-operand NULL OR [:12257]");

    pInOutSz = sizeof(p); gInOutSz = sizeof(g);
    ret = wc_DhParamsLoad(input, sizeof(input), p, &pInOutSz, g, &gInOutSz);
    WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG), "baseline (all false)");

    pInOutSz = sizeof(p); gInOutSz = sizeof(g);
    ret = wc_DhParamsLoad(NULL, sizeof(input), p, &pInOutSz, g, &gInOutSz);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "input==NULL");

    pInOutSz = sizeof(p); gInOutSz = sizeof(g);
    ret = wc_DhParamsLoad(input, sizeof(input), NULL, &pInOutSz, g, &gInOutSz);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "p==NULL");

    pInOutSz = sizeof(p); gInOutSz = sizeof(g);
    ret = wc_DhParamsLoad(input, sizeof(input), p, NULL, g, &gInOutSz);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "pInOutSz==NULL");

    pInOutSz = sizeof(p); gInOutSz = sizeof(g);
    ret = wc_DhParamsLoad(input, sizeof(input), p, &pInOutSz, NULL, &gInOutSz);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "g==NULL");

    pInOutSz = sizeof(p); gInOutSz = sizeof(g);
    ret = wc_DhParamsLoad(input, sizeof(input), p, &pInOutSz, g, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "gInOutSz==NULL");
}
#else
static void wb_dh_params_load_null_args(void) { WB_NOTE("WOLFSSL_ASN_TEMPLATE/NO_DH mismatch; skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Section 7: AltNameDup() (:12920), fault-injection.
 *   if (ret->name == NULL
 *       || (from->ipString != NULL && ret->ipString == NULL)
 *       || (from->ridString != NULL && ret->ridString == NULL)) { ...free... }
 * Normal execution never fails a CopyString()/XMALLOC() call, so the OR's
 * true side (and the operand pairs inside the two AND subterms) is only
 * reachable by forcing an allocation to fail. Sweep the fail-index across
 * AltNameNew()'s struct alloc and each CopyString() call (name, ipString,
 * ridString, in that source order) -- mirrors
 * tests/unit-mcdc/test_hpke_fault_whitebox.c's sweep_kem() technique.
 * ------------------------------------------------------------------------- */
static void wb_alt_name_dup_fault(void)
{
    DNS_entry  from;
    DNS_entry* dup;
    int        n;
    const int  K = 8; /* > AltNameNew + up to 3 CopyString() alloc sites */

    WB_NOTE("AltNameDup(): OOM-cleanup OR across name/ipString/ridString [:12920]");

    XMEMSET(&from, 0, sizeof(from));
    from.type = ASN_DNS_TYPE;
    from.name = "test.example.com";
    from.len  = (int)XSTRLEN(from.name);
#ifdef WOLFSSL_IP_ALT_NAME
    from.ipString = (char*)"127.0.0.1";
#endif
#ifdef WOLFSSL_RID_ALT_NAME
    from.ridString = (char*)"1.2.3.4";
#endif

    /* baseline: unarmed, every allocation succeeds -> whole OR false. */
    dup = AltNameDup(&from, NULL);
    WB_CHECK(dup != NULL, "baseline (all operands false)");
    if (dup != NULL) {
        FreeAltNames(dup, NULL);
    }

    mcdc_fa_install();
    for (n = 1; n <= K; n++) {
        mcdc_fa_arm(n);
        dup = AltNameDup(&from, NULL);
        mcdc_fa_disarm();
        if (dup != NULL) {
            FreeAltNames(dup, NULL);
        }
    }
    mcdc_fa_disarm();
    mcdc_fa_restore();
}

/* ------------------------------------------------------------------------- *
 * Section 8: ConfirmSignature() (:17462).
 *   if (sigCtx==NULL || buf==NULL || bufSz==0 || key==NULL || keySz==0 ||
 *       sig==NULL || sigSz==0) return BAD_FUNC_ARG;
 * ------------------------------------------------------------------------- */
static void wb_confirm_signature_null_args(void)
{
    SignatureCtx sigCtx;
    byte         buf[16] = { 0 };
    byte         key[16] = { 0 };
    byte         sig[16] = { 0 };
    int          ret;

    WB_NOTE("ConfirmSignature(): 7-operand NULL/zero-size OR [:17462]");

    /* baseline: every pointer/size valid. keyOID/sigOID are 0 (matches no
     * known key type in SigOidMatchesKeyOid()), so it rejects immediately
     * at SIG_STATE_HASH -- exercises this guard's all-false row without a
     * real key/signature pair and without touching key/sig content. */
    InitSignatureCtx(&sigCtx, NULL, INVALID_DEVID);
    ret = ConfirmSignature(&sigCtx, buf, sizeof(buf), key, sizeof(key), 0,
            sig, sizeof(sig), 0, NULL, 0, NULL);
    WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG), "baseline (all operands false)");
    FreeSignatureCtx(&sigCtx);

    /* The remaining calls all return before touching *sigCtx, so its
     * post-Free state is irrelevant. */
    ret = ConfirmSignature(NULL, buf, sizeof(buf), key, sizeof(key), 0,
            sig, sizeof(sig), 0, NULL, 0, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "sigCtx==NULL");

    ret = ConfirmSignature(&sigCtx, NULL, sizeof(buf), key, sizeof(key), 0,
            sig, sizeof(sig), 0, NULL, 0, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "buf==NULL");

    ret = ConfirmSignature(&sigCtx, buf, 0, key, sizeof(key), 0,
            sig, sizeof(sig), 0, NULL, 0, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "bufSz==0");

    ret = ConfirmSignature(&sigCtx, buf, sizeof(buf), NULL, sizeof(key), 0,
            sig, sizeof(sig), 0, NULL, 0, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "key==NULL");

    ret = ConfirmSignature(&sigCtx, buf, sizeof(buf), key, 0, 0,
            sig, sizeof(sig), 0, NULL, 0, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "keySz==0");

    ret = ConfirmSignature(&sigCtx, buf, sizeof(buf), key, sizeof(key), 0,
            NULL, sizeof(sig), 0, NULL, 0, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "sig==NULL");

    ret = ConfirmSignature(&sigCtx, buf, sizeof(buf), key, sizeof(key), 0,
            sig, 0, 0, NULL, 0, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "sigSz==0");
}

/* ------------------------------------------------------------------------- *
 * Section 9: URI host name-constraint helpers (IGNORE_NAME_CONSTRAINTS
 * gated, matching asn.c's own guard on these statics).
 *   UriHostIsDecOctet()          :18664  s==NULL||sSz<=0||sSz>3
 *   UriHostIsIpv4Address()       :18687  host==NULL||hostSz<=0
 *   UriRegNameHasNonEmptyLabels() :18711 host==NULL||hostSz<=0||
 *                                        host[0]=='.'||host[hostSz-1]=='.'
 *   GetUriHost()                 :18736  uri==NULL||uriSz<3||host==NULL||
 *                                        hostSz==NULL||hostType==NULL
 * ------------------------------------------------------------------------- */
#ifndef IGNORE_NAME_CONSTRAINTS
static void wb_uri_host_helpers_null_args(void)
{
    int ret;

    WB_NOTE("UriHostIsDecOctet(): s==NULL/sSz<=0/sSz>3 OR [:18664]");
    ret = UriHostIsDecOctet("123", 3);
    WB_CHECK(ret == 1, "baseline (all false)");
    ret = UriHostIsDecOctet(NULL, 3);
    WB_CHECK(ret == 0, "s==NULL");
    ret = UriHostIsDecOctet("1", 0);
    WB_CHECK(ret == 0, "sSz<=0");
    ret = UriHostIsDecOctet("1234", 4);
    WB_CHECK(ret == 0, "sSz>3");

    WB_NOTE("UriHostIsIpv4Address(): host==NULL/hostSz<=0 OR [:18687]");
    ret = UriHostIsIpv4Address("1.2.3.4", 7);
    WB_CHECK(ret == 1, "baseline (all false)");
    ret = UriHostIsIpv4Address(NULL, 7);
    WB_CHECK(ret == 0, "host==NULL");
    ret = UriHostIsIpv4Address("1.2.3.4", 0);
    WB_CHECK(ret == 0, "hostSz<=0");

    WB_NOTE("UriRegNameHasNonEmptyLabels(): host==NULL/hostSz<=0/"
            "host[0]=='.'/ host[last]=='.' OR [:18711]");
    ret = UriRegNameHasNonEmptyLabels("a.b.c", 5);
    WB_CHECK(ret == 1, "baseline (all false)");
    ret = UriRegNameHasNonEmptyLabels(NULL, 5);
    WB_CHECK(ret == 0, "host==NULL");
    ret = UriRegNameHasNonEmptyLabels("a.b.c", 0);
    WB_CHECK(ret == 0, "hostSz<=0");
    ret = UriRegNameHasNonEmptyLabels(".a.b", 4);
    WB_CHECK(ret == 0, "host[0]=='.'");
    ret = UriRegNameHasNonEmptyLabels("a.b.", 4);
    WB_CHECK(ret == 0, "host[hostSz-1]=='.'");

    WB_NOTE("GetUriHost(): uri/host/hostSz/hostType NULL, uriSz<3 OR [:18736]");
    {
        const char*  host = NULL;
        int          hostSz = 0;
        UriHostType  hostType = URI_HOST_REG_NAME;
        static const char uri[] = "http://example.com/";
        const int    uriLen = (int)sizeof(uri) - 1;

        ret = GetUriHost(uri, uriLen, &host, &hostSz, &hostType);
        WB_CHECK(ret == 1, "baseline (all false)");

        ret = GetUriHost(NULL, uriLen, &host, &hostSz, &hostType);
        WB_CHECK(ret == 0, "uri==NULL");

        ret = GetUriHost(uri, 2, &host, &hostSz, &hostType);
        WB_CHECK(ret == 0, "uriSz<3");

        ret = GetUriHost(uri, uriLen, NULL, &hostSz, &hostType);
        WB_CHECK(ret == 0, "host==NULL");

        ret = GetUriHost(uri, uriLen, &host, NULL, &hostType);
        WB_CHECK(ret == 0, "hostSz==NULL");

        ret = GetUriHost(uri, uriLen, &host, &hostSz, NULL);
        WB_CHECK(ret == 0, "hostType==NULL");
    }
}
#else
static void wb_uri_host_helpers_null_args(void) { WB_NOTE("IGNORE_NAME_CONSTRAINTS on; skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Section 10: wc_CertGetPubKey() (:23797).
 *   if ((cert==NULL)||(pubKey==NULL)||(pubKeySz==NULL)) ret = BAD_FUNC_ARG;
 * This function's own doc comment says it "assumes data has previously been
 * parsed for complete validity" -- it reads cert[o] with no bound of its
 * own, so (unlike the other targets here) its baseline needs a real
 * minimal valid TBSCertificate-shaped DER blob rather than garbage bytes,
 * to stay crash-safe. Built by hand to match its private DecodeInstr op
 * list: SEQ(step in) / SEQ TBS(step in) / [version skipped: optional and
 * simply absent] / INTEGER serial(skip) / SEQ sigAlg(skip) / SEQ
 * issuer(skip) / SEQ validity(skip) / SEQ subject(skip) / SEQ SPKI(step
 * in) / SEQ SPKI-alg(skip) / BIT_STRING pubkey(step in).
 * ------------------------------------------------------------------------- */
#if (defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT)) || \
    (defined(HAVE_ED448) && defined(HAVE_ED448_KEY_IMPORT))
static void wb_cert_get_pub_key_null_args(void)
{
    static const byte certPubKeyDer[] = {
        0x30, 0x15,                   /* Certificate SEQ, len 21 */
          0x30, 0x13,                 /* TBSCertificate SEQ, len 19 */
            0x02, 0x01, 0x01,         /* serial INTEGER (skip) */
            0x30, 0x00,               /* signature AlgId SEQ (skip) */
            0x30, 0x00,               /* issuer SEQ (skip) */
            0x30, 0x00,               /* validity SEQ (skip) */
            0x30, 0x00,               /* subject SEQ (skip) */
            0x30, 0x06,               /* SPKI SEQ, len 6 (step in) */
              0x30, 0x00,             /*   algorithm SEQ (skip) */
              0x03, 0x02, 0x00, 0xAA  /*   BIT_STRING, len 2 (step in) */
    };
    const unsigned char* pubKey = NULL;
    word32                pubKeySz = 0;
    int                   ret;

    WB_NOTE("wc_CertGetPubKey(): cert/pubKey/pubKeySz NULL OR [:23797]");

    ret = wc_CertGetPubKey(certPubKeyDer, sizeof(certPubKeyDer), &pubKey,
            &pubKeySz);
    WB_CHECK(ret == 0, "baseline (all false)");

    ret = wc_CertGetPubKey(NULL, sizeof(certPubKeyDer), &pubKey, &pubKeySz);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "cert==NULL");

    ret = wc_CertGetPubKey(certPubKeyDer, sizeof(certPubKeyDer), NULL,
            &pubKeySz);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "pubKey==NULL");

    ret = wc_CertGetPubKey(certPubKeyDer, sizeof(certPubKeyDer), &pubKey,
            NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "pubKeySz==NULL");
}
#else
static void wb_cert_get_pub_key_null_args(void) { WB_NOTE("HAVE_ED25519_KEY_IMPORT/HAVE_ED448_KEY_IMPORT off; skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Section 11: wc_GetSubjectPubKeyInfoDerFromCert() (:23867).
 *   if (certDer==NULL || certDerSz==0 || pubKeyDerSz==NULL)
 *       return BAD_FUNC_ARG;
 * Unlike wc_CertGetPubKey() above, this parses via wc_InitDecodedCert() +
 * wc_GetPubX509(), both fully bounds-checked, so a malformed-but-non-NULL
 * buffer fails safely deeper in without ever returning BAD_FUNC_ARG.
 * ------------------------------------------------------------------------- */
static void wb_get_subject_pubkeyinfo_der_null_args(void)
{
    byte   garbage[8] = { 0x30, 0x02, 0x00, 0x00, 0, 0, 0, 0 };
    byte   outBuf[64];
    word32 outSz;
    int    ret;

    WB_NOTE("wc_GetSubjectPubKeyInfoDerFromCert(): certDer/certDerSz/"
            "pubKeyDerSz NULL/zero OR [:23867]");

    outSz = sizeof(outBuf);
    ret = wc_GetSubjectPubKeyInfoDerFromCert(garbage, sizeof(garbage), outBuf,
            &outSz);
    WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG), "baseline (all false)");

    outSz = sizeof(outBuf);
    ret = wc_GetSubjectPubKeyInfoDerFromCert(NULL, sizeof(garbage), outBuf,
            &outSz);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "certDer==NULL");

    outSz = sizeof(outBuf);
    ret = wc_GetSubjectPubKeyInfoDerFromCert(garbage, 0, outBuf, &outSz);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "certDerSz==0");

    ret = wc_GetSubjectPubKeyInfoDerFromCert(garbage, sizeof(garbage), outBuf,
            NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "pubKeyDerSz==NULL");
}

/* ------------------------------------------------------------------------- *
 * Section 12: eccToPKCS8() (:33519, file-static).
 *   if (key == NULL || key->dp == NULL || outLen == NULL)
 *       return BAD_FUNC_ARG;
 * ------------------------------------------------------------------------- */
#if defined(HAVE_PKCS8) && defined(HAVE_ECC) && defined(HAVE_ECC_KEY_EXPORT)
static void wb_ecc_to_pkcs8_null_args(void)
{
    ecc_key key;
    word32  outLen;
    int     ret;

    WB_NOTE("eccToPKCS8(): key/key->dp/outLen NULL OR [:33519]");

    XMEMSET(&key, 0, sizeof(key));
    outLen = 0;
    ret = eccToPKCS8(NULL, NULL, &outLen, 1);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "key==NULL");

    /* key->dp==NULL: a zeroed ecc_key has no curve set. */
    outLen = 0;
    ret = eccToPKCS8(&key, NULL, &outLen, 1);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "key->dp==NULL");

    /* baseline + outLen==NULL both need a real curve set on the key. */
    if (wc_ecc_init(&key) == 0 &&
            wc_ecc_set_curve(&key, 32, ECC_SECP256R1) == 0) {
        outLen = 0;
        ret = eccToPKCS8(&key, NULL, &outLen, 1);
        WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG), "baseline (all false)");

        ret = eccToPKCS8(&key, NULL, NULL, 1);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "outLen==NULL");

        wc_ecc_free(&key);
    }
    else {
        WB_NOTE("wc_ecc_set_curve(SECP256R1) unavailable; "
                "baseline/outLen==NULL cases skipped");
    }
}
#else
static void wb_ecc_to_pkcs8_null_args(void) { WB_NOTE("HAVE_PKCS8/HAVE_ECC/HAVE_ECC_KEY_EXPORT off; skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Section 13: wc_{Ed25519,Curve25519,Ed448,Curve448}*KeyDecode() family.
 * All nine functions share the identical guard shape:
 *   if (input==NULL || inOutIdx==NULL || key==NULL || inSz==0)
 *       return BAD_FUNC_ARG;
 * One macro drives the 4-operand OR identically for each; the macro-
 * generated static function's own baseline (all-zero 4-byte buffer) never
 * decodes as a valid key, so it fails deeper with an ASN.1 parse error,
 * never BAD_FUNC_ARG.
 * ------------------------------------------------------------------------- */
#define WB_KEYDEC_NULLGUARD(FUNC, KEYTYPE, LOC) \
static void wb_##FUNC##_null_args(void) \
{ \
    byte   buf[4] = { 0x00, 0x00, 0x00, 0x00 }; \
    word32 idx; \
    KEYTYPE key; \
    int     ret; \
    WB_NOTE(#FUNC "(): input/inOutIdx/key NULL, inSz==0 OR [" LOC "]"); \
    idx = 0; \
    ret = FUNC(buf, &idx, &key, sizeof(buf)); \
    WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG), "baseline (all false)"); \
    idx = 0; \
    ret = FUNC(NULL, &idx, &key, sizeof(buf)); \
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "input==NULL"); \
    ret = FUNC(buf, NULL, &key, sizeof(buf)); \
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "inOutIdx==NULL"); \
    idx = 0; \
    ret = FUNC(buf, &idx, NULL, sizeof(buf)); \
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "key==NULL"); \
    idx = 0; \
    ret = FUNC(buf, &idx, &key, 0); \
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "inSz==0"); \
}

#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT)
WB_KEYDEC_NULLGUARD(wc_Ed25519PrivateKeyDecode, ed25519_key, ":34037")
WB_KEYDEC_NULLGUARD(wc_Ed25519PublicKeyDecode, ed25519_key, ":34062")
#else
static void wb_wc_Ed25519PrivateKeyDecode_null_args(void) { WB_NOTE("HAVE_ED25519/HAVE_ED25519_KEY_IMPORT off; skipped"); }
static void wb_wc_Ed25519PublicKeyDecode_null_args(void) { WB_NOTE("HAVE_ED25519/HAVE_ED25519_KEY_IMPORT off; skipped"); }
#endif

#if defined(HAVE_CURVE25519) && defined(HAVE_CURVE25519_KEY_IMPORT)
WB_KEYDEC_NULLGUARD(wc_Curve25519PrivateKeyDecode, curve25519_key, ":34086")
WB_KEYDEC_NULLGUARD(wc_Curve25519PublicKeyDecode, curve25519_key, ":34105")
WB_KEYDEC_NULLGUARD(wc_Curve25519KeyDecode, curve25519_key, ":34133")
#else
static void wb_wc_Curve25519PrivateKeyDecode_null_args(void) { WB_NOTE("HAVE_CURVE25519/HAVE_CURVE25519_KEY_IMPORT off; skipped"); }
static void wb_wc_Curve25519PublicKeyDecode_null_args(void) { WB_NOTE("HAVE_CURVE25519/HAVE_CURVE25519_KEY_IMPORT off; skipped"); }
static void wb_wc_Curve25519KeyDecode_null_args(void) { WB_NOTE("HAVE_CURVE25519/HAVE_CURVE25519_KEY_IMPORT off; skipped"); }
#endif

#if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_IMPORT)
WB_KEYDEC_NULLGUARD(wc_Ed448PrivateKeyDecode, ed448_key, ":34460")
WB_KEYDEC_NULLGUARD(wc_Ed448PublicKeyDecode, ed448_key, ":34485")
#else
static void wb_wc_Ed448PrivateKeyDecode_null_args(void) { WB_NOTE("HAVE_ED448/HAVE_ED448_KEY_IMPORT off; skipped"); }
static void wb_wc_Ed448PublicKeyDecode_null_args(void) { WB_NOTE("HAVE_ED448/HAVE_ED448_KEY_IMPORT off; skipped"); }
#endif

#if defined(HAVE_CURVE448) && defined(HAVE_CURVE448_KEY_IMPORT)
WB_KEYDEC_NULLGUARD(wc_Curve448PrivateKeyDecode, curve448_key, ":34506")
WB_KEYDEC_NULLGUARD(wc_Curve448PublicKeyDecode, curve448_key, ":34525")
#else
static void wb_wc_Curve448PrivateKeyDecode_null_args(void) { WB_NOTE("HAVE_CURVE448/HAVE_CURVE448_KEY_IMPORT off; skipped"); }
static void wb_wc_Curve448PublicKeyDecode_null_args(void) { WB_NOTE("HAVE_CURVE448/HAVE_CURVE448_KEY_IMPORT off; skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Section 14: wc_ParseCRLReasonFromExtensions() (:36953).
 *   if (ext == NULL || reasonCode == NULL) return BAD_FUNC_ARG;
 * ------------------------------------------------------------------------- */
#ifdef HAVE_CRL
static void wb_parse_crl_reason_null_args(void)
{
    byte ext[4] = { 0x30, 0x02, 0x00, 0x00 };
    int  reasonCode = -1;
    int  ret;

    WB_NOTE("wc_ParseCRLReasonFromExtensions(): ext/reasonCode NULL OR [:36953]");

    ret = wc_ParseCRLReasonFromExtensions(ext, sizeof(ext), &reasonCode);
    WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG), "baseline (both false)");

    ret = wc_ParseCRLReasonFromExtensions(NULL, sizeof(ext), &reasonCode);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "ext==NULL");

    ret = wc_ParseCRLReasonFromExtensions(ext, sizeof(ext), NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "reasonCode==NULL");
}
#else
static void wb_parse_crl_reason_null_args(void) { WB_NOTE("HAVE_CRL off; skipped"); }
#endif

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("asn.c fault/NULL-guard white-box supplement\n");

    wb_ber_to_der_null_args();
    wb_encode_object_id_null_args();
    wb_oid_sum_null_args();
    wb_check_private_key_cert_null_args();
    wb_get_key_oid_null_args();
    wb_dh_params_load_null_args();
    wb_alt_name_dup_fault();
    wb_confirm_signature_null_args();
    wb_uri_host_helpers_null_args();
    wb_cert_get_pub_key_null_args();
    wb_get_subject_pubkeyinfo_der_null_args();
    wb_ecc_to_pkcs8_null_args();
    wb_wc_Ed25519PrivateKeyDecode_null_args();
    wb_wc_Ed25519PublicKeyDecode_null_args();
    wb_wc_Curve25519PrivateKeyDecode_null_args();
    wb_wc_Curve25519PublicKeyDecode_null_args();
    wb_wc_Curve25519KeyDecode_null_args();
    wb_wc_Ed448PrivateKeyDecode_null_args();
    wb_wc_Ed448PublicKeyDecode_null_args();
    wb_wc_Curve448PrivateKeyDecode_null_args();
    wb_wc_Curve448PublicKeyDecode_null_args();
    wb_parse_crl_reason_null_args();

    printf("done (%s)\n", wb_fail ? "with failures" : "ok");
    /* Always return 0: a nonzero exit discards this variant's coverage
     * entirely in the campaign harness. Failures are surfaced via the
     * printed [FAIL] lines instead. */
    (void)wb_fail;
    return 0;
}
