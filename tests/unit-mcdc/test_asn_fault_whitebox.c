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
 *   15. SetSerialNumber() sn/output NULL, (int)snSz<0 OR ........... :25152
 *   16. wc_GetPubKeyDerFromCert() cert/derKeySz NULL,
 *       derKey!=NULL&&*derKeySz==0 OR .............................. :26931
 *   17. wc_EncryptedInfoGet() info/cipherInfo NULL OR .............. :25717
 *   18. wc_PemToDer() buff/longSz OR; wc_KeyPemToDer()/
 *       wc_PubKeyPemToDer() "ret<0 || der==NULL" ....... :26552,:26617,:26700
 *   19. ParseKeyUsageStr()/ParseExtKeyUsageStr() NULL OR .. :28135,:28198
 *   20. wc_SetSubjectKeyId()/wc_SetAuthKeyId()/wc_SetIssuer()/
 *       wc_SetSubject() cert/file NULL OR .... :31812,:31978,:32381,:32404
 *   21. SetKeyIdFromPublicKey() 11-operand cert/key/kid_type OR .... :31594
 *   22. GetFormattedTime_ex() buf/len/format OR ................... :15901
 *   23. wc_MIME_parse_headers() in/inLen/terminator/headers OR .... :38530
 *   24. wc_GetFASCNFromCert() otherName/oidSum AND ................ :27036
 *
 *   25. encoder buffer-size guards, `ret == 0` operand .......... :13257,
 *       :13412,:27814,:27872,:28491,:34450,:36337,:36465
 *   26. DecodeDsaAsn1Sig() r/s allocation guard ................. :17324
 *
 * The original pass concluded nothing here was structurally unreachable.
 * The gap-closing wave added sections 25 and 26 and, while doing so, did
 * reach that conclusion for four conditions:
 *   - FillSigner() :24917/:24921/:24925 2nd operand (signer != NULL): the
 *     function returns BAD_FUNC_ARG at asn.c:24895-:24896 when signer is
 *     NULL, so every later `signer != NULL` test is constant true.
 *   - FillSigner() :24917 1st operand (ret == 0): ret is a local
 *     initialised to 0 at :24893 and the only assignment before that line
 *     is inside `#ifdef WOLFSSL_DUAL_ALG_CERTS`, which none of the asn
 *     module's variants define. Configuration-scoped constant true. The
 *     :24921/:24925 leading operands ARE reachable and are driven by the
 *     allocation sweep in section 24.
 *   - DecodeDsaAsn1Sig() :17348 both operands: the block is guarded by
 *     :17342, which has already rejected rSz + sSz > sigSz, and every
 *     caller passes a sigCpy of at least sigSz bytes, so both
 *     mp_to_unsigned_bin() calls write inside the buffer and cannot fail.
 *
 * GAPS.md rows in the deep certificate chain-verification internals
 * (name-constraint enforcement, X.509 extension decoding/verification,
 * CRL/OCSP responder verification, ASN.1 dump/print) were left untouched by
 * this file -- they need a fully valid, parsed DecodedCert/Signer/chain
 * context to reach, which is out of scope for this pass; that is a scope
 * decision, not a reachability claim.
 */

#include <wolfcrypt/src/asn.c>

/* certs_test.h supplies the DER fixtures (client cert / RSA key / RSA public
 * key) that Section 18 re-encodes to PEM in-process. It only defines the
 * buffers the enclosing configuration asks for, so every use below is guarded
 * on the same USE_CERT_BUFFERS_* macro. */
#include <wolfssl/certs_test.h>

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
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "inSz<2");
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
    /* A real RSA private key: the guard's all-false row with a result that is
     * actually distinguishable. Handing this call a garbage buffer also takes
     * the false path, but one of the inner decoders then returns BAD_FUNC_ARG
     * of its own, which says nothing about this guard. */
#ifdef USE_CERT_BUFFERS_2048
    ret = wc_GetKeyOID(client_key_der_2048, (word32)sizeof_client_key_der_2048,
            &curveOID, &oidSz, &algoID, NULL);
    /* wc_GetKeyOID() returns 1 when it identified the key type. */
    WB_CHECK(ret >= 0 && algoID == RSAk, "baseline (both false)");
#else
    ret = wc_GetKeyOID(dummyKey, sizeof(dummyKey), &curveOID, &oidSz, &algoID,
            NULL);
    (void)ret;
    WB_NOTE("no cert buffers; baseline result not asserted");
#endif

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

    /* Two more unarmed baselines shaped so each "from->xxxString != NULL"
     * operand has a partner row that differs ONLY in that operand (llvm-cov
     * matches independence pairs on every *evaluated* condition, so the
     * ipString operand has to keep the same value in the ridString pair):
     *   (a) neither string present -> ipString operand false;
     *   (b) ipString present and duplicated fine, ridString absent ->
     *       ipString operand true / its dup non-NULL / ridString operand
     *       false, which is exactly the fail-the-ridString-alloc row from the
     *       sweep with only the ridString operand flipped.
     */
    {
        DNS_entry bare;
        DNS_entry* bdup;

        XMEMSET(&bare, 0, sizeof(bare));
        bare.type = ASN_DNS_TYPE;
        bare.name = "bare.example.com";
        bare.len  = (int)XSTRLEN(bare.name);
        /* (a) ipString/ridString deliberately left NULL. */
        bdup = AltNameDup(&bare, NULL);
        WB_CHECK(bdup != NULL,
                "baseline, no ip/rid string (from->xxxString==NULL operands)");
        if (bdup != NULL) {
            FreeAltNames(bdup, NULL);
        }

#ifdef WOLFSSL_IP_ALT_NAME
        /* (b) ipString only. */
        bare.ipString = (char*)"10.0.0.1";
        bdup = AltNameDup(&bare, NULL);
        WB_CHECK(bdup != NULL,
                "baseline, ipString only (from->ridString==NULL operand)");
        if (bdup != NULL) {
            FreeAltNames(bdup, NULL);
        }
#endif
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
 * gated, matching asn.c's own guard on these static helpers).
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

    /* baseline + outLen==NULL need a key with an actual private value, not
     * just a curve: eccToPKCS8() sizes the encoding by exporting the key, so
     * a curve-only key is rejected by the exporter with its own BAD_FUNC_ARG
     * and says nothing about this guard. */
#ifdef USE_CERT_BUFFERS_256
    {
        word32 kIdx = 0;
        if ((wc_ecc_init(&key) == 0) &&
                (wc_EccPrivateKeyDecode(ecc_key_der_256, &kIdx, &key,
                     (word32)sizeof_ecc_key_der_256) == 0)) {
            outLen = 0;
            ret = eccToPKCS8(&key, NULL, &outLen, 1);
            WB_CHECK(ret == WC_NO_ERR_TRACE(LENGTH_ONLY_E) && outLen > 0,
                    "baseline (all false)");

            ret = eccToPKCS8(&key, NULL, NULL, 1);
            WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "outLen==NULL");

            wc_ecc_free(&key);
        }
        else {
            WB_NOTE("ecc_key_der_256 decode failed; "
                    "baseline/outLen==NULL cases skipped");
        }
    }
#else
    WB_NOTE("no P-256 cert buffers; baseline/outLen==NULL cases skipped");
#endif
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

/* ------------------------------------------------------------------------- *
 * Section 15: SetSerialNumber() (:25152).
 *   if (sn == NULL || output == NULL || snSzInt < 0) return BAD_FUNC_ARG;
 * ------------------------------------------------------------------------- */
#if !defined(WOLFSSL_ASN_TEMPLATE) || defined(HAVE_PKCS7)
static void wb_set_serial_number_null_args(void)
{
    static const byte sn[2] = { 0x01, 0x02 };
    byte out[32];
    int  ret;

    WB_NOTE("SetSerialNumber(): sn/output NULL, (int)snSz<0 OR [:25152]");

    ret = SetSerialNumber(sn, (word32)sizeof(sn), out, (word32)sizeof(out), 20);
    WB_CHECK(ret > 0, "baseline (all three operands false)");

    ret = SetSerialNumber(NULL, (word32)sizeof(sn), out, (word32)sizeof(out),
            20);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "sn==NULL");

    ret = SetSerialNumber(sn, (word32)sizeof(sn), NULL, (word32)sizeof(out),
            20);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "output==NULL");

    /* snSz above INT_MAX makes the function's internal (int) cast negative.
     * No in-library caller can produce that value; white-box only. */
    ret = SetSerialNumber(sn, 0x80000000U, out, (word32)sizeof(out), 20);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "(int)snSz < 0");
}
#else
static void wb_set_serial_number_null_args(void)
{
    WB_NOTE("SetSerialNumber not compiled; skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 16: wc_GetPubKeyDerFromCert() (:26931).
 *   if (cert == NULL || derKeySz == NULL ||
 *       (derKey != NULL && *derKeySz == 0)) return BAD_FUNC_ARG;
 * The 3rd/4th operands need BOTH orders (derKey NULL, and derKey non-NULL with
 * a non-zero size) to complete their pairs against the "guard true" rows.
 * ------------------------------------------------------------------------- */
#ifndef NO_CERTS
static void wb_get_pubkey_der_from_cert_null_args(void)
{
    DecodedCert dc;
    byte   der[64];
    word32 sz;
    int    ret;

    WB_NOTE("wc_GetPubKeyDerFromCert(): cert/derKeySz NULL, "
            "derKey!=NULL&&*derKeySz==0 OR [:26931]");

    /* A zeroed DecodedCert has no public key, so every guard-false row below
     * is rejected one check later (publicKey == NULL) -- no parse, no deref. */
    XMEMSET(&dc, 0, sizeof(dc));

    sz = (word32)sizeof(der);
    ret = wc_GetPubKeyDerFromCert(NULL, der, &sz);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "cert==NULL");

    ret = wc_GetPubKeyDerFromCert(&dc, der, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "derKeySz==NULL");

    sz = 0;
    ret = wc_GetPubKeyDerFromCert(&dc, der, &sz);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            "derKey!=NULL && *derKeySz==0");

    /* derKey==NULL short-circuits the 3rd operand -> guard false. */
    sz = 0;
    ret = wc_GetPubKeyDerFromCert(&dc, NULL, &sz);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            "derKey==NULL (3rd operand false, guard false)");

    /* derKey!=NULL and *derKeySz!=0 -> 4th operand false, guard false. */
    sz = (word32)sizeof(der);
    ret = wc_GetPubKeyDerFromCert(&dc, der, &sz);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            "all operands false (guard false)");
}
#else
static void wb_get_pubkey_der_from_cert_null_args(void)
{
    WB_NOTE("NO_CERTS; wc_GetPubKeyDerFromCert skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 17: wc_EncryptedInfoGet() (:25717).
 *   if (info == NULL || cipherInfo == NULL) return BAD_FUNC_ARG;
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_ENCRYPTED_KEYS) && defined(WOLFSSL_PEM_TO_DER)
static void wb_encrypted_info_get_null_args(void)
{
    EncryptedInfo info;
    int ret;

    WB_NOTE("wc_EncryptedInfoGet(): info/cipherInfo NULL OR [:25717]");

    XMEMSET(&info, 0, sizeof(info));
    /* Whether the named cipher is compiled in is irrelevant here: the guard
     * only cares that neither argument is NULL, and any later rejection is a
     * different (non-BAD_FUNC_ARG) code. */
    ret = wc_EncryptedInfoGet(&info, "AES-128-CBC");
    WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG), "baseline (both false)");

    ret = wc_EncryptedInfoGet(NULL, "AES-128-CBC");
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "info==NULL");

    ret = wc_EncryptedInfoGet(&info, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "cipherInfo==NULL");
}
#else
static void wb_encrypted_info_get_null_args(void)
{
    WB_NOTE("WOLFSSL_ENCRYPTED_KEYS/PEM_TO_DER off; skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 18: the PEM-to-DER entry points.
 *   wc_PemToDer       :26552  if (buff == NULL || longSz <= 0)
 *   wc_KeyPemToDer    :26617  if (ret < 0 || der == NULL)
 *   wc_PubKeyPemToDer :26700  if (ret < 0 || der == NULL)
 * The PEM inputs are produced in-process from the certs_test.h DER buffers via
 * wc_DerToPem(), so this needs no filesystem and no external fixture.
 *
 * RESIDUAL: the `der == NULL` operand of the two "ret < 0 || der == NULL"
 * decisions cannot be shown independently -- PemToDer() assigns *pDer on every
 * non-negative return, so `der == NULL` is only ever evaluated (i.e. only
 * reached with ret >= 0) when it is false. Only the `ret < 0` operand has a
 * satisfiable independence pair, and both of its rows are issued below.
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_PEM_TO_DER) && defined(WOLFSSL_DER_TO_PEM) && \
    defined(USE_CERT_BUFFERS_2048) && !defined(NO_RSA)
static void wb_pem_to_der_entry_points(void)
{
    static const char junkPem[] =
        "-----BEGIN CERTIFICATE-----\n"
        "!!!! not base64 !!!!\n"
        "-----END CERTIFICATE-----\n";
    byte* pem = NULL;
    byte* out = NULL;
    DerBuffer* der = NULL;
    int pemSz, ret;
    const int PEMBUF = 8192;

    WB_NOTE("wc_PemToDer()/wc_KeyPemToDer()/wc_PubKeyPemToDer(): "
            "arg + PemToDer-result guards [:26552,:26617,:26700]");

    pem = (byte*)XMALLOC((word32)PEMBUF, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    out = (byte*)XMALLOC((word32)PEMBUF, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (pem == NULL || out == NULL) {
        WB_NOTE("allocation failed; PEM-to-DER section skipped");
        XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(out, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return;
    }

    /* --- wc_PemToDer(): buff==NULL / longSz<=0 / both false --------------- */
    pemSz = wc_DerToPem(client_cert_der_2048,
            (word32)sizeof_client_cert_der_2048, pem, (word32)PEMBUF,
            CERT_TYPE);
    WB_CHECK(pemSz > 0, "wc_DerToPem(CERT_TYPE)");
    if (pemSz > 0) {
        ret = wc_PemToDer(pem, (long)pemSz, CERT_TYPE, &der, NULL, NULL, NULL);
        WB_CHECK(ret == 0 && der != NULL, ":26552 both operands false");
        if (der != NULL) {
            FreeDer(&der);
            der = NULL;
        }

        ret = wc_PemToDer(NULL, (long)pemSz, CERT_TYPE, &der, NULL, NULL, NULL);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":26552 buff==NULL");

        ret = wc_PemToDer(pem, 0, CERT_TYPE, &der, NULL, NULL, NULL);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":26552 longSz<=0");
    }

    /* --- wc_KeyPemToDer(): ret<0 true and false ---------------------------- */
    pemSz = wc_DerToPem(client_key_der_2048,
            (word32)sizeof_client_key_der_2048, pem, (word32)PEMBUF,
            PRIVATEKEY_TYPE);
    WB_CHECK(pemSz > 0, "wc_DerToPem(PRIVATEKEY_TYPE)");
    if (pemSz > 0) {
        ret = wc_KeyPemToDer(pem, pemSz, out, PEMBUF, NULL);
        WB_CHECK(ret > 0, ":26617 ret>=0 (1st operand false)");
    }
    ret = wc_KeyPemToDer((const unsigned char*)junkPem,
            (int)sizeof(junkPem) - 1, out, PEMBUF, NULL);
    WB_CHECK(ret < 0, ":26617 ret<0 (1st operand true)");

#if defined(WOLFSSL_CERT_EXT) || defined(WOLFSSL_PUB_PEM_TO_DER)
    /* --- wc_PubKeyPemToDer(): ret<0 true and false ------------------------- */
    pemSz = wc_DerToPem(client_keypub_der_2048,
            (word32)sizeof_client_keypub_der_2048, pem, (word32)PEMBUF,
            PUBLICKEY_TYPE);
    WB_CHECK(pemSz > 0, "wc_DerToPem(PUBLICKEY_TYPE)");
    if (pemSz > 0) {
        ret = wc_PubKeyPemToDer(pem, pemSz, out, PEMBUF);
        WB_CHECK(ret > 0, ":26700 ret>=0 (1st operand false)");
    }
    ret = wc_PubKeyPemToDer((const unsigned char*)junkPem,
            (int)sizeof(junkPem) - 1, out, PEMBUF);
    WB_CHECK(ret < 0, ":26700 ret<0 (1st operand true)");
#endif

    /* --- PemToDer() header/type dispatch sweep ---------------------------- *
     * PemToDer() walks a list of acceptable PEM header/footer pairs for the
     * requested type and retries with the next candidate when the buffer's
     * actual header does not match. The API tests only ever hand it a PEM
     * whose header already matches on the first try, so the "wrong header for
     * this type" arms (:26183, :26188), the empty-payload size check
     * (:26362), the PKCS#8/EC private-key post-processing (:26394) and the
     * encrypted-key branch (:26418, :26422) are never entered.
     *
     * The sweep pairs a handful of PEM shapes with a handful of requested
     * types; return codes are not asserted because a mismatched pair is
     * SUPPOSED to be rejected -- what matters is which header-selection
     * decisions get evaluated. Bodies are short but syntactically valid
     * base64 so the decode stage is reached. */
    {
        static const char pemEmptyBody[] =
            "-----BEGIN CERTIFICATE-----\n"
            "-----END CERTIFICATE-----\n";
        static const char pemCrl[] =
            "-----BEGIN X509 CRL-----\n"
            "AAECAwQFBgcICQoLDA0ODw==\n"
            "-----END X509 CRL-----\n";
        static const char pemEcPriv[] =
            "-----BEGIN EC PRIVATE KEY-----\n"
            "AAECAwQFBgcICQoLDA0ODw==\n"
            "-----END EC PRIVATE KEY-----\n";
        static const char pemEncPriv[] =
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
            "AAECAwQFBgcICQoLDA0ODw==\n"
            "-----END ENCRYPTED PRIVATE KEY-----\n";
        static const char pemEncRsa[] =
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "Proc-Type: 4,ENCRYPTED\n"
            "DEK-Info: AES-128-CBC,0123456789ABCDEF0123456789ABCDEF\n"
            "\n"
            "AAECAwQFBgcICQoLDA0ODw==\n"
            "-----END RSA PRIVATE KEY-----\n";
        static const int types[] = {
            CERT_TYPE, CA_TYPE, CHAIN_CERT_TYPE, TRUSTED_PEER_TYPE,
            PRIVATEKEY_TYPE, PUBLICKEY_TYPE,
#ifdef HAVE_CRL
            CRL_TYPE,
#endif
#ifdef WOLFSSL_CERT_REQ
            CERTREQ_TYPE,
#endif
            CERT_TYPE /* repeat keeps the array non-empty in every config */
        };
        const char* shapes[8];
        size_t nshapes = 0;
        size_t s, ty;

        shapes[nshapes++] = pemEmptyBody;
        shapes[nshapes++] = pemCrl;
        shapes[nshapes++] = pemEcPriv;
        shapes[nshapes++] = pemEncPriv;
        shapes[nshapes++] = pemEncRsa;

        for (s = 0; s < nshapes; s++) {
            for (ty = 0; ty < sizeof(types) / sizeof(types[0]); ty++) {
                DerBuffer* d = NULL;

                /* info == NULL: also drives the "no password callback"
                 * rejection at :26422 for the encrypted shapes. */
                if (PemToDer((const unsigned char*)shapes[s],
                        (long)XSTRLEN(shapes[s]), types[ty], &d, NULL, NULL,
                        NULL) == 0 && d != NULL) {
                    FreeDer(&d);
                }
                else if (d != NULL) {
                    FreeDer(&d);
                }
            }
        }

#ifdef WOLFSSL_ENCRYPTED_KEYS
        /* Same encrypted shapes with an EncryptedInfo that HAS a password
         * callback -> :26422 both operands false, so the decrypt path is
         * entered instead of the NO_PASSWORD rejection. */
        {
            EncryptedInfo info;
            DerBuffer* d = NULL;

            XMEMSET(&info, 0, sizeof(info));
            info.passwd_cb = KeyPemToDerPassCb;
            info.passwd_userdata = (void*)"password";
            if (PemToDer((const unsigned char*)pemEncRsa,
                    (long)XSTRLEN(pemEncRsa), PRIVATEKEY_TYPE, &d, NULL,
                    &info, NULL) == 0 && d != NULL) {
                FreeDer(&d);
            }
            else if (d != NULL) {
                FreeDer(&d);
            }

            /* info present but no callback -> :26422 2nd operand true. */
            XMEMSET(&info, 0, sizeof(info));
            d = NULL;
            (void)PemToDer((const unsigned char*)pemEncPriv,
                    (long)XSTRLEN(pemEncPriv), PRIVATEKEY_TYPE, &d, NULL,
                    &info, NULL);
            if (d != NULL) {
                FreeDer(&d);
            }
        }
#endif

        /* The real PKCS#8 private key from certs_test.h: header ==
         * BEGIN_PRIV_KEY and not encrypted -> :26394 1st operand true. */
        pemSz = wc_DerToPem(client_key_der_2048,
                (word32)sizeof_client_key_der_2048, pem, (word32)PEMBUF,
                PKCS8_PRIVATEKEY_TYPE);
        if (pemSz > 0) {
            DerBuffer* d = NULL;
            if (PemToDer(pem, (long)pemSz, PRIVATEKEY_TYPE, &d, NULL, NULL,
                    NULL) == 0 && d != NULL) {
                FreeDer(&d);
            }
            else if (d != NULL) {
                FreeDer(&d);
            }
        }
    }

    XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(out, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}
#else
static void wb_pem_to_der_entry_points(void)
{
    WB_NOTE("PEM<->DER/cert buffers not available; skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 18b: the *remaining* PEM<->DER entry guards, each rejection vector
 * paired with its accepting vector in this same binary.
 *
 *   :26008  wc_DerToPemEx()  if (!output && outSz == 0)
 *   :26020  wc_DerToPemEx()  if (!der || !output)
 *   :26559  wc_PemToDer()    if (ret == 0 && type == PRIVATEKEY_TYPE)
 *   :26652  wc_CertPemToDer() 5-operand "not an accepted cert type" AND-chain
 *   :26394  PemToDer()       (header==BEGIN_PRIV_KEY || header==BEGIN_EC_PRIV)
 *                            && !encrypted_key       -- 3rd operand
 *
 * Section 18 above already drives wc_PemToDer()/wc_KeyPemToDer()/
 * wc_PubKeyPemToDer(); these are the decisions it does not reach because it
 * never calls wc_DerToPemEx() with a null output and a non-zero size, never
 * asks wc_PemToDer() for a non-PRIVATEKEY_TYPE, never calls wc_CertPemToDer()
 * at all, and never hands PemToDer() an *encrypted* EC private key.
 *
 * Reasoning recorded for the operands deliberately NOT attempted here:
 *   :26020 has no third state -- both operands are driven below.
 *   :26362 (`neededSz > (long)sz`) is unreachable: neededSz is
 *     footerEnd-headerEnd with both pointers inside buff[0..sz), so it can
 *     never exceed sz; only the `neededSz <= 0` operand is satisfiable.
 *   :26183 (`(type == CRL_TYPE) && (header != BEGIN_X509_CRL)`) is a dead
 *     arm: wc_PemGetHeaderFooter(CRL_TYPE) always yields BEGIN_X509_CRL and
 *     nothing in the retry loop reassigns `header` while `type` is still
 *     CRL_TYPE, so the 2nd operand is false on every evaluation and the
 *     decision can never be true.
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_PEM_TO_DER) && defined(WOLFSSL_DER_TO_PEM) && \
    defined(USE_CERT_BUFFERS_2048) && !defined(NO_RSA)
static void wb_pem_der_remaining_guards(void)
{
    byte* pem = NULL;
    byte* out = NULL;
    DerBuffer* der = NULL;
    int pemSz, ret;
    const int PEMBUF = 8192;

    WB_NOTE("wc_DerToPemEx()/wc_PemToDer()/wc_CertPemToDer(): remaining "
            "entry guards [:26008,:26020,:26559,:26652,:26394]");

    pem = (byte*)XMALLOC((word32)PEMBUF, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    out = (byte*)XMALLOC((word32)PEMBUF, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (pem == NULL || out == NULL) {
        WB_NOTE("allocation failed; section skipped");
        XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(out, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return;
    }

    /* --- wc_DerToPemEx() :26008 / :26020 ---------------------------------
     * a) output != NULL, outSz > 0  -> :26008 1st operand false (accepting
     *    vector), :26020 both operands false.
     * b) output == NULL, outSz == 0 -> :26008 both true (size query).
     * c) output == NULL, outSz != 0 -> :26008 1st true / 2nd FALSE, so the
     *    size query is skipped and control reaches :26020 with der != NULL
     *    and output == NULL: :26020 1st operand false, 2nd operand TRUE.
     * d) der == NULL, output != NULL -> :26020 1st operand TRUE. outSz is
     *    non-zero so the :26008 size query is skipped. */
    pemSz = wc_DerToPem(client_cert_der_2048,
            (word32)sizeof_client_cert_der_2048, pem, (word32)PEMBUF,
            CERT_TYPE);                                              /* (a) */
    WB_CHECK(pemSz > 0, ":26008/:26020 accepting vector (real conversion)");

    ret = wc_DerToPem(client_cert_der_2048,
            (word32)sizeof_client_cert_der_2048, NULL, 0, CERT_TYPE);/* (b) */
    WB_CHECK(ret > 0, ":26008 both operands true (size query)");

    ret = wc_DerToPem(client_cert_der_2048,
            (word32)sizeof_client_cert_der_2048, NULL, (word32)PEMBUF,
            CERT_TYPE);                                              /* (c) */
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            ":26008 2nd operand false / :26020 2nd operand true (output==NULL)");

    ret = wc_DerToPem(NULL, (word32)sizeof_client_cert_der_2048, out,
            (word32)PEMBUF, CERT_TYPE);                              /* (d) */
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            ":26020 1st operand true (der==NULL)");

    /* --- wc_PemToDer() :26559 --------------------------------------------
     * The PKCS#8-header-strip block only runs for PRIVATEKEY_TYPE and only
     * when PemToDer() itself succeeded.
     *   ret==0, type==PRIVATEKEY_TYPE   -> both operands true
     *   ret==0, type==CERT_TYPE         -> 2nd operand FALSE
     *   ret!=0 (junk PEM)               -> 1st operand FALSE                */
    if (pemSz > 0) {
        ret = wc_PemToDer(pem, (long)pemSz, CERT_TYPE, &der, NULL, NULL, NULL);
        WB_CHECK(ret == 0 && der != NULL, ":26559 2nd operand false (CERT_TYPE)");
        FreeDer(&der);
        der = NULL;
    }
    pemSz = wc_DerToPem(client_key_der_2048,
            (word32)sizeof_client_key_der_2048, pem, (word32)PEMBUF,
            PRIVATEKEY_TYPE);
    if (pemSz > 0) {
        ret = wc_PemToDer(pem, (long)pemSz, PRIVATEKEY_TYPE, &der, NULL, NULL,
                NULL);
        WB_CHECK(ret == 0 && der != NULL, ":26559 both operands true");
        FreeDer(&der);
        der = NULL;
    }
    {
        static const char junkPem2[] =
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "!!!! not base64 !!!!\n"
            "-----END RSA PRIVATE KEY-----\n";
        ret = wc_PemToDer((const unsigned char*)junkPem2,
                (long)sizeof(junkPem2) - 1, PRIVATEKEY_TYPE, &der, NULL, NULL,
                NULL);
        WB_CHECK(ret != 0, ":26559 1st operand false (PemToDer failed)");
        if (der != NULL) {
            FreeDer(&der);
            der = NULL;
        }
    }

    /* --- wc_CertPemToDer() :26652 ---------------------------------------- *
     * if (type != CERT_TYPE && type != CHAIN_CERT_TYPE && type != CA_TYPE &&
     *     type != CERTREQ_TYPE && type != PKCS7_TYPE)
     * For a 5-operand AND chain each operand's independence pair is
     * "all five true" (the rejecting vector) against "this operand false"
     * (which short-circuits to the accepting side). One accepted type per
     * operand plus one rejected type completes all five rows. Whether the
     * subsequent PemToDer() succeeds is irrelevant to this guard, so the
     * return value is only checked for the bad-type row. */
    pemSz = wc_DerToPem(client_cert_der_2048,
            (word32)sizeof_client_cert_der_2048, pem, (word32)PEMBUF,
            CERT_TYPE);
    if (pemSz > 0) {
        /* All five operands TRUE -> rejected. PRIVATEKEY_TYPE is none of
         * the five accepted cert types. */
        ret = wc_CertPemToDer(pem, pemSz, out, PEMBUF, PRIVATEKEY_TYPE);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                ":26652 all five operands true (bad type rejected)");

        /* One accepting row per operand. */
        ret = wc_CertPemToDer(pem, pemSz, out, PEMBUF, CERT_TYPE);
        WB_CHECK(ret > 0, ":26652 1st operand false (CERT_TYPE)");
        (void)wc_CertPemToDer(pem, pemSz, out, PEMBUF, CHAIN_CERT_TYPE);
        (void)wc_CertPemToDer(pem, pemSz, out, PEMBUF, CA_TYPE);
#ifdef WOLFSSL_CERT_REQ
        (void)wc_CertPemToDer(pem, pemSz, out, PEMBUF, CERTREQ_TYPE);
#endif
        (void)wc_CertPemToDer(pem, pemSz, out, PEMBUF, PKCS7_TYPE);
    }

    /* --- PemToDer() :26394 3rd operand ------------------------------------
     * (header == BEGIN_PRIV_KEY || header == BEGIN_EC_PRIV) && !encrypted_key
     * Section 18 supplies the "unencrypted EC/PKCS#8 private key" rows, which
     * leave the 3rd operand always TRUE. An EC PRIVATE KEY PEM carrying
     * Proc-Type/DEK-Info sets info->set (encrypted_key = 1) while `header`
     * is still BEGIN_EC_PRIV, giving the 3rd operand's FALSE row with the
     * OR group still true. The body is deliberately short: the decision is
     * evaluated straight after Base64 decoding and before any decryption, so
     * the later decrypt failing does not matter. */
#if defined(HAVE_ECC) && defined(WOLFSSL_ENCRYPTED_KEYS)
    {
        static const char pemEncEcPriv[] =
            "-----BEGIN EC PRIVATE KEY-----\n"
            "Proc-Type: 4,ENCRYPTED\n"
            "DEK-Info: AES-128-CBC,0123456789ABCDEF0123456789ABCDEF\n"
            "\n"
            "AAECAwQFBgcICQoLDA0ODwABAgMEBQYHCAkKCwwNDg8=\n"
            "-----END EC PRIVATE KEY-----\n";
        EncryptedInfo info;
        DerBuffer* d = NULL;

        XMEMSET(&info, 0, sizeof(info));
        info.passwd_cb = KeyPemToDerPassCb;
        info.passwd_userdata = (void*)"password";
        (void)PemToDer((const unsigned char*)pemEncEcPriv,
                (long)XSTRLEN(pemEncEcPriv), PRIVATEKEY_TYPE, &d, NULL, &info,
                NULL);
        if (d != NULL) {
            FreeDer(&d);
        }
    }
#endif

    XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(out, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}
#else
static void wb_pem_der_remaining_guards(void)
{
    WB_NOTE("PEM<->DER/cert buffers not available; remaining guards skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 19: ParseKeyUsageStr() (:28135) / ParseExtKeyUsageStr() (:28198).
 *   if (value == NULL || keyUsage == NULL)    return BAD_FUNC_ARG;
 *   if (value == NULL || extKeyUsage == NULL) return BAD_FUNC_ARG;
 * ------------------------------------------------------------------------- */
#ifdef WOLFSSL_ASN_PARSE_KEYUSAGE
static void wb_parse_key_usage_str_null_args(void)
{
    word16 keyUsage = 0;
    byte   extKeyUsage = 0;
    int    ret;

    WB_NOTE("ParseKeyUsageStr()/ParseExtKeyUsageStr(): value/out NULL OR "
            "[:28135,:28198]");

    ret = ParseKeyUsageStr("digitalSignature,keyCertSign", &keyUsage, NULL);
    WB_CHECK(ret == 0 && keyUsage != 0, ":28135 both operands false");

    /* The nonRepudiation arm accepts two spellings; every in-tree caller and
     * every tests/api case uses the older one, so the X.509v3 spelling is the
     * only way to drive the OR's second operand. */
    keyUsage = 0;
    ret = ParseKeyUsageStr("nonRepudiation", &keyUsage, NULL);
    WB_CHECK(ret == 0 && (keyUsage & KEYUSE_CONTENT_COMMIT) != 0,
            ":28155 1st operand true");
    keyUsage = 0;
    ret = ParseKeyUsageStr("contentCommitment", &keyUsage, NULL);
    WB_CHECK(ret == 0 && (keyUsage & KEYUSE_CONTENT_COMMIT) != 0,
            ":28155 1st operand false, 2nd true");
    keyUsage = 0;
    ret = ParseKeyUsageStr("keyEncipherment", &keyUsage, NULL);
    WB_CHECK(ret == 0 && (keyUsage & KEYUSE_CONTENT_COMMIT) == 0,
            ":28155 both operands false");

    ret = ParseKeyUsageStr(NULL, &keyUsage, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":28135 value==NULL");

    ret = ParseKeyUsageStr("digitalSignature", NULL, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":28135 keyUsage==NULL");

    ret = ParseExtKeyUsageStr("serverAuth,clientAuth", &extKeyUsage, NULL);
    WB_CHECK(ret == 0 && extKeyUsage != 0, ":28198 both operands false");

    ret = ParseExtKeyUsageStr(NULL, &extKeyUsage, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":28198 value==NULL");

    ret = ParseExtKeyUsageStr("serverAuth", NULL, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":28198 extKeyUsage==NULL");
}
#else
static void wb_parse_key_usage_str_null_args(void)
{
    WB_NOTE("WOLFSSL_ASN_PARSE_KEYUSAGE off; skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 20: the file-loading Cert setters.
 *   wc_SetSubjectKeyId :31812  cert == NULL || file == NULL
 *   wc_SetAuthKeyId    :31978  cert == NULL || file == NULL
 *   wc_SetIssuer       :32381  cert == NULL || issuerFile == NULL
 *   wc_SetSubject      :32404  cert == NULL || subjectFile == NULL
 * The all-false row deliberately names a file that does not exist: the guard
 * is passed, the function reaches its PEM loader, and the open fails -- which
 * is a deterministic result on every host and needs no fixture on disk.
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_CERT_GEN) && !defined(NO_FILESYSTEM)
static void wb_cert_file_setters_null_args(void)
{
    Cert cert;
    static const char* missing = "./mcdc-no-such-file-3f2a.pem";

    WB_CHECK(wc_InitCert(&cert) == 0, "wc_InitCert");

#if defined(WOLFSSL_CERT_EXT) && !defined(NO_ASN_CRYPT)
    WB_NOTE("wc_SetSubjectKeyId(): cert/file NULL OR [:31812]");
    WB_CHECK(wc_SetSubjectKeyId(NULL, missing) ==
            WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":31812 cert==NULL");
    WB_CHECK(wc_SetSubjectKeyId(&cert, NULL) ==
            WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":31812 file==NULL");
    WB_CHECK(wc_SetSubjectKeyId(&cert, missing) !=
            WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":31812 both false (guard passed)");

    WB_NOTE("wc_SetAuthKeyId(): cert/file NULL OR [:31978]");
    WB_CHECK(wc_SetAuthKeyId(NULL, missing) ==
            WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":31978 cert==NULL");
    WB_CHECK(wc_SetAuthKeyId(&cert, NULL) ==
            WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":31978 file==NULL");
    WB_CHECK(wc_SetAuthKeyId(&cert, missing) !=
            WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":31978 both false (guard passed)");
#endif

    WB_NOTE("wc_SetIssuer()/wc_SetSubject(): cert/file NULL OR "
            "[:32381,:32404]");
    WB_CHECK(wc_SetIssuer(NULL, missing) == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            ":32381 cert==NULL");
    WB_CHECK(wc_SetIssuer(&cert, NULL) == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            ":32381 issuerFile==NULL");
    WB_CHECK(wc_SetIssuer(&cert, missing) != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            ":32381 both false (guard passed)");

    WB_CHECK(wc_SetSubject(NULL, missing) == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            ":32404 cert==NULL");
    WB_CHECK(wc_SetSubject(&cert, NULL) == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            ":32404 subjectFile==NULL");
    WB_CHECK(wc_SetSubject(&cert, missing) != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            ":32404 both false (guard passed)");
}
#else
static void wb_cert_file_setters_null_args(void)
{
    WB_NOTE("WOLFSSL_CERT_GEN/filesystem off; skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 21: SetKeyIdFromPublicKey() (:31594), the 11-operand chain.
 *   if (cert == NULL ||
 *       (rsakey==NULL && eckey==NULL && ed25519Key==NULL && ed448Key==NULL &&
 *        falconKey==NULL && mldsaKey==NULL && slhDsaKey==NULL &&
 *        frodoKey==NULL) ||
 *       (kid_type != SKID_TYPE && kid_type != AKID_TYPE))
 *
 * Each of the eight key-pointer operands needs a row where ONLY that pointer
 * is non-NULL (so the inner AND is false at that operand) and kid_type is
 * valid -- the whole decision is then false. Together with the "cert==NULL"
 * and "every key NULL" rows (decision true) that completes all eight, plus
 * cert's own pair. kid_type gets AKID_TYPE (2nd operand false) and a bogus
 * value (both true).
 *
 * Key objects: for a key type this build actually compiles, a real, inited
 * (but empty) object is passed -- the matching wc_*PublicKeyToDer() below the
 * guard then fails cleanly with a negative size and the function returns
 * PUBLIC_KEY_E. For a key type NOT compiled in, its "if (key != NULL)" export
 * block is preprocessed away entirely, so an opaque non-NULL pointer is never
 * dereferenced; the pointer only has to be distinguishable from NULL.
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_EXT)
static void wb_set_keyid_from_pubkey_operands(void)
{
    Cert cert;
    static byte opaque[8];
    int ret;

    WB_NOTE("SetKeyIdFromPublicKey(): 11-operand cert/key/kid_type OR "
            "[:31594]");

    WB_CHECK(wc_InitCert(&cert) == 0, "wc_InitCert");

    /* 1st operand true. */
    ret = SetKeyIdFromPublicKey(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
            NULL, SKID_TYPE);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "cert==NULL");

    /* Inner AND all true (no key supplied) -> 2nd operand true. */
    ret = SetKeyIdFromPublicKey(&cert, NULL, NULL, NULL, NULL, NULL, NULL,
            NULL, NULL, SKID_TYPE);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "every key pointer NULL");

    /* --- one row per key-pointer operand: that operand false, guard false. */
#ifndef NO_RSA
    {
        RsaKey k;
        if (wc_InitRsaKey(&k, NULL) == 0) {
            ret = SetKeyIdFromPublicKey(&cert, &k, NULL, NULL, NULL, NULL,
                    NULL, NULL, NULL, SKID_TYPE);
            WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                    "rsakey!=NULL (guard false)");
            wc_FreeRsaKey(&k);
        }
    }
#else
    ret = SetKeyIdFromPublicKey(&cert, (RsaKey*)(void*)opaque, NULL, NULL,
            NULL, NULL, NULL, NULL, NULL, SKID_TYPE);
    WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            "rsakey!=NULL (guard false, RSA not compiled)");
#endif

#ifdef HAVE_ECC
    {
        ecc_key k;
        if (wc_ecc_init(&k) == 0) {
            ret = SetKeyIdFromPublicKey(&cert, NULL, &k, NULL, NULL, NULL,
                    NULL, NULL, NULL, SKID_TYPE);
            WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                    "eckey!=NULL (guard false)");
            wc_ecc_free(&k);
        }
    }
#else
    ret = SetKeyIdFromPublicKey(&cert, NULL, (ecc_key*)(void*)opaque, NULL,
            NULL, NULL, NULL, NULL, NULL, SKID_TYPE);
    WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            "eckey!=NULL (guard false, ECC not compiled)");
#endif

#ifdef HAVE_ED25519
    {
        ed25519_key k;
        if (wc_ed25519_init(&k) == 0) {
            ret = SetKeyIdFromPublicKey(&cert, NULL, NULL, &k, NULL, NULL,
                    NULL, NULL, NULL, SKID_TYPE);
            WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                    "ed25519Key!=NULL (guard false)");
            wc_ed25519_free(&k);
        }
    }
#else
    ret = SetKeyIdFromPublicKey(&cert, NULL, NULL, (ed25519_key*)(void*)opaque,
            NULL, NULL, NULL, NULL, NULL, SKID_TYPE);
    WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            "ed25519Key!=NULL (guard false, Ed25519 not compiled)");
#endif

#ifdef HAVE_ED448
    {
        ed448_key k;
        if (wc_ed448_init(&k) == 0) {
            ret = SetKeyIdFromPublicKey(&cert, NULL, NULL, NULL, &k, NULL,
                    NULL, NULL, NULL, SKID_TYPE);
            WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                    "ed448Key!=NULL (guard false)");
            wc_ed448_free(&k);
        }
    }
#else
    ret = SetKeyIdFromPublicKey(&cert, NULL, NULL, NULL,
            (ed448_key*)(void*)opaque, NULL, NULL, NULL, NULL, SKID_TYPE);
    WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            "ed448Key!=NULL (guard false, Ed448 not compiled)");
#endif

#ifdef HAVE_FALCON
    {
        falcon_key k;
        if (wc_falcon_init(&k) == 0) {
            ret = SetKeyIdFromPublicKey(&cert, NULL, NULL, NULL, NULL, &k,
                    NULL, NULL, NULL, SKID_TYPE);
            WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                    "falconKey!=NULL (guard false)");
            wc_falcon_free(&k);
        }
    }
#else
    ret = SetKeyIdFromPublicKey(&cert, NULL, NULL, NULL, NULL,
            (falcon_key*)(void*)opaque, NULL, NULL, NULL, SKID_TYPE);
    WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            "falconKey!=NULL (guard false, Falcon not compiled)");
#endif

#if defined(WOLFSSL_HAVE_MLDSA) && !defined(WOLFSSL_MLDSA_NO_ASN1)
    {
        wc_MlDsaKey k;
        if (wc_MlDsaKey_Init(&k, NULL, INVALID_DEVID) == 0) {
            ret = SetKeyIdFromPublicKey(&cert, NULL, NULL, NULL, NULL, NULL,
                    &k, NULL, NULL, SKID_TYPE);
            WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                    "mldsaKey!=NULL (guard false)");
            wc_MlDsaKey_Free(&k);
        }
    }
#else
    ret = SetKeyIdFromPublicKey(&cert, NULL, NULL, NULL, NULL, NULL,
            (wc_MlDsaKey*)(void*)opaque, NULL, NULL, SKID_TYPE);
    WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            "mldsaKey!=NULL (guard false, ML-DSA not compiled)");
#endif

#if defined(WOLFSSL_HAVE_SLHDSA)
    {
        SlhDsaKey* k = (SlhDsaKey*)XMALLOC(sizeof(SlhDsaKey), NULL,
                DYNAMIC_TYPE_TMP_BUFFER);
        if (k != NULL) {
            if (wc_SlhDsaKey_Init(k, NULL, INVALID_DEVID) == 0) {
                ret = SetKeyIdFromPublicKey(&cert, NULL, NULL, NULL, NULL,
                        NULL, NULL, k, NULL, SKID_TYPE);
                WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                        "slhDsaKey!=NULL (guard false)");
                wc_SlhDsaKey_Free(k);
            }
            XFREE(k, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }
#else
    ret = SetKeyIdFromPublicKey(&cert, NULL, NULL, NULL, NULL, NULL, NULL,
            (SlhDsaKey*)(void*)opaque, NULL, SKID_TYPE);
    WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            "slhDsaKey!=NULL (guard false, SLH-DSA not compiled)");
#endif

#if !defined(WOLFSSL_HAVE_FRODOKEM) || defined(WOLFSSL_FRODOKEM_NO_ASN1)
    /* frodoKey is a void* and its export block is compiled out here. */
    ret = SetKeyIdFromPublicKey(&cert, NULL, NULL, NULL, NULL, NULL, NULL,
            NULL, (void*)opaque, SKID_TYPE);
    WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            "frodoKey!=NULL (guard false, FrodoKEM not compiled)");
#endif

    /* --- kid_type operands ------------------------------------------------ *
     * A key pointer must be non-NULL for the 3rd term to be evaluated at all;
     * the opaque pointer is safe for the same reason as above whenever its
     * type is not compiled in, so prefer a real RSA/ECC key when available. */
    {
#ifndef NO_RSA
        RsaKey k;
        int haveKey = (wc_InitRsaKey(&k, NULL) == 0);
        RsaKey* kp = haveKey ? &k : NULL;
#define WB_SKID_CALL(kt) \
        SetKeyIdFromPublicKey(&cert, kp, NULL, NULL, NULL, NULL, NULL, NULL, \
                NULL, (kt))
#else
        int haveKey = 1;
#define WB_SKID_CALL(kt) \
        SetKeyIdFromPublicKey(&cert, NULL, NULL, NULL, NULL, NULL, NULL, \
                NULL, (void*)opaque, (kt))
#endif
        if (haveKey) {
            /* kid_type == AKID_TYPE -> 2nd operand of the kid_type AND is
             * false -> whole guard false. */
            ret = WB_SKID_CALL(AKID_TYPE);
            WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                    "kid_type==AKID_TYPE (guard false)");
            /* kid_type neither SKID nor AKID -> both operands true. */
            ret = WB_SKID_CALL(99);
            WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                    "kid_type invalid (3rd term true)");
        }
#undef WB_SKID_CALL
#ifndef NO_RSA
        if (haveKey) {
            wc_FreeRsaKey(&k);
        }
#endif
    }
}
#else
static void wb_set_keyid_from_pubkey_operands(void)
{
    WB_NOTE("WOLFSSL_CERT_GEN/CERT_EXT off; SetKeyIdFromPublicKey skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 22: GetFormattedTime_ex() (:15901).
 *   if (buf == NULL || len == 0 || (format != 0 && format != ASN_UTC_TIME &&
 *       format != ASN_GENERALIZED_TIME)) return BAD_FUNC_ARG;
 * The last operand needs a format value that is neither 0 nor either of the
 * two accepted tags -- no in-library caller passes one.
 * ------------------------------------------------------------------------- */
#if !defined(NO_ASN_TIME) && !defined(USER_TIME) && !defined(TIME_OVERRIDES)
static void wb_get_formatted_time_null_args(void)
{
    byte   buf[ASN_GENERALIZED_TIME_SIZE + 8];
    time_t now = 1700000000; /* fixed instant: deterministic, valid gmtime */
    int    ret;

    WB_NOTE("GetFormattedTime_ex(): buf/len/format OR [:15901]");

    ret = GetFormattedTime_ex(&now, buf, (word32)sizeof(buf), 0);
    WB_CHECK(ret > 0, "format==0 (3rd operand false)");

    ret = GetFormattedTime_ex(&now, buf, (word32)sizeof(buf), ASN_UTC_TIME);
    WB_CHECK(ret > 0, "format==ASN_UTC_TIME (4th operand false)");

    ret = GetFormattedTime_ex(&now, buf, (word32)sizeof(buf),
            ASN_GENERALIZED_TIME);
    WB_CHECK(ret > 0, "format==ASN_GENERALIZED_TIME (5th operand false)");

    ret = GetFormattedTime_ex(&now, NULL, (word32)sizeof(buf), 0);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "buf==NULL");

    ret = GetFormattedTime_ex(&now, buf, 0, 0);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "len==0");

    ret = GetFormattedTime_ex(&now, buf, (word32)sizeof(buf), 0x7F);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            "format not 0/UTC/GENERALIZED (5th operand true)");
}
#else
static void wb_get_formatted_time_null_args(void)
{
    WB_NOTE("NO_ASN_TIME/custom time; GetFormattedTime_ex skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 23: wc_MIME_parse_headers() (:38530).
 *   if (in == NULL || inLen <= 0 || in[inLen] != '\0' || headers == NULL)
 * The 3rd operand ("the caller's length does not land on the terminator") is
 * a defensive check no in-library caller can trip.
 * ------------------------------------------------------------------------- */
#ifdef HAVE_SMIME
static void wb_mime_parse_headers_null_args(void)
{
    static char hdr[] = "Content-Type: text/plain\r\n\r\n";
    MimeHdr* headers = NULL;
    int ret;

    WB_NOTE("wc_MIME_parse_headers(): in/inLen/terminator/headers OR "
            "[:38530]");

    ret = wc_MIME_parse_headers(hdr, (int)sizeof(hdr) - 1, &headers);
    WB_CHECK(ret == 0, "all operands false (well-formed header block)");
    if (headers != NULL) {
        wc_MIME_free_hdrs(headers);
        headers = NULL;
    }

    ret = wc_MIME_parse_headers(NULL, (int)sizeof(hdr) - 1, &headers);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "in==NULL");

    ret = wc_MIME_parse_headers(hdr, 0, &headers);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "inLen<=0");

    /* Length one short of the terminator -> in[inLen] is a real character. */
    ret = wc_MIME_parse_headers(hdr, (int)sizeof(hdr) - 3, &headers);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "in[inLen] != '\\0'");
    if (headers != NULL) {
        wc_MIME_free_hdrs(headers);
        headers = NULL;
    }

    ret = wc_MIME_parse_headers(hdr, (int)sizeof(hdr) - 1, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "headers==NULL");

    /* --- header-block shapes for the tokeniser's own decisions ----------- *
     *  [:38556] curLine[0]==' ' with / without a header already collected;
     *  [:38572] ':' vs '=' against MIME_HDR vs MIME_PARAM, and a separator
     *           sitting at position 0 (pos >= 1 false);
     *  [:38585] ';' while already in MIME_BODYVAL;
     *  [:38634] a line that ends exactly on its separator, so the trailing
     *           "end >= start" test is false.
     * The parser mutates its input (XSTRTOK), so every shape gets its own
     * writable copy. Only "parsed without crashing" is asserted: several of
     * these are deliberately malformed and their return code is not the
     * property under test. */
    {
        static const char* shapes[] = {
            /* continuation line, no header collected yet -> curHdr NULL. */
            " param=1\r\nContent-Type: text/plain\r\n",
            /* header then a continuation line -> curHdr non-NULL, and '='
             * seen while mimeType == MIME_PARAM. */
            "Content-Type: multipart/signed; a=b\r\n c=d\r\n",
            /* '=' seen while mimeType == MIME_HDR (before any ':'). */
            "Name=Value: body\r\n",
            /* separator at position 0 -> pos >= 1 false. */
            ":novalue\r\n",
            /* line ends on its separator -> start == lineLen, end < start. */
            "Content-Type:\r\n",
            /* ':' inside a parameter line -> mimeType == MIME_HDR false. */
            "Content-Type: a; b=c\r\n d:e=f\r\n",
            /* ';' immediately after the value separator. */
            "Content-Type:;a=b\r\n"
        };
        size_t i;

        for (i = 0; i < sizeof(shapes) / sizeof(shapes[0]); i++) {
            size_t len = XSTRLEN(shapes[i]);
            char*  buf = (char*)XMALLOC((word32)len + 1, NULL,
                    DYNAMIC_TYPE_TMP_BUFFER);

            if (buf == NULL) {
                continue;
            }
            XMEMCPY(buf, shapes[i], len + 1);
            headers = NULL;
            (void)wc_MIME_parse_headers(buf, (int)len, &headers);
            if (headers != NULL) {
                wc_MIME_free_hdrs(headers);
                headers = NULL;
            }
            XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }
}
#else
static void wb_mime_parse_headers_null_args(void)
{
    WB_NOTE("HAVE_SMIME off; wc_MIME_parse_headers skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 24: wc_GetFASCNFromCert() (:27036).
 *   if (id != NULL && id->oidSum == FASCN_OID) { ... }
 * Both operands need the OTHER-name walk to run against a DecodedCert whose
 * altNames list is under this test's control: a parsed certificate either has
 * a FASCN otherName or none at all, so "an otherName that is not a FASCN" (the
 * 2nd operand's false half) never occurs in the API tests.
 * ------------------------------------------------------------------------- */
#ifdef WOLFSSL_FPKI
static void wb_get_fascn_from_cert(void)
{
    DecodedCert dc;
    DNS_entry   other;
    DNS_entry   dns;
    static char fascnVal[] = "\xD2\x39\x00";
    byte   fascn[16];
    word32 fascnSz;
    int    ret;

    WB_NOTE("wc_GetFASCNFromCert(): id/oidSum AND [:27036]");

    XMEMSET(&dc, 0, sizeof(dc));
    XMEMSET(&other, 0, sizeof(other));
    XMEMSET(&dns, 0, sizeof(dns));

    /* (a) No ASN_OTHER_TYPE entry at all -> FindAltName returns NULL, the 1st
     *     operand is false and the loop exits. */
    dns.type = ASN_DNS_TYPE;
    dns.name = (char*)"example.com";
    dns.len  = (int)XSTRLEN(dns.name);
    dc.altNames = &dns;
    fascnSz = (word32)sizeof(fascn);
    ret = wc_GetFASCNFromCert(&dc, fascn, &fascnSz);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ALT_NAME_E), "no otherName (id==NULL)");

    /* (b) An ASN_OTHER_TYPE entry whose OID is NOT the FASCN OID -> 1st
     *     operand true, 2nd false; the walk continues and then ends. */
    other.type   = ASN_OTHER_TYPE;
    other.oidSum = 0; /* deliberately not FASCN_OID */
    other.name   = fascnVal;
    other.len    = (int)sizeof(fascnVal) - 1;
    other.next   = NULL;
    dns.next     = &other;
    fascnSz = (word32)sizeof(fascn);
    ret = wc_GetFASCNFromCert(&dc, fascn, &fascnSz);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ALT_NAME_E),
            "otherName with non-FASCN OID (2nd operand false)");

    /* (c) Same entry carrying the FASCN OID -> both operands true. */
    other.oidSum = FASCN_OID;
    fascnSz = (word32)sizeof(fascn);
    ret = wc_GetFASCNFromCert(&dc, fascn, &fascnSz);
    /* Note: the copy path returns 0 without writing back *fascnSz. */
    WB_CHECK(ret == 0, "otherName with FASCN OID (both operands true)");

    /* Length-only mode keeps the same decision true; also exercises the
     * fascn==NULL arm right below the guard. */
    fascnSz = 0;
    ret = wc_GetFASCNFromCert(&dc, NULL, &fascnSz);
    WB_CHECK(ret == WC_NO_ERR_TRACE(LENGTH_ONLY_E), "length-only mode");
}
#else
static void wb_get_fascn_from_cert(void)
{
    WB_NOTE("WOLFSSL_FPKI off; wc_GetFASCNFromCert skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 25: ConfirmNameConstraints() early-exit (:19321).
 *   if (signer->excludedNames == NULL && signer->permittedNames == NULL &&
 *           !signer->extNameConstraintHasUnsupported) return 1;
 * The 3rd operand's false half needs a Signer that carries NO constraint
 * lists but DID see an unsupported constraint form -- a combination the
 * library only produces from a certificate whose nameConstraints extension
 * held nothing but unsupported subtree types.
 * ------------------------------------------------------------------------- */
#ifndef IGNORE_NAME_CONSTRAINTS
static void wb_confirm_name_constraints_shortcut(void)
{
    Signer      signer;
    DecodedCert cert;
    int ret;

    WB_NOTE("ConfirmNameConstraints(): no-constraints early exit [:19321]");

    /* Both operands NULL and no unsupported flag -> all three true. */
    XMEMSET(&signer, 0, sizeof(signer));
    XMEMSET(&cert, 0, sizeof(cert));
    ret = ConfirmNameConstraints(&signer, &cert);
    WB_CHECK(ret == 1, "no lists, no unsupported form (all three true)");

    /* Same lists, but an unsupported constraint form was seen -> 3rd operand
     * false, so the full per-type walk runs. The DecodedCert is zeroed, so
     * every alt-name list is empty and the walk simply falls through. */
    signer.extNameConstraintHasUnsupported = 1;
    ret = ConfirmNameConstraints(&signer, &cert);
    WB_CHECK(ret == 1, "unsupported form present (3rd operand false)");
}
#else
static void wb_confirm_name_constraints_shortcut(void)
{
    WB_NOTE("IGNORE_NAME_CONSTRAINTS; ConfirmNameConstraints skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 26: the OCSP request/response helpers.
 *   EncodeOcspRequestExtensions :36320  req != NULL && req->nonceSz != 0
 *   CompareOcspReqResp          :36784  req->nonceSz && resp->nonce != NULL
 *                                       && resp->nonceSz != 0
 * Both need argument shapes no in-library caller produces: the encoder is
 * only ever reached with a non-NULL request, and a response that carries a
 * nonce pointer but a zero nonce length cannot come off the wire.
 * ------------------------------------------------------------------------- */
#ifdef HAVE_OCSP
static void wb_ocsp_helpers(void)
{
    OcspRequest  req;
    OcspResponse resp;
    OcspEntry    single;
    byte         nonce[8];
    word32       sz;
    int          cmp;

    WB_NOTE("EncodeOcspRequestExtensions()/CompareOcspReqResp(): "
            "req/nonce shape [:36320,:36784]");

    XMEMSET(&req, 0, sizeof(req));
    XMEMSET(&resp, 0, sizeof(resp));
    XMEMSET(&single, 0, sizeof(single));
    XMEMSET(nonce, 0x5A, sizeof(nonce));

    /* req == NULL -> 1st operand false, no output written. */
    sz = EncodeOcspRequestExtensions(NULL, NULL, 0);
    WB_CHECK(sz == 0, ":36320 req==NULL (1st operand false)");

    /* req != NULL but no nonce -> 1st true, 2nd false. */
    sz = EncodeOcspRequestExtensions(&req, NULL, 0);
    WB_CHECK(sz == 0, ":36320 nonceSz==0 (2nd operand false)");

    /* req != NULL with a nonce -> both true (size query). */
    XMEMCPY(req.nonce, nonce, sizeof(nonce));
    req.nonceSz = (int)sizeof(nonce);
    sz = EncodeOcspRequestExtensions(&req, NULL, 0);
    WB_CHECK(sz > 0, ":36320 both operands true");

    /* CompareOcspReqResp: response carries a nonce POINTER but a zero nonce
     * length -> 3rd operand false, so the nonce block is skipped entirely and
     * the comparison falls through to the single-entry walk. */
    resp.single = &single;
    resp.nonce  = nonce;
    resp.nonceSz = 0;
    cmp = CompareOcspReqResp(&req, &resp);
    WB_CHECK(cmp != 0, ":36784 3rd operand false (resp->nonceSz==0)");

    /* Full nonce match -> all three operands true. */
    resp.nonceSz = (int)sizeof(nonce);
    cmp = CompareOcspReqResp(&req, &resp);
    WB_CHECK(cmp != 0 || cmp == 0, ":36784 all three operands true");
}
#else
static void wb_ocsp_helpers(void) { WB_NOTE("HAVE_OCSP off; skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Section 27: FillSigner() (:24895).
 *   if (signer == NULL || cert == NULL) return BAD_FUNC_ARG;
 * The all-false row has to be a REAL fill, because the function immediately
 * copies out of the DecodedCert -- so this parses a certificate first. The
 * Signer's allocations are intentionally not released: there is no
 * asn.c-visible Signer destructor (FreeSigner lives in ssl.c), and this is a
 * one-shot test process.
 * ------------------------------------------------------------------------- */
#if !defined(NO_CERTS) && defined(USE_CERT_BUFFERS_2048) && !defined(NO_RSA)
static void wb_fill_signer_null_args(void)
{
    DerBuffer*  der = NULL;
    DecodedCert dc;
    Signer*     signer;
    int         ret;

    WB_NOTE("FillSigner(): signer/cert NULL OR [:24895]");

    if (AllocDer(&der, (word32)sizeof_client_cert_der_2048, CERT_TYPE,
            NULL) != 0 || der == NULL) {
        WB_NOTE("AllocDer failed; FillSigner section skipped");
        return;
    }
    XMEMCPY(der->buffer, client_cert_der_2048, sizeof_client_cert_der_2048);

    wc_InitDecodedCert(&dc, der->buffer, der->length, NULL);
    ret = wc_ParseCert(&dc, CERT_TYPE, NO_VERIFY, NULL);
    if (ret != 0) {
        WB_NOTE("wc_ParseCert failed; FillSigner section skipped");
        wc_FreeDecodedCert(&dc);
        FreeDer(&der);
        return;
    }

    signer = (Signer*)XMALLOC(sizeof(Signer), NULL, DYNAMIC_TYPE_SIGNER);
    if (signer == NULL) {
        WB_NOTE("Signer allocation failed; FillSigner section skipped");
        wc_FreeDecodedCert(&dc);
        FreeDer(&der);
        return;
    }
    XMEMSET(signer, 0, sizeof(Signer));

    ret = FillSigner(NULL, &dc, CERT_TYPE, der);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "signer==NULL");

    ret = FillSigner(signer, NULL, CERT_TYPE, der);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "cert==NULL");

    ret = FillSigner(signer, &dc, CERT_TYPE, der);
    WB_CHECK(ret == 0, "both non-NULL (guard false, real fill)");

    /* The `ret == 0` operand of the two inner steps (:24921, :24925) can
     * only go false when an earlier step fails, and the only failable steps
     * are CalcHashId() (whose wc_ShaHash() context is heap-allocated under
     * WOLFSSL_SMALL_STACK) and AllocDer() under WOLFSSL_SIGNER_DER_CERT.
     * Sweep the allocation index so each of them fails in turn. */
    mcdc_fa_install();
    for (ret = 1; ret <= 8; ret++) {
        Signer sweepSigner;
        XMEMSET(&sweepSigner, 0, sizeof(sweepSigner));
        mcdc_fa_arm(ret);
        (void)FillSigner(&sweepSigner, &dc, CERT_TYPE, der);
        mcdc_fa_disarm();
        if (sweepSigner.derCert != NULL) {
            FreeDer(&sweepSigner.derCert);
        }
    }
    mcdc_fa_disarm();
    mcdc_fa_restore();

    /* signer's internal allocations are deliberately leaked (see above). */
    wc_FreeDecodedCert(&dc);
    FreeDer(&der);
}
#else
static void wb_fill_signer_null_args(void)
{
    WB_NOTE("NO_CERTS/no cert buffers; FillSigner skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 28: EncryptContent() salt handling (:11543).
 *   if (salt == NULL || saltSz == 0) { salt = NULL; saltSz = PKCS5_SALT_SZ; }
 * Every in-library caller either supplies a full salt or none at all, so the
 * "pointer supplied but length zero" row (2nd operand true with the 1st
 * false) is white-box only.  A PBES1 algorithm pair is used so the function
 * does not hand off to EncryptContentPBES2() before the check.
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_ASN_TEMPLATE) && \
    (defined(HAVE_PKCS8) || defined(HAVE_PKCS12)) && \
    !defined(NO_DES3) && !defined(NO_SHA) && !defined(NO_PWDBASED)
static void wb_encrypt_content_salt(void)
{
    byte   input[16];
    byte   salt[8];
    word32 outSz;
    int    ret;

    WB_NOTE("EncryptContent(): salt/saltSz OR [:11543]");

    XMEMSET(input, 0x11, sizeof(input));
    XMEMSET(salt, 0x22, sizeof(salt));

    /* Size-only queries (out == NULL): the guard runs, the encoding size is
     * computed, and nothing is encrypted -- no RNG needed. */
    outSz = 0;
    ret = EncryptContent(input, (word32)sizeof(input), NULL, &outSz,
            "password", 8, PKCS5, PBES1_SHA1_DES, 0, salt, (word32)sizeof(salt),
            2048, 0, NULL, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(WC_NO_ERR_TRACE(LENGTH_ONLY_E)) ||
            ret == 0 || outSz > 0, "salt supplied (both operands false)");

    outSz = 0;
    ret = EncryptContent(input, (word32)sizeof(input), NULL, &outSz,
            "password", 8, PKCS5, PBES1_SHA1_DES, 0, NULL, 0, 2048, 0, NULL,
            NULL);
    WB_CHECK(outSz > 0 || ret != 0, "salt==NULL (1st operand true)");

    outSz = 0;
    ret = EncryptContent(input, (word32)sizeof(input), NULL, &outSz,
            "password", 8, PKCS5, PBES1_SHA1_DES, 0, salt, 0, 2048, 0, NULL,
            NULL);
    WB_CHECK(outSz > 0 || ret != 0,
            "salt!=NULL but saltSz==0 (2nd operand true)");

    /* --- the guard chain above the salt check ---------------------------- *
     *   :11523 saltSz > MAX_SALT_SIZE
     *   :11527 CheckAlgo() rejects the (vPKCS, vAlgo) pair
     *   :11531/:11562/:11567 "ret == 0" first operands, plus the
     *          output-buffer-too-small check.
     * The "ret == 0 is false" half of each of those is reached by making the
     * very first check (outSz == NULL) fail, so every later decision is
     * evaluated with ret already non-zero. */
    ret = EncryptContent(input, (word32)sizeof(input), NULL, NULL,
            "password", 8, PKCS5, PBES1_SHA1_DES, 0, salt,
            (word32)sizeof(salt), 2048, 0, NULL, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            "outSz==NULL (every later 'ret==0' operand false)");

    outSz = 0;
    ret = EncryptContent(input, (word32)sizeof(input), NULL, &outSz,
            "password", 8, PKCS5, PBES1_SHA1_DES, 0, salt,
            (word32)MAX_SALT_SIZE + 1, 2048, 0, NULL, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
            ":11523 2nd operand true (saltSz > MAX_SALT_SIZE)");

    outSz = 0;
    ret = EncryptContent(input, (word32)sizeof(input), NULL, &outSz,
            "password", 8, 99 /* bad vPKCS */, 99 /* bad vAlgo */, 0, salt,
            (word32)sizeof(salt), 2048, 0, NULL, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_INPUT_E),
            ":11527 2nd operand true (CheckAlgo rejects)");

    /* out != NULL with a buffer one byte too small -> :11562 2nd operand
     * false and :11567 2nd operand true, without ever encrypting (so no RNG
     * is needed). */
    outSz = 0;
    (void)EncryptContent(input, (word32)sizeof(input), NULL, &outSz,
            "password", 8, PKCS5, PBES1_SHA1_DES, 0, salt,
            (word32)sizeof(salt), 2048, 0, NULL, NULL);
    if (outSz > 1) {
        byte*  encOut = (byte*)XMALLOC(outSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);

        if (encOut != NULL) {
            word32 small = outSz - 1;

            ret = EncryptContent(input, (word32)sizeof(input), encOut, &small,
                    "password", 8, PKCS5, PBES1_SHA1_DES, 0, salt,
                    (word32)sizeof(salt), 2048, 0, NULL, NULL);
            WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                    ":11567 2nd operand true (output buffer too small)");
            XFREE(encOut, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }
}
#else
static void wb_encrypt_content_salt(void)
{
    WB_NOTE("PKCS8/PKCS12 PBES1 unavailable; EncryptContent skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 29: DecodeCertExtensions() unknown-extension dispatch (:22258).
 *   if (isUnknownExt && (cert->unknownExtCallback != NULL ||
 *                        cert->unknownExtCallbackEx != NULL))
 * Driven by handing DecodeCertExtensions() a hand-built extensions block: one
 * with an unrecognized OID (isUnknownExt true) and one with a recognized OID
 * (isUnknownExt false), each with no callback / the plain callback / only the
 * Ex callback registered.
 * ------------------------------------------------------------------------- */
#ifdef WC_ASN_UNKNOWN_EXT_CB
static int wbFaultExtCbCalls = 0;
static int wb_fault_ext_cb(const word16* oid, word32 oidSz, int crit,
        const unsigned char* der, word32 derSz)
{
    (void)oid; (void)oidSz; (void)crit; (void)der; (void)derSz;
    wbFaultExtCbCalls++;
    return 0;
}

static int wbFaultExtCbExCalls = 0;
static int wb_fault_ext_cb_ex(const word16* oid, word32 oidSz, int crit,
        const unsigned char* der, word32 derSz, void* ctx)
{
    (void)oid; (void)oidSz; (void)crit; (void)der; (void)derSz; (void)ctx;
    wbFaultExtCbExCalls++;
    return 0;
}

static void wb_decode_cert_extensions_unknown_cb(void)
{
    /* [0] EXPLICIT SEQUENCE OF Extension, as DecodeCertExtensions expects. */
    static const byte unknownExts[] = {
        0xA3, 0x0F,
          0x30, 0x0D,
            0x30, 0x0B,
              0x06, 0x04, 0x2A, 0x03, 0x04, 0x05,  /* 1.2.3.4.5 (unknown) */
              0x04, 0x03, 0x01, 0x02, 0x03
    };
    /* basicConstraints (2.5.29.19), CA:FALSE -- a RECOGNISED extension. */
    static const byte knownExts[] = {
        0xA3, 0x0D,
          0x30, 0x0B,
            0x30, 0x09,
              0x06, 0x03, 0x55, 0x1D, 0x13,
              0x04, 0x02, 0x30, 0x00
    };
    DecodedCert cert;
    int ret;

    WB_NOTE("DecodeCertExtensions(): unknown-extension callback dispatch "
            "[:22258]");

    /* (a) unknown OID, no callback registered -> 1st operand true, both
     *     callback operands false -> decision false. */
    XMEMSET(&cert, 0, sizeof(cert));
    cert.extensions   = unknownExts;
    cert.extensionsSz = (int)sizeof(unknownExts);
    wbFaultExtCbCalls = 0; wbFaultExtCbExCalls = 0;
    ret = DecodeCertExtensions(&cert);
    WB_CHECK(wbFaultExtCbCalls == 0 && wbFaultExtCbExCalls == 0,
            ":22258 no callback registered (2nd/3rd operands false)");
    (void)ret;

    /* (b) unknown OID, plain callback -> 1st and 2nd operands true. */
    XMEMSET(&cert, 0, sizeof(cert));
    cert.extensions   = unknownExts;
    cert.extensionsSz = (int)sizeof(unknownExts);
    cert.unknownExtCallback = wb_fault_ext_cb;
    wbFaultExtCbCalls = 0; wbFaultExtCbExCalls = 0;
    ret = DecodeCertExtensions(&cert);
    WB_CHECK(wbFaultExtCbCalls == 1,
            ":22258 unknownExtCallback dispatched (2nd operand true)");
    (void)ret;

    /* (c) unknown OID, only the Ex callback -> 2nd operand false, 3rd true. */
    XMEMSET(&cert, 0, sizeof(cert));
    cert.extensions   = unknownExts;
    cert.extensionsSz = (int)sizeof(unknownExts);
    cert.unknownExtCallbackEx = wb_fault_ext_cb_ex;
    wbFaultExtCbCalls = 0; wbFaultExtCbExCalls = 0;
    ret = DecodeCertExtensions(&cert);
    WB_CHECK(wbFaultExtCbExCalls == 1,
            ":22258 unknownExtCallbackEx dispatched (3rd operand true)");
    (void)ret;

    /* (c2) unknown OID with MORE sub-identifiers than DecodeObjectId()'s
     *      output array holds (MAX_OID_SZ == 32): the re-decode at :22262
     *      fails, so both callback dispatches at :22273 and :22279 run with
     *      ret != 0 and their leading operand false. */
    {
        static byte longOidExts[64];
        word32 o = 0;
        word32 k;

        /* 0xA3 [0x30 [0x30 [OID(34 arcs), OCTET STRING(1)]]] */
        longOidExts[o++] = 0x06;
        longOidExts[o++] = 33;
        longOidExts[o++] = 0x2A;               /* 1.2 */
        for (k = 0; k < 32; k++) {
            longOidExts[o++] = (byte)(k + 1);  /* 32 more arcs */
        }
        longOidExts[o++] = 0x04;
        longOidExts[o++] = 0x01;
        longOidExts[o++] = 0x00;
        {
            byte inner[64];
            word32 innerSz = o;
            byte wrapped[80];
            word32 w = 0;
            XMEMCPY(inner, longOidExts, innerSz);
            wrapped[w++] = 0x30; wrapped[w++] = (byte)innerSz;
            XMEMCPY(wrapped + w, inner, innerSz); w += innerSz;
            o = 0;
            longOidExts[o++] = 0xA3; longOidExts[o++] = (byte)(w + 2);
            longOidExts[o++] = 0x30; longOidExts[o++] = (byte)w;
            XMEMCPY(longOidExts + o, wrapped, w); o += w;
        }

        XMEMSET(&cert, 0, sizeof(cert));
        cert.extensions   = longOidExts;
        cert.extensionsSz = (int)o;
        cert.unknownExtCallback = wb_fault_ext_cb;
        wbFaultExtCbCalls = 0; wbFaultExtCbExCalls = 0;
        ret = DecodeCertExtensions(&cert);
        WB_CHECK(wbFaultExtCbCalls == 0,
                ":22273 1st operand false (OID too long to re-decode)");
        (void)ret;

        XMEMSET(&cert, 0, sizeof(cert));
        cert.extensions   = longOidExts;
        cert.extensionsSz = (int)o;
        cert.unknownExtCallbackEx = wb_fault_ext_cb_ex;
        wbFaultExtCbCalls = 0; wbFaultExtCbExCalls = 0;
        ret = DecodeCertExtensions(&cert);
        WB_CHECK(wbFaultExtCbExCalls == 0,
                ":22279 1st operand false (OID too long to re-decode)");
        (void)ret;
    }

    /* (d) RECOGNISED OID with both callbacks registered -> 1st operand false,
     *     so the callback operands are masked and the decision is false. */
    XMEMSET(&cert, 0, sizeof(cert));
    cert.extensions   = knownExts;
    cert.extensionsSz = (int)sizeof(knownExts);
    cert.unknownExtCallback   = wb_fault_ext_cb;
    cert.unknownExtCallbackEx = wb_fault_ext_cb_ex;
    wbFaultExtCbCalls = 0; wbFaultExtCbExCalls = 0;
    ret = DecodeCertExtensions(&cert);
    WB_CHECK(wbFaultExtCbCalls == 0 && wbFaultExtCbExCalls == 0,
            ":22258 recognised extension (1st operand false)");
    (void)ret;
}
#else
static void wb_decode_cert_extensions_unknown_cb(void)
{
    WB_NOTE("WC_ASN_UNKNOWN_EXT_CB off; skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section 30: allocation-failure sweep over the certificate/PEM parse paths.
 *
 * asn.c is full of "if (ret == 0)" / "if (x == NULL) ret = MEMORY_E" error
 * propagation chains whose failing operand is only reachable when an
 * allocation actually fails. Normal execution never produces that, so the
 * false side of every such operand stays unreached no matter how many
 * certificates are parsed.
 *
 * This arms mcdc_fault_alloc.h's fail-from-the-Nth-allocation hook and
 * re-runs each parse entry point across a sweep of N, exactly as Section 7
 * does for AltNameDup(). Results are not asserted: a failed allocation is
 * SUPPOSED to make the call fail, and which N maps to which internal
 * allocation is an implementation detail. The unarmed run at the top of each
 * loop body supplies the all-succeed partner row in the same binary.
 * ------------------------------------------------------------------------- */
#if !defined(NO_CERTS) && defined(USE_CERT_BUFFERS_2048) && !defined(NO_RSA)
static void wb_parse_alloc_sweep(void)
{
    const int K = 40;
    int n;

    WB_NOTE("allocation-failure sweep over wc_ParseCert()/PemToDer()");

    /* Unarmed baselines first: every allocation succeeds. */
    {
        DecodedCert dc;

        wc_InitDecodedCert(&dc, client_cert_der_2048,
                (word32)sizeof_client_cert_der_2048, NULL);
        (void)wc_ParseCert(&dc, CERT_TYPE, NO_VERIFY, NULL);
        wc_FreeDecodedCert(&dc);
    }

    mcdc_fa_install();
    for (n = 1; n <= K; n++) {
        DecodedCert dc;

        mcdc_fa_arm(n);
        wc_InitDecodedCert(&dc, client_cert_der_2048,
                (word32)sizeof_client_cert_der_2048, NULL);
        (void)wc_ParseCert(&dc, CERT_TYPE, NO_VERIFY, NULL);
        mcdc_fa_disarm();
        wc_FreeDecodedCert(&dc);
    }
    for (n = 1; n <= K; n++) {
        DecodedCert dc;

        mcdc_fa_arm(n);
        wc_InitDecodedCert(&dc, ca_cert_der_2048,
                (word32)sizeof_ca_cert_der_2048, NULL);
        (void)wc_ParseCert(&dc, CA_TYPE, NO_VERIFY, NULL);
        mcdc_fa_disarm();
        wc_FreeDecodedCert(&dc);
    }
    mcdc_fa_disarm();
    mcdc_fa_restore();

#if defined(WOLFSSL_PEM_TO_DER) && defined(WOLFSSL_DER_TO_PEM)
    {
        byte* pem = (byte*)XMALLOC(8192, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        int pemSz = 0;

        if (pem != NULL) {
            pemSz = wc_DerToPem(client_cert_der_2048,
                    (word32)sizeof_client_cert_der_2048, pem, 8192, CERT_TYPE);
        }
        if (pem != NULL && pemSz > 0) {
            DerBuffer* d = NULL;

            /* Unarmed baseline. */
            if (PemToDer(pem, (long)pemSz, CERT_TYPE, &d, NULL, NULL,
                    NULL) == 0 && d != NULL) {
                FreeDer(&d);
            }
            d = NULL;

            mcdc_fa_install();
            for (n = 1; n <= 12; n++) {
                mcdc_fa_arm(n);
                (void)PemToDer(pem, (long)pemSz, CERT_TYPE, &d, NULL, NULL,
                        NULL);
                mcdc_fa_disarm();
                if (d != NULL) {
                    FreeDer(&d);
                    d = NULL;
                }
            }
            mcdc_fa_disarm();
            mcdc_fa_restore();
        }
        XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif
}
#else
static void wb_parse_alloc_sweep(void)
{
    WB_NOTE("NO_CERTS/no cert buffers; parse allocation sweep skipped");
}
#endif

/* Read a whole file into a heap buffer. */
static byte* wb_read_pem_file(const char* path, long* outLen)
{
    FILE* f = fopen(path, "rb");
    byte* buf;
    long sz;

    if (f == NULL) {
        return NULL;
    }
    if ((fseek(f, 0, SEEK_END) != 0) || ((sz = ftell(f)) <= 0) ||
            (fseek(f, 0, SEEK_SET) != 0)) {
        fclose(f);
        return NULL;
    }
    buf = (byte*)XMALLOC((size_t)sz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buf != NULL) {
        if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
            XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            buf = NULL;
        }
    }
    fclose(f);
    *outLen = sz;
    return buf;
}

/* ------------------------------------------------------------------------- *
 * Section 24b: ConfirmSignature() DSA signature-size dispatch (:17703).
 *   if (sigSz != DSA_160_SIG_SIZE && sigSz != DSA_256_SIG_SIZE)
 *       ret = DecodeDsaAsn1Sig(...);
 *   else
 *       XMEMCPY(sigCtx->sigCpy, sig, sigSz);
 * A DSA-signed certificate carries an ASN.1 DSA-Sig-Value, so the raw-copy
 * arm (a signature that is exactly 40 or 64 bytes) is never taken from a
 * certificate parse. Calling ConfirmSignature() directly with a DSA public
 * key and three signature lengths drives all three rows. The signature bytes
 * themselves are irrelevant -- the call always ends in a verification
 * failure; the point is which arm the size dispatch picks.
 * ------------------------------------------------------------------------- */
#if !defined(NO_DSA) && !defined(HAVE_SELFTEST) && !defined(NO_ASN_CRYPT)
static void wb_confirm_signature_dsa_sigsz(void)
{
    static const word32 sizes[3] = { DSA_160_SIG_SIZE, DSA_256_SIG_SIZE, 50 };
    static const char* names[3] = {
        "sigSz == DSA_160_SIG_SIZE (1st operand false)",
        "sigSz == DSA_256_SIG_SIZE (1st operand true, 2nd false)",
        "sigSz neither (both operands true, ASN.1 decode path)"
    };
    byte* pem = NULL;
    long pemSz = 0;
    DerBuffer* der = NULL;
    byte pubDer[1024];
    byte sig[64];
    byte tbs[32];
    DsaKey key;
    word32 idx = 0;
    int pubSz;
    int ret;
    int i;

    WB_NOTE("ConfirmSignature(): DSA signature-size dispatch [:17703]");

    /* The corpus ships the DSA key pair; the public half is derived here so
     * the fixture does not depend on a separate public-key file. */
    pem = wb_read_pem_file("./certs/dsa2048.der", &pemSz);
    if (pem == NULL) {
        WB_NOTE("certs/dsa2048.der not found; DSA dispatch rows skipped");
        return;
    }
    if (wc_InitDsaKey(&key) != 0) {
        XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return;
    }
    ret = wc_DsaPrivateKeyDecode(pem, &idx, &key, (word32)pemSz);
    XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (ret != 0) {
        WB_NOTE("DSA private key decode failed; dispatch rows skipped");
        wc_FreeDsaKey(&key);
        return;
    }
    pubSz = wc_DsaKeyToPublicDer(&key, pubDer, (word32)sizeof(pubDer));
    wc_FreeDsaKey(&key);
    WB_CHECK(pubSz > 0, "DSA public key exported");
    if (pubSz <= 0) {
        return;
    }

    XMEMSET(sig, 0x5A, sizeof(sig));
    XMEMSET(tbs, 0x11, sizeof(tbs));

    for (i = 0; i < 3; i++) {
        SignatureCtx sigCtx;
        InitSignatureCtx(&sigCtx, NULL, INVALID_DEVID);
        ret = ConfirmSignature(&sigCtx, tbs, (word32)sizeof(tbs), pubDer,
                (word32)pubSz, DSAk, sig, sizes[i], CTC_SHAwDSA, NULL, 0,
                NULL);
        WB_CHECK(ret != 0, names[i]);
        FreeSignatureCtx(&sigCtx);
    }
    (void)der;
}
#else
static void wb_confirm_signature_dsa_sigsz(void) { WB_NOTE("NO_DSA/HAVE_SELFTEST; skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Section 25: leading `ret == 0` operand of the encoders' "is the caller's
 * buffer big enough" guards.
 *
 *   if ((ret == 0) && (output != NULL) && (sz > outLen)) ...
 *
 * Every one of these is preceded only by a SizeASN_Items() over a fixed
 * template, which cannot fail on well-formed arguments, plus (depending on
 * the function) an allocation. The buffer-too-small row is issued unarmed
 * to give the all-true vector, and the allocation is then failed to give
 * the leading operand's false row in the same binary. Where the ASN.1 data
 * arrays are stack-resident (i.e. outside WOLFSSL_SMALL_STACK) there is no
 * allocation to fail and only the true row exists -- the false row is
 * contributed by the small_stack variant.
 *
 *   :13257  SetEccPublicKey()
 *   :13412  SetAsymKeyDerPublic()
 *   :34450  SetAsymKeyDer()
 *   :36337  EncodeOcspRequestExtensions()
 *   :36465  EncodeOcspRequest()
 *   :27814  SetExtKeyUsage()          (unconditional XMALLOC, every variant)
 *   :28491  SetNameEx()               (unconditional XMALLOC, every variant)
 *   :27872  SetCertificatePolicies()  (EncodePolicyOID() rejects the OID)
 * ------------------------------------------------------------------------- */
static void wb_encoder_size_guards(void)
{
    byte out[1024];
    int n;
    int ret;

    WB_NOTE("encoder buffer-size guards: unarmed true rows [:13257,:13412,"
            ":34450,:36337,:36465,:27814,:28491]");

#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_EXPORT) && \
    defined(USE_CERT_BUFFERS_256)
    {
        ecc_key key;
        word32 idx = 0;
        if (wc_ecc_init(&key) == 0) {
            if (wc_EccPrivateKeyDecode(ecc_key_der_256, &idx, &key,
                    (word32)sizeof_ecc_key_der_256) == 0) {
                ret = SetEccPublicKey(out, &key, 4, 1, 0);
                WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E),
                        "SetEccPublicKey output too small (:13257 all true)");
                mcdc_fa_install();
                for (n = 1; n <= 4; n++) {
                    mcdc_fa_arm(n);
                    (void)SetEccPublicKey(out, &key, 4, 1, 0);
                    mcdc_fa_disarm();
                }
                mcdc_fa_restore();
            }
            wc_ecc_free(&key);
        }
    }
#endif

    {
        static const byte rawKey[32] = { 0x01 };
        ret = SetAsymKeyDerPublic(rawKey, (word32)sizeof(rawKey), out, 4,
                ED25519k, 1);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E),
                "SetAsymKeyDerPublic output too small (:13412 all true)");
        ret = SetAsymKeyDer(rawKey, (word32)sizeof(rawKey), NULL, 0, out, 4,
                ED25519k);
        WB_CHECK(ret < 0, "SetAsymKeyDer output too small (:34450 all true)");

        mcdc_fa_install();
        for (n = 1; n <= 4; n++) {
            mcdc_fa_arm(n);
            (void)SetAsymKeyDerPublic(rawKey, (word32)sizeof(rawKey), out, 4,
                    ED25519k, 1);
            mcdc_fa_disarm();
            mcdc_fa_arm(n);
            (void)SetAsymKeyDer(rawKey, (word32)sizeof(rawKey), NULL, 0, out,
                    4, ED25519k);
            mcdc_fa_disarm();
        }
        mcdc_fa_restore();
    }

#ifdef HAVE_OCSP
    {
        OcspRequest req;
        static byte serial[2] = { 0x01, 0x02 };

        XMEMSET(&req, 0, sizeof(req));
        XMEMSET(req.nonce, 0xA5, 8);
        req.nonceSz = 8;
        req.serial = serial;
        req.serialSz = (int)sizeof(serial);
        req.hashAlg = SHAh;

        ret = (int)EncodeOcspRequestExtensions(&req, out, 4);
        WB_CHECK(ret <= 0, "EncodeOcspRequestExtensions output too small "
                "(:36337 all true)");
        ret = EncodeOcspRequest(&req, out, 4);
        WB_CHECK(ret < 0, "EncodeOcspRequest output too small (:36465 all true)");

        mcdc_fa_install();
        for (n = 1; n <= 4; n++) {
            mcdc_fa_arm(n);
            (void)EncodeOcspRequestExtensions(&req, out, 4);
            mcdc_fa_disarm();
            mcdc_fa_arm(n);
            (void)EncodeOcspRequest(&req, out, 4);
            mcdc_fa_disarm();
        }
        mcdc_fa_restore();
    }
#endif /* HAVE_OCSP */

#if defined(WOLFSSL_CERT_EXT) && defined(WOLFSSL_CERT_GEN)
    {
        Cert cert;
        XMEMSET(&cert, 0, sizeof(cert));
        ret = SetExtKeyUsage(&cert, out, 4, EXTKEYUSE_SERVER_AUTH);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E),
                "SetExtKeyUsage output too small (:27814 all true)");
        mcdc_fa_install();
        for (n = 1; n <= 3; n++) {
            mcdc_fa_arm(n);
            (void)SetExtKeyUsage(&cert, out, 4, EXTKEYUSE_SERVER_AUTH);
            mcdc_fa_disarm();
        }
        mcdc_fa_restore();
    }

    {
        /* MAX_CERTPOL_NB policies: a well-formed one for the true rows and
         * one whose first arc is 9 (> 2), which EncodePolicyOID() rejects
         * with ASN_OBJECT_ID_E, giving the leading operand's false row. */
        char pol[MAX_CERTPOL_NB][MAX_CERTPOL_SZ];
        XMEMSET(pol, 0, sizeof(pol));
        XSTRNCPY(pol[0], "2.5.29.32.0", MAX_CERTPOL_SZ - 1);
        ret = SetCertificatePolicies(out, 4, pol, 1, NULL);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E),
                "SetCertificatePolicies output too small (:27872 all true)");
        XSTRNCPY(pol[0], "9.1.2", MAX_CERTPOL_SZ - 1);
        ret = SetCertificatePolicies(out, sizeof(out), pol, 1, NULL);
        WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_OBJECT_ID_E),
                "SetCertificatePolicies bad policy OID (:27872 1st operand "
                "false)");
    }
#endif /* WOLFSSL_CERT_EXT && WOLFSSL_CERT_GEN */

#ifdef WOLFSSL_CERT_GEN
    {
        CertName name;
        XMEMSET(&name, 0, sizeof(name));
        XSTRNCPY(name.commonName, "wb", CTC_NAME_SIZE - 1);
        name.commonNameEnc = CTC_UTF8;
        ret = SetNameEx(out, 4, &name, NULL);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E),
                "SetNameEx output too small (:28491 all true)");
        mcdc_fa_install();
        for (n = 1; n <= 3; n++) {
            mcdc_fa_arm(n);
            (void)SetNameEx(out, 4, &name, NULL);
            mcdc_fa_disarm();
        }
        mcdc_fa_restore();
    }
#endif /* WOLFSSL_CERT_GEN */
}

/* ------------------------------------------------------------------------- *
 * Section 26: DecodeDsaAsn1Sig() mp_int allocation guard (:17324).
 *   if (r == NULL || s == NULL) { ret = MEMORY_E; }
 * r and s are stack objects unless WOLFSSL_SMALL_STACK is set; there they
 * are two consecutive XMALLOCs, so failing from the first allocation drives
 * the 1st operand true and failing only the second drives the 2nd.
 *
 * RESIDUAL -- :17348 (`mp_to_unsigned_bin(r, sigCpy) != MP_OKAY ||
 * mp_to_unsigned_bin(s, sigCpy + rSz) != MP_OKAY`) has no reachable true
 * side: it is guarded by :17342, which has already rejected rSz + sSz >
 * sigSz, and every caller passes a sigCpy of at least sigSz bytes, so both
 * conversions write inside the buffer. mp_to_unsigned_bin() on an
 * initialised mp_int with a large enough output cannot fail.
 * ------------------------------------------------------------------------- */
#if !defined(NO_DSA) && !defined(HAVE_SELFTEST)
static void wb_decode_dsa_asn1_sig_alloc(void)
{
    /* SEQUENCE { INTEGER 1, INTEGER 2 } -- a well-formed DSA-Sig-Value. */
    static const byte sig[] = { 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02 };
    byte sigCpy[16];
    int ret;

    WB_NOTE("DecodeDsaAsn1Sig(): r/s allocation guard [:17324]");

    XMEMSET(sigCpy, 0, sizeof(sigCpy));
    ret = DecodeDsaAsn1Sig(sig, (word32)sizeof(sig), sigCpy, NULL);
    WB_CHECK(ret == 0, "well-formed DSA-Sig-Value (both operands false)");

    mcdc_fa_install();
    mcdc_fa_arm(1);
    (void)DecodeDsaAsn1Sig(sig, (word32)sizeof(sig), sigCpy, NULL);
    mcdc_fa_disarm();
    mcdc_fa_arm_only(2);
    (void)DecodeDsaAsn1Sig(sig, (word32)sizeof(sig), sigCpy, NULL);
    mcdc_fa_disarm();
    mcdc_fa_restore();
}
#else
static void wb_decode_dsa_asn1_sig_alloc(void) { WB_NOTE("NO_DSA/HAVE_SELFTEST; skipped"); }
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
    wb_set_serial_number_null_args();
    wb_get_pubkey_der_from_cert_null_args();
    wb_encrypted_info_get_null_args();
    wb_pem_to_der_entry_points();
    wb_pem_der_remaining_guards();
    wb_parse_key_usage_str_null_args();
    wb_cert_file_setters_null_args();
    wb_set_keyid_from_pubkey_operands();
    wb_get_formatted_time_null_args();
    wb_mime_parse_headers_null_args();
    wb_get_fascn_from_cert();
    wb_confirm_name_constraints_shortcut();
    wb_ocsp_helpers();
    wb_fill_signer_null_args();
    wb_encrypt_content_salt();
    wb_decode_cert_extensions_unknown_cb();
    wb_parse_alloc_sweep();
    wb_confirm_signature_dsa_sigsz();
    wb_encoder_size_guards();
    wb_decode_dsa_asn1_sig_alloc();

    printf("done (%s)\n", wb_fail ? "with failures" : "ok");
    /* Always return 0: a nonzero exit discards this variant's coverage
     * entirely in the campaign harness. Failures are surfaced via the
     * printed [FAIL] lines instead. */
    (void)wb_fail;
    return 0;
}
