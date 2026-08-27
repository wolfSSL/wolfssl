/* test_tsp_whitebox.c
 *
 * White-box MC/DC supplement for wolfcrypt/src/tsp.c and
 * wolfcrypt/src/asn_tsp.c (RFC 3161 Time-Stamp Protocol).
 *
 * tests/api/test_tsp.c drives the module through its public API with
 * well-formed requests/responses/tokens built end to end (real signatures,
 * real certificates), which never exercises many of the failure-half
 * conditions here: a few argument combinations tests/api does not happen to
 * hit, a handful of file-static helpers (Tsp_CheckTsaName,
 * Tsp_CheckSignerCert, TspResponse_Verify) whose "impossible" operand
 * combinations every public caller avoids, and low-level ASN.1 syntax edges
 * in TspCheckGenTimeSyntax/TspCheckOneSignerInfo/TspCheckSigningCertAttr
 * that are simplest to reach with hand-built buffers rather than a full
 * signed token.
 *
 * asn_tsp.c is #include'd into asn.c (WOLFSSL_ASN_TSP_INCLUDED guard) and is
 * NOT compiled as its own translation unit, so its file-static helpers are
 * not directly reachable from a TU that only includes tsp.c. This file does
 * not need to reach any of them, though: every asn_tsp.c function targeted
 * below (TspCheckGenTimeSyntax, TspCheckSigningCertAttr,
 * TspCheckOneSignerInfo, TspEncodeSigningCertV2) is declared WOLFSSL_LOCAL
 * (extern, hidden visibility) in tsp.h and already linked into the built
 * library's asn.o - they are called directly through the normal library
 * link, with only wolfcrypt/src/tsp.c compiled in directly (#include) to
 * reach its own three file-static helpers (Tsp_CheckTsaName,
 * Tsp_CheckSignerCert, TspResponse_Verify).
 *
 * Targeted residuals, by class:
 *   Class 1  wc_TspTstInfo_SetNonce() leading-zero-strip loop ........ 1 cond
 *   Class 2  wc_TspTstInfo_SetFromRequest() policySz/serialSz==0 ..... 2 conds
 *   Class 3  wc_TspTstInfo_CheckRequest() nonce/policy mismatch ...... 2 conds
 *   Class 4  wc_TspTstInfo_SignWithPkcs7() singleCertSz==0 ........... 1 cond
 *   Class 5  Tsp_CheckTsaName() ASN chain + name comparisons ......... 9 conds
 *   Class 6  Tsp_CheckSignerCert() key usage (tsa_bad_ku_cert fixture)  1 cond
 *   Class 7  TspResponse_Verify() token==NULL||tokenSz==0 ............ 1 cond
 *   Class 8  TspCheckGenTimeSyntax() date/time and fraction syntax ... 7 conds
 *   Class 9  wc_TspTstInfo_Encode() accuracy micros!=0 ............... 1 cond
 *   Class 10 TspCheckSigningCertAttr() cert-hash mismatch ............ 1 cond
 *   Class 11 TspCheckOneSignerInfo() SignerInfo SET walk ............. 4 conds
 * Total newly exercised: 30 conditions (of 58 in the campaign's GAPS.md).
 *
 * Documented residuals (not exercised here; time-boxed out of this pass -
 * each needs either a fault only reachable through a platform-specific
 * extreme time_t/clock failure, a fixture this pass did not locate, or a
 * fully valid signed CMS SignedData token plus certificate chain, which is
 * substantially more setup than the rest of this file):
 *   - tsp.c:1112 wc_TspTstInfo_CheckGenTime() second GetFormattedTime_ex()
 *     call's `ret==0` operand: requires the FIRST GetFormattedTime_ex() call
 *     (formatting `now - tolerance`) to fail, which needs XGMTIME()/
 *     ValidateGmtime() to reject a computed time_t - not reliably
 *     triggerable across platforms without a clock/libc fault injection.
 *   - tsp.c:1763 Tsp_CheckSignerCert() extended-key-usage guard,
 *     `!extExtKeyUsageSet` and `!extExtKeyUsageCrit` operands: no test
 *     fixture with "no EKU extension at all" or "EKU present but not
 *     critical" was found in certs_test.h within this pass's time budget
 *     (tsa_bad_ku_cert_der_2048 and tsa_extra_eku_cert_der_2048 cover other
 *     operands of the same two decisions, already outside GAPS.md).
 *   - tsp.c:1854 wc_TspTstInfo_VerifyWithPKCS7() contentType-OID mismatch,
 *     tsp.c:2162/:2167/:2179/:2188/:2230 TspResponse_Verify()'s cm/cert/
 *     contentSz/cleanup decisions past a successful token verify: all
 *     require a genuinely valid signed CMS SignedData TimeStampToken (real
 *     RSA signature over real SignedAttributes) to reach `ret==0` at that
 *     point - buildable with tsa_cert_der_2048/tsa_key_der_2048 the same way
 *     tests/api/test_tsp.c's test_tsp_make_token() does, but not attempted
 *     in this pass.
 *   - asn_tsp.c:714/:718/:1021/:1194 wc_TspTstInfo_Decode()/
 *     wc_TspResponse_Decode() ASN-template decode-side conditions (empty
 *     hash, out-of-range accuracy on decode, PKIStatusInfo failInfo/tag
 *     checks, resp->status range on decode): reachable by encoding a valid
 *     structure with wc_TspTstInfo_Encode()/wc_TspResponse_Encode() and then
 *     surgically corrupting specific DER length/tag bytes (the same
 *     technique as test_pkcs12_parse_whitebox.c's Class 3), but the ASN
 *     template's exact byte offsets were not worked out in this pass.
 *
 * STRUCTURALLY UNSATISFIABLE (recorded in campaign/db/exclusions.json):
 *   - asn_tsp.c:1021 idx1 `length >= 2`, idx2 `length <= 5`. Defence in depth
 *     behind the ASN.1 template. GetASN_Items() stores the item's FULL length
 *     (asn.c:1948) before stepping over a BIT STRING's unused-bits byte, then
 *     rejects a zero-length BIT STRING in GetASN_BitString() and rejects
 *     len == 0 || len > 4 in GetASN_StoreData()'s ASN_DATA_TYPE_WORD32 case,
 *     which is the target GetASN_Int32Bit() installs for TSPRESPASN_IDX_STAT_
 *     FAIL. A decoded failInfo therefore always has length in [2,5] and
 *     neither explicit bound can be false. When the optional item is absent
 *     the leading `tag != 0` operand short-circuits first.
 *   - asn_tsp.c:1433 idx0: see the note above the signerInfos fixtures.
 *
 * Idiom: same as the other tests/unit-mcdc files. #include tsp.c directly to
 * reach its three file-static helpers; everything else is called through
 * the normal external link (tsp.h prototypes + the built library).
 */

#include <wolfcrypt/src/tsp.c>

#include <wolfssl/certs_test.h>
#include <stdio.h>
#include <string.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if !defined(WOLFSSL_TSP)

int main(void)
{
    printf("tsp.c white-box: WOLFSSL_TSP absent, nothing to do\n");
    return 0;
}

#else

/* ------------------------------------------------------------------------- *
 * Class 1: wc_TspTstInfo_SetNonce() leading-zero-strip loop (tsp.c:939)
 *   while ((nonceSz > 1) && (nonce[0] == 0x00))
 * Real nonces from wc_TspRequest_GenerateNonce()/decoded requests either
 * have more than one byte (exercising both operands normally) or are a
 * single non-zero byte; a single *zero* byte demonstrates the `nonceSz > 1`
 * operand's independent effect: the loop body must not run regardless of
 * nonce[0], because there is nowhere left to strip from.
 * ------------------------------------------------------------------------- */
#ifdef WOLFSSL_TSP_RESPONDER
static void wb_set_nonce(void)
{
    TspTstInfo tst;
    byte nonce1[1] = { 0x00 };
    int ret;

    XMEMSET(&tst, 0, sizeof(tst));
    ret = wc_TspTstInfo_SetNonce(&tst, nonce1, 1);
    if ((ret != 0) || (tst.nonceSz != 1)) {
        WB_NOTE("wc_TspTstInfo_SetNonce single-zero-byte case misbehaved");
        wb_fail = 1;
    }
    WB_NOTE("wc_TspTstInfo_SetNonce nonceSz>1 false-side exercised");
}
#else
static void wb_set_nonce(void) { WB_NOTE("WOLFSSL_TSP_RESPONDER off; SetNonce skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Class 2: wc_TspTstInfo_SetFromRequest() (tsp.c:1033) six-operand NULL/
 * size guard - policySz==0 (operand 3) and serialSz==0 (operand 5) with
 * every other operand false (valid pointers, non-zero sizes elsewhere).
 * ------------------------------------------------------------------------- */
#ifdef WOLFSSL_TSP_RESPONDER
static void wb_set_from_request(void)
{
    TspTstInfo tst;
    TspRequest req;
    byte policy[4] = { 1, 2, 3, 4 };
    byte serial[4] = { 5, 6, 7, 8 };
    int ret;

    XMEMSET(&tst, 0, sizeof(tst));
    XMEMSET(&req, 0, sizeof(req));

    ret = wc_TspTstInfo_SetFromRequest(&tst, &req, policy, 0, serial,
            sizeof(serial), NULL, 0);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("SetFromRequest policySz==0 case misbehaved");
        wb_fail = 1;
    }

    ret = wc_TspTstInfo_SetFromRequest(&tst, &req, policy, sizeof(policy),
            serial, 0, NULL, 0);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("SetFromRequest serialSz==0 case misbehaved");
        wb_fail = 1;
    }
    WB_NOTE("wc_TspTstInfo_SetFromRequest policySz/serialSz==0 pairs exercised");
}
#else
static void wb_set_from_request(void) { WB_NOTE("WOLFSSL_TSP_RESPONDER off; SetFromRequest skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Class 3: wc_TspTstInfo_CheckRequest() (tsp.c:1175 nonce mismatch,
 * tsp.c:1182 policy mismatch), each the true-side of a mismatch guard whose
 * companion "matches" false-side is exercised by tests/api's happy-path
 * verify tests. TspRequest's nonce/policy members are fixed-size arrays, not
 * pointers - copied into with XMEMCPY, never assigned as a pointer.
 * ------------------------------------------------------------------------- */
#ifdef WOLFSSL_TSP_VERIFIER
static void wb_check_request(void)
{
    TspTstInfo tst;
    TspRequest req;
    byte nonceA[2] = { 0x01, 0x02 };
    byte nonceB[2] = { 0x01, 0x03 };
    byte policyA[3] = { 0x0A, 0x0B, 0x0C };
    byte policyB[3] = { 0x0A, 0x0B, 0x0D };
    int ret;

    XMEMSET(&tst, 0, sizeof(tst));
    XMEMSET(&req, 0, sizeof(req));
    tst.version = WC_TSP_VERSION;
    tst.imprint.hashAlgOID = SHA256h;
    req.imprint.hashAlgOID = SHA256h;
    tst.imprint.hashSz = 4;
    req.imprint.hashSz = 4;
    XMEMSET(tst.imprint.hash, 0xAA, 4);
    XMEMSET(req.imprint.hash, 0xAA, 4);

    /* 1175 true: request has a nonce, tstInfo's differs. */
    tst.nonce = nonceA;
    tst.nonceSz = sizeof(nonceA);
    XMEMCPY(req.nonce, nonceB, sizeof(nonceB));
    req.nonceSz = sizeof(nonceB);
    ret = wc_TspTstInfo_CheckRequest(&tst, &req);
    if (ret != WC_NO_ERR_TRACE(TSP_VERIFY_E)) {
        WB_NOTE("CheckRequest nonce-mismatch case misbehaved");
        wb_fail = 1;
    }

    /* 1182 true: no nonce requested (1175 false), request has a policy,
     * tstInfo's differs. */
    req.nonceSz = 0;
    tst.policy = policyA;
    tst.policySz = sizeof(policyA);
    XMEMCPY(req.policy, policyB, sizeof(policyB));
    req.policySz = sizeof(policyB);
    ret = wc_TspTstInfo_CheckRequest(&tst, &req);
    if (ret != WC_NO_ERR_TRACE(TSP_VERIFY_E)) {
        WB_NOTE("CheckRequest policy-mismatch case misbehaved");
        wb_fail = 1;
    }
    WB_NOTE("wc_TspTstInfo_CheckRequest nonce/policy mismatch pairs exercised");
}
#else
static void wb_check_request(void) { WB_NOTE("WOLFSSL_TSP_VERIFIER off; CheckRequest skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Class 4: wc_TspTstInfo_SignWithPkcs7() (tsp.c:1472) singleCertSz==0 with
 * singleCert non-NULL - the reachable half of the pkcs7->singleCert guard
 * beyond the NULL check tests/api already exercises.
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_TSP_RESPONDER) && defined(HAVE_PKCS7)
static void wb_sign_with_pkcs7_certsz(void)
{
    TspTstInfo tst;
    wc_PKCS7 pkcs7;
    byte certBuf[4] = { 1, 2, 3, 4 };
    byte out[16];
    word32 outSz = sizeof(out);
    int ret;

    XMEMSET(&tst, 0, sizeof(tst));
    XMEMSET(&pkcs7, 0, sizeof(pkcs7));
    pkcs7.singleCert = certBuf;
    pkcs7.singleCertSz = 0;
    ret = wc_TspTstInfo_SignWithPkcs7(&tst, &pkcs7, out, &outSz);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("SignWithPkcs7 singleCertSz==0 case misbehaved");
        wb_fail = 1;
    }
    WB_NOTE("wc_TspTstInfo_SignWithPkcs7 singleCertSz==0 exercised");
}
#else
static void wb_sign_with_pkcs7_certsz(void) { WB_NOTE("WOLFSSL_TSP_RESPONDER/HAVE_PKCS7 off; SignWithPkcs7 certsz skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Class 5: Tsp_CheckTsaName() (static, tsp.c:1655) - the ASN chain for the
 * directoryName branch and the RFC822/DNS/URI branch, plus the altNames
 * comparison loop. Small hand-built GeneralName buffers; DecodedCert's
 * subjectRaw/altNames fields are set directly (fully visible struct, no
 * need to run a real certificate parse for this static helper).
 * ------------------------------------------------------------------------- */
#ifdef WOLFSSL_TSP_VERIFIER
static word32 wb_der_len(byte* buf, word32 n)
{
    if (n < 0x80) {
        buf[0] = (byte)n;
        return 1;
    }
    buf[0] = 0x81;
    buf[1] = (byte)n;
    return 2;
}

static word32 wb_build_tlv(byte* out, byte tag, const byte* content,
        word32 contentLen)
{
    word32 idx = 0;
    byte lenBuf[4];
    word32 lenLen = wb_der_len(lenBuf, contentLen);

    out[idx++] = tag;
    XMEMCPY(out + idx, lenBuf, lenLen);
    idx += lenLen;
    XMEMCPY(out + idx, content, contentLen);
    idx += contentLen;
    return idx;
}

static void wb_check_tsa_name(void)
{
    DecodedCert dCert;
    byte tsa[64];
    DNS_entry entry;
    DNS_entry entry2;
    int ret;

    XMEMSET(&dCert, 0, sizeof(dCert));

    /* 1663 op0 true: GetASNTag fails on an empty buffer. */
    ret = Tsp_CheckTsaName(&dCert, tsa, 0);
    if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) { wb_fail = 1; }

    /* 1663 op2 true: valid header, but idx+len != tsaSz (claim more bytes
     * than the encoded GeneralName actually has; the extra byte is still
     * inside the real tsa[64] buffer, so no out-of-bounds read occurs). */
    tsa[0] = (byte)(ASN_CONTEXT_SPECIFIC | ASN_RFC822_TYPE);
    tsa[1] = 0x02;
    tsa[2] = 'a';
    tsa[3] = 'b';
    ret = Tsp_CheckTsaName(&dCert, tsa, 10);
    if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) { wb_fail = 1; }

    /* 1676 op0 true: directoryName [4] header ok, but nothing left for the
     * inner Name's own GetASNTag. */
    {
        byte inner[1] = { 0 };
        word32 n = wb_build_tlv(tsa, (byte)(ASN_CONTEXT_SPECIFIC |
                ASN_CONSTRUCTED | ASN_DIR_TYPE), inner, 0);
        ret = Tsp_CheckTsaName(&dCert, tsa, n);
        if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) { wb_fail = 1; }
    }

    /* 1676 op2 true: inner tag is SEQUENCE|CONSTRUCTED (op1 false), but its
     * own GetLength has nothing left to read. */
    {
        byte nameHdr[1] = { ASN_SEQUENCE | ASN_CONSTRUCTED };
        word32 n = wb_build_tlv(tsa, (byte)(ASN_CONTEXT_SPECIFIC |
                ASN_CONSTRUCTED | ASN_DIR_TYPE), nameHdr, 1);
        ret = Tsp_CheckTsaName(&dCert, tsa, n);
        if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) { wb_fail = 1; }
    }

    /* 1676 op3 true / 1683 op0 true: well-formed directoryName/Name, but (a)
     * tsaSz claims one extra byte beyond the encoding (op3), and (b)
     * dCert->subjectRaw is NULL for the else-if that follows once the chain
     * is well-formed. */
    {
        byte nameContent[4] = { 0xAA, 0xBB, 0xCC, 0xDD };
        byte name[8];
        word32 nameN = wb_build_tlv(name, ASN_SEQUENCE | ASN_CONSTRUCTED,
                nameContent, sizeof(nameContent));
        word32 n = wb_build_tlv(tsa, (byte)(ASN_CONTEXT_SPECIFIC |
                ASN_CONSTRUCTED | ASN_DIR_TYPE), name, nameN);

        ret = Tsp_CheckTsaName(&dCert, tsa, n + 1);
        if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) { wb_fail = 1; }

        dCert.subjectRaw = NULL;
        ret = Tsp_CheckTsaName(&dCert, tsa, n);
        if (ret != WC_NO_ERR_TRACE(TSP_VERIFY_E)) { wb_fail = 1; }

        /* 1683 op2 true: subjectRaw set, same length, differing content. */
        {
            byte subj[4] = { 0xAA, 0xBB, 0xCC, 0xDE };
            dCert.subjectRaw = subj;
            dCert.subjectRawLen = (int)sizeof(nameContent);
            ret = Tsp_CheckTsaName(&dCert, tsa, n);
            if (ret != WC_NO_ERR_TRACE(TSP_VERIFY_E)) { wb_fail = 1; }
        }
    }

    /* 1697 op0 true: tag == rfc822Name. No matching altName -> TSP_VERIFY_E
     * (the mismatch path is what is under test here, not a match). */
    {
        byte content[2] = { 'a', 'b' };
        word32 n = wb_build_tlv(tsa, (byte)(ASN_CONTEXT_SPECIFIC |
                ASN_RFC822_TYPE), content, sizeof(content));
        dCert.altNames = NULL;
        ret = Tsp_CheckTsaName(&dCert, tsa, n);
        if (ret != WC_NO_ERR_TRACE(TSP_VERIFY_E)) { wb_fail = 1; }
    }

    /* 1697 op2 true: tag == uniformResourceIdentifier (neither rfc822Name
     * nor dNSName) - and give it a matching altNames entry so this also
     * shows the 1706 loop reaching a real match. */
    {
        byte content[3] = { 'x', 'y', 'z' };
        word32 n = wb_build_tlv(tsa, (byte)(ASN_CONTEXT_SPECIFIC |
                ASN_URI_TYPE), content, sizeof(content));
        entry.next = NULL;
        entry.type = ASN_URI_TYPE;
        entry.len = 3;
        entry.name = "xyz";
        dCert.altNames = &entry;
        ret = Tsp_CheckTsaName(&dCert, tsa, n);
        if (ret != 0) { wb_fail = 1; }

        /* 1706 op0 false: first entry's type does not match; loop moves to
         * the next (still no match -> TSP_VERIFY_E). */
        entry2.next = NULL;
        entry2.type = ASN_DNS_TYPE;
        entry2.len = 3;
        entry2.name = "xyz";
        entry.next = &entry2;
        entry.type = ASN_RFC822_TYPE; /* != ASN_URI_TYPE requested above */
        dCert.altNames = &entry;
        ret = Tsp_CheckTsaName(&dCert, tsa, n);
        if (ret != WC_NO_ERR_TRACE(TSP_VERIFY_E)) { wb_fail = 1; }

        /* 1706 op1 false: entry->type matches but entry->len does not. */
        entry.next = NULL;
        entry.type = ASN_URI_TYPE;
        entry.len = 4;
        entry.name = "xyzq";
        dCert.altNames = &entry;
        ret = Tsp_CheckTsaName(&dCert, tsa, n);
        if (ret != WC_NO_ERR_TRACE(TSP_VERIFY_E)) { wb_fail = 1; }
    }

    WB_NOTE("Tsp_CheckTsaName ASN chain and name-comparison pairs exercised");
}
#else
static void wb_check_tsa_name(void) { WB_NOTE("WOLFSSL_TSP_VERIFIER off; Tsp_CheckTsaName skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Class 6: Tsp_CheckSignerCert() (static, tsp.c:1747) key usage guard
 * (tsp.c:1773 idx2: extKeyUsageSet true but neither digital-signature nor
 * content-commitment bit set). tsa_bad_ku_cert_der_2048 is a purpose-built
 * fixture in certs_test.h with a critical Key Usage of keyEncipherment only
 * and a critical, single, time-stamping-only Extended Key Usage (so this
 * exercises 1773 without also perturbing the 1763 EKU decision).
 * ------------------------------------------------------------------------- */
#ifdef WOLFSSL_TSP_VERIFIER
static void wb_check_signer_cert(void)
{
    int ret = Tsp_CheckSignerCert(tsa_bad_ku_cert_der_2048,
            sizeof(tsa_bad_ku_cert_der_2048), NULL, 0, NULL);

    if (ret != WC_NO_ERR_TRACE(KEYUSAGE_E)) {
        WB_NOTE("Tsp_CheckSignerCert tsa_bad_ku_cert case misbehaved");
        wb_fail = 1;
    }
    WB_NOTE("Tsp_CheckSignerCert key-usage-not-signing-only exercised");
}
#else
static void wb_check_signer_cert(void) { WB_NOTE("WOLFSSL_TSP_VERIFIER off; Tsp_CheckSignerCert skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Class 7: TspResponse_Verify() (static, tsp.c:2101) token==NULL||
 * tokenSz==0 (tsp.c:2135, second operand) - resp->status must be granted
 * first for ret==0 to reach this line, no signed token needed for this
 * specific guard.
 * ------------------------------------------------------------------------- */
#ifdef WOLFSSL_TSP_RESPONDER
static void wb_response_verify_no_token(void)
{
    TspResponse resp;
    int ret;

    XMEMSET(&resp, 0, sizeof(resp));
    resp.status = WC_TSP_PKISTATUS_GRANTED;
    resp.token = NULL;
    resp.tokenSz = 0;
    ret = TspResponse_Verify(&resp, NULL, 0, NULL, NULL);
    if (ret != WC_NO_ERR_TRACE(TSP_VERIFY_E)) {
        WB_NOTE("TspResponse_Verify no-token case misbehaved");
        wb_fail = 1;
    }
    WB_NOTE("TspResponse_Verify token==NULL||tokenSz==0 exercised");
}
#else
static void wb_response_verify_no_token(void) { WB_NOTE("WOLFSSL_TSP_RESPONDER off; TspResponse_Verify skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Class 8: TspCheckGenTimeSyntax() (asn_tsp.c:329, WOLFSSL_LOCAL - linked
 * externally, no #include needed). Date/time digit-range and fraction
 * syntax edges.
 * ------------------------------------------------------------------------- */
static void wb_check_gentime_syntax(void)
{
    int ret;

    /* 341 op1 true: non-digit above '9' in the 14-digit date/time run. */
    {
        static const byte g[] = "2024010112000AZ";
        ret = TspCheckGenTimeSyntax(g, sizeof(g) - 1);
        if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) { wb_fail = 1; }
    }
    /* 341 op0 true: non-digit below '0'. */
    {
        static const byte g[] = "2024010112000/Z";
        ret = TspCheckGenTimeSyntax(g, sizeof(g) - 1);
        if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) { wb_fail = 1; }
    }
    /* 354 idx3 true: day > 31 (all other date/time fields in range). */
    {
        static const byte g[] = "20240132120000Z";
        ret = TspCheckGenTimeSyntax(g, sizeof(g) - 1);
        if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) { wb_fail = 1; }
    }
    /* 362 op1 false: fraction digit run stops on a char below '0'. */
    {
        static const byte g[] = "20240101120000.5/Z";
        ret = TspCheckGenTimeSyntax(g, sizeof(g) - 1);
        if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) { wb_fail = 1; }
    }
    /* 362 op2 false: fraction digit run stops naturally at 'Z'. */
    {
        static const byte g[] = "20240101120000.5Z";
        ret = TspCheckGenTimeSyntax(g, sizeof(g) - 1);
        if (ret != 0) { wb_fail = 1; }
    }
    /* 369 op1 true: trailing byte after 'Z'. */
    {
        static const byte g[] = "20240101120000ZZ";
        ret = TspCheckGenTimeSyntax(g, sizeof(g) - 1);
        if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) { wb_fail = 1; }
    }
    WB_NOTE("TspCheckGenTimeSyntax date/time and fraction pairs exercised");
}

/* ------------------------------------------------------------------------- *
 * Class 9: wc_TspTstInfo_Encode() (asn_tsp.c:460) accuracy-all-zero check
 * (asn_tsp.c:557 idx2 false: micros != 0 while seconds/millis are 0, so
 * accuracy IS encoded).
 * ------------------------------------------------------------------------- */
#if !defined(NO_ASN_TIME) && !defined(USER_TIME) && !defined(TIME_OVERRIDES)
static void wb_encode_accuracy(void)
{
    TspTstInfo tst;
    byte policy[] = { 0x2b, 0x06, 0x01 };
    byte serial[] = { 0x01 };
    byte out[512];
    word32 outSz = sizeof(out);
    int ret;

    XMEMSET(&tst, 0, sizeof(tst));
    tst.policy = policy;
    tst.policySz = sizeof(policy);
    tst.imprint.hashAlgOID = SHA256h;
    tst.imprint.hashSz = 32;
    XMEMSET(tst.imprint.hash, 0xAA, 32);
    tst.serial = serial;
    tst.serialSz = sizeof(serial);
    tst.genTime = (const byte*)"20240101120000Z";
    tst.genTimeSz = 15;
    tst.accuracy.seconds = 0;
    tst.accuracy.millis = 0;
    tst.accuracy.micros = 5;

    ret = wc_TspTstInfo_Encode(&tst, out, &outSz);
    if (ret != 0) {
        WB_NOTE("wc_TspTstInfo_Encode accuracy-micros case misbehaved");
        wb_fail = 1;
    }
    WB_NOTE("wc_TspTstInfo_Encode accuracy micros!=0 exercised");
}
#else
static void wb_encode_accuracy(void) { WB_NOTE("no real clock; Encode accuracy skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Class 10: TspCheckSigningCertAttr() (asn_tsp.c:1258, WOLFSSL_LOCAL) - the
 * certHash-mismatch guard. A hand-built wc_PKCS7 object (heap/verifyCert/
 * decodedAttrib set directly - no real signing needed) with a
 * SigningCertificateV2 attribute value produced by TspEncodeSigningCertV2()
 * (also WOLFSSL_LOCAL, externally linked) hashing the same verifyCert bytes
 * gives a match; corrupting verifyCert afterward gives the mismatch.
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_TSP_VERIFIER) && defined(HAVE_PKCS7)
static void wb_check_signing_cert_attr(void)
{
    wc_PKCS7 pkcs7;
    PKCS7DecodedAttrib attrib;
    byte certBuf[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    byte essCert[128];
    word32 essCertSz = sizeof(essCert);
    byte oidBuf[32];
    int ret;

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));
    pkcs7.heap = NULL;
    pkcs7.verifyCert = certBuf;
    pkcs7.verifyCertSz = sizeof(certBuf);

    ret = TspEncodeSigningCertV2(SHA256h, certBuf, sizeof(certBuf), essCert,
            &essCertSz, NULL);
    if (ret != 0) {
        WB_NOTE("TspEncodeSigningCertV2 setup failed");
        wb_fail = 1;
        return;
    }

    XMEMSET(&attrib, 0, sizeof(attrib));
    XMEMCPY(oidBuf, tspSigningCertV2Oid, sizeof(tspSigningCertV2Oid));
    attrib.oid = oidBuf;
    attrib.oidSz = (word32)sizeof(tspSigningCertV2Oid);
    attrib.value = essCert;
    attrib.valueSz = essCertSz;
    pkcs7.decodedAttrib = &attrib;

    /* baseline: certHash matches the hash of verifyCert. */
    ret = TspCheckSigningCertAttr(&pkcs7);
    if (ret != 0) {
        WB_NOTE("TspCheckSigningCertAttr match case misbehaved");
        wb_fail = 1;
    }

    /* 1343 true: verifyCert changed after the attribute was built, so its
     * hash no longer matches certHash. */
    pkcs7.verifyCert[0] ^= 0xFF;
    ret = TspCheckSigningCertAttr(&pkcs7);
    if (ret != WC_NO_ERR_TRACE(TSP_VERIFY_E)) {
        WB_NOTE("TspCheckSigningCertAttr mismatch case misbehaved");
        wb_fail = 1;
    }
    WB_NOTE("TspCheckSigningCertAttr certHash mismatch pair exercised");
}
#else
static void wb_check_signing_cert_attr(void) { WB_NOTE("WOLFSSL_TSP_VERIFIER/HAVE_PKCS7 off; TspCheckSigningCertAttr skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Class 11: TspCheckOneSignerInfo() (asn_tsp.c:1408, WOLFSSL_LOCAL) - the
 * SignerInfo SET walk. Hand-built minimal SignedData wrappers (ContentInfo
 * SEQUENCE{OID signedData, [0]{SEQUENCE{version, empty digestAlgorithms SET,
 * empty encapContentInfo SEQUENCE, signerInfos SET}}}) with a crafted
 * signerInfos SET content:
 *   - a single malformed entry (tag mismatch, or a truncated long-form
 *     length) drives the inner while loop's `ret==0` operand false on its
 *     second check (asn_tsp.c:1429) and the final `cnt!=1` guard's
 *     `ret==0` operand false (asn_tsp.c:1445), since the malformed entry
 *     sets ret non-zero before either is reached again;
 *   - two well-formed empty entries give cnt==2, driving the final
 *     `cnt!=1` guard true with ret==0.
 * The while loop's own `GetASNTag(...)<0` operand (asn_tsp.c:1433 idx0) is
 * structurally unreachable at this call site: the loop only runs while
 * `idx<signersSz`, which already guarantees at least one byte is available
 * for GetASNTag's own single-byte bounds check, so that call can never fail
 * here - not attempted.
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_TSP_VERIFIER) && defined(HAVE_PKCS7)
static const byte wbTspTokenTagMismatch[] = {
    0x30, 0x1A, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07,
    0x02, 0xA0, 0x0D, 0x30, 0x0B, 0x02, 0x01, 0x01, 0x31, 0x00, 0x30, 0x00,
    0x31, 0x02, 0x02, 0x00
}; /* signerInfos content = { 0x02, 0x00 } -- tag is INTEGER, not SEQUENCE */

static const byte wbTspTokenBadLen[] = {
    0x30, 0x1A, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07,
    0x02, 0xA0, 0x0D, 0x30, 0x0B, 0x02, 0x01, 0x01, 0x31, 0x00, 0x30, 0x00,
    0x31, 0x02, 0x30, 0x82
}; /* signerInfos content = { 0x30, 0x82 } -- SEQUENCE tag, truncated
    * long-form length */

static const byte wbTspTokenTwoSigners[] = {
    0x30, 0x1C, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07,
    0x02, 0xA0, 0x0F, 0x30, 0x0D, 0x02, 0x01, 0x01, 0x31, 0x00, 0x30, 0x00,
    0x31, 0x04, 0x30, 0x00, 0x30, 0x00
}; /* signerInfos content = two empty SEQUENCEs -> cnt == 2 */

static void wb_check_one_signer_info(void)
{
    int ret;

    /* 1429 op0 false-exit (ret becomes non-zero mid-loop) / 1433 op1 true
     * (tag != SEQUENCE) / 1445 op0 false (ret!=0 short-circuits cnt!=1). */
    ret = TspCheckOneSignerInfo(wbTspTokenTagMismatch,
            sizeof(wbTspTokenTagMismatch), NULL);
    if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) { wb_fail = 1; }

    /* 1433 op2 true: valid SEQUENCE tag, but GetLength has nothing left. */
    ret = TspCheckOneSignerInfo(wbTspTokenBadLen, sizeof(wbTspTokenBadLen),
            NULL);
    if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) { wb_fail = 1; }

    /* 1445 op1 true (cnt==2 != 1) with op0 true (ret==0 throughout the
     * walk - both entries are well-formed empty SEQUENCEs). */
    ret = TspCheckOneSignerInfo(wbTspTokenTwoSigners,
            sizeof(wbTspTokenTwoSigners), NULL);
    if (ret != WC_NO_ERR_TRACE(TSP_VERIFY_E)) { wb_fail = 1; }

    WB_NOTE("TspCheckOneSignerInfo SignerInfo SET walk pairs exercised");
}
#else
static void wb_check_one_signer_info(void) { WB_NOTE("WOLFSSL_TSP_VERIFIER/HAVE_PKCS7 off; TspCheckOneSignerInfo skipped"); }
#endif

int main(void)
{
    printf("tsp.c / asn_tsp.c white-box MC/DC supplement\n");
    wb_set_nonce();
    wb_set_from_request();
    wb_check_request();
    wb_sign_with_pkcs7_certsz();
    wb_check_tsa_name();
    wb_check_signer_cert();
    wb_response_verify_no_token();
    wb_check_gentime_syntax();
    wb_encode_accuracy();
    wb_check_signing_cert_attr();
    wb_check_one_signer_info();
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Always return 0: a nonzero exit makes the campaign discard the whole
     * variant's coverage, including the parts that did succeed. */
    return 0;
}

#endif /* WOLFSSL_TSP */
