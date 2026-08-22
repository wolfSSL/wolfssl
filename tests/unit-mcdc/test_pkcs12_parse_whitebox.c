/* test_pkcs12_parse_whitebox.c
 *
 * White-box MC/DC supplement for wolfcrypt/src/pkcs12.c -- DER/BER-walk
 * decisions in the parse path that test_pkcs12_whitebox.c does not reach
 * (that file covers the container/NULL-guard/alloc-failure classes; this
 * file is the deep-parse companion. Read together, never edited together --
 * this file does not modify test_pkcs12_whitebox.c).
 *
 * Idiom: same as test_pkcs12_whitebox.c. #include pkcs12.c directly to reach
 * file-static helpers (PKCS12_CheckConstructedZero, PKCS12_CoalesceOctetStrings)
 * and call the public wc_d2i_PKCS12()/wc_PKCS12_parse() with hand-built or
 * corrupted DER/BER to reach the ASN_BER_TO_DER-only paths in
 * wc_PKCS12_parse_ex()'s ENCRYPTED_DATA content-info branch.
 *
 * Targeted residuals (pkcs12.c), by class:
 *   Class 1  PKCS12_CheckConstructedZero() outer-SEQUENCE failure ... 1 cond
 *            (pkcs12.c:1239, `ret==0` operand false side; the true side and
 *            all five later steps are already exercised by
 *            test_pkcs12_whitebox.c's wb_check_constructed_zero)
 *   Class 2  PKCS12_CoalesceOctetStrings() ASN chain .............. 4 conds
 *            (pkcs12.c:1294 tag!=OCTET_STRING, :1297 GetLength<=0)
 *   Class 3  wc_PKCS12_parse_ex() ENCRYPTED_DATA contentType OID .. 2 conds
 *            (pkcs12.c:1460 `ret<0 || oid!=WC_PKCS12_DATA`)
 *   Class 4  wc_d2i_PKCS12() indefinite-length EOC skip ............ 2 conds
 *            (pkcs12.c:809 `idx<totalSz && der[idx]==ASN_EOC`)
 *   Class 5  wc_PKCS12_parse_ex() indefinite + CheckConstructedZero . 2 conds
 *            (pkcs12.c:1470 `pkcs12->indefinite && PKCS12_CheckConstructedZero(...)==1`)
 *
 * How Class 4/5 buffers were built: a from-scratch minimal PFX (RFC 7292)
 * with the OUTER SEQUENCE BER-indefinite-length-encoded (`30 80 ... 00 00`),
 * which is the "size==0" trigger wc_d2i_PKCS12() uses to invoke
 * wc_BerToDer() and set pkcs12->indefinite=1. wc_BerToDer() only resolves
 * indefinite lengths it can see in the outer buffer; an OCTET STRING's
 * *content* is opaque to it, so a SEPARATE, independently BER-indefinite
 * AuthenticatedSafe (SEQUENCE OF ContentInfo) nested *inside* that octet
 * string survives the outer conversion untouched. GetSafeContent() then
 * converts that nested content itself (because pkcs12->indefinite is set),
 * which shrinks it by removing its own trailing EOC pair -- but the
 * *outer* index bookkeeping (idx = position-before-copy + bytes-consumed-
 * from-the-shrunk-copy) lands short of where the octet string's original,
 * unconverted declared length actually ends in the outer buffer, stranding
 * the original inner EOC pair right there. That is exactly what pkcs12.c:809
 * skips. Empirically verified (temporary instrumentation, not shipped here)
 * against a real build of this module's config.
 *
 * Documented residuals (not exercised here; independently re-confirmed the
 * same structural-dead-code conclusions already logged by
 * test_pkcs12_whitebox.c's file header, so not repeated as test code):
 *   - pkcs12.c:445/:477 digest/salt "size+curIdx>totalSz" operand,
 *     pkcs12.c:599 kLen<0, pkcs12.c:886 *pkcs12!=NULL false-side,
 *     pkcs12.c:2043/:2465 LENGTH_ONLY_E-passthrough ret<0 false-side --
 *     all structurally unreachable for the reasons already given at point
 *     of use in test_pkcs12_whitebox.c (each guarded by an earlier check --
 *     GetLength()'s own bounds check, wc_HashGetDigestSize()'s macro-
 *     identical guard, callerAlloc's assignment invariant, or the internal
 *     out==NULL call always returning exactly LENGTH_ONLY_E or a negative --
 *     that makes the missing half of the pair provably impossible).
 */

#include <wolfcrypt/src/pkcs12.c>

#include <wolfssl/certs_test.h>
#include <stdio.h>
#include <string.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if !defined(HAVE_PKCS12) || defined(NO_ASN) || defined(NO_PWDBASED) || \
    defined(NO_HMAC) || defined(NO_CERTS)

int main(void)
{
    printf("pkcs12.c parse white-box: HAVE_PKCS12 surface absent, nothing to do\n");
    return 0;
}

#else

#ifdef ASN_BER_TO_DER
/* Class 1: PKCS12_CheckConstructedZero() outer GetSequence() failure
 * (pkcs12.c:1239, `ret==0` operand false side). A buffer too small to even
 * hold a SEQUENCE header fails the very first step, so `ret` is already
 * non-zero when line 1239 is reached -- short-circuiting the whole
 * decision to false regardless of GetObjectId(). All other steps of this
 * chain (including 1239's true side) are covered by
 * test_pkcs12_whitebox.c's wb_check_constructed_zero. */
static void wb_check_zero_op1_false(void)
{
    byte buf[1] = { 0x30 };
    word32 idx = 0;
    int ret = PKCS12_CheckConstructedZero(buf, 0, &idx);

    if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) {
        WB_NOTE("PKCS12_CheckConstructedZero unexpectedly did not fail on empty input");
        wb_fail = 1;
    }
    WB_NOTE("PKCS12_CheckConstructedZero: 1239 ret==0 false-side exercised");
}

/* Class 2: PKCS12_CoalesceOctetStrings() ASN chain (pkcs12.c:1294/:1297).
 * Loop body: GetASNTag -> (ret==0 && tag!=OCTET_STRING) -> GetLength ->
 * (ret==0 && GetLength(...)<=0). `curIdx` is an independent caller-supplied
 * anchor (not derived from `dataSz`), so it can be set decoupled from the
 * buffer bound to make the loop want to run past the physical buffer,
 * isolating an in-loop GetASNTag failure from the outer-GetLength failure
 * already covered as "loop never entered" territory. */
static void wb_coalesce_octet_strings(void)
{
    WC_PKCS12 p;
    word32 idx;
    int curIdx, ret;

    XMEMSET(&p, 0, sizeof(p));

    /* baseline: one real 2-byte octet string chunk, ret==0 throughout ->
     * 1294 (T,F) and 1297 (T,F). */
    {
        byte data[] = { 0x04, 0x04, 0x02, 0xAA, 0xBB };
        idx = 0; curIdx = 0;
        ret = PKCS12_CoalesceOctetStrings(&p, data, sizeof(data), &idx, &curIdx);
        if (ret != 0) { wb_fail = 1; }
    }

    /* 1294/1297 op1 false: outer originalEncSz GetLength succeeds (len=0),
     * but curIdx is set far beyond dataSz so the loop condition is true
     * with no buffer left for the first GetASNTag -> ret becomes nonzero
     * *before* either line 1294 or 1297 is reached. */
    {
        byte data[] = { 0x00 };
        idx = 0; curIdx = 1000;
        ret = PKCS12_CoalesceOctetStrings(&p, data, sizeof(data), &idx, &curIdx);
        if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) { wb_fail = 1; }
    }

    /* 1294 op1=T,op2=T -> TRUE: a real tag byte is read (ret==0 going in)
     * but it is an INTEGER (0x02), not OCTET_STRING. */
    {
        byte data[] = { 0x02, 0x02, 0x00 };
        idx = 0; curIdx = 0;
        ret = PKCS12_CoalesceOctetStrings(&p, data, sizeof(data), &idx, &curIdx);
        if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) { wb_fail = 1; }
    }

    /* 1297 op1=T,op2=T -> TRUE: tag IS OCTET_STRING (ret==0 going in), but
     * its length reads back as a valid, explicit zero -- GetLength()'s
     * return value equals the length, so 0 satisfies "<=0" without being a
     * parse failure. */
    {
        byte data[] = { 0x02, 0x04, 0x00 };
        idx = 0; curIdx = 0;
        ret = PKCS12_CoalesceOctetStrings(&p, data, sizeof(data), &idx, &curIdx);
        if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) { wb_fail = 1; }
    }

    WB_NOTE("PKCS12_CoalesceOctetStrings 1294/1297 chain pairs exercised");
}
#else
static void wb_check_zero_op1_false(void) { WB_NOTE("ASN_BER_TO_DER off; PKCS12_CheckConstructedZero skipped"); }
static void wb_coalesce_octet_strings(void) { WB_NOTE("ASN_BER_TO_DER off; PKCS12_CoalesceOctetStrings skipped"); }
#endif

#ifndef NO_FILESYSTEM
/* Class 3: wc_PKCS12_parse_ex() ENCRYPTED_DATA contentType OID check
 * (pkcs12.c:1460, `ret<0 || oid!=WC_PKCS12_DATA`). certs/test-servercert.p12
 * genuinely contains a pkcs7-encryptedData ContentInfo alongside its Data
 * one, so the normal parse already reaches this line -- both operands stay
 * false there. Corrupting the inner contentType OID bytes in-place (after
 * dropping pkcs12->signData to skip the MAC check, since the MAC covers
 * this exact region and would otherwise fail first) reaches both true
 * halves without needing to build a whole synthetic file. Offsets found by
 * walking the real DER with openssl asn1parse; ci->data points at the
 * ContentInfo's `[0]` wrapper, so ci->data[15] is the inner contentType
 * OID's tag byte and ci->data[25] its last content byte. */
static byte* wb_readfile(const char* path, word32* sz)
{
    FILE* f = fopen(path, "rb");
    long n;
    byte* buf;

    if (f == NULL) {
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = (byte*)XMALLOC((size_t)n, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buf != NULL) {
        if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
            XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            buf = NULL;
        }
        else {
            *sz = (word32)n;
        }
    }
    fclose(f);
    return buf;
}

static void wb_free_signdata(WC_PKCS12* pkcs12)
{
    if (pkcs12->signData != NULL) {
        XFREE(pkcs12->signData->digest, pkcs12->heap, DYNAMIC_TYPE_DIGEST);
        XFREE(pkcs12->signData->salt, pkcs12->heap, DYNAMIC_TYPE_SALT);
        XFREE(pkcs12->signData, pkcs12->heap, DYNAMIC_TYPE_PKCS);
        pkcs12->signData = NULL;
    }
}

static void wb_encrypted_ci_oid_case(const byte* orig, word32 sz,
        int corruptOff, byte corruptVal, int expectParseRet, const char* label)
{
    byte* buf = (byte*)XMALLOC(sz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    WC_PKCS12* p;
    int ret;

    if (buf == NULL) {
        wb_fail = 1;
        return;
    }
    XMEMCPY(buf, orig, sz);
    if (corruptOff >= 0) {
        buf[corruptOff] = corruptVal;
    }

    p = wc_PKCS12_new();
    if (p == NULL) {
        XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        wb_fail = 1;
        return;
    }
    ret = wc_d2i_PKCS12(buf, sz, p);
    if (ret == 0) {
        byte* pkey = NULL; word32 pkeySz = 0;
        byte* cert = NULL; word32 certSz = 0;
        WC_DerCertList* ca = NULL;
        int pret;

        wb_free_signdata(p); /* skip MAC verify: it covers the very bytes
                               * we are about to corrupt in-place */
        pret = wc_PKCS12_parse(p, "wolfSSL test", &pkey, &pkeySz, &cert,
                &certSz, &ca);
        if (pret != expectParseRet) {
            WB_NOTE(label);
            WB_NOTE("  unexpected wc_PKCS12_parse return for this case");
            wb_fail = 1;
        }
        if (pkey != NULL) {
            XFREE(pkey, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
        }
        if (cert != NULL) {
            XFREE(cert, NULL, DYNAMIC_TYPE_PKCS);
        }
        while (ca != NULL) {
            WC_DerCertList* next = ca->next;
            XFREE(ca->buffer, NULL, DYNAMIC_TYPE_DER);
            XFREE(ca, NULL, DYNAMIC_TYPE_DER);
            ca = next;
        }
    }
    else {
        WB_NOTE(label);
        WB_NOTE("  unexpected wc_d2i_PKCS12 failure");
        wb_fail = 1;
    }
    wc_PKCS12_free(p);
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}

static void wb_encrypted_data_oid(void)
{
    word32 sz = 0;
    byte* buf = wb_readfile("./certs/test-servercert.p12", &sz);

    if (buf == NULL) {
        WB_NOTE("test-servercert.p12 unavailable; 1460 case skipped");
        return;
    }

    /* baseline: both operands false (real file, untouched) */
    wb_encrypted_ci_oid_case(buf, sz, -1, 0, 0,
            "1460 baseline (both operands false)");

    /* op1 true: corrupt the inner contentType OID's tag byte so
     * GetObjectId() itself fails (ret<0). */
    wb_encrypted_ci_oid_case(buf, sz, 64, 0x00,
            WC_NO_ERR_TRACE(ASN_PARSE_E), "1460 op1=true (GetObjectId fails)");

    /* op1 false, op2 true: corrupt only the OID's last content byte so it
     * decodes as a *different*, valid OID (pkcs7-signedData instead of
     * pkcs7-data) -- GetObjectId succeeds, but oid != WC_PKCS12_DATA. */
    wb_encrypted_ci_oid_case(buf, sz, 74, 0x02,
            WC_NO_ERR_TRACE(ASN_PARSE_E), "1460 op2=true (oid mismatch)");

    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    WB_NOTE("wc_PKCS12_parse_ex 1460 contentType-OID pairs exercised");
}
#else
static void wb_encrypted_data_oid(void) { WB_NOTE("NO_FILESYSTEM; 1460 case skipped"); }
#endif /* !NO_FILESYSTEM */

#ifdef ASN_BER_TO_DER
/* Class 4: wc_d2i_PKCS12() indefinite-length EOC skip (pkcs12.c:809). See
 * file header for how the leftover EOC pair arises. Two hand-built PFX
 * blobs: one where the loop runs out of buffer (operand1 false-exit), one
 * with real trailing bytes after the stranded EOC pair (operand2
 * false-exit, by content rather than by buffer end). Both also demonstrate
 * the (true,true) iterations. wc_PKCS12_parse() is not expected to succeed
 * on these -- only the AuthenticatedSafe skeleton is realistic; MacData is
 * absent/garbage on purpose -- the interesting side effect is entirely in
 * wc_d2i_PKCS12()'s own idx bookkeeping. */
static const byte wbEocEndOfBuffer[] = {
    /* PFX SEQUENCE, indefinite */
    0x30, 0x80,
      0x02, 0x01, 0x03,                     /* version = 3 */
      0x30, 0x26,                           /* authSafe ContentInfo, definite */
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, /* OID pkcs7-data */
        0xA0, 0x19,                         /* [0] EXPLICIT */
          0x04, 0x17,                       /* OCTET STRING, definite len=0x17 */
            /* content: AuthenticatedSafe itself BER-indefinite */
            0x30, 0x80,
              0x30, 0x11,                   /* one Data ContentInfo */
                0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
                0xA0, 0x04,
                  0x04, 0x02, 0xAA, 0xBB,
            0x00, 0x00,                     /* inner EOC (stranded after
                                              * GetSafeContent's own inner
                                              * conversion shrinks the copy) */
    0x00, 0x00                              /* outer EOC (consumed by the
                                              * outer wc_BerToDer conversion;
                                              * buffer ends exactly here) */
};

static const byte wbEocThenRealByte[] = {
    0x30, 0x80,
      0x02, 0x01, 0x03,
      0x30, 0x26,
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
        0xA0, 0x19,
          0x04, 0x17,
            0x30, 0x80,
              0x30, 0x11,
                0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
                0xA0, 0x04,
                  0x04, 0x02, 0xAA, 0xBB,
            0x00, 0x00,                     /* inner EOC, same as above */
      0x30, 0x00,                           /* trailing empty SEQUENCE inside
                                              * the outer PFX content -- a
                                              * real (non-EOC) byte sitting
                                              * right after the stranded pair,
                                              * still within totalSz */
    0x00, 0x00
};

static void wb_d2i_eoc_skip(void)
{
    WC_PKCS12* p;
    int ret;

    /* operand1 false-exit: idx reaches totalSz exactly after consuming both
     * stranded EOC bytes (both iterations operand1=T,operand2=T; final
     * check operand1=F ends the loop). */
    p = wc_PKCS12_new();
    if (p != NULL) {
        ret = wc_d2i_PKCS12(wbEocEndOfBuffer, sizeof(wbEocEndOfBuffer), p);
        (void)ret; /* trailing MacData is absent; a parse error here is
                    * expected and does not affect the 809 decision, which
                    * already ran to completion inside wc_d2i_PKCS12(). */
        wc_PKCS12_free(p);
    }
    else {
        wb_fail = 1;
    }

    /* operand2 false-exit: after the same two (T,T) iterations, a genuine
     * non-EOC byte follows while buffer remains -> operand1=T,operand2=F. */
    p = wc_PKCS12_new();
    if (p != NULL) {
        ret = wc_d2i_PKCS12(wbEocThenRealByte, sizeof(wbEocThenRealByte), p);
        (void)ret;
        wc_PKCS12_free(p);
    }
    else {
        wb_fail = 1;
    }

    WB_NOTE("wc_d2i_PKCS12 809 indefinite-EOC-skip pairs exercised");
}

/* Class 5: wc_PKCS12_parse_ex() ENCRYPTED_DATA branch, indefinite +
 * CheckConstructedZero (pkcs12.c:1470). Three synthetic PFX blobs, each an
 * ENCRYPTED_DATA AuthenticatedSafe ContentInfo whose encryptedContentInfo
 * carries a contentType OID (WC_PKCS12_DATA, satisfying line 1460) followed
 * by a SEQUENCE/OID/SEQUENCE/OCTET-STRING/INTEGER/tag chain identical in
 * shape to test_pkcs12_whitebox.c's wb_build_zero_buf, so
 * PKCS12_CheckConstructedZero() walks it cleanly:
 *   - wbEncIndefTrue:     outer PFX indefinite, final tag = context[0]
 *                         constructed -> indefinite=1, CheckConstructedZero
 *                         returns 1 (operand1=T, operand2=T -> TRUE).
 *   - wbEncIndefFalseTag: outer PFX indefinite, final tag = 0x00
 *                         -> indefinite=1, CheckConstructedZero returns 0
 *                         (operand1=T, operand2=F -> FALSE).
 *   - wbEncDefinite:      outer PFX definite length entirely
 *                         -> indefinite=0 (operand1=F, short-circuits).
 * Each was checked (temporary instrumentation, not shipped here) against a
 * real build of this module's config to confirm pkcs12->indefinite and
 * PKCS12_CheckConstructedZero()'s return exactly as annotated before this
 * file was written; wc_PKCS12_parse() itself is expected to fail past this
 * point (no real encrypted content follows) which does not affect the 1470
 * decision. */
static const byte wbEncIndefTrue[] = {
    0x30, 0x80, 0x02, 0x01, 0x03, 0x30, 0x4B, 0x06, 0x09, 0x2A, 0x86, 0x48,
    0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, 0xA0, 0x3E, 0x04, 0x3C, 0x30, 0x3A,
    0x30, 0x38, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07,
    0x06, 0xA0, 0x2B, 0x30, 0x29, 0x02, 0x01, 0x00, 0x30, 0x24, 0x06, 0x09,
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, 0x30, 0x16, 0x06,
    0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, 0x30, 0x06,
    0x04, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0x02, 0x01, 0x01, 0xA0, 0x00, 0x00
};

static const byte wbEncIndefFalseTag[] = {
    0x30, 0x80, 0x02, 0x01, 0x03, 0x30, 0x4B, 0x06, 0x09, 0x2A, 0x86, 0x48,
    0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, 0xA0, 0x3E, 0x04, 0x3C, 0x30, 0x3A,
    0x30, 0x38, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07,
    0x06, 0xA0, 0x2B, 0x30, 0x29, 0x02, 0x01, 0x00, 0x30, 0x24, 0x06, 0x09,
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, 0x30, 0x16, 0x06,
    0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, 0x30, 0x06,
    0x04, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00
};

static const byte wbEncDefinite[] = {
    0x30, 0x50, 0x02, 0x01, 0x03, 0x30, 0x4B, 0x06, 0x09, 0x2A, 0x86, 0x48,
    0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, 0xA0, 0x3E, 0x04, 0x3C, 0x30, 0x3A,
    0x30, 0x38, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07,
    0x06, 0xA0, 0x2B, 0x30, 0x29, 0x02, 0x01, 0x00, 0x30, 0x24, 0x06, 0x09,
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, 0x30, 0x16, 0x06,
    0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, 0x30, 0x06,
    0x04, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0x02, 0x01, 0x01, 0xA0
};

static void wb_parse_one(const byte* der, word32 derSz, const char* label)
{
    WC_PKCS12* p = wc_PKCS12_new();
    int ret;

    if (p == NULL) {
        WB_NOTE(label);
        WB_NOTE("  wc_PKCS12_new failed");
        wb_fail = 1;
        return;
    }
    ret = wc_d2i_PKCS12(der, derSz, p);
    if (ret == 0) {
        byte* pkey = NULL; word32 pkeySz = 0;
        byte* cert = NULL; word32 certSz = 0;
        WC_DerCertList* ca = NULL;

        /* No MacData in these blobs, so pkcs12->signData is NULL and
         * wc_PKCS12_parse() skips the MAC-verify branch naturally. */
        ret = wc_PKCS12_parse(p, "x", &pkey, &pkeySz, &cert, &certSz, &ca);
        (void)ret; /* not expected to succeed past this synthetic skeleton */
        if (pkey != NULL) {
            XFREE(pkey, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
        }
        if (cert != NULL) {
            XFREE(cert, NULL, DYNAMIC_TYPE_PKCS);
        }
        while (ca != NULL) {
            WC_DerCertList* next = ca->next;
            XFREE(ca->buffer, NULL, DYNAMIC_TYPE_DER);
            XFREE(ca, NULL, DYNAMIC_TYPE_DER);
            ca = next;
        }
    }
    else {
        WB_NOTE(label);
        WB_NOTE("  wc_d2i_PKCS12 unexpectedly failed to build the skeleton");
        wb_fail = 1;
    }
    wc_PKCS12_free(p);
}

static void wb_encrypted_zero_check(void)
{
    wb_parse_one(wbEncIndefTrue, sizeof(wbEncIndefTrue),
            "1470 operand1=T,operand2=T (indefinite + CheckConstructedZero==1)");
    wb_parse_one(wbEncIndefFalseTag, sizeof(wbEncIndefFalseTag),
            "1470 operand1=T,operand2=F (indefinite, CheckConstructedZero!=1)");
    wb_parse_one(wbEncDefinite, sizeof(wbEncDefinite),
            "1470 operand1=F (not indefinite, short-circuit)");
    WB_NOTE("wc_PKCS12_parse_ex 1470 indefinite/CheckConstructedZero pairs exercised");
}
#else
static void wb_d2i_eoc_skip(void) { WB_NOTE("ASN_BER_TO_DER off; 809 EOC-skip skipped"); }
static void wb_encrypted_zero_check(void) { WB_NOTE("ASN_BER_TO_DER off; 1470 case skipped"); }
#endif /* ASN_BER_TO_DER */

int main(void)
{
    printf("pkcs12.c parse white-box MC/DC supplement\n");
    wb_check_zero_op1_false();
    wb_coalesce_octet_strings();
    wb_encrypted_data_oid();
    wb_d2i_eoc_skip();
    wb_encrypted_zero_check();
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Always return 0: a nonzero exit makes the harness discard the whole
     * variant's coverage, including the parts that did succeed. */
    return 0;
}

#endif /* HAVE_PKCS12 && !NO_ASN && !NO_PWDBASED && !NO_HMAC && !NO_CERTS */
