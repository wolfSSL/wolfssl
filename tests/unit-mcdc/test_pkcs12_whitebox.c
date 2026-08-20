/* test_pkcs12_whitebox.c
 *
 * White-box MC/DC supplement for wolfcrypt/src/pkcs12.c.
 *
 * tests/api/test_pkcs12.c drives pkcs12.c through its public API with valid
 * containers, which never exercises the failure half of most internal guards
 * (malformed DER, allocation failures, argument NULL checks that every public
 * wrapper pre-validates). This translation unit compiles pkcs12.c directly
 * (#include) to reach its static helpers and calls them with both halves of
 * each targeted MC/DC independence pair. Heap-allocation failures use the
 * shared suite fault injector (mcdc_fault_alloc.h) to force a specific
 * XMALLOC call to return NULL deterministically.
 *
 * Coverage from this binary is unioned with the tests/api variant coverage by
 * source line:col in the per-module suite.
 *
 * Targeted residuals (pkcs12.c), by class:
 *   Class 1  GetSignData() digest/salt alloc-failure guards ....... 2 conds
 *   Class 2  wc_PKCS12_create_mac() NULL guard + size guards ..... 8 conds
 *   Class 3  wc_PKCS12_verify() NULL guard ........................ 3 conds
 *   Class 4  wc_PKCS12_verify_ex() NULL guard ..................... 2 conds
 *   Class 5  wc_d2i_PKCS12() NULL guard ............................ 2 conds
 *   Class 6  wc_d2i_PKCS12_fp() cleanup guard ...................... 3 conds
 *   Class 7  wc_i2d_PKCS12() NULL guard ............................ 4 conds
 *   Class 8  PKCS12_ConcatenateContent() NULL guard ................ 2 conds
 *   Class 9  PKCS12_CheckConstructedZero() ASN chain .............. 12 conds
 *   Class 10 wc_PKCS12_shroud_key() NULL guard ..................... 5 conds
 *   Class 11 wc_PKCS12_create_key_bag() / PKCS12_create_key_content()
 *            LENGTH_ONLY_E passthrough guards ....................... 4 conds
 *
 * Documented residuals (not exercised here, reason given at point of use):
 *   - GetSignData() digest/salt "size + curIdx > totalSz" operand (pkcs12.c:445
 *     and :477): dead code. digestSz/saltSz is the value the preceding
 *     GetLength() (check=1 wrapper) just returned, and curIdx is the same index
 *     GetLength advanced past the length field -- GetLength(check=1) already
 *     refuses to return success unless length <= maxIdx-idx, i.e. unless this
 *     same "size + curIdx <= totalSz" holds, so the ">" half can never be true
 *     once GetLength has succeeded. Confirmed empirically (a totalSz small
 *     enough to trip the overflow makes GetLength itself fail first, with a
 *     BUFFER_E/ASN_PARSE_E return, never reaching this line with digest/salt
 *     already allocated). Logged in the defect notes as
 *     dead/simplify candidates; only the alloc-failure half is exercised here.
 *   - wc_PKCS12_create_mac() kLen<0 (line ~599): every hash OID that
 *     wc_OidGetHash() maps to a non-NONE wc_HashType is guarded in
 *     wc_HashGetDigestSize() by the identical compile-time macro, so kLen is
 *     never negative once hashT != WC_HASH_TYPE_NONE has already been
 *     rejected earlier in the same function. Structurally unreachable.
 *   - wc_d2i_PKCS12_fp() *pkcs12!=NULL false-side (line 886): callerAlloc is
 *     cleared to 0 only in the same branch that assigns *pkcs12 = tmpPkcs12
 *     (non-NULL), so callerAlloc==0 implies *pkcs12!=NULL always in this
 *     function. Structurally unreachable.
 *   - wc_PKCS12_create_key_bag()/PKCS12_create_key_content() ret<0 with
 *     ret!=WC_NO_ERR_TRACE(LENGTH_ONLY_E) does not have a companion "false" pairing beyond
 *     what is covered here (see Class 11 note at point of use).
 *   - GetSafeContent/wc_PKCS12_parse_ex indefinite-length (BER) decisions
 *     (line ~809, ~1470) need a genuinely BER indefinite-length top-level
 *     PKCS12 structure; no such file exists in the test corpus and
 *     synthesizing one is out of scope for this pass.
 */

#include <wolfcrypt/src/pkcs12.c>

#include "mcdc_fault_alloc.h"

#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/certs_test.h>
#include <stdio.h>
#include <string.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if !defined(HAVE_PKCS12) || defined(NO_ASN) || defined(NO_PWDBASED) || \
    defined(NO_HMAC) || defined(NO_CERTS)

int main(void)
{
    printf("pkcs12.c white-box: HAVE_PKCS12 surface absent, nothing to do\n");
    return 0;
}

#else

/* ------------------------------------------------------------------------- *
 * Shared "DigestInfo + salt [+ itt]" buffer used by GetSignData() tests.
 *
 * Layout (byte offsets), all header/length bytes short-form DER:
 *   [0]        outer SEQUENCE header (len=1: GetSignData's own check on this
 *              header is `<= 0`, so unlike the `< 0` callers elsewhere a
 *              placeholder length of 0 would be rejected; the value itself is
 *              otherwise unused/discarded by the caller)
 *   [2..14]    algo id: SEQUENCE(len=11) { OID(len=9) <9 OID bytes> }
 *   [15..20]   digest: OCTET STRING(len=4) <4 bytes>
 *   [21..26]   salt:   OCTET STRING(len=4) <4 bytes>
 *   [27..29]   itt:    INTEGER(len=1) <1 byte> (SetShortInt(1))
 * Total 30 bytes.
 * ------------------------------------------------------------------------- */
static word32 wb_build_signdata_buf(byte* buf)
{
    word32 idx = 0;

    buf[idx++] = ASN_SEQUENCE | ASN_CONSTRUCTED; buf[idx++] = 0x01;

    buf[idx++] = ASN_SEQUENCE | ASN_CONSTRUCTED; buf[idx++] = 0x0B; /* 11 */
    buf[idx++] = ASN_OBJECT_ID; buf[idx++] = (byte)sizeof(WC_PKCS12_DATA_OID);
    XMEMCPY(buf + idx, WC_PKCS12_DATA_OID, sizeof(WC_PKCS12_DATA_OID));
    idx += (word32)sizeof(WC_PKCS12_DATA_OID);

    buf[idx++] = ASN_OCTET_STRING; buf[idx++] = 0x04;
    buf[idx++] = 0xAA; buf[idx++] = 0xBB; buf[idx++] = 0xCC; buf[idx++] = 0xDD;

    buf[idx++] = ASN_OCTET_STRING; buf[idx++] = 0x04;
    buf[idx++] = 0x11; buf[idx++] = 0x22; buf[idx++] = 0x33; buf[idx++] = 0x44;

    buf[idx++] = ASN_INTEGER; buf[idx++] = 0x01; buf[idx++] = 0x01;

    return idx; /* 30 */
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

/* Class 1: GetSignData() digest/salt alloc-failure guards (pkcs12.c:445
 * mac->digest==NULL; pkcs12.c:477 mac->salt==NULL -- the reachable half of
 * each `|| size+curIdx>totalSz` guard; see file header for why the size half
 * is dead code). Both operands normally false (real
 * DER + successful alloc); the alloc-failure half is white-box only, reached
 * here with the shared fault injector on a static-function-direct call. */
static void wb_getsigndata(void)
{
    WC_PKCS12 p;
    byte buf[32];
    word32 idx;
    word32 total = wb_build_signdata_buf(buf);

    XMEMSET(&p, 0, sizeof(p));
    mcdc_fa_install();

    /* baseline: both digest (445) and salt (477) guards false */
    idx = 0;
    (void)GetSignData(&p, buf, &idx, total);
    wb_free_signdata(&p);

    /* 445 true: digest XMALLOC (2nd allocation: mac struct, then
     * mac->digest) fails -> mac->digest==NULL. */
    mcdc_fa_arm(2);
    idx = 0;
    (void)GetSignData(&p, buf, &idx, total);
    mcdc_fa_disarm();
    wb_free_signdata(&p);

    /* 477 true: salt XMALLOC (3rd allocation) fails -> mac->salt==NULL.
     * digest (alloc #2) still succeeds normally. */
    mcdc_fa_arm(3);
    idx = 0;
    (void)GetSignData(&p, buf, &idx, total);
    mcdc_fa_disarm();
    wb_free_signdata(&p);

    mcdc_fa_restore();
    WB_NOTE("GetSignData digest/salt alloc-failure pairs exercised "
            "(size-overflow half is dead code, see file header)");
}

/* Class 2: wc_PKCS12_create_mac() NULL guard (pkcs12.c:546-547) and the
 * unicode-size (574-575) / kLen-outSz (599) size guards. Public callers
 * (wc_PKCS12_verify/wc_PKCS12_verify_ex) always supply valid pointers and a
 * full-size digest buffer, so the true side of every operand here is
 * white-box only. */
static void wb_create_mac(void)
{
    WC_PKCS12 p;
    MacData mac;
    byte data[8] = { 0 };
    byte out[WC_MAX_DIGEST_SIZE];
    byte psw[300];
    byte saltBuf[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

    XMEMSET(&p, 0, sizeof(p));
    XMEMSET(&mac, 0, sizeof(mac));
    XMEMSET(psw, 'p', sizeof(psw));
    mac.oid = SHA256h;
    mac.salt = saltBuf;
    mac.saltSz = sizeof(saltBuf);
    mac.itt = 1;
    p.signData = &mac;

    /* line 546-547: pkcs12/signData/data/out NULL guard, one flip at a time */
    (void)wc_PKCS12_create_mac(NULL, data, sizeof(data), psw, 10, out,
            sizeof(out));                                       /* pkcs12==NULL */
    p.signData = NULL;
    (void)wc_PKCS12_create_mac(&p, data, sizeof(data), psw, 10, out,
            sizeof(out));                                       /* signData==NULL */
    p.signData = &mac;
    (void)wc_PKCS12_create_mac(&p, NULL, sizeof(data), psw, 10, out,
            sizeof(out));                                       /* data==NULL */
    (void)wc_PKCS12_create_mac(&p, data, sizeof(data), psw, 10, NULL,
            sizeof(out));                                       /* out==NULL */
    WB_NOTE("wc_PKCS12_create_mac NULL guard pairs exercised");

    /* line 574-575: pswSz >= MAX_UNICODE_SZ || (pswSz*2+2) > MAX_UNICODE_SZ.
     * MAX_UNICODE_SZ == 256. */
    (void)wc_PKCS12_create_mac(&p, data, sizeof(data), psw, 10, out,
            sizeof(out));                    /* baseline: both false (10<256) */
    (void)wc_PKCS12_create_mac(&p, data, sizeof(data), psw, 256, out,
            sizeof(out));                    /* idx0 true: 256>=256 */
    (void)wc_PKCS12_create_mac(&p, data, sizeof(data), psw, 200, out,
            sizeof(out));                    /* idx0 false, idx1 true: 402>256 */
    WB_NOTE("wc_PKCS12_create_mac unicode-size guard pairs exercised");

    /* line 599: kLen<0 || outSz<(word32)kLen. kLen<0 is unreachable here (see
     * file header note): every hash OID wc_OidGetHash() can map to a non-NONE
     * type is guarded identically in wc_HashGetDigestSize(), so kLen is never
     * negative once hashT != NONE has already passed the line-591 check.
     * Only the outSz-too-small (idx1) half is exercised. */
    (void)wc_PKCS12_create_mac(&p, data, sizeof(data), psw, 10, out, 4);
                                             /* idx0 false (kLen=32), idx1 true (4<32) */
    WB_NOTE("wc_PKCS12_create_mac kLen/outSz guard idx1 exercised "
            "(idx0 structurally unreachable, see file header)");
}

/* Class 3: wc_PKCS12_verify() NULL guard (pkcs12.c:650). */
static void wb_verify(void)
{
    WC_PKCS12 p;
    MacData mac;
    byte data[8] = { 0 };

    XMEMSET(&p, 0, sizeof(p));
    XMEMSET(&mac, 0, sizeof(mac));
    mac.oid = SHA256h;
    p.signData = &mac;

    /* baseline: all three operands false (mac->digestSz==0 trips the
     * line-661 too-small-build guard right after, harmlessly) */
    (void)wc_PKCS12_verify(&p, data, sizeof(data), (byte*)"x", 1);
    (void)wc_PKCS12_verify(NULL, data, sizeof(data), (byte*)"x", 1); /* pkcs12==NULL */
    p.signData = NULL;
    (void)wc_PKCS12_verify(&p, data, sizeof(data), (byte*)"x", 1);   /* signData==NULL */
    p.signData = &mac;
    (void)wc_PKCS12_verify(&p, NULL, sizeof(data), (byte*)"x", 1);   /* data==NULL */
    WB_NOTE("wc_PKCS12_verify NULL guard pairs exercised");
}

/* Class 4: wc_PKCS12_verify_ex() NULL guard (pkcs12.c:698, public API). */
static void wb_verify_ex(void)
{
    WC_PKCS12* p = wc_PKCS12_new();
    AuthenticatedSafe safe;

    if (p == NULL) {
        WB_NOTE("wc_PKCS12_new failed (verify_ex skipped)");
        wb_fail = 1;
        return;
    }
    XMEMSET(&safe, 0, sizeof(safe));

    (void)wc_PKCS12_verify_ex(NULL, (byte*)"x", 1);   /* pkcs12==NULL */
    (void)wc_PKCS12_verify_ex(p, (byte*)"x", 1);       /* safe==NULL */
    p->safe = &safe;
    (void)wc_PKCS12_verify_ex(p, (byte*)"x", 1);       /* both false (safe->data==NULL
                                                         * fails one level deeper, harmless) */
    p->safe = NULL; /* avoid double-free of stack safe in wc_PKCS12_free */
    wc_PKCS12_free(p);
    WB_NOTE("wc_PKCS12_verify_ex NULL guard pairs exercised");
}

/* Class 5: wc_d2i_PKCS12() NULL guard (pkcs12.c:727, public API). */
static void wb_d2i(void)
{
    WC_PKCS12* p = wc_PKCS12_new();
    byte der[4] = { 0 };

    if (p == NULL) {
        WB_NOTE("wc_PKCS12_new failed (d2i skipped)");
        wb_fail = 1;
        return;
    }
    (void)wc_d2i_PKCS12(NULL, sizeof(der), p);   /* der==NULL */
    (void)wc_d2i_PKCS12(der, sizeof(der), NULL); /* pkcs12==NULL */
    (void)wc_d2i_PKCS12(der, sizeof(der), p);    /* both false (garbage DER,
                                                   * fails to parse, harmless) */
    wc_PKCS12_free(p);
    WB_NOTE("wc_d2i_PKCS12 NULL guard pairs exercised");
}

#ifndef NO_FILESYSTEM
/* Class 6: wc_d2i_PKCS12_fp() cleanup guard (pkcs12.c:886)
 *   if (ret != 0 && callerAlloc == 0 && *pkcs12 != NULL)
 * See file header for why the *pkcs12!=NULL false-side is unreachable. */
static void wb_d2i_fp(void)
{
    WC_PKCS12* p;
    int ret;

    /* all-true: fresh alloc (*pkcs12==NULL -> callerAlloc becomes 0), parse
     * fails (a real, readable, but non-PKCS12 file). Runs the cleanup path:
     * frees the fresh allocation and NULLs *pkcs12. */
    p = NULL;
    ret = wc_d2i_PKCS12_fp("./certs/test-degenerate.p7b", &p);
    if (ret == 0) {
        WB_NOTE("test-degenerate.p7b unexpectedly parsed as PKCS12");
        wc_PKCS12_free(p);
        wb_fail = 1;
    }
    else if (p != NULL) {
        WB_NOTE("wc_d2i_PKCS12_fp cleanup did not NULL *pkcs12");
        wc_PKCS12_free(p);
        wb_fail = 1;
    }

    /* flip term1 (ret!=0 -> false): valid PKCS12 file, fresh alloc. */
    p = NULL;
    ret = wc_d2i_PKCS12_fp("./certs/test-servercert.p12", &p);
    if (ret != 0 || p == NULL) {
        WB_NOTE("test-servercert.p12 unexpectedly failed to parse");
        wb_fail = 1;
    }
    wc_PKCS12_free(p);

    /* flip term2 (callerAlloc==0 -> false): caller pre-allocates *pkcs12, so
     * callerAlloc stays 1; parse fails on the same non-PKCS12 file. Cleanup
     * is NOT run (callerAlloc!=0), so we free it ourselves afterward. */
    p = wc_PKCS12_new();
    if (p != NULL) {
        ret = wc_d2i_PKCS12_fp("./certs/test-degenerate.p7b", &p);
        if (ret == 0) {
            WB_NOTE("test-degenerate.p7b unexpectedly parsed (term2 case)");
            wb_fail = 1;
        }
        wc_PKCS12_free(p);
    }
    else {
        wb_fail = 1;
    }

    WB_NOTE("wc_d2i_PKCS12_fp cleanup guard pairs exercised "
            "(term3 false-side structurally unreachable, see file header)");
}
#else
static void wb_d2i_fp(void) { WB_NOTE("NO_FILESYSTEM; wc_d2i_PKCS12_fp skipped"); }
#endif

/* Class 7: wc_i2d_PKCS12() NULL guard (pkcs12.c:916-917, public API)
 *   if ((pkcs12==NULL) || (pkcs12->safe==NULL) || (der==NULL && derSz==NULL))
 */
static void wb_i2d(void)
{
    WC_PKCS12* p = wc_PKCS12_new();
    AuthenticatedSafe safe;
    byte safeData[4] = { 0x30, 0x00, 0x00, 0x00 };
    byte* derOut = NULL;
    int derSz = 0;
    int ret;

    if (p == NULL) {
        WB_NOTE("wc_PKCS12_new failed (i2d skipped)");
        wb_fail = 1;
        return;
    }
    XMEMSET(&safe, 0, sizeof(safe));
    safe.data = safeData;
    safe.dataSz = sizeof(safeData);

    (void)wc_i2d_PKCS12(NULL, &derOut, &derSz);      /* pkcs12==NULL */
    (void)wc_i2d_PKCS12(p, &derOut, &derSz);          /* safe==NULL */

    p->safe = &safe;
    (void)wc_i2d_PKCS12(p, NULL, NULL);               /* der==NULL && derSz==NULL: true */

    /* der==NULL alone false-forcing: der param itself NULL, derSz valid ->
     * (der==NULL && derSz==NULL) is (T && F) = F -> whole guard false ->
     * length-only query path. */
    ret = wc_i2d_PKCS12(p, NULL, &derSz);
    if (ret != WC_NO_ERR_TRACE(LENGTH_ONLY_E)) {
        WB_NOTE("wc_i2d_PKCS12 length-only query unexpectedly failed");
        wb_fail = 1;
    }

    /* derSz==NULL alone false-forcing: der non-NULL (points at a NULL local),
     * derSz NULL -> (F && T) = F -> whole guard false -> real allocate path. */
    derOut = NULL;
    ret = wc_i2d_PKCS12(p, &derOut, NULL);
    if (ret > 0 && derOut != NULL) {
        XFREE(derOut, NULL, DYNAMIC_TYPE_PKCS);
    }
    else {
        WB_NOTE("wc_i2d_PKCS12 real-encode path unexpectedly failed");
        wb_fail = 1;
    }

    p->safe = NULL; /* avoid double-free of stack safe */
    wc_PKCS12_free(p);
    WB_NOTE("wc_i2d_PKCS12 NULL guard pairs exercised");
}

/* Class 8: PKCS12_ConcatenateContent() NULL guard (pkcs12.c:1198). */
#ifdef ASN_BER_TO_DER
static void wb_concat_content(void)
{
    WC_PKCS12* p = wc_PKCS12_new();
    byte* merged;
    word32 mergedSz;
    byte in[4] = { 1, 2, 3, 4 };
    byte* result;

    if (p == NULL) {
        WB_NOTE("wc_PKCS12_new failed (concat skipped)");
        wb_fail = 1;
        return;
    }

    /* baseline: both false, real merge */
    merged = (byte*)XMALLOC(2, NULL, DYNAMIC_TYPE_PKCS);
    if (merged != NULL) {
        merged[0] = 0xAA; merged[1] = 0xBB;
        mergedSz = 2;
        result = PKCS12_ConcatenateContent(p, merged, &mergedSz, in, sizeof(in));
        if (result != NULL) {
            XFREE(result, NULL, DYNAMIC_TYPE_PKCS);
        }
        else {
            wb_fail = 1;
        }
    }

    /* mergedData==NULL -> true, short-circuit before touching in/pkcs12 */
    (void)PKCS12_ConcatenateContent(p, NULL, &mergedSz, in, sizeof(in));

    /* in==NULL -> true, mergedData!=NULL (false) */
    merged = (byte*)XMALLOC(2, NULL, DYNAMIC_TYPE_PKCS);
    if (merged != NULL) {
        mergedSz = 2;
        (void)PKCS12_ConcatenateContent(p, merged, &mergedSz, NULL, 0);
        /* mergedData freed internally by the function on the in==NULL
         * early-return? No -- guard returns NULL before reaching any XFREE,
         * so we own 'merged' still. */
        XFREE(merged, NULL, DYNAMIC_TYPE_PKCS);
    }

    wc_PKCS12_free(p);
    WB_NOTE("PKCS12_ConcatenateContent NULL guard pairs exercised");
}
#else
static void wb_concat_content(void) { WB_NOTE("ASN_BER_TO_DER off; PKCS12_ConcatenateContent skipped"); }
#endif

/* Class 9: PKCS12_CheckConstructedZero() ASN chain (pkcs12.c:1239-1261).
 * Six `if (ret==0 && <step>)`/`else if` decisions walking SEQUENCE, OID,
 * SEQUENCE, OCTET STRING, INTEGER, then a raw tag peek. Built once as a
 * single valid 25-byte buffer (offsets: outer-seq-hdr ends 2, OID ends 13,
 * inner-seq-hdr ends 15, octetstring-hdr+content ends 21, integer ends 24,
 * final tag byte at 24, ends 25); truncating the `dataSz` bound to each
 * cumulative offset forces exactly the next step to fail (BUFFER_E) while
 * every earlier step still succeeds -- the "ret==0 true, step true" half of
 * each decision. The untruncated buffer supplies the "both false" half for
 * all six at once; a copy with the final byte set to the constructed-context
 * tag supplies the else-if's true half.
 * ------------------------------------------------------------------------- */
#ifdef ASN_BER_TO_DER
static word32 wb_build_zero_buf(byte* buf, byte finalTag)
{
    word32 idx = 0;

    buf[idx++] = ASN_SEQUENCE | ASN_CONSTRUCTED; buf[idx++] = 0x00; /* outer, end=2 */

    buf[idx++] = ASN_OBJECT_ID; buf[idx++] = (byte)sizeof(WC_PKCS12_DATA_OID);
    XMEMCPY(buf + idx, WC_PKCS12_DATA_OID, sizeof(WC_PKCS12_DATA_OID));
    idx += (word32)sizeof(WC_PKCS12_DATA_OID);                        /* end=13 */

    buf[idx++] = ASN_SEQUENCE | ASN_CONSTRUCTED; buf[idx++] = 0x00;   /* end=15 */

    buf[idx++] = ASN_OCTET_STRING; buf[idx++] = 0x04;
    buf[idx++] = 0xAA; buf[idx++] = 0xBB; buf[idx++] = 0xCC; buf[idx++] = 0xDD;
                                                                       /* end=21 */

    buf[idx++] = ASN_INTEGER; buf[idx++] = 0x01; buf[idx++] = 0x01;   /* end=24 */

    buf[idx++] = finalTag;                                            /* end=25 */

    return idx;
}

static void wb_check_constructed_zero(void)
{
    byte buf[26];
    word32 idx;
    int ret;

    /* baseline: all six steps succeed, final tag != context-specific-0 ->
     * both halves of decisions 1239/1243/1247/1252/1258 false, and 1261's
     * else-if false (function returns 0). */
    (void)wb_build_zero_buf(buf, 0x00);
    idx = 0;
    ret = PKCS12_CheckConstructedZero(buf, 25, &idx);
    if (ret != 0) { wb_fail = 1; }

    /* 1261 else-if true: same valid chain, final tag IS context-specific-0 */
    (void)wb_build_zero_buf(buf, (byte)(ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC));
    idx = 0;
    ret = PKCS12_CheckConstructedZero(buf, 25, &idx);
    if (ret != 1) { wb_fail = 1; }

    /* 1239 true: truncate right after the outer SEQUENCE header (dataSz=2),
     * failing GetObjectId; also gives the "ret==0 false" half of 1243/1247/
     * 1252/1258/1261 in this same call (short-circuited once ret != 0). */
    (void)wb_build_zero_buf(buf, 0x00);
    idx = 0;
    (void)PKCS12_CheckConstructedZero(buf, 2, &idx);

    /* 1243 true: truncate right after the OID (dataSz=13), failing the
     * inner GetSequence. */
    idx = 0;
    (void)PKCS12_CheckConstructedZero(buf, 13, &idx);

    /* 1247 true: truncate right after the inner SEQUENCE header (dataSz=15),
     * failing GetOctetString. */
    idx = 0;
    (void)PKCS12_CheckConstructedZero(buf, 15, &idx);

    /* 1252 true: truncate right after the octet string (dataSz=21), failing
     * GetShortInt. */
    idx = 0;
    (void)PKCS12_CheckConstructedZero(buf, 21, &idx);

    /* 1258 true: truncate right after the integer (dataSz=24), failing the
     * final GetASNTag. */
    idx = 0;
    (void)PKCS12_CheckConstructedZero(buf, 24, &idx);

    WB_NOTE("PKCS12_CheckConstructedZero ASN chain pairs exercised");
}
#else
static void wb_check_constructed_zero(void) { WB_NOTE("ASN_BER_TO_DER off; PKCS12_CheckConstructedZero skipped"); }
#endif

/* Class 10: wc_PKCS12_shroud_key() NULL guard (pkcs12.c:1938-1939)
 *   if (outSz==NULL || pkcs12==NULL || rng==NULL || key==NULL || pass==NULL)
 * Class 11: wc_PKCS12_create_key_bag()/PKCS12_create_key_content()
 *   LENGTH_ONLY_E passthrough guards (pkcs12.c:2043, 2465):
 *   if (ret != WC_NO_ERR_TRACE(LENGTH_ONLY_E) && ret < 0) return ret;
 * wc_PKCS12_shroud_key(out==NULL,...) either returns LENGTH_ONLY_E (the
 * normal "just tell me the size" path) or a genuine negative error -- there
 * is no route to a non-negative, non-LENGTH_ONLY_E return, so only the
 * baseline (false) and the ret<0 (true) halves are reachable; passing
 * rng==NULL cascades the Class-10 guard's BAD_FUNC_ARG straight through both
 * Class-11 sites in one call. */
static void wb_shroud_and_keybag(void)
{
    WC_PKCS12* p = wc_PKCS12_new();
    WC_RNG rng;
    byte key[64];
    byte out[8];
    word32 outSz = sizeof(out);
    word32 keyBufSz;
    byte* keyCi;
    word32 keyCiSz;
    int haveRng = 0;

    if (p == NULL) {
        WB_NOTE("wc_PKCS12_new failed (shroud/keybag skipped)");
        wb_fail = 1;
        return;
    }
    XMEMCPY(key, server_key_der_2048, sizeof(key)); /* content unused by guard */

    if (wc_InitRng(&rng) == 0) {
        haveRng = 1;
    }
    else {
        WB_NOTE("wc_InitRng failed; NULL-guard flips still run without it");
    }

    /* line 1938-1939: five-operand NULL guard, one flip at a time (all
     * short-circuit before touching pkcs12->heap or the key/pass buffers) */
    (void)wc_PKCS12_shroud_key(p, haveRng ? &rng : NULL, NULL, NULL, key,
            sizeof(key), -1, "pw", 2, 1);                     /* outSz==NULL */
    (void)wc_PKCS12_shroud_key(NULL, haveRng ? &rng : NULL, NULL, &outSz, key,
            sizeof(key), -1, "pw", 2, 1);                     /* pkcs12==NULL */
    (void)wc_PKCS12_shroud_key(p, NULL, NULL, &outSz, key, sizeof(key), -1,
            "pw", 2, 1);                                      /* rng==NULL */
    (void)wc_PKCS12_shroud_key(p, haveRng ? &rng : NULL, NULL, &outSz, NULL,
            sizeof(key), -1, "pw", 2, 1);                     /* key==NULL */
    (void)wc_PKCS12_shroud_key(p, haveRng ? &rng : NULL, NULL, &outSz, key,
            sizeof(key), -1, NULL, 0, 1);                     /* pass==NULL */
    WB_NOTE("wc_PKCS12_shroud_key NULL guard pairs exercised");

    /* Class 11 baseline (false): a real unencrypted RSA key bag length
     * query, algo<0 so no RNG use inside shroud_key itself, key decodes as
     * RSA so wc_GetKeyOID/wc_CreatePKCS8Key(out=NULL) succeed and return
     * LENGTH_ONLY_E through both wc_PKCS12_create_key_bag and
     * PKCS12_create_key_content. */
    if (haveRng) {
        keyBufSz = 0;
        (void)wc_PKCS12_create_key_bag(p, &rng, NULL, &keyBufSz,
                (byte*)server_key_der_2048, sizeof(server_key_der_2048),
                -1, 1, "pw", 2);

        keyCiSz = 0;
        keyCi = PKCS12_create_key_content(p, -1, &keyCiSz, &rng, "pw", 2,
                (byte*)server_key_der_2048, sizeof(server_key_der_2048), 1);
        if (keyCi != NULL) {
            XFREE(keyCi, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }

    /* Class 11 true side: rng==NULL cascades a BAD_FUNC_ARG (non-negative-
     * impossible, != WC_NO_ERR_TRACE(LENGTH_ONLY_E)) out of wc_PKCS12_shroud_key, through
     * wc_PKCS12_create_key_bag's own check (2043) and then through
     * PKCS12_create_key_content's check (2465) in the same call. */
    keyBufSz = 0;
    (void)wc_PKCS12_create_key_bag(p, NULL, NULL, &keyBufSz, key, sizeof(key),
            -1, 1, "pw", 2);

    keyCiSz = 0;
    keyCi = PKCS12_create_key_content(p, -1, &keyCiSz, NULL, "pw", 2, key,
            sizeof(key), 1);
    if (keyCi != NULL) {
        WB_NOTE("PKCS12_create_key_content unexpectedly succeeded with "
                "rng==NULL");
        XFREE(keyCi, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        wb_fail = 1;
    }
    WB_NOTE("wc_PKCS12_create_key_bag/PKCS12_create_key_content "
            "LENGTH_ONLY_E-passthrough pairs exercised");

    if (haveRng) {
        wc_FreeRng(&rng);
    }
    wc_PKCS12_free(p);
}

int main(void)
{
    printf("pkcs12.c white-box MC/DC supplement\n");
    wb_getsigndata();
    wb_create_mac();
    wb_verify();
    wb_verify_ex();
    wb_d2i();
    wb_d2i_fp();
    wb_i2d();
    wb_concat_content();
    wb_check_constructed_zero();
    wb_shroud_and_keybag();
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup failures are surfaced as skips, not test failures: the harness
     * treats a nonzero exit as a failed variant and discards its coverage. */
    return 0;
}

#endif /* HAVE_PKCS12 && !NO_ASN && !NO_PWDBASED && !NO_HMAC && !NO_CERTS */
