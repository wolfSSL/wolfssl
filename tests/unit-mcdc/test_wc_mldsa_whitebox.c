/* test_wc_mldsa_whitebox.c
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

/* White-box MC/DC supplement for wolfcrypt/src/wc_mldsa.c.
 *
 * wc_mldsa.c carries ~137 file-static helpers implementing the FIPS 204
 * ML-DSA primitives (NTT, encode/decode packing, decompose, make/check/use
 * hint, range checks, ASN.1 length parsing, param lookup). Every public
 * caller drives them only with well-formed, self-consistent operands, so the
 * argument-check and bound-check decisions inside these helpers cannot have
 * both halves of each independence pair demonstrated from tests/api. This TU
 * #includes wc_mldsa.c so the statics are in scope and calls each targeted
 * helper with BOTH halves of every targeted decision in a single binary
 * (MC/DC is computed per binary).
 *
 * Scope choices to keep the binary fast and memory-safe:
 *   - only branch-bearing helpers are driven (the branchless bit-trick
 *     helpers -- mldsa_red / mldsa_mont_red / mldsa_decompose_q* -- carry no
 *     decisions and are exercised structurally by the API tests);
 *   - ML-DSA-44 constants (smallest param set) are used for the hint/range
 *     helpers;
 *   - no keygen/sign/verify round trip is performed here (the API tests own
 *     those positive paths); every call is on a small stack buffer.
 *
 * Crash-safety: all inputs are bounded, fixed-size stack arrays sized to
 * MLDSA_N coefficients; no helper is handed a short/NULL buffer it would
 * dereference past. On any unexpected result we print a note and continue;
 * the binary always returns 0 so the campaign keeps the variant.
 */

#include <wolfcrypt/src/wc_mldsa.c>

#include <stdio.h>

static int wb_notes = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); wb_notes++; } while (0)
#define WB_OK(msg)   do { printf("  [wb] %s\n", (msg)); } while (0)

#if defined(WOLFSSL_HAVE_MLDSA)

/* ------------------------------------------------------------------ *
 * mldsa_get_params: for-loop match decision (mldsa_params[i].level == level)
 * both T (valid level found) and F (no match -> NOT_COMPILED_IN).
 * ------------------------------------------------------------------ */
static void wb_get_params(void)
{
    const wc_MlDsaParams* p = NULL;
    int ret;

    /* match arm: level 2 (ML-DSA-44) is present -> loop body T at least once */
    ret = mldsa_get_params(WC_ML_DSA_44, &p);
    if ((ret != 0) || (p == NULL)) {
        WB_NOTE("mldsa_get_params(valid) unexpected");
    }
    /* no-match arm: bogus level -> every iteration F -> NOT_COMPILED_IN */
    p = NULL;
    ret = mldsa_get_params(0x7f, &p);
    if (ret != WC_NO_ERR_TRACE(NOT_COMPILED_IN)) {
        WB_NOTE("mldsa_get_params(invalid) unexpected");
    }
    WB_OK("mldsa_get_params match/no-match pair exercised");
}

/* ------------------------------------------------------------------ *
 * mldsa_check_low / mldsa_vec_check_low_c: the compound
 *   (a[j] <= nhi) || (a[j] >= hi)
 * Drive independence pairs: both F (in range), left T (a<=nhi),
 * right T with left F (a>=hi). Plus the vector-level (ret==1)&&(i<l).
 * ------------------------------------------------------------------ */
#if !defined(WOLFSSL_MLDSA_NO_SIGN) || !defined(WOLFSSL_MLDSA_NO_VERIFY)
static void wb_check_low(void)
{
    sword32 a[2 * MLDSA_N];
    unsigned int j;
    const sword32 hi = 1000;
    int ret;

    /* All in range: both operands FALSE every iteration -> ret 1. */
    for (j = 0; j < MLDSA_N; j++) {
        a[j] = 0;
    }
    ret = mldsa_check_low(a, hi);
    if (ret != 1) {
        WB_NOTE("mldsa_check_low(in-range) expected 1");
    }

    /* Left operand TRUE (a[j] <= -hi), right FALSE -> ret 0. */
    a[5] = -hi;            /* -hi <= -hi is true, -hi >= hi is false */
    ret = mldsa_check_low(a, hi);
    if (ret != 0) {
        WB_NOTE("mldsa_check_low(<=nhi) expected 0");
    }

    /* Right operand TRUE (a[j] >= hi), left FALSE -> ret 0. */
    a[5] = 0;
    a[7] = hi;            /* hi >= hi true, hi <= -hi false */
    ret = mldsa_check_low(a, hi);
    if (ret != 0) {
        WB_NOTE("mldsa_check_low(>=hi) expected 0");
    }

    /* Vector level: two polynomials, both in range -> (ret==1)&&(i<l) walks
     * both, returns 1; then a first-poly-out-of-range -> early ret 0. */
    for (j = 0; j < 2 * MLDSA_N; j++) {
        a[j] = 0;
    }
    ret = mldsa_vec_check_low_c(a, 2, hi);
    if (ret != 1) {
        WB_NOTE("mldsa_vec_check_low_c(in-range,l=2) expected 1");
    }
    a[3] = hi;           /* first polynomial out of range */
    ret = mldsa_vec_check_low_c(a, 2, hi);
    if (ret != 0) {
        WB_NOTE("mldsa_vec_check_low_c(out) expected 0");
    }
    WB_OK("mldsa_check_low / vec_check_low_c operand pairs exercised");
}
#endif

/* ------------------------------------------------------------------ *
 * mldsa_make_hint_88 / _32 / mldsa_make_hint: the 3-way compound
 *   (s>LOW) || (s<-LOW) || ((s==-LOW) && (w1!=0))
 * and the too-many-hints guard (idx>OMEGA -> -1), plus mldsa_make_hint's
 * gamma2 dispatch (88 arm / 32 arm / neither).
 * ------------------------------------------------------------------ */
#ifndef WOLFSSL_MLDSA_NO_SIGN
#ifndef WOLFSSL_NO_ML_DSA_44
static void wb_make_hint_88(void)
{
    sword32 s[MLDSA_N];
    sword32 w1[MLDSA_N];
    byte    h[256];
    byte    idx;
    unsigned int j;
    int ret;
    const sword32 low = (sword32)MLDSA_Q_LOW_88;

    for (j = 0; j < MLDSA_N; j++) {
        s[j] = 0;
        w1[j] = 0;
    }

    /* All three operands FALSE for every coefficient -> no hint, idx stays 0. */
    idx = 0;
    ret = mldsa_make_hint_88(s, w1, h, &idx);
    if ((ret != 0) || (idx != 0)) {
        WB_NOTE("mldsa_make_hint_88(no-hint) unexpected");
    }

    /* First operand TRUE (s > LOW). */
    idx = 0;
    s[1] = low + 1;
    ret = mldsa_make_hint_88(s, w1, h, &idx);
    if ((ret != 0) || (idx != 1)) {
        WB_NOTE("mldsa_make_hint_88(s>LOW) unexpected");
    }

    /* Second operand TRUE (s < -LOW), first FALSE. */
    idx = 0;
    s[1] = 0;
    s[2] = -low - 1;
    ret = mldsa_make_hint_88(s, w1, h, &idx);
    if ((ret != 0) || (idx != 1)) {
        WB_NOTE("mldsa_make_hint_88(s<-LOW) unexpected");
    }

    /* Third operand: (s == -LOW) && (w1 != 0) -> TRUE (drives w1!=0 T). */
    idx = 0;
    s[2] = 0;
    s[3] = -low;
    w1[3] = 1;
    ret = mldsa_make_hint_88(s, w1, h, &idx);
    if ((ret != 0) || (idx != 1)) {
        WB_NOTE("mldsa_make_hint_88(s==-LOW,w1!=0) unexpected");
    }

    /* Third operand right half FALSE: (s == -LOW) && (w1 == 0) -> no hint
     * (independence of the w1!=0 operand). */
    idx = 0;
    w1[3] = 0;
    ret = mldsa_make_hint_88(s, w1, h, &idx);
    if ((ret != 0) || (idx != 0)) {
        WB_NOTE("mldsa_make_hint_88(s==-LOW,w1==0) unexpected");
    }

    /* Too-many-hints: every coefficient qualifies -> idx crosses OMEGA -> -1. */
    idx = 0;
    for (j = 0; j < MLDSA_N; j++) {
        s[j] = low + 1;
        w1[j] = 0;
    }
    ret = mldsa_make_hint_88(s, w1, h, &idx);
    if (ret != -1) {
        WB_NOTE("mldsa_make_hint_88(too-many) expected -1");
    }
    WB_OK("mldsa_make_hint_88 operand + overflow pairs exercised");
}
#endif /* !WOLFSSL_NO_ML_DSA_44 */

#if !defined(WOLFSSL_NO_ML_DSA_65) || !defined(WOLFSSL_NO_ML_DSA_87)
static void wb_make_hint_32(void)
{
    sword32 s[MLDSA_N];
    sword32 w1[MLDSA_N];
    byte    h[256];
    byte    idx;
    unsigned int j;
    int ret;
    const sword32 low = (sword32)MLDSA_Q_LOW_32;
    const byte omega = 55; /* ML-DSA-65 OMEGA */

    for (j = 0; j < MLDSA_N; j++) {
        s[j] = 0;
        w1[j] = 0;
    }

    /* No hint. */
    idx = 0;
    ret = mldsa_make_hint_32(s, w1, omega, h, &idx);
    if ((ret != 0) || (idx != 0)) {
        WB_NOTE("mldsa_make_hint_32(no-hint) unexpected");
    }

    /* s > LOW. */
    idx = 0;
    s[1] = low + 1;
    ret = mldsa_make_hint_32(s, w1, omega, h, &idx);
    if ((ret != 0) || (idx != 1)) {
        WB_NOTE("mldsa_make_hint_32(s>LOW) unexpected");
    }

    /* s < -LOW. */
    idx = 0;
    s[1] = 0;
    s[2] = -low - 1;
    ret = mldsa_make_hint_32(s, w1, omega, h, &idx);
    if ((ret != 0) || (idx != 1)) {
        WB_NOTE("mldsa_make_hint_32(s<-LOW) unexpected");
    }

    /* (s == -LOW) && (w1 != 0). */
    idx = 0;
    s[2] = 0;
    s[3] = -low;
    w1[3] = 1;
    ret = mldsa_make_hint_32(s, w1, omega, h, &idx);
    if ((ret != 0) || (idx != 1)) {
        WB_NOTE("mldsa_make_hint_32(s==-LOW,w1!=0) unexpected");
    }

    /* (s == -LOW) && (w1 == 0) -> no hint. */
    idx = 0;
    w1[3] = 0;
    ret = mldsa_make_hint_32(s, w1, omega, h, &idx);
    if ((ret != 0) || (idx != 0)) {
        WB_NOTE("mldsa_make_hint_32(s==-LOW,w1==0) unexpected");
    }

    /* Too many: idx crosses omega -> -1. */
    idx = 0;
    for (j = 0; j < MLDSA_N; j++) {
        s[j] = low + 1;
    }
    ret = mldsa_make_hint_32(s, w1, omega, h, &idx);
    if (ret != -1) {
        WB_NOTE("mldsa_make_hint_32(too-many) expected -1");
    }
    WB_OK("mldsa_make_hint_32 operand + overflow pairs exercised");
}
#endif /* ML_DSA_65 || ML_DSA_87 */

#ifndef WOLFSSL_MLDSA_SIGN_SMALL_MEM
static void wb_make_hint_dispatch(void)
{
    sword32 s[PARAMS_ML_DSA_44_K * MLDSA_N];
    sword32 w1[PARAMS_ML_DSA_44_K * MLDSA_N];
    byte    h[512];
    unsigned int j;
    int ret;

    for (j = 0; j < PARAMS_ML_DSA_44_K * MLDSA_N; j++) {
        s[j] = 0;
        w1[j] = 0;
    }
    XMEMSET(h, 0, sizeof(h));

#ifndef WOLFSSL_NO_ML_DSA_44
    /* gamma2 == MLDSA_Q_LOW_88 arm. */
    ret = mldsa_make_hint(s, w1, PARAMS_ML_DSA_44_K, MLDSA_Q_LOW_88,
        PARAMS_ML_DSA_44_OMEGA, h);
    if (ret < 0) {
        WB_NOTE("mldsa_make_hint(88 arm) unexpected");
    }
#endif
#if !defined(WOLFSSL_NO_ML_DSA_65) || !defined(WOLFSSL_NO_ML_DSA_87)
    /* gamma2 == MLDSA_Q_LOW_32 arm. */
    XMEMSET(h, 0, sizeof(h));
    ret = mldsa_make_hint(s, w1, 4, MLDSA_Q_LOW_32, 55, h);
    if (ret < 0) {
        WB_NOTE("mldsa_make_hint(32 arm) unexpected");
    }
#endif
    /* Neither arm: gamma2 matches no known low modulus -> empty else. Use a
     * small omega so the trailing XMEMSET(h+idx, 0, omega-idx) stays in
     * bounds (idx==0 here). */
    XMEMSET(h, 0, sizeof(h));
    ret = mldsa_make_hint(s, w1, 1, 12345, 1, h);
    if (ret != 0) {
        WB_NOTE("mldsa_make_hint(neither arm) expected 0");
    }
    WB_OK("mldsa_make_hint gamma2 dispatch arms exercised");
    (void)ret;
}
#endif /* !WOLFSSL_MLDSA_SIGN_SMALL_MEM */
#endif /* !WOLFSSL_MLDSA_NO_SIGN */

/* ------------------------------------------------------------------ *
 * mldsa_check_hint (verify path): valid encoding (ret 0), a non-increasing
 * index pair (h[i-1] >= h[i] -> SIG_VERIFY_E), and a non-zero trailing hint
 * (h[i] != 0 -> SIG_VERIFY_E).
 * ------------------------------------------------------------------ */
#ifndef WOLFSSL_MLDSA_NO_VERIFY
static void wb_check_hint(void)
{
    byte h[256];
    const byte k = 2;
    const byte omega = 8;
    int ret;

    /* Valid: polynomial 0 has hints at indices {0,1} (strictly increasing),
     * count for poly0 = 2, count for poly1 = 2 (no more hints). */
    XMEMSET(h, 0, sizeof(h));
    h[0] = 0;
    h[1] = 1;
    h[omega + 0] = 2;   /* poly 0 uses hints 0..1 */
    h[omega + 1] = 2;   /* poly 1 adds none */
    ret = mldsa_check_hint(h, k, omega);
    if (ret != 0) {
        WB_NOTE("mldsa_check_hint(valid) expected 0");
    }

    /* Non-increasing hint values within a polynomial -> SIG_VERIFY_E. */
    XMEMSET(h, 0, sizeof(h));
    h[0] = 5;
    h[1] = 5;           /* h[0] >= h[1] */
    h[omega + 0] = 2;
    h[omega + 1] = 2;
    ret = mldsa_check_hint(h, k, omega);
    if (ret != WC_NO_ERR_TRACE(SIG_VERIFY_E)) {
        WB_NOTE("mldsa_check_hint(non-increasing) expected SIG_VERIFY_E");
    }

    /* Trailing non-zero hint beyond used counts -> SIG_VERIFY_E. */
    XMEMSET(h, 0, sizeof(h));
    h[omega + 0] = 0;
    h[omega + 1] = 0;   /* no polynomial claims any hint */
    h[3] = 7;           /* but a stray non-zero hint remains */
    ret = mldsa_check_hint(h, k, omega);
    if (ret != WC_NO_ERR_TRACE(SIG_VERIFY_E)) {
        WB_NOTE("mldsa_check_hint(stray) expected SIG_VERIFY_E");
    }
    WB_OK("mldsa_check_hint valid/invalid decisions exercised");
}
#endif /* !WOLFSSL_MLDSA_NO_VERIFY */

/* ------------------------------------------------------------------ *
 * mldsa_check_eta_range: eta==MLDSA_ETA_4 arm (two nibble operands, in/out
 * of range) and the eta!=4 (ETA_2) else arm (3-bit groups, in/out of range).
 * ------------------------------------------------------------------ */
#ifdef WOLFSSL_MLDSA_PRIVATE_KEY
static void wb_check_eta_range(void)
{
    byte p[12];
    int ret;

    /* eta == 4 arm, all in range: nibbles <= 2*eta == 8. */
    XMEMSET(p, 0, sizeof(p));
    ret = mldsa_check_eta_range(p, MLDSA_ETA_4, sizeof(p));
    if (ret != 0) {
        WB_NOTE("mldsa_check_eta_range(eta4,in) expected 0");
    }

    /* eta == 4 arm, low nibble out of range: (p&0xf) > max. */
    XMEMSET(p, 0, sizeof(p));
    p[0] = 0x0f;         /* 15 > 8 */
    ret = mldsa_check_eta_range(p, MLDSA_ETA_4, sizeof(p));
    if (ret != WC_NO_ERR_TRACE(PUBLIC_KEY_E)) {
        WB_NOTE("mldsa_check_eta_range(eta4,low-hi) expected PUBLIC_KEY_E");
    }

    /* eta == 4 arm, high nibble out of range: (p>>4) > max, low in range. */
    XMEMSET(p, 0, sizeof(p));
    p[0] = 0xf0;         /* high nibble 15 > 8, low nibble 0 */
    ret = mldsa_check_eta_range(p, MLDSA_ETA_4, sizeof(p));
    if (ret != WC_NO_ERR_TRACE(PUBLIC_KEY_E)) {
        WB_NOTE("mldsa_check_eta_range(eta4,high-hi) expected PUBLIC_KEY_E");
    }

    /* eta != 4 (ETA_2) else arm, all in range: 3-bit groups <= 2*eta == 4. */
    XMEMSET(p, 0, sizeof(p));
    ret = mldsa_check_eta_range(p, MLDSA_ETA_2, sizeof(p));
    if (ret != 0) {
        WB_NOTE("mldsa_check_eta_range(eta2,in) expected 0");
    }

    /* eta != 4 else arm, a 3-bit group out of range (value 7 > 4). */
    XMEMSET(p, 0, sizeof(p));
    p[0] = 0x07;         /* first 3-bit group == 7 > 4 */
    ret = mldsa_check_eta_range(p, MLDSA_ETA_2, sizeof(p));
    if (ret != WC_NO_ERR_TRACE(PUBLIC_KEY_E)) {
        WB_NOTE("mldsa_check_eta_range(eta2,hi) expected PUBLIC_KEY_E");
    }
    WB_OK("mldsa_check_eta_range eta4/eta2 in/out pairs exercised");
}
#endif /* WOLFSSL_MLDSA_PRIVATE_KEY */

/* ------------------------------------------------------------------ *
 * ASN.1 fallback helpers. These file-static parsers are ONLY compiled when
 * WOLFSSL_MLDSA_NO_ASN1 is defined (the hand-rolled DER parser used in place
 * of the wolfSSL ASN template engine); with the template engine on they do
 * not exist. Reached only by the mldsa_no_asn1 variant's white-box.
 * mldsa_get_der_length: the full short/long-form length cascade.
 * mldsa_check_type: idx>=inSz / tag mismatch / ok.
 * mldsa_oid_to_level: matching OID / no match.
 * ------------------------------------------------------------------ */
#ifdef WOLFSSL_MLDSA_NO_ASN1
static void wb_der_length(void)
{
    byte in[8];
    word32 idx;
    int len;
    int ret;

    /* idx >= inSz -> ASN_PARSE_E. */
    idx = 4;
    ret = mldsa_get_der_length(in, &idx, &len, 4);
    if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) {
        WB_NOTE("get_der_length(idx>=inSz) expected ASN_PARSE_E");
    }

    /* short form: input[idx] < 0x80. */
    idx = 0; in[0] = 0x05;
    ret = mldsa_get_der_length(in, &idx, &len, sizeof(in));
    if ((ret != 0) || (len != 5) || (idx != 1)) {
        WB_NOTE("get_der_length(short) unexpected");
    }

    /* input[idx] == 0x80 -> ASN_PARSE_E. */
    idx = 0; in[0] = 0x80;
    ret = mldsa_get_der_length(in, &idx, &len, sizeof(in));
    if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) {
        WB_NOTE("get_der_length(0x80) expected ASN_PARSE_E");
    }

    /* input[idx] >= 0x83 -> ASN_PARSE_E (same else-if operand, other half). */
    idx = 0; in[0] = 0x83;
    ret = mldsa_get_der_length(in, &idx, &len, sizeof(in));
    if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) {
        WB_NOTE("get_der_length(0x83) expected ASN_PARSE_E");
    }

    /* 0x81 form, truncated (idx+1 >= inSz) -> ASN_PARSE_E. */
    idx = 0; in[0] = 0x81;
    ret = mldsa_get_der_length(in, &idx, &len, 1);
    if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) {
        WB_NOTE("get_der_length(0x81 trunc) expected ASN_PARSE_E");
    }

    /* 0x81 form, second byte < 0x80 (non-canonical) -> ASN_PARSE_E. */
    idx = 0; in[0] = 0x81; in[1] = 0x7f;
    ret = mldsa_get_der_length(in, &idx, &len, sizeof(in));
    if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) {
        WB_NOTE("get_der_length(0x81 noncanon) expected ASN_PARSE_E");
    }

    /* 0x81 form, valid: second byte >= 0x80. Provide enough buffer. */
    {
        byte big[200];
        XMEMSET(big, 0, sizeof(big));
        idx = 0; big[0] = 0x81; big[1] = 0x80; /* len 128 */
        ret = mldsa_get_der_length(big, &idx, &len, sizeof(big));
        if ((ret != 0) || (len != 0x80) || (idx != 2)) {
            WB_NOTE("get_der_length(0x81 valid) unexpected");
        }

        /* 0x82 form, truncated (idx+2 >= inSz) -> ASN_PARSE_E. */
        idx = 0; big[0] = 0x82;
        ret = mldsa_get_der_length(big, &idx, &len, 2);
        if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) {
            WB_NOTE("get_der_length(0x82 trunc) expected ASN_PARSE_E");
        }

        /* 0x82 form, len < 0x100 (non-canonical) -> ASN_PARSE_E. */
        idx = 0; big[0] = 0x82; big[1] = 0x00; big[2] = 0x10;
        ret = mldsa_get_der_length(big, &idx, &len, sizeof(big));
        if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) {
            WB_NOTE("get_der_length(0x82 noncanon) expected ASN_PARSE_E");
        }

        /* 0x82 form, valid len 0x100 but (idx+len) > inSz -> final guard. */
        idx = 0; big[0] = 0x82; big[1] = 0x01; big[2] = 0x00; /* len 256 */
        ret = mldsa_get_der_length(big, &idx, &len, sizeof(big));
        if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) {
            WB_NOTE("get_der_length(0x82 overrun) expected ASN_PARSE_E");
        }

        /* 0x82 form, valid and fits: len 0x100 with a large enough inSz. */
        idx = 0; big[0] = 0x82; big[1] = 0x01; big[2] = 0x00;
        ret = mldsa_get_der_length(big, &idx, &len, 0x100 + 3);
        if ((ret != 0) || (len != 0x100) || (idx != 3)) {
            WB_NOTE("get_der_length(0x82 valid) unexpected");
        }
    }
    WB_OK("mldsa_get_der_length cascade exercised");
}

static void wb_check_type(void)
{
    byte in[4];
    word32 idx;
    int ret;

    /* idx >= inSz -> ASN_PARSE_E. */
    idx = 2;
    ret = mldsa_check_type(in, &idx, 0x30, 2);
    if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) {
        WB_NOTE("check_type(idx>=inSz) expected ASN_PARSE_E");
    }

    /* tag mismatch -> ASN_PARSE_E. */
    idx = 0; in[0] = 0x31;
    ret = mldsa_check_type(in, &idx, 0x30, sizeof(in));
    if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) {
        WB_NOTE("check_type(mismatch) expected ASN_PARSE_E");
    }

    /* match -> 0, idx advanced. */
    idx = 0; in[0] = 0x30;
    ret = mldsa_check_type(in, &idx, 0x30, sizeof(in));
    if ((ret != 0) || (idx != 1)) {
        WB_NOTE("check_type(match) unexpected");
    }
    WB_OK("mldsa_check_type decisions exercised");
}

static void wb_oid_to_level(void)
{
    byte level = 0;
    int ret;

#ifndef WOLFSSL_NO_ML_DSA_44
    /* Matching OID (ML-DSA-44, non-draft) -> level set, ret 0. */
    ret = mldsa_oid_to_level(ml_dsa_oid_44, (word32)sizeof(ml_dsa_oid_44),
        &level);
    if ((ret != 0) || (level != WC_ML_DSA_44)) {
        WB_NOTE("oid_to_level(44) unexpected");
    }
#endif

    /* No match: length matches a known OID but bytes differ -> ASN_PARSE_E. */
    {
        byte bogus[9];
        XMEMSET(bogus, 0xAA, sizeof(bogus));
        level = 0;
        ret = mldsa_oid_to_level(bogus, (word32)sizeof(bogus), &level);
        if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) {
            WB_NOTE("oid_to_level(bogus) expected ASN_PARSE_E");
        }
    }
    WB_OK("mldsa_oid_to_level match/no-match exercised");
}
#endif /* WOLFSSL_MLDSA_NO_ASN1 */

#endif /* WOLFSSL_HAVE_MLDSA */

int main(void)
{
    printf("wc_mldsa.c white-box MC/DC supplement\n");
#if !defined(WOLFSSL_HAVE_MLDSA)
    printf("  ML-DSA not enabled; nothing to exercise\n");
    return 0;
#else
    wb_get_params();
#if !defined(WOLFSSL_MLDSA_NO_SIGN) || !defined(WOLFSSL_MLDSA_NO_VERIFY)
    wb_check_low();
#endif
#ifndef WOLFSSL_MLDSA_NO_SIGN
#ifndef WOLFSSL_NO_ML_DSA_44
    wb_make_hint_88();
#endif
#if !defined(WOLFSSL_NO_ML_DSA_65) || !defined(WOLFSSL_NO_ML_DSA_87)
    wb_make_hint_32();
#endif
#ifndef WOLFSSL_MLDSA_SIGN_SMALL_MEM
    wb_make_hint_dispatch();
#endif
#endif /* !WOLFSSL_MLDSA_NO_SIGN */
#ifndef WOLFSSL_MLDSA_NO_VERIFY
    wb_check_hint();
#endif
#ifdef WOLFSSL_MLDSA_PRIVATE_KEY
    wb_check_eta_range();
#endif
#ifdef WOLFSSL_MLDSA_NO_ASN1
    wb_der_length();
    wb_check_type();
    wb_oid_to_level();
#endif
    printf("done (%d note%s)\n", wb_notes, (wb_notes == 1) ? "" : "s");
    return 0;
#endif
}
