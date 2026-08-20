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
 * #includes wc_mldsa.c so the static functions are in scope and calls each
 * targeted helper with BOTH halves of every targeted decision in a single
 * binary
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

/* SAVE_VECTOR_REGISTERS2() gates every SIMD dispatch in this file. In a
 * userspace build types.h resolves it to the literal 0, so "(0 == 0)" is
 * structurally true and that operand has no false side at all -- it is real
 * only where the save can be refused (the kernel-module build, where it
 * becomes WC_CHECK_FOR_INTR_SIGNALS()). That is the #ifndef extension point
 * types.h offers, so defining it here -- BEFORE any wolfSSL header is reached
 * through the .c below -- routes every dispatch through a variable this file
 * controls, using the library's own hook rather than overriding a macro
 * behind its back. Same arrangement as test_wc_mlkem_poly_whitebox.c.
 */
/* The hook is a function rather than a plain variable because the dispatches
 * NEST: mldsa_expand_a() picks an AVX512 matrix generator, and only when that
 * arm is declined does control reach the portable code whose mldsa_ntt() /
 * mldsa_invntt() / mldsa_mul() carry their own
 *
 *     if (USE_INTEL_AVX512(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0))
 *
 * A process-wide "always accept" never reaches those inner sites at all, and a
 * process-wide "always refuse" reaches them only on their false row -- which
 * is exactly the shape of the 12 residual conditions at wc_mldsa.c:6832/7861/
 * 7890/8242.  Refusing a periodic subset of the calls instead lets an outer
 * dispatch be declined while a later inner one is accepted, so both rows of
 * the inner decision land in one binary without any cpuid bit being claimed
 * that this CPU does not have. */
static int  wb_intr_ret = 0;   /* != 0: refuse every save (blanket row)   */
static long wb_intr_ix  = 0;   /* SAVE_VECTOR_REGISTERS2() calls seen     */
static long wb_intr_mod = 0;   /* > 0: refuse when (ix % mod) == res      */
static long wb_intr_res = 0;

static int wb_intr_hook(void)
{
    long ix = wb_intr_ix++;

    if (wb_intr_ret != 0) {
        return wb_intr_ret;
    }
    if ((wb_intr_mod > 0) && ((ix % wb_intr_mod) == wb_intr_res)) {
        return 1;
    }
    return 0;
}
#define WC_CHECK_FOR_INTR_SIGNALS() wb_intr_hook()

/* ------------------------------------------------------------------------- *
 * Rejection-sampling lane interposition.
 *
 * The six AVX2 generators each fill four (or three) polynomials in parallel
 * and then loop while any lane is still short:
 *
 *     ctr0 = wc_mldsa_rej_uniform_n_avx2(...);   ... ctr3 = ...
 *     while ((ctr0 < MLDSA_N) || (ctr1 < MLDSA_N) || (ctr2 < MLDSA_N) ||
 *            (ctr3 < MLDSA_N)) { ... }
 *
 * Each operand's independence pair needs an evaluation in which THAT lane is
 * the first short one, and a real seed fills every lane from the first block
 * essentially always -- so the vector observed is (F,F,F,F) and which operands
 * a run happens to catch is luck rather than test design.
 *
 * The loop's counters come from WOLFSSL_LOCAL leaf routines declared in
 * wc_mldsa.h (the first-pass sampler wc_mldsa_rej_uniform_n_avx2 and the eta
 * extractors), so declaring that header first keeps the real prototypes under
 * their real names and the renames below rewrite only the uses inside
 * wc_mldsa.c.  The refill routines (wc_mldsa_rej_uniform_avx2, and the second
 * and later calls into the extractors) are deliberately left alone so every
 * loop still terminates on its next pass. */
#include <wolfssl/wolfcrypt/libwolfssl_sources.h>
#include <wolfssl/wolfcrypt/wc_mldsa.h>

#if defined(USE_INTEL_SPEEDUP) && !defined(WC_SHA3_NO_ASM)

static int  wb_rej_n_avx2(sword32* a, word32 len, const byte* r, word32 rLen);
static void wb_extract_eta2_avx2(const byte* z, unsigned int zLen, sword32* s,
    unsigned int* cnt);
static void wb_extract_eta4_avx2(const byte* z, unsigned int zLen, sword32* s,
    unsigned int* cnt);

#define wc_mldsa_rej_uniform_n_avx2      wb_rej_n_avx2
#define wc_mldsa_extract_coeffs_eta2_avx2 wb_extract_eta2_avx2
#define wc_mldsa_extract_coeffs_eta4_avx2 wb_extract_eta4_avx2

#endif /* USE_INTEL_SPEEDUP && !WC_SHA3_NO_ASM */

#include <wolfcrypt/src/wc_mldsa.c>

#if defined(USE_INTEL_SPEEDUP) && !defined(WC_SHA3_NO_ASM)
#undef wc_mldsa_rej_uniform_n_avx2
#undef wc_mldsa_extract_coeffs_eta2_avx2
#undef wc_mldsa_extract_coeffs_eta4_avx2

/* Sampler-call index within the current pass and the call to report one
 * coefficient short.  The polynomial is still fully and correctly sampled --
 * the generator's own refill pass writes the last coefficient -- so the only
 * behavioural change is that the "a lane came up short" path runs, which is
 * what the hardware does anyway a few times in every thousand key
 * generations. */
static long wb_lane_ix = 0;
static long wb_lane_at = -1;

static int wb_lane_hit(void)
{
    long ix = wb_lane_ix++;

    return (wb_lane_at >= 0) && (ix == wb_lane_at);
}

static int wb_rej_n_avx2(sword32* a, word32 len, const byte* r, word32 rLen)
{
    int got = wc_mldsa_rej_uniform_n_avx2(a, len, r, rLen);

    if (wb_lane_hit() && (got == (int)len) && (len > 0)) {
        got = (int)len - 1;
    }
    return got;
}

static void wb_extract_eta2_avx2(const byte* z, unsigned int zLen, sword32* s,
    unsigned int* cnt)
{
    wc_mldsa_extract_coeffs_eta2_avx2(z, zLen, s, cnt);
    if (wb_lane_hit() && (*cnt >= (unsigned int)MLDSA_N)) {
        *cnt = (unsigned int)MLDSA_N - 1;
    }
}

static void wb_extract_eta4_avx2(const byte* z, unsigned int zLen, sword32* s,
    unsigned int* cnt)
{
    wc_mldsa_extract_coeffs_eta4_avx2(z, zLen, s, cnt);
    if (wb_lane_hit() && (*cnt >= (unsigned int)MLDSA_N)) {
        *cnt = (unsigned int)MLDSA_N - 1;
    }
}

#endif /* USE_INTEL_SPEEDUP && !WC_SHA3_NO_ASM */

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
 * mldsa_check_hint: two inner loop decisions that the 3-outcome test
 * above never reaches because their FALSE/TRUE pair only shows up with
 * carefully overlapping polynomial hint-count bytes (not just a simple
 * valid/invalid signature encoding):
 *
 *   do { o++; } while ((o < k) && (i == h[omega + o]));  [line ~5363]
 *     Needs the (o < k) operand held TRUE while (i == h[omega+o]) is
 *     shown both TRUE (poly o+1 shares the same running count) and
 *     FALSE (poly o+2 has a different count) -- a single call with 3
 *     polynomials sharing the count at the first match and diverging at
 *     the next index demonstrates both.
 *
 *   while ((o < k) && (i == h[omega + o])) { o++; }      [line ~5377]
 *     The "consume trailing same-count polynomials" loop entered only
 *     when the outer for-loop is exhausted by i reaching omega with o
 *     stalled below k. Since mldsa_check_hint does not itself validate
 *     that hint-count bytes are monotonic/bounded, arbitrary trailing
 *     byte values let us show the (i == h[omega+o]) operand both TRUE
 *     and FALSE while (o < k) stays TRUE.
 * ------------------------------------------------------------------ */
#ifndef WOLFSSL_MLDSA_NO_VERIFY
static void wb_check_hint_inner_loops(void)
{
    byte h[32];
    int ret;

    /* Line ~5363 do-while: k=3, omega=8. Hint values h[0..7] strictly
     * increasing so the "else if (h[i-1] >= h[i])" arm never fires.
     * Counts: poly0=poly1=3 (do-while continues: TRUE), poly2=5
     * (do-while stops: FALSE), both checked while (o < k) is TRUE. */
    XMEMSET(h, 0, sizeof(h));
    h[0] = 0; h[1] = 1; h[2] = 2; h[3] = 3; h[4] = 4;
    h[5] = 0; h[6] = 0; h[7] = 0; /* tail hint bytes unused, zero */
    h[8] = 3; h[9] = 3; h[10] = 5;
    ret = mldsa_check_hint(h, 3, 8);
    if (ret != 0) {
        WB_NOTE("mldsa_check_hint(inner do-while pair) expected 0");
    }

    /* Line ~5377 while: k=2, omega=8. Hint values 0..7 strictly
     * increasing (no false-positive match, no else-if error), so the
     * outer for-loop exhausts via i==omega with o stalled at 0. The
     * trailing counts h[8]=8 (matches i==omega -> TRUE, o advances to 1)
     * then h[9]=3 (does not match i==omega -> FALSE, o stays at 1),
     * both observed while (o < k) is TRUE. o!=k at the end -> a hint
     * count was left unconsumed -> SIG_VERIFY_E. */
    XMEMSET(h, 0, sizeof(h));
    h[0] = 0; h[1] = 1; h[2] = 2; h[3] = 3; h[4] = 4; h[5] = 5; h[6] = 6;
    h[7] = 7;
    h[8] = 8; h[9] = 3;
    ret = mldsa_check_hint(h, 2, 8);
    if (ret != WC_NO_ERR_TRACE(SIG_VERIFY_E)) {
        WB_NOTE("mldsa_check_hint(inner while pair) expected SIG_VERIFY_E");
    }
    WB_OK("mldsa_check_hint inner do-while/while operand pairs exercised");
}
#endif /* !WOLFSSL_MLDSA_NO_VERIFY */

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
    /* Matching OID (ML-DSA-44, non-draft) -> level set, ret 0.
     * Also exercises the 65/87 chain arms' (ret != 0) operand as TRUE
     * (44 didn't match anything before this call in a fresh call, but
     * here 44 matches immediately so the 65/87 "ret != 0" checks below
     * see ret==0 and short-circuit to FALSE). */
    ret = mldsa_oid_to_level(ml_dsa_oid_44, (word32)sizeof(ml_dsa_oid_44),
        &level);
    if ((ret != 0) || (level != WC_ML_DSA_44)) {
        WB_NOTE("oid_to_level(44) unexpected");
    }
#endif
#ifndef WOLFSSL_NO_ML_DSA_65
    /* Matching OID (ML-DSA-65): 44's arm (ret != 0) is TRUE (no match
     * yet), 65's arm matches (ret != 0 TRUE, oidLen== TRUE, memcmp==0
     * TRUE), then 87's arm sees (ret != 0) FALSE (already matched). */
    level = 0;
    ret = mldsa_oid_to_level(ml_dsa_oid_65, (word32)sizeof(ml_dsa_oid_65),
        &level);
    if ((ret != 0) || (level != WC_ML_DSA_65)) {
        WB_NOTE("oid_to_level(65) unexpected");
    }
#endif
#ifndef WOLFSSL_NO_ML_DSA_87
    /* Matching OID (ML-DSA-87): 44/65 arms' (ret != 0) stay TRUE (no
     * match), 87's arm matches. */
    level = 0;
    ret = mldsa_oid_to_level(ml_dsa_oid_87, (word32)sizeof(ml_dsa_oid_87),
        &level);
    if ((ret != 0) || (level != WC_ML_DSA_87)) {
        WB_NOTE("oid_to_level(87) unexpected");
    }
#endif

    /* No match, same length: length matches every known OID (all 9
     * bytes) but bytes differ from all of them -> ASN_PARSE_E. Gives
     * (oidLen == sizeof(...)) TRUE and memcmp()==0 FALSE for every arm
     * in one call. */
    {
        byte bogus[9];
        XMEMSET(bogus, 0xAA, sizeof(bogus));
        level = 0;
        ret = mldsa_oid_to_level(bogus, (word32)sizeof(bogus), &level);
        if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) {
            WB_NOTE("oid_to_level(bogus) expected ASN_PARSE_E");
        }
    }

    /* No match, different length: (oidLen == sizeof(...)) FALSE for
     * every arm (independence of the oidLen operand from the memcmp
     * one) -> falls through every arm untouched -> ASN_PARSE_E. */
    {
        byte shortOid[3] = { 0xAA, 0xAA, 0xAA };
        level = 0;
        ret = mldsa_oid_to_level(shortOid, (word32)sizeof(shortOid), &level);
        if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) {
            WB_NOTE("oid_to_level(short) expected ASN_PARSE_E");
        }
    }
    WB_OK("mldsa_oid_to_level match/no-match/length pairs exercised");
}
#endif /* WOLFSSL_MLDSA_NO_ASN1 */

#endif /* WOLFSSL_HAVE_MLDSA */

/* ------------------------------------------------------------------------- *
 * SIMD dispatch rows.
 *
 * wc_mldsa.c selects an implementation with
 *
 *     if (IS_INTEL_AVX512_VBMI(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0))
 *     if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0))
 *     if (IS_INTEL_AVX2(cpuid_flags) && IS_INTEL_BMI2(cpuid_flags) && ...)
 *     if ((k == N) && (l == N) && IS_INTEL_AVX2(cpuid_flags) && ...)
 *
 * On a capable host every feature bit is set and the save always succeeds, so
 * only the all-true row is ever seen and no operand gets an independence pair.
 * Each row below clears a different suffix of the feature ladder -- an arm's
 * true side only occurs when the richer features above it are absent -- and
 * one row refuses the save so every chain falls through at its last operand.
 *
 * Every compiled parameter set is swept because a good many of the dispatches
 * are guarded by (k == ..) && (l == ..) first, so one level alone leaves the
 * others' dispatches unexecuted.
 *
 * cpuid_flags is this file's own static and mldsa_init()-style refresh only
 * happens while it still holds WC_CPUID_INITIALIZER, so a forced value stays.
 * Clearing bits only ever selects portable C, and the rows that keep bits
 * claim only what this CPU actually reported.
 * ------------------------------------------------------------------------- */
/* Shared scratch for the direct file-static calls below: the largest shape is
 * ML-DSA-87's 8 x 7 matrix, and s1/s2 are at most 8 polynomials each.  File
 * scope keeps ~75 KB off the stack. */
#if defined(WOLFSSL_HAVE_MLDSA) && defined(USE_INTEL_SPEEDUP)
static sword32 wb_lane_a[8 * 7 * MLDSA_N];
static sword32 wb_lane_s1[8 * MLDSA_N];
static sword32 wb_lane_s2[8 * MLDSA_N];
/* Read-only inputs: MLDSA_GEN_A_SEED_SZ (34) for the matrix generators,
 * MLDSA_PRIV_SEED_SZ (64) for the s generators. */
static byte    wb_lane_seed[128];
#endif

#if defined(WOLFSSL_HAVE_MLDSA) && defined(USE_INTEL_SPEEDUP) && \
    !defined(WOLFSSL_MLDSA_NO_SIGN) && !defined(WOLFSSL_MLDSA_NO_VERIFY) && \
    !defined(WOLFSSL_MLDSA_NO_MAKE_KEY)

static const int wb_dsa_levels[] = {
#ifndef WOLFSSL_NO_ML_DSA_44
    WC_ML_DSA_44,
#endif
#ifndef WOLFSSL_NO_ML_DSA_65
    WC_ML_DSA_65,
#endif
#ifndef WOLFSSL_NO_ML_DSA_87
    WC_ML_DSA_87,
#endif
    0 /* sentinel keeps the array non-empty */
};

static const byte wb_dsa_seed[32] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};

static void wb_dsa_cycle(WC_RNG* rng, int level)
{
    (void)rng;
    wc_MlDsaKey key;
    static byte sig[MLDSA_MAX_SIG_SIZE];
    byte   msg[32];
    word32 sigLen = (word32)sizeof(sig);
    int    res = 0;

    if (level == 0) {
        return;
    }
    XMEMSET(msg, 0x5a, sizeof(msg));

    if (wc_MlDsaKey_Init(&key, NULL, INVALID_DEVID) != 0) {
        return;
    }
    /* The ctx-based entry points are the ones this config compiles;
     * wc_MlDsaKey_Sign/Verify exist only under WOLFSSL_MLDSA_NO_CTX. Seeded
     * signing keeps the cycle deterministic across rows, so a row difference
     * is a dispatch difference and nothing else. */
    if (wc_MlDsaKey_SetParams(&key, level) == 0 &&
            wc_MlDsaKey_MakeKeyFromSeed(&key, wb_dsa_seed) == 0) {
        if (wc_MlDsaKey_SignCtxWithSeed(&key, NULL, 0, sig, &sigLen, msg,
                (word32)sizeof(msg), wb_dsa_seed) == 0) {
            (void)wc_MlDsaKey_VerifyCtx(&key, sig, sigLen, NULL, 0, msg,
                (word32)sizeof(msg), &res);
        }
    }
    wc_MlDsaKey_Free(&key);
}

static void wb_dispatch_rows(void)
{
    cpuid_flags_t saved_flags = cpuid_flags;
    int           saved_intr  = wb_intr_ret;
    WC_RNG        rng;
    unsigned      i, t;
    /* USE_INTEL_AVX512(f) is itself IS_INTEL_AVX512(f) && IS_INTEL_AVX512_BW(f)
     * (cpuid.h), so each AVX512 dispatch is a three-condition decision and the
     * F and BW bits need to be cleared separately.  SHA3_USE_AVX2(f) is
     * IS_INTEL_AVX2(f) && IS_CPU_INTEL(f): its vendor operand is false on any
     * AMD host, so CPUID_INTEL is forced on for the rows that need its true
     * side -- the arm behind it is plain AVX2, which runs anywhere AVX2 does. */
    static const struct {
        cpuid_flags_t set;
        cpuid_flags_t clear;
        int           intr;
    } rows[] = {
        { CPUID_INTEL, 0,                          0 },  /* richest arm      */
        { CPUID_INTEL, 0,                          1 },  /* save refused     */
        { CPUID_INTEL, CPUID_AVX512_BW,            0 },  /* F set, BW clear  */
        { CPUID_INTEL, CPUID_AVX512_BW,            1 },  /* BW clear, refuse */
        /* The AVX512 matrix/mask dispatches read
         *   USE_INTEL_AVX512(f) && IS_INTEL_BMI2(f) && (save == 0)
         * so their BMI2 operand only takes its false side on a row that keeps
         * AVX512 and drops BMI2 -- dropping both together (further down)
         * never evaluates it. */
        { CPUID_INTEL, CPUID_BMI2,                 0 },  /* AVX512, no BMI2  */
        { CPUID_INTEL, CPUID_BMI2,                 1 },  /* ditto, refuse    */
        { CPUID_INTEL, CPUID_AVX2,                 0 },  /* AVX512, no AVX2  */
        { CPUID_INTEL, CPUID_AVX512,               0 },  /* F clear          */
        { CPUID_INTEL, CPUID_AVX512_VBMI,          0 },  /* no VBMI          */
        { CPUID_INTEL, CPUID_AVX512 | CPUID_AVX512_BW |
                       CPUID_AVX512_VBMI,          0 },  /* -> AVX2 arm      */
        { CPUID_INTEL, CPUID_AVX512 | CPUID_AVX512_BW |
                       CPUID_AVX512_VBMI | CPUID_BMI2, 0 }, /* AVX2 no BMI2  */
        { CPUID_INTEL, CPUID_AVX512 | CPUID_AVX512_BW |
                       CPUID_AVX512_VBMI | CPUID_BMI2 |
                       CPUID_AVX2,                 0 },  /* portable C       */
        { 0,           CPUID_INTEL,                0 },  /* non-Intel vendor */
    };

    if (wc_InitRng(&rng) != 0) {
        printf("  [wb] wc_InitRng failed; SIMD dispatch rows skipped\n");
        return;
    }

    for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        cpuid_flags = WC_CPUID_INITIALIZER;
        (void)cpuid_get_flags_ex(&cpuid_flags);
        cpuid_flags |= rows[i].set;
        cpuid_flags &= (cpuid_flags_t)~rows[i].clear;
        wb_intr_ret = rows[i].intr;

        for (t = 0; t < sizeof(wb_dsa_levels) / sizeof(wb_dsa_levels[0]); t++) {
            wb_dsa_cycle(&rng, wb_dsa_levels[t]);
        }
    }

    /* Periodic save-refusal rows: see the wb_intr_hook comment at the top of
     * this file.  Every feature bit stays set so the OUTER dispatch is the one
     * being declined, and the inner NTT/mul dispatches get the accepted row
     * that a blanket refusal can never give them.  Several periods are used
     * because which call index an outer dispatch lands on depends on how much
     * hashing the level did before it. */
    {
        static const long periods[][2] = {
            { 2, 0 }, { 2, 1 }, { 3, 0 }, { 3, 1 }, { 3, 2 }
        };
        unsigned p;

        for (p = 0; p < sizeof(periods) / sizeof(periods[0]); p++) {
            cpuid_flags = WC_CPUID_INITIALIZER;
            (void)cpuid_get_flags_ex(&cpuid_flags);
            cpuid_flags |= (cpuid_flags_t)CPUID_INTEL;
            wb_intr_ret = 0;
            wb_intr_ix  = 0;
            wb_intr_mod = periods[p][0];
            wb_intr_res = periods[p][1];

            for (t = 0; t < sizeof(wb_dsa_levels) / sizeof(wb_dsa_levels[0]);
                    t++) {
                wb_dsa_cycle(&rng, wb_dsa_levels[t]);
            }
        }
        wb_intr_mod = 0;
        wb_intr_res = 0;
    }

    /* mldsa_expand_a()'s AVX2 arms are guarded by (k == N) && (l == N) pairs.
     * No real parameter set has k == 4 with l != 4, so the second operand of
     * each pair has no false side along the key paths; the function is
     * file-static, so it is called here with the mismatched shapes directly.
     * Every mismatch falls through to mldsa_expand_a_c(), which fills k*l
     * polynomials of the buffer and needs no SIMD arm at all. */
#if !defined(WOLFSSL_NO_ML_DSA_44) && !defined(WOLFSSL_NO_ML_DSA_65) && \
    !defined(WOLFSSL_NO_ML_DSA_87)
    {
        static const byte shapes[][2] = { { 4, 5 }, { 6, 4 }, { 8, 5 } };
        wc_Shake shake128;
        unsigned p;

        /* AVX512 cleared so the k/l-guarded AVX2 arms are the ones evaluated;
         * AVX2 and BMI2 are left as the host reported them. */
        cpuid_flags = WC_CPUID_INITIALIZER;
        (void)cpuid_get_flags_ex(&cpuid_flags);
        cpuid_flags |= (cpuid_flags_t)CPUID_INTEL;
        cpuid_flags &= (cpuid_flags_t)~(CPUID_AVX512 | CPUID_AVX512_BW |
                                        CPUID_AVX512_VBMI);
        wb_intr_ret = 0;

        if (wc_InitShake128(&shake128, NULL, INVALID_DEVID) == 0) {
            for (p = 0; p < sizeof(shapes) / sizeof(shapes[0]); p++) {
                (void)mldsa_expand_a(&shake128, wb_dsa_seed, shapes[p][0],
                    shapes[p][1], wb_lane_a, NULL);
            }
            wc_Shake128_Free(&shake128);
        }
    }
#endif

    cpuid_flags = saved_flags;
    wb_intr_ret = saved_intr;
    wb_intr_mod = 0;
    wc_FreeRng(&rng);
    printf("  [wb] SIMD dispatch rows (cpuid x save-accepted) exercised\n");
}

#else
static void wb_dispatch_rows(void)
{
    printf("  [wb] no Intel SIMD dispatch in this variant; rows skipped\n");
}
#endif

/* ------------------------------------------------------------------------- *
 * Rejection-sampling lane rows.
 *
 * Six generators carry the "did any lane come up short" loops (and, in the
 * gen_s pair, the matching `if` that decides whether to squeeze another
 * block).  They are file-static, and this TU #includes wc_mldsa.c, so they can
 * be driven directly with their own buffers instead of through a key
 * operation -- which also means one pass costs one matrix expansion rather
 * than a whole ML-DSA key generation.
 *
 * Pass n reports sampler call n one coefficient short, so the group that call
 * belongs to yields exactly the (F..F,T,-..) vector for that lane; sweeping n
 * across more calls than the widest generator makes reaches every lane of
 * every group, including the two- and three-lane tails.  The unswept pass
 * supplies the all-false vector every operand needs as its partner.
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_HAVE_MLDSA) && defined(USE_INTEL_SPEEDUP) && \
    !defined(WC_SHA3_NO_ASM) && \
    !defined(WOLFSSL_MLDSA_NO_MAKE_KEY) && \
    !defined(WOLFSSL_MLDSA_MAKE_KEY_SMALL_MEM) && \
    !defined(WOLFSSL_NO_ML_DSA_44) && !defined(WOLFSSL_NO_ML_DSA_65) && \
    !defined(WOLFSSL_NO_ML_DSA_87)

/* 6x5 makes 28 grouped calls plus a two-lane tail, so 32 positions reach every
 * lane of every group in every one of the six generators. */
#define WB_LANE_SWEEP 32

static void wb_gen_lane_rows(void)
{
    sword32* s[2];
    long     n;

    XMEMSET(wb_lane_seed, 0x71, sizeof(wb_lane_seed));
    XMEMSET(wb_lane_a, 0, sizeof(wb_lane_a));
    XMEMSET(wb_lane_s1, 0, sizeof(wb_lane_s1));
    XMEMSET(wb_lane_s2, 0, sizeof(wb_lane_s2));
    s[0] = wb_lane_s1;
    s[1] = wb_lane_s2;

    for (n = -1; n < (long)WB_LANE_SWEEP; n++) {
        wb_lane_at = n;

        wb_lane_ix = 0;
        (void)wc_mldsa_gen_matrix_4x4_avx2(wb_lane_a, wb_lane_seed);
        wb_lane_ix = 0;
        (void)wc_mldsa_gen_matrix_6x5_avx2(wb_lane_a, wb_lane_seed);
        wb_lane_ix = 0;
        (void)wc_mldsa_gen_matrix_8x7_avx2(wb_lane_a, wb_lane_seed);

        wb_lane_ix = 0;
        (void)wc_mldsa_gen_s_4_4_avx2(s, wb_lane_seed);
        wb_lane_ix = 0;
        (void)wc_mldsa_gen_s_5_6_avx2(s, wb_lane_seed);
        wb_lane_ix = 0;
        (void)wc_mldsa_gen_s_7_8_avx2(s, wb_lane_seed);
    }

    wb_lane_at = -1;
    wb_lane_ix = 0;
    printf("  [wb] rejection-sampling short-lane rows exercised\n");
}

#else
static void wb_gen_lane_rows(void)
{
    printf("  [wb] no AVX2 generators in this variant; lane rows skipped\n");
}
#endif

/* ------------------------------------------------------------------------- *
 * Argument guards on file-static entry points.
 *
 * mldsa_verify_ctx_msg() / mldsa_verify_ctx_hash() open with
 *
 *     if ((key == NULL) || (key->params == NULL)) ...
 *
 * but every public caller has already rejected a NULL key and a key without
 * params, so along the API only the (F,F) row is ever seen.  Both are file
 * static and this TU #includes wc_mldsa.c, so they take the two rejecting rows
 * directly: a NULL key for operand 0, and a zeroed key object (params NULL,
 * never dereferenced past the guard) for operand 1.
 *
 * mldsa_get_hash_oid()'s first operand is the "is this hash algorithm known"
 * result; an unrecognised algorithm gives it the NULL side that no caller with
 * a validated hash id can produce.  Its second operand -- the OID fitting in
 * MLDSA_HASH_OID_LEN -- is a property of the fixed OID table, not of any
 * argument, so it has no false side to drive and stays a residual.
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_HAVE_MLDSA)
static void wb_arg_guards(void)
{
#if !defined(WOLFSSL_MLDSA_NO_VERIFY) && !defined(WOLFSSL_MLDSA_NO_CTX)
    {
        wc_MlDsaKey noParams;
        byte  msg[8];
        byte  sig[8];
        int   res = 0;

        XMEMSET(&noParams, 0, sizeof(noParams));   /* params == NULL */
        XMEMSET(msg, 0x11, sizeof(msg));
        XMEMSET(sig, 0x22, sizeof(sig));

        /* operand 0 true: key == NULL (short-circuits before any deref). */
        (void)mldsa_verify_ctx_msg(NULL, NULL, 0, msg, (word32)sizeof(msg),
            sig, (word32)sizeof(sig), &res);
        /* operand 0 false, operand 1 true: key non-NULL, params NULL. */
        (void)mldsa_verify_ctx_msg(&noParams, NULL, 0, msg,
            (word32)sizeof(msg), sig, (word32)sizeof(sig), &res);

        (void)mldsa_verify_ctx_hash(NULL, NULL, 0, WC_HASH_TYPE_SHA256, msg,
            (word32)sizeof(msg), sig, (word32)sizeof(sig), &res);
        (void)mldsa_verify_ctx_hash(&noParams, NULL, 0, WC_HASH_TYPE_SHA256,
            msg, (word32)sizeof(msg), sig, (word32)sizeof(sig), &res);
    }
#endif

    {
        byte   oidBuf[64];
        word32 oidLen = 0;

        XMEMSET(oidBuf, 0, sizeof(oidBuf));
        /* Known algorithm: the (T,T) row. */
        oidLen = 0;
        (void)mldsa_get_hash_oid(WC_HASH_TYPE_SHA256, oidBuf, &oidLen);
        /* Unknown algorithm: no OID -> operand 0 false. */
        oidLen = 0;
        (void)mldsa_get_hash_oid(WC_HASH_TYPE_NONE, oidBuf, &oidLen);
        oidLen = 0;
        (void)mldsa_get_hash_oid(-1, oidBuf, &oidLen);
    }

    printf("  [wb] file-static argument-guard rows exercised\n");
}
#else
static void wb_arg_guards(void)
{
}
#endif

/* ------------------------------------------------------------------------- *
 * Verification failure rows.
 *
 * mldsa_verify_with_mu() threads a `valid` flag through a dozen
 *
 *     if ((ret == 0) && valid) { ... }
 *
 * guards: `valid` goes false when a decoded hint is malformed, a norm check
 * fails, or the recomputed commitment differs.  A campaign that only ever
 * verifies signatures it just produced sees valid == 1 at every one of them,
 * so the operand is undriven -- and a genuinely corrupt signature is the
 * ordinary, in-spec way to drive it.
 *
 * Single-bit flips are spread across the signature so different structural
 * parts (c-tilde, the z vector, the hint block, and its trailing padding)
 * fail, each tripping a different guard.  The valid signature is verified too
 * so every guard also has its true row in this binary; both rows are what the
 * independence pair needs.
 *
 * mldsa_verify_ctx_hash() gets its (F,F) row here as well: the key is real and
 * carries params, which is the one row a NULL/param-less key cannot show.
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_HAVE_MLDSA) && !defined(WOLFSSL_MLDSA_NO_SIGN) && \
    !defined(WOLFSSL_MLDSA_NO_VERIFY) && !defined(WOLFSSL_MLDSA_NO_MAKE_KEY)
static void wb_verify_invalid(void)
{
    static byte sig[MLDSA_MAX_SIG_SIZE];
    static byte bad[MLDSA_MAX_SIG_SIZE];
    wc_MlDsaKey key;
    byte        msg[32];
    byte        hash[32];
    byte        seed[MLDSA_SEED_SZ];
    word32      sigLen = (word32)sizeof(sig);
    int         res = 0;
    unsigned    i;
#ifndef WOLFSSL_NO_ML_DSA_44
    const int   level = WC_ML_DSA_44;   /* smallest set: fastest under cov */
#elif !defined(WOLFSSL_NO_ML_DSA_65)
    const int   level = WC_ML_DSA_65;
#else
    const int   level = WC_ML_DSA_87;
#endif

    XMEMSET(msg, 0x5a, sizeof(msg));
    XMEMSET(hash, 0x3e, sizeof(hash));
    XMEMSET(seed, 0x27, sizeof(seed));

    if (wc_MlDsaKey_Init(&key, NULL, INVALID_DEVID) != 0) {
        return;
    }
    if ((wc_MlDsaKey_SetParams(&key, level) != 0) ||
            (wc_MlDsaKey_MakeKeyFromSeed(&key, seed) != 0) ||
            (wc_MlDsaKey_SignCtxWithSeed(&key, NULL, 0, sig, &sigLen, msg,
                (word32)sizeof(msg), seed) != 0)) {
        wc_MlDsaKey_Free(&key);
        WB_NOTE("verification-failure rows skipped (sign unavailable)");
        return;
    }

    /* True row for every guard. */
    (void)wc_MlDsaKey_VerifyCtx(&key, sig, sigLen, NULL, 0, msg,
        (word32)sizeof(msg), &res);

    /* 24 flip positions spread across the whole signature: the leading
     * c-tilde, the packed z vector and the trailing hint block all decode
     * differently, so the failure surfaces at different guards. */
    for (i = 0; i < 24; i++) {
        word32 off = (word32)(((word64)i * sigLen) / 24U);

        XMEMCPY(bad, sig, sigLen);
        bad[off] = (byte)(bad[off] ^ 0x80);
        res = 0;
        (void)wc_MlDsaKey_VerifyCtx(&key, bad, sigLen, NULL, 0, msg,
            (word32)sizeof(msg), &res);
    }

    /* All-ones and all-zeros signatures: maximally malformed hint blocks. */
    XMEMSET(bad, 0xFF, sigLen);
    res = 0;
    (void)wc_MlDsaKey_VerifyCtx(&key, bad, sigLen, NULL, 0, msg,
        (word32)sizeof(msg), &res);
    XMEMSET(bad, 0x00, sigLen);
    res = 0;
    (void)wc_MlDsaKey_VerifyCtx(&key, bad, sigLen, NULL, 0, msg,
        (word32)sizeof(msg), &res);

    /* A different message against the good signature: everything decodes, the
     * recomputed commitment is what differs. */
    msg[0] ^= 0xFF;
    res = 0;
    (void)wc_MlDsaKey_VerifyCtx(&key, sig, sigLen, NULL, 0, msg,
        (word32)sizeof(msg), &res);
    msg[0] ^= 0xFF;

#if !defined(WOLFSSL_MLDSA_NO_CTX)
    /* mldsa_verify_ctx_hash() with a real, params-carrying key: the (F,F) row
     * of its (key == NULL) || (key->params == NULL) guard. */
    res = 0;
    (void)mldsa_verify_ctx_hash(&key, NULL, 0, WC_HASH_TYPE_SHA256, hash,
        (word32)sizeof(hash), sig, sigLen, &res);
#endif

    wc_MlDsaKey_Free(&key);
    printf("  [wb] verification-failure (valid == 0) rows exercised\n");
}
#else
static void wb_verify_invalid(void)
{
}
#endif

/* ------------------------------------------------------------------------- *
 * wc_MlDsaKey_CheckKey()'s s1/s2 coefficient range check (wc_mldsa.c:12517,
 * :12522, :12523).
 *
 *     for (c = 0; c < (word32)(params->l * MLDSA_N); c++) {
 *         if (s1[c] < -eta || s1[c] > eta) { ret = PUBLIC_KEY_E; break; }
 *     }
 *     for (c = 0; (ret == 0) && (c < (word32)(params->k * MLDSA_N)); c++) {
 *         if (s2[c] < -eta || s2[c] > eta) { ret = PUBLIC_KEY_E; break; }
 *     }
 *
 * Every key the API can hand this function was either generated (s1/s2 are in
 * range by construction) or decoded through mldsa_check_eta_range(), which
 * rejects an out-of-range nibble/3-bit group before the key is marked set. So
 * from tests/api the two `< -eta` operands only ever take their FALSE side and
 * the s2 loop header's `ret == 0` operand only ever takes its TRUE side.
 *
 * The vector is a MUTATED private key blob: a good key is generated, then the
 * first byte of the packed s1 (or s2) region of key->k is forced to 0xFF. The
 * eta unpackers read `eta - t` from an unsigned bit field -- t is a 3-bit
 * group for eta 2 and a nibble for eta 4 (mldsa_decode_eta_2_bits_c /
 * mldsa_decode_eta_4_bits_c) -- so 0xFF decodes the first coefficient as
 * 2 - 7 = -5 or 4 - 15 = -11, out of range on the LOW side for either
 * parameter set. The un-mutated CheckKey call in the same binary supplies the
 * all-false row of both `||` decisions and the `ret == 0` TRUE row; the s1
 * mutation supplies the s2 header's `ret == 0` FALSE row (the s1 loop has
 * already set PUBLIC_KEY_E when that header is next evaluated).
 *
 * The HIGH side (`s1[c] > eta`) is NOT driven here and cannot be: the unpack
 * is `eta - t` with t unsigned, so the decoded coefficient never exceeds eta.
 * Both `> eta` operands are recorded in campaign/db/exclusions.json.
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_HAVE_MLDSA) && defined(WOLFSSL_MLDSA_CHECK_KEY) && \
    !defined(WOLFSSL_MLDSA_NO_MAKE_KEY) && \
    !defined(WOLFSSL_MLDSA_ASSIGN_KEY) && defined(WOLFSSL_MLDSA_PRIVATE_KEY)
static void wb_check_key_range(void)
{
    wc_MlDsaKey key;
    byte        seed[MLDSA_SEED_SZ];
    byte*       kp;
    byte*       s1p;
    byte*       s2p;
    byte        savedS1;
    byte        savedS2;
    int         ret;
#ifndef WOLFSSL_NO_ML_DSA_44
    const int   level = WC_ML_DSA_44;   /* smallest set: fastest under cov */
#elif !defined(WOLFSSL_NO_ML_DSA_65)
    const int   level = WC_ML_DSA_65;
#else
    const int   level = WC_ML_DSA_87;
#endif

    XMEMSET(seed, 0x27, sizeof(seed));

    if (wc_MlDsaKey_Init(&key, NULL, INVALID_DEVID) != 0) {
        WB_NOTE("CheckKey range rows skipped (init failed)");
        return;
    }
    if ((wc_MlDsaKey_SetParams(&key, level) != 0) ||
            (wc_MlDsaKey_MakeKeyFromSeed(&key, seed) != 0)) {
        wc_MlDsaKey_Free(&key);
        WB_NOTE("CheckKey range rows skipped (keygen unavailable)");
        return;
    }

    /* All-false row of both range decisions, and the s2 header's ret == 0
     * true row: a well-formed key. */
    ret = wc_MlDsaKey_CheckKey(&key);
    if (ret != 0) {
        WB_NOTE("wc_MlDsaKey_CheckKey rejected a freshly generated key");
    }

    kp  = (byte*)key.k;
    s1p = kp + MLDSA_PUB_SEED_SZ + MLDSA_K_SZ + MLDSA_TR_SZ;
    s2p = s1p + key.params->s1EncSz;
    savedS1 = s1p[0];
    savedS2 = s2p[0];

    /* s1[0] out of range on the low side: :12517 idx0 true, and the s2 loop
     * header (:12522 idx0) is then evaluated with ret != 0. */
    s1p[0] = 0xFF;
    ret = wc_MlDsaKey_CheckKey(&key);
    if (ret == 0) {
        WB_NOTE("CheckKey accepted an out-of-range s1 coefficient");
    }
    s1p[0] = savedS1;

    /* s2[0] out of range: the s1 loop runs clean, the s2 header is true, and
     * :12523 idx0 takes its true side. */
    s2p[0] = 0xFF;
    ret = wc_MlDsaKey_CheckKey(&key);
    if (ret == 0) {
        WB_NOTE("CheckKey accepted an out-of-range s2 coefficient");
    }
    s2p[0] = savedS2;

    wc_MlDsaKey_Free(&key);
    WB_NOTE("CheckKey s1/s2 range rows exercised (12517, 12522, 12523)");
}
#else
static void wb_check_key_range(void)
{
    WB_NOTE("CheckKey range rows skipped (not compiled in this variant)");
}
#endif

int main(void)
{
    /* Unbuffered: on a timeout the process is killed and anything still
     * buffered is lost, which reads as an empty log. */
    setvbuf(stdout, NULL, _IONBF, 0);

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
    wb_check_hint_inner_loops();
#endif
#ifdef WOLFSSL_MLDSA_PRIVATE_KEY
    wb_check_eta_range();
#endif
#ifdef WOLFSSL_MLDSA_NO_ASN1
    wb_der_length();
    wb_check_type();
    wb_oid_to_level();
#endif
    wb_dispatch_rows();
    wb_gen_lane_rows();
    wb_arg_guards();
    wb_verify_invalid();
    wb_check_key_range();
    printf("done (%d note%s)\n", wb_notes, (wb_notes == 1) ? "" : "s");
    return 0;
#endif
}
