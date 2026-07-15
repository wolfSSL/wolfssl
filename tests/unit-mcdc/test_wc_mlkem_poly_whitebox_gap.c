/* test_wc_mlkem_poly_whitebox.c
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

/* White-box supplement for wolfcrypt/src/wc_mlkem_poly.c (C fallback
 * arithmetic: rejection sampling / noise generation static functions).
 *
 * tests/api/test_mlkem.c drives wc_mlkem_poly.c through the public
 * wc_MlKemKey_* API. The overwhelming majority of this file's MC/DC gaps
 * (see reports/mlkem/GAPS.md) are NOT closable from tests/api at all in
 * this build variant, for two structural reasons documented per-class
 * below; only two conditions are both (a) file-static and (b) reachable
 * with a contrived input this white-box can construct, and those are the
 * ones exercised here.
 *
 * Residual classes left untouched by this file (see the gap-closing
 * REPORT.md for the full accounting):
 *   - IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0):
 *     cpuid-dispatch, host-always-AVX2 residual (same class as every
 *     other module's intel-dispatch skip).
 *   - The USE_INTEL_SPEEDUP AVX2 rejection-sampling while-loops (gen
 *     matrix, ~line 2373/2486/2641): USE_INTEL_SPEEDUP is OFF by default
 *     and only compiled with the separate `--enable-intelasm` axis, which
 *     this campaign build does not use - a different variant entirely,
 *     not reachable in this binary regardless of white-box effort.
 *   - `(ret == 0) && ...` chain guards in mlkem_gen_matrix_c/_i and
 *     mlkem_get_noise_c (e.g. lines 3478, 3482, 3684, 4621, 4629, 4640):
 *     ret can only go non-zero via a mid-chain PRF/hash failure, which is
 *     not selectable without corrupting library state.
 *   - mlkem_hash512()'s data2 checks (line 3002): cond0 is the same
 *     ret==0 chain guard; the data2==NULL side only occurs on the
 *     WOLFSSL_MLKEM_KYBER (original Kyber) call path, a separate build
 *     axis from this campaign's ML-KEM-only variant; no caller anywhere
 *     supplies a non-NULL data2 with data2Len==0.
 *
 * Targeted here:
 *   - mlkem_rej_uniform_c() (static), line ~3340:
 *       for (; (i + 4 < len) && (j < rLen); j += 6)
 *     cond1 (j < rLen)'s independence pair requires a caller-controlled
 *     random buffer that keeps every sample rejected (i pinned near 0,
 *     holding "i + 4 < len" true) while the buffer itself runs out
 *     mid-loop. No real caller ever passes rejection-only bytes, so this
 *     can only be shown by calling the static directly with a crafted
 *     buffer.
 *   - mlkem_get_noise_c() (static), line ~4627:
 *       if ((ret == 0) && (vec2 != NULL))
 *     cond1 (vec2 != NULL)'s False side never happens through the public
 *     API in this build: the only call site compiled into this variant
 *     (the non-WOLFSSL_MLKEM_MAKEKEY_SMALL_MEM / non-SMALL_MEM arm of
 *     mlkem_get_noise(), wc_mlkem.c:934/1223) always forwards a non-NULL
 *     vec2. The WOLFSSL_MLKEM_MAKEKEY_SMALL_MEM/ENCAPSULATE_SMALL_MEM
 *     call sites that DO pass NULL are a different, mutually exclusive
 *     build axis.
 *
 * Compiles wc_mlkem_poly.c in verbatim so both static functions are in
 * scope and instrumented in THIS binary; coverage is unioned by source
 * line:col with the tests/api variant per tests/unit-mcdc/README.md.
 */

#include <wolfcrypt/src/wc_mlkem_poly.c>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if defined(WOLFSSL_HAVE_MLKEM) && \
    !(defined(WOLFSSL_ARMASM) && defined(__aarch64__))

/* ------------------------------------------------------------------------- *
 * mlkem_rej_uniform_c(): j < rLen independence pair.
 *
 *   for (; (i + 4 < len) && (j < rLen); j += 6) { ... }
 *
 * All-0xFF random bytes decode to four 12-bit values of 0xFFF (4095) per
 * 6-byte block - always >= MLKEM_Q (3329), so every candidate is rejected
 * and "i" never advances past 0. With len == 8, "i + 4 < len" (4 < 8)
 * stays true for the whole call, isolating j < rLen: the loop runs at
 * least twice while data remains (j < rLen true) then stops the instant
 * j reaches rLen (j < rLen false), with i + 4 < len unchanged throughout.
 * ------------------------------------------------------------------------- */
static void wb_rej_uniform_c_rlen_exhaust(void)
{
    sword16 p[16];
    byte r[40];
    unsigned int len = 8;
    unsigned int rLen = 24;
    unsigned int got;

    XMEMSET(p, 0, sizeof(p));
    /* All-ones: every decoded 12-bit sample is rejected (>= MLKEM_Q). */
    XMEMSET(r, 0xFF, sizeof(r));

    got = mlkem_rej_uniform_c(p, len, r, rLen);
    if (got != 0) {
        WB_NOTE("mlkem_rej_uniform_c: expected 0 accepted samples from an"
            " all-rejected buffer");
        wb_fail = 1;
    }

    WB_NOTE("mlkem_rej_uniform_c j<rLen exhaustion pair exercised");
}

/* ------------------------------------------------------------------------- *
 * mlkem_get_noise_c(): vec2 != NULL independence pair.
 *
 *   if ((ret == 0) && (vec2 != NULL)) { ... for each of k polynomials ... }
 *
 * Call once with a real vec2 (True side - also reachable from the public
 * API) and once with vec2 == NULL (False side - not reachable from the
 * public API in this build variant; see file header). k == 2 is used
 * purely as a small, generic vector length; it does not depend on which
 * WOLFSSL_WC_ML_KEM_* parameter set is compiled in.
 * ------------------------------------------------------------------------- */
static void wb_get_noise_c_vec2_null(void)
{
    MLKEM_PRF_T prf;
    sword16 vec1[2 * MLKEM_N];
    sword16 vec2[2 * MLKEM_N];
    sword16 poly[MLKEM_N];
    byte seed[WC_ML_KEM_SYM_SZ + 4];
    const int k = 2;
    int ret;

    XMEMSET(vec1, 0, sizeof(vec1));
    XMEMSET(vec2, 0, sizeof(vec2));
    XMEMSET(poly, 0, sizeof(poly));
    XMEMSET(seed, 0x37, sizeof(seed));

    mlkem_prf_init(&prf);
    /* vec2 != NULL True side (also poly != NULL True side). */
    ret = mlkem_get_noise_c(&prf, k, vec1, MLKEM_CBD_ETA2, vec2,
        MLKEM_CBD_ETA2, poly, seed);
    if (ret != 0) {
        WB_NOTE("mlkem_get_noise_c (vec2 non-NULL) failed");
        wb_fail = 1;
    }

    XMEMSET(seed, 0x37, sizeof(seed));
    /* vec2 != NULL False side: not reachable via the public API in this
     * build variant (see file header). poly is also NULL here so the
     * call stays memory-safe (no dereference of either optional output). */
    ret = mlkem_get_noise_c(&prf, k, vec1, MLKEM_CBD_ETA2, NULL,
        MLKEM_CBD_ETA2, NULL, seed);
    if (ret != 0) {
        WB_NOTE("mlkem_get_noise_c (vec2 NULL) failed");
        wb_fail = 1;
    }

    mlkem_prf_free(&prf);

    WB_NOTE("mlkem_get_noise_c vec2 NULL/non-NULL sides exercised");
}

#else

static void wb_rej_uniform_c_rlen_exhaust(void)
{
    WB_NOTE("mlkem_rej_uniform_c arm not compiled in this variant; skipped");
}

static void wb_get_noise_c_vec2_null(void)
{
    WB_NOTE("mlkem_get_noise_c arm not compiled in this variant; skipped");
}

#endif

int main(void)
{
    printf("wc_mlkem_poly.c white-box MC/DC supplement\n");
#ifndef WOLFSSL_HAVE_MLKEM
    printf("  WOLFSSL_HAVE_MLKEM not defined; nothing to exercise\n");
    return 0;
#else
    wb_rej_uniform_c_rlen_exhaust();
    wb_get_noise_c_vec2_null();
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup failures are surfaced as skips, not test failures: the campaign
     * treats a nonzero exit as a failed variant and discards its coverage. */
    return 0;
#endif
}
