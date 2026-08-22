/* test_mlkem_poly_hash_fault_whitebox.c
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
 * MC/DC hash-fault white-box supplement for wolfcrypt/src/wc_mlkem_poly.c.
 *
 * suite/reports/mlkem/the uncovered-condition report leaves ten residuals on this file and all ten
 * are the FALSE half of a success chain or an optional-argument guard that the
 * public wc_MlKemKey_* API never produces:
 *
 *     mlkem_hash512()     if ((ret == 0) && (data2 != NULL) && (data2Len > 0))
 *     mlkem_gen_matrix_c()  for (i = 0; (ret == 0) && (i < k); i++, ...)
 *                           for (j = 0; (ret == 0) && (j < k); j++)
 *     mlkem_gen_matrix_i()  for (j = 0; (ret == 0) && (j < k); j++)
 *     mlkem_get_noise_c()   for (i = 0; (ret == 0) && (i < k); i++)
 *                           if ((ret == 0) && (vec2 != NULL))
 *                           for (i = 0; (ret == 0) && (i < k); i++)
 *                           if ((ret == 0) && (poly != NULL))
 *
 * TWO LEVERS, NO KEYGEN
 * ---------------------
 * All four helpers are file-static (or WOLFSSL_LOCAL) and this TU #includes
 * wc_mlkem_poly.c, so each is called DIRECTLY with the operand combination the
 * API cannot produce. No key generation is performed at all, which keeps the
 * whole binary well inside the wall-clock budget.
 *
 *   1. mlkem_hash512()'s three conditions need no injector:
 *        - data2 == NULL and data2Len == 0 are simply passed in;
 *        - ret != 0 is produced by data1 == NULL with data1Len > 0, which
 *          wc_Sha3Update() rejects with BAD_FUNC_ARG (sha3.c checks
 *          `data == NULL && len == 0` first, so this is the one NULL form that
 *          is an error rather than a no-op). The hash object itself stays
 *          valid, and wc_Sha3_512_Final() is never reached because ret is
 *          already non-zero.
 *
 *   2. The three chain-driven helpers take their `ret` exclusively from
 *      mlkem_xof_absorb() / mlkem_xof_squeezeblocks() (wc_Shake128_Absorb,
 *      wc_Shake128_SqueezeBlocks) and mlkem_prf() (wc_Shake256_Update,
 *      wc_Shake256_Final). None of those allocates, so mcdc_fault_alloc.h has
 *      nothing to break; mcdc_fault_hash.h macro-interposes them for THIS
 *      translation unit only and mcdc_fh_arm(n) makes the n-th primitive call
 *      -- and every later one -- return BAD_FUNC_ARG.
 *
 * The sweep is a short dense range (1..WB_SWEEP) per helper. Each helper's
 * whole chain is only a handful of primitive calls deep, and index 1 alone
 * already drives the first loop condition false; the deeper indices are what
 * reach mlkem_get_noise_c()'s SECOND vector loop, whose (ret == 0) operand can
 * only go false after the first k noise polynomials have succeeded.
 *
 * PAIRING: every helper is run DISARMED first, which is the (T,T,..) row for
 * the same decisions, so both halves of each independence pair land in this
 * one binary (HARD RULE 1).
 *
 * NOT REACHABLE HERE: under USE_INTEL_SPEEDUP mlkem_prf() writes the Keccak
 * state directly (sha3_block_bmi2 / sha3_block_avx2 / BlockSha3) and returns a
 * literal 0, so mlkem_get_noise_c()'s chain cannot be broken in the mlkem_avx2
 * variant. The six portable-C variants supply those rows and the harness
 * unions by line:col.
 *
 * VARIANT COVERAGE (HARD RULE 2): every helper is behind the same #if the
 * library uses for it, with an #else skip stub, and main() always returns 0.
 */

#include "mcdc_fault_hash.h"

/* wc_mlkem_poly.c is #included AFTER the interposers are installed. */
#include <wolfcrypt/src/wc_mlkem_poly.c>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

/* Dense head: the deepest chain here (mlkem_get_noise_c with k == 2) is well
 * under 32 primitive calls, so a fixed dense sweep both terminates quickly and
 * is completely deterministic (HARD RULE 3 -- a vector count, never a clock). */
#define WB_SWEEP  40

/* Small, generic vector length. It is not tied to a compiled parameter set:
 * every helper below takes k as a plain argument. */
#define WB_K      2

#if defined(WOLFSSL_HAVE_MLKEM) && \
    !(defined(WOLFSSL_ARMASM) && defined(__aarch64__))

/* ------------------------------------------------------------------------- *
 * mlkem_hash512(): all three conditions of
 *     if ((ret == 0) && (data2 != NULL) && (data2Len > 0))
 * ------------------------------------------------------------------------- */
static void wb_hash512_rows(void)
{
    MLKEM_HASH_T hash;
    byte    d1[32];
    byte    d2[32];
    byte    out[WC_SHA3_512_DIGEST_SIZE];

    XMEMSET(d1, 0x11, sizeof(d1));
    XMEMSET(d2, 0x22, sizeof(d2));
    XMEMSET(out, 0, sizeof(out));

    if (mlkem_hash_new(&hash, NULL, INVALID_DEVID) != 0) {
        WB_NOTE("mlkem_hash_new failed; hash512 rows skipped");
        wb_fail = 1;
        return;
    }

    /* (T,T,T): both blocks present -- also the API's own row. */
    if (mlkem_hash512(&hash, d1, (word32)sizeof(d1), d2, (word32)sizeof(d2),
            out) != 0) {
        WB_NOTE("mlkem_hash512 two-block call failed");
        wb_fail = 1;
    }

    /* (T,F,-): no second block. */
    if (mlkem_hash512(&hash, d1, (word32)sizeof(d1), NULL, 0, out) != 0) {
        WB_NOTE("mlkem_hash512 data2 == NULL call failed");
        wb_fail = 1;
    }

    /* (T,T,F): second block present but empty. */
    if (mlkem_hash512(&hash, d1, (word32)sizeof(d1), d2, 0, out) != 0) {
        WB_NOTE("mlkem_hash512 data2Len == 0 call failed");
        wb_fail = 1;
    }

    /* (F,-,-): the first Update fails, so the second is never evaluated.
     * data1 == NULL with a non-zero length is BAD_FUNC_ARG in wc_Sha3Update();
     * the object is left untouched and Final is not reached. */
    if (mlkem_hash512(&hash, NULL, 1, d2, (word32)sizeof(d2), out) == 0) {
        WB_NOTE("mlkem_hash512 accepted a NULL first block");
        wb_fail = 1;
    }

    mlkem_hash_free(&hash);
    WB_NOTE("mlkem_hash512 data2/data2Len/ret rows exercised");
}

/* ------------------------------------------------------------------------- *
 * mlkem_get_noise_c(): the (ret == 0) operand of both vector loops and of the
 * vec2 / poly guards.
 * ------------------------------------------------------------------------- */
static void wb_get_noise_rows(void)
{
    MLKEM_PRF_T prf;
    static sword16 vec1[WB_K * MLKEM_N];
    static sword16 vec2[WB_K * MLKEM_N];
    static sword16 poly[MLKEM_N];
    byte    seed[WC_ML_KEM_SYM_SZ + 4];
    long    n;

    mlkem_prf_init(&prf);

    /* Disarmed: the all-true row for every decision below. */
    XMEMSET(seed, 0x37, sizeof(seed));
    mcdc_fh_disarm();
    if (mlkem_get_noise_c(&prf, WB_K, vec1, MLKEM_CBD_ETA2, vec2,
            MLKEM_CBD_ETA2, poly, seed) != 0) {
        WB_NOTE("baseline mlkem_get_noise_c failed");
        wb_fail = 1;
    }

    /* Armed: index 1 breaks the FIRST vector loop; the deeper indices land in
     * the second loop, which is the only way its own (ret == 0) operand and
     * the poly guard's can be driven false while vec2/poly stay non-NULL. */
    for (n = 1; n <= (long)WB_SWEEP; n++) {
        XMEMSET(seed, 0x37, sizeof(seed));
        mcdc_fh_arm(n);
        (void)mlkem_get_noise_c(&prf, WB_K, vec1, MLKEM_CBD_ETA2, vec2,
            MLKEM_CBD_ETA2, poly, seed);
        mcdc_fh_disarm();
    }

    mlkem_prf_free(&prf);
    WB_NOTE("mlkem_get_noise_c success-chain rows exercised");
}

#else

static void wb_hash512_rows(void)
{
    WB_NOTE("mlkem_hash512 arm not compiled in this variant; skipped");
}

static void wb_get_noise_rows(void)
{
    WB_NOTE("mlkem_get_noise_c arm not compiled in this variant; skipped");
}

#endif

/* ------------------------------------------------------------------------- *
 * mlkem_gen_matrix_c(): the (ret == 0) operand of the vector and polynomial
 * loops. Compiled unless BOTH small-mem arms are on.
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_HAVE_MLKEM) && \
    !(defined(WOLFSSL_ARMASM) && defined(__aarch64__)) && \
    (!defined(WOLFSSL_MLKEM_MAKEKEY_SMALL_MEM) || \
     !defined(WOLFSSL_MLKEM_ENCAPSULATE_SMALL_MEM))

static void wb_gen_matrix_c_rows(void)
{
    MLKEM_PRF_T    prf;
    static sword16 a[WB_K * WB_K * MLKEM_N];
    byte           seed[WC_ML_KEM_SYM_SZ + 2];
    long           n;

    mlkem_prf_init(&prf);
    XMEMSET(seed, 0x5c, sizeof(seed));

    mcdc_fh_disarm();
    if (mlkem_gen_matrix_c(&prf, a, WB_K, seed, 0) != 0) {
        WB_NOTE("baseline mlkem_gen_matrix_c failed");
        wb_fail = 1;
    }

    for (n = 1; n <= (long)WB_SWEEP; n++) {
        mcdc_fh_arm(n);
        (void)mlkem_gen_matrix_c(&prf, a, WB_K, seed, 0);
        mcdc_fh_disarm();
        mcdc_fh_arm(n);
        (void)mlkem_gen_matrix_c(&prf, a, WB_K, seed, 1);
        mcdc_fh_disarm();
    }

    mlkem_prf_free(&prf);
    WB_NOTE("mlkem_gen_matrix_c success-chain rows exercised");
}

#else

static void wb_gen_matrix_c_rows(void)
{
    WB_NOTE("mlkem_gen_matrix_c arm not compiled in this variant; skipped");
}

#endif

/* ------------------------------------------------------------------------- *
 * mlkem_gen_matrix_i(): the small-memory single-row generator. Only compiled
 * when one of the small-mem arms is on.
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_HAVE_MLKEM) && \
    !(defined(WOLFSSL_ARMASM) && defined(__aarch64__)) && \
    (defined(WOLFSSL_MLKEM_MAKEKEY_SMALL_MEM) || \
     defined(WOLFSSL_MLKEM_ENCAPSULATE_SMALL_MEM))

static void wb_gen_matrix_i_rows(void)
{
    MLKEM_PRF_T    prf;
    static sword16 a[WB_K * MLKEM_N];
    byte           seed[WC_ML_KEM_SYM_SZ + 2];
    long           n;

    mlkem_prf_init(&prf);
    XMEMSET(seed, 0x5c, sizeof(seed));

    mcdc_fh_disarm();
    if (mlkem_gen_matrix_i(&prf, a, WB_K, seed, 0, 0) != 0) {
        WB_NOTE("baseline mlkem_gen_matrix_i failed");
        wb_fail = 1;
    }

    for (n = 1; n <= (long)WB_SWEEP; n++) {
        mcdc_fh_arm(n);
        (void)mlkem_gen_matrix_i(&prf, a, WB_K, seed, 0, 0);
        mcdc_fh_disarm();
        mcdc_fh_arm(n);
        (void)mlkem_gen_matrix_i(&prf, a, WB_K, seed, 1, 1);
        mcdc_fh_disarm();
    }

    mlkem_prf_free(&prf);
    WB_NOTE("mlkem_gen_matrix_i success-chain rows exercised");
}

#else

static void wb_gen_matrix_i_rows(void)
{
    WB_NOTE("mlkem_gen_matrix_i arm not compiled in this variant; skipped");
}

#endif

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("wc_mlkem_poly.c hash-fault white-box supplement\n");

    mcdc_fh_disarm();
    wb_hash512_rows();
    wb_gen_matrix_c_rows();
    wb_gen_matrix_i_rows();
    wb_get_noise_rows();
    mcdc_fh_disarm();

    printf("done (%s)\n", wb_fail ? "with failures" : "ok");
    /* A non-zero exit makes the harness discard this binary's coverage. */
    return 0;
}
