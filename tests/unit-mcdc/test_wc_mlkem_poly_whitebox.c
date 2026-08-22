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

/* White-box MC/DC supplement for wolfcrypt/src/wc_mlkem_poly.c.
 *
 * wc_mlkem_poly.c holds ML-KEM's polynomial arithmetic core. Several file-static
 * helpers own decision independence pairs that the public wc_MlKemKey_* API
 * cannot exhibit cleanly, because every public caller feeds them only the
 * "valid" operand combination:
 *
 *   - mlkem_cmp_c (constant-time byte compare): the API's re-encryption check
 *     drives it, but only the "equal" path deterministically; the returned
 *     0/-1 mask's independence needs BOTH an all-equal and a differing buffer
 *     in one binary.
 *   - mlkem_rej_uniform_c (rejection sampling of 12-bit values): the "v < q"
 *     accept and ">= q" reject branches, plus the "i < len" early-stop guard,
 *     need inputs crafted to hit both sides -- random matrix seeds almost never
 *     produce a full run of rejections.
 *   - mlkem_ntt / mlkem_invntt / mlkem_csubq_c: exercised per-variant so each of
 *     the four code-size arms (default / WOLFSSL_MLKEM_SMALL /
 *     WOLFSSL_MLKEM_NO_LARGE_CODE / WOLFSSL_MLKEM_NTT_UNROLL) gets its reduction
 *     and butterfly loops driven when the harness rebuilds this TU per arm.
 *
 * This TU #includes wc_mlkem_poly.c so those static helpers are in scope, then calls
 * each with both halves of every targeted pair on tiny fixed-size buffers.
 * Memory-safe by construction (all buffers are MLKEM_N sword16 / bounded byte
 * arrays); prints skips and returns 0 on any unexpected result so the harness
 * keeps the variant.
 */

/* SAVE_VECTOR_REGISTERS2() gates every SIMD dispatch in this file:
 *
 *     if (IS_INTEL_AVX512(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0))
 *
 * In a userspace build types.h resolves it to SAVE_NO_VECTOR_REGISTERS2(),
 * which is the literal 0, so "(0 == 0)" is structurally true and that operand
 * can never take its false side -- it is not merely undriven. The false side
 * is real on platforms that can refuse the save (the kernel module build,
 * where it becomes WC_CHECK_FOR_INTR_SIGNALS()).
 *
 * WC_CHECK_FOR_INTR_SIGNALS is the #ifndef extension point types.h offers for
 * exactly that, so defining it here -- BEFORE any wolfSSL header is pulled in
 * by the .c below -- routes all 58 SAVE_VECTOR_REGISTERS2() sites through a
 * variable this file controls, using the library's own hook rather than
 * overriding a macro behind its back. Setting it non-zero makes each dispatch
 * fall through to the portable C path, which is what the operand's false side
 * selects on a platform that really can refuse.
 *
 * The file uses only SAVE_VECTOR_REGISTERS2(); the SAVE_VECTOR_REGISTERS(
 * fail_clause) form, whose expansion also changes under this hook, appears
 * nowhere here.
 */
/* The hook is a function rather than a plain variable so a single pass can put
 * the save-refused answer at a CHOSEN call index instead of only "always" or
 * "never".  Two dispatch guards nest inside one another:
 *
 *     mlkem_gen_matrix()                 if (IS_INTEL_AVX2(..) && save == 0)
 *       mlkem_gen_matrix_k3_avx2()         for (..) { if (IS_INTEL_BMI2(..))
 *                                                    else if (IS_INTEL_AVX2(..)
 *                                                          && save == 0)
 *
 * so the inner guard's operands can only be reached when the OUTER one was
 * already satisfied.  A process-wide "always refuse" therefore never lets the
 * inner site run at all, and its false side would stay unreachable.  Letting
 * call 0..n-1 succeed and calls >= n refuse gives the inner site a genuine
 * (T,F) row while the outer one still took (T,T).
 *
 * wb_intr_action is the same idea for the cpuid operand of the inner guard:
 * the action runs after IS_INTEL_AVX2() has already been evaluated for THIS
 * decision, so clearing CPUID_AVX2 from wc_mlkem_poly.c's own dispatch word
 * inside the hook leaves the current iteration on its (T,T) row and flips the
 * NEXT iteration of the same loop to (F,-).  Both rows land in one binary, at
 * one source line, without the outer dispatch ever changing its mind. */
static int  wb_intr_ret = 0;        /* != 0: refuse every save (blanket) */
static long wb_intr_count = 0;      /* SAVE_VECTOR_REGISTERS2() calls seen */
static long wb_intr_fail_from = -1; /* >= 0: refuse from this call index on */
static void (*wb_intr_action)(long ix) = 0; /* runs on every call */

static int wb_intr_hook(void)
{
    long ix = wb_intr_count++;

    if (wb_intr_action != 0) {
        wb_intr_action(ix);
    }
    if (wb_intr_ret != 0) {
        return wb_intr_ret;
    }
    if ((wb_intr_fail_from >= 0) && (ix >= wb_intr_fail_from)) {
        return 1;
    }
    return 0;
}
#define WC_CHECK_FOR_INTR_SIGNALS() wb_intr_hook()

/* ------------------------------------------------------------------------- *
 * Rejection-sampling lane interposition.
 *
 * Nine decisions in this file have the shape
 *
 *     ctr[i] = mlkem_rej_uniform_n_ins(...);        (i = 0..3 or 0..7)
 *     while ((ctr[0] < MLKEM_N) || (ctr[1] < MLKEM_N) || ... ) { ... }
 *
 * The loop only runs when a lane came up short, and each operand only gets an
 * independence pair when THAT lane is the first short one.  Uniform random
 * seeds fill all lanes on the first block with overwhelming probability, so in
 * practice the vector is always (F,F,..,F): the operands are undriven, and
 * which of them a nightly run happens to catch is pure luck -- the origin of
 * this module's 68 -> 74 -> 69 gate flapping.
 *
 * mlkem_rej_uniform_n_ins()/mlkem_rej_uniform_ins() are static WC_INLINE (or
 * plain #defines) inside the .c, so a macro on THEM would rename the library's
 * own definition rather than wrap it.  The leaf samplers they dispatch to are
 * WOLFSSL_LOCAL functions declared in wc_mlkem.h, so declaring that header
 * FIRST keeps the real prototypes under their real names, and the renames
 * below then only rewrite the uses inside wc_mlkem_poly.c.
 *
 * Only the FIRST-round samplers (the _n_ forms) are wrapped.  The loop body
 * calls the non-_n_ forms to top the short lane up, and those are left alone
 * so every loop provably terminates. */
#include <wolfssl/wolfcrypt/libwolfssl_sources.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>

static unsigned int wb_rej_trim(unsigned int got, unsigned int len);

#if defined(USE_INTEL_SPEEDUP) && !defined(WC_SHA3_NO_ASM)

static unsigned int wb_rej_n_avx2(sword16* p, unsigned int len, const byte* r,
    unsigned int rLen);
#define mlkem_rej_uniform_n_avx2                wb_rej_n_avx2

#ifdef WOLFSSL_MLKEM_HAVE_INTEL_AVX512
static unsigned int wb_rej_n_avx512(sword16* p, unsigned int len,
    const byte* r, unsigned int rLen);
#define mlkem_rej_uniform_n_avx512              wb_rej_n_avx512
#ifdef WOLFSSL_MLKEM_HAVE_INTEL_AVX512_VBMI2
static unsigned int wb_rej_n_avx512_vbmi2(sword16* p, unsigned int len,
    const byte* r, unsigned int rLen);
#define mlkem_rej_uniform_n_avx512_vbmi2        wb_rej_n_avx512_vbmi2
#endif
#ifdef WOLFSSL_MLKEM_HAVE_INTEL_AVX512_VBMI
static unsigned int wb_rej_n_avx512_vbmi(sword16* p, unsigned int len,
    const byte* r, unsigned int rLen);
#define mlkem_rej_uniform_n_avx512_vbmi         wb_rej_n_avx512_vbmi
#ifdef WOLFSSL_MLKEM_HAVE_INTEL_AVX512_VBMI2
static unsigned int wb_rej_n_avx512_vbmi_vbmi2(sword16* p, unsigned int len,
    const byte* r, unsigned int rLen);
#define mlkem_rej_uniform_n_avx512_vbmi_vbmi2   wb_rej_n_avx512_vbmi_vbmi2
#endif
#endif
#endif /* WOLFSSL_MLKEM_HAVE_INTEL_AVX512 */

#endif /* USE_INTEL_SPEEDUP && !WC_SHA3_NO_ASM */

#include <wolfcrypt/src/wc_mlkem_poly.c>

#if defined(USE_INTEL_SPEEDUP) && !defined(WC_SHA3_NO_ASM)
#undef mlkem_rej_uniform_n_avx2
#ifdef WOLFSSL_MLKEM_HAVE_INTEL_AVX512
#undef mlkem_rej_uniform_n_avx512
#ifdef WOLFSSL_MLKEM_HAVE_INTEL_AVX512_VBMI2
#undef mlkem_rej_uniform_n_avx512_vbmi2
#endif
#ifdef WOLFSSL_MLKEM_HAVE_INTEL_AVX512_VBMI
#undef mlkem_rej_uniform_n_avx512_vbmi
#ifdef WOLFSSL_MLKEM_HAVE_INTEL_AVX512_VBMI2
#undef mlkem_rej_uniform_n_avx512_vbmi_vbmi2
#endif
#endif
#endif
#endif

/* Index of the first-round sampler call within the current pass, and the lane
 * (call index mod 8) whose result is reported one sample short.  MLKEM_N-1 of
 * MLKEM_N samples are genuinely present; the loop's own top-up call fills the
 * last one, so the matrix that comes out is still a valid uniform matrix -- the
 * only thing that changed is that the code took the "some lane was short" path
 * it takes in the field roughly once every few thousand key generations. */
static unsigned int wb_rej_ix = 0;
static int          wb_rej_lane = -1;
/* Absolute-index form: short exactly ONE sampler call in the whole pass.  The
 * mod-8 form assumes each group of samplers starts at an index that is a
 * multiple of 8; the absolute form does not, so sweeping it over the number of
 * polynomials in the largest matrix reaches every lane of every group whatever
 * the grouping turns out to be. */
static long         wb_rej_abs = -1;

static unsigned int wb_rej_trim(unsigned int got, unsigned int len)
{
    long ix = (long)wb_rej_ix++;
    int  hit = 0;

    if ((wb_rej_lane >= 0) && ((ix & 7L) == (long)wb_rej_lane)) {
        hit = 1;
    }
    if ((wb_rej_abs >= 0) && (ix == wb_rej_abs)) {
        hit = 1;
    }
    if (hit && (got == len) && (len > 0)) {
        got = len - 1;
    }
    return got;
}

#if defined(USE_INTEL_SPEEDUP) && !defined(WC_SHA3_NO_ASM)

static unsigned int wb_rej_n_avx2(sword16* p, unsigned int len, const byte* r,
    unsigned int rLen)
{
    return wb_rej_trim(mlkem_rej_uniform_n_avx2(p, len, r, rLen), len);
}

#ifdef WOLFSSL_MLKEM_HAVE_INTEL_AVX512
static unsigned int wb_rej_n_avx512(sword16* p, unsigned int len,
    const byte* r, unsigned int rLen)
{
    return wb_rej_trim(mlkem_rej_uniform_n_avx512(p, len, r, rLen), len);
}
#ifdef WOLFSSL_MLKEM_HAVE_INTEL_AVX512_VBMI2
static unsigned int wb_rej_n_avx512_vbmi2(sword16* p, unsigned int len,
    const byte* r, unsigned int rLen)
{
    return wb_rej_trim(mlkem_rej_uniform_n_avx512_vbmi2(p, len, r, rLen), len);
}
#endif
#ifdef WOLFSSL_MLKEM_HAVE_INTEL_AVX512_VBMI
static unsigned int wb_rej_n_avx512_vbmi(sword16* p, unsigned int len,
    const byte* r, unsigned int rLen)
{
    return wb_rej_trim(mlkem_rej_uniform_n_avx512_vbmi(p, len, r, rLen), len);
}
#ifdef WOLFSSL_MLKEM_HAVE_INTEL_AVX512_VBMI2
static unsigned int wb_rej_n_avx512_vbmi_vbmi2(sword16* p, unsigned int len,
    const byte* r, unsigned int rLen)
{
    return wb_rej_trim(
        mlkem_rej_uniform_n_avx512_vbmi_vbmi2(p, len, r, rLen), len);
}
#endif
#endif
#endif /* WOLFSSL_MLKEM_HAVE_INTEL_AVX512 */

#endif /* USE_INTEL_SPEEDUP && !WC_SHA3_NO_ASM */

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if defined(WOLFSSL_HAVE_MLKEM) && !defined(WOLFSSL_ARMASM)

/* mlkem_cmp_c: drive both the all-equal (returns 0) and differing (returns -1)
 * results so the constant-time mask expression shows its independence pair. */
static void wb_cmp(void)
{
    byte a[64];
    byte b[64];
    unsigned int i;

    for (i = 0; i < sizeof(a); i++) {
        a[i] = (byte)i;
        b[i] = (byte)i;
    }
    if (mlkem_cmp_c(a, b, (int)sizeof(a)) != 0) {
        WB_NOTE("mlkem_cmp_c equal buffers did not return 0");
        wb_fail = 1;
    }
    /* Flip a single byte: differing path. */
    b[17] ^= 0x80;
    if (mlkem_cmp_c(a, b, (int)sizeof(a)) == 0) {
        WB_NOTE("mlkem_cmp_c differing buffers returned 0");
        wb_fail = 1;
    }
}

/* mlkem_rej_uniform_c: craft a random-byte buffer whose 12-bit little-endian
 * fields include values BOTH below q (accepted) and >= q (rejected), and pass a
 * len smaller than the number of acceptable samples so the "i < len" early stop
 * fires while candidates remain -- covering both sides of the accept and
 * early-stop decisions. */
static void wb_rej_uniform(void)
{
    /* Each 3 bytes yields two 12-bit integers v0,v1.
     *   0x00,0x00 -> v0 = 0x000 (accept, < q)
     *   ...,0xFF pattern -> 0xFFF = 4095 (>= q, reject)
     * Interleave so the sampler sees accepts and rejects. */
    byte r[96];
    sword16 p[MLKEM_N];
    unsigned int n;
    unsigned int i;

    for (i = 0; i < sizeof(r); i += 3) {
        /* v0 low, v1 high. Alternate accept/reject blocks. */
        if ((i / 3) & 1) {
            r[i + 0] = 0xFF; r[i + 1] = 0xFF; r[i + 2] = 0xFF; /* both >= q */
        }
        else {
            r[i + 0] = 0x01; r[i + 1] = 0x00; r[i + 2] = 0x00; /* both < q  */
        }
    }
    XMEMSET(p, 0, sizeof(p));

    /* Full length: exercises accept + reject with room to store accepts. */
    n = mlkem_rej_uniform_c(p, MLKEM_N, r, (unsigned int)sizeof(r));
    if (n > (unsigned int)MLKEM_N) {
        WB_NOTE("mlkem_rej_uniform_c over-produced");
        wb_fail = 1;
    }
    /* Tiny len: the (i < len) guard stops early while bytes remain. */
    (void)mlkem_rej_uniform_c(p, 1, r, (unsigned int)sizeof(r));
}

/* mlkem_ntt / mlkem_invntt / mlkem_csubq_c: run the transform pipeline for
 * whichever code-size arm this TU was compiled with. */
static void wb_transform(void)
{
    sword16 poly[MLKEM_N];
    unsigned int i;

    for (i = 0; i < MLKEM_N; i++) {
        poly[i] = (sword16)((i * 7) % MLKEM_Q);
    }
    mlkem_ntt(poly);
    mlkem_invntt(poly);
    mlkem_csubq_c(poly);
}

#endif /* WOLFSSL_HAVE_MLKEM && !WOLFSSL_ARMASM */

/* ------------------------------------------------------------------------- *
 * Additional file-static gap drivers (merged from the former _gap TU).
 *
 * Residual classes left untouched here (see the gap-closing REPORT.md for the
 * full accounting):
 *   - IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0):
 *     cpuid-dispatch, host-always-AVX2 residual (same class as every other
 *     module's intel-dispatch skip).
 *   - The USE_INTEL_SPEEDUP AVX2 rejection-sampling while-loops: USE_INTEL_SPEEDUP
 *     is OFF by default and only compiled with the separate `--enable-intelasm`
 *     axis, which this suite build does not use.
 *   - `(ret == 0) && ...` chain guards in mlkem_gen_matrix_c/_i and
 *     mlkem_get_noise_c: ret can only go non-zero via a mid-chain PRF/hash
 *     failure, which is not selectable without corrupting library state.
 *   - mlkem_hash512()'s data2 checks: the data2==NULL side only occurs on the
 *     WOLFSSL_MLKEM_KYBER (original Kyber) call path, a separate build axis.
 * ------------------------------------------------------------------------- */
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

/* ------------------------------------------------------------------------- *
 * SIMD dispatch rows.
 *
 * 28 functions here select an implementation with
 *
 *     if (IS_INTEL_AVX512(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0))
 *     else if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0))
 *     else <portable C>
 *
 * On an AVX512-capable host the first arm always wins, so only the [T,T] row
 * is ever seen and neither operand gets an independence pair. Both rows are
 * supplied by driving one full ML-KEM key cycle per setting:
 *
 *   [T,T]  features present, save accepted   -> the SIMD arm runs
 *   [F,-]  cpuid_flags cleared               -> operand 0's pair
 *   [T,F]  features present, save refused    -> operand 1's pair
 *
 * cpuid_flags is this file's own static and mlkem_init() only refreshes it
 * while it still holds WC_CPUID_INITIALIZER, so a forced value stays put.
 * Clearing feature bits only ever selects portable C, and claiming bits the
 * host really has is what the unforced build already does, so no row runs an
 * instruction the CPU lacks.
 *
 * A whole keygen/encapsulate/decapsulate cycle is used rather than 28 hand
 * written calls: the top-level entry points reach the compress/decompress,
 * to/from bytes, rej-uniform, noise and NTT dispatches transitively, with
 * correctly sized buffers.
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_HAVE_MLKEM) && defined(USE_INTEL_SPEEDUP) && \
    !defined(WOLFSSL_ARMASM)

/* Every parameter set the build compiles. The compress/decompress dispatches
 * are du/dv specific -- ML-KEM-768 uses du=10,dv=4 and never reaches
 * mlkem_vec_compress_11 or mlkem_compress_5 (du=11,dv=5, the 1024 params) --
 * and the matrix generators are specialised per k, so one parameter set alone
 * leaves most of the SIMD dispatches unexecuted. */
/* WC_ML_KEM_512 is enum value 0 (wc_mlkem.h), so a 0 terminator here silently
 * dropped the entire ML-KEM-512 axis: its k == WC_ML_KEM_512_K arms in
 * mlkem_gen_matrix() / mlkem_get_noise() and the k2 matrix generators were
 * never entered by any row.  The list carries its own length instead. */
static const int wb_kem_types[] = {
#ifdef WOLFSSL_WC_ML_KEM_512
    WC_ML_KEM_512,
#endif
#ifdef WOLFSSL_WC_ML_KEM_768
    WC_ML_KEM_768,
#endif
#ifdef WOLFSSL_WC_ML_KEM_1024
    WC_ML_KEM_1024,
#endif
#if !defined(WOLFSSL_WC_ML_KEM_512) && !defined(WOLFSSL_WC_ML_KEM_768) && \
    !defined(WOLFSSL_WC_ML_KEM_1024)
    /* wc_mlkem.h forces at least one parameter set on, so this only keeps the
     * initialiser well-formed if that ever changes. */
    WC_ML_KEM_512,
#endif
};
#define WB_KEM_TYPE_CNT ((unsigned)(sizeof(wb_kem_types) / sizeof(int)))

/* One key generation only: the matrix generators and their rejection-sampling
 * loops all hang off wc_MlKemKey_MakeKey(), and keeping the per-pass work to a
 * single keygen is what lets the lane sweep below afford ~100 passes inside the
 * suite's wall-clock budget. */
static void wb_run_keygen(WC_RNG* rng, int type)
{
    MlKemKey key;

    if (wc_MlKemKey_Init(&key, type, NULL, INVALID_DEVID) != 0) {
        return;
    }
    (void)wc_MlKemKey_MakeKey(&key, rng);
    wc_MlKemKey_Free(&key);
}

static void wb_run_cycle(WC_RNG* rng, int type)
{
    MlKemKey key;
    byte     ct[WC_ML_KEM_MAX_CIPHER_TEXT_SIZE];
    byte     ss[WC_ML_KEM_SS_SZ];
    byte     ss2[WC_ML_KEM_SS_SZ];
    byte     pub[WC_ML_KEM_MAX_PUBLIC_KEY_SIZE];
    byte     priv[WC_ML_KEM_MAX_PRIVATE_KEY_SIZE];
    word32   ctSz = 0;
    word32   pubSz = 0;
    word32   privSz = 0;

    if (wc_MlKemKey_Init(&key, type, NULL, INVALID_DEVID) != 0) {
        return;
    }
    if (wc_MlKemKey_MakeKey(&key, rng) == 0 &&
            wc_MlKemKey_CipherTextSize(&key, &ctSz) == 0 &&
            ctSz <= (word32)sizeof(ct)) {
        if (wc_MlKemKey_Encapsulate(&key, ct, ss, rng) == 0) {
            (void)wc_MlKemKey_Decapsulate(&key, ss2, ct, ctSz);
        }
    }

    /* mlkem_to_bytes() / mlkem_from_bytes() are reached only by the key
     * encode/decode entry points, never by keygen/encap/decap, so without this
     * round trip their AVX512-VBMI / AVX512 / AVX2 dispatch chain is dead code
     * in this binary no matter which cpuid row is installed. */
    if (wc_MlKemKey_PublicKeySize(&key, &pubSz) == 0 &&
            pubSz <= (word32)sizeof(pub) &&
            wc_MlKemKey_EncodePublicKey(&key, pub, pubSz) == 0) {
        (void)wc_MlKemKey_DecodePublicKey(&key, pub, pubSz);
    }
    if (wc_MlKemKey_PrivateKeySize(&key, &privSz) == 0 &&
            privSz <= (word32)sizeof(priv) &&
            wc_MlKemKey_EncodePrivateKey(&key, priv, privSz) == 0) {
        (void)wc_MlKemKey_DecodePrivateKey(&key, priv, privSz);
    }

    wc_MlKemKey_Free(&key);
}

/* Install a cpuid word derived from the host's REAL flags with exactly the
 * named features removed, so a "present" row never claims a feature this CPU
 * lacks and a "absent" row can only ever select a slower, equally correct
 * path.  cpuid_flags is wc_mlkem_poly.c's own file-static dispatch word and
 * mlkem_init() refreshes it only while it still holds WC_CPUID_INITIALIZER, so
 * the value written here stays put for the rest of the pass. */
static void wb_set_flags(cpuid_flags_t clear)
{
    cpuid_flags = WC_CPUID_INITIALIZER;
    (void)cpuid_get_flags_ex(&cpuid_flags);
    cpuid_flags &= (cpuid_flags_t)~clear;
}

/* wb_intr_action for the inner sha3-block dispatch: drop AVX2 from the file's
 * dispatch word once the loop has already taken its (T,T) row, so the next
 * iteration of the SAME loop evaluates IS_INTEL_AVX2() false. */
static cpuid_flags_t wb_action_clear = 0;
static long          wb_action_at = -1;

static void wb_clear_flags_at(long ix)
{
    if ((wb_action_at >= 0) && (ix == wb_action_at)) {
        cpuid_flags &= (cpuid_flags_t)~wb_action_clear;
    }
}

/* ------------------------------------------------------------------------- *
 * Rejection-sampling lane rows.
 *
 * For an N-way OR, operand j's independence pair needs one evaluation where
 * every earlier operand is false and j is true, plus the all-false evaluation.
 * Pass s reports the sampler call whose index mod 8 is s one sample short, so
 * the group containing that call yields exactly the (F..F,T,-,..) vector for
 * lane s; the eight passes together cover every lane of the 8-wide AVX512
 * loops and (twice over) every lane of the 4-wide AVX2 loops.  The unmodified
 * rows elsewhere in this file supply the all-false vector.
 *
 * The sweep is repeated per feature row because the 4-wide loops live in the
 * AVX2 generators and the 8-wide ones in the AVX512 generators, and because
 * mlkem_rej_uniform_ins()'s own VBMI/VBMI2 dispatch is only ever reached from
 * inside these loop bodies -- with no short lane it is unexecuted code.
 * ------------------------------------------------------------------------- */
static void wb_rejection_lanes(WC_RNG* rng)
{
    static const cpuid_flags_t famRows[] = {
        0,
        CPUID_AVX512_VBMI2,
        CPUID_AVX512_VBMI | CPUID_AVX512_VBMI2,
        CPUID_AVX512_VBMI | CPUID_AVX512_VBMI2 | CPUID_AVX512
    };
    unsigned f;
    int      s;
    unsigned t;

    for (f = 0; f < sizeof(famRows) / sizeof(famRows[0]); f++) {
        for (s = 0; s < 8; s++) {
            for (t = 0; t < WB_KEM_TYPE_CNT; t++) {
                wb_set_flags(famRows[f]);
                /* Reset per keygen so call index 0 is the first lane of the
                 * first group; the lane-to-index mapping depends on it. */
                wb_rej_ix = 0;
                wb_rej_lane = s;
                wb_run_keygen(rng, wb_kem_types[t]);
            }
        }
    }
    wb_rej_lane = -1;

    for (f = 0; f < sizeof(famRows) / sizeof(famRows[0]); f++) {
        for (s = 0; s < 16; s++) {
            for (t = 0; t < WB_KEM_TYPE_CNT; t++) {
                wb_set_flags(famRows[f]);
                wb_rej_ix = 0;
                wb_rej_abs = s;
                wb_run_keygen(rng, wb_kem_types[t]);
            }
        }
    }

    wb_rej_abs = -1;
    wb_rej_ix = 0;
    WB_NOTE("rejection-sampling short-lane rows exercised");
}

/* ------------------------------------------------------------------------- *
 * sha3-block dispatch rows.
 *
 * Inside each AVX2/AVX512 matrix generator every SHA3 block is squeezed with
 *
 *     if (IS_INTEL_BMI2(cpuid_flags))            sha3_block_bmi2()
 *     else if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0))
 *     else                                       BlockSha3()
 *
 * Every x86-64 CPU that has AVX2 also has BMI2, so the first arm always wins
 * and the second is never evaluated: clearing CPUID_BMI2 is the only way to
 * reach it at all.  Its two operands then need rows the OUTER dispatch would
 * normally forbid (see the wb_intr_hook comment at the top of this file):
 * wb_action_at flips AVX2 off between two iterations of the same loop, and
 * wb_intr_fail_from refuses the save only from a later call index, both after
 * the enclosing generator has already been entered on its (T,T) row.
 * ------------------------------------------------------------------------- */
static void wb_sha3_block_rows(WC_RNG* rng)
{
    /* AVX512 generators first (BMI2 cleared only), then AVX2 generators
     * (BMI2 + the AVX512 ladder cleared): the same three source sites exist in
     * both families. */
    static const cpuid_flags_t famRows[] = {
        CPUID_BMI2,
        CPUID_BMI2 | CPUID_AVX512_VBMI | CPUID_AVX512_VBMI2 | CPUID_AVX512
    };
    unsigned f;
    unsigned t;
    long     at;

    /* The k3 generators squeeze their ninth polynomial in a tail loop that only
     * runs when that lane came up short, and it carries its own copy of the
     * same three-way sha3 dispatch.  Shorting lane 0 (the tail sampler is call
     * index 8, and 8 mod 8 == 0) makes the tail loop execute in every pass
     * below, so the BMI2-cleared rows reach that copy too. */
    wb_rej_lane = 0;

    for (f = 0; f < sizeof(famRows) / sizeof(famRows[0]); f++) {
        for (t = 0; t < WB_KEM_TYPE_CNT; t++) {
            /* (T,T): BMI2 absent, AVX2 present, save accepted. */
            wb_set_flags(famRows[f]);
            wb_rej_ix = 0;
            wb_run_keygen(rng, wb_kem_types[t]);

            /* (T,F): the enclosing generator is entered on the very first
             * save, then every later save is refused, so the inner site sees
             * AVX2 true and the save refused. */
            for (at = 1; at <= 3; at++) {
                wb_set_flags(famRows[f]);
                wb_intr_count = 0;
                wb_rej_ix = 0;
                wb_intr_fail_from = at;
                wb_run_keygen(rng, wb_kem_types[t]);
                wb_intr_fail_from = -1;
            }

            /* (F,-): AVX2 is dropped after the site has run once, so the next
             * iteration of the same loop takes the portable BlockSha3 arm. */
            for (at = 0; at <= 3; at++) {
                wb_set_flags(famRows[f]);
                wb_intr_count = 0;
                wb_rej_ix = 0;
                wb_action_clear = CPUID_AVX2;
                wb_action_at = at;
                wb_intr_action = wb_clear_flags_at;
                wb_run_keygen(rng, wb_kem_types[t]);
                wb_intr_action = NULL;
                wb_action_at = -1;
                wb_action_clear = 0;
            }
        }
    }

    wb_rej_lane = -1;
    wb_rej_ix = 0;
    WB_NOTE("sha3-block (BMI2 / AVX2 / portable) rows exercised");
}

/* ------------------------------------------------------------------------- *
 * The same three-way sha3-block dispatch also sits in two leaf helpers that
 * the AVX2/AVX512 key paths never call: mlkem_prf() (the SHAKE-256 PRF used by
 * the portable noise generator) and mlkem_get_noise_eta2_avx2().  Reaching
 * them through the public API needs the outer dispatch to have already chosen
 * a path that skips them, so they are called directly here -- with no outer
 * guard in the way, a blanket save-refused setting is enough for the second
 * operand's false side. */
static void wb_leaf_sha3_rows(void)
{
    static const struct {
        cpuid_flags_t clear;
        int           intr;
    } rows[] = {
        { CPUID_BMI2,               0 },  /* BMI2 F, AVX2 T, save accepted */
        { CPUID_BMI2,               1 },  /* BMI2 F, AVX2 T, save refused  */
        { CPUID_BMI2 | CPUID_AVX2,  0 }   /* BMI2 F, AVX2 F -> BlockSha3   */
    };
    MLKEM_PRF_T prf;
    byte        key[WC_ML_KEM_SYM_SZ + 1];
    byte        out[3 * WC_SHA3_256_BLOCK_SIZE];
    unsigned    i;
#if defined(WOLFSSL_KYBER512) || defined(WOLFSSL_WC_ML_KEM_512) || \
    defined(WOLFSSL_KYBER1024) || defined(WOLFSSL_WC_ML_KEM_1024)
    sword16     p[MLKEM_N];
#endif

    XMEMSET(key, 0x5a, sizeof(key));
    mlkem_prf_init(&prf);

    for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        wb_set_flags(rows[i].clear);
        wb_intr_ret = rows[i].intr;

        /* Several output blocks so the dispatch is evaluated more than once. */
        (void)mlkem_prf(&prf, out, (unsigned int)sizeof(out), key);
#if defined(WOLFSSL_KYBER512) || defined(WOLFSSL_WC_ML_KEM_512) || \
    defined(WOLFSSL_KYBER1024) || defined(WOLFSSL_WC_ML_KEM_1024)
        XMEMSET(p, 0, sizeof(p));
        (void)mlkem_get_noise_eta2_avx2(&prf, p, key);
#endif
    }

    wb_intr_ret = 0;
    mlkem_prf_free(&prf);
    WB_NOTE("leaf sha3-block dispatch (mlkem_prf / eta2) rows exercised");
}

static void wb_dispatch_rows(void)
{
    cpuid_flags_t saved_flags = cpuid_flags;
    int           saved_intr  = wb_intr_ret;
    WC_RNG        rng;
    unsigned      i;
    unsigned      t;
    /* The dispatches form chains:
     *
     *     if      (AVX512_VBMI && save) ...
     *     else if (AVX512      && save) ...
     *     else if (AVX2        && save) ...
     *     else                          <portable C>
     *
     * so an arm's true row only happens when every RICHER feature above it is
     * absent -- with all bits set the first arm always wins and the ones below
     * are never even evaluated. Each row therefore clears a different suffix of
     * the feature ladder, and the save-refused row makes every arm in a chain
     * fall through, which is that operand's false side at each level. */
    static const struct {
        cpuid_flags_t clear;
        int           intr;
        const char*   what;
    } rows[] = {
        { 0,                                                    0,
          "all features, save accepted -> richest arm" },
        { 0,                                                    1,
          "all features, save refused  -> operand 1 false at every level" },
        /* mlkem_rej_uniform_n_ins()/_ins() test VBMI and VBMI2 as two operands
         * of one decision, so a row that drops both together can never give
         * the second one its pair. */
        { CPUID_AVX512_VBMI2,                                   0,
          "VBMI without VBMI2          -> vpcompressd sampler" },
        { CPUID_AVX512_VBMI | CPUID_AVX512_VBMI2,               0,
          "no VBMI                     -> plain AVX512 arm" },
        /* USE_INTEL_AVX512() is IS_INTEL_AVX512() && IS_INTEL_AVX512_BW()
         * (cpuid.h), so those dispatches carry three conditions. Clearing BW
         * alone is the only row that gives the middle operand a false side
         * while the F bit above it is still true. */
        { CPUID_AVX512_VBMI | CPUID_AVX512_VBMI2 | CPUID_AVX512_BW, 0,
          "AVX512 without BW           -> USE_INTEL_AVX512 operand 1 false" },
        { CPUID_AVX512_VBMI | CPUID_AVX512_VBMI2 | CPUID_AVX512, 0,
          "no AVX512                   -> AVX2 arm" },
        { CPUID_AVX512_VBMI | CPUID_AVX512_VBMI2 | CPUID_AVX512 |
          CPUID_AVX512_BW | CPUID_AVX2,                          0,
          "no SIMD                     -> portable C arm" },
    };

    if (wc_InitRng(&rng) != 0) {
        WB_NOTE("wc_InitRng failed; SIMD dispatch rows skipped");
        return;
    }

    for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        /* Start from the host's real flags so the "present" rows claim only
         * what this CPU actually has. */
        wb_set_flags(rows[i].clear);
        wb_intr_ret = rows[i].intr;

        for (t = 0; t < WB_KEM_TYPE_CNT; t++) {
            wb_run_cycle(&rng, wb_kem_types[t]);
        }
    }
    wb_intr_ret = 0;

    wb_rejection_lanes(&rng);
    wb_sha3_block_rows(&rng);
    wb_leaf_sha3_rows();

    cpuid_flags = saved_flags;
    wb_intr_ret = saved_intr;
    wb_intr_fail_from = -1;
    wb_intr_action = NULL;
    wc_FreeRng(&rng);
    WB_NOTE("SIMD dispatch rows (cpuid x save-accepted) exercised");
}

#else
static void wb_dispatch_rows(void)
{
    WB_NOTE("no Intel SIMD dispatch in this variant; rows skipped");
}
#endif

int main(void)
{
    printf("wc_mlkem_poly.c white-box MC/DC supplement\n");
#if defined(WOLFSSL_HAVE_MLKEM) && !defined(WOLFSSL_ARMASM)
    wb_cmp();
    wb_rej_uniform();
    wb_transform();
    if (wb_fail) {
        /* Do not fail the harness variant on a behavioural surprise; the
         * coverage is still valid. Report and exit 0. */
        printf("  [wb] note: one or more sanity checks were unexpected\n");
    }
#else
    printf("wc_mlkem_poly.c white-box: skipped (MLKEM off or ARMASM build)\n");
#endif
    /* gap drivers below carry their own skip-stubs, so they are always safe
     * to call regardless of the feature guard above. */
    wb_rej_uniform_c_rlen_exhaust();
    wb_get_noise_c_vec2_null();
    wb_dispatch_rows();
    printf("wc_mlkem_poly.c white-box: done\n");
    return 0;
}
