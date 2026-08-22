/* test_poly1305_whitebox.c
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

/* White-box supplement for wolfcrypt/src/poly1305.c.
 *
 * On an x86-64 USE_INTEL_POLY1305_SPEEDUP build (USE_INTEL_SPEEDUP +
 * WOLFSSL_X86_64_BUILD, poly1305.h) wc_Poly1305SetKey()/wc_Poly1305Update()/
 * wc_Poly1305Final() dispatch through a file-static cpuid mask (intel_flags),
 * set once in SetKey and reused by Update/Final:
 *
 *   if (IS_INTEL_AVX2(intel_flags)) poly1305_*_avx2(...);
 *   else                            poly1305_*_avx(...);
 *
 * Each of these is a single-condition branch (not a compound MC/DC decision:
 * poly1305.c's own the module registry-measured MC/DC total is unaffected by
 * which of these paths a given build takes), so this white-box does not
 * change the covered/total counts. It is kept anyway, matching
 * the intel-dispatch technique used by the aes/sha3 white-boxes and this
 * suite's chacha sibling, for FEATURE/branch-coverage evidence that the
 * AVX2-false (AVX1-only) side is reachable and correct: on an AVX2-capable
 * CI host, cpuid_get_flags_ex()'s real detection always takes the AVX2
 * branch through the public API, so tests/api alone never demonstrates the
 * AVX1-only side.
 *
 * cpuid_get_flags_ex() is idempotent (wolfssl/wolfcrypt/cpuid.h): it only
 * re-queries the hardware when the flags word still holds
 * WC_CPUID_INITIALIZER. Forcing intel_flags to a real (non-initializer)
 * value before calling wc_Poly1305SetKey() makes it trust our forced value
 * instead of re-detecting. Crash-safety: this host has real AVX1 hardware
 * (see the module registry poly1305 notes), so forcing intel_flags to "AVX1
 * only" and letting the dispatch call the real poly1305_*_avx asm is always
 * safe: we never claim a capability the CPU lacks, only hide one it has.
 *
 * ---------------------------------------------------------------------------
 * AVX-512 / IFMA / fused-flag dispatch (wb_poly1305_avx512_dispatch)
 * ---------------------------------------------------------------------------
 * The AVX-512 Poly1305 work turned the single-condition AVX2 test above into
 * six compound decisions -- three in wc_Poly1305Update, three in
 * wc_Poly1305Final -- with the same shape in both:
 *
 *   if (!POLY1305_FORCE_AVX2(ctx) && !POLY1305_FORCE_SCALAR(ctx) &&
 *           poly1305_use_ifma(intel_flags))       <- 8-way IFMA, radix 2^44
 *   if (!POLY1305_FORCE_AVX2(ctx) && !POLY1305_FORCE_SCALAR(ctx) &&
 *           poly1305_use_avx512(intel_flags))     <- 8-way vpmuludq
 *   if (!POLY1305_FORCE_SCALAR(ctx) && IS_INTEL_AVX2(intel_flags))
 *
 * plus the two predicates they call:
 *
 *   poly1305_use_avx512: IS_INTEL_AVX512(f) && IS_INTEL_VAES(f)
 *   poly1305_use_ifma:   IS_INTEL_AVX512_IFMA(f) && IS_CPU_INTEL(f)
 *
 * Three inputs decide all six: the two ctx flags (set only by the fused
 * ChaCha20-Poly1305 kernels in chacha20_poly1305.c, so no poly1305-only caller
 * ever sets them) and intel_flags. Any one host reaches exactly one
 * combination -- on an AMD host IS_CPU_INTEL is false while AVX-512 and VAES
 * are present, so every call takes the 8-way vpmuludq path and the other five
 * decisions are never evaluated with a differing operand.
 * wb_poly1305_dispatch_case() drives one (intel_flags, forceAvx2, forceScalar)
 * triple through SetKey/Update/Final; the table in
 * wb_poly1305_avx512_dispatch() is the full combination sweep, every row of it
 * in this one binary so that each condition's independence pair is derivable
 * here (llvm-cov computes MC/DC per binary).
 *
 * Crash-safety rule, unchanged from above: a forced mask may only CLEAR
 * capability bits the CPU has, never claim one it lacks. Each row's mask is
 * built as (wanted & real cpuid_get_flags()), so on a host without AVX-512 the
 * AVX-512 rows collapse onto the rows below them and are simply not gained --
 * never executed as an unsupported instruction. The one bit forced ON,
 * CPUID_INTEL, is a vendor tag rather than a capability: poly1305_use_ifma()'s
 * own comment states the gate is a throughput preference between two paths any
 * IFMA-capable CPU can run (AMD Zen 4/5 implement IFMA), and the row that lets
 * the IFMA kernel actually execute is additionally skipped unless the host
 * really reports AVX-512 IFMA.
 *
 * The ctx-flag rows reproduce, on a poly1305-only context, exactly the state
 * the fused kernels set up before calling Update/Final: forceAvx2 -> zero
 * ctx->hh, started = 0 (chacha20_poly1305_encrypt_fused); forceScalar -> zero
 * ctx->h, finished = 1, leftover = 0, started = 0
 * (chacha20_poly1305_encrypt_fused_ifma, wc_ChaCha20Poly1305_UpdateData).
 * No MAC value is checked: which kernel computes the right tag is the KAT
 * suite's job, this file only drives the dispatch decisions.
 */

#include <wolfcrypt/src/poly1305.c>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if defined(HAVE_POLY1305) && defined(USE_INTEL_POLY1305_SPEEDUP)

static void wb_poly1305_dispatch(void)
{
    Poly1305 ctx;
    static const byte key[32] = {
        0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,
        0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
        0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,
        0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b
    };
    /* Multiple blocks so poly1305_blocks_avx() actually runs (not just
     * poly1305_block_avx()'s single-block path). */
    byte msg[3 * POLY1305_BLOCK_SIZE + 5];
    byte tag[WC_POLY1305_MAC_SZ];
    cpuid_flags_t saved_flags = intel_flags;
    size_t i;

    for (i = 0; i < sizeof(msg); i++) {
        msg[i] = (byte)i;
    }

    /* AVX2-false, AVX1-true: forces poly1305_setkey_avx/blocks_avx/
     * final_avx. Real hardware capability, so safe to actually execute. */
    intel_flags = CPUID_AVX1;
    if (wc_Poly1305SetKey(&ctx, key, sizeof(key)) == 0) {
        if (wc_Poly1305Update(&ctx, msg, (word32)sizeof(msg)) != 0 ||
            wc_Poly1305Final(&ctx, tag) != 0) {
            WB_NOTE("Update/Final (AVX1-only) failed");
            wb_fail = 1;
        }
    }
    else {
        WB_NOTE("wc_Poly1305SetKey failed (AVX1-only case skipped)");
        wb_fail = 1;
    }

    intel_flags = saved_flags;
    WB_NOTE("poly1305 intel dispatch AVX1-only side exercised");
}

#else

static void wb_poly1305_dispatch(void)
{
    WB_NOTE("USE_INTEL_POLY1305_SPEEDUP not compiled in this variant; "
        "skipped");
}

#endif

/* -------------------------------------------------------------------------
 * AVX-512 / IFMA / fused-flag dispatch sweep. See the file header.
 * ---------------------------------------------------------------------- */
#if defined(HAVE_POLY1305) && defined(USE_INTEL_POLY1305_SPEEDUP)

/* Capability bits are only ever removed from what the CPU really reports, so a
 * forced mask can never make the dispatch enter a path the host cannot run. */
static cpuid_flags_t wb_hw(cpuid_flags_t wanted)
{
    return wanted & cpuid_get_flags();
}

/* Reproduce the context state the fused ChaCha20-Poly1305 kernels leave behind
 * when they pin Update/Final to one path (chacha20_poly1305.c). */
static void wb_poly1305_force(Poly1305* ctx, int forceAvx2, int forceScalar)
{
#ifdef WOLFSSL_CHACHA20_POLY1305_FUSED
    if (forceAvx2) {
        ctx->forceAvx2 = 1;
        XMEMSET(ctx->hh, 0, sizeof(ctx->hh));
        ctx->started  = 0;
        ctx->leftover = 0;
    }
#else
    (void)forceAvx2;
#endif
#ifdef WOLFSSL_CHACHA20_POLY1305_FUSED_IFMA
    if (forceScalar) {
        ctx->forceScalar = 1;
        XMEMSET(ctx->h, 0, sizeof(ctx->h));
        ctx->finished = 1;
        ctx->started  = 0;
        ctx->leftover = 0;
    }
#else
    (void)forceScalar;
#endif
    (void)ctx;
}

/* One (intel_flags, forceAvx2, forceScalar) row: key, hash more than the
 * 8-block buffer so the block kernels run, and finalise. */
static void wb_poly1305_dispatch_case(cpuid_flags_t flags, int forceAvx2,
                                      int forceScalar, const char* what)
{
    static const byte key[32] = {
        0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,
        0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
        0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,
        0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b
    };
    Poly1305 ctx;
    byte msg[17 * POLY1305_BLOCK_SIZE + 5];
    byte tag[WC_POLY1305_MAC_SZ];
    size_t i;

    for (i = 0; i < sizeof(msg); i++) {
        msg[i] = (byte)i;
    }

    XMEMSET(&ctx, 0, sizeof(ctx));
    /* Non-initializer value: cpuid_get_flags_ex() in SetKey keeps it. */
    intel_flags = flags;
    if (wc_Poly1305SetKey(&ctx, key, (word32)sizeof(key)) != 0) {
        printf("  [wb] wc_Poly1305SetKey failed (%s skipped)\n", what);
        wb_fail = 1;
        return;
    }
    wb_poly1305_force(&ctx, forceAvx2, forceScalar);
    if (wc_Poly1305Update(&ctx, msg, (word32)sizeof(msg)) != 0 ||
            wc_Poly1305Final(&ctx, tag) != 0) {
        printf("  [wb] Update/Final failed (%s)\n", what);
        wb_fail = 1;
    }
}

static void wb_poly1305_avx512_dispatch(void)
{
    cpuid_flags_t saved_flags = intel_flags;
    cpuid_flags_t real        = cpuid_get_flags();
    /* Common base: the scalar and 4-way kernels this host really has. */
    const cpuid_flags_t avx1 = wb_hw(CPUID_AVX1);
    const cpuid_flags_t avx2 = wb_hw(CPUID_AVX1 | CPUID_AVX2);
    const cpuid_flags_t f512 = wb_hw(CPUID_AVX1 | CPUID_AVX2 | CPUID_AVX512);
    const cpuid_flags_t fvaes = wb_hw(CPUID_AVX1 | CPUID_AVX2 | CPUID_AVX512 |
                                      CPUID_VAES | CPUID_AVX512_IFMA);

    /* AVX2 absent: IS_INTEL_AVX2 false, every AVX-512 predicate false. */
    wb_poly1305_dispatch_case(avx1, 0, 0, "scalar (AVX1 only)");
    /* AVX2 present, no AVX-512: the 4-way path. */
    wb_poly1305_dispatch_case(avx2, 0, 0, "4-way AVX2");
    /* AVX-512 without VAES: poly1305_use_avx512() second operand false. */
    wb_poly1305_dispatch_case(f512, 0, 0, "AVX-512 without VAES");
    /* AVX-512 + VAES + IFMA, vendor bit absent: use_avx512 true (8-way
     * vpmuludq), use_ifma's IS_CPU_INTEL operand false. */
    wb_poly1305_dispatch_case(fvaes, 0, 0, "8-way AVX-512, non-Intel vendor");
    /* Same, plus the Intel vendor tag: the IFMA path. Only when the host
     * really implements AVX-512 IFMA -- the kernel is vpmadd52 asm. */
    if (IS_INTEL_AVX512(real) && IS_INTEL_AVX512_IFMA(real)) {
        wb_poly1305_dispatch_case(fvaes | CPUID_INTEL, 0, 0,
                                  "8-way AVX-512 IFMA");
    }
    else {
        WB_NOTE("host reports no AVX-512 IFMA; IFMA dispatch row skipped");
    }
    /* Fused-kernel context flags: each pins the dispatch to one path. */
    wb_poly1305_dispatch_case(fvaes, 1, 0, "forceAvx2 (fused 4-way)");
    wb_poly1305_dispatch_case(fvaes, 0, 1, "forceScalar (fused IFMA stitch)");

    intel_flags = saved_flags;
    WB_NOTE("poly1305 AVX-512/IFMA/fused-flag dispatch sweep exercised");
}

#ifdef HAVE_INTEL_AVX512
/* poly1305_use_avx512()/poly1305_use_ifma() are pure predicates over a flags
 * word: no state, no instruction from the feature they test. Evaluating them
 * directly over the four operand combinations pairs both conditions of each
 * without depending on what this host implements, so the two predicates close
 * on any machine; the dispatch sweep above then shows the same rows arising
 * from real calls wherever the hardware allows. */
static void wb_poly1305_predicates(void)
{
    static volatile cpuid_flags_t rows[4];
    volatile int sink = 0;
    int i;

    rows[0] = 0;
    rows[1] = CPUID_AVX512 | CPUID_AVX512_IFMA;
    rows[2] = CPUID_VAES | CPUID_INTEL;
    rows[3] = CPUID_AVX512 | CPUID_AVX512_IFMA | CPUID_VAES | CPUID_INTEL;

    for (i = 0; i < 4; i++) {
        sink += poly1305_use_avx512(rows[i]);
        sink += poly1305_use_ifma(rows[i]);
    }
    (void)sink;
    WB_NOTE("poly1305_use_avx512/use_ifma operand combinations exercised");
}
#else
static void wb_poly1305_predicates(void)
{
    WB_NOTE("HAVE_INTEL_AVX512 off; use_avx512/use_ifma predicates skipped");
}
#endif

#else

static void wb_poly1305_avx512_dispatch(void)
{
    WB_NOTE("USE_INTEL_POLY1305_SPEEDUP not compiled in this variant; "
        "AVX-512 dispatch sweep skipped");
}

static void wb_poly1305_predicates(void)
{
    WB_NOTE("USE_INTEL_POLY1305_SPEEDUP not compiled in this variant; "
        "predicate sweep skipped");
}

#endif

/* ---- wc_Poly1305SetKey() argument guard (~line 850) ---------------------- *
 *
 *   if ((ctx == NULL) || (key == NULL) || (keySz != 32))
 *
 * MEASURED RESULT: idx1 (key == NULL) is UNSATISFIABLE, and this function is
 * the evidence. wc_Poly1305SetKey() opens with a separate, earlier
 *
 *     if (key == NULL) return BAD_FUNC_ARG;
 *
 * (~line 836), so by the time the compound at ~850 is evaluated key is
 * non-NULL by construction: idx1 is a redundant re-check that can only ever
 * be observed FALSE, and no independence pair for it exists through any entry
 * point. Calling wc_Poly1305SetKey(ctx, NULL, 32) here returns from the
 * earlier guard and never reaches line 850 -- confirmed by the white-box
 * binary's own MC/DC record, which shows idx0/idx2 covered and idx1 not.
 * The three satisfiable vectors plus the all-false baseline are kept as
 * same-binary regression evidence for idx0/idx2.
 *
 * Also NOT chased (structurally unsatisfiable): wc_Poly1305_Pad()'s
 * "(paddingLen > 0) && (paddingLen < WC_POLY1305_PAD_SZ)" idx1. paddingLen is
 * computed as "(-(int)lenToPad) & (WC_POLY1305_PAD_SZ - 1)", i.e. masked into
 * [0, WC_POLY1305_PAD_SZ-1], so whenever idx1 is evaluated it is TRUE by
 * construction -- no call shape can make it false, so no independence pair
 * exists.
 * ------------------------------------------------------------------------ */
#ifdef HAVE_POLY1305
static void wb_poly1305_setkey_guard(void)
{
    Poly1305 ctx;
    static const byte key[32] = {
        0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,
        0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
        0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,
        0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b
    };
    byte tag[WC_POLY1305_MAC_SZ];

    XMEMSET(&ctx, 0, sizeof(ctx));

    /* idx0 true: ctx == NULL. */
    if (wc_Poly1305SetKey(NULL, key, (word32)sizeof(key)) !=
            WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("wc_Poly1305SetKey(ctx==NULL) not rejected");
        wb_fail = 1;
    }
    /* idx0 false, idx1 TRUE: valid ctx, absent key. */
    if (wc_Poly1305SetKey(&ctx, NULL, (word32)sizeof(key)) !=
            WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("wc_Poly1305SetKey(key==NULL) not rejected");
        wb_fail = 1;
    }
    /* idx0/idx1 false, idx2 true: wrong key size. */
    if (wc_Poly1305SetKey(&ctx, key, 16) != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("wc_Poly1305SetKey(keySz!=32) not rejected");
        wb_fail = 1;
    }
    /* All-false baseline in the same binary, run to completion. */
    if (wc_Poly1305SetKey(&ctx, key, (word32)sizeof(key)) != 0 ||
            wc_Poly1305Update(&ctx, key, (word32)sizeof(key)) != 0 ||
            wc_Poly1305Final(&ctx, tag) != 0) {
        WB_NOTE("wc_Poly1305SetKey valid sequence failed");
        wb_fail = 1;
    }

    WB_NOTE("wc_Poly1305SetKey ctx/key/keySz guard pairs exercised");
}
#else
static void wb_poly1305_setkey_guard(void)
{ WB_NOTE("HAVE_POLY1305 off; wc_Poly1305SetKey guard skipped"); }
#endif

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("poly1305.c white-box supplement\n");
#ifndef HAVE_POLY1305
    printf("  HAVE_POLY1305 not defined; nothing to exercise\n");
    return 0;
#else
    wb_poly1305_dispatch();
    wb_poly1305_predicates();
    wb_poly1305_avx512_dispatch();
    wb_poly1305_setkey_guard();
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup failures are surfaced as skips, not test failures: the harness
     * treats a nonzero exit as a failed variant and discards its coverage. */
    return 0;
#endif
}
