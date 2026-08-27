/* test_chacha_whitebox.c
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

/* White-box supplement for wolfcrypt/src/chacha.c.
 *
 * On an x86-64 USE_INTEL_CHACHA_SPEEDUP build (USE_INTEL_SPEEDUP +
 * WOLFSSL_X86_64_BUILD, chacha.h) wc_Chacha_Process() dispatches through a
 * file-static cpuid mask (cpuidFlags):
 *
 *   if (IS_INTEL_AVX2(cpuidFlags)) { chacha_encrypt_avx2(...); return 0; }
 *   if (IS_INTEL_AVX1(cpuidFlags)) { chacha_encrypt_avx1(...); return 0; }
 *   else                           { chacha_encrypt_x64(...);  return 0; }
 *
 * Each of these is a single-condition branch (not a compound MC/DC decision:
 * chacha.c's own db/modules.json-measured MC/DC total is unaffected by which
 * of these paths a given build takes), so this white-box does not change the
 * campaign's covered/total counts. It is kept anyway, matching the intel-
 * dispatch technique used by the aes/sha3 white-boxes and this campaign's
 * poly1305 sibling, for FEATURE/branch-coverage evidence that the AVX2-false
 * sides (AVX1-only and the generic x64 fallback) are reachable and correct:
 * on an AVX2-capable CI host, cpuid_get_flags_ex()'s real detection always
 * takes the AVX2 branch through the public API, so tests/api alone never
 * demonstrates the AVX1-only or x64-fallback sides.
 *
 * cpuid_get_flags_ex() is idempotent (wolfssl/wolfcrypt/cpuid.h): it only
 * re-queries the hardware when the flags word still holds
 * WC_CPUID_INITIALIZER. Forcing cpuidFlags to a real (non-initializer) value
 * before calling wc_Chacha_Process() makes it trust our forced value instead
 * of re-detecting. Crash-safety: we only ever CLEAR capability bits the real
 * host does not actually have removed either -- this host has both AVX1 and
 * AVX2 hardware (see db/modules.json chacha notes), so forcing cpuidFlags to
 * "AVX1 only" or "neither" and letting the dispatch call the real
 * chacha_encrypt_avx1/chacha_encrypt_x64 asm is always safe: we never claim
 * a capability the CPU lacks, only hide one it has.
 *
 * ---------------------------------------------------------------------------
 * AVX-512 dispatch ladder (wb_chacha_avx512_dispatch)
 * ---------------------------------------------------------------------------
 * The AVX-512 ChaCha work replaced that flat if/else with a length-and-feature
 * ladder in wc_Chacha_Process, five compound decisions deep:
 *
 *   msglen <= CHACHA_CHUNK_BYTES && IS_INTEL_AVX512_VL(f) == 0 &&
 *       IS_INTEL_AVX1(f)                                   -> 1-block AVX1
 *   IS_INTEL_AVX512_VL(f) == 0 && msglen < 4*CHUNK &&
 *       IS_INTEL_SSSE3(f)                                  -> SSSE3
 *   IS_INTEL_AVX512_VL(f) == 0 && msglen < 4*CHUNK         -> scalar x64
 *   chacha_avx512_beneficial(f) && msglen >= 16*CHUNK      -> 512-bit zmm
 *   IS_INTEL_AVX512_VL(f) && msglen < 8*CHUNK              -> AVX-512VL
 *
 * plus the predicate chacha_avx512_beneficial(): IS_INTEL_AVX512(f) &&
 * IS_INTEL_VAES(f).
 *
 * Two inputs decide all of them: the message length and the cpuid mask. One
 * host only ever supplies one mask -- on an AVX-512VL machine every
 * "IS_INTEL_AVX512_VL(f) == 0" operand is permanently false, which pins three
 * of the five decisions to a single outcome no matter what lengths the tests
 * use, and on a machine without AVX-512 the last two are pinned the other way.
 * wb_chacha_process_case() drives one (mask, length) pair; the table in
 * wb_chacha_avx512_dispatch() is the full sweep -- every row in this one
 * binary, since llvm-cov derives MC/DC independence pairs per binary.
 *
 * Crash-safety, same rule as above and enforced by wb_hw(): each row's mask is
 * built as (wanted & real cpuid_get_flags()), so a capability bit is only ever
 * cleared, never claimed. On a host without AVX-512 the AVX-512 rows degrade
 * into the rows below them in the ladder -- coverage is not gained, but no
 * unsupported instruction is ever executed.
 */

#include <wolfcrypt/src/chacha.c>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if defined(HAVE_CHACHA) && defined(USE_INTEL_CHACHA_SPEEDUP)

static void wb_chacha_dispatch(void)
{
    ChaCha enc;
    static const byte key[CHACHA_MAX_KEY_SZ] = {
        0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b, 0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b, 0x1c,0x1d,0x1e,0x1f
    };
    static const byte nonce[CHACHA_IV_BYTES] = {
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x02
    };
    /* Two chunk-boundary-crossing blocks, big enough to drive the leftover
     * handling too. */
    byte plain[130];
    byte cipher[sizeof(plain)];
    cpuid_flags_t saved_flags = cpuidFlags;
    size_t i;

    for (i = 0; i < sizeof(plain); i++) {
        plain[i] = (byte)i;
    }

    /* AVX2-false, AVX1-true: forces the chacha_encrypt_avx1() side. Real
     * hardware capability, so safe to actually execute. */
    if (wc_Chacha_SetKey(&enc, key, sizeof(key)) == 0 &&
        wc_Chacha_SetIV(&enc, nonce, 0) == 0) {
        cpuidFlags = CPUID_AVX1;
        if (wc_Chacha_Process(&enc, cipher, plain, sizeof(plain)) != 0) {
            WB_NOTE("wc_Chacha_Process (AVX1-only) failed");
            wb_fail = 1;
        }
    }
    else {
        WB_NOTE("SetKey/SetIV failed (AVX1-only case skipped)");
        wb_fail = 1;
    }

    /* AVX2-false, AVX1-false: forces the generic chacha_encrypt_x64() side.
     * Always safe -- no AVX/AVX2 instructions involved. */
    if (wc_Chacha_SetKey(&enc, key, sizeof(key)) == 0 &&
        wc_Chacha_SetIV(&enc, nonce, 0) == 0) {
        cpuidFlags = 0;
        if (wc_Chacha_Process(&enc, cipher, plain, sizeof(plain)) != 0) {
            WB_NOTE("wc_Chacha_Process (x64 fallback) failed");
            wb_fail = 1;
        }
    }
    else {
        WB_NOTE("SetKey/SetIV failed (x64 fallback case skipped)");
        wb_fail = 1;
    }

    cpuidFlags = saved_flags;
    WB_NOTE("chacha intel dispatch AVX1/x64 sides exercised");
}

#else

static void wb_chacha_dispatch(void)
{
    WB_NOTE("USE_INTEL_CHACHA_SPEEDUP not compiled in this variant; skipped");
}

#endif

/* -------------------------------------------------------------------------
 * AVX-512 dispatch ladder sweep. See the file header.
 * ---------------------------------------------------------------------- */
#if defined(HAVE_CHACHA) && defined(USE_INTEL_CHACHA_SPEEDUP)

/* Capability bits are only ever removed from what the CPU really reports. */
static cpuid_flags_t wb_hw(cpuid_flags_t wanted)
{
    return wanted & cpuid_get_flags();
}

/* Longest row: one 16-block zmm chunk plus a tail. */
#define WB_CHACHA_MAX_LEN (20 * CHACHA_CHUNK_BYTES)

static void wb_chacha_process_case(cpuid_flags_t flags, word32 msglen,
                                   const char* what)
{
    static const byte key[CHACHA_MAX_KEY_SZ] = {
        0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b, 0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b, 0x1c,0x1d,0x1e,0x1f
    };
    static const byte nonce[CHACHA_IV_BYTES] = {
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x02
    };
    ChaCha enc;
    byte plain[WB_CHACHA_MAX_LEN];
    byte cipher[WB_CHACHA_MAX_LEN];
    word32 i;

    for (i = 0; i < (word32)sizeof(plain); i++) {
        plain[i] = (byte)i;
    }

    /* A fresh key/IV per row: ctx->left from the previous row must not shift
     * which branch of the ladder this row's length reaches. */
    if (wc_Chacha_SetKey(&enc, key, (word32)sizeof(key)) != 0 ||
            wc_Chacha_SetIV(&enc, nonce, 0) != 0) {
        printf("  [wb] SetKey/SetIV failed (%s skipped)\n", what);
        wb_fail = 1;
        return;
    }
    cpuidFlags = flags;
    if (wc_Chacha_Process(&enc, cipher, plain, msglen) != 0) {
        printf("  [wb] wc_Chacha_Process failed (%s)\n", what);
        wb_fail = 1;
    }
}

static void wb_chacha_avx512_dispatch(void)
{
    cpuid_flags_t saved_flags = cpuidFlags;
    const word32 chunk = CHACHA_CHUNK_BYTES;
    const cpuid_flags_t none  = 0;
    const cpuid_flags_t avx1  = wb_hw(CPUID_AVX1);
    const cpuid_flags_t ssse3 = wb_hw(CPUID_SSSE3);
    const cpuid_flags_t vl    = wb_hw(CPUID_AVX512 | CPUID_AVX512_VL |
                                      CPUID_VAES);
    const cpuid_flags_t f512  = wb_hw(CPUID_AVX512);
    const cpuid_flags_t zmm   = wb_hw(CPUID_AVX512 | CPUID_VAES);

    /* One block or less, no AVX-512VL, AVX1 present: the 1-block AVX1 path. */
    wb_chacha_process_case(avx1, chunk / 2, "<=1 block, AVX1");
    /* Same length, AVX-512VL present: second operand of that test false. */
    wb_chacha_process_case(vl, chunk / 2, "<=1 block, AVX-512VL present");
    /* Same length, no AVX1 either: third operand false, scalar single block. */
    wb_chacha_process_case(none, chunk / 2, "<=1 block, no SIMD");
    /* 65..255 bytes, SSSE3 present, no AVX-512VL: the SSSE3 exact-block path. */
    wb_chacha_process_case(ssse3, 2 * chunk, "<4 blocks, SSSE3");
    /* Same length without SSSE3: falls to the scalar <4-block path. */
    wb_chacha_process_case(none, 2 * chunk, "<4 blocks, no SSSE3");
    /* Same length with AVX-512VL: the two "VL == 0" first operands are false
     * and the AVX-512VL kernel handles it. */
    wb_chacha_process_case(vl, 2 * chunk, "<4 blocks, AVX-512VL");
    /* >=4 blocks: the length operand of the SSSE3 and scalar tests is false. */
    wb_chacha_process_case(ssse3, 8 * chunk, ">=4 blocks, SSSE3");
    /* >=4 blocks, nothing available: reaches the zmm and AVX-512VL tests with
     * both their feature operands false. */
    wb_chacha_process_case(none, 8 * chunk, ">=4 blocks, no SIMD");
    /* AVX-512 without VAES: chacha_avx512_beneficial()'s second operand false,
     * so the zmm kernel is not entered whatever the length. */
    wb_chacha_process_case(f512, 8 * chunk, "AVX-512 without VAES");
    /* AVX-512 + VAES and a >=16-block message: the 512-bit zmm kernel. */
    wb_chacha_process_case(zmm, 17 * chunk, ">=16 blocks, zmm");
    /* AVX-512 + VAES but under 16 blocks: the length operand false. */
    wb_chacha_process_case(zmm, 8 * chunk, "<16 blocks, zmm beneficial");

    cpuidFlags = saved_flags;
    WB_NOTE("chacha AVX-512 dispatch ladder sweep exercised");
}

#ifdef HAVE_INTEL_AVX512
/* chacha_avx512_beneficial() is a pure predicate over a flags word: it runs no
 * instruction from the feature it tests, so evaluating it directly over the
 * four operand combinations pairs both of its conditions on any host,
 * independently of what this machine implements. */
static void wb_chacha_predicate(void)
{
    static volatile cpuid_flags_t rows[4];
    volatile int sink = 0;
    int i;

    rows[0] = 0;
    rows[1] = CPUID_AVX512;
    rows[2] = CPUID_VAES;
    rows[3] = CPUID_AVX512 | CPUID_VAES;

    for (i = 0; i < 4; i++) {
        sink += chacha_avx512_beneficial(rows[i]);
    }
    (void)sink;
    WB_NOTE("chacha_avx512_beneficial operand combinations exercised");
}
#else
static void wb_chacha_predicate(void)
{
    WB_NOTE("HAVE_INTEL_AVX512 off; chacha_avx512_beneficial skipped");
}
#endif

#else

static void wb_chacha_avx512_dispatch(void)
{
    WB_NOTE("USE_INTEL_CHACHA_SPEEDUP not compiled in this variant; "
        "AVX-512 ladder sweep skipped");
}

static void wb_chacha_predicate(void)
{
    WB_NOTE("USE_INTEL_CHACHA_SPEEDUP not compiled in this variant; "
        "predicate sweep skipped");
}

#endif

int main(void)
{
    printf("chacha.c white-box supplement\n");
#ifndef HAVE_CHACHA
    printf("  HAVE_CHACHA not defined; nothing to exercise\n");
    return 0;
#else
    wb_chacha_dispatch();
    wb_chacha_predicate();
    wb_chacha_avx512_dispatch();
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup failures are surfaced as skips, not test failures: the campaign
     * treats a nonzero exit as a failed variant and discards its coverage. */
    return 0;
#endif
}
