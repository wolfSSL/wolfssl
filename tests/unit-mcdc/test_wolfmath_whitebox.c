/* test_wolfmath_whitebox.c
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
 * MC/DC RNG-scripting white-box supplement for wolfcrypt/src/wolfmath.c.
 *
 * THE TWO OPEN CONDITIONS
 * -----------------------
 *     wolfmath.c:211  while ((ret == MP_OKAY) && (a->dp[a->used - 1] == 0))
 *
 * This is mp_rand()'s "ensure the top digit is not zero" retry loop. Driven by
 * a real RNG it is only ever evaluated once, as (T,F): ret is MP_OKAY because
 * the preceding wc_RNG_GenerateBlock() succeeded, and the top digit is zero
 * with probability 2^-64 (2^-32 on a 32-bit build), so:
 *
 *   idx1 (a->dp[a->used - 1] == 0) has no TRUE row  -- the loop body is never
 *        entered at all;
 *   idx0 (ret == MP_OKAY) has no FALSE row -- `ret` can only become non-OKAY
 *        INSIDE the loop body, from mp_get_rand_digit(), which is only reached
 *        once idx1 has already been TRUE.
 *
 * Both halves therefore hang off the same lever: the randomness mp_rand()
 * consumes. Waiting for the real RNG to hand out an all-zero top digit is not
 * an option for ASIL-D evidence (it is a 2^-64 lottery, and rule 3 of this
 * suite forbids evidence that depends on a live draw), so this TU scripts
 * the stream instead.
 *
 * HOW -- MACRO INTERPOSITION ON wc_RNG_GenerateBlock()
 * ---------------------------------------------------
 * random.h is included and the hook declared FIRST, then wc_RNG_GenerateBlock
 * is #defined to the hook, and only then is wolfmath.c #included. Both of
 * wolfmath.c's call sites (mp_rand()'s block fill and mp_get_rand_digit()'s
 * single-digit redraw) are rewritten; every other translation unit in the
 * archive keeps the real function. The hook's own body sits after an #undef,
 * so it still reaches the real RNG when the script is idle.
 *
 * PER-CONDITION VECTOR MAP (all three rows in THIS binary)
 * --------------------------------------------------------
 *   WB_RNG_FIXED   block fill = 0xa5..  -> top digit != 0
 *                  loop evaluated once: (T,F) -> decision FALSE
 *   WB_RNG_ZERO    block fill = 0x00..  -> top digit == 0
 *                  1st evaluation:      (T,T) -> decision TRUE, body runs
 *                  mp_get_rand_digit()'s redraw is then refused, so
 *                  2nd evaluation:      (F,.) -> decision FALSE
 *   WB_RNG_REAL    pass-through, so an ordinary mp_rand() is also measured.
 *
 * (T,T) against (F,.) is idx0's independence pair; (T,T) against (T,F) is
 * idx1's. Both are completed inside this binary, which is what MC/DC needs:
 * llvm-cov computes independence per binary and the harness only ORs the
 * resulting bits by line:col.
 *
 * Build: compiled by the coverage runner's white-box step with the SAME MC/DC
 * CFLAGS, -DHAVE_CONFIG_H and -I<workspace> as the instrumented library, then
 * linked against that variant's libwolfssl.a with its wolfmath.o removed
 * (this TU supplies the instrumented wolfmath.c). NOT part of the wolfSSL
 * build; not registered in tests/api. See tests/unit-mcdc/README.md.
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>
#include <wolfssl/wolfcrypt/random.h>

/* Declare the hook explicitly rather than relying on the macro to rewrite
 * random.h's own prototype: if anything drags random.h in first, the include
 * guard skips that prototype, the hook is never declared, and every call site
 * inside wolfmath.c fails to compile -- which the harness scores as a SILENT
 * SKIP (see the same note in mcdc_seed_rng.h). */
static int wb_wm_rng_block(WC_RNG* rng, byte* out, word32 sz);

#define wc_RNG_GenerateBlock(rng, out, sz) wb_wm_rng_block((rng), (out), (sz))

/* Pull wolfmath.c in verbatim so it is instrumented in THIS binary and sees
 * the interposer above. */
#include <wolfcrypt/src/wolfmath.c>

#undef wc_RNG_GenerateBlock

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)
#define WB_CHECK(cond, msg) \
    do { if (!(cond)) { printf("  [wb][FAIL] %s\n", (msg)); wb_fail = 1; } } \
    while (0)

#define WB_RNG_REAL     0   /* pass through to the real RNG                */
#define WB_RNG_FIXED    1   /* every draw is 0xa5.. (top digit non-zero)   */
#define WB_RNG_ZERO     2   /* first draw all-zero, every later draw fails */

static int wb_rng_mode  = WB_RNG_REAL;
static int wb_rng_calls = 0;

static int wb_wm_rng_block(WC_RNG* rng, byte* out, word32 sz)
{
    if (wb_rng_mode == WB_RNG_REAL) {
        return wc_RNG_GenerateBlock(rng, out, sz);
    }

    wb_rng_calls++;

    if (wb_rng_mode == WB_RNG_FIXED) {
        XMEMSET(out, 0xa5, sz);
        return 0;
    }

    /* WB_RNG_ZERO: hand mp_rand() a block whose top digit is zero, then
     * refuse the redraw mp_get_rand_digit() makes from inside the loop. */
    if (wb_rng_calls == 1) {
        XMEMSET(out, 0, sz);
        return 0;
    }
    return WC_NO_ERR_TRACE(RNG_FAILURE_E);
}

#if !defined(WC_NO_RNG) && (!defined(NO_BIG_INT) || defined(WOLFSSL_SP_MATH))

static void wb_mp_rand_top_digit(void)
{
    mp_int  a;
    WC_RNG  rng;
    int     ret;
    /* Two digits is the smallest shape that still exercises the a->used
     * indexing; mp_rand() rejects digits <= 0. */
    const int digits = 2;

    if (mp_init(&a) != MP_OKAY) {
        WB_NOTE("mp_init failed; skipping mp_rand vectors");
        return;
    }
    if (wc_InitRng(&rng) != 0) {
        WB_NOTE("wc_InitRng failed; skipping mp_rand vectors");
        mp_clear(&a);
        return;
    }

    /* Row 1 -- ordinary draw, pass-through: the loop is evaluated once and
     * both operands come from the real RNG. */
    ret = mp_rand(&a, digits, &rng);
    if (ret != MP_OKAY) {
        WB_NOTE("mp_rand with the real RNG failed");
        wb_fail = 1;
    }

    /* Row 2 -- (T,F): a scripted non-zero top digit, so the loop is entered
     * zero times deterministically (the real-RNG row above cannot be relied
     * on for this: it is a draw, not a vector). */
    wb_rng_mode  = WB_RNG_FIXED;
    wb_rng_calls = 0;
    ret = mp_rand(&a, digits, &rng);
    wb_rng_mode  = WB_RNG_REAL;
    if (ret != MP_OKAY) {
        WB_NOTE("mp_rand with a scripted non-zero fill failed");
        wb_fail = 1;
    }

    /* Row 3+4 -- (T,T) then (F,.): an all-zero block enters the loop, and the
     * mp_get_rand_digit() redraw inside it is refused, so the very next
     * evaluation of the same decision has ret != MP_OKAY. */
    wb_rng_mode  = WB_RNG_ZERO;
    wb_rng_calls = 0;
    ret = mp_rand(&a, digits, &rng);
    wb_rng_mode  = WB_RNG_REAL;
    if (ret != WC_NO_ERR_TRACE(RNG_FAILURE_E)) {
        WB_NOTE("refused top-digit redraw did not propagate out of mp_rand");
        wb_fail = 1;
    }
    if (wb_rng_calls < 2) {
        WB_NOTE("mp_rand never re-drew the top digit; loop was not entered");
        wb_fail = 1;
    }

    wc_FreeRng(&rng);
    mp_clear(&a);

    WB_NOTE("mp_rand top-digit retry loop pairs exercised");
}

#else

static void wb_mp_rand_top_digit(void)
{
    /* Keep the interposer referenced so it is never an unused static in a
     * variant that compiles mp_rand() out. */
    (void)&wb_wm_rng_block;
    WB_NOTE("WC_NO_RNG or no big-int math; mp_rand vectors skipped");
}

#endif /* !WC_NO_RNG && (!NO_BIG_INT || WOLFSSL_SP_MATH) */

#if defined(HAVE_ECC) && !defined(WC_NO_RNG) && \
    (!defined(NO_BIG_INT) || defined(WOLFSSL_SP_MATH)) && \
    !defined(NO_ECC256) && !defined(NO_ECC_SECP)
static void wb_ecc_derive_pub_if_needed(void)
{
    WC_RNG rng;
    ecc_key key;
    int ret;

    WB_NOTE("wc_ecc_derive_pub_if_needed(): NULL / full / private-only / "
            "failed derivation");
    ret = wc_ecc_derive_pub_if_needed(NULL, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "key==NULL");

    if (wc_InitRng(&rng) != 0) {
        WB_NOTE("wc_InitRng failed; skipped");
        return;
    }
    if (wc_ecc_init(&key) != 0) {
        WB_NOTE("wc_ecc_init failed; skipped");
        wc_FreeRng(&rng);
        return;
    }
    if (wc_ecc_make_key_ex(&rng, 0, &key, ECC_SECP256R1) != 0) {
        WB_NOTE("wc_ecc_make_key_ex failed; skipped");
        goto out;
    }

    /* A key that already holds its point is left untouched. A marker in
     * pubkey.x tells an early return apart from a silent recompute. */
    if (mp_set(key.pubkey.x, 1) == MP_OKAY) {
        ret = wc_ecc_derive_pub_if_needed(&key, &rng);
        WB_CHECK((ret == 0) && (key.type == ECC_PRIVATEKEY) &&
            (mp_isone(key.pubkey.x) == MP_YES), "full key early-returns");
    }

    /* A private-only key is completed, replacing the marker. */
    key.type = ECC_PRIVATEKEY_ONLY;
    ret = wc_ecc_derive_pub_if_needed(&key, &rng);
    WB_CHECK((ret == 0) && (key.type == ECC_PRIVATEKEY) &&
        (mp_isone(key.pubkey.x) != MP_YES), "private-only key promoted");

    /* So is an ECC_PRIVATEKEY with an all-zero point, as SetECKeyInternal()
     * leaves when only the private key was set. */
    mp_zero(key.pubkey.x);
    mp_zero(key.pubkey.y);
    ret = wc_ecc_derive_pub_if_needed(&key, &rng);
    WB_CHECK((ret == 0) && (key.type == ECC_PRIVATEKEY) &&
        !mp_iszero(key.pubkey.x), "zero point completed");

#if defined(ECC_TIMING_RESISTANT) && !defined(WOLFSSL_SP_MATH) && \
    !defined(HAVE_SELFTEST) && \
    !(defined(HAVE_FIPS) && FIPS_VERSION_LT(5,0)) && \
    !defined(WOLF_CRYPTO_CB_ONLY_ECC) && \
    !defined(WOLFSSL_ATECC508A) && !defined(WOLFSSL_ATECC608A) && \
    !defined(WOLFSSL_MICROCHIP_TA100) && \
    !defined(WOLFSSL_CRYPTOCELL) && !defined(WOLFSSL_SILABS_SE_ACCEL) && \
    !defined(WOLFSSL_KCAPI_ECC) && !defined(NO_ECC_MAKE_PUB) && \
    !defined(WOLFSSL_NO_ECC_SW)
    /* No local RNG for a curve the SP fixed-base multiply handles. */
    #if defined(WOLFSSL_HAVE_SP_ECC) && !defined(WOLFSSL_SP_NO_256)
    WB_CHECK(ecc_derive_pub_uses_rng(&key) == 0, "SP P-256 takes no RNG");
    #else
    WB_CHECK(ecc_derive_pub_uses_rng(&key) == 1, "MP P-256 takes an RNG");
    #endif
#endif

    /* A failed derivation leaves the key private-only. */
    key.type = ECC_PRIVATEKEY_ONLY;
    mp_zero(key.k);
#ifdef WOLFSSL_ECC_BLIND_K
    mp_zero(key.kb);
#endif
    ret = wc_ecc_derive_pub_if_needed(&key, &rng);
    WB_CHECK((ret != 0) && (key.type == ECC_PRIVATEKEY_ONLY),
        "zero scalar fails closed");

out:
    wc_ecc_free(&key);
    wc_FreeRng(&rng);
}
#else
static void wb_ecc_derive_pub_if_needed(void)
{
    WB_NOTE("ECC P-256 or RNG unavailable; derive-pub vectors skipped");
}
#endif

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("wolfmath.c white-box supplement\n");
    wb_mp_rand_top_digit();
    wb_ecc_derive_pub_if_needed();
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup issues are surfaced as skips; a nonzero exit would make the
     * suite discard this variant's coverage. */
    return 0;
}
