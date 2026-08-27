/* test_sp_int_fault_whitebox.c
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
 * Heap-fault MC/DC supplement for wolfcrypt/src/sp_int.c.
 *
 * TARGET
 * ------
 * sp_int.c carries its error state in `err` and gates every subsequent step on
 * it:
 *
 *     if ((err == MP_OKAY) && useMont) {
 *     if ((!done) && (err == MP_OKAY)) {
 *     for (; (err == MP_OKAY) && (i >= 0); i--) {
 *
 * Called with valid operands nothing sets `err`, so the first operand of each
 * of these never takes its false side. The failure that does set it is a
 * temporary allocation: under WOLFSSL_SMALL_STACK (sp_int.h:872)
 * DECL_MP_INT_SIZE/NEW_MP_INT_SIZE become a real XMALLOC whose result is
 * checked, whereas otherwise the temporaries are stack arrays and `err` cannot
 * change at all.
 *
 * The campaign's sp-math module already builds a `small_stack` variant, so
 * unlike the SP backends this needs no new configuration -- only this driver.
 *
 * METHOD
 * ------
 * mcdc_fault_alloc.h fails the n-th and every later allocation; sweeping n
 * walks the MEMORY_E down the allocation sites of each operation, so every
 * `err == MP_OKAY` checkpoint downstream of one is observed both holding and
 * not holding.
 *
 * Two properties of the sweep are load-bearing:
 *
 *   1. ONE operation per armed window. mcdc_fa_arm(n) resets the allocation
 *      counter, so a window that runs several operations only positions the
 *      failure inside the FIRST of them -- every later one starts with the
 *      counter already past n and sees its very first allocation fail. Each
 *      operation therefore gets its own arm/disarm pair here.
 *
 *   2. The window must be deep enough. The outer temporaries of an
 *      exponentiation are a single array allocation, so failing at index 1
 *      only ever reaches the checkpoints in the function prologue. The
 *      checkpoints INSIDE the square-and-multiply loops are reached only when
 *      the failure lands on an allocation made by a nested sp_mul() /
 *      sp_sqr() / sp_mod() / _sp_mont_red() call, which is tens of
 *      allocations deep. SP_FAULT_MAX_N is sized for that.
 *
 * The internal engines are also driven directly (they are file-static and in
 * scope because this TU #includes sp_int.c), which both localises the
 * allocation index to one engine and reaches the "base is not less than
 * modulus" arm that sp_exptmod()'s own up-front reduction makes dead.
 *
 * Operands are deliberately small. These decisions test the error state and
 * the shape of the operands, not their magnitude, and the sweep repeats every
 * operation once per fail-index -- TEST_TIMEOUT is wall clock and variants run
 * concurrently under MAXPAR, so a full-size modexp here would be a timeout
 * rather than evidence. The one exception is the invmod pair, which needs a
 * modulus of at least 1024 bits to select the division-based inverse.
 *
 * Build: compiled by the campaign's white-box step with the same MC/DC CFLAGS
 * as the instrumented library, then linked against that variant's
 * libwolfssl.a with sp_int.o removed. Not part of the wolfSSL build.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#include <wolfcrypt/src/sp_int.c>

#include "mcdc_fault_alloc.h"

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL)

/* Deep enough to walk the failure through the nested sp_mul()/sp_sqr()/
 * sp_mod() allocations inside the square-and-multiply loops, not just the
 * prologue temporaries. Over-sweeping is harmless: once n exceeds an
 * operation's allocation count the operation simply runs to completion. */
#ifndef SP_FAULT_MAX_N
    #define SP_FAULT_MAX_N 160
#endif

/* Small primes/moduli: big enough to take the montgomery and non-montgomery
 * routes, small enough that the whole sweep stays well inside TEST_TIMEOUT. */
static const char* WB_M_ODD  = "F0000000000000000000000000000037";
static const char* WB_M_EVEN = "F0000000000000000000000000000038";
static const char* WB_B      = "0123456789ABCDEF0123456789ABCDEF";
static const char* WB_E      = "10001";

/* A dividend WIDER than the moduli above.
 *
 * _sp_div() short-circuits (done = 1, no temporaries allocated at all) for
 * dividend < divisor, dividend == divisor, and dividend of the same bit length
 * as the divisor. Every division fed the operands above therefore returned
 * before reaching a single allocation site, which is why the division family's
 * error checkpoints stayed unreached no matter how the fail-index was swept.
 * This value is twice as wide as the moduli, so the long-division body runs. */
static const char* WB_A_BIG =
    "C3A5B1D7E9F0246813579BDF02468ACE0123456789ABCDEF0123456789ABCDEF";

/* 1024-bit moduli: sp_invmod() only selects the division-based inverse when
 * the modulus is at least 1024 bits, so the small moduli above never reach
 * _sp_invmod_div() at all. */
static const char* WB_M1024_ODD =
    "C0000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000061";
static const char* WB_M1024_EVEN =
    "C0000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000062";

/* Which internal engines this configuration compiles. Mirrors sp_int.c's own
 * guards so the TU builds under every campaign variant. */
#if (defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_RSA_VERIFY_ONLY) && \
    !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || !defined(NO_DH) || \
    defined(OPENSSL_ALL)
    #define WB_HAVE_EXPTMOD_EX
#endif
#if (defined(WOLFSSL_SP_MATH_ALL) && ((!defined(WOLFSSL_RSA_VERIFY_ONLY) && \
    !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || !defined(NO_DH))) || \
    defined(OPENSSL_ALL)
    #define WB_HAVE_EXPTMOD_MONT_EX
    #define WB_HAVE_EXPTMOD_BASE_2
#endif
#if defined(WOLFSSL_SP_MATH_ALL) || defined(WOLFSSL_HAVE_SP_DH)
#if defined(WOLFSSL_SP_FAST_NCT_EXPTMOD) || !defined(WOLFSSL_SP_SMALL)
    #define WB_HAVE_EXPTMOD_NCT
#endif
#endif

/* Number of distinct operations swept. */
#define WB_OP_COUNT   34

#ifndef WC_NO_RNG
static WC_RNG wb_rng;
static int    wb_rng_ok = 0;
#endif

/* Build the operands for one operation (allocator DISARMED), arm the n-th
 * allocation, run exactly that operation, then disarm. */
static void wb_op(int op, int n)
{
    mp_int a;
    mp_int b;
    mp_int e;
    mp_int m;
    mp_int r;
    mp_int q;

    if (mp_init_multi(&a, &b, &e, &m, &r, &q) != MP_OKAY) {
        wb_fail = 1;
        return;
    }

    /* Common operands. Every read_radix here runs while disarmed. */
    if ((mp_read_radix(&b, WB_B, MP_RADIX_HEX) != MP_OKAY) ||
            (mp_read_radix(&e, WB_E, MP_RADIX_HEX) != MP_OKAY) ||
            (mp_read_radix(&a, WB_B, MP_RADIX_HEX) != MP_OKAY)) {
        wb_fail = 1;
        goto done;
    }

    /* The division family needs a dividend wider than the divisor or the
     * engine returns before allocating anything. */
    if ((op == 16) || (op == 17) || (op == 20) || (op == 21) || (op == 33)) {
        if (mp_read_radix(&a, WB_A_BIG, MP_RADIX_HEX) != MP_OKAY) {
            wb_fail = 1;
            goto done;
        }
    }

    switch (op) {
    case 0:
    case 1:
    case 2:
    case 5:
        if (mp_read_radix(&m, WB_M_ODD, MP_RADIX_HEX) != MP_OKAY) {
            goto done;
        }
        break;
    case 3:
    case 4:
    case 6:
        if (mp_read_radix(&m, WB_M_EVEN, MP_RADIX_HEX) != MP_OKAY) {
            goto done;
        }
        break;
    case 13:
    case 28:
        if (mp_read_radix(&m, WB_M1024_ODD, MP_RADIX_HEX) != MP_OKAY) {
            goto done;
        }
        break;
    case 14:
    case 29:
        if (mp_read_radix(&m, WB_M1024_EVEN, MP_RADIX_HEX) != MP_OKAY) {
            goto done;
        }
        break;
    case 12:
    case 27:
        if (mp_read_radix(&m, WB_M_EVEN, MP_RADIX_HEX) != MP_OKAY) {
            goto done;
        }
        break;
    default:
        if (mp_read_radix(&m, WB_M_ODD, MP_RADIX_HEX) != MP_OKAY) {
            goto done;
        }
        break;
    }

    /* Base 2 for the dedicated base-2 exponentiation engine. */
    if ((op == 5) || (op == 6) || (op == 10)) {
        mp_set(&b, 2);
    }
    /* Base at (a multiple of) the modulus for the direct engine calls: the
     * public entry point reduces the base first, so this arm is dead from
     * the API. */
    if ((op >= 7) && (op <= 9)) {
        if (mp_copy(&m, &b) != MP_OKAY) {
            goto done;
        }
    }

    mcdc_fa_arm(n);
    switch (op) {
    case 0:
        (void)mp_exptmod(&b, &e, &m, &r);
        break;
    case 1:
        (void)mp_exptmod_ex(&b, &e, (int)m.used, &m, &r);
        break;
    case 2:
        (void)mp_exptmod_nct(&b, &e, &m, &r);
        break;
    case 3:
        (void)mp_exptmod(&b, &e, &m, &r);
        break;
    case 4:
        (void)mp_exptmod_nct(&b, &e, &m, &r);
        break;
    case 5:
    case 6:
        (void)mp_exptmod(&b, &e, &m, &r);
        break;
    case 7:
#ifdef WB_HAVE_EXPTMOD_EX
        (void)_sp_exptmod_ex(&b, &e, sp_count_bits(&e), &m, &r);
#endif
        break;
    case 8:
#ifdef WB_HAVE_EXPTMOD_MONT_EX
        (void)_sp_exptmod_mont_ex(&b, &e, sp_count_bits(&e), &m, &r);
#endif
        break;
    case 9:
#ifdef WB_HAVE_EXPTMOD_NCT
        (void)_sp_exptmod_nct(&b, &e, &m, &r);
#endif
        break;
    case 10:
#ifdef WB_HAVE_EXPTMOD_BASE_2
        (void)_sp_exptmod_base_2(&e, (int)e.used, &m, &r);
#endif
        break;
    case 11:
    case 12:
    case 13:
    case 14:
        (void)mp_invmod(&a, &m, &r);
        break;
    case 15:
#ifdef WOLFSSL_SP_INVMOD_MONT_CT
        (void)mp_invmod_mont_ct(&a, &m, &r, (sp_digit)1);
#endif
        break;
    case 16:
        (void)mp_div(&a, &m, &q, &r);
        break;
    case 17:
        (void)mp_mod(&a, &m, &r);
        break;
    case 18:
        (void)mp_mulmod(&a, &a, &m, &r);
        break;
    case 19:
        (void)mp_sqrmod(&a, &m, &r);
        break;
    case 20:
        (void)mp_gcd(&a, &m, &r);
        break;
    case 21:
#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN) && \
    (!defined(WC_RSA_BLINDING) || defined(HAVE_FIPS) || defined(HAVE_SELFTEST))
        (void)mp_lcm(&a, &m, &r);
#endif
        break;
    case 22:
#ifdef WOLFSSL_SP_PRIME_GEN
        {
            int res = 0;
            (void)mp_prime_is_prime(&m, 2, &res);
        }
#endif
        break;
    case 23:
#if defined(WOLFSSL_SP_PRIME_GEN) && !defined(WC_NO_RNG)
        if (wb_rng_ok) {
            int res = 0;
            (void)mp_prime_is_prime_ex(&m, 2, &res, &wb_rng);
        }
#endif
        break;
    case 24:
        (void)mp_mul(&a, &a, &r);
        break;
    case 25:
        (void)mp_sqr(&a, &r);
        break;

    /* ---- internal engines called directly -------------------------------
     * The public entry points do their own reduction/validation and allocate
     * on the way in, so a fail-index that lands inside the engine is many
     * allocations further along and different for every operand shape.
     * Calling the engine directly puts its first allocation at index 1, which
     * makes the sweep actually walk THAT engine's sites. ------------------ */
    case 26:
    case 27:
    case 28:
    case 29:
#ifdef WOLFSSL_SP_INVMOD
        (void)_sp_invmod(&a, &m, &r);
#endif
        break;
    case 30:
#ifdef WOLFSSL_SP_PRIME_GEN
        {
            int res = 0;
            (void)_sp_prime_trials(&m, 2, &res);
        }
#endif
        break;
    case 31:
#if defined(WOLFSSL_SP_PRIME_GEN) && !defined(WC_NO_RNG)
        if (wb_rng_ok) {
            int res = 0;
            (void)_sp_prime_random_trials(&m, 1, &res, &wb_rng);
        }
#endif
        break;
    case 32:
#ifdef WOLFSSL_SP_PRIME_GEN
        {
            int    res = 0;
            sp_int n1;
            sp_int rr;

            _sp_init_size(&n1, (sp_size_t)(m.used + 1U));
            _sp_init_size(&rr, (sp_size_t)(m.used * 2U + 1U));
            (void)sp_prime_miller_rabin(&m, &b, &res, &n1, &rr);
        }
#endif
        break;
    case 33:
#if defined(WOLFSSL_SP_MATH_ALL) || !defined(NO_DH) || defined(HAVE_ECC) || \
    (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY) && \
     !defined(WOLFSSL_RSA_PUBLIC_ONLY))
        (void)_sp_div(&a, &m, &q, &r, (unsigned int)(a.used + 1U));
#endif
        break;
    default:
        break;
    }
    mcdc_fa_disarm();

done:
    mcdc_fa_disarm();
    mp_free(&a);
    mp_free(&b);
    mp_free(&e);
    mp_free(&m);
    mp_free(&r);
    mp_free(&q);
}

static void wb_sweep(void)
{
    int n;
    int op;

    for (op = 0; op < WB_OP_COUNT; op++) {
        for (n = 1; n <= SP_FAULT_MAX_N; n++) {
            wb_op(op, n);
        }
    }
}

/* Baseline pass: the same operations with the injector installed but never
 * armed, so the TRUE half of every `err == MP_OKAY` checkpoint is recorded in
 * THIS binary too (llvm-cov computes MC/DC independence per binary). */
static void wb_baseline(void)
{
    int op;

    for (op = 0; op < WB_OP_COUNT; op++) {
        wb_op(op, 0);
    }
}

#endif /* WOLFSSL_SP_MATH || WOLFSSL_SP_MATH_ALL */

int main(void)
{
    /* Unbuffered: on a timeout the process is killed and anything still
     * buffered is lost, which reads as an empty log. */
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("sp_int.c heap-fault white-box supplement\n");

#if !defined(WOLFSSL_SP_MATH) && !defined(WOLFSSL_SP_MATH_ALL)
    WB_NOTE("SP math not compiled; nothing to exercise");
#elif defined(MCDC_FA_UNAVAILABLE)
    WB_NOTE("allocator hooks unavailable in this config; nothing to sweep");
#else
    #ifndef WOLFSSL_SMALL_STACK
    WB_NOTE("WOLFSSL_SMALL_STACK off: mp_int temporaries are stack arrays, so "
            "err cannot leave MP_OKAY; sweep runs but cannot fail one");
    #endif
#ifndef WC_NO_RNG
    wb_rng_ok = (wc_InitRng(&wb_rng) == 0);
    if (!wb_rng_ok) {
        WB_NOTE("RNG init failed; randomised prime sweep skipped");
    }
#endif

    mcdc_fa_install();

    wb_baseline();
    wb_sweep();

    mcdc_fa_disarm();
    mcdc_fa_restore();

#ifndef WC_NO_RNG
    if (wb_rng_ok) {
        (void)wc_FreeRng(&wb_rng);
    }
#endif
#endif

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Always 0: a nonzero exit discards this variant's whole coverage. */
    (void)wb_fail;
    return 0;
}
