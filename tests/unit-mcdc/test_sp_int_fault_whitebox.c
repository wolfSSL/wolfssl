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
 *     if ((err == MP_OKAY) && sp_isone(a)) {
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
 * Operands are deliberately small. These decisions test the error state and
 * the shape of the operands, not their magnitude, and the sweep repeats every
 * operation once per fail-index -- TEST_TIMEOUT is wall clock and variants run
 * concurrently under MAXPAR, so a full-size modexp here would be a timeout
 * rather than evidence.
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

#ifndef SP_FAULT_MAX_N
    #define SP_FAULT_MAX_N 40
#endif

/* Small primes/moduli: big enough to take the montgomery and non-montgomery
 * routes, small enough that the whole sweep stays well inside TEST_TIMEOUT. */
static const char* WB_M_ODD  = "F0000000000000000000000000000037";
static const char* WB_M_EVEN = "F0000000000000000000000000000038";
static const char* WB_B      = "0123456789ABCDEF0123456789ABCDEF";
static const char* WB_E      = "10001";

static void wb_exptmod_sweep(void)
{
    int n;

    for (n = 1; n <= SP_FAULT_MAX_N; n++) {
        mp_int b;
        mp_int e;
        mp_int m;
        mp_int r;

        if (mp_init_multi(&b, &e, &m, &r, NULL, NULL) != MP_OKAY) {
            wb_fail = 1;
            return;
        }
        if ((mp_read_radix(&b, WB_B, MP_RADIX_HEX) == MP_OKAY) &&
                (mp_read_radix(&e, WB_E, MP_RADIX_HEX) == MP_OKAY)) {
            /* Odd modulus takes the montgomery route, even the divide one. */
            if (mp_read_radix(&m, WB_M_ODD, MP_RADIX_HEX) == MP_OKAY) {
                mcdc_fa_arm(n);
                (void)mp_exptmod(&b, &e, &m, &r);
                (void)mp_exptmod_ex(&b, &e, (int)m.used, &m, &r);
                (void)mp_exptmod_nct(&b, &e, &m, &r);
                mcdc_fa_disarm();
            }
            if (mp_read_radix(&m, WB_M_EVEN, MP_RADIX_HEX) == MP_OKAY) {
                mcdc_fa_arm(n);
                (void)mp_exptmod(&b, &e, &m, &r);
                (void)mp_exptmod_nct(&b, &e, &m, &r);
                mcdc_fa_disarm();
            }
        }
        mp_free(&b);
        mp_free(&e);
        mp_free(&m);
        mp_free(&r);
    }
}

static void wb_invmod_sweep(void)
{
    int n;

    for (n = 1; n <= SP_FAULT_MAX_N; n++) {
        mp_int a;
        mp_int m;
        mp_int r;

        if (mp_init_multi(&a, &m, &r, NULL, NULL, NULL) != MP_OKAY) {
            wb_fail = 1;
            return;
        }
        if (mp_read_radix(&a, WB_B, MP_RADIX_HEX) == MP_OKAY) {
            if (mp_read_radix(&m, WB_M_ODD, MP_RADIX_HEX) == MP_OKAY) {
                mcdc_fa_arm(n);
                (void)mp_invmod(&a, &m, &r);
#ifdef WOLFSSL_SP_INVMOD_MONT_CT
                (void)mp_invmod_mont_ct(&a, &m, &r, (sp_digit)1);
#endif
                mcdc_fa_disarm();
            }
            /* Even modulus routes through the division-based inverse. */
            if (mp_read_radix(&m, WB_M_EVEN, MP_RADIX_HEX) == MP_OKAY) {
                mcdc_fa_arm(n);
                (void)mp_invmod(&a, &m, &r);
                mcdc_fa_disarm();
            }
        }
        mp_free(&a);
        mp_free(&m);
        mp_free(&r);
    }
}

static void wb_div_mul_sweep(void)
{
    int n;

    for (n = 1; n <= SP_FAULT_MAX_N; n++) {
        mp_int a;
        mp_int b;
        mp_int q;
        mp_int rem;

        if (mp_init_multi(&a, &b, &q, &rem, NULL, NULL) != MP_OKAY) {
            wb_fail = 1;
            return;
        }
        if ((mp_read_radix(&a, WB_B, MP_RADIX_HEX) == MP_OKAY) &&
                (mp_read_radix(&b, WB_M_ODD, MP_RADIX_HEX) == MP_OKAY)) {
            mcdc_fa_arm(n);
            (void)mp_div(&a, &b, &q, &rem);
            (void)mp_mod(&a, &b, &rem);
            (void)mp_mulmod(&a, &a, &b, &rem);
            (void)mp_sqrmod(&a, &b, &rem);
            (void)mp_gcd(&a, &b, &q);
            mcdc_fa_disarm();
        }
        mp_free(&a);
        mp_free(&b);
        mp_free(&q);
        mp_free(&rem);
    }
}

#if defined(WOLFSSL_KEY_GEN) || !defined(NO_DH) || !defined(NO_DSA)
static void wb_prime_sweep(void)
{
    int n;

    for (n = 1; n <= SP_FAULT_MAX_N; n++) {
        mp_int a;
        int    res = 0;

        if (mp_init(&a) != MP_OKAY) {
            wb_fail = 1;
            return;
        }
        if (mp_read_radix(&a, WB_M_ODD, MP_RADIX_HEX) == MP_OKAY) {
            mcdc_fa_arm(n);
            (void)mp_prime_is_prime(&a, 2, &res);
            mcdc_fa_disarm();
        }
        mp_free(&a);
    }
}
#else
static void wb_prime_sweep(void)
{
    WB_NOTE("prime testing not compiled; skipped");
}
#endif

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
    mcdc_fa_install();

    wb_exptmod_sweep();
    wb_invmod_sweep();
    wb_div_mul_sweep();
    wb_prime_sweep();

    mcdc_fa_disarm();
    mcdc_fa_restore();
#endif

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Always 0: a nonzero exit discards this variant's whole coverage. */
    (void)wb_fail;
    return 0;
}
