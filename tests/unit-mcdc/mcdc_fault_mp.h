/* mcdc_fault_mp.h
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
 * mcdc_fault_mp.h -- header-only big-integer (mp_*) fault injector for the
 * per-module MC/DC campaign. Third lever, beside mcdc_fault_alloc.h (heap) and
 * mcdc_fault_hash.h (hash / block-cipher primitives).
 *
 * WHY
 * ---
 * dh.c, dsa.c, eccsi.c and sakke.c are written as long big-integer success
 * chains:
 *
 *     if (ret == 0 && mp_copy(&key->p, p) != MP_OKAY) ...
 *     if (ret == 0 && mp_to_unsigned_bin(y, pub) != MP_OKAY) ...
 *     while ((err == 0) && (mp_iszero(ssk) || ...)) ...
 *     for (i = ...; (err == 0) && (i >= 0); i--) ...
 *
 * BOTH operands of these are residual, for the same underlying reason: on a
 * healthy machine no mp_* call ever fails, so
 *   - operand 1 (`mp_xxx(...) != MP_OKAY`) is never TRUE, and
 *   - operand 0 (`ret == 0`) is never FALSE, because nothing upstream failed.
 * The heap-fault lever only reaches these where the mp_int scratch itself is
 * heap-allocated (the small_stack variants), and even there it can only make
 * the ALLOCATION fail, never a computation.
 *
 * HOW
 * ---
 * Same macro-interposition trick as mcdc_fault_hash.h, applied to the mp_*
 * API: this header defines typed wrapper functions that call the REAL mp_*
 * entry point, and only THEN #defines the mp_* names to the wrappers. The
 * ordering is load-bearing -- the wrappers are compiled while mp_copy still
 * means sp_copy (or the integer.c/tfm.c function, depending on the math
 * backend), so they reach the genuine implementation. The involved .c must be
 * #included AFTER this header.
 *
 * mcdc_fm_arm(n) makes the n-th mp_* call -- and every later one -- return
 * MP_VAL, exactly mirroring mcdc_fa_arm()/mcdc_fh_arm(). Sweeping n therefore
 *   - drives operand 1 TRUE at the call site whose index is n, and
 *   - drives operand 0 FALSE at every guard downstream of it,
 * which is precisely the pair of residuals above, from one sweep.
 *
 * ONLY value-returning COMPUTATION operations are interposed. Predicates
 * (mp_iszero / mp_cmp / mp_count_bits / mp_unsigned_bin_size) and teardown
 * (mp_clear / mp_free / mp_forcezero) are deliberately left alone: faulting
 * them would change program meaning rather than inject an error, and cleanup
 * must keep working so an armed call stays crash-safe.
 *
 * SWEEP PATTERN
 *     mcdc_fm_disarm();          -- baseline: everything succeeds (the TRUE
 *     Target(...);                  half of every guard, same binary)
 *     k = mcdc_fm_seen();        -- number of mp_* calls that took
 *     for (n = 1; n <= k; n++) {
 *         ...rebuild inputs while DISARMED...
 *         mcdc_fm_arm(n);
 *         (void)Target(...);
 *         mcdc_fm_disarm();
 *     }
 *
 * PORTABILITY
 * -----------
 * The wrappers use mp_int / mp_digit / WC_RNG, which every math backend
 * (sp_int.h, integer.h, tfm.h) provides, and non-const pointer parameters so
 * they bind under all three. A backend that does not provide one of the
 * wrapped entry points is handled by the per-function guards below; a TU that
 * must not interpose a given call can #undef that macro after including this
 * header.
 */

#ifndef MCDC_FAULT_MP_H
#define MCDC_FAULT_MP_H

/* Must be first: same include prologue every wolfcrypt .c uses, so including
 * this header before the involved .c does not change how that .c sees the
 * world. */
#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/wolfmath.h>

/* MP_VAL is defined by every math backend and is the code these callers
 * already propagate for a rejected big-integer operation. */
#define MCDC_FM_ERR   MP_VAL

#if defined(__GNUC__) || defined(__clang__)
    #define MCDC_FM_MAYBE_UNUSED __attribute__((unused))
#else
    #define MCDC_FM_MAYBE_UNUSED
#endif

/* file-static injector state (one TU per white-box, so file scope is fine) */
static long mcdc_fm_count   = 0;  /* mp_* calls seen since arm/disarm */
static long mcdc_fm_fail_at = 0;  /* fail from this index on; 0 = off  */

MCDC_FM_MAYBE_UNUSED static int mcdc_fm_hit(void)
{
    mcdc_fm_count++;
    return (mcdc_fm_fail_at != 0) && (mcdc_fm_count >= mcdc_fm_fail_at);
}

/* Arm: the n-th mp_* call from now on (and every later one) returns MP_VAL. */
MCDC_FM_MAYBE_UNUSED static void mcdc_fm_arm(long n)
{
    mcdc_fm_count   = 0;
    mcdc_fm_fail_at = (n > 0) ? n : 0;
}

MCDC_FM_MAYBE_UNUSED static void mcdc_fm_disarm(void)
{
    mcdc_fm_fail_at = 0;
    mcdc_fm_count   = 0;
}

/* mp_* calls counted since the last arm()/disarm(); sizes the sweep. */
MCDC_FM_MAYBE_UNUSED static long mcdc_fm_seen(void)
{
    return mcdc_fm_count;
}

/* ---- wrappers (compiled while the mp_* names still mean the real thing) -- */

/* Input operands are taken as `const mp_int*` and cast on the way through:
 * sp_int.h declares them const while integer.h / tfm.h do not, and callers in
 * dh.c / dsa.c / eccsi.c / sakke.c pass both. Accepting const and casting is
 * the one signature that binds cleanly under every math backend without
 * emitting -Wincompatible-pointer-types-discards-qualifiers at the call site.
 * The cast is safe: the wrapper only forwards the pointer to the real
 * operation, which does not write through it. */
#define MCDC_FM_MI(x)  ((mp_int*)(x))

#define MCDC_FM_W0(nm, fn)                                                   \
    MCDC_FM_MAYBE_UNUSED static int nm(mp_int* a)                            \
    { if (mcdc_fm_hit()) return MCDC_FM_ERR; return fn(a); }
#define MCDC_FM_W2(nm, fn)                                                   \
    MCDC_FM_MAYBE_UNUSED static int nm(const mp_int* a, mp_int* r)           \
    { if (mcdc_fm_hit()) return MCDC_FM_ERR; return fn(MCDC_FM_MI(a), r); }
#define MCDC_FM_W3(nm, fn)                                                   \
    MCDC_FM_MAYBE_UNUSED static int nm(const mp_int* a, const mp_int* b,     \
        mp_int* r)                                                           \
    { if (mcdc_fm_hit()) return MCDC_FM_ERR;                                 \
      return fn(MCDC_FM_MI(a), MCDC_FM_MI(b), r); }
#define MCDC_FM_W4(nm, fn)                                                   \
    MCDC_FM_MAYBE_UNUSED static int nm(const mp_int* a, const mp_int* b,     \
        const mp_int* c, mp_int* r)                                          \
    { if (mcdc_fm_hit()) return MCDC_FM_ERR;                                 \
      return fn(MCDC_FM_MI(a), MCDC_FM_MI(b), MCDC_FM_MI(c), r); }
#define MCDC_FM_WD3(nm, fn)                                                  \
    MCDC_FM_MAYBE_UNUSED static int nm(const mp_int* a, mp_digit d,          \
        mp_int* r)                                                           \
    { if (mcdc_fm_hit()) return MCDC_FM_ERR;                                 \
      return fn(MCDC_FM_MI(a), d, r); }

#ifdef MCDC_FM_WITH_INIT
MCDC_FM_W0(mcdc_fm_init,   mp_init)
MCDC_FM_MAYBE_UNUSED static int mcdc_fm_init_multi(mp_int* a, mp_int* b,
    mp_int* c, mp_int* d, mp_int* e, mp_int* f)
{
    if (mcdc_fm_hit())
        return MCDC_FM_ERR;
    return mp_init_multi(a, b, c, d, e, f);
}
#endif /* MCDC_FM_WITH_INIT */
MCDC_FM_W2(mcdc_fm_copy,   mp_copy)
MCDC_FM_W3(mcdc_fm_add,    mp_add)
MCDC_FM_W3(mcdc_fm_sub,    mp_sub)
MCDC_FM_W3(mcdc_fm_mul,    mp_mul)
MCDC_FM_W3(mcdc_fm_mod,    mp_mod)
MCDC_FM_W3(mcdc_fm_invmod, mp_invmod)
MCDC_FM_W2(mcdc_fm_sqr,    mp_sqr)
MCDC_FM_W4(mcdc_fm_mulmod, mp_mulmod)
MCDC_FM_W4(mcdc_fm_addmod, mp_addmod)
MCDC_FM_W4(mcdc_fm_submod, mp_submod)
MCDC_FM_W4(mcdc_fm_exptmod, mp_exptmod)
MCDC_FM_WD3(mcdc_fm_add_d, mp_add_d)
MCDC_FM_WD3(mcdc_fm_sub_d, mp_sub_d)
MCDC_FM_WD3(mcdc_fm_mul_d, mp_mul_d)

MCDC_FM_MAYBE_UNUSED static int mcdc_fm_set(mp_int* a, mp_digit d)
{
    if (mcdc_fm_hit())
        return MCDC_FM_ERR;
    return mp_set(a, d);
}

MCDC_FM_MAYBE_UNUSED static int mcdc_fm_read_unsigned_bin(mp_int* a,
    const byte* in, word32 inSz)
{
    if (mcdc_fm_hit())
        return MCDC_FM_ERR;
    return mp_read_unsigned_bin(a, in, inSz);
}

MCDC_FM_MAYBE_UNUSED static int mcdc_fm_to_unsigned_bin(const mp_int* a,
    byte* out)
{
    if (mcdc_fm_hit())
        return MCDC_FM_ERR;
    return mp_to_unsigned_bin(MCDC_FM_MI(a), out);
}

MCDC_FM_MAYBE_UNUSED static int mcdc_fm_to_unsigned_bin_len(const mp_int* a,
    byte* out, int outSz)
{
    if (mcdc_fm_hit())
        return MCDC_FM_ERR;
    return mp_to_unsigned_bin_len(MCDC_FM_MI(a), out, outSz);
}

MCDC_FM_MAYBE_UNUSED static int mcdc_fm_read_radix(mp_int* a, const char* in,
    int radix)
{
    if (mcdc_fm_hit())
        return MCDC_FM_ERR;
    return mp_read_radix(a, in, radix);
}

MCDC_FM_MAYBE_UNUSED static int mcdc_fm_exptmod_ex(const mp_int* b,
    const mp_int* e, int digits, const mp_int* m, mp_int* r)
{
    if (mcdc_fm_hit())
        return MCDC_FM_ERR;
    return mp_exptmod_ex(MCDC_FM_MI(b), MCDC_FM_MI(e), digits, MCDC_FM_MI(m),
        r);
}

MCDC_FM_MAYBE_UNUSED static int mcdc_fm_prime_is_prime(const mp_int* a, int t,
    int* result)
{
    if (mcdc_fm_hit())
        return MCDC_FM_ERR;
    return mp_prime_is_prime(MCDC_FM_MI(a), t, result);
}

MCDC_FM_MAYBE_UNUSED static int mcdc_fm_prime_is_prime_ex(const mp_int* a,
    int t, int* result, WC_RNG* rng)
{
    if (mcdc_fm_hit())
        return MCDC_FM_ERR;
    return mp_prime_is_prime_ex(MCDC_FM_MI(a), t, result, rng);
}

MCDC_FM_MAYBE_UNUSED static int mcdc_fm_rand_prime(mp_int* r, int len,
    WC_RNG* rng, void* heap)
{
    if (mcdc_fm_hit())
        return MCDC_FM_ERR;
    return mp_rand_prime(r, len, rng, heap);
}

MCDC_FM_MAYBE_UNUSED static int mcdc_fm_montgomery_setup(const mp_int* m,
    mp_digit* rho)
{
    if (mcdc_fm_hit())
        return MCDC_FM_ERR;
    return mp_montgomery_setup(MCDC_FM_MI(m), rho);
}

MCDC_FM_MAYBE_UNUSED static int mcdc_fm_montgomery_reduce(mp_int* a,
    const mp_int* m, mp_digit mp)
{
    if (mcdc_fm_hit())
        return MCDC_FM_ERR;
    return mp_montgomery_reduce(a, MCDC_FM_MI(m), mp);
}

MCDC_FM_MAYBE_UNUSED static int mcdc_fm_montgomery_calc_normalization(
    mp_int* a, const mp_int* b)
{
    if (mcdc_fm_hit())
        return MCDC_FM_ERR;
    return mp_montgomery_calc_normalization(a, MCDC_FM_MI(b));
}

/* ------------------------------------------------------------------------
 * Install the interposers. Everything above is already bound to the REAL
 * mp_* entry points; from here on the name means the wrapper. The involved
 * .c must be #included AFTER this point.
 * ---------------------------------------------------------------------- */
/* mp_init / mp_init_multi are OPT-IN (MCDC_FM_WITH_INIT), and off by default,
 * because faulting INITIALISATION is not crash-safe in general: a caller that
 * writes `err = mp_init_multi(a, b, ...)` (rather than mapping the failure to
 * MP_INIT_E) then runs a cleanup path that mp_clear()s objects the failed
 * init never constructed -- a segfault on heap-allocated scratch under
 * WOLFSSL_SMALL_STACK. dsa.c does exactly that at three call sites. Faulting
 * the COMPUTATION calls below drives the same residual operands without ever
 * leaving an mp_int unconstructed. */
#ifdef MCDC_FM_WITH_INIT
    #undef  mp_init
    #define mp_init(a)                    mcdc_fm_init((a))
    #undef  mp_init_multi
    #define mp_init_multi(a, b, c, d, e, f) \
        mcdc_fm_init_multi((a), (b), (c), (d), (e), (f))
#endif
#undef  mp_copy
#define mp_copy(a, b)                 mcdc_fm_copy((a), (b))
#undef  mp_set
#define mp_set(a, d)                  mcdc_fm_set((a), (d))
#undef  mp_add
#define mp_add(a, b, c)               mcdc_fm_add((a), (b), (c))
#undef  mp_sub
#define mp_sub(a, b, c)               mcdc_fm_sub((a), (b), (c))
#undef  mp_mul
#define mp_mul(a, b, c)               mcdc_fm_mul((a), (b), (c))
#undef  mp_sqr
#define mp_sqr(a, b)                  mcdc_fm_sqr((a), (b))
#undef  mp_mod
#define mp_mod(a, b, c)               mcdc_fm_mod((a), (b), (c))
#undef  mp_invmod
#define mp_invmod(a, b, c)            mcdc_fm_invmod((a), (b), (c))
#undef  mp_mulmod
#define mp_mulmod(a, b, c, d)         mcdc_fm_mulmod((a), (b), (c), (d))
#undef  mp_addmod
#define mp_addmod(a, b, c, d)         mcdc_fm_addmod((a), (b), (c), (d))
#undef  mp_submod
#define mp_submod(a, b, c, d)         mcdc_fm_submod((a), (b), (c), (d))
#undef  mp_exptmod
#define mp_exptmod(a, b, c, d)        mcdc_fm_exptmod((a), (b), (c), (d))
#undef  mp_exptmod_ex
#define mp_exptmod_ex(b, e, dg, m, r) mcdc_fm_exptmod_ex((b), (e), (dg), (m), (r))
#undef  mp_add_d
#define mp_add_d(a, d, r)             mcdc_fm_add_d((a), (d), (r))
#undef  mp_sub_d
#define mp_sub_d(a, d, r)             mcdc_fm_sub_d((a), (d), (r))
#undef  mp_mul_d
#define mp_mul_d(a, d, r)             mcdc_fm_mul_d((a), (d), (r))
#undef  mp_read_unsigned_bin
#define mp_read_unsigned_bin(a, b, c) mcdc_fm_read_unsigned_bin((a), (b), (c))
#undef  mp_to_unsigned_bin
#define mp_to_unsigned_bin(a, b)      mcdc_fm_to_unsigned_bin((a), (b))
#undef  mp_to_unsigned_bin_len
#define mp_to_unsigned_bin_len(a, b, c) \
    mcdc_fm_to_unsigned_bin_len((a), (b), (c))
#undef  mp_read_radix
#define mp_read_radix(a, b, c)        mcdc_fm_read_radix((a), (b), (c))
#undef  mp_prime_is_prime
#define mp_prime_is_prime(a, t, r)    mcdc_fm_prime_is_prime((a), (t), (r))
#undef  mp_prime_is_prime_ex
#define mp_prime_is_prime_ex(a, t, r, g) \
    mcdc_fm_prime_is_prime_ex((a), (t), (r), (g))
#undef  mp_rand_prime
#define mp_rand_prime(r, l, g, h)     mcdc_fm_rand_prime((r), (l), (g), (h))
#undef  mp_montgomery_setup
#define mp_montgomery_setup(m, rho)   mcdc_fm_montgomery_setup((m), (rho))
#undef  mp_montgomery_reduce
#define mp_montgomery_reduce(a, m, r) mcdc_fm_montgomery_reduce((a), (m), (r))
#undef  mp_montgomery_calc_normalization
#define mp_montgomery_calc_normalization(a, b) \
    mcdc_fm_montgomery_calc_normalization((a), (b))

#endif /* MCDC_FAULT_MP_H */
