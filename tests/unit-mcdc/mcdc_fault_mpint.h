/* mcdc_fault_mpint.h
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
 * mcdc_fault_mpint.h -- fault injector for the SCRATCH-mp_int LIFECYCLE macros
 * NEW_MP_INT_SIZE() / INIT_MP_INT_SIZE(), for the per-module MC/DC campaign.
 * Fourth lever, beside mcdc_fault_alloc.h (heap), mcdc_fault_hash.h (digest /
 * block-cipher primitives) and mcdc_fault_mp.h (big-integer computations).
 *
 * WHY
 * ---
 * rsa.c (and ecc.c / asn.c, which use the same idiom) allocate every big-int
 * temporary through the backend-supplied pair
 *
 *     DECL_MP_INT_SIZE_DYN(tmp, mp_bitsused(&key->n), RSA_MAX_SIZE);
 *     NEW_MP_INT_SIZE(tmp, mp_bitsused(&key->n), key->heap, DYNAMIC_TYPE_RSA);
 *     if (tmp == NULL) ...                    (only if MP_INT_SIZE_CHECK_NULL)
 *     if (ret == 0 && INIT_MP_INT_SIZE(tmp, mp_bitsused(&key->n)) != MP_OKAY)
 *
 * and then hang a long success chain off the resulting `ret`. Neither of the
 * two failure modes is reachable from a healthy machine:
 *
 *   - INIT_MP_INT_SIZE() resolves to mp_init_size() (sp_int) or mp_init()
 *     (tfm / integer), neither of which can fail for a scratch object whose
 *     storage the caller already owns, so the `!= MP_OKAY` operand is never
 *     TRUE and the `ret == 0` operand of every guard behind it is never FALSE;
 *   - NEW_MP_INT_SIZE() only performs a real allocation under
 *     WOLFSSL_SMALL_STACK. In every other build it is an XMEMSET of storage
 *     the DECL already reserved on the stack, so the NULL guard behind it
 *     (compiled only when the backend defines MP_INT_SIZE_CHECK_NULL) does not
 *     even exist, and the `ret == 0` operand that follows it is a constant.
 *
 * The heap lever cannot substitute: it can only fault the SMALL_STACK spelling
 * of NEW_MP_INT_SIZE, and it can never make an INIT fail at all. The
 * big-integer lever cannot substitute either: mcdc_fault_mp.h deliberately
 * leaves initialisation alone (see its MCDC_FM_WITH_INIT note) and, in the
 * sp_int backend, INIT_MP_INT_SIZE does not go through mp_init() anyway.
 *
 * HOW
 * ---
 * Same macro-interposition trick as mcdc_fault_hash.h / mcdc_fault_mp.h,
 * applied to the two lifecycle macros: a typed wrapper is compiled while the
 * macro still means the REAL thing, and only THEN is the name redefined to the
 * wrapper. The .c under test must be #included AFTER this header.
 *
 *   mcdc_fmi_arm_init(n)       n-th INIT_MP_INT_SIZE, and every later one,
 *                              reports failure instead of initialising.
 *   mcdc_fmi_arm_init_only(n)  ONLY the n-th one does.
 *   mcdc_fmi_arm_new(n)        n-th NEW_MP_INT_SIZE, and every later one,
 *                              leaves its pointer NULL.
 *   mcdc_fmi_arm_new_only(n)   ONLY the n-th one does.
 *   mcdc_fmi_disarm()          everything succeeds again (counters reset).
 *   mcdc_fmi_init_seen() / mcdc_fmi_new_seen()   sizes the sweep.
 *
 * A one-shot arm matters for the same reason it does in mcdc_fault_alloc.h: a
 * monotone fail-from-n that nulls an EARLIER pointer short-circuits the guard
 * whose later operand is the target (RsaFunctionPrivate's rnd/rndi pair is
 * exactly that shape).
 *
 * SWEEP PATTERN
 *     mcdc_fmi_disarm();          -- baseline: everything succeeds, giving the
 *     Target(...);                   accepting half of every guard IN THE SAME
 *                                    BINARY as the rejecting vectors below
 *     for (n = 1; n <= K; n++) {
 *         mcdc_fmi_arm_init(n);
 *         (void)Target(...);
 *         mcdc_fmi_disarm();
 *     }
 *
 * CRASH SAFETY
 * ------------
 * A faulted INIT leaves the object exactly as NEW_MP_INT_SIZE left it: all
 * zeroes. That is the state every backend's teardown is written to tolerate
 * (sp_clear / sp_forcezero walk `size` digits, which is 0; integer.h's
 * mp_clear tests dp for NULL), and the caller skips every operation on the
 * object because its own `ret` is set. A faulted NEW leaves the pointer NULL,
 * which the caller must test before use -- that test is the point -- and the
 * matching FREE_MP_INT_SIZE is either XFREE(NULL) or nothing at all.
 *
 * AVAILABILITY  (read the note in mcdc_seed_rng.h first: a conditionally
 * available header must still define its API UNCONDITIONALLY, or a TU that
 * calls it fails to COMPILE under some variant -- which the campaign scores as
 * a silent skip rather than an error.)
 *
 * The INIT lever works under every backend: INIT_MP_INT_SIZE is an expression
 * returning int in all three.
 *
 * The NEW lever needs to be able to ASSIGN NULL to the declared name, and that
 * is only true where DECL_MP_INT_SIZE declares a pointer:
 *
 *   sp_int, no WOLFSSL_SMALL_STACK   sp_int* name = (sp_int*)named   -> yes
 *   sp_int, WOLFSSL_SMALL_STACK      real XMALLOC; use the heap lever instead
 *   tfm,    WOLFSSL_SMALL_STACK      real XMALLOC; use the heap lever instead
 *   tfm,    no WOLFSSL_SMALL_STACK   mp_int name[1]  -- an ARRAY -> no
 *   integer.h (always)               mp_int name[1]  -- an ARRAY -> no
 *
 * The first row is exactly the build in which the backend defines
 * MP_INT_ZERO_SIZE and does NOT define MP_INT_SIZE_CHECK_NULL, so that pair of
 * macros is used as the availability test rather than a backend spelling.
 * Where the lever is unavailable the API is still defined, as inert stubs, and
 * mcdc_fmi_new_available() returns 0 so a white-box can say so in its log.
 *
 * Where it IS available this header also defines MP_INT_SIZE_CHECK_NULL, so
 * the caller's NULL guard is compiled and the injected NULL is acted on. That
 * is the same source the WOLFSSL_SMALL_STACK builds compile; it adds no NEW
 * MC/DC condition to the union (every guard it enables in rsa.c is a
 * single-condition `if`, which llvm-cov does not record as an MC/DC decision,
 * except rsa.c's rnd/rndi pair which the small_stack variant already
 * compiles).
 */

#ifndef MCDC_FAULT_MPINT_H
#define MCDC_FAULT_MPINT_H

/* Must be first: same include prologue every wolfcrypt .c uses, so including
 * this header before the involved .c does not change how that .c sees the
 * world. wolfmath.h pulls in whichever backend header (sp_int.h / tfm.h /
 * integer.h) defines the two macros interposed below -- pull it in HERE rather
 * than relying on the .c under test to have done it, so this header never
 * depends on include order. */
#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/wolfmath.h>

#if defined(__GNUC__) || defined(__clang__)
    #define MCDC_FMI_MAYBE_UNUSED __attribute__((unused))
#else
    #define MCDC_FMI_MAYBE_UNUSED
#endif

/* Reported by a faulted INIT_MP_INT_SIZE. MP_VAL is defined by every math
 * backend and is what these callers already map to their own init-failure
 * code, so nothing downstream sees a value it does not already handle. */
#define MCDC_FMI_ERR   MP_VAL

/* The NEW lever is available exactly where DECL_MP_INT_SIZE declares an
 * assignable pointer to storage this header did not allocate; see the
 * AVAILABILITY table above. */
#if !defined(MP_INT_ZERO_SIZE) || defined(MP_INT_SIZE_CHECK_NULL)
    #define MCDC_FMI_NEW_UNAVAILABLE 1
#endif

#ifndef INIT_MP_INT_SIZE
    #define MCDC_FMI_INIT_UNAVAILABLE 1
#endif

/* file-static injector state (one TU per white-box, so file scope is fine) */
static long mcdc_fmi_init_count   = 0;
static long mcdc_fmi_init_fail_at = 0;
static int  mcdc_fmi_init_only    = 0;
static long mcdc_fmi_new_count    = 0;
static long mcdc_fmi_new_fail_at  = 0;
static int  mcdc_fmi_new_only     = 0;

MCDC_FMI_MAYBE_UNUSED static int mcdc_fmi_init_hit(void)
{
    if (mcdc_fmi_init_fail_at == 0)
        return 0;
    ++mcdc_fmi_init_count;
    if (mcdc_fmi_init_only)
        return mcdc_fmi_init_count == mcdc_fmi_init_fail_at;
    return mcdc_fmi_init_count >= mcdc_fmi_init_fail_at;
}

MCDC_FMI_MAYBE_UNUSED static int mcdc_fmi_new_hit(void)
{
    if (mcdc_fmi_new_fail_at == 0)
        return 0;
    ++mcdc_fmi_new_count;
    if (mcdc_fmi_new_only)
        return mcdc_fmi_new_count == mcdc_fmi_new_fail_at;
    return mcdc_fmi_new_count >= mcdc_fmi_new_fail_at;
}

/* Counting probes. Unlike the trip tests above these count unconditionally, so
 * a DISARMED baseline run measures the sweep length. */
static long mcdc_fmi_init_probe = 0;
static long mcdc_fmi_new_probe  = 0;

MCDC_FMI_MAYBE_UNUSED static void mcdc_fmi_arm_init(long n)
{
    mcdc_fmi_init_count   = 0;
    mcdc_fmi_init_only    = 0;
    mcdc_fmi_init_fail_at = (n > 0) ? n : 0;
}

MCDC_FMI_MAYBE_UNUSED static void mcdc_fmi_arm_init_only(long n)
{
    mcdc_fmi_init_count   = 0;
    mcdc_fmi_init_only    = 1;
    mcdc_fmi_init_fail_at = (n > 0) ? n : 0;
}

MCDC_FMI_MAYBE_UNUSED static void mcdc_fmi_arm_new(long n)
{
    mcdc_fmi_new_count   = 0;
    mcdc_fmi_new_only    = 0;
    mcdc_fmi_new_fail_at = (n > 0) ? n : 0;
}

MCDC_FMI_MAYBE_UNUSED static void mcdc_fmi_arm_new_only(long n)
{
    mcdc_fmi_new_count   = 0;
    mcdc_fmi_new_only    = 1;
    mcdc_fmi_new_fail_at = (n > 0) ? n : 0;
}

MCDC_FMI_MAYBE_UNUSED static void mcdc_fmi_disarm(void)
{
    mcdc_fmi_init_count   = 0;
    mcdc_fmi_init_fail_at = 0;
    mcdc_fmi_init_only    = 0;
    mcdc_fmi_new_count    = 0;
    mcdc_fmi_new_fail_at  = 0;
    mcdc_fmi_new_only     = 0;
    mcdc_fmi_init_probe   = 0;
    mcdc_fmi_new_probe    = 0;
}

/* Lifecycle calls seen since the last arm()/disarm(); sizes the sweep. */
MCDC_FMI_MAYBE_UNUSED static long mcdc_fmi_init_seen(void)
{
    return mcdc_fmi_init_probe;
}

MCDC_FMI_MAYBE_UNUSED static long mcdc_fmi_new_seen(void)
{
    return mcdc_fmi_new_probe;
}

MCDC_FMI_MAYBE_UNUSED static int mcdc_fmi_new_available(void)
{
#ifdef MCDC_FMI_NEW_UNAVAILABLE
    return 0;
#else
    return 1;
#endif
}

MCDC_FMI_MAYBE_UNUSED static int mcdc_fmi_init_available(void)
{
#ifdef MCDC_FMI_INIT_UNAVAILABLE
    return 0;
#else
    return 1;
#endif
}

/* ---- wrapper (compiled while INIT_MP_INT_SIZE still means the real thing) - */

#ifndef MCDC_FMI_INIT_UNAVAILABLE
/* `bits` is consumed by the sp_int spelling (mp_init_size(name,
 * MP_BITS_CNT(bits))) and ignored by the tfm / integer spelling (mp_init(name))
 * -- the (void) cast keeps the second one warning-free. The pointer is taken as
 * mp_int* so an array-spelled DECL_MP_INT_SIZE decays into it cleanly. */
MCDC_FMI_MAYBE_UNUSED static int mcdc_fmi_init_call(mp_int* a, unsigned int bits)
{
    ++mcdc_fmi_init_probe;
    if (mcdc_fmi_init_hit())
        return MCDC_FMI_ERR;
    (void)bits;
    return INIT_MP_INT_SIZE(a, bits);
}
#endif /* !MCDC_FMI_INIT_UNAVAILABLE */

/* ------------------------------------------------------------------------
 * Install the interposers. Everything above is already bound to the REAL
 * macros; from here on the names mean the wrappers, so the .c under test must
 * be #included AFTER this point.
 * ---------------------------------------------------------------------- */

#ifndef MCDC_FMI_INIT_UNAVAILABLE
    #undef  INIT_MP_INT_SIZE
    #define INIT_MP_INT_SIZE(name, bits) \
        mcdc_fmi_init_call((mp_int*)(name), (unsigned int)(bits))
#endif

#ifndef MCDC_FMI_NEW_UNAVAILABLE
/* The real macro on this path is
 *     XMEMSET((name), 0, MP_INT_ZERO_SIZE(name, bits))
 * (sp_int.h, the arm without WOLFSSL_SMALL_STACK). It is re-spelled rather
 * than forwarded to because a macro cannot call the definition it replaces:
 * the replacement is "blue-painted" while it expands, so a saved alias would
 * come back out as an undeclared identifier. Zeroing happens FIRST and
 * unconditionally, so the storage is in the same state it would be in without
 * the injector and only the pointer handed to the caller changes.
 *
 * heap / type are ignored here exactly as the real macro ignores them. */
    #undef  NEW_MP_INT_SIZE
    #define NEW_MP_INT_SIZE(name, bits, heap, type)                          \
        do {                                                                 \
            XMEMSET((name), 0, MP_INT_ZERO_SIZE(name, bits));                \
            ++mcdc_fmi_new_probe;                                            \
            if (mcdc_fmi_new_hit()) {                                        \
                (name) = NULL;                                               \
            }                                                                \
        }                                                                    \
        while (0)

/* Compile the caller's NULL guard, which this build would otherwise not have.
 * Without it the injected NULL would be dereferenced instead of tested. */
    #define MP_INT_SIZE_CHECK_NULL
#endif /* !MCDC_FMI_NEW_UNAVAILABLE */

#endif /* MCDC_FAULT_MPINT_H */
