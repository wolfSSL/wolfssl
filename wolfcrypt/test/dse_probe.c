/* dse_probe.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335,
 * USA
 */

/*
 * Dead-store-elimination (DSE) regression probes for ForceZero().
 *
 * check-forcezero-dse.sh compiles this file against a configured build
 * directory (real flags, real headers, real include paths) and checks that
 * every *_wipe() function emits more non-barrier stores than its *_b()
 * twin.  A wipe folded away by the compiler is caught as a regression
 * before it ships.
 *
 * Why pull in misc.c here?
 * ForceZero() is WC_MISC_STATIC WC_INLINE - its body only exists inside
 * each translation unit that includes misc.c.  DSE of the zeroing stores
 * happens inside that TU.  To observe DSE we must compile ForceZero() in
 * the same TU as the caller; the WOLFSSL_MISC_INCLUDED guard is the
 * established mechanism for this (also used by wolfcrypt/test/test.c via
 * WOLFSSL_VIS_FOR_TESTS).
 *
 * Why is this better than the old shell-script probe?
 * The old check-forcezero-dse.sh constructed a C file inline and compiled
 * it with hand-rolled -I paths and feature flags.  This file is compiled
 * by the script using the flags from an existing configured build
 * directory (-I<builddir> -I<srcdir> -DHAVE_CONFIG_H), so the probe sees
 * exactly the same preprocessor state as the rest of the library.
 *
 * Probe naming convention:
 *   <case>_wipe   - calls ForceZero() on a dead local; stores must survive.
 *   <case>_b      - identical arithmetic plus both barriers, no wipe; this
 *                   is the baseline check-forcezero-dse.sh compares against
 *                   (isolates the zeroing stores from barrier overhead).
 *   <case>_nowipe - identical arithmetic, no wipe, no barriers; kept for
 *                   manual inspection (objdump -d), not used by the script.
 * check-forcezero-dse.sh asserts wipe_insns > b_insns for every case.
 *
 * The probe does NOT read back the zeroed memory.  Reading it back would
 * make the stores live and trivially prevent DSE - the whole point is that
 * WC_BARRIER_DATA() / WC_BARRIER() must keep them alive without a read.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#if !defined(WOLFSSL_USER_SETTINGS) && !defined(WOLFSSL_NO_OPTIONS_H)
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

/* Pull ForceZero() into this TU as a static inline, exactly like test.c
 * does via WOLFSSL_VIS_FOR_TESTS.  The guard prevents the "misc.c does
 * not need to be compiled" warning that misc.c emits when NO_INLINE is
 * not defined. */
#define WOLFSSL_MISC_INCLUDED
#include <wolfcrypt/src/misc.c>

/* ForceZero() only exists when misc.c is built with this defined; skip the
 * probes under WOLFSSL_NO_FORCE_ZERO so the script's own "no dse_probe_*
 * symbols found" diagnostic fires instead of an undeclared-function error. */
#ifndef WOLFSSL_NO_FORCE_ZERO

/* Shared sink: the compiler cannot see through this extern volatile, so
 * writes to it (and reads from locals before it) are never optimised away.
 * Only the post-wipe zeroing stores are left potentially dead. */
volatile unsigned long dse_probe_sink = 0;

/* -----------------------------------------------------------------------
 * word32 scalar
 * --------------------------------------------------------------------- */
__attribute__((used)) void dse_probe_word32_wipe(void)
{
    word32 v = (word32)(dse_probe_sink * 3UL);
    dse_probe_sink = v;
    ForceZero(&v, sizeof(v));
}
__attribute__((used)) void dse_probe_word32_nowipe(void)
{
    word32 v = (word32)(dse_probe_sink * 3UL);
    dse_probe_sink = v;
}
__attribute__((used)) void dse_probe_word32_b(void)
{
    word32 v = (word32)(dse_probe_sink * 3UL);
    dse_probe_sink = v;
    WC_BARRIER();
    WC_BARRIER_DATA(&v);
}

/* -----------------------------------------------------------------------
 * sub-word length (3 bytes)
 * --------------------------------------------------------------------- */
__attribute__((used)) void dse_probe_tiny_wipe(void)
{
    byte v[3];
    unsigned int i;
    for (i = 0; i < 3; i++)
        v[i] = (byte)(dse_probe_sink + i);
    dse_probe_sink = v[0];
    ForceZero(v, 3);
}
__attribute__((used)) void dse_probe_tiny_nowipe(void)
{
    byte v[3];
    unsigned int i;
    for (i = 0; i < 3; i++)
        v[i] = (byte)(dse_probe_sink + i);
    dse_probe_sink = v[0];
}
__attribute__((used)) void dse_probe_tiny_b(void)
{
    byte v[3];
    unsigned int i;
    for (i = 0; i < 3; i++)
        v[i] = (byte)(dse_probe_sink + i);
    dse_probe_sink = v[0];
    WC_BARRIER();
    WC_BARRIER_DATA(v);
}

/* -----------------------------------------------------------------------
 * unsigned long scalar
 * --------------------------------------------------------------------- */
__attribute__((used)) void dse_probe_scalar_wipe(void)
{
    unsigned long v = dse_probe_sink * 3UL;
    dse_probe_sink = v;
    ForceZero(&v, sizeof(v));
}
__attribute__((used)) void dse_probe_scalar_nowipe(void)
{
    unsigned long v = dse_probe_sink * 3UL;
    dse_probe_sink = v;
}
__attribute__((used)) void dse_probe_scalar_b(void)
{
    unsigned long v = dse_probe_sink * 3UL;
    dse_probe_sink = v;
    WC_BARRIER();
    WC_BARRIER_DATA(&v);
}

/* -----------------------------------------------------------------------
 * byte arrays: 8, 32, 128 bytes
 * --------------------------------------------------------------------- */
#define DSE_PROBE_ARRAY(n, SZ)                                                 \
__attribute__((used)) void dse_probe_arr##n##_wipe(void)                       \
{                                                                              \
    byte v[SZ];                                                                \
    unsigned int i;                                                            \
    for (i = 0; i < (SZ); i++)                                                 \
        v[i] = (byte)(dse_probe_sink + i);                                     \
    dse_probe_sink = v[0];                                                     \
    ForceZero(v, (SZ));                                                        \
}                                                                              \
__attribute__((used)) void dse_probe_arr##n##_nowipe(void)                     \
{                                                                              \
    byte v[SZ];                                                                \
    unsigned int i;                                                            \
    for (i = 0; i < (SZ); i++)                                                 \
        v[i] = (byte)(dse_probe_sink + i);                                     \
    dse_probe_sink = v[0];                                                     \
}                                                                              \
__attribute__((used)) void dse_probe_arr##n##_b(void)                          \
{                                                                              \
    byte v[SZ];                                                                \
    unsigned int i;                                                            \
    for (i = 0; i < (SZ); i++)                                                 \
        v[i] = (byte)(dse_probe_sink + i);                                     \
    dse_probe_sink = v[0];                                                     \
    WC_BARRIER();                                                              \
    WC_BARRIER_DATA(v);                                                        \
}

DSE_PROBE_ARRAY(8,   8)
DSE_PROBE_ARRAY(32,  32)
DSE_PROBE_ARRAY(128, 128)

/* -----------------------------------------------------------------------
 * unaligned start + sub-word tail (17 bytes starting at offset 3)
 * --------------------------------------------------------------------- */
__attribute__((used)) void dse_probe_unalign_wipe(void)
{
    byte v[40];
    unsigned int i;
    for (i = 0; i < 40; i++)
        v[i] = (byte)(dse_probe_sink + i);
    dse_probe_sink = v[0];
    ForceZero(v + 3, 17);
}
__attribute__((used)) void dse_probe_unalign_nowipe(void)
{
    byte v[40];
    unsigned int i;
    for (i = 0; i < 40; i++)
        v[i] = (byte)(dse_probe_sink + i);
    dse_probe_sink = v[0];
}
__attribute__((used)) void dse_probe_unalign_b(void)
{
    byte v[40];
    unsigned int i;
    for (i = 0; i < 40; i++)
        v[i] = (byte)(dse_probe_sink + i);
    dse_probe_sink = v[0];
    WC_BARRIER();
    WC_BARRIER_DATA(v + 3);
}

/* -----------------------------------------------------------------------
 * struct field wipe (key material inside a larger struct)
 * --------------------------------------------------------------------- */
struct dse_probe_kt { unsigned long a; byte k[32]; unsigned long b; };

__attribute__((used)) void dse_probe_field_wipe(void)
{
    struct dse_probe_kt s;
    unsigned int i;
    s.a = dse_probe_sink;
    for (i = 0; i < 32; i++)
        s.k[i] = (byte)(dse_probe_sink + i);
    s.b = dse_probe_sink;
    dse_probe_sink = s.k[0] + s.a + s.b;
    ForceZero(s.k, sizeof(s.k));
}
__attribute__((used)) void dse_probe_field_nowipe(void)
{
    struct dse_probe_kt s;
    unsigned int i;
    s.a = dse_probe_sink;
    for (i = 0; i < 32; i++)
        s.k[i] = (byte)(dse_probe_sink + i);
    s.b = dse_probe_sink;
    dse_probe_sink = s.k[0] + s.a + s.b;
}
__attribute__((used)) void dse_probe_field_b(void)
{
    struct dse_probe_kt s;
    unsigned int i;
    s.a = dse_probe_sink;
    for (i = 0; i < 32; i++)
        s.k[i] = (byte)(dse_probe_sink + i);
    s.b = dse_probe_sink;
    dse_probe_sink = s.k[0] + s.a + s.b;
    WC_BARRIER();
    WC_BARRIER_DATA(s.k);
}

#endif /* !WOLFSSL_NO_FORCE_ZERO */

int main(void)
{
    return 0;
}
