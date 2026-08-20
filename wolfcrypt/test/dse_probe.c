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

/* DSE probes for ForceZero(). */

/* Must precede every include. */
#define WOLFSSL_VIS_FOR_TESTS

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#if !defined(WOLFSSL_USER_SETTINGS) && !defined(WOLFSSL_NO_OPTIONS_H)
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

/* Pull ForceZero() into this TU to allow potential DSE.
 * Under NO_INLINE, ForceZero() is an opaque external call and immune to DSE,
 * breaking the instruction-count heuristic, so we skip it.
 * Note: check-forcezero-dse.sh --link + NO_INLINE currently fails to link
 * due to missing misc.c (ConstantCompare) anyway.
 */
#ifndef NO_INLINE
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifdef __GNUC__
    #define DSE_PROBE_USED __attribute__((used))
#else
    #define DSE_PROBE_USED
#endif


/* Guard ForceZero(). */
#if !defined(WOLFSSL_NO_FORCE_ZERO) && !defined(NO_INLINE)

/* Shared sink. */
volatile unsigned long dse_probe_sink = 0;

/* Force pre-wipe value to memory. */
#define DSE_PROBE_ESCAPE(p) WC_BARRIER_DATA(p)

/* word32 scalar.
 * Sized off sizeof(unsigned long), not a literal 2: on LP64 targets
 * "unsigned long" is 8 bytes, so word32 v[2] is only one machine word and
 * collapses to a single store -- the one-store jitter this probe exists to
 * rule out. This guarantees at least two machine-word stores everywhere.
 */
#define DSE_PROBE_WORD32_COUNT (2 * sizeof(unsigned long) / sizeof(word32))
DSE_PROBE_USED void dse_probe_word32_wipe(void)
{
    word32 v[DSE_PROBE_WORD32_COUNT];
    unsigned int i;
    for (i = 0; i < DSE_PROBE_WORD32_COUNT; i++)
        v[i] = (word32)(dse_probe_sink * 3UL) + i;
    dse_probe_sink = v[0];
    DSE_PROBE_ESCAPE(v);
    ForceZero(v, sizeof(v));
}
DSE_PROBE_USED void dse_probe_word32_b(void)
{
    word32 v[DSE_PROBE_WORD32_COUNT];
    unsigned int i;
    for (i = 0; i < DSE_PROBE_WORD32_COUNT; i++)
        v[i] = (word32)(dse_probe_sink * 3UL) + i;
    dse_probe_sink = v[0];
    DSE_PROBE_ESCAPE(v);
    WC_BARRIER();
    WC_BARRIER_DATA(v);
}

/* Sub-word length. */
DSE_PROBE_USED void dse_probe_tiny_wipe(void)
{
    byte v[3];
    unsigned int i;
    for (i = 0; i < 3; i++)
        v[i] = (byte)(dse_probe_sink + i);
    dse_probe_sink = v[0];
    DSE_PROBE_ESCAPE(v);
    ForceZero(v, 3);
}
DSE_PROBE_USED void dse_probe_tiny_b(void)
{
    byte v[3];
    unsigned int i;
    for (i = 0; i < 3; i++)
        v[i] = (byte)(dse_probe_sink + i);
    dse_probe_sink = v[0];
    DSE_PROBE_ESCAPE(v);
    WC_BARRIER();
    WC_BARRIER_DATA(v);
}

/* unsigned long scalar. Two words -- see dse_probe_word32_wipe(). */
DSE_PROBE_USED void dse_probe_scalar_wipe(void)
{
    unsigned long v[2];
    unsigned int i;
    for (i = 0; i < 2; i++)
        v[i] = dse_probe_sink * 3UL + i;
    dse_probe_sink = v[0];
    DSE_PROBE_ESCAPE(v);
    ForceZero(v, sizeof(v));
}
DSE_PROBE_USED void dse_probe_scalar_b(void)
{
    unsigned long v[2];
    unsigned int i;
    for (i = 0; i < 2; i++)
        v[i] = dse_probe_sink * 3UL + i;
    dse_probe_sink = v[0];
    DSE_PROBE_ESCAPE(v);
    WC_BARRIER();
    WC_BARRIER_DATA(v);
}

/* Byte arrays. */
#define DSE_PROBE_ARRAY(n, SZ)                                                 \
DSE_PROBE_USED void dse_probe_arr##n##_wipe(void)                       \
{                                                                              \
    byte v[SZ];                                                                \
    unsigned int i;                                                            \
    for (i = 0; i < (SZ); i++)                                                 \
        v[i] = (byte)(dse_probe_sink + i);                                     \
    dse_probe_sink = v[0];                                                     \
    DSE_PROBE_ESCAPE(v);                                                       \
    ForceZero(v, (SZ));                                                        \
}                                                                              \
DSE_PROBE_USED void dse_probe_arr##n##_b(void)                          \
{                                                                              \
    byte v[SZ];                                                                \
    unsigned int i;                                                            \
    for (i = 0; i < (SZ); i++)                                                 \
        v[i] = (byte)(dse_probe_sink + i);                                     \
    dse_probe_sink = v[0];                                                     \
    DSE_PROBE_ESCAPE(v);                                                       \
    WC_BARRIER();                                                              \
    WC_BARRIER_DATA(v);                                                        \
}

DSE_PROBE_ARRAY(8,   8)
DSE_PROBE_ARRAY(32,  32)
DSE_PROBE_ARRAY(128, 128)

/* Unaligned start, sub-word tail. */
DSE_PROBE_USED void dse_probe_unalign_wipe(void)
{
    byte v[40];
    unsigned int i;
    for (i = 0; i < 40; i++)
        v[i] = (byte)(dse_probe_sink + i);
    dse_probe_sink = v[0];
    DSE_PROBE_ESCAPE(v);
    ForceZero(v + 3, 17);
}
DSE_PROBE_USED void dse_probe_unalign_b(void)
{
    byte v[40];
    unsigned int i;
    for (i = 0; i < 40; i++)
        v[i] = (byte)(dse_probe_sink + i);
    dse_probe_sink = v[0];
    DSE_PROBE_ESCAPE(v);
    WC_BARRIER();
    WC_BARRIER_DATA(v + 3);
}

/* Struct field wipe. */
struct dse_probe_kt { unsigned long a; byte k[32]; unsigned long b; };

DSE_PROBE_USED void dse_probe_field_wipe(void)
{
    struct dse_probe_kt s;
    unsigned int i;
    s.a = dse_probe_sink;
    for (i = 0; i < 32; i++)
        s.k[i] = (byte)(dse_probe_sink + i);
    s.b = dse_probe_sink;
    dse_probe_sink = s.k[0] + s.a + s.b;
    DSE_PROBE_ESCAPE(s.k);
    ForceZero(s.k, sizeof(s.k));
}
DSE_PROBE_USED void dse_probe_field_b(void)
{
    struct dse_probe_kt s;
    unsigned int i;
    s.a = dse_probe_sink;
    for (i = 0; i < 32; i++)
        s.k[i] = (byte)(dse_probe_sink + i);
    s.b = dse_probe_sink;
    dse_probe_sink = s.k[0] + s.a + s.b;
    DSE_PROBE_ESCAPE(s.k);
    WC_BARRIER();
    WC_BARRIER_DATA(s.k);
}

#else /* WOLFSSL_NO_FORCE_ZERO || NO_INLINE */

/* Marker for check-forcezero-dse.sh when ForceZero() is compiled out or
 * NO_INLINE is used, differentiating from a toolchain failure.
 */
DSE_PROBE_USED void dse_probe_not_applicable(void)
{
}

#endif /* !WOLFSSL_NO_FORCE_ZERO && !NO_INLINE */

#ifndef NO_MAIN_DRIVER
int main(void)
{
    return 0;
}
#endif /* !NO_MAIN_DRIVER */
