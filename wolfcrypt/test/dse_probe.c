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

/* Pull ForceZero() into TU for DSE testing. Skip for NO_INLINE. */
#ifndef NO_INLINE
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifdef __GNUC__
    #define DSE_PROBE_USED __attribute__((used))
#else
    #define DSE_PROBE_USED
#endif

/* Silence -Wmissing-prototypes for probes. */
PRAGMA_GCC("GCC diagnostic ignored \"-Wmissing-prototypes\"")
PRAGMA_CLANG("clang diagnostic ignored \"-Wmissing-prototypes\"")

/* Guard ForceZero(). */
#if !defined(WOLFSSL_NO_FORCE_ZERO) && !defined(NO_INLINE)

/* Shared sink. */
volatile unsigned long dse_probe_sink = 0;

/* Force pre-wipe value to memory. */
#define DSE_PROBE_ESCAPE(p) WC_BARRIER_DATA(p)

/* Typed scalar array: fills, escapes, then wipes. */
#define DSE_PROBE_SCALAR(name, TYPE, COUNT)                            \
DSE_PROBE_USED void dse_probe_##name##_wipe(void)                      \
{                                                                       \
    TYPE v[COUNT];                                                     \
    unsigned int i;                                                    \
    for (i = 0; i < (COUNT); i++)                                      \
        v[i] = (TYPE)(dse_probe_sink * 3UL) + i;                       \
    dse_probe_sink = v[0];                                             \
    DSE_PROBE_ESCAPE(v);                                               \
    ForceZero(v, sizeof(v));                                           \
}                                                                       \
DSE_PROBE_USED void dse_probe_##name##_b(void)                         \
{                                                                       \
    TYPE v[COUNT];                                                     \
    unsigned int i;                                                    \
    for (i = 0; i < (COUNT); i++)                                      \
        v[i] = (TYPE)(dse_probe_sink * 3UL) + i;                       \
    dse_probe_sink = v[0];                                             \
    DSE_PROBE_ESCAPE(v);                                               \
    WC_BARRIER();                                                      \
    WC_BARRIER_DATA(v);                                                \
}

/* word32, x2 words minimum. */
#define DSE_PROBE_WORD32_COUNT (2 * sizeof(unsigned long) / sizeof(word32))
DSE_PROBE_SCALAR(word32, word32, DSE_PROBE_WORD32_COUNT)

/* unsigned long scalar. Two words -- see dse_probe_word32_wipe() above. */
DSE_PROBE_SCALAR(scalar, unsigned long, 2)

/* Byte arrays: plain byte fill for arbitrary sizes. */
#define DSE_PROBE_ARRAY(name, SZ)                                      \
DSE_PROBE_USED void dse_probe_##name##_wipe(void)                      \
{                                                                       \
    byte v[SZ];                                                        \
    unsigned int i;                                                    \
    for (i = 0; i < (SZ); i++)                                         \
        v[i] = (byte)(dse_probe_sink + i);                             \
    dse_probe_sink = v[0];                                             \
    DSE_PROBE_ESCAPE(v);                                               \
    ForceZero(v, (SZ));                                                \
}                                                                       \
DSE_PROBE_USED void dse_probe_##name##_b(void)                         \
{                                                                       \
    byte v[SZ];                                                        \
    unsigned int i;                                                    \
    for (i = 0; i < (SZ); i++)                                         \
        v[i] = (byte)(dse_probe_sink + i);                             \
    dse_probe_sink = v[0];                                             \
    DSE_PROBE_ESCAPE(v);                                               \
    WC_BARRIER();                                                      \
    WC_BARRIER_DATA(v);                                                \
}

/* Sub-word length. */
DSE_PROBE_ARRAY(tiny, 3)

DSE_PROBE_ARRAY(arr8,   8)
DSE_PROBE_ARRAY(arr32,  32)
DSE_PROBE_ARRAY(arr128, 128)

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

/* check-forcezero-dse.sh marker. */
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
