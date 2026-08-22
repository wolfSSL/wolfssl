/* oe_timers.c
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

DESCRIPTION
Per-platform high resolution counter read for the SP 800-90B noise source in
wolfentropy.c.  This translation unit is deliberately placed OUTSIDE the FIPS
module boundary: src/include.am lists it after wolfcrypt_last.c, so its .text
falls beyond wolfCrypt_FIPS_last() and is not covered by the in-core integrity
hash.

The point of the split is that porting the noise source to a new platform adds
an arm HERE and changes nothing inside the boundary.  wolfentropy.c holds a
single fixed call site (`wc_OE_TimeHiRes()`), so the in-boundary bytes are
identical across every platform.

Note what this does NOT change: the entropy estimate for a new platform still
requires its own SP 800-90B raw-data collection and ESV entry.  Moving the code
out of the boundary trades a module change for an ESV change; it does not make
a port free.  The noise source's continuous health tests (RCT/APT) and its
SHA3-256 conditioning stay inside the boundary in wolfentropy.c.

Selection is resolved entirely at BUILD time by the #if ladder below.  There is
no runtime selection and no function pointer: one build produces exactly one
definition of wc_OE_TimeHiRes().  If no arm matches, the build fails rather
than falling back to a second mechanism.

*/

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

/* Mirrors the call-site condition in wolfentropy.c: a custom counter always
 * wins, otherwise the hardware counter is used unless the build asked for the
 * threaded proxy, in which case nothing here is needed. */
#if defined(HAVE_ENTROPY_MEMUSE) && \
    (defined(CUSTOM_ENTROPY_TIMEHIRES) || !defined(ENTROPY_MEMUSE_THREAD))

#include <wolfssl/wolfcrypt/oe_timers.h>

#if defined(__APPLE__) || defined(__MACH__)
    #include <mach/mach_time.h>
#endif

#ifdef CUSTOM_ENTROPY_TIMEHIRES
word64 wc_OE_TimeHiRes(void)
{
    return CUSTOM_ENTROPY_TIMEHIRES();
}
#elif defined(__x86_64__) || defined(__i386__)
/* Get the high resolution time counter.
 *
 * @return  64-bit count of CPU cycles.
 */
word64 wc_OE_TimeHiRes(void)
{
    unsigned int lo_c, hi_c;
    __asm__ __volatile__ (
        "rdtsc"
            : "=a"(lo_c), "=d"(hi_c)   /* out */
            : "a"(0)                   /* in */
            : "%ebx", "%ecx");         /* clobber */
    return ((word64)lo_c) | (((word64)hi_c) << 32);
}
#elif defined(__APPLE__) || defined(__MACH__)
/* Get the high resolution time counter.
 *
 * @return  64-bit time in nanoseconds.
 */
word64 wc_OE_TimeHiRes(void)
{
    return clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW);
}
#elif defined(__aarch64__)
/* Get the high resolution time counter.
 *
 * @return  64-bit timer count.
 */
word64 wc_OE_TimeHiRes(void)
{
    word64 cnt;
    __asm__ __volatile__ (
        "mrs %[cnt], cntvct_el0"
        : [cnt] "=r"(cnt)
        :
        :
    );
    return cnt;
}
#elif defined(__MICROBLAZE__)

#define LPD_SCNTR_BASE_ADDRESS 0xFF250000

/* Get the high resolution time counter.
 * Collect ticks from LPD_SCNTR
 * @return  64-bit tick count.
 */
word64 wc_OE_TimeHiRes(void)
{
    word64 cnt;
    word32 *ptr;

    ptr = (word32*)LPD_SCNTR_BASE_ADDRESS;
    cnt = *(ptr+1);
    cnt = cnt << 32;
    cnt |= *ptr;

    return cnt;
}
#elif defined(_POSIX_C_SOURCE) && (_POSIX_C_SOURCE >= 199309L)
/* Get the high resolution time counter.
 *
 * @return  64-bit time that is the nanoseconds of current time.
 */
word64 wc_OE_TimeHiRes(void)
{
    struct timespec now;

    clock_gettime(CLOCK_REALTIME, &now);

    return now.tv_nsec;
}
#elif defined(_WIN32) /* USE_WINDOWS_API */
/* Get the high resolution time counter.
 *
 * @return  64-bit timer
 */
word64 wc_OE_TimeHiRes(void)
{
    LARGE_INTEGER count;
    QueryPerformanceCounter(&count);
    return (word64)(count.QuadPart);
}
#elif defined(__arm__)
/* Get time counter from arch_sys_counter clocksource.
 *
 * @return  64-bit timer count.
 */
word64 wc_OE_TimeHiRes(void)
{
    word32 lo, hi;
    __asm__ __volatile__ (
        "mrrc p15, 1, %[lo], %[hi], c14"
        : [lo] "=r"(lo), [hi] "=r"(hi)
    );
    return ((word64)hi << 32) | lo;
}
#else
    #error oe_timers.c: no high resolution counter for this \
platform. Add an arm to oe_timers.c or define CUSTOM_ENTROPY_TIMEHIRES.
#endif

#endif /* HAVE_ENTROPY_MEMUSE && (CUSTOM || !THREAD) */
