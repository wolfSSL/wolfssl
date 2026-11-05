/* entropy-timers.c
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

/* Timers for wolfEntropy.  See wolfssl/wolfcrypt/entropy-timers.h. */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if defined(HAVE_ENTROPY_MEMUSE) && defined(WC_ENTROPY_TIMER_AMD_APERF)

#include <wolfssl/wolfcrypt/entropy-timers.h>
#include <cpuid.h>

/* Bare metal only: hypervisors trap RDPRU (AWS c7a: 881 ns a read, not 5 ns),
 * so a seed takes ~1.2 s in a VM; use --enable-amdrdseed there.  Details: fips
 * repo entropy/portable-timer-callbacks/README.md. */

/* AMD64 APM vol. 3: RDPRU is CPUID Fn8000_0008 EBX bit 4 and RDTSCP is
 * Fn8000_0001 EDX bit 27.  Those leaves are vendor defined: check AMD first. */
static int Entropy_AmdRdpruPresent(void)
{
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;

    if (!__get_cpuid(0, &eax, &ebx, &ecx, &edx) ||
            XMEMCMP(&ebx, "Auth", 4) != 0 || XMEMCMP(&edx, "enti", 4) != 0 ||
            XMEMCMP(&ecx, "cAMD", 4) != 0) {
        return 0;
    }
    if (!__get_cpuid(0x80000001, &eax, &ebx, &ecx, &edx) || !((edx >> 27) & 1))
        return 0;
    return __get_cpuid(0x80000008, &eax, &ebx, &ecx, &edx) && ((ebx >> 4) & 1);
}

/* Linux's per-CPU tag in TSC_AUX, (node << 12) | cpu, returned by RDTSCP.
 * Linux arch/x86/include/asm/segment.h vdso_encode_cpunode() and
 * arch/x86/kernel/cpu/common.c setup_getcpu(). */
static unsigned int Entropy_CpuTag(void)
{
    unsigned int lo, hi, aux;

    __asm__ __volatile__ ("rdtscp" : "=a"(lo), "=d"(hi), "=c"(aux));
    (void)lo;
    (void)hi;
    return aux;
}

/* APERF (RDPRU ECX=1) counts per CPU, so only increments read on one CPU are
 * added, as Linux does (arch/x86/kernel/cpu/aperfmperf.c:475-487).  Returns 0
 * without RDPRU.  Callers hold entropy_mutex. */
word64 wc_Entropy_TimeAmdAperf(void)
{
    static int present = -1;
    static word64 total = 0;
    static word64 last = 0;
    static unsigned int lastCpu = 0xffffffffU;
    unsigned int lo, hi, cpu, cpuAfter;
    word64 aperf;

    if (present < 0) {
        present = Entropy_AmdRdpruPresent();
        if (!present)
            WOLFSSL_MSG("No AMD RDPRU: the APERF entropy timer reads 0");
    }
    if (!present)
        return 0;

    cpu = Entropy_CpuTag();
    /* RDPRU, encoded as bytes for assemblers that do not know it. */
    __asm__ __volatile__ (".byte 0x0f,0x01,0xfd"
                          : "=a"(lo), "=d"(hi) : "c"(1));
    cpuAfter = Entropy_CpuTag();
    aperf = ((word64)hi << 32) | lo;

    if ((cpu == cpuAfter) && (cpu == lastCpu))
        total += aperf - last;
    else if (total == 0)
        total = aperf;
    last = aperf;
    lastCpu = (cpu == cpuAfter) ? cpu : 0xffffffffU;
    return total;
}

#endif /* HAVE_ENTROPY_MEMUSE && WC_ENTROPY_TIMER_AMD_APERF */
