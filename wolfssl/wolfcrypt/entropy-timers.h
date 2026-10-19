/* entropy-timers.h
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

/*!
    \file wolfssl/wolfcrypt/entropy-timers.h
*/

/* Build-time timers for wolfEntropy; each one sets CUSTOM_ENTROPY_TIMEHIRES,
 * which wolfentropy.c uses before its own timers. */

#ifndef WOLF_CRYPT_ENTROPY_TIMERS_H
#define WOLF_CRYPT_ENTROPY_TIMERS_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* AMD core clock (APERF) via RDPRU; reads 0 without RDPRU, so the health
 * tests fail closed.  --enable-wolfEntropy=amd-aperf */
#ifdef WC_ENTROPY_TIMER_AMD_APERF
    /* Bare metal: 5 ns per read.  Cloud VMs can trap RDPRU (AWS c7a: 881 ns,
     * 1.2 s per seed); use --enable-amdrdseed there. */
    #if !defined(__x86_64__) || !(defined(__GNUC__) || defined(__clang__))
        #error WC_ENTROPY_TIMER_AMD_APERF needs x86_64 and GCC or clang
    #endif
    #if defined(WOLFSSL_LINUXKM) || defined(WOLFSSL_BSDKM)
        #error WC_ENTROPY_TIMER_AMD_APERF needs a user-space build
    #endif
    #ifndef __linux__
        #error WC_ENTROPY_TIMER_AMD_APERF needs Linux (CPU number in TSC_AUX)
    #endif
    #ifdef CUSTOM_ENTROPY_TIMEHIRES
        #error WC_ENTROPY_TIMER_AMD_APERF and CUSTOM_ENTROPY_TIMEHIRES both set
    #endif
    #ifdef ENTROPY_MEMUSE_THREAD
        #error WC_ENTROPY_TIMER_AMD_APERF and ENTROPY_MEMUSE_THREAD both set
    #endif
    WOLFSSL_LOCAL word64 wc_Entropy_TimeAmdAperf(void);
    #define CUSTOM_ENTROPY_TIMEHIRES wc_Entropy_TimeAmdAperf
#endif

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLF_CRYPT_ENTROPY_TIMERS_H */
