/* ti-c2000-entropy.h
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

/* Oscillator-jitter entropy source for the TI C2000 (C28x).
 *
 * The F28P55x has no TRNG, but it has three independent oscillators (INTOSC1,
 * INTOSC2 - on-chip ~10 MHz RC - and the crystal behind SYSCLK/PLLRAWCLK) and
 * two Dual-Clock Comparators that can count one against another.  A DCC
 * counts PLL edges inside a window of RC-clock cycles; the LSB of that count
 * is the noise bit, carrying the relative phase drift of two physically
 * distinct oscillators.
 *
 * The port supplies only that measurement.  The SP800-90B startup and
 * continuous health tests, the entropy budget, the SHA-256 conditioner and the
 * latched failure state come from the generic wc_NoiseSrc_* layer declared in
 * wolfssl/wolfcrypt/random.h, which the tuning macros below configure.
 *
 * Characterization behind the defaults is in IDE/C2000/README.md.
 */

#ifndef WOLF_CRYPT_PORT_TI_C2000_ENTROPY_H
#define WOLF_CRYPT_PORT_TI_C2000_ENTROPY_H

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/random.h>

#ifdef WOLFSSL_C2000_ENTROPY

/* random.h turns this on for us; catch an include order that defeats it. */
#ifndef WOLFSSL_NOISE_SRC
    #error "WOLFSSL_C2000_ENTROPY needs random.h included first"
#endif

/* Owns the DCCs and static buffers with no locking. */
#if !defined(SINGLE_THREADED) && !defined(WOLFSSL_C2000_ENTROPY_NO_LOCK)
    #error "WOLFSSL_C2000_ENTROPY needs SINGLE_THREADED or WOLFSSL_C2000_ENTROPY_NO_LOCK"
#endif

/* ---- Hardware selection -------------------------------------------------
 * Override these if the board needs a DCC for clock monitoring, targets a
 * different C2000 part, or wants a different oscillator pairing.  Values are
 * C2000Ware driverlib enums, so set them to e.g. DCC_COUNT0SRC_XTAL.
 *
 * Set NUM_SRC to 1 to use source 0 only and leave DCC0 free.  Source 0 is the
 * credited one; source 1 is unaccounted defence-in-depth, so dropping it
 * costs no budgeted entropy. */
#ifndef WOLFSSL_C2000_ENTROPY_NUM_SRC
    #define WOLFSSL_C2000_ENTROPY_NUM_SRC 2
#endif
#if (WOLFSSL_C2000_ENTROPY_NUM_SRC < 1) || (WOLFSSL_C2000_ENTROPY_NUM_SRC > 2)
    #error "WOLFSSL_C2000_ENTROPY_NUM_SRC must be 1 or 2"
#endif

#ifndef WOLFSSL_C2000_ENTROPY_SRC0_DCC
    #define WOLFSSL_C2000_ENTROPY_SRC0_DCC  DCC1_BASE
#endif
#ifndef WOLFSSL_C2000_ENTROPY_SRC0_CLK
    #define WOLFSSL_C2000_ENTROPY_SRC0_CLK  DCC_COUNT0SRC_INTOSC1
#endif
#ifndef WOLFSSL_C2000_ENTROPY_SRC1_DCC
    #define WOLFSSL_C2000_ENTROPY_SRC1_DCC  DCC0_BASE
#endif
#ifndef WOLFSSL_C2000_ENTROPY_SRC1_CLK
    #define WOLFSSL_C2000_ENTROPY_SRC1_CLK  DCC_COUNT0SRC_INTOSC2
#endif
/* The fast clock both sources count.  SYSCLK works if PLLRAWCLK is unusable,
 * at coarser quantization. */
#ifndef WOLFSSL_C2000_ENTROPY_REF_CLK
    #define WOLFSSL_C2000_ENTROPY_REF_CLK   DCC_COUNT1SRC_PLL
#endif

/* Define if the application already manages the DCC peripheral clocks; the
 * port then neither enables nor disables them. */
/* #define WOLFSSL_C2000_ENTROPY_NO_CLK_INIT */

/* ---- Sampling -----------------------------------------------------------
 * Window is in slow-clock cycles per noise bit.  Counter1 seeds at 0xFFFFF
 * and counts down, so the window must stay well under 2^20 PLL cycles; 256
 * (~25.6 us) measured as well as any larger window and is the fastest. */
#ifndef WOLFSSL_C2000_ENTROPY_WINDOW
    #define WOLFSSL_C2000_ENTROPY_WINDOW 256U
#endif

/* ---- Entropy budget -----------------------------------------------------
 * HMIN is assumed min-entropy per raw bit in 1/100 bits; MARGIN oversamples
 * on top.  Measured ~0.92 bits/bit for the credited source, so the 0.5
 * default plus 2x is roughly a 4x cushion.  Raising HMIN gathers less. */
#ifndef WOLFSSL_C2000_ENTROPY_HMIN
    #define WOLFSSL_C2000_ENTROPY_HMIN 50
#endif
#ifndef WOLFSSL_C2000_ENTROPY_MARGIN
    #define WOLFSSL_C2000_ENTROPY_MARGIN 2
#endif
#if (WOLFSSL_C2000_ENTROPY_MARGIN) < 1
    #error "WOLFSSL_C2000_ENTROPY_MARGIN must be >= 1"
#endif
#if (WOLFSSL_C2000_ENTROPY_HMIN) < 1 || (WOLFSSL_C2000_ENTROPY_HMIN) > 100
    #error "WOLFSSL_C2000_ENTROPY_HMIN is 1/100 bits per raw bit: use 1..100"
#endif

/* ---- SP800-90B 4.4 health tests -----------------------------------------
 * Cutoffs assume 4 bits of min-entropy per octet (8 raw bits x HMIN 0.5) at
 * alpha = 2^-30, from the exact binomial:
 *   RCT 4.4.1: C = 1 + ceil(30/H)                   = 9
 *   APT 4.4.2: C = 1 + CRITBINOM(W, 2^-H, 1-alpha)  = 71 at W = 512
 * Recompute both if HMIN changes: a cutoff that does not match the assumed H
 * either never trips or trips constantly. */
#ifndef WOLFSSL_C2000_ENTROPY_RCT_CUTOFF
    #define WOLFSSL_C2000_ENTROPY_RCT_CUTOFF 9
#endif
#ifndef WOLFSSL_C2000_ENTROPY_APT_WINDOW
    #define WOLFSSL_C2000_ENTROPY_APT_WINDOW 512
#endif
#ifndef WOLFSSL_C2000_ENTROPY_APT_CUTOFF
    #define WOLFSSL_C2000_ENTROPY_APT_CUTOFF 71
#endif

/* SP800-90B 4.3 startup test, octets per source.  Must exceed one APT window
 * or the startup pass never exercises that test. */
#ifndef WOLFSSL_C2000_ENTROPY_STARTUP_OCTETS
    #define WOLFSSL_C2000_ENTROPY_STARTUP_OCTETS 1024
#endif
#if WOLFSSL_C2000_ENTROPY_STARTUP_OCTETS < WOLFSSL_C2000_ENTROPY_APT_WINDOW
    #error "WOLFSSL_C2000_ENTROPY_STARTUP_OCTETS must be >= APT window"
#endif

#ifdef __cplusplus
    extern "C" {
#endif

/* These wrap a wc_NoiseSrc instance configured from the macros above; the
 * generic wc_NoiseSrc_* API in random.h is usable directly too. */

/* Enable the DCCs and run the startup health test.  Called automatically on
 * first use.  Claims the configured DCCs for the life of the source; costs
 * ~420 ms at the defaults. */
WOLFSSL_API int wc_c2000_Entropy_Init(void);

/* Release the DCCs and clear any latched failure. */
WOLFSSL_API void wc_c2000_Entropy_Free(void);

/* Unconditioned noise, for characterization and self-test only - runs no
 * health tests, so never use it for keying material.  srcIdx 0 or 1. */
WOLFSSL_API int wc_c2000_Entropy_GetRaw(byte* out, word32 len, int srcIdx);

/* Conditioned seed material, called by the wc_GenerateSeed() branch in
 * random.c.  After a health-test failure this returns the latched error on
 * every later call until wc_c2000_Entropy_Free(). */
WOLFSSL_API int wc_c2000_GenerateSeed(byte* output, word32 sz);

/* Liveness check on the raw noise: each source must produce differing
 * gathers and never a constant octet. */
WOLFSSL_API int wc_c2000_Entropy_SelfTest(void);

#ifdef __cplusplus
    }
#endif

#endif /* WOLFSSL_C2000_ENTROPY */

#endif /* WOLF_CRYPT_PORT_TI_C2000_ENTROPY_H */
