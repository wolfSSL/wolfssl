/* ti-c2000.h
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

/* TI C2000 (C28x) on-chip crypto support.
 *
 * The F28P55x/F28P65x carry an "AESA" accelerator (a TI EIP-120t instance)
 * offering ECB/CBC/CTR/CFB/GCM/CCM with 128/192/256-bit keys.  wolfCrypt
 * reaches it through the crypto-callback framework rather than by replacing
 * wolfcrypt/src/aes.c, so software AES stays available: a given Aes context
 * opts in by passing WOLFSSL_C2000_DEVID to wc_AesInit(), and a context
 * initialised with INVALID_DEVID runs pure software.  Anything the hardware
 * cannot do returns CRYPTOCB_UNAVAILABLE and falls through to software.
 *
 * This is a different device from the TivaWare/TM4C block behind
 * WOLFSSL_TI_CRYPT (wolfcrypt/src/port/ti/ti-aes.c); the two are not
 * interchangeable and must not both be enabled.
 */

#ifndef WOLF_CRYPT_PORT_TI_C2000_H
#define WOLF_CRYPT_PORT_TI_C2000_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_C2000_AES

#if defined(WOLFSSL_TI_CRYPT)
    #error "WOLFSSL_C2000_AES and WOLFSSL_TI_CRYPT are different devices"
#endif

/* The AESA block is a single shared resource with no per-context state (key,
 * IV and mode are reloaded on every operation), so the port is re-entrant
 * across Aes contexts but not across preemption or an ISR.  Define
 * WOLFSSL_C2000_AES_NO_LOCK to assert that an external lock provides that
 * guarantee. */
#if !defined(SINGLE_THREADED) && !defined(WOLFSSL_C2000_AES_NO_LOCK)
    #error "WOLFSSL_C2000_AES needs SINGLE_THREADED or WOLFSSL_C2000_AES_NO_LOCK"
#endif

/* devId handed to wc_AesInit() and wc_CryptoCb_RegisterDevice(). */
#ifndef WOLFSSL_C2000_DEVID
    #define WOLFSSL_C2000_DEVID 0x2000
#endif

/* AESA_BASE / AESA_SS_BASE from C2000Ware inc/hw_memmap.h.  Defaulted here so
 * the port does not depend on which device header happens to be on the
 * include path. */
#ifndef WOLFSSL_C2000_AES_BASE
    #define WOLFSSL_C2000_AES_BASE    0x00042000U
#endif
#ifndef WOLFSSL_C2000_AES_SS_BASE
    #define WOLFSSL_C2000_AES_SS_BASE 0x00042C00U
#endif

#ifdef __cplusplus
    extern "C" {
#endif

struct wc_CryptoInfo;

/* Enable and reset the AESA block, then register the callback for devId.
 * Must be called after wolfCrypt_Init(): wc_CryptoCb_RegisterDevice() looks
 * for a slot whose devId is INVALID_DEVID, and the device table is only
 * initialised to that value by wolfCrypt_Init(). */
WOLFSSL_API int wc_C2000_Init(int devId);

/* Unregister the callback. */
WOLFSSL_API int wc_C2000_Cleanup(int devId);

/* The callback itself, exposed so an application can register it by hand. */
WOLFSSL_API int wc_C2000_CryptoCb(int devId, struct wc_CryptoInfo* info,
    void* ctx);

#ifdef __cplusplus
    }
#endif

#endif /* WOLFSSL_C2000_AES */

#endif /* WOLF_CRYPT_PORT_TI_C2000_H */
