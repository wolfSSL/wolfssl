/* asu_settings.h
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

/* Compile time configuration for the Versal Gen2 ASU port. This header holds
 * only preprocessor macros and pulls in no BSP headers, so wolfSSL settings.h
 * can include it to select engines and map WC_USE_DEVID before the unmodified
 * wolfcrypt test and benchmark read it.
 *
 * Engine selection:
 *   WOLFSSL_VERSAL_GEN2_ASU enables the port and must always be defined in
 *   user_settings.h. With only that defined, every supported engine is
 *   offloaded. To offload a subset, also define one or more of the engine
 *   macros below, in which case only those are offloaded:
 *       WOLFSSL_VERSAL_GEN2_ASU_TRNG
 *       WOLFSSL_VERSAL_GEN2_ASU_HASH
 *       WOLFSSL_VERSAL_GEN2_ASU_HMAC
 *       WOLFSSL_VERSAL_GEN2_ASU_AES
 *       WOLFSSL_VERSAL_GEN2_ASU_CMAC
 *       WOLFSSL_VERSAL_GEN2_ASU_RSA
 *       WOLFSSL_VERSAL_GEN2_ASU_ECC
 *   An engine macro on its own does not enable the port.
 */

#ifndef WOLFSSL_VERSAL_GEN2_ASU_SETTINGS_H
#define WOLFSSL_VERSAL_GEN2_ASU_SETTINGS_H

#ifdef WOLFSSL_VERSAL_GEN2_ASU

/* The port routes operations through the wolfSSL crypto callback framework. */
#ifndef WOLF_CRYPTO_CB
    #define WOLF_CRYPTO_CB
#endif

/* If the port is on but no specific engine was requested, enable the full
 * supported set. */
#if !defined(WOLFSSL_VERSAL_GEN2_ASU_TRNG) && \
    !defined(WOLFSSL_VERSAL_GEN2_ASU_HASH)  && \
    !defined(WOLFSSL_VERSAL_GEN2_ASU_HMAC) && \
    !defined(WOLFSSL_VERSAL_GEN2_ASU_AES)  && \
    !defined(WOLFSSL_VERSAL_GEN2_ASU_CMAC) && \
    !defined(WOLFSSL_VERSAL_GEN2_ASU_RSA)  && \
    !defined(WOLFSSL_VERSAL_GEN2_ASU_ECC)
    #define WOLFSSL_VERSAL_GEN2_ASU_TRNG
    #define WOLFSSL_VERSAL_GEN2_ASU_HASH
    #define WOLFSSL_VERSAL_GEN2_ASU_HMAC
    #define WOLFSSL_VERSAL_GEN2_ASU_AES
    #define WOLFSSL_VERSAL_GEN2_ASU_CMAC
    #define WOLFSSL_VERSAL_GEN2_ASU_RSA
    #define WOLFSSL_VERSAL_GEN2_ASU_ECC
#endif

/* Device id used to register and route to the ASU crypto callback. Override by
 * defining WOLFSSL_VERSAL_GEN2_ASU_DEVID (or WC_USE_DEVID) in user_settings.h
 * before settings.h. Any int other than INVALID_DEVID (-2) is valid; this is an
 * identifier, not an address or index. */
#ifndef WOLFSSL_VERSAL_GEN2_ASU_DEVID
    #define WOLFSSL_VERSAL_GEN2_ASU_DEVID 0x4153 /* 'AS' for ASU */
#endif

/* Let the unmodified wolfcrypt test and benchmark route every operation through
 * this device by giving their devId the ASU value. */
#ifndef WC_USE_DEVID
    #define WC_USE_DEVID WOLFSSL_VERSAL_GEN2_ASU_DEVID
#endif

/* When the timer and RTC are turned on (WOLFSSL_VERSAL_GEN2_ASU_RTC in
 * user_settings.h), supply the benchmark current_time() hook from the port. */
#ifdef WOLFSSL_VERSAL_GEN2_ASU_RTC
    #ifndef WOLFSSL_USER_CURRTIME
        #define WOLFSSL_USER_CURRTIME
    #endif
#endif

/* Mirror the application data cache switch into a port owned macro so the port
 * translation units do not depend on the application macro name. When
 * XASU_DISABLE_CACHE is set globally the data cache is off, so the port skips
 * buffer maintenance; otherwise it cleans inputs and invalidates outputs. */
#ifdef XASU_DISABLE_CACHE
    #ifndef WC_ASU_DISABLE_CACHE
        #define WC_ASU_DISABLE_CACHE
    #endif
#endif

/* Threading. The ticketing concurrency that lets several threads keep the ASU
 * queue busy is compiled out for a single threaded build, which instead uses
 * the wolfSSL crypto hardware mutex. Derived from SINGLE_THREADED. */
#ifdef SINGLE_THREADED
    #undef  WOLFSSL_VERSAL_GEN2_ASU_SINGLE_THREADED
    #define WOLFSSL_VERSAL_GEN2_ASU_SINGLE_THREADED
#endif

#endif /* WOLFSSL_VERSAL_GEN2_ASU */

#endif /* WOLFSSL_VERSAL_GEN2_ASU_SETTINGS_H */
