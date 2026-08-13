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
 *       WOLFSSL_VERSAL_GEN2_ASU_CIPHER
 *       WOLFSSL_VERSAL_GEN2_ASU_CMAC
 *       WOLFSSL_VERSAL_GEN2_ASU_RSA (not auto-enabled under NO_RSA; enabling it
 *           implicitly defines WOLF_CRYPTO_CB_RSA_PAD so the ASU performs the
 *           full padded PSS/OAEP operation, not just the modexp)
 *       WOLFSSL_VERSAL_GEN2_ASU_ECC
 *   An engine macro on its own does not enable the port.
 *
 * Opt-out (keep the RSA engine, drop the padding path back to software):
 *       WOLFSSL_VERSAL_GEN2_ASU_NO_RSA_PAD - RSA on, all padding in software
 *           (the raw modexp still offloads)
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
    !defined(WOLFSSL_VERSAL_GEN2_ASU_CIPHER)  && \
    !defined(WOLFSSL_VERSAL_GEN2_ASU_CMAC) && \
    !defined(WOLFSSL_VERSAL_GEN2_ASU_RSA)  && \
    !defined(WOLFSSL_VERSAL_GEN2_ASU_ECC)
    #define WOLFSSL_VERSAL_GEN2_ASU_TRNG
    #define WOLFSSL_VERSAL_GEN2_ASU_HASH
    #define WOLFSSL_VERSAL_GEN2_ASU_HMAC
    #define WOLFSSL_VERSAL_GEN2_ASU_CIPHER
    #define WOLFSSL_VERSAL_GEN2_ASU_CMAC
    /* Do not auto-enable RSA under NO_RSA. asu_rsa.c also compiles to nothing
     * on a late NO_RSA, so this is a clean default, not the sole guard. */
    #ifndef NO_RSA
        #define WOLFSSL_VERSAL_GEN2_ASU_RSA
    #endif
    #define WOLFSSL_VERSAL_GEN2_ASU_ECC
#endif

/* WOLF_CRYPTO_CB_RSA_PAD on with RSA. WOLFSSL_VERSAL_GEN2_ASU_NO_RSA_PAD opts
 * out; it changes wc_CryptoInfo layout, set identically in lib and app. */
#if defined(WOLFSSL_VERSAL_GEN2_ASU_RSA) && \
    !defined(WOLF_CRYPTO_CB_RSA_PAD) && \
    !defined(WOLFSSL_VERSAL_GEN2_ASU_NO_RSA_PAD)
    #define WOLF_CRYPTO_CB_RSA_PAD
#endif

/* Device id for the ASU crypto callback; set WOLFSSL_VERSAL_GEN2_ASU_DEVID (or
 * WC_USE_DEVID) to any int but INVALID_DEVID (-2), an id not an address. */
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

/* Mirror XASU_DISABLE_CACHE into the port macro WC_ASU_DISABLE_CACHE. When set,
 * the cache is off, port skips buffer maintenance, else cleans/invalidates. */
#ifdef XASU_DISABLE_CACHE
    #ifndef WC_ASU_DISABLE_CACHE
        #define WC_ASU_DISABLE_CACHE
    #endif
#endif

/* ALIGN64 is a no-op without WOLFSSL_USE_ALIGN, so define it here, but only
 * when the data cache is on (WC_ASU_DISABLE_CACHE off). */
#ifndef WC_ASU_DISABLE_CACHE
    #ifndef WOLFSSL_USE_ALIGN
        #define WOLFSSL_USE_ALIGN
    #endif
#endif

/* Threading. Ticketing concurrency that keeps the ASU queue busy is compiled
 * out for a SINGLE_THREADED build, which uses the wolfSSL crypto HW mutex. */
#ifdef SINGLE_THREADED
    #undef  WOLFSSL_VERSAL_GEN2_ASU_SINGLE_THREADED
    #define WOLFSSL_VERSAL_GEN2_ASU_SINGLE_THREADED
#endif

#endif /* WOLFSSL_VERSAL_GEN2_ASU */

#endif /* WOLFSSL_VERSAL_GEN2_ASU_SETTINGS_H */
