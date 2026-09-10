/* silabs_settings.h
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

/* Compile time configuration for the Silicon Labs crypto callback port. Macros
 * only, no SDK headers, so settings.h can include it to select engines and map
 * WC_USE_DEVID before the wolfcrypt test and benchmark read it.
 *
 * WOLFSSL_SILABS_CRYPTOCB enables the port and must always be defined. On its
 * own it offloads every supported engine. To offload a subset, also define one
 * or more of these, in which case only those are offloaded:
 *       WOLFSSL_SILABS_CRYPTOCB_TRNG
 *       WOLFSSL_SILABS_CRYPTOCB_HASH
 *       WOLFSSL_SILABS_CRYPTOCB_CIPHER
 *       WOLFSSL_SILABS_CRYPTOCB_CMAC
 *       WOLFSSL_SILABS_CRYPTOCB_ECC
 *       WOLFSSL_SILABS_CRYPTOCB_KDF
 * An engine macro on its own does not enable the port.
 *
 * There is no RSA engine - Series 2 has no RSA hardware. There is no HMAC
 * engine either: wolfCrypt gives the inner and outer hash contexts the Hmac's
 * devId, so every block is already offloaded through the hash engine, and the
 * SE's own HMAC state cannot buffer a partial block.
 */

#ifndef WOLFSSL_SILABS_SETTINGS_H
#define WOLFSSL_SILABS_SETTINGS_H

#ifdef WOLFSSL_SILABS_CRYPTOCB

/* The two SiLabs ports are mutually exclusive. The direct port replaces the
 * software implementations at compile time, which would leave the callback
 * port with nothing to fall back to when the SE declines an operation. */
#ifdef WOLFSSL_SILABS_SE_ACCEL
    #error "SILABS_CRYPTOCB and SILABS_SE_ACCEL are mutually exclusive"
#endif

/* The port routes operations through the wolfSSL crypto callback framework. */
#ifndef WOLF_CRYPTO_CB
    #define WOLF_CRYPTO_CB
#endif

/* CMAC hangs its SE multipart state off the object devCtx, so the port needs
 * the free callback to release it. */
#ifndef WOLF_CRYPTO_CB_FREE
    #define WOLF_CRYPTO_CB_FREE
#endif

/* Pulls the SE context members into Aes, ecc_key and wc_Sha*, shared with the
 * direct port. Defined in settings.h for WOLFSSL_SILABS_SE_ACCEL as well. */
#ifndef WOLFSSL_SILABS_SE_TYPES
    #define WOLFSSL_SILABS_SE_TYPES
#endif

/* If the port is on but no specific engine was requested, enable the full
 * supported set. */
#if !defined(WOLFSSL_SILABS_CRYPTOCB_TRNG)   && \
    !defined(WOLFSSL_SILABS_CRYPTOCB_HASH)   && \
    !defined(WOLFSSL_SILABS_CRYPTOCB_CIPHER) && \
    !defined(WOLFSSL_SILABS_CRYPTOCB_CMAC)   && \
    !defined(WOLFSSL_SILABS_CRYPTOCB_ECC)    && \
    !defined(WOLFSSL_SILABS_CRYPTOCB_KDF)
    #define WOLFSSL_SILABS_CRYPTOCB_TRNG
    #define WOLFSSL_SILABS_CRYPTOCB_HASH
    #define WOLFSSL_SILABS_CRYPTOCB_CIPHER
    #define WOLFSSL_SILABS_CRYPTOCB_CMAC
    #ifdef HAVE_ECC
        #define WOLFSSL_SILABS_CRYPTOCB_ECC
    #endif
    #define WOLFSSL_SILABS_CRYPTOCB_KDF
#endif


/* Device id for the SE crypto callback; set WOLFSSL_SILABS_DEVID (or
 * WC_USE_DEVID) to any int but INVALID_DEVID (-2), an id not an address. */
#ifndef WOLFSSL_SILABS_DEVID
    #define WOLFSSL_SILABS_DEVID 0x5345 /* 'SE' */
#endif

/* Route the unmodified wolfcrypt test and benchmark through this device.
 *
 * Not under the host compile-test, where the SE Manager stub does no crypto
 * and every known-answer vector would fail. That build is a compile gate;
 * correctness is established on EFR32 silicon. */
#ifndef WOLFSSL_SILABS_HOST_TEST
    #ifndef WC_USE_DEVID
        #define WC_USE_DEVID WOLFSSL_SILABS_DEVID
    #endif
#endif

#endif /* WOLFSSL_SILABS_CRYPTOCB */

#endif /* WOLFSSL_SILABS_SETTINGS_H */
