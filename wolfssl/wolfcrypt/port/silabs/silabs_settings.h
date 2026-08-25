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

/* Compile time configuration for the Silicon Labs crypto callback port. This
 * header holds only preprocessor macros and pulls in no SDK headers, so
 * wolfSSL settings.h can include it to select engines and map WC_USE_DEVID
 * before the unmodified wolfcrypt test and benchmark read it.
 *
 * Engine selection:
 *   WOLFSSL_SILABS_CRYPTOCB enables the port and must always be defined in
 *   user_settings.h. With only that defined, every supported engine is
 *   offloaded. To offload a subset, also define one or more of the engine
 *   macros below, in which case only those are offloaded:
 *       WOLFSSL_SILABS_CRYPTOCB_TRNG
 *       WOLFSSL_SILABS_CRYPTOCB_HASH
 *       WOLFSSL_SILABS_CRYPTOCB_CIPHER
 *       WOLFSSL_SILABS_CRYPTOCB_CMAC
 *       WOLFSSL_SILABS_CRYPTOCB_ECC
 *       WOLFSSL_SILABS_CRYPTOCB_KDF
 *   An engine macro on its own does not enable the port.
 *
 * There is no RSA engine: the Series 2 High Security Engine has no RSA
 * hardware, so RSA always runs in software.
 *
 * There is no HMAC engine either, and none is needed: wolfCrypt's HMAC gives
 * its inner and outer hash contexts the Hmac's own devId, so every hash block
 * of an HMAC is already offloaded through the hash engine above. The SE's own
 * HMAC streaming state has no room to buffer a partial block, so a dedicated
 * engine would have to re-block the message for no gain.
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

/* Let the unmodified wolfcrypt test and benchmark route every operation
 * through this device by giving their devId the SE value.
 *
 * Not under the host compile-test: there the SE Manager is a stub that does no
 * crypto, so pointing the test at it would fail every known-answer vector.
 * WOLFSSL_SILABS_HOST_TEST is a build gate - it proves the port and its wiring
 * compile under the full warning set - while correctness is established on
 * EFR32 silicon, where the test does route through this device. */
#ifndef WOLFSSL_SILABS_HOST_TEST
    #ifndef WC_USE_DEVID
        #define WC_USE_DEVID WOLFSSL_SILABS_DEVID
    #endif
#endif

#endif /* WOLFSSL_SILABS_CRYPTOCB */

#endif /* WOLFSSL_SILABS_SETTINGS_H */
