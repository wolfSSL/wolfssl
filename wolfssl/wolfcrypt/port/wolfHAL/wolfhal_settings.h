/* wolfhal_settings.h
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

/* Compile time configuration for the wolfHAL port. This header holds only
 * preprocessor macros and pulls in no wolfHAL or BSP headers, so wolfSSL
 * settings.h can include it to map WC_USE_DEVID before the unmodified
 * wolfcrypt test and benchmark read it.
 *
 * WOLFSSL_WOLFHAL enables the port and must be defined in user_settings.h.
 * Which AES modes are offloaded follows the usual wolfCrypt feature gates
 * (HAVE_AES_CBC, HAVE_AESGCM, HAVE_AESCCM, HAVE_AES_ECB); the callback
 * returns CRYPTOCB_UNAVAILABLE for anything else and wolfCrypt falls back to
 * software.
 *
 * WOLFSSL_WOLFHAL_RNG additionally builds wc_wolfHAL_GenerateSeed() and wires
 * it in below as the DRBG's entropy source, so no user_settings.h step is
 * needed beyond enabling it.
 */

#ifndef WOLF_CRYPT_PORT_WOLFHAL_SETTINGS_H
#define WOLF_CRYPT_PORT_WOLFHAL_SETTINGS_H

#ifdef WOLFSSL_WOLFHAL

/* The port routes operations through the wolfSSL crypto callback framework. */
#ifndef WOLF_CRYPTO_CB
    #define WOLF_CRYPTO_CB
#endif

/* Device id used to register and route to the wolfHAL crypto callback.
 * Override by defining WOLFSSL_WOLFHAL_DEVID (or WC_USE_DEVID) in
 * user_settings.h before settings.h. Any int other than INVALID_DEVID (-2) is
 * valid; this is an identifier, not an address or index.
 *
 * wolfCrypt_Init() registers at WOLFSSL_WOLFHAL_DEVID and unqualified callers
 * route to WC_USE_DEVID, so setting either one alone makes the other follow it.
 * Setting both to different values is the deliberate multi-device case. */
#ifndef WOLFSSL_WOLFHAL_DEVID
    #ifdef WC_USE_DEVID
        #define WOLFSSL_WOLFHAL_DEVID WC_USE_DEVID
    #else
        #define WOLFSSL_WOLFHAL_DEVID 0x5748 /* 'WH' for wolfHAL */
    #endif
#endif

#ifndef WC_USE_DEVID
    #define WC_USE_DEVID WOLFSSL_WOLFHAL_DEVID
#endif

#ifdef WOLFSSL_WOLFHAL_RNG

#ifdef __cplusplus
    extern "C" {
#endif

int wc_wolfHAL_GenerateSeed(unsigned char* output, unsigned int sz);

#ifdef __cplusplus
    }
#endif

#ifndef CUSTOM_RAND_GENERATE_SEED
    #define CUSTOM_RAND_GENERATE_SEED wc_wolfHAL_GenerateSeed
#endif

#endif /* WOLFSSL_WOLFHAL_RNG */

#endif /* WOLFSSL_WOLFHAL */
#endif /* WOLF_CRYPT_PORT_WOLFHAL_SETTINGS_H */
