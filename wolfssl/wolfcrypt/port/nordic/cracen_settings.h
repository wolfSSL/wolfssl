/* cracen_settings.h
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

/* Macro-only derivations for the Nordic nRF54L CRACEN crypto callback port.
 * Included from wolfssl/wolfcrypt/settings.h when WOLFSSL_NRF54L_CRACEN is
 * defined, before the rest of settings.h and before the test and benchmark
 * read WC_USE_DEVID. Pulls in no vendor headers.
 *
 * Build options:
 *   WOLFSSL_NRF54L_CRACEN      umbrella, enables the port
 *   WOLFSSL_CRACEN_HOST_TEST   compile the port against a shim on a PC; every
 *                              operation declines so software runs
 *   WOLFSSL_CRACEN_TRNG        TRNG as seed source (default when !WC_NO_RNG)
 *   WOLFSSL_CRACEN_HASH        SHA-1/224/256/384/512 (default when enabled)
 *   WOLFSSL_CRACEN_CIPHER      AES ECB/CBC/CTR/GCM (default when !NO_AES)
 *   WOLFSSL_CRACEN_CMAC        AES-CMAC (default when WOLFSSL_CMAC)
 *   WOLFSSL_CRACEN_DEVID       device id (default 0x4352)
 *   WOLFSSL_CRACEN_NO_SEED     do not make the TRNG the wc_GenerateSeed source
 *   WOLFSSL_CRACEN_RNG_DIRECT  also serve WC_ALGO_TYPE_RNG from the TRNG
 *   WOLFSSL_CRACEN_TIMEOUT     poll iterations before an op is failed
 *   WOLFSSL_CRACEN_TRNG_CLKDIV ring oscillator sample clock divider
 */

#ifndef WOLFSSL_CRACEN_SETTINGS_H
#define WOLFSSL_CRACEN_SETTINGS_H

#ifdef WOLFSSL_NRF54L_CRACEN

#ifndef WOLF_CRYPTO_CB
    #define WOLF_CRYPTO_CB
#endif

/* The emulator is a host-test build whose shim computes results in software
 * behind the hardware interface, so the callback logic can be tested on a PC. */
#if defined(WOLFSSL_CRACEN_HOST_EMULATE) && !defined(WOLFSSL_CRACEN_HOST_TEST)
    #define WOLFSSL_CRACEN_HOST_TEST
#endif

#if !defined(WOLFSSL_CRACEN_TRNG)   && \
    !defined(WOLFSSL_CRACEN_HASH)   && \
    !defined(WOLFSSL_CRACEN_CIPHER) && \
    !defined(WOLFSSL_CRACEN_CMAC)
    /* Enable each engine only when its wc_CryptoInfo union member exists. */
    #ifndef WC_NO_RNG
        #define WOLFSSL_CRACEN_TRNG
    #endif
    #if !defined(NO_SHA) || !defined(NO_SHA256) || \
        defined(WOLFSSL_SHA384) || defined(WOLFSSL_SHA512)
        #define WOLFSSL_CRACEN_HASH
    #endif
    #ifndef NO_AES
        #define WOLFSSL_CRACEN_CIPHER
        #ifdef WOLFSSL_CMAC
            #define WOLFSSL_CRACEN_CMAC
        #endif
    #endif
#endif

#ifndef WOLFSSL_CRACEN_DEVID
    #define WOLFSSL_CRACEN_DEVID 0x4352 /* 'CR' */
#endif

#if !defined(WOLFSSL_CRACEN_HOST_TEST) || defined(WOLFSSL_CRACEN_HOST_EMULATE)
    #ifndef WC_USE_DEVID
        #define WC_USE_DEVID WOLFSSL_CRACEN_DEVID
    #endif
#endif

#ifndef WOLFSSL_CRACEN_HOST_TEST
    #if defined(WOLFSSL_CRACEN_TRNG) && !defined(WOLFSSL_CRACEN_NO_SEED) && \
        !defined(CUSTOM_RAND_GENERATE_SEED) && \
        !defined(CUSTOM_RAND_GENERATE_SEED_OS) && \
        !defined(CUSTOM_RAND_GENERATE_BLOCK) && \
        !defined(CUSTOM_RAND_GENERATE)
        #define CUSTOM_RAND_GENERATE_SEED wc_CracenGenerateSeed
        #ifdef __cplusplus
            extern "C" {
        #endif
        int wc_CracenGenerateSeed(unsigned char* output, unsigned int sz);
        #ifdef __cplusplus
            }
        #endif
    #endif
#endif /* !WOLFSSL_CRACEN_HOST_TEST */

#endif /* WOLFSSL_NRF54L_CRACEN */

#endif /* WOLFSSL_CRACEN_SETTINGS_H */
