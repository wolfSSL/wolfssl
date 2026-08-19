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

/* Build settings for the ASU port. Macros only, no BSP headers, so settings.h
 * can include it early.
 *
 * WOLFSSL_VERSAL_GEN2_ASU turns the port on and is always needed. On its own
 * it offloads every engine we support. Name one or more of these instead and
 * only those are offloaded:
 *       WOLFSSL_VERSAL_GEN2_ASU_TRNG
 *       WOLFSSL_VERSAL_GEN2_ASU_HASH
 *       WOLFSSL_VERSAL_GEN2_ASU_HMAC
 *       WOLFSSL_VERSAL_GEN2_ASU_CIPHER
 *       WOLFSSL_VERSAL_GEN2_ASU_CMAC
 *       WOLFSSL_VERSAL_GEN2_ASU_RSA
 *       WOLFSSL_VERSAL_GEN2_ASU_ECC (also covers ECDH and ECIES)
 *
 * Other switches:
 *       WOLFSSL_VERSAL_GEN2_ASU_NO_RSA_PAD - RSA on, padding in software
 *       WOLFSSL_VERSAL_GEN2_ASU_IPI_BASEADDR - IPI channel to use
 *       WOLFSSL_VERSAL_GEN2_ASU_NO_CLIENT_INIT - app starts the client itself
 */

#ifndef WOLFSSL_VERSAL_GEN2_ASU_SETTINGS_H
#define WOLFSSL_VERSAL_GEN2_ASU_SETTINGS_H

#ifdef WOLFSSL_VERSAL_GEN2_ASU

/* The port works through the wolfSSL crypto callback. */
#ifndef WOLF_CRYPTO_CB
    #define WOLF_CRYPTO_CB
#endif

/* Register command, where the port brings the ASU client up. */
#ifndef WOLF_CRYPTO_CB_CMD
    #define WOLF_CRYPTO_CB_CMD
#endif

/* No engine was named, so turn them all on. */
#if !defined(WOLFSSL_VERSAL_GEN2_ASU_TRNG) && \
    !defined(WOLFSSL_VERSAL_GEN2_ASU_HASH)  && \
    !defined(WOLFSSL_VERSAL_GEN2_ASU_HMAC) && \
    !defined(WOLFSSL_VERSAL_GEN2_ASU_CIPHER)  && \
    !defined(WOLFSSL_VERSAL_GEN2_ASU_CMAC) && \
    !defined(WOLFSSL_VERSAL_GEN2_ASU_RSA)  && \
    !defined(WOLFSSL_VERSAL_GEN2_ASU_ECC) && \
    !defined(WOLFSSL_VERSAL_GEN2_ASU_ECDH) && \
    !defined(WOLFSSL_VERSAL_GEN2_ASU_ECIES)
    #define WOLFSSL_VERSAL_GEN2_ASU_TRNG
    #define WOLFSSL_VERSAL_GEN2_ASU_HASH
    #define WOLFSSL_VERSAL_GEN2_ASU_HMAC
    #define WOLFSSL_VERSAL_GEN2_ASU_CIPHER
    #define WOLFSSL_VERSAL_GEN2_ASU_CMAC
    /* Leave RSA off in a build without RSA. */
    #ifndef NO_RSA
        #define WOLFSSL_VERSAL_GEN2_ASU_RSA
    #endif
    /* HAVE_ECC is decided later, so set this now and let asu_ecc.c check. */
    #define WOLFSSL_VERSAL_GEN2_ASU_ECC
#endif

/* Turn on RSA padding in hardware. This changes a struct layout, so the
 * library and the app must agree. */
#if defined(WOLFSSL_VERSAL_GEN2_ASU_RSA) && \
    !defined(WOLF_CRYPTO_CB_RSA_PAD) && \
    !defined(WOLFSSL_VERSAL_GEN2_ASU_NO_RSA_PAD)
    #define WOLF_CRYPTO_CB_RSA_PAD
#endif

/* ECDH and ECIES come along with ECC when their features are built. */
#ifdef WOLFSSL_VERSAL_GEN2_ASU_ECC
    /* Those feature macros are decided later, so check user macros here. */
    #if !defined(NO_ECC_DHE) && !defined(WC_NO_RNG) && \
        !defined(WOLFSSL_VERSAL_GEN2_ASU_ECDH) && \
        !defined(WOLFSSL_VERSAL_GEN2_ASU_NO_ECDH)
        #define WOLFSSL_VERSAL_GEN2_ASU_ECDH
    #endif
    /* The ASU cannot match those two older ECIES layouts. */
    #if defined(HAVE_ECC_ENCRYPT) && defined(WOLFSSL_ECIES_GEN_IV) && \
        !defined(NO_AES) && \
        !defined(WOLFSSL_ECIES_OLD) && !defined(WOLFSSL_ECIES_ISO18033) && \
        !defined(WOLFSSL_VERSAL_GEN2_ASU_ECIES) && \
        !defined(WOLFSSL_VERSAL_GEN2_ASU_NO_ECIES)
        #define WOLFSSL_VERSAL_GEN2_ASU_ECIES
    #endif
#endif

/* Turn off engines whose algorithm is not in the build. */
#if defined(WOLFSSL_VERSAL_GEN2_ASU_CMAC) && !defined(WOLFSSL_CMAC)
    #undef WOLFSSL_VERSAL_GEN2_ASU_CMAC
#endif
#if defined(WOLFSSL_VERSAL_GEN2_ASU_HMAC) && defined(NO_HMAC)
    #undef WOLFSSL_VERSAL_GEN2_ASU_HMAC
#endif
#if defined(WOLFSSL_VERSAL_GEN2_ASU_CIPHER) && defined(NO_AES)
    #undef WOLFSSL_VERSAL_GEN2_ASU_CIPHER
#endif

/* Requirements the enabled engines place on the wolfCrypt configuration. */

/* The port always handles context copy and free, so ask for both. */
#ifndef WOLF_CRYPTO_CB_COPY
    #define WOLF_CRYPTO_CB_COPY
#endif
#ifndef WOLF_CRYPTO_CB_FREE
    #define WOLF_CRYPTO_CB_FREE
#endif

/* The hash and HMAC engines accumulate the message with _wc_Hash_Grow. */
#if defined(WOLFSSL_VERSAL_GEN2_ASU_HASH) || \
    defined(WOLFSSL_VERSAL_GEN2_ASU_HMAC)
    #ifndef WOLFSSL_HASH_KEEP
        #define WOLFSSL_HASH_KEEP
    #endif
#endif

/* The hash engine uses the hashType field to tell the SHA-512 sizes apart. */
#ifdef WOLFSSL_VERSAL_GEN2_ASU_HASH
    #ifndef WOLFSSL_SHA512_HASHTYPE
        #define WOLFSSL_SHA512_HASHTYPE
    #endif
#endif

/* Device id for the callback. Any number except -2 works. It is an id, not
 * an address. */
#ifndef WOLFSSL_VERSAL_GEN2_ASU_DEVID
    #define WOLFSSL_VERSAL_GEN2_ASU_DEVID 0x4153 /* 'AS' for ASU */
#endif

/* Give the test and benchmark the same id so their work goes to the ASU. */
#ifndef WC_USE_DEVID
    #define WC_USE_DEVID WOLFSSL_VERSAL_GEN2_ASU_DEVID
#endif

/* With the timer on, the port supplies the benchmark time source. */
#ifdef WOLFSSL_VERSAL_GEN2_ASU_RTC
    #ifndef WOLFSSL_USER_CURRTIME
        #define WOLFSSL_USER_CURRTIME
    #endif
#endif

/* Copy the BSP cache switch into our own macro. With the cache off the port
 * skips all the flush and reload work. */
#ifdef XASU_DISABLE_CACHE
    #ifndef WC_ASU_DISABLE_CACHE
        #define WC_ASU_DISABLE_CACHE
    #endif
#endif

/* Align buffers to 64 bytes when the cache is on. With it off this does
 * nothing. */
#ifdef WC_ASU_DISABLE_CACHE
    #define WC_ASU_ALIGN64
#else
    #define WC_ASU_ALIGN64 XALIGNED(64)
#endif

/* A single threaded build uses the wolfSSL hardware mutex instead. */
#ifdef SINGLE_THREADED
    #undef  WOLFSSL_VERSAL_GEN2_ASU_SINGLE_THREADED
    #define WOLFSSL_VERSAL_GEN2_ASU_SINGLE_THREADED
#endif

#endif /* WOLFSSL_VERSAL_GEN2_ASU */

#endif /* WOLFSSL_VERSAL_GEN2_ASU_SETTINGS_H */
