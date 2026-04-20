/* wc_slhdsa.h
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

#ifndef WOLF_CRYPT_WC_SLHDSA_H
#define WOLF_CRYPT_WC_SLHDSA_H

#include <wolfssl/wolfcrypt/types.h>

#if FIPS_VERSION3_GE(7,0,0)
    #include <wolfssl/wolfcrypt/fips.h>
#endif

#ifdef WOLFSSL_HAVE_SLHDSA

#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha3.h>

#ifdef WOLFSSL_SLHDSA_SHA2
    #include <wolfssl/wolfcrypt/sha256.h>
    #include <wolfssl/wolfcrypt/sha512.h>
    #include <wolfssl/wolfcrypt/hmac.h>
#endif

/* ======== SHAKE parameter guards ======== */
#ifdef WOLFSSL_SLHDSA_NO_SHAKE

    #define WOLFSSL_SLHDSA_PARAM_NO_128S
    #define WOLFSSL_SLHDSA_PARAM_NO_128F
    #define WOLFSSL_SLHDSA_PARAM_NO_192S
    #define WOLFSSL_SLHDSA_PARAM_NO_192F
    #define WOLFSSL_SLHDSA_PARAM_NO_256S
    #define WOLFSSL_SLHDSA_PARAM_NO_256F

#else /* !WOLFSSL_SLHDSA_NO_SHAKE */

/* When a bits/opt is defined then ensure 'NO' defines are off. */
#ifdef WOLFSSL_SLHDSA_PARAM_128S
    #undef WOLFSSL_SLHDSA_PARAM_NO_128S
    #undef WOLFSSL_SLHDSA_PARAM_NO_128
    #undef WOLFSSL_SLHDSA_PARAM_NO_SMALL
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_128F
    #undef WOLFSSL_SLHDSA_PARAM_NO_128F
    #undef WOLFSSL_SLHDSA_PARAM_NO_128
    #undef WOLFSSL_SLHDSA_PARAM_NO_FAST
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_192S
    #undef WOLFSSL_SLHDSA_PARAM_NO_192S
    #undef WOLFSSL_SLHDSA_PARAM_NO_192
    #undef WOLFSSL_SLHDSA_PARAM_NO_SMALL
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_192F
    #undef WOLFSSL_SLHDSA_PARAM_NO_192F
    #undef WOLFSSL_SLHDSA_PARAM_NO_192
    #undef WOLFSSL_SLHDSA_PARAM_NO_FAST
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_256S
    #undef WOLFSSL_SLHDSA_PARAM_NO_256S
    #undef WOLFSSL_SLHDSA_PARAM_NO_256
    #undef WOLFSSL_SLHDSA_PARAM_NO_SMALL
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_256F
    #undef WOLFSSL_SLHDSA_PARAM_NO_256F
    #undef WOLFSSL_SLHDSA_PARAM_NO_256
    #undef WOLFSSL_SLHDSA_PARAM_NO_FAST
#endif

#endif /* !WOLFSSL_SLHDSA_NO_SHAKE */

/* When 'NO' defines are on then define no parameter set. */
#if defined(WOLFSSL_SLHDSA_PARAM_NO_128S) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_128F)
    #undef WOLFSSL_SLHDSA_NO_128
    #define WOLFSSL_SLHDSA_NO_128
#endif
#if defined(WOLFSSL_SLHDSA_PARAM_NO_192S) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_192F)
    #undef WOLFSSL_SLHDSA_NO_192
    #define WOLFSSL_SLHDSA_NO_192
#endif
#if defined(WOLFSSL_SLHDSA_PARAM_NO_256S) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_256F)
    #undef WOLFSSL_SLHDSA_NO_256
    #define WOLFSSL_SLHDSA_NO_256
#endif
#if defined(WOLFSSL_SLHDSA_PARAM_NO_128S) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_192S) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_256S)
    #undef WOLFSSL_SLHDSA_PARAM_NO_SMALL
    #define WOLFSSL_SLHDSA_PARAM_NO_SMALL
#endif
#if defined(WOLFSSL_SLHDSA_PARAM_NO_128F) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_192F) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_256F)
    #undef WOLFSSL_SLHDSA_PARAM_NO_FAST
    #define WOLFSSL_SLHDSA_PARAM_NO_FAST
#endif

/* Turn on parameter set based on 'NO' defines. */
#if !defined(WOLFSSL_SLHDSA_PARAM_NO_128S) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_128) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_SMALL)
    #undef WOLFSSL_SLHDSA_PARAM_128S
    #define WOLFSSL_SLHDSA_PARAM_128S
#endif
#if !defined(WOLFSSL_SLHDSA_PARAM_NO_128F) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_128) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_FAST)
    #undef WOLFSSL_SLHDSA_PARAM_128F
    #define WOLFSSL_SLHDSA_PARAM_128F
#endif
#if !defined(WOLFSSL_SLHDSA_PARAM_NO_192S) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_192) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_SMALL)
    #undef WOLFSSL_SLHDSA_PARAM_192S
    #define WOLFSSL_SLHDSA_PARAM_192S
#endif
#if !defined(WOLFSSL_SLHDSA_PARAM_NO_192F) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_192) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_FAST)
    #undef WOLFSSL_SLHDSA_PARAM_192F
    #define WOLFSSL_SLHDSA_PARAM_192F
#endif
#if !defined(WOLFSSL_SLHDSA_PARAM_NO_256S) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_256) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_SMALL)
    #undef WOLFSSL_SLHDSA_PARAM_256S
    #define WOLFSSL_SLHDSA_PARAM_256S
#endif
#if !defined(WOLFSSL_SLHDSA_PARAM_NO_256F) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_256) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_FAST)
    #undef WOLFSSL_SLHDSA_PARAM_256F
    #define WOLFSSL_SLHDSA_PARAM_256F
#endif

#if defined(WOLFSSL_SLHDSA_PARAM_NO_128S) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_192S) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_256S)
    #undef WOLFSSL_SLHDSA_PARAM_NO_SMALL
    #define WOLFSSL_SLHDSA_PARAM_NO_SMALL
#endif
#if defined(WOLFSSL_SLHDSA_PARAM_NO_128F) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_192F) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_256F)
    #undef WOLFSSL_SLHDSA_PARAM_NO_FAST
    #define WOLFSSL_SLHDSA_PARAM_NO_FAST
#endif
#if defined(WOLFSSL_SLHDSA_PARAM_NO_128S) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_128F)
    #undef WOLFSSL_SLHDSA_PARAM_NO_128
    #define WOLFSSL_SLHDSA_PARAM_NO_128
#endif
#if defined(WOLFSSL_SLHDSA_PARAM_NO_192S) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_192F)
    #undef WOLFSSL_SLHDSA_PARAM_NO_192
    #define WOLFSSL_SLHDSA_PARAM_NO_192
#endif
#if defined(WOLFSSL_SLHDSA_PARAM_NO_256S) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_256F)
    #undef WOLFSSL_SLHDSA_PARAM_NO_256
    #define WOLFSSL_SLHDSA_PARAM_NO_256
#endif

#if defined(WOLFSSL_SLHDSA_PARAM_NO_128) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_192) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_256)
    #define WOLFSSL_SLHDSA_NO_SHAKE
#endif

/* ======== SHA2 parameter guards ======== */
#ifdef WOLFSSL_SLHDSA_SHA2

/* When a SHA2 param is defined, ensure 'NO' defines are off. */
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128S
    #undef WOLFSSL_SLHDSA_PARAM_NO_SHA2_128S
    #undef WOLFSSL_SLHDSA_PARAM_NO_SHA2_128
    #undef WOLFSSL_SLHDSA_PARAM_NO_SHA2_SMALL
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128F
    #undef WOLFSSL_SLHDSA_PARAM_NO_SHA2_128F
    #undef WOLFSSL_SLHDSA_PARAM_NO_SHA2_128
    #undef WOLFSSL_SLHDSA_PARAM_NO_SHA2_FAST
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192S
    #undef WOLFSSL_SLHDSA_PARAM_NO_SHA2_192S
    #undef WOLFSSL_SLHDSA_PARAM_NO_SHA2_192
    #undef WOLFSSL_SLHDSA_PARAM_NO_SHA2_SMALL
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192F
    #undef WOLFSSL_SLHDSA_PARAM_NO_SHA2_192F
    #undef WOLFSSL_SLHDSA_PARAM_NO_SHA2_192
    #undef WOLFSSL_SLHDSA_PARAM_NO_SHA2_FAST
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256S
    #undef WOLFSSL_SLHDSA_PARAM_NO_SHA2_256S
    #undef WOLFSSL_SLHDSA_PARAM_NO_SHA2_256
    #undef WOLFSSL_SLHDSA_PARAM_NO_SHA2_SMALL
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256F
    #undef WOLFSSL_SLHDSA_PARAM_NO_SHA2_256F
    #undef WOLFSSL_SLHDSA_PARAM_NO_SHA2_256
    #undef WOLFSSL_SLHDSA_PARAM_NO_SHA2_FAST
#endif

/* Derive aggregate 'NO' defines for SHA2. */
#if defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_128S) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_128F)
    #undef WOLFSSL_SLHDSA_PARAM_NO_SHA2_128
    #define WOLFSSL_SLHDSA_PARAM_NO_SHA2_128
#endif
#if defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_192S) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_192F)
    #undef WOLFSSL_SLHDSA_PARAM_NO_SHA2_192
    #define WOLFSSL_SLHDSA_PARAM_NO_SHA2_192
#endif
#if defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_256S) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_256F)
    #undef WOLFSSL_SLHDSA_PARAM_NO_SHA2_256
    #define WOLFSSL_SLHDSA_PARAM_NO_SHA2_256
#endif
#if defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_128S) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_192S) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_256S)
    #undef WOLFSSL_SLHDSA_PARAM_NO_SHA2_SMALL
    #define WOLFSSL_SLHDSA_PARAM_NO_SHA2_SMALL
#endif
#if defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_128F) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_192F) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_256F)
    #undef WOLFSSL_SLHDSA_PARAM_NO_SHA2_FAST
    #define WOLFSSL_SLHDSA_PARAM_NO_SHA2_FAST
#endif

/* Turn on SHA2 parameter set based on 'NO' defines. */
#if !defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_128S) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_128) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_SMALL)
    #undef WOLFSSL_SLHDSA_PARAM_SHA2_128S
    #define WOLFSSL_SLHDSA_PARAM_SHA2_128S
#endif
#if !defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_128F) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_128) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_FAST)
    #undef WOLFSSL_SLHDSA_PARAM_SHA2_128F
    #define WOLFSSL_SLHDSA_PARAM_SHA2_128F
#endif
#if !defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_192S) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_192) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_SMALL)
    #undef WOLFSSL_SLHDSA_PARAM_SHA2_192S
    #define WOLFSSL_SLHDSA_PARAM_SHA2_192S
#endif
#if !defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_192F) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_192) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_FAST)
    #undef WOLFSSL_SLHDSA_PARAM_SHA2_192F
    #define WOLFSSL_SLHDSA_PARAM_SHA2_192F
#endif
#if !defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_256S) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_256) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_SMALL)
    #undef WOLFSSL_SLHDSA_PARAM_SHA2_256S
    #define WOLFSSL_SLHDSA_PARAM_SHA2_256S
#endif
#if !defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_256F) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_256) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_FAST)
    #undef WOLFSSL_SLHDSA_PARAM_SHA2_256F
    #define WOLFSSL_SLHDSA_PARAM_SHA2_256F
#endif

/* Re-derive aggregate NOs for SHA2. */
#if defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_128S) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_192S) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_256S)
    #undef WOLFSSL_SLHDSA_PARAM_NO_SHA2_SMALL
    #define WOLFSSL_SLHDSA_PARAM_NO_SHA2_SMALL
#endif
#if defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_128F) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_192F) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_256F)
    #undef WOLFSSL_SLHDSA_PARAM_NO_SHA2_FAST
    #define WOLFSSL_SLHDSA_PARAM_NO_SHA2_FAST
#endif
#if defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_128S) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_128F)
    #undef WOLFSSL_SLHDSA_PARAM_NO_SHA2_128
    #define WOLFSSL_SLHDSA_PARAM_NO_SHA2_128
#endif
#if defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_192S) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_192F)
    #undef WOLFSSL_SLHDSA_PARAM_NO_SHA2_192
    #define WOLFSSL_SLHDSA_PARAM_NO_SHA2_192
#endif
#if defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_256S) && \
    defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_256F)
    #undef WOLFSSL_SLHDSA_PARAM_NO_SHA2_256
    #define WOLFSSL_SLHDSA_PARAM_NO_SHA2_256
#endif

#else /* !WOLFSSL_SLHDSA_SHA2 */

    #define WOLFSSL_SLHDSA_NO_SHA2

#endif /* !WOLFSSL_SLHDSA_SHA2 */

/* ======== Security parameter (n) per FIPS 205 Table 2 ======== */

/* Security parameter n, in bytes. SLH-DSA seed length, public key half,
 * and other primitive sizes are derived from n. The SHA2 hash dispatch
 * also keys off n: n = 128 uses SHA-256, n = 192/256 use SHA-512. */
/* Category 1, 128-bit classical security. */
#define WC_SLHDSA_N_128                 16
/* Category 3, 192-bit classical security. */
#define WC_SLHDSA_N_192                 24
/* Category 5, 256-bit classical security. */
#define WC_SLHDSA_N_256                 32

/* ======== SHAKE size defines ======== */

/* Seed length for SLH-DSA SHAKE-128s/f. */
#define WC_SLHDSA_SHAKE128_SEED_LEN     WC_SLHDSA_N_128
/* Seed length for SLH-DSA SHAKE-192s/f. */
#define WC_SLHDSA_SHAKE192_SEED_LEN     WC_SLHDSA_N_192
/* Seed length for SLH-DSA SHAKE-256s/f. */
#define WC_SLHDSA_SHAKE256_SEED_LEN     WC_SLHDSA_N_256

/* Private key length for SLH-DSA SHAKE-128s. */
#define WC_SLHDSA_SHAKE128S_PRIV_LEN    (4 * 16)
/* Public key length for SLH-DSA SHAKE-128s. */
#define WC_SLHDSA_SHAKE128S_PUB_LEN     (2 * 16)
/* Signature length for SLH-DSA SHAKE-128s. */
#define WC_SLHDSA_SHAKE128S_SIG_LEN     7856
/* Seed length for SLH-DSA SHAKE-128s. */
#define WC_SLHDSA_SHAKE128S_SEED_LEN    WC_SLHDSA_SHAKE128_SEED_LEN

/* Private key length for SLH-DSA SHAKE-128f. */
#define WC_SLHDSA_SHAKE128F_PRIV_LEN    (4 * 16)
/* Public key length for SLH-DSA SHAKE-128f. */
#define WC_SLHDSA_SHAKE128F_PUB_LEN     (2 * 16)
/* Signature length for SLH-DSA SHAKE-128f. */
#define WC_SLHDSA_SHAKE128F_SIG_LEN     17088
/* Seed length for SLH-DSA SHAKE-128f. */
#define WC_SLHDSA_SHAKE128F_SEED_LEN    WC_SLHDSA_SHAKE128_SEED_LEN

/* Private key length for SLH-DSA SHAKE-192s. */
#define WC_SLHDSA_SHAKE192S_PRIV_LEN    (4 * 24)
/* Public key length for SLH-DSA SHAKE-192s. */
#define WC_SLHDSA_SHAKE192S_PUB_LEN     (2 * 24)
/* Signature length for SLH-DSA SHAKE-192s. */
#define WC_SLHDSA_SHAKE192S_SIG_LEN     16224
/* Seed length for SLH-DSA SHAKE-192s. */
#define WC_SLHDSA_SHAKE192S_SEED_LEN    WC_SLHDSA_SHAKE192_SEED_LEN

/* Private key length for SLH-DSA SHAKE-192f. */
#define WC_SLHDSA_SHAKE192F_PRIV_LEN    (4 * 24)
/* Public key length for SLH-DSA SHAKE-192f. */
#define WC_SLHDSA_SHAKE192F_PUB_LEN     (2 * 24)
/* Signature length for SLH-DSA SHAKE-192f. */
#define WC_SLHDSA_SHAKE192F_SIG_LEN     35664
/* Seed length for SLH-DSA SHAKE-192f. */
#define WC_SLHDSA_SHAKE192F_SEED_LEN    WC_SLHDSA_SHAKE192_SEED_LEN

/* Private key length for SLH-DSA SHAKE-256s. */
#define WC_SLHDSA_SHAKE256S_PRIV_LEN    (4 * 32)
/* Public key length for SLH-DSA SHAKE-256s. */
#define WC_SLHDSA_SHAKE256S_PUB_LEN     (2 * 32)
/* Signature length for SLH-DSA SHAKE-256s. */
#define WC_SLHDSA_SHAKE256S_SIG_LEN     29792
/* Seed length for SLH-DSA SHAKE-256s. */
#define WC_SLHDSA_SHAKE256S_SEED_LEN    WC_SLHDSA_SHAKE256_SEED_LEN

/* Private key length for SLH-DSA SHAKE-256f. */
#define WC_SLHDSA_SHAKE256F_PRIV_LEN    (4 * 32)
/* Public key length for SLH-DSA SHAKE-256f. */
#define WC_SLHDSA_SHAKE256F_PUB_LEN     (2 * 32)
/* Signature length for SLH-DSA SHAKE-256f. */
#define WC_SLHDSA_SHAKE256F_SIG_LEN     49856
/* Seed length for SLH-DSA SHAKE-256f. */
#define WC_SLHDSA_SHAKE256F_SEED_LEN    WC_SLHDSA_SHAKE256_SEED_LEN

/* ======== SHA2 size defines ======== */
#ifdef WOLFSSL_SLHDSA_SHA2

/* Seed length for SLH-DSA SHA2-128s/f. */
#define WC_SLHDSA_SHA2_128_SEED_LEN     WC_SLHDSA_N_128
/* Seed length for SLH-DSA SHA2-192s/f. */
#define WC_SLHDSA_SHA2_192_SEED_LEN     WC_SLHDSA_N_192
/* Seed length for SLH-DSA SHA2-256s/f. */
#define WC_SLHDSA_SHA2_256_SEED_LEN     WC_SLHDSA_N_256

/* Private key length for SLH-DSA SHA2-128s. */
#define WC_SLHDSA_SHA2_128S_PRIV_LEN    (4 * 16)
/* Public key length for SLH-DSA SHA2-128s. */
#define WC_SLHDSA_SHA2_128S_PUB_LEN     (2 * 16)
/* Signature length for SLH-DSA SHA2-128s. */
#define WC_SLHDSA_SHA2_128S_SIG_LEN     7856
/* Seed length for SLH-DSA SHA2-128s. */
#define WC_SLHDSA_SHA2_128S_SEED_LEN    WC_SLHDSA_SHA2_128_SEED_LEN

/* Private key length for SLH-DSA SHA2-128f. */
#define WC_SLHDSA_SHA2_128F_PRIV_LEN    (4 * 16)
/* Public key length for SLH-DSA SHA2-128f. */
#define WC_SLHDSA_SHA2_128F_PUB_LEN     (2 * 16)
/* Signature length for SLH-DSA SHA2-128f. */
#define WC_SLHDSA_SHA2_128F_SIG_LEN     17088
/* Seed length for SLH-DSA SHA2-128f. */
#define WC_SLHDSA_SHA2_128F_SEED_LEN    WC_SLHDSA_SHA2_128_SEED_LEN

/* Private key length for SLH-DSA SHA2-192s. */
#define WC_SLHDSA_SHA2_192S_PRIV_LEN    (4 * 24)
/* Public key length for SLH-DSA SHA2-192s. */
#define WC_SLHDSA_SHA2_192S_PUB_LEN     (2 * 24)
/* Signature length for SLH-DSA SHA2-192s. */
#define WC_SLHDSA_SHA2_192S_SIG_LEN     16224
/* Seed length for SLH-DSA SHA2-192s. */
#define WC_SLHDSA_SHA2_192S_SEED_LEN    WC_SLHDSA_SHA2_192_SEED_LEN

/* Private key length for SLH-DSA SHA2-192f. */
#define WC_SLHDSA_SHA2_192F_PRIV_LEN    (4 * 24)
/* Public key length for SLH-DSA SHA2-192f. */
#define WC_SLHDSA_SHA2_192F_PUB_LEN     (2 * 24)
/* Signature length for SLH-DSA SHA2-192f. */
#define WC_SLHDSA_SHA2_192F_SIG_LEN     35664
/* Seed length for SLH-DSA SHA2-192f. */
#define WC_SLHDSA_SHA2_192F_SEED_LEN    WC_SLHDSA_SHA2_192_SEED_LEN

/* Private key length for SLH-DSA SHA2-256s. */
#define WC_SLHDSA_SHA2_256S_PRIV_LEN    (4 * 32)
/* Public key length for SLH-DSA SHA2-256s. */
#define WC_SLHDSA_SHA2_256S_PUB_LEN     (2 * 32)
/* Signature length for SLH-DSA SHA2-256s. */
#define WC_SLHDSA_SHA2_256S_SIG_LEN     29792
/* Seed length for SLH-DSA SHA2-256s. */
#define WC_SLHDSA_SHA2_256S_SEED_LEN    WC_SLHDSA_SHA2_256_SEED_LEN

/* Private key length for SLH-DSA SHA2-256f. */
#define WC_SLHDSA_SHA2_256F_PRIV_LEN    (4 * 32)
/* Public key length for SLH-DSA SHA2-256f. */
#define WC_SLHDSA_SHA2_256F_PUB_LEN     (2 * 32)
/* Signature length for SLH-DSA SHA2-256f. */
#define WC_SLHDSA_SHA2_256F_SIG_LEN     49856
/* Seed length for SLH-DSA SHA2-256f. */
#define WC_SLHDSA_SHA2_256F_SEED_LEN    WC_SLHDSA_SHA2_256_SEED_LEN

#endif /* WOLFSSL_SLHDSA_SHA2 */

/* ======== Maximum size defines ======== */

/* Determine maximum private and public key lengths based on maximum 256-bit
 * output length. SHA2 variants have identical sizes to SHAKE counterparts. */
#ifndef WOLFSSL_SLHDSA_PARAM_NO_256
    /* Maximum private key length. */
    #define WC_SLHDSA_MAX_PRIV_LEN          WC_SLHDSA_SHAKE256F_PRIV_LEN
    /* Maximum public key length. */
    #define WC_SLHDSA_MAX_PUB_LEN           WC_SLHDSA_SHAKE256F_PUB_LEN
    /* Maximum seed length. */
    #define WC_SLHDSA_MAX_SEED              WC_SLHDSA_SHAKE256_SEED_LEN
#elif !defined(WOLFSSL_SLHDSA_PARAM_NO_192)
    /* Maximum private key length. */
    #define WC_SLHDSA_MAX_PRIV_LEN          WC_SLHDSA_SHAKE192F_PRIV_LEN
    /* Maximum public key length. */
    #define WC_SLHDSA_MAX_PUB_LEN           WC_SLHDSA_SHAKE192F_PUB_LEN
    /* Maximum seed length. */
    #define WC_SLHDSA_MAX_SEED              WC_SLHDSA_SHAKE192_SEED_LEN
#else
    /* Maximum private key length. */
    #define WC_SLHDSA_MAX_PRIV_LEN          WC_SLHDSA_SHAKE128F_PRIV_LEN
    /* Maximum public key length. */
    #define WC_SLHDSA_MAX_PUB_LEN           WC_SLHDSA_SHAKE128F_PUB_LEN
    /* Maximum seed length. */
    #define WC_SLHDSA_MAX_SEED              WC_SLHDSA_SHAKE128_SEED_LEN
#endif

/* Determine maximum signature length depending on the parameters compiled in.
 */
#if !defined(WOLFSSL_SLHDSA_PARAM_NO_256) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_FAST)
    /* Maximum signature length. */
    #define WC_SLHDSA_MAX_SIG_LEN           WC_SLHDSA_SHAKE256F_SIG_LEN
#elif !defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_256) && \
    !defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_FAST)
    /* Maximum signature length. */
    #define WC_SLHDSA_MAX_SIG_LEN           WC_SLHDSA_SHA2_256F_SIG_LEN
#elif !defined(WOLFSSL_SLHDSA_PARAM_NO_192) && \
      !defined(WOLFSSL_SLHDSA_PARAM_NO_FAST)
    /* Maximum signature length. */
    #define WC_SLHDSA_MAX_SIG_LEN           WC_SLHDSA_SHAKE192F_SIG_LEN
#elif !defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_192) && \
      !defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_FAST)
    /* Maximum signature length. */
    #define WC_SLHDSA_MAX_SIG_LEN           WC_SLHDSA_SHA2_192F_SIG_LEN
#elif !defined(WOLFSSL_SLHDSA_PARAM_NO_256) && \
      !defined(WOLFSSL_SLHDSA_PARAM_NO_SMALL)
    /* Maximum signature length. */
    #define WC_SLHDSA_MAX_SIG_LEN           WC_SLHDSA_SHAKE256S_SIG_LEN
#elif !defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_256) && \
      !defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_SMALL)
    /* Maximum signature length. */
    #define WC_SLHDSA_MAX_SIG_LEN           WC_SLHDSA_SHA2_256S_SIG_LEN
#elif !defined(WOLFSSL_SLHDSA_PARAM_NO_128) && \
      !defined(WOLFSSL_SLHDSA_PARAM_NO_FAST)
    /* Maximum signature length. */
    #define WC_SLHDSA_MAX_SIG_LEN           WC_SLHDSA_SHAKE128F_SIG_LEN
#elif !defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_128) && \
      !defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_FAST)
    /* Maximum signature length. */
    #define WC_SLHDSA_MAX_SIG_LEN           WC_SLHDSA_SHA2_128F_SIG_LEN
#elif !defined(WOLFSSL_SLHDSA_PARAM_NO_192) && \
      !defined(WOLFSSL_SLHDSA_PARAM_NO_SMALL)
    /* Maximum signature length. */
    #define WC_SLHDSA_MAX_SIG_LEN           WC_SLHDSA_SHAKE192S_SIG_LEN
#elif !defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_192) && \
      !defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_SMALL)
    /* Maximum signature length. */
    #define WC_SLHDSA_MAX_SIG_LEN           WC_SLHDSA_SHA2_192S_SIG_LEN
#elif !defined(WOLFSSL_SLHDSA_PARAM_NO_128) && \
      !defined(WOLFSSL_SLHDSA_PARAM_NO_SMALL)
    /* Maximum signature length. */
    #define WC_SLHDSA_MAX_SIG_LEN           WC_SLHDSA_SHAKE128S_SIG_LEN
#elif !defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_128) && \
      !defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_SMALL)
    /* Maximum signature length. */
    #define WC_SLHDSA_MAX_SIG_LEN           WC_SLHDSA_SHA2_128S_SIG_LEN
#else
    #error "No parameters defined"
#endif

/* Ids for supported SLH-DSA parameters. */
enum SlhDsaParam {
    SLHDSA_SHAKE128S = 0,   /* SLH-DSA SHAKE128s */
    SLHDSA_SHAKE128F = 1,   /* SLH-DSA SHAKE128f */
    SLHDSA_SHAKE192S = 2,   /* SLH-DSA SHAKE192s */
    SLHDSA_SHAKE192F = 3,   /* SLH-DSA SHAKE192f */
    SLHDSA_SHAKE256S = 4,   /* SLH-DSA SHAKE256s */
    SLHDSA_SHAKE256F = 5,   /* SLH-DSA SHAKE256f */
#ifdef WOLFSSL_SLHDSA_SHA2
    SLHDSA_SHA2_128S = 6,   /* SLH-DSA SHA2-128s */
    SLHDSA_SHA2_128F = 7,   /* SLH-DSA SHA2-128f */
    SLHDSA_SHA2_192S = 8,   /* SLH-DSA SHA2-192s */
    SLHDSA_SHA2_192F = 9,   /* SLH-DSA SHA2-192f */
    SLHDSA_SHA2_256S = 10,  /* SLH-DSA SHA2-256s */
    SLHDSA_SHA2_256F = 11,  /* SLH-DSA SHA2-256f */
#endif
};

/* Helper macro to detect SHA2 parameter sets. */
#ifdef WOLFSSL_SLHDSA_SHA2
    #define SLHDSA_IS_SHA2(p)   ((p) >= SLHDSA_SHA2_128S)
#else
    #define SLHDSA_IS_SHA2(p)   0
#endif

/* Pre-defined parameter values. */
typedef struct SlhDsaParameters {
    enum SlhDsaParam param;     /* Parameter set id. */
    byte n;                     /* Size of digest output. */
    byte h;                     /* Total tree height. */
    byte d;                     /* Depth of subtree. */
    byte h_m;                   /* Height of message tree - XMSS tree. */
    byte a;                     /* Number of authenthication nodes. */
    byte k;                     /* Number of FORS signatures. */
    byte len;                   /* Length of WOTS+ encoded message with csum. */
    byte dl1;                   /* Length first part of message digest. */
    byte dl2;                   /* Length second part of message digest. */
    byte dl3;                   /* Length third part of message digest. */
    word32 sigLen;              /* Signature length in bytes. */
} SlhDsaParameters;

#define WC_SLHDSA_FLAG_PRIVATE       0x0001
#define WC_SLHDSA_FLAG_PUBLIC        0x0002
#define WC_SLHDSA_FLAG_BOTH_KEYS     (WC_SLHDSA_FLAG_PRIVATE | \
                                      WC_SLHDSA_FLAG_PUBLIC)

/* SLH-DSA key data and state. */
typedef struct SlhDsaKey {
    /* Parameters. */
    const SlhDsaParameters* params;
    /* Flags of the key. */
    int flags;
    /* Dynamic memory hint. */
    void* heap;
#ifdef WOLF_CRYPTO_CB
    /* Device Identifier. */
    int devId;
#endif

    /* sk_seed | sk_prf | pk_seed, pk_root */
    byte sk[32 * 4];
    /* Hash objects for SHAKE or SHA2. */
    union {
        struct {
            /* Primary SHAKE-256 object. */
            wc_Shake shake;
            /* Secondary SHAKE-256 object (T_l streaming). */
            wc_Shake shake2;
        } shk;
#ifdef WOLFSSL_SLHDSA_SHA2
        struct {
            /* F, PRF (all cats) + H, T_l (cat 1). */
            wc_Sha256 sha256;
            /* T_l streaming (cat 1), H_msg scratch. */
            wc_Sha256 sha256_2;
            /* H, T_l (cats 3, 5). */
            wc_Sha512 sha512;
            /* H_msg streaming (cats 3, 5). */
            wc_Sha512 sha512_2;
            /* Pre-computed midstate: PK.seed || pad(64 - n). */
            wc_Sha256 sha256_mid;
            /* Pre-computed midstate: PK.seed || pad(128 - n). */
            wc_Sha512 sha512_mid;
        } sha2;
#endif
    } hash;
} SlhDsaKey;

WOLFSSL_API int  wc_SlhDsaKey_Init(SlhDsaKey* key, enum SlhDsaParam param,
    void* heap, int devId);
WOLFSSL_API void wc_SlhDsaKey_Free(SlhDsaKey* key);

WOLFSSL_API int  wc_SlhDsaKey_MakeKey(SlhDsaKey* key, WC_RNG* rng);
WOLFSSL_API int  wc_SlhDsaKey_MakeKeyWithRandom(SlhDsaKey* key,
    const byte* sk_seed, word32 sk_seed_len,
    const byte* sk_prf, word32 sk_prf_len,
    const byte* pk_seed, word32 pk_seed_len);

WOLFSSL_API int  wc_SlhDsaKey_SignDeterministic(SlhDsaKey* key, const byte* ctx,
    byte ctxSz, const byte* msg, word32 msgSz, byte* sig, word32* sigSz);
WOLFSSL_API int  wc_SlhDsaKey_SignWithRandom(SlhDsaKey* key, const byte* ctx,
    byte ctxSz, const byte* msg, word32 msgSz, byte* sig, word32* sigSz,
    const byte* addRnd);
WOLFSSL_API int  wc_SlhDsaKey_Sign(SlhDsaKey* key, const byte* ctx,
    byte ctxSz, const byte* msg, word32 msgSz, byte* sig, word32* sigSz,
    WC_RNG* rng);
WOLFSSL_API int  wc_SlhDsaKey_Verify(SlhDsaKey* key, const byte* ctx,
    byte ctxSz, const byte* msg, word32 msgSz, const byte* sig, word32 sigSz);

/* Internal interface: M' provided directly (no M' construction). */
WOLFSSL_API int  wc_SlhDsaKey_SignMsgDeterministic(SlhDsaKey* key,
    const byte* mprime, word32 mprimeSz, byte* sig, word32* sigSz);
WOLFSSL_API int  wc_SlhDsaKey_SignMsgWithRandom(SlhDsaKey* key,
    const byte* mprime, word32 mprimeSz, byte* sig, word32* sigSz,
    const byte* addRnd);
WOLFSSL_API int  wc_SlhDsaKey_VerifyMsg(SlhDsaKey* key, const byte* mprime,
    word32 mprimeSz, const byte* sig, word32 sigSz);

WOLFSSL_API int  wc_SlhDsaKey_SignHashDeterministic(SlhDsaKey* key,
    const byte* ctx, byte ctxSz, const byte* msg, word32 msgSz,
    enum wc_HashType hashType, byte* sig, word32* sigSz);
WOLFSSL_API int  wc_SlhDsaKey_SignHashWithRandom(SlhDsaKey* key,
    const byte* ctx, byte ctxSz, const byte* msg, word32 msgSz,
    enum wc_HashType hashType, byte* sig, word32* sigSz, byte* addRnd);
WOLFSSL_API int  wc_SlhDsaKey_SignHash(SlhDsaKey* key, const byte* ctx,
    byte ctxSz, const byte* msg, word32 msgSz, enum wc_HashType hashType,
    byte* sig, word32* sigSz, WC_RNG* rng);
WOLFSSL_API int  wc_SlhDsaKey_VerifyHash(SlhDsaKey* key, const byte* ctx,
    byte ctxSz, const byte* msg, word32 msgSz, enum wc_HashType hashType,
    const byte* sig, word32 sigSz);

WOLFSSL_API int  wc_SlhDsaKey_ImportPrivate(SlhDsaKey* key, const byte* in,
    word32 inLen);
WOLFSSL_API int  wc_SlhDsaKey_ImportPublic(SlhDsaKey* key, const byte* in,
    word32 inLen);
WOLFSSL_API int  wc_SlhDsaKey_CheckKey(SlhDsaKey* key);

WOLFSSL_API int  wc_SlhDsaKey_ExportPrivate(SlhDsaKey* key, byte* out,
    word32* outLen);
WOLFSSL_API int  wc_SlhDsaKey_ExportPublic(SlhDsaKey* key, byte* out,
    word32* outLen);

WOLFSSL_API int  wc_SlhDsaKey_PrivateSize(SlhDsaKey* key);
WOLFSSL_API int  wc_SlhDsaKey_PublicSize(SlhDsaKey* key);
WOLFSSL_API int  wc_SlhDsaKey_SigSize(SlhDsaKey* key);
WOLFSSL_API int  wc_SlhDsaKey_PrivateSizeFromParam(enum SlhDsaParam param);
WOLFSSL_API int  wc_SlhDsaKey_PublicSizeFromParam(enum SlhDsaParam param);
WOLFSSL_API int  wc_SlhDsaKey_SigSizeFromParam(enum SlhDsaParam param);

/* DER encode/decode */
#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
WOLFSSL_API int  wc_SlhDsaKey_PrivateKeyDecode(const byte* input,
    word32* inOutIdx, SlhDsaKey* key, word32 inSz);
#endif
WOLFSSL_API int  wc_SlhDsaKey_PublicKeyDecode(const byte* input,
    word32* inOutIdx, SlhDsaKey* key, word32 inSz);
#ifdef WC_ENABLE_ASYM_KEY_EXPORT
#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
WOLFSSL_API int  wc_SlhDsaKey_KeyToDer(SlhDsaKey* key, byte* output,
    word32 inLen);
/* SLH-DSA has no separate private-only encoding based on RFC 9909. This
 * function is an intentional alias of wc_SlhDsaKey_KeyToDer, kept for API
 * parity with other algorithms which do have a distinct private form. */
WOLFSSL_API int  wc_SlhDsaKey_PrivateKeyToDer(SlhDsaKey* key, byte* output,
    word32 inLen);
#endif
WOLFSSL_API int  wc_SlhDsaKey_PublicKeyToDer(SlhDsaKey* key, byte* output,
    word32 inLen, int withAlg);
#endif

#endif /* WOLFSSL_HAVE_SLHDSA */

#endif /* WOLF_CRYPT_WC_SLHDSA_H */
