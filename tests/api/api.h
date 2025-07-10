/* api.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#ifndef WOLFCRYPT_TEST_API_H
#define WOLFCRYPT_TEST_API_H


/* force enable test buffers */
#ifndef USE_CERT_BUFFERS_2048
    #define USE_CERT_BUFFERS_2048
#endif
#ifndef USE_CERT_BUFFERS_256
    #define USE_CERT_BUFFERS_256
#endif
#include <wolfssl/certs_test.h>


#ifndef HEAP_HINT
    #define HEAP_HINT NULL
#endif


#define TEST_STRING    "Everyone gets Friday off."
#define TEST_STRING_SZ 25


#ifndef ONEK_BUF
    #define ONEK_BUF 1024
#endif
#ifndef TWOK_BUF
    #define TWOK_BUF 2048
#endif
#ifndef FOURK_BUF
    #define FOURK_BUF 4096
#endif


#ifndef NO_RSA
#define GEN_BUF  294

#if (!defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL)) && \
    (!defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION < 4)) && \
    (defined(RSA_MIN_SIZE) && (RSA_MIN_SIZE <= 1024))
#define TEST_RSA_BITS 1024
#else
#define TEST_RSA_BITS 2048
#endif
#define TEST_RSA_BYTES (TEST_RSA_BITS/8)
#endif /* !NO_RSA */

#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
    /* In FIPS builds, wc_MakeRsaKey() will return an error if it cannot find
     * a probable prime in 5*(modLen/2) attempts. In non-FIPS builds, it keeps
     * trying until it gets a probable prime. */
    #ifdef HAVE_FIPS
        extern int MakeRsaKeyRetry(RsaKey* key, int size, long e, WC_RNG* rng);
        #define MAKE_RSA_KEY(a, b, c, d) MakeRsaKeyRetry(a, b, c, d)
    #else
        #define MAKE_RSA_KEY(a, b, c, d) wc_MakeRsaKey(a, b, c, d)
    #endif
#endif

#ifndef NO_DSA
    #ifndef DSA_SIG_SIZE
        #define DSA_SIG_SIZE 40
    #endif
    #ifndef MAX_DSA_PARAM_SIZE
        #define MAX_DSA_PARAM_SIZE 256
    #endif
#endif

#ifdef HAVE_ECC
    #ifndef ECC_ASN963_MAX_BUF_SZ
        #define ECC_ASN963_MAX_BUF_SZ 133
    #endif
    #ifndef ECC_PRIV_KEY_BUF
        #define ECC_PRIV_KEY_BUF 66  /* For non user defined curves. */
    #endif
    /* ecc key sizes: 14, 16, 20, 24, 28, 30, 32, 40, 48, 64 */
    /* logic to choose right key ECC size */
    #if (defined(HAVE_ECC112) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 112
        #define KEY14 14
    #else
        #define KEY14 32
    #endif
    #if (defined(HAVE_ECC128) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 128
        #define KEY16 16
    #else
        #define KEY16 32
    #endif
    #if (defined(HAVE_ECC160) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 160
        #define KEY20 20
    #else
        #define KEY20 32
    #endif
    #if (defined(HAVE_ECC192) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 192
        #define KEY24 24
    #else
        #define KEY24 32
    #endif
    #if defined(HAVE_ECC224) || defined(HAVE_ALL_CURVES)
        #define KEY28 28
    #else
        #define KEY28 32
    #endif
    #if defined(HAVE_ECC239) || defined(HAVE_ALL_CURVES)
        #define KEY30 30
    #else
        #define KEY30 32
    #endif
    #define KEY32 32
    #if defined(HAVE_ECC320) || defined(HAVE_ALL_CURVES)
        #define KEY40 40
    #else
        #define KEY40 32
    #endif
    #if defined(HAVE_ECC384) || defined(HAVE_ALL_CURVES)
        #define KEY48 48
    #else
        #define KEY48 32
    #endif
    #if defined(HAVE_ECC512) || defined(HAVE_ALL_CURVES)
        #define KEY64 64
    #else
        #define KEY64 32
    #endif

    #if !defined(HAVE_COMP_KEY)
        #if !defined(NOCOMP)
            #define NOCOMP 0
        #endif
    #else
        #if !defined(COMP)
            #define COMP 1
        #endif
    #endif
    #if !defined(DER_SZ)
        #define DER_SZ(ks) ((ks) * 2 + 1)
    #endif
#endif /* HAVE_ECC */
#ifndef WOLFSSL_HAVE_ECC_KEY_GET_PRIV
    /* FIPS build has replaced ecc.h. */
    #define wc_ecc_key_get_priv(key) (&((key)->k))
    #define WOLFSSL_HAVE_ECC_KEY_GET_PRIV
#endif

/* Returns the result based on whether check is true.
 *
 * @param [in] check  Condition for success.
 * @return  When condition is true: TEST_SUCCESS.
 * @return  When condition is false: TEST_FAIL.
 */
#ifdef DEBUG_WOLFSSL_VERBOSE
#define XSTRINGIFY(s) STRINGIFY(s)
#define STRINGIFY(s)  #s
#define TEST_RES_CHECK(check) ({ \
    int _ret = (check) ? TEST_SUCCESS : TEST_FAIL; \
    if (_ret == TEST_FAIL) { \
        fprintf(stderr, " check \"%s\" at %d ", \
            XSTRINGIFY(check), __LINE__); \
    } \
    _ret; })
#else
#define TEST_RES_CHECK(check) \
    ((check) ? TEST_SUCCESS : TEST_FAIL)
#endif /* DEBUG_WOLFSSL_VERBOSE */

#define PRINT_DATA(name, data, len)             \
do {                                            \
    int ii;                                     \
    fprintf(stderr, "%s\n", name);              \
    for (ii = 0; ii < (int)(len); ii++) {       \
        if ((ii % 8) == 0)                      \
            fprintf(stderr, "        ");        \
        fprintf(stderr, "0x%02x,", (data)[ii]); \
        if ((ii % 8) == 7)                      \
            fprintf(stderr, "\n");              \
        else                                    \
            fprintf(stderr, " ");               \
    }                                           \
    fprintf(stderr, "\n");                      \
} while (0)

#define PRINT_DATA_STR(name, data, len)         \
do {                                            \
    int ii;                                     \
    fprintf(stderr, "%s\n", name);              \
    for (ii = 0; ii < (int)(len); ii++) {       \
        if ((ii % 8) == 0)                      \
            fprintf(stderr, "        \"");      \
        fprintf(stderr, "\\x%02x", (data)[ii]); \
        if ((ii % 8) == 7)                      \
            fprintf(stderr, "\"\n");            \
    }                                           \
    if ((ii % 8) != 0)                          \
        fprintf(stderr, "\"");                  \
    fprintf(stderr, "\n");                      \
} while (0)

typedef struct testVector {
    const char* input;
    const char* output;
    size_t inLen;
    size_t outLen;
} testVector;


extern int testDevId;

#endif /* WOLFCRYPT_TEST_API_H */

