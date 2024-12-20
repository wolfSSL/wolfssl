/* wc_kyber_poly.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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

/* Implementation based on NIST 3rd Round submission package.
 * See link at:
 *   https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization/round-3-submissions
 */

/* Implementation of the functions that operate on polynomials or vectors of
 * polynomials.
 */

/* Possible Kyber options:
 *
 * WOLFSSL_WC_KYBER                                           Default: OFF
 *   Enables this code, wolfSSL implementation, to be built.
 *
 * WOLFSSL_WC_ML_KEM_512                                      Default: OFF
 *   Enables the ML-KEM 512 parameter implementations.
 * WOLFSSL_WC_ML_KEM_768                                      Default: OFF
 *   Enables the ML-KEM 768 parameter implementations.
 * WOLFSSL_WC_ML_KEM_1024                                     Default: OFF
 *   Enables the ML-KEM 1024 parameter implementations.
 * WOLFSSL_KYBER512                                           Default: OFF
 *   Enables the KYBER512 parameter implementations.
 * WOLFSSL_KYBER768                                           Default: OFF
 *   Enables the KYBER768 parameter implementations.
 * WOLFSSL_KYBER1024                                          Default: OFF
 *   Enables the KYBER1024 parameter implementations.
 *
 * USE_INTEL_SPEEDUP                                          Default: OFF
 *   Compiles in Intel x64 specific implementations that are faster.
 * WOLFSSL_KYBER_NO_LARGE_CODE                                Default: OFF
 *   Compiles smaller, fast code size with a speed trade-off.
 * WOLFSSL_KYBER_SMALL                                        Default: OFF
 *   Compiles to small code size with a speed trade-off.
 * WOLFSSL_SMALL_STACK                                        Default: OFF
 *   Use less stack by dynamically allocating local variables.
 *
 * WOLFSSL_KYBER_NTT_UNROLL                                   Default: OFF
 *   Enable an alternative NTT implementation that may be faster on some
 *   platforms and is smaller in code size.
 * WOLFSSL_KYBER_INVNTT_UNROLL                                Default: OFF
 *   Enables an alternative inverse NTT implementation that may be faster on
 *   some platforms and is smaller in code size.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/wc_kyber.h>
#include <wolfssl/wolfcrypt/cpuid.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef WOLFSSL_WC_KYBER

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* Declared in wc_kyber.c to stop compiler optimizer from simplifying. */
extern volatile sword16 kyber_opt_blocker;

#ifdef USE_INTEL_SPEEDUP
static word32 cpuid_flags = 0;
#endif

/* Half of Q plus one. Converted message bit value of 1. */
#define KYBER_Q_1_HALF      ((KYBER_Q + 1) / 2)
/* Half of Q */
#define KYBER_Q_HALF        (KYBER_Q / 2)


/* q^-1 mod 2^16 (inverse of 3329 mod 16384) */
#define KYBER_QINV       62209

/* Used in Barrett Reduction:
 *    r = a mod q
 * => r = a - ((V * a) >> 26) * q), as V based on 2^26
 * V is the multiplier that gets the quotient after shifting.
 */
#define KYBER_V          (((1U << 26) + (KYBER_Q / 2)) / KYBER_Q)

/* Used in converting to Montgomery form.
 * f is the normalizer = 2^k % m.
 * 16-bit value cast to sword32 in use.
 */
#define KYBER_F          ((1ULL << 32) % KYBER_Q)

/* Number of bytes in an output block of SHA-3-128 */
#define SHA3_128_BYTES   (WC_SHA3_128_COUNT * 8)
/* Number of bytes in an output block of SHA-3-256 */
#define SHA3_256_BYTES   (WC_SHA3_256_COUNT * 8)

/* Number of blocks to generate for matrix. */
#define GEN_MATRIX_NBLOCKS \
    ((12 * KYBER_N / 8 * (1 << 12) / KYBER_Q + XOF_BLOCK_SIZE) / XOF_BLOCK_SIZE)
/* Number of bytes to generate for matrix. */
#define GEN_MATRIX_SIZE     GEN_MATRIX_NBLOCKS * XOF_BLOCK_SIZE


/* Number of random bytes to generate for ETA3. */
#define ETA3_RAND_SIZE     ((3 * KYBER_N) / 4)
/* Number of random bytes to generate for ETA2. */
#define ETA2_RAND_SIZE     ((2 * KYBER_N) / 4)


/* Montgomery reduce a.
 *
 * @param  [in]  a  32-bit value to be reduced.
 * @return  Montgomery reduction result.
 */
#define KYBER_MONT_RED(a) \
    (sword16)(((a) - (sword32)(((sword16)((sword16)(a) * \
                                (sword16)KYBER_QINV)) * \
                               (sword32)KYBER_Q)) >> 16)

/* Barrett reduce a. r = a mod q.
 *
 * Converted division to multiplication.
 *
 * @param  [in]  a  16-bit value to be reduced to range of q.
 * @return  Modulo result.
 */
#define KYBER_BARRETT_RED(a) \
    (sword16)((sword16)(a) - (sword16)((sword16)( \
        ((sword32)((sword32)KYBER_V * (sword16)(a))) >> 26) * (word16)KYBER_Q))


/* Zetas for NTT. */
const sword16 zetas[KYBER_N / 2] = {
    2285, 2571, 2970, 1812, 1493, 1422,  287,  202, 3158,  622, 1577,  182,
     962, 2127, 1855, 1468,  573, 2004,  264,  383, 2500, 1458, 1727, 3199,
    2648, 1017,  732,  608, 1787,  411, 3124, 1758, 1223,  652, 2777, 1015,
    2036, 1491, 3047, 1785,  516, 3321, 3009, 2663, 1711, 2167,  126, 1469,
    2476, 3239, 3058,  830,  107, 1908, 3082, 2378, 2931,  961, 1821, 2604,
     448, 2264,  677, 2054, 2226,  430,  555,  843, 2078,  871, 1550,  105,
     422,  587,  177, 3094, 3038, 2869, 1574, 1653, 3083,  778, 1159, 3182,
    2552, 1483, 2727, 1119, 1739,  644, 2457,  349,  418,  329, 3173, 3254,
     817, 1097,  603,  610, 1322, 2044, 1864,  384, 2114, 3193, 1218, 1994,
    2455,  220, 2142, 1670, 2144, 1799, 2051,  794, 1819, 2475, 2459,  478,
     3221, 3021,  996,  991,  958, 1869, 1522, 1628
};

/* Zetas for inverse NTT. */
const sword16 zetas_inv[KYBER_N / 2] = {
    1701, 1807, 1460, 2371, 2338, 2333,  308,  108, 2851,  870,  854, 1510,
    2535, 1278, 1530, 1185, 1659, 1187, 3109,  874, 1335, 2111,  136, 1215,
    2945, 1465, 1285, 2007, 2719, 2726, 2232, 2512,   75,  156, 3000, 2911,
    2980,  872, 2685, 1590, 2210,  602, 1846,  777,  147, 2170, 2551,  246,
    1676, 1755,  460,  291,  235, 3152, 2742, 2907, 3224, 1779, 2458, 1251,
    2486, 2774, 2899, 1103, 1275, 2652, 1065, 2881,  725, 1508, 2368,  398,
     951,  247, 1421, 3222, 2499,  271,   90,  853, 1860, 3203, 1162, 1618,
     666,  320,    8, 2813, 1544,  282, 1838, 1293, 2314,  552, 2677, 2106,
    1571,  205, 2918, 1542, 2721, 2597, 2312,  681,  130, 1602, 1871,  829,
    2946, 3065, 1325, 2756, 1861, 1474, 1202, 2367, 3147, 1752, 2707,  171,
    3127, 3042, 1907, 1836, 1517,  359,  758, 1441
};

#define KYBER_BARRETT(a)                            \
        "SMULWB     r10, r14, " #a "\n\t"           \
        "SMULWT     r11, r14, " #a "\n\t"           \
        "SMULBT     r10, r12, r10\n\t"              \
        "SMULBT     r11, r12, r11\n\t"              \
        "PKHBT      r10, r10, r11, LSL #16\n\t"     \
        "SSUB16     " #a ", " #a ", r10\n\t"


#if !defined(WOLFSSL_ARMASM)
/* Number-Theoretic Transform.
 *
 * @param  [in, out]  r  Polynomial to transform.
 */
static void kyber_ntt(sword16* r)
{
#ifdef WOLFSSL_KYBER_SMALL
    unsigned int len;
    unsigned int k;
    unsigned int j;

    k = 1;
    for (len = KYBER_N / 2; len >= 2; len >>= 1) {
        unsigned int start;
        for (start = 0; start < KYBER_N; start = j + len) {
            sword16 zeta = zetas[k++];
            for (j = start; j < start + len; ++j) {
                sword32 p = (sword32)zeta * r[j + len];
                sword16 t = KYBER_MONT_RED(p);
                sword16 rj = r[j];
                r[j + len] = rj - t;
                r[j] = rj + t;
            }
        }
    }

    /* Reduce coefficients with quick algorithm. */
    for (j = 0; j < KYBER_N; ++j) {
        r[j] = KYBER_BARRETT_RED(r[j]);
    }
#elif defined(WOLFSSL_KYBER_NO_LARGE_CODE)
    unsigned int len;
    unsigned int k = 1;
    unsigned int j;
    unsigned int start;
    sword16 zeta = zetas[k++];

    for (j = 0; j < KYBER_N / 2; ++j) {
        sword32 p = (sword32)zeta * r[j + KYBER_N / 2];
        sword16 t = KYBER_MONT_RED(p);
        sword16 rj = r[j];
        r[j + KYBER_N / 2] = rj - t;
        r[j] = rj + t;
    }
    for (len = KYBER_N / 4; len >= 2; len >>= 1) {
        for (start = 0; start < KYBER_N; start = j + len) {
            zeta = zetas[k++];
            for (j = start; j < start + len; ++j) {
                sword32 p = (sword32)zeta * r[j + len];
                sword16 t = KYBER_MONT_RED(p);
                sword16 rj = r[j];
                r[j + len] = rj - t;
                r[j] = rj + t;
            }
        }
    }

    /* Reduce coefficients with quick algorithm. */
    for (j = 0; j < KYBER_N; ++j) {
        r[j] = KYBER_BARRETT_RED(r[j]);
    }
#elif defined(WOLFSSL_KYBER_NTT_UNROLL)
    unsigned int k = 1;
    unsigned int j;
    unsigned int start;
    sword16 zeta = zetas[k++];

    for (j = 0; j < KYBER_N / 2; ++j) {
        sword32 p = (sword32)zeta * r[j + KYBER_N / 2];
        sword16 t = KYBER_MONT_RED(p);
        sword16 rj = r[j];
        r[j + KYBER_N / 2] = rj - t;
        r[j] = rj + t;
    }
    for (start = 0; start < KYBER_N; start += 2 * 64) {
        zeta = zetas[k++];
        for (j = 0; j < 64; ++j) {
            sword32 p = (sword32)zeta * r[start + j + 64];
            sword16 t = KYBER_MONT_RED(p);
            sword16 rj = r[start + j];
            r[start + j + 64] = rj - t;
            r[start + j] = rj + t;
        }
    }
    for (start = 0; start < KYBER_N; start += 2 * 32) {
        zeta = zetas[k++];
        for (j = 0; j < 32; ++j) {
            sword32 p = (sword32)zeta * r[start + j + 32];
            sword16 t = KYBER_MONT_RED(p);
            sword16 rj = r[start + j];
            r[start + j + 32] = rj - t;
            r[start + j] = rj + t;
        }
    }
    for (start = 0; start < KYBER_N; start += 2 * 16) {
        zeta = zetas[k++];
        for (j = 0; j < 16; ++j) {
            sword32 p = (sword32)zeta * r[start + j + 16];
            sword16 t = KYBER_MONT_RED(p);
            sword16 rj = r[start + j];
            r[start + j + 16] = rj - t;
            r[start + j] = rj + t;
        }
    }
    for (start = 0; start < KYBER_N; start += 2 * 8) {
        zeta = zetas[k++];
        for (j = 0; j < 8; ++j) {
            sword32 p = (sword32)zeta * r[start + j + 8];
            sword16 t = KYBER_MONT_RED(p);
            sword16 rj = r[start + j];
            r[start + j + 8] = rj - t;
            r[start + j] = rj + t;
        }
    }
    for (start = 0; start < KYBER_N; start += 2 * 4) {
        zeta = zetas[k++];
        for (j = 0; j < 4; ++j) {
            sword32 p = (sword32)zeta * r[start + j + 4];
            sword16 t = KYBER_MONT_RED(p);
            sword16 rj = r[start + j];
            r[start + j + 4] = rj - t;
            r[start + j] = rj + t;
        }
    }
    for (start = 0; start < KYBER_N; start += 2 * 2) {
        zeta = zetas[k++];
        for (j = 0; j < 2; ++j) {
            sword32 p = (sword32)zeta * r[start + j + 2];
            sword16 t = KYBER_MONT_RED(p);
            sword16 rj = r[start + j];
            r[start + j + 2] = rj - t;
            r[start + j] = rj + t;
        }
    }
    /* Reduce coefficients with quick algorithm. */
    for (j = 0; j < KYBER_N; ++j) {
        r[j] = KYBER_BARRETT_RED(r[j]);
    }
#else
    unsigned int j;
    sword16 t0;
    sword16 t1;
    sword16 t2;
    sword16 t3;

    sword16 zeta128 = zetas[1];
    sword16 zeta64_0 = zetas[2];
    sword16 zeta64_1 = zetas[3];
    for (j = 0; j < KYBER_N / 8; j++) {
        sword16 r0 = r[j +   0];
        sword16 r1 = r[j +  32];
        sword16 r2 = r[j +  64];
        sword16 r3 = r[j +  96];
        sword16 r4 = r[j + 128];
        sword16 r5 = r[j + 160];
        sword16 r6 = r[j + 192];
        sword16 r7 = r[j + 224];

        t0 = KYBER_MONT_RED((sword32)zeta128 * r4);
        t1 = KYBER_MONT_RED((sword32)zeta128 * r5);
        t2 = KYBER_MONT_RED((sword32)zeta128 * r6);
        t3 = KYBER_MONT_RED((sword32)zeta128 * r7);
        r4 = r0 - t0;
        r5 = r1 - t1;
        r6 = r2 - t2;
        r7 = r3 - t3;
        r0 += t0;
        r1 += t1;
        r2 += t2;
        r3 += t3;

        t0 = KYBER_MONT_RED((sword32)zeta64_0 * r2);
        t1 = KYBER_MONT_RED((sword32)zeta64_0 * r3);
        t2 = KYBER_MONT_RED((sword32)zeta64_1 * r6);
        t3 = KYBER_MONT_RED((sword32)zeta64_1 * r7);
        r2 = r0 - t0;
        r3 = r1 - t1;
        r6 = r4 - t2;
        r7 = r5 - t3;
        r0 += t0;
        r1 += t1;
        r4 += t2;
        r5 += t3;

        r[j +   0] = r0;
        r[j +  32] = r1;
        r[j +  64] = r2;
        r[j +  96] = r3;
        r[j + 128] = r4;
        r[j + 160] = r5;
        r[j + 192] = r6;
        r[j + 224] = r7;
    }

    for (j = 0; j < KYBER_N; j += 64) {
        int i;
        sword16 zeta32   = zetas[ 4 + j / 64 + 0];
        sword16 zeta16_0 = zetas[ 8 + j / 32 + 0];
        sword16 zeta16_1 = zetas[ 8 + j / 32 + 1];
        sword16 zeta8_0  = zetas[16 + j / 16 + 0];
        sword16 zeta8_1  = zetas[16 + j / 16 + 1];
        sword16 zeta8_2  = zetas[16 + j / 16 + 2];
        sword16 zeta8_3  = zetas[16 + j / 16 + 3];
        for (i = 0; i < 8; i++) {
            sword16 r0 = r[j + i +  0];
            sword16 r1 = r[j + i +  8];
            sword16 r2 = r[j + i + 16];
            sword16 r3 = r[j + i + 24];
            sword16 r4 = r[j + i + 32];
            sword16 r5 = r[j + i + 40];
            sword16 r6 = r[j + i + 48];
            sword16 r7 = r[j + i + 56];

            t0 = KYBER_MONT_RED((sword32)zeta32 * r4);
            t1 = KYBER_MONT_RED((sword32)zeta32 * r5);
            t2 = KYBER_MONT_RED((sword32)zeta32 * r6);
            t3 = KYBER_MONT_RED((sword32)zeta32 * r7);
            r4 = r0 - t0;
            r5 = r1 - t1;
            r6 = r2 - t2;
            r7 = r3 - t3;
            r0 += t0;
            r1 += t1;
            r2 += t2;
            r3 += t3;

            t0 = KYBER_MONT_RED((sword32)zeta16_0 * r2);
            t1 = KYBER_MONT_RED((sword32)zeta16_0 * r3);
            t2 = KYBER_MONT_RED((sword32)zeta16_1 * r6);
            t3 = KYBER_MONT_RED((sword32)zeta16_1 * r7);
            r2 = r0 - t0;
            r3 = r1 - t1;
            r6 = r4 - t2;
            r7 = r5 - t3;
            r0 += t0;
            r1 += t1;
            r4 += t2;
            r5 += t3;

            t0 = KYBER_MONT_RED((sword32)zeta8_0 * r1);
            t1 = KYBER_MONT_RED((sword32)zeta8_1 * r3);
            t2 = KYBER_MONT_RED((sword32)zeta8_2 * r5);
            t3 = KYBER_MONT_RED((sword32)zeta8_3 * r7);
            r1 = r0 - t0;
            r3 = r2 - t1;
            r5 = r4 - t2;
            r7 = r6 - t3;
            r0 += t0;
            r2 += t1;
            r4 += t2;
            r6 += t3;

            r[j + i +  0] = r0;
            r[j + i +  8] = r1;
            r[j + i + 16] = r2;
            r[j + i + 24] = r3;
            r[j + i + 32] = r4;
            r[j + i + 40] = r5;
            r[j + i + 48] = r6;
            r[j + i + 56] = r7;
        }
    }

    for (j = 0; j < KYBER_N; j += 8) {
        sword16 zeta4  = zetas[32 + j / 8 + 0];
        sword16 zeta2_0 = zetas[64 + j / 4 + 0];
        sword16 zeta2_1 = zetas[64 + j / 4 + 1];
        sword16 r0 = r[j + 0];
        sword16 r1 = r[j + 1];
        sword16 r2 = r[j + 2];
        sword16 r3 = r[j + 3];
        sword16 r4 = r[j + 4];
        sword16 r5 = r[j + 5];
        sword16 r6 = r[j + 6];
        sword16 r7 = r[j + 7];

        t0 = KYBER_MONT_RED((sword32)zeta4 * r4);
        t1 = KYBER_MONT_RED((sword32)zeta4 * r5);
        t2 = KYBER_MONT_RED((sword32)zeta4 * r6);
        t3 = KYBER_MONT_RED((sword32)zeta4 * r7);
        r4 = r0 - t0;
        r5 = r1 - t1;
        r6 = r2 - t2;
        r7 = r3 - t3;
        r0 += t0;
        r1 += t1;
        r2 += t2;
        r3 += t3;

        t0 = KYBER_MONT_RED((sword32)zeta2_0 * r2);
        t1 = KYBER_MONT_RED((sword32)zeta2_0 * r3);
        t2 = KYBER_MONT_RED((sword32)zeta2_1 * r6);
        t3 = KYBER_MONT_RED((sword32)zeta2_1 * r7);
        r2 = r0 - t0;
        r3 = r1 - t1;
        r6 = r4 - t2;
        r7 = r5 - t3;
        r0 += t0;
        r1 += t1;
        r4 += t2;
        r5 += t3;

        r[j + 0] = KYBER_BARRETT_RED(r0);
        r[j + 1] = KYBER_BARRETT_RED(r1);
        r[j + 2] = KYBER_BARRETT_RED(r2);
        r[j + 3] = KYBER_BARRETT_RED(r3);
        r[j + 4] = KYBER_BARRETT_RED(r4);
        r[j + 5] = KYBER_BARRETT_RED(r5);
        r[j + 6] = KYBER_BARRETT_RED(r6);
        r[j + 7] = KYBER_BARRETT_RED(r7);
    }
#endif
}

/* Inverse Number-Theoretic Transform.
 *
 * @param  [in, out]  r  Polynomial to transform.
 */
static void kyber_invntt(sword16* r)
{
#ifdef WOLFSSL_KYBER_SMALL
    unsigned int len;
    unsigned int k;
    unsigned int j;
    sword16 zeta;

    k = 0;
    for (len = 2; len <= KYBER_N / 2; len <<= 1) {
        unsigned int start;
        for (start = 0; start < KYBER_N; start = j + len) {
            zeta = zetas_inv[k++];
            for (j = start; j < start + len; ++j) {
                sword32 p;
                sword16 rj = r[j];
                sword16 rjl = r[j + len];
                sword16 t = rj + rjl;
                r[j] = KYBER_BARRETT_RED(t);
                rjl = rj - rjl;
                p = (sword32)zeta * rjl;
                r[j + len] = KYBER_MONT_RED(p);
            }
        }
    }

    zeta = zetas_inv[127];
    for (j = 0; j < KYBER_N; ++j) {
        sword32 p = (sword32)zeta * r[j];
        r[j] = KYBER_MONT_RED(p);
    }
#elif defined(WOLFSSL_KYBER_NO_LARGE_CODE)
    unsigned int len;
    unsigned int k;
    unsigned int j;
    sword16 zeta;
    sword16 zeta2;

    k = 0;
    for (len = 2; len <= KYBER_N / 4; len <<= 1) {
        unsigned int start;
        for (start = 0; start < KYBER_N; start = j + len) {
            zeta = zetas_inv[k++];
            for (j = start; j < start + len; ++j) {
                sword32 p;
                sword16 rj = r[j];
                sword16 rjl = r[j + len];
                sword16 t = rj + rjl;
                r[j] = KYBER_BARRETT_RED(t);
                rjl = rj - rjl;
                p = (sword32)zeta * rjl;
                r[j + len] = KYBER_MONT_RED(p);
            }
        }
    }

    zeta = zetas_inv[126];
    zeta2 = zetas_inv[127];
    for (j = 0; j < KYBER_N / 2; ++j) {
        sword32 p;
        sword16 rj = r[j];
        sword16 rjl = r[j + KYBER_N / 2];
        sword16 t = rj + rjl;
        rjl = rj - rjl;
        p = (sword32)zeta * rjl;
        r[j] = t;
        r[j + KYBER_N / 2] = KYBER_MONT_RED(p);

        p = (sword32)zeta2 * r[j];
        r[j] = KYBER_MONT_RED(p);
        p = (sword32)zeta2 * r[j + KYBER_N / 2];
        r[j + KYBER_N / 2] = KYBER_MONT_RED(p);
    }
#elif defined(WOLFSSL_KYBER_INVNTT_UNROLL)
    unsigned int k;
    unsigned int j;
    unsigned int start;
    sword16 zeta;
    sword16 zeta2;

    k = 0;
    for (start = 0; start < KYBER_N; start += 2 * 2) {
        zeta = zetas_inv[k++];
        for (j = 0; j < 2; ++j) {
            sword32 p;
            sword16 rj = r[start + j];
            sword16 rjl = r[start + j + 2];
            sword16 t = rj + rjl;
            r[start + j] = t;
            rjl = rj - rjl;
            p = (sword32)zeta * rjl;
            r[start + j + 2] = KYBER_MONT_RED(p);
        }
    }
    for (start = 0; start < KYBER_N; start += 2 * 4) {
        zeta = zetas_inv[k++];
        for (j = 0; j < 4; ++j) {
            sword32 p;
            sword16 rj = r[start + j];
            sword16 rjl = r[start + j + 4];
            sword16 t = rj + rjl;
            r[start + j] = t;
            rjl = rj - rjl;
            p = (sword32)zeta * rjl;
            r[start + j + 4] = KYBER_MONT_RED(p);
        }
    }
    for (start = 0; start < KYBER_N; start += 2 * 8) {
        zeta = zetas_inv[k++];
        for (j = 0; j < 8; ++j) {
            sword32 p;
            sword16 rj = r[start + j];
            sword16 rjl = r[start + j + 8];
            sword16 t = rj + rjl;
            /* Reduce. */
            r[start + j] = KYBER_BARRETT_RED(t);
            rjl = rj - rjl;
            p = (sword32)zeta * rjl;
            r[start + j + 8] = KYBER_MONT_RED(p);
        }
    }
    for (start = 0; start < KYBER_N; start += 2 * 16) {
        zeta = zetas_inv[k++];
        for (j = 0; j < 16; ++j) {
            sword32 p;
            sword16 rj = r[start + j];
            sword16 rjl = r[start + j + 16];
            sword16 t = rj + rjl;
            r[start + j] = t;
            rjl = rj - rjl;
            p = (sword32)zeta * rjl;
            r[start + j + 16] = KYBER_MONT_RED(p);
        }
    }
    for (start = 0; start < KYBER_N; start += 2 * 32) {
        zeta = zetas_inv[k++];
        for (j = 0; j < 32; ++j) {
            sword32 p;
            sword16 rj = r[start + j];
            sword16 rjl = r[start + j + 32];
            sword16 t = rj + rjl;
            r[start + j] = t;
            rjl = rj - rjl;
            p = (sword32)zeta * rjl;
            r[start + j + 32] = KYBER_MONT_RED(p);
        }
    }
    for (start = 0; start < KYBER_N; start += 2 * 64) {
        zeta = zetas_inv[k++];
        for (j = 0; j < 64; ++j) {
            sword32 p;
            sword16 rj = r[start + j];
            sword16 rjl = r[start + j + 64];
            sword16 t = rj + rjl;
            /* Reduce. */
            r[start + j] = KYBER_BARRETT_RED(t);
            rjl = rj - rjl;
            p = (sword32)zeta * rjl;
            r[start + j + 64] = KYBER_MONT_RED(p);
        }
    }
    zeta = zetas_inv[126];
    zeta2 = zetas_inv[127];
    for (j = 0; j < KYBER_N / 2; ++j) {
        sword32 p;
        sword16 rj = r[j];
        sword16 rjl = r[j + KYBER_N / 2];
        sword16 t = rj + rjl;
        rjl = rj - rjl;
        p = (sword32)zeta * rjl;
        r[j] = t;
        r[j + KYBER_N / 2] = KYBER_MONT_RED(p);

        p = (sword32)zeta2 * r[j];
        r[j] = KYBER_MONT_RED(p);
        p = (sword32)zeta2 * r[j + KYBER_N / 2];
        r[j + KYBER_N / 2] = KYBER_MONT_RED(p);
    }
#else
    unsigned int j;
    sword16 t0;
    sword16 t1;
    sword16 t2;
    sword16 t3;
    sword16 zeta64_0;
    sword16 zeta64_1;
    sword16 zeta128;
    sword16 zeta256;
    sword32 p;

    for (j = 0; j < KYBER_N; j += 8) {
        sword16 zeta2_0 = zetas_inv[ 0 + j / 4 + 0];
        sword16 zeta2_1 = zetas_inv[ 0 + j / 4 + 1];
        sword16 zeta4   = zetas_inv[64 + j / 8 + 0];
        sword16 r0 = r[j + 0];
        sword16 r1 = r[j + 1];
        sword16 r2 = r[j + 2];
        sword16 r3 = r[j + 3];
        sword16 r4 = r[j + 4];
        sword16 r5 = r[j + 5];
        sword16 r6 = r[j + 6];
        sword16 r7 = r[j + 7];

        p = (sword32)zeta2_0 * (sword16)(r0 - r2);
        t0 = KYBER_MONT_RED(p);
        p = (sword32)zeta2_0 * (sword16)(r1 - r3);
        t1 = KYBER_MONT_RED(p);
        p = (sword32)zeta2_1 * (sword16)(r4 - r6);
        t2 = KYBER_MONT_RED(p);
        p = (sword32)zeta2_1 * (sword16)(r5 - r7);
        t3 = KYBER_MONT_RED(p);
        r0 += r2;
        r1 += r3;
        r4 += r6;
        r5 += r7;
        r2 = t0;
        r3 = t1;
        r6 = t2;
        r7 = t3;

        p = (sword32)zeta4 * (sword16)(r0 - r4);
        t0 = KYBER_MONT_RED(p);
        p = (sword32)zeta4 * (sword16)(r1 - r5);
        t1 = KYBER_MONT_RED(p);
        p = (sword32)zeta4 * (sword16)(r2 - r6);
        t2 = KYBER_MONT_RED(p);
        p = (sword32)zeta4 * (sword16)(r3 - r7);
        t3 = KYBER_MONT_RED(p);
        r0 += r4;
        r1 += r5;
        r2 += r6;
        r3 += r7;
        r4 = t0;
        r5 = t1;
        r6 = t2;
        r7 = t3;

        r[j + 0] = r0;
        r[j + 1] = r1;
        r[j + 2] = r2;
        r[j + 3] = r3;
        r[j + 4] = r4;
        r[j + 5] = r5;
        r[j + 6] = r6;
        r[j + 7] = r7;
    }

    for (j = 0; j < KYBER_N; j += 64) {
        int i;
        sword16 zeta8_0  = zetas_inv[ 96 + j / 16 + 0];
        sword16 zeta8_1  = zetas_inv[ 96 + j / 16 + 1];
        sword16 zeta8_2  = zetas_inv[ 96 + j / 16 + 2];
        sword16 zeta8_3  = zetas_inv[ 96 + j / 16 + 3];
        sword16 zeta16_0 = zetas_inv[112 + j / 32 + 0];
        sword16 zeta16_1 = zetas_inv[112 + j / 32 + 1];
        sword16 zeta32   = zetas_inv[120 + j / 64 + 0];
        for (i = 0; i < 8; i++) {
            sword16 r0 = r[j + i +  0];
            sword16 r1 = r[j + i +  8];
            sword16 r2 = r[j + i + 16];
            sword16 r3 = r[j + i + 24];
            sword16 r4 = r[j + i + 32];
            sword16 r5 = r[j + i + 40];
            sword16 r6 = r[j + i + 48];
            sword16 r7 = r[j + i + 56];

            p = (sword32)zeta8_0 * (sword16)(r0 - r1);
            t0 = KYBER_MONT_RED(p);
            p = (sword32)zeta8_1 * (sword16)(r2 - r3);
            t1 = KYBER_MONT_RED(p);
            p = (sword32)zeta8_2 * (sword16)(r4 - r5);
            t2 = KYBER_MONT_RED(p);
            p = (sword32)zeta8_3 * (sword16)(r6 - r7);
            t3 = KYBER_MONT_RED(p);
            r0 = KYBER_BARRETT_RED(r0 + r1);
            r2 = KYBER_BARRETT_RED(r2 + r3);
            r4 = KYBER_BARRETT_RED(r4 + r5);
            r6 = KYBER_BARRETT_RED(r6 + r7);
            r1 = t0;
            r3 = t1;
            r5 = t2;
            r7 = t3;

            p = (sword32)zeta16_0 * (sword16)(r0 - r2);
            t0 = KYBER_MONT_RED(p);
            p = (sword32)zeta16_0 * (sword16)(r1 - r3);
            t1 = KYBER_MONT_RED(p);
            p = (sword32)zeta16_1 * (sword16)(r4 - r6);
            t2 = KYBER_MONT_RED(p);
            p = (sword32)zeta16_1 * (sword16)(r5 - r7);
            t3 = KYBER_MONT_RED(p);
            r0 += r2;
            r1 += r3;
            r4 += r6;
            r5 += r7;
            r2 = t0;
            r3 = t1;
            r6 = t2;
            r7 = t3;

            p = (sword32)zeta32 * (sword16)(r0 - r4);
            t0 = KYBER_MONT_RED(p);
            p = (sword32)zeta32 * (sword16)(r1 - r5);
            t1 = KYBER_MONT_RED(p);
            p = (sword32)zeta32 * (sword16)(r2 - r6);
            t2 = KYBER_MONT_RED(p);
            p = (sword32)zeta32 * (sword16)(r3 - r7);
            t3 = KYBER_MONT_RED(p);
            r0 += r4;
            r1 += r5;
            r2 += r6;
            r3 += r7;
            r4 = t0;
            r5 = t1;
            r6 = t2;
            r7 = t3;

            r[j + i +  0] = r0;
            r[j + i +  8] = r1;
            r[j + i + 16] = r2;
            r[j + i + 24] = r3;
            r[j + i + 32] = r4;
            r[j + i + 40] = r5;
            r[j + i + 48] = r6;
            r[j + i + 56] = r7;
        }
    }

    zeta64_0 = zetas_inv[124];
    zeta64_1 = zetas_inv[125];
    zeta128  = zetas_inv[126];
    zeta256  = zetas_inv[127];
    for (j = 0; j < KYBER_N / 8; j++) {
        sword16 r0 = r[j +   0];
        sword16 r1 = r[j +  32];
        sword16 r2 = r[j +  64];
        sword16 r3 = r[j +  96];
        sword16 r4 = r[j + 128];
        sword16 r5 = r[j + 160];
        sword16 r6 = r[j + 192];
        sword16 r7 = r[j + 224];

        p = (sword32)zeta64_0 * (sword16)(r0 - r2);
        t0 = KYBER_MONT_RED(p);
        p = (sword32)zeta64_0 * (sword16)(r1 - r3);
        t1 = KYBER_MONT_RED(p);
        p = (sword32)zeta64_1 * (sword16)(r4 - r6);
        t2 = KYBER_MONT_RED(p);
        p = (sword32)zeta64_1 * (sword16)(r5 - r7);
        t3 = KYBER_MONT_RED(p);
        r0 = KYBER_BARRETT_RED(r0 + r2);
        r1 = KYBER_BARRETT_RED(r1 + r3);
        r4 = KYBER_BARRETT_RED(r4 + r6);
        r5 = KYBER_BARRETT_RED(r5 + r7);
        r2 = t0;
        r3 = t1;
        r6 = t2;
        r7 = t3;

        p = (sword32)zeta128 * (sword16)(r0 - r4);
        t0 = KYBER_MONT_RED(p);
        p = (sword32)zeta128 * (sword16)(r1 - r5);
        t1 = KYBER_MONT_RED(p);
        p = (sword32)zeta128 * (sword16)(r2 - r6);
        t2 = KYBER_MONT_RED(p);
        p = (sword32)zeta128 * (sword16)(r3 - r7);
        t3 = KYBER_MONT_RED(p);
        r0 += r4;
        r1 += r5;
        r2 += r6;
        r3 += r7;
        r4 = t0;
        r5 = t1;
        r6 = t2;
        r7 = t3;

        p = (sword32)zeta256 * r0;
        r0 = KYBER_MONT_RED(p);
        p = (sword32)zeta256 * r1;
        r1 = KYBER_MONT_RED(p);
        p = (sword32)zeta256 * r2;
        r2 = KYBER_MONT_RED(p);
        p = (sword32)zeta256 * r3;
        r3 = KYBER_MONT_RED(p);
        p = (sword32)zeta256 * r4;
        r4 = KYBER_MONT_RED(p);
        p = (sword32)zeta256 * r5;
        r5 = KYBER_MONT_RED(p);
        p = (sword32)zeta256 * r6;
        r6 = KYBER_MONT_RED(p);
        p = (sword32)zeta256 * r7;
        r7 = KYBER_MONT_RED(p);

        r[j +   0] = r0;
        r[j +  32] = r1;
        r[j +  64] = r2;
        r[j +  96] = r3;
        r[j + 128] = r4;
        r[j + 160] = r5;
        r[j + 192] = r6;
        r[j + 224] = r7;
    }
#endif
}

/* Multiplication of polynomials in Zq[X]/(X^2-zeta).
 *
 * Used for multiplication of elements in Rq in NTT domain.
 *
 * @param  [out]  r     Result polynomial.
 * @param  [in]   a     First factor.
 * @param  [in]   b     Second factor.
 * @param  [in]   zeta  Integer defining the reduction polynomial.
 */
static void kyber_basemul(sword16* r, const sword16* a, const sword16* b,
    sword16 zeta)
{
    sword16 r0;
    sword16 a0 = a[0];
    sword16 a1 = a[1];
    sword16 b0 = b[0];
    sword16 b1 = b[1];
    sword32 p1;
    sword32 p2;

    p1   = (sword32)a1 * b1;
    p2   = (sword32)a0 * b0;
    r0   = KYBER_MONT_RED(p1);
    p1   = (sword32)zeta * r0;
    p1  += p2;
    r[0] = KYBER_MONT_RED(p1);

    p1   = (sword32)a0 * b1;
    p2   = (sword32)a1 * b0;
    p1  += p2;
    r[1] = KYBER_MONT_RED(p1);
}

/* Multiply two polynomials in NTT domain. r = a * b.
 *
 * @param  [out]  r  Result polynomial.
 * @param  [in]   a  First polynomial multiplier.
 * @param  [in]   b  Second polynomial multiplier.
 */
static void kyber_basemul_mont(sword16* r, const sword16* a, const sword16* b)
{
    const sword16* zeta = zetas + 64;

#if defined(WOLFSSL_KYBER_SMALL)
    unsigned int i;
    for (i = 0; i < KYBER_N; i += 4, zeta++) {
        kyber_basemul(r + i + 0, a + i + 0, b + i + 0,  zeta[0]);
        kyber_basemul(r + i + 2, a + i + 2, b + i + 2, -zeta[0]);
    }
#elif defined(WOLFSSL_KYBER_NO_LARGE_CODE)
    unsigned int i;
    for (i = 0; i < KYBER_N; i += 8, zeta += 2) {
        kyber_basemul(r + i + 0, a + i + 0, b + i + 0,  zeta[0]);
        kyber_basemul(r + i + 2, a + i + 2, b + i + 2, -zeta[0]);
        kyber_basemul(r + i + 4, a + i + 4, b + i + 4,  zeta[1]);
        kyber_basemul(r + i + 6, a + i + 6, b + i + 6, -zeta[1]);
    }
#else
    unsigned int i;
    for (i = 0; i < KYBER_N; i += 16, zeta += 4) {
        kyber_basemul(r + i +  0, a + i +  0, b + i +  0,  zeta[0]);
        kyber_basemul(r + i +  2, a + i +  2, b + i +  2, -zeta[0]);
        kyber_basemul(r + i +  4, a + i +  4, b + i +  4,  zeta[1]);
        kyber_basemul(r + i +  6, a + i +  6, b + i +  6, -zeta[1]);
        kyber_basemul(r + i +  8, a + i +  8, b + i +  8,  zeta[2]);
        kyber_basemul(r + i + 10, a + i + 10, b + i + 10, -zeta[2]);
        kyber_basemul(r + i + 12, a + i + 12, b + i + 12,  zeta[3]);
        kyber_basemul(r + i + 14, a + i + 14, b + i + 14, -zeta[3]);
    }
#endif
}

/* Multiply two polynomials in NTT domain and add to result. r += a * b.
 *
 * @param  [in, out]  r  Result polynomial.
 * @param  [in]       a  First polynomial multiplier.
 * @param  [in]       b  Second polynomial multiplier.
 */
static void kyber_basemul_mont_add(sword16* r, const sword16* a,
    const sword16* b)
{
    const sword16* zeta = zetas + 64;

#if defined(WOLFSSL_KYBER_SMALL)
    unsigned int i;
    for (i = 0; i < KYBER_N; i += 4, zeta++) {
        sword16 t0[2];
        sword16 t2[2];

        kyber_basemul(t0, a + i + 0, b + i + 0,  zeta[0]);
        kyber_basemul(t2, a + i + 2, b + i + 2, -zeta[0]);

        r[i + 0] += t0[0];
        r[i + 1] += t0[1];
        r[i + 2] += t2[0];
        r[i + 3] += t2[1];
    }
#elif defined(WOLFSSL_KYBER_NO_LARGE_CODE)
    unsigned int i;
    for (i = 0; i < KYBER_N; i += 8, zeta += 2) {
        sword16 t0[2];
        sword16 t2[2];
        sword16 t4[2];
        sword16 t6[2];

        kyber_basemul(t0, a + i + 0, b + i + 0,  zeta[0]);
        kyber_basemul(t2, a + i + 2, b + i + 2, -zeta[0]);
        kyber_basemul(t4, a + i + 4, b + i + 4,  zeta[1]);
        kyber_basemul(t6, a + i + 6, b + i + 6, -zeta[1]);

        r[i + 0] += t0[0];
        r[i + 1] += t0[1];
        r[i + 2] += t2[0];
        r[i + 3] += t2[1];
        r[i + 4] += t4[0];
        r[i + 5] += t4[1];
        r[i + 6] += t6[0];
        r[i + 7] += t6[1];
    }
#else
    unsigned int i;
    for (i = 0; i < KYBER_N; i += 16, zeta += 4) {
        sword16 t0[2];
        sword16 t2[2];
        sword16 t4[2];
        sword16 t6[2];
        sword16 t8[2];
        sword16 t10[2];
        sword16 t12[2];
        sword16 t14[2];

        kyber_basemul(t0, a + i + 0, b + i + 0,  zeta[0]);
        kyber_basemul(t2, a + i + 2, b + i + 2, -zeta[0]);
        kyber_basemul(t4, a + i + 4, b + i + 4,  zeta[1]);
        kyber_basemul(t6, a + i + 6, b + i + 6, -zeta[1]);
        kyber_basemul(t8, a + i + 8, b + i + 8,  zeta[2]);
        kyber_basemul(t10, a + i + 10, b + i + 10, -zeta[2]);
        kyber_basemul(t12, a + i + 12, b + i + 12,  zeta[3]);
        kyber_basemul(t14, a + i + 14, b + i + 14, -zeta[3]);

        r[i + 0] += t0[0];
        r[i + 1] += t0[1];
        r[i + 2] += t2[0];
        r[i + 3] += t2[1];
        r[i + 4] += t4[0];
        r[i + 5] += t4[1];
        r[i + 6] += t6[0];
        r[i + 7] += t6[1];
        r[i + 8] += t8[0];
        r[i + 9] += t8[1];
        r[i + 10] += t10[0];
        r[i + 11] += t10[1];
        r[i + 12] += t12[0];
        r[i + 13] += t12[1];
        r[i + 14] += t14[0];
        r[i + 15] += t14[1];
    }
#endif
}
#endif

/* Pointwise multiply elements of a and b, into r, and multiply by 2^-16.
 *
 * @param  [out]  r   Result polynomial.
 * @param  [in]   a   First vector polynomial to multiply with.
 * @param  [in]   b   Second vector polynomial to multiply with.
 * @param  [in]   kp  Number of polynomials in vector.
 */
static void kyber_pointwise_acc_mont(sword16* r, const sword16* a,
    const sword16* b, unsigned int kp)
{
    unsigned int i;

    kyber_basemul_mont(r, a, b);
    for (i = 1; i < kp - 1; ++i) {
        kyber_basemul_mont_add(r, a + i * KYBER_N, b + i * KYBER_N);
    }
    kyber_basemul_mont_add(r, a + (kp - 1) * KYBER_N, b + (kp - 1) * KYBER_N);
}

/******************************************************************************/

/* Initialize Kyber implementation.
 */
void kyber_init(void)
{
#ifdef USE_INTEL_SPEEDUP
    cpuid_flags = cpuid_get_flags();
#endif
}

/******************************************************************************/

#if defined(__aarch64__) && defined(WOLFSSL_ARMASM)

/* Generate a public-private key pair from randomly generated data.
 *
 * @param  [in, out]  priv  Private key vector of polynomials.
 * @param  [out]      pub   Public key vector of polynomials.
 * @param  [in]       e     Error values as a vector of polynomials. Modified.
 * @param  [in]       a     Random values in an array of vectors of polynomials.
 * @param  [in]       kp    Number of polynomials in vector.
 */
void kyber_keygen(sword16* priv, sword16* pub, sword16* e, const sword16* a,
    int kp)
{
    int i;

    /* Transform private key. All of result used in public key calculation */
    for (i = 0; i < kp; ++i) {
        kyber_ntt(priv + i * KYBER_N);
    }

    /* For each polynomial in the vectors. */
    for (i = 0; i < kp; ++i) {
        /* Multiply a by private into public polynomial. */
        kyber_pointwise_acc_mont(pub + i * KYBER_N, a + i * kp * KYBER_N, priv,
            kp);
        /* Convert public polynomial to Montgomery form. */
        kyber_to_mont(pub + i * KYBER_N);
        /* Transform error values polynomial. */
        kyber_ntt(e + i * KYBER_N);
        /* Add errors to public key and reduce. */
        kyber_add_reduce(pub + i * KYBER_N, e + i * KYBER_N);
    }
}

/* Encapsulate message.
 *
 * @param  [in]   pub  Public key vector of polynomials.
 * @param  [out]  bp   Vector of polynomials.
 * @param  [out]  v    Polynomial.
 * @param  [in]   at   Array of vector of polynomials.
 * @param  [in]   sp   Vector of polynomials.
 * @param  [in]   ep   Error Vector of polynomials.
 * @param  [in]   epp  Error polynomial.
 * @param  [in]   m    Message polynomial.
 * @param  [in]   kp   Number of polynomials in vector.
 */
void kyber_encapsulate(const sword16* pub, sword16* bp, sword16* v,
    const sword16* at, sword16* sp, const sword16* ep, const sword16* epp,
    const sword16* m, int kp)
{
    int i;

    /* Transform sp. All of result used in calculation of bp and v. */
    for (i = 0; i < kp; ++i) {
        kyber_ntt(sp + i * KYBER_N);
    }

    /* For each polynomial in the vectors. */
    for (i = 0; i < kp; ++i) {
        /* Multiply at by sp into bp polynomial. */
        kyber_pointwise_acc_mont(bp + i * KYBER_N, at +  i * kp * KYBER_N, sp,
            kp);
        /* Inverse transform bp polynomial. */
        kyber_invntt(bp + i * KYBER_N);
        /* Add errors to bp and reduce. */
        kyber_add_reduce(bp + i * KYBER_N, ep + i * KYBER_N);
    }

    /* Multiply public key by sp into v polynomial. */
    kyber_pointwise_acc_mont(v, pub, sp, kp);
    /* Inverse transform v. */
    kyber_invntt(v);
    /* Add errors and message to v and reduce. */
    kyber_add3_reduce(v, epp, m);
}

/* Decapsulate message.
 *
 * @param  [in]   priv  Private key vector of polynomials.
 * @param  [out]  mp    Message polynomial.
 * @param  [in]   bp    Vector of polynomials containing error.
 * @param  [in]   v     Encapsulated message polynomial.
 * @param  [in]   kp    Number of polynomials in vector.
 */
void kyber_decapsulate(const sword16* priv, sword16* mp, sword16* bp,
    const sword16* v, int kp)
{
    int i;

    /* Transform bp. All of result used in calculation of mp. */
    for (i = 0; i < kp; ++i) {
        kyber_ntt(bp + i * KYBER_N);
    }

    /* Multiply private key by bp into mp polynomial. */
    kyber_pointwise_acc_mont(mp, priv, bp, kp);
    /* Inverse transform mp. */
    kyber_invntt(mp);
    /* Subtract errors (mp) out of v and reduce into mp. */
    kyber_rsub_reduce(mp, v);
}

#else

/* Generate a public-private key pair from randomly generated data.
 *
 * @param  [in, out]  priv  Private key vector of polynomials.
 * @param  [out]      pub   Public key vector of polynomials.
 * @param  [in]       e     Error values as a vector of polynomials. Modified.
 * @param  [in]       a     Random values in an array of vectors of polynomials.
 * @param  [in]       kp    Number of polynomials in vector.
 */
static void kyber_keygen_c(sword16* priv, sword16* pub, sword16* e,
    const sword16* a, int kp)
{
    int i;

    /* Transform private key. All of result used in public key calculation */
    for (i = 0; i < kp; ++i) {
        kyber_ntt(priv + i * KYBER_N);
    }

    /* For each polynomial in the vectors. */
    for (i = 0; i < kp; ++i) {
        unsigned int j;

        /* Multiply a by private into public polynomial. */
        kyber_pointwise_acc_mont(pub + i * KYBER_N, a + i * kp * KYBER_N, priv,
            kp);
        /* Convert public polynomial to Montgomery form. */
        for (j = 0; j < KYBER_N; ++j) {
            sword32 t = pub[i * KYBER_N + j] * (sword32)KYBER_F;
            pub[i * KYBER_N + j] = KYBER_MONT_RED(t);
        }
        /* Transform error values polynomial. */
        kyber_ntt(e + i * KYBER_N);
        /* Add errors to public key and reduce. */
        for (j = 0; j < KYBER_N; ++j) {
            sword16 t = pub[i * KYBER_N + j] + e[i * KYBER_N + j];
            pub[i * KYBER_N + j] = KYBER_BARRETT_RED(t);
        }
    }
}

/* Generate a public-private key pair from randomly generated data.
 *
 * @param  [in, out]  priv  Private key vector of polynomials.
 * @param  [out]      pub   Public key vector of polynomials.
 * @param  [in]       e     Error values as a vector of polynomials. Modified.
 * @param  [in]       a     Random values in an array of vectors of polynomials.
 * @param  [in]       kp    Number of polynomials in vector.
 */
void kyber_keygen(sword16* priv, sword16* pub, sword16* e, const sword16* a,
    int kp)
{
#ifdef USE_INTEL_SPEEDUP
    if ((IS_INTEL_AVX2(cpuid_flags)) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        kyber_keygen_avx2(priv, pub, e, a, kp);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
        kyber_keygen_c(priv, pub, e, a, kp);
    }
}

/* Encapsulate message.
 *
 * @param  [in]   pub  Public key vector of polynomials.
 * @param  [out]  bp   Vector of polynomials.
 * @param  [out]  v    Polynomial.
 * @param  [in]   at   Array of vector of polynomials.
 * @param  [in]   sp   Vector of polynomials.
 * @param  [in]   ep   Error Vector of polynomials.
 * @param  [in]   epp  Error polynomial.
 * @param  [in]   m    Message polynomial.
 * @param  [in]   kp   Number of polynomials in vector.
 */
static void kyber_encapsulate_c(const sword16* pub, sword16* bp, sword16* v,
    const sword16* at, sword16* sp, const sword16* ep, const sword16* epp,
    const sword16* m, int kp)
{
    int i;

    /* Transform sp. All of result used in calculation of bp and v. */
    for (i = 0; i < kp; ++i) {
        kyber_ntt(sp + i * KYBER_N);
    }

    /* For each polynomial in the vectors. */
    for (i = 0; i < kp; ++i) {
        unsigned int j;

        /* Multiply at by sp into bp polynomial. */
        kyber_pointwise_acc_mont(bp + i * KYBER_N, at +  i * kp * KYBER_N, sp,
            kp);
        /* Inverse transform bp polynomial. */
        kyber_invntt(bp + i * KYBER_N);
        /* Add errors to bp and reduce. */
        for (j = 0; j < KYBER_N; ++j) {
            sword16 t = bp[i * KYBER_N + j] + ep[i * KYBER_N + j];
            bp[i * KYBER_N + j] = KYBER_BARRETT_RED(t);
        }
    }

    /* Multiply public key by sp into v polynomial. */
    kyber_pointwise_acc_mont(v, pub, sp, kp);
    /* Inverse transform v. */
    kyber_invntt(v);
    /* Add errors and message to v and reduce. */
    for (i = 0; i < KYBER_N; ++i) {
        sword16 t = v[i] + epp[i] + m[i];
        v[i] = KYBER_BARRETT_RED(t);
    }
}


/* Encapsulate message.
 *
 * @param  [in]   pub  Public key vector of polynomials.
 * @param  [out]  bp   Vector of polynomials.
 * @param  [out]  v    Polynomial.
 * @param  [in]   at   Array of vector of polynomials.
 * @param  [in]   sp   Vector of polynomials.
 * @param  [in]   ep   Error Vector of polynomials.
 * @param  [in]   epp  Error polynomial.
 * @param  [in]   m    Message polynomial.
 * @param  [in]   kp   Number of polynomials in vector.
 */
void kyber_encapsulate(const sword16* pub, sword16* bp, sword16* v,
    const sword16* at, sword16* sp, const sword16* ep, const sword16* epp,
    const sword16* m, int kp)
{
#ifdef USE_INTEL_SPEEDUP
    if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        kyber_encapsulate_avx2(pub, bp, v, at, sp, ep, epp, m, kp);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
        kyber_encapsulate_c(pub, bp, v, at, sp, ep, epp, m, kp);
    }
}

/* Decapsulate message.
 *
 * @param  [in]   priv  Private key vector of polynomials.
 * @param  [out]  mp    Message polynomial.
 * @param  [in]   bp    Vector of polynomials containing error.
 * @param  [in]   v     Encapsulated message polynomial.
 * @param  [in]   kp    Number of polynomials in vector.
 */
static void kyber_decapsulate_c(const sword16* priv, sword16* mp, sword16* bp,
    const sword16* v, int kp)
{
    int i;

    /* Transform bp. All of result used in calculation of mp. */
    for (i = 0; i < kp; ++i) {
        kyber_ntt(bp + i * KYBER_N);
    }

    /* Multiply private key by bp into mp polynomial. */
    kyber_pointwise_acc_mont(mp, priv, bp, kp);
    /* Inverse transform mp. */
    kyber_invntt(mp);
    /* Subtract errors (mp) out of v and reduce into mp. */
    for (i = 0; i < KYBER_N; ++i) {
        sword16 t = v[i] - mp[i];
        mp[i] = KYBER_BARRETT_RED(t);
    }
}

/* Decapsulate message.
 *
 * @param  [in]   priv  Private key vector of polynomials.
 * @param  [out]  mp    Message polynomial.
 * @param  [in]   bp    Vector of polynomials containing error.
 * @param  [in]   v     Encapsulated message polynomial.
 * @param  [in]   kp    Number of polynomials in vector.
 */
void kyber_decapsulate(const sword16* priv, sword16* mp, sword16* bp,
    const sword16* v, int kp)
{
#ifdef USE_INTEL_SPEEDUP
    if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        kyber_decapsulate_avx2(priv, mp, bp, v, kp);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
        kyber_decapsulate_c(priv, mp, bp, v, kp);
    }
}

#endif

/******************************************************************************/

#ifdef USE_INTEL_SPEEDUP
#if defined(WOLFSSL_KYBER512) || defined(WOLFSSL_WC_ML_KEM_512)
/* Deterministically generate a matrix (or transpose) of uniform integers mod q.
 *
 * Seed used with XOF to generate random bytes.
 *
 * @param  [out]  a           Matrix of uniform integers.
 * @param  [in]   seed        Bytes to seed XOF generation.
 * @param  [in]   transposed  Whether A or A^T is generated.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails. Only possible when
 * WOLFSSL_SMALL_STACK is defined.
 */
static int kyber_gen_matrix_k2_avx2(sword16* a, byte* seed, int transposed)
{
    int i;
    byte rand[4 * GEN_MATRIX_SIZE + 2];
    word64 state[25 * 4];
    unsigned int ctr0;
    unsigned int ctr1;
    unsigned int ctr2;
    unsigned int ctr3;
    byte* p;

    /* Loading 64 bits, only using 48 bits. Loading 2 bytes more than used. */
    rand[4 * GEN_MATRIX_SIZE + 0] = 0xff;
    rand[4 * GEN_MATRIX_SIZE + 1] = 0xff;

    if (!transposed) {
        state[4*4 + 0] = 0x1f0000 + 0x000;
        state[4*4 + 1] = 0x1f0000 + 0x001;
        state[4*4 + 2] = 0x1f0000 + 0x100;
        state[4*4 + 3] = 0x1f0000 + 0x101;
    }
    else {
        state[4*4 + 0] = 0x1f0000 + 0x000;
        state[4*4 + 1] = 0x1f0000 + 0x100;
        state[4*4 + 2] = 0x1f0000 + 0x001;
        state[4*4 + 3] = 0x1f0000 + 0x101;
    }

    kyber_sha3_128_blocksx4_seed_avx2(state, seed);
    kyber_redistribute_21_rand_avx2(state, rand + 0 * GEN_MATRIX_SIZE,
        rand + 1 * GEN_MATRIX_SIZE, rand + 2 * GEN_MATRIX_SIZE,
        rand + 3 * GEN_MATRIX_SIZE);
    for (i = SHA3_128_BYTES; i < GEN_MATRIX_SIZE; i += SHA3_128_BYTES) {
        kyber_sha3_blocksx4_avx2(state);
        kyber_redistribute_21_rand_avx2(state, rand + i + 0 * GEN_MATRIX_SIZE,
            rand + i + 1 * GEN_MATRIX_SIZE, rand + i + 2 * GEN_MATRIX_SIZE,
            rand + i + 3 * GEN_MATRIX_SIZE);
    }

    /* Sample random bytes to create a polynomial. */
    p = rand;
    ctr0 = kyber_rej_uniform_n_avx2(a + 0 * KYBER_N, KYBER_N, p,
        GEN_MATRIX_SIZE);
    p += GEN_MATRIX_SIZE;
    ctr1 = kyber_rej_uniform_n_avx2(a + 1 * KYBER_N, KYBER_N, p,
        GEN_MATRIX_SIZE);
    p += GEN_MATRIX_SIZE;
    ctr2 = kyber_rej_uniform_n_avx2(a + 2 * KYBER_N, KYBER_N, p,
        GEN_MATRIX_SIZE);
    p += GEN_MATRIX_SIZE;
    ctr3 = kyber_rej_uniform_n_avx2(a + 3 * KYBER_N, KYBER_N, p,
        GEN_MATRIX_SIZE);
    /* Create more blocks if too many rejected. */
    while ((ctr0 < KYBER_N) || (ctr1 < KYBER_N) || (ctr2 < KYBER_N) ||
           (ctr3 < KYBER_N)) {
        kyber_sha3_blocksx4_avx2(state);
        kyber_redistribute_21_rand_avx2(state, rand + 0 * GEN_MATRIX_SIZE,
            rand + 1 * GEN_MATRIX_SIZE, rand + 2 * GEN_MATRIX_SIZE,
            rand + 3 * GEN_MATRIX_SIZE);

        p = rand;
        ctr0 += kyber_rej_uniform_avx2(a + 0 * KYBER_N + ctr0, KYBER_N - ctr0,
            p, XOF_BLOCK_SIZE);
        p += GEN_MATRIX_SIZE;
        ctr1 += kyber_rej_uniform_avx2(a + 1 * KYBER_N + ctr1, KYBER_N - ctr1,
            p, XOF_BLOCK_SIZE);
        p += GEN_MATRIX_SIZE;
        ctr2 += kyber_rej_uniform_avx2(a + 2 * KYBER_N + ctr2, KYBER_N - ctr2,
            p, XOF_BLOCK_SIZE);
        p += GEN_MATRIX_SIZE;
        ctr3 += kyber_rej_uniform_avx2(a + 3 * KYBER_N + ctr3, KYBER_N - ctr3,
            p, XOF_BLOCK_SIZE);
    }

    return 0;
}
#endif

#if defined(WOLFSSL_KYBER768) || defined(WOLFSSL_WC_ML_KEM_768)
/* Deterministically generate a matrix (or transpose) of uniform integers mod q.
 *
 * Seed used with XOF to generate random bytes.
 *
 * @param  [out]  a           Matrix of uniform integers.
 * @param  [in]   seed        Bytes to seed XOF generation.
 * @param  [in]   transposed  Whether A or A^T is generated.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails. Only possible when
 * WOLFSSL_SMALL_STACK is defined.
 */
static int kyber_gen_matrix_k3_avx2(sword16* a, byte* seed, int transposed)
{
    int i;
    int k;
    byte rand[4 * GEN_MATRIX_SIZE + 2];
    word64 state[25 * 4];
    unsigned int ctr0;
    unsigned int ctr1;
    unsigned int ctr2;
    unsigned int ctr3;
    byte* p;

    /* Loading 64 bits, only using 48 bits. Loading 2 bytes more than used. */
    rand[4 * GEN_MATRIX_SIZE + 0] = 0xff;
    rand[4 * GEN_MATRIX_SIZE + 1] = 0xff;

    for (k = 0; k < 2; k++) {
        for (i = 0; i < 4; i++) {
            if (!transposed) {
                state[4*4 + i] = 0x1f0000 + (((k*4+i)/3) << 8) + ((k*4+i)%3);
            }
            else {
                state[4*4 + i] = 0x1f0000 + (((k*4+i)%3) << 8) + ((k*4+i)/3);
            }
        }

        kyber_sha3_128_blocksx4_seed_avx2(state, seed);
        kyber_redistribute_21_rand_avx2(state,
            rand + 0 * GEN_MATRIX_SIZE, rand + 1 * GEN_MATRIX_SIZE,
            rand + 2 * GEN_MATRIX_SIZE, rand + 3 * GEN_MATRIX_SIZE);
        for (i = SHA3_128_BYTES; i < GEN_MATRIX_SIZE; i += SHA3_128_BYTES) {
            kyber_sha3_blocksx4_avx2(state);
            kyber_redistribute_21_rand_avx2(state,
                rand + i + 0 * GEN_MATRIX_SIZE, rand + i + 1 * GEN_MATRIX_SIZE,
                rand + i + 2 * GEN_MATRIX_SIZE, rand + i + 3 * GEN_MATRIX_SIZE);
        }

        /* Sample random bytes to create a polynomial. */
        p = rand;
        ctr0 = kyber_rej_uniform_n_avx2(a + 0 * KYBER_N, KYBER_N, p,
            GEN_MATRIX_SIZE);
        p += GEN_MATRIX_SIZE;
        ctr1 = kyber_rej_uniform_n_avx2(a + 1 * KYBER_N, KYBER_N, p,
            GEN_MATRIX_SIZE);
        p += GEN_MATRIX_SIZE;
        ctr2 = kyber_rej_uniform_n_avx2(a + 2 * KYBER_N, KYBER_N, p,
            GEN_MATRIX_SIZE);
        p += GEN_MATRIX_SIZE;
        ctr3 = kyber_rej_uniform_n_avx2(a + 3 * KYBER_N, KYBER_N, p,
            GEN_MATRIX_SIZE);
        /* Create more blocks if too many rejected. */
        while ((ctr0 < KYBER_N) || (ctr1 < KYBER_N) || (ctr2 < KYBER_N) ||
               (ctr3 < KYBER_N)) {
            kyber_sha3_blocksx4_avx2(state);
            kyber_redistribute_21_rand_avx2(state, rand + 0 * GEN_MATRIX_SIZE,
                rand + 1 * GEN_MATRIX_SIZE, rand + 2 * GEN_MATRIX_SIZE,
                rand + 3 * GEN_MATRIX_SIZE);

            p = rand;
            ctr0 += kyber_rej_uniform_avx2(a + 0 * KYBER_N + ctr0,
                KYBER_N - ctr0, p, XOF_BLOCK_SIZE);
            p += GEN_MATRIX_SIZE;
            ctr1 += kyber_rej_uniform_avx2(a + 1 * KYBER_N + ctr1,
                KYBER_N - ctr1, p, XOF_BLOCK_SIZE);
            p += GEN_MATRIX_SIZE;
            ctr2 += kyber_rej_uniform_avx2(a + 2 * KYBER_N + ctr2,
                KYBER_N - ctr2, p, XOF_BLOCK_SIZE);
            p += GEN_MATRIX_SIZE;
            ctr3 += kyber_rej_uniform_avx2(a + 3 * KYBER_N + ctr3,
                KYBER_N - ctr3, p, XOF_BLOCK_SIZE);
        }

        a += 4 * KYBER_N;
    }

    readUnalignedWords64(state, seed, 4);
    /* Transposed value same as not. */
    state[4] = 0x1f0000 + (2 << 8) + 2;
    XMEMSET(state + 5, 0, sizeof(*state) * (25 - 5));
    state[20] = W64LIT(0x8000000000000000);
    for (i = 0; i < GEN_MATRIX_SIZE; i += SHA3_128_BYTES) {
        if (IS_INTEL_BMI2(cpuid_flags)) {
            sha3_block_bmi2(state);
        }
        else if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
            sha3_block_avx2(state);
            RESTORE_VECTOR_REGISTERS();
        }
        else {
            BlockSha3(state);
        }
        XMEMCPY(rand + i, state, SHA3_128_BYTES);
    }
    ctr0 = kyber_rej_uniform_n_avx2(a, KYBER_N, rand, GEN_MATRIX_SIZE);
    while (ctr0 < KYBER_N) {
        if (IS_INTEL_BMI2(cpuid_flags)) {
            sha3_block_bmi2(state);
        }
        else if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
            sha3_block_avx2(state);
            RESTORE_VECTOR_REGISTERS();
        }
        else {
            BlockSha3(state);
        }
        XMEMCPY(rand, state, SHA3_128_BYTES);
        ctr0 += kyber_rej_uniform_avx2(a + ctr0, KYBER_N - ctr0, rand,
            XOF_BLOCK_SIZE);
    }

    return 0;
}
#endif
#if defined(WOLFSSL_KYBER1024) || defined(WOLFSSL_WC_ML_KEM_1024)
/* Deterministically generate a matrix (or transpose) of uniform integers mod q.
 *
 * Seed used with XOF to generate random bytes.
 *
 * @param  [out]  a           Matrix of uniform integers.
 * @param  [in]   seed        Bytes to seed XOF generation.
 * @param  [in]   transposed  Whether A or A^T is generated.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails. Only possible when
 * WOLFSSL_SMALL_STACK is defined.
 */
static int kyber_gen_matrix_k4_avx2(sword16* a, byte* seed, int transposed)
{
    int i;
    int k;
    byte rand[4 * GEN_MATRIX_SIZE + 2];
    word64 state[25 * 4];
    unsigned int ctr0;
    unsigned int ctr1;
    unsigned int ctr2;
    unsigned int ctr3;
    byte* p;

    /* Loading 64 bits, only using 48 bits. Loading 2 bytes more than used. */
    rand[4 * GEN_MATRIX_SIZE + 0] = 0xff;
    rand[4 * GEN_MATRIX_SIZE + 1] = 0xff;

    for (k = 0; k < 4; k++) {
        for (i = 0; i < 4; i++) {
            if (!transposed) {
                state[4*4 + i] = 0x1f0000 + (k << 8) + i;
            }
            else {
                state[4*4 + i] = 0x1f0000 + (i << 8) + k;
            }
        }

        kyber_sha3_128_blocksx4_seed_avx2(state, seed);
        kyber_redistribute_21_rand_avx2(state,
            rand + 0 * GEN_MATRIX_SIZE, rand + 1 * GEN_MATRIX_SIZE,
            rand + 2 * GEN_MATRIX_SIZE, rand + 3 * GEN_MATRIX_SIZE);
        for (i = SHA3_128_BYTES; i < GEN_MATRIX_SIZE; i += SHA3_128_BYTES) {
            kyber_sha3_blocksx4_avx2(state);
            kyber_redistribute_21_rand_avx2(state,
                rand + i + 0 * GEN_MATRIX_SIZE, rand + i + 1 * GEN_MATRIX_SIZE,
                rand + i + 2 * GEN_MATRIX_SIZE, rand + i + 3 * GEN_MATRIX_SIZE);
        }

        /* Sample random bytes to create a polynomial. */
        p = rand;
        ctr0 = kyber_rej_uniform_n_avx2(a + 0 * KYBER_N, KYBER_N, p,
            GEN_MATRIX_SIZE);
        p += GEN_MATRIX_SIZE;
        ctr1 = kyber_rej_uniform_n_avx2(a + 1 * KYBER_N, KYBER_N, p,
            GEN_MATRIX_SIZE);
        p += GEN_MATRIX_SIZE;
        ctr2 = kyber_rej_uniform_n_avx2(a + 2 * KYBER_N, KYBER_N, p,
            GEN_MATRIX_SIZE);
        p += GEN_MATRIX_SIZE;
        ctr3 = kyber_rej_uniform_n_avx2(a + 3 * KYBER_N, KYBER_N, p,
            GEN_MATRIX_SIZE);
        /* Create more blocks if too many rejected. */
        while ((ctr0 < KYBER_N) || (ctr1 < KYBER_N) || (ctr2 < KYBER_N) ||
               (ctr3 < KYBER_N)) {
            kyber_sha3_blocksx4_avx2(state);
            kyber_redistribute_21_rand_avx2(state, rand + 0 * GEN_MATRIX_SIZE,
                rand + 1 * GEN_MATRIX_SIZE, rand + 2 * GEN_MATRIX_SIZE,
                rand + 3 * GEN_MATRIX_SIZE);

            p = rand;
            ctr0 += kyber_rej_uniform_avx2(a + 0 * KYBER_N + ctr0,
                KYBER_N - ctr0, p, XOF_BLOCK_SIZE);
            p += GEN_MATRIX_SIZE;
            ctr1 += kyber_rej_uniform_avx2(a + 1 * KYBER_N + ctr1,
                KYBER_N - ctr1, p, XOF_BLOCK_SIZE);
            p += GEN_MATRIX_SIZE;
            ctr2 += kyber_rej_uniform_avx2(a + 2 * KYBER_N + ctr2,
                KYBER_N - ctr2, p, XOF_BLOCK_SIZE);
            p += GEN_MATRIX_SIZE;
            ctr3 += kyber_rej_uniform_avx2(a + 3 * KYBER_N + ctr3,
                KYBER_N - ctr3, p, XOF_BLOCK_SIZE);
        }

        a += 4 * KYBER_N;
    }

    return 0;
}
#endif /* WOLFSSL_KYBER1024 || WOLFSSL_WC_ML_KEM_1024 */
#elif defined(WOLFSSL_ARMASM) && defined(__aarch64__)
#if defined(WOLFSSL_KYBER512) || defined(WOLFSSL_WC_ML_KEM_512)
/* Deterministically generate a matrix (or transpose) of uniform integers mod q.
 *
 * Seed used with XOF to generate random bytes.
 *
 * @param  [out]  a           Matrix of uniform integers.
 * @param  [in]   seed        Bytes to seed XOF generation.
 * @param  [in]   transposed  Whether A or A^T is generated.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails. Only possible when
 * WOLFSSL_SMALL_STACK is defined.
 */
static int kyber_gen_matrix_k2_aarch64(sword16* a, byte* seed, int transposed)
{
    word64 state[3 * 25];
    word64* st = (word64*)state;
    unsigned int ctr0;
    unsigned int ctr1;
    unsigned int ctr2;
    byte* p;

    if (!transposed) {
        state[0*25 + 4] = 0x1f0000 + (0 << 8) + 0;
        state[1*25 + 4] = 0x1f0000 + (0 << 8) + 1;
        state[2*25 + 4] = 0x1f0000 + (1 << 8) + 0;
    }
    else {
        state[0*25 + 4] = 0x1f0000 + (0 << 8) + 0;
        state[1*25 + 4] = 0x1f0000 + (1 << 8) + 0;
        state[2*25 + 4] = 0x1f0000 + (0 << 8) + 1;
    }

    kyber_shake128_blocksx3_seed_neon(state, seed);
    /* Sample random bytes to create a polynomial. */
    p = (byte*)st;
    ctr0 = kyber_rej_uniform_neon(a + 0 * KYBER_N, KYBER_N, p, XOF_BLOCK_SIZE);
    p += 25 * 8;
    ctr1 = kyber_rej_uniform_neon(a + 1 * KYBER_N, KYBER_N, p, XOF_BLOCK_SIZE);
    p += 25 * 8;
    ctr2 = kyber_rej_uniform_neon(a + 2 * KYBER_N, KYBER_N, p, XOF_BLOCK_SIZE);
    while ((ctr0 < KYBER_N) || (ctr1 < KYBER_N) || (ctr2 < KYBER_N)) {
        kyber_sha3_blocksx3_neon(st);

        p = (byte*)st;
        ctr0 += kyber_rej_uniform_neon(a + 0 * KYBER_N + ctr0, KYBER_N - ctr0,
            p, XOF_BLOCK_SIZE);
        p += 25 * 8;
        ctr1 += kyber_rej_uniform_neon(a + 1 * KYBER_N + ctr1, KYBER_N - ctr1,
            p, XOF_BLOCK_SIZE);
        p += 25 * 8;
        ctr2 += kyber_rej_uniform_neon(a + 2 * KYBER_N + ctr2, KYBER_N - ctr2,
            p, XOF_BLOCK_SIZE);
    }

    a += 3 * KYBER_N;

    readUnalignedWords64(state, seed, 4);
    /* Transposed value same as not. */
    state[4] = 0x1f0000 + (1 << 8) + 1;
    XMEMSET(state + 5, 0, sizeof(*state) * (25 - 5));
    state[20] = W64LIT(0x8000000000000000);
    BlockSha3(state);
    p = (byte*)state;
    ctr0 = kyber_rej_uniform_neon(a, KYBER_N, p, XOF_BLOCK_SIZE);
    while (ctr0 < KYBER_N) {
        BlockSha3(state);
        ctr0 += kyber_rej_uniform_neon(a + ctr0, KYBER_N - ctr0, p,
            XOF_BLOCK_SIZE);
    }

    return 0;
}
#endif

#if defined(WOLFSSL_KYBER768) || defined(WOLFSSL_WC_ML_KEM_768)
/* Deterministically generate a matrix (or transpose) of uniform integers mod q.
 *
 * Seed used with XOF to generate random bytes.
 *
 * @param  [out]  a           Matrix of uniform integers.
 * @param  [in]   seed        Bytes to seed XOF generation.
 * @param  [in]   transposed  Whether A or A^T is generated.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails. Only possible when
 * WOLFSSL_SMALL_STACK is defined.
 */
static int kyber_gen_matrix_k3_aarch64(sword16* a, byte* seed, int transposed)
{
    int i;
    int k;
    word64 state[3 * 25];
    word64* st = (word64*)state;
    unsigned int ctr0;
    unsigned int ctr1;
    unsigned int ctr2;
    byte* p;

    for (k = 0; k < 3; k++) {
        for (i = 0; i < 3; i++) {
            if (!transposed) {
                state[i*25 + 4] = 0x1f0000 + ((k << 8) + i);
            }
            else {
                state[i*25 + 4] = 0x1f0000 + ((i << 8) + k);
            }
        }

        kyber_shake128_blocksx3_seed_neon(state, seed);
        /* Sample random bytes to create a polynomial. */
        p = (byte*)st;
        ctr0 = kyber_rej_uniform_neon(a + 0 * KYBER_N, KYBER_N, p,
            XOF_BLOCK_SIZE);
        p += 25 * 8;
        ctr1 = kyber_rej_uniform_neon(a + 1 * KYBER_N, KYBER_N, p,
            XOF_BLOCK_SIZE);
        p +=25 * 8;
        ctr2 = kyber_rej_uniform_neon(a + 2 * KYBER_N, KYBER_N, p,
            XOF_BLOCK_SIZE);
        /* Create more blocks if too many rejected. */
        while ((ctr0 < KYBER_N) || (ctr1 < KYBER_N) || (ctr2 < KYBER_N)) {
            kyber_sha3_blocksx3_neon(st);

            p = (byte*)st;
            ctr0 += kyber_rej_uniform_neon(a + 0 * KYBER_N + ctr0,
                KYBER_N - ctr0, p, XOF_BLOCK_SIZE);
            p += 25 * 8;
            ctr1 += kyber_rej_uniform_neon(a + 1 * KYBER_N + ctr1,
                KYBER_N - ctr1, p, XOF_BLOCK_SIZE);
            p += 25 * 8;
            ctr2 += kyber_rej_uniform_neon(a + 2 * KYBER_N + ctr2,
                KYBER_N - ctr2, p, XOF_BLOCK_SIZE);
        }

        a += 3 * KYBER_N;
    }

    return 0;
}
#endif

#if defined(WOLFSSL_KYBER1024) || defined(WOLFSSL_WC_ML_KEM_1024)
/* Deterministically generate a matrix (or transpose) of uniform integers mod q.
 *
 * Seed used with XOF to generate random bytes.
 *
 * @param  [out]  a           Matrix of uniform integers.
 * @param  [in]   seed        Bytes to seed XOF generation.
 * @param  [in]   transposed  Whether A or A^T is generated.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails. Only possible when
 * WOLFSSL_SMALL_STACK is defined.
 */
static int kyber_gen_matrix_k4_aarch64(sword16* a, byte* seed, int transposed)
{
    int i;
    int k;
    word64 state[3 * 25];
    word64* st = (word64*)state;
    unsigned int ctr0;
    unsigned int ctr1;
    unsigned int ctr2;
    byte* p;

    for (k = 0; k < 5; k++) {
        for (i = 0; i < 3; i++) {
            byte bi = ((k * 3) + i) / 4;
            byte bj = ((k * 3) + i) % 4;
            if (!transposed) {
                state[i*25 + 4] = 0x1f0000 + (bi << 8) + bj;
            }
            else {
                state[i*25 + 4] = 0x1f0000 + (bj << 8) + bi;
            }
        }

        kyber_shake128_blocksx3_seed_neon(state, seed);
        /* Sample random bytes to create a polynomial. */
        p = (byte*)st;
        ctr0 = kyber_rej_uniform_neon(a + 0 * KYBER_N, KYBER_N, p,
            XOF_BLOCK_SIZE);
        p += 25 * 8;
        ctr1 = kyber_rej_uniform_neon(a + 1 * KYBER_N, KYBER_N, p,
            XOF_BLOCK_SIZE);
        p += 25 * 8;
        ctr2 = kyber_rej_uniform_neon(a + 2 * KYBER_N, KYBER_N, p,
            XOF_BLOCK_SIZE);
        /* Create more blocks if too many rejected. */
        while ((ctr0 < KYBER_N) || (ctr1 < KYBER_N) || (ctr2 < KYBER_N)) {
            kyber_sha3_blocksx3_neon(st);

            p = (byte*)st;
            ctr0 += kyber_rej_uniform_neon(a + 0 * KYBER_N + ctr0,
                KYBER_N - ctr0, p, XOF_BLOCK_SIZE);
            p += 25 * 8;
            ctr1 += kyber_rej_uniform_neon(a + 1 * KYBER_N + ctr1,
                KYBER_N - ctr1, p, XOF_BLOCK_SIZE);
            p += 25 * 8;
            ctr2 += kyber_rej_uniform_neon(a + 2 * KYBER_N + ctr2,
                KYBER_N - ctr2, p, XOF_BLOCK_SIZE);
        }

        a += 3 * KYBER_N;
    }

    readUnalignedWords64(state, seed, 4);
    /* Transposed value same as not. */
    state[4] = 0x1f0000 + (3 << 8) + 3;
    XMEMSET(state + 5, 0, sizeof(*state) * (25 - 5));
    state[20] = W64LIT(0x8000000000000000);
    BlockSha3(state);
    p = (byte*)state;
    ctr0 = kyber_rej_uniform_neon(a, KYBER_N, p, XOF_BLOCK_SIZE);
    while (ctr0 < KYBER_N) {
        BlockSha3(state);
        ctr0 += kyber_rej_uniform_neon(a + ctr0, KYBER_N - ctr0, p,
            XOF_BLOCK_SIZE);
    }

    return 0;
}
#endif
#endif /* USE_INTEL_SPEEDUP */

#if !(defined(WOLFSSL_ARMASM) && defined(__aarch64__))
/* Absorb the seed data for squeezing out pseudo-random data.
 *
 * @param  [in, out]  shake128  SHAKE-128 object.
 * @param  [in]       seed      Data to absorb.
 * @param  [in]       len       Length of data to absorb in bytes.
 * @return  0 on success always.
 */
static int kyber_xof_absorb(wc_Shake* shake128, byte* seed, int len)
{
    int ret;

    ret = wc_InitShake128(shake128, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_Shake128_Absorb(shake128, seed, len);
    }

    return ret;
}

/* Squeeze the state to produce pseudo-random data.
 *
 * @param  [in, out]  shake128  SHAKE-128 object.
 * @param  [out]      out       Buffer to write to.
 * @param  [in]       blocks    Number of blocks to write.
 * @return  0 on success always.
 */
static int kyber_xof_squeezeblocks(wc_Shake* shake128, byte* out, int blocks)
{
    return wc_Shake128_SqueezeBlocks(shake128, out, blocks);
}
#endif

/* New/Initialize SHA-3 object.
 *
 * @param  [in, out]  hash    SHA-3 object.
 * @param  [in]       heap    Dynamic memory allocator hint.
 * @param  [in]       devId   Device id.
 * @return  0 on success always.
 */
int kyber_hash_new(wc_Sha3* hash, void* heap, int devId)
{
    return wc_InitSha3_256(hash, heap, devId);
}

/* Free SHA-3 object.
 *
 * @param  [in, out]  hash  SHA-3 object.
 */
void kyber_hash_free(wc_Sha3* hash)
{
    wc_Sha3_256_Free(hash);
}

int kyber_hash256(wc_Sha3* hash, const byte* data, word32 dataLen, byte* out)
{
    int ret;

    ret = wc_Sha3_256_Update(hash, data, dataLen);
    if (ret == 0) {
        ret = wc_Sha3_256_Final(hash, out);
    }

    return ret;
}

int kyber_hash512(wc_Sha3* hash, const byte* data1, word32 data1Len,
    const byte* data2, word32 data2Len, byte* out)
{
    int ret;

    ret = wc_Sha3_512_Update(hash, data1, data1Len);
    if ((ret == 0) && (data2Len > 0)) {
        ret = wc_Sha3_512_Update(hash, data2, data2Len);
    }
    if (ret == 0) {
        ret = wc_Sha3_512_Final(hash, out);
    }

    return ret;
}

/* Initialize SHAKE-256 object.
 *
 * @param  [in, out]  shake256  SHAKE-256 object.
 */
void kyber_prf_init(wc_Shake* prf)
{
    XMEMSET(prf->s, 0, sizeof(prf->s));
}

/* New/Initialize SHAKE-256 object.
 *
 * @param  [in, out]  shake256  SHAKE-256 object.
 * @param  [in]       heap      Dynamic memory allocator hint.
 * @param  [in]       devId     Device id.
 * @return  0 on success always.
 */
int kyber_prf_new(wc_Shake* prf, void* heap, int devId)
{
    return wc_InitShake256(prf, heap, devId);
}

/* Free SHAKE-256 object.
 *
 * @param  [in, out]  shake256  SHAKE-256 object.
 */
void kyber_prf_free(wc_Shake* prf)
{
    wc_Shake256_Free(prf);
}

#if !(defined(WOLFSSL_ARMASM) && defined(__aarch64__))
/* Create pseudo-random data from the key using SHAKE-256.
 *
 * @param  [in, out]  shake256  SHAKE-256 object.
 * @param  [out]      out       Buffer to write to.
 * @param  [in]       outLen    Number of bytes to write.
 * @param  [in]       key       Data to derive from. Must be KYBER_SYM_SZ + 1
 *                              bytes in length.
 * @return  0 on success always.
 */
static int kyber_prf(wc_Shake* shake256, byte* out, unsigned int outLen,
    const byte* key)
{
#ifdef USE_INTEL_SPEEDUP
    word64 state[25];

    (void)shake256;

    readUnalignedWords64(state, key, KYBER_SYM_SZ / sizeof(word64));
    state[KYBER_SYM_SZ / 8] = 0x1f00 | key[KYBER_SYM_SZ];
    XMEMSET(state + KYBER_SYM_SZ / 8 + 1, 0,
        (25 - KYBER_SYM_SZ / 8 - 1) * sizeof(word64));
    state[WC_SHA3_256_COUNT - 1] = W64LIT(0x8000000000000000);

    while (outLen > 0) {
        unsigned int len = min(outLen, WC_SHA3_256_BLOCK_SIZE);

        if (IS_INTEL_BMI2(cpuid_flags)) {
            sha3_block_bmi2(state);
        }
        else if (IS_INTEL_AVX2(cpuid_flags) &&
                 (SAVE_VECTOR_REGISTERS2() == 0)) {
            sha3_block_avx2(state);
            RESTORE_VECTOR_REGISTERS();
        }
        else {
            BlockSha3(state);
        }
        XMEMCPY(out, state, len);
        out += len;
        outLen -= len;
    }

    return 0;
#else
    int ret;

    ret = wc_Shake256_Update(shake256, key, KYBER_SYM_SZ + 1);
    if (ret == 0) {
        ret = wc_Shake256_Final(shake256, out, outLen);
    }

    return ret;
#endif
}
#endif

#ifdef USE_INTEL_SPEEDUP
/* Create pseudo-random key from the seed using SHAKE-256.
 *
 * @param  [in]  seed      Data to derive from.
 * @param  [in]  seedLen   Length of data to derive from in bytes.
 * @param  [out] out       Buffer to write to.
 * @param  [in]  outLen    Number of bytes to derive.
 * @return  0 on success always.
 */
int kyber_kdf(byte* seed, int seedLen, byte* out, int outLen)
{
    word64 state[25];
    word32 len64 = seedLen / 8;

    readUnalignedWords64(state, seed, len64);
    state[len64] = 0x1f;
    XMEMSET(state + len64 + 1, 0, (25 - len64 - 1) * sizeof(word64));
    state[WC_SHA3_256_COUNT - 1] = W64LIT(0x8000000000000000);

    if (IS_INTEL_BMI2(cpuid_flags)) {
        sha3_block_bmi2(state);
    }
    else if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        sha3_block_avx2(state);
        RESTORE_VECTOR_REGISTERS();
    }
    else {
        BlockSha3(state);
    }
    XMEMCPY(out, state, outLen);

    return 0;
}
#endif

#if defined(WOLFSSL_ARMASM) && defined(__aarch64__)
/* Create pseudo-random key from the seed using SHAKE-256.
 *
 * @param  [in]  seed      Data to derive from.
 * @param  [in]  seedLen   Length of data to derive from in bytes.
 * @param  [out] out       Buffer to write to.
 * @param  [in]  outLen    Number of bytes to derive.
 * @return  0 on success always.
 */
int kyber_kdf(byte* seed, int seedLen, byte* out, int outLen)
{
    word64 state[25];
    word32 len64 = seedLen / 8;

    readUnalignedWords64(state, seed, len64);
    state[len64] = 0x1f;
    XMEMSET(state + len64 + 1, 0, (25 - len64 - 1) * sizeof(word64));
    state[WC_SHA3_256_COUNT - 1] = W64LIT(0x8000000000000000);

    BlockSha3(state);
    XMEMCPY(out, state, outLen);

    return 0;
}
#endif

#if !defined(WOLFSSL_ARMASM)
/* Rejection sampling on uniform random bytes to generate uniform random
 * integers mod q.
 *
 * @param  [out]  p     Uniform random integers mod q.
 * @param  [in]   len   Maximum number of integers.
 * @param  [in]   r     Uniform random bytes buffer.
 * @param  [in]   rLen  Length of random data in buffer.
 * @return  Number of integers sampled.
 */
static unsigned int kyber_rej_uniform_c(sword16* p, unsigned int len,
    const byte* r, unsigned int rLen)
{
    unsigned int i;
    unsigned int j;

#if defined(WOLFSSL_KYBER_SMALL) || !defined(WC_64BIT_CPU)
    /* Keep sampling until maximum number of integers reached or buffer used up.
     */
    for (i = 0, j = 0; (i < len) && (j <= rLen - 3); j += 3) {
        /* Use 24 bits (3 bytes) as two 12 bits integers. */
        sword16 v0 = ((r[0] >> 0) | ((word16)r[1] << 8)) & 0xFFF;
        sword16 v1 = ((r[1] >> 4) | ((word16)r[2] << 4)) & 0xFFF;

        /* Reject first 12-bit integer if greater than or equal to q. */
        if (v0 < KYBER_Q) {
            p[i++] = v0;
        }
        /* Check second if we don't have enough integers yet.
         * Reject second 12-bit integer if greater than or equal to q. */
        if ((i < len) && (v1 < KYBER_Q)) {
            p[i++] = v1;
        }

        /* Move over used bytes. */
        r += 3;
    }
#else
    unsigned int minJ;

    minJ = len / 4 * 6;
    if (minJ > rLen)
        minJ = rLen;
    i = 0;
    for (j = 0; j < minJ; j += 6) {
        /* Use 48 bits (6 bytes) as four 12-bit integers. */
        word64 r_word = readUnalignedWord64(r);
        sword16 v0 =  r_word        & 0xfff;
        sword16 v1 = (r_word >> 12) & 0xfff;
        sword16 v2 = (r_word >> 24) & 0xfff;
        sword16 v3 = (r_word >> 36) & 0xfff;

        p[i] = v0 & (0 - (v0 < KYBER_Q));
        i += v0 < KYBER_Q;
        p[i] = v1 & (0 - (v1 < KYBER_Q));
        i += v1 < KYBER_Q;
        p[i] = v2 & (0 - (v2 < KYBER_Q));
        i += v2 < KYBER_Q;
        p[i] = v3 & (0 - (v3 < KYBER_Q));
        i += v3 < KYBER_Q;

        /* Move over used bytes. */
        r += 6;
    }
    if (j < rLen) {
        for (; (i + 4 < len) && (j < rLen); j += 6) {
            /* Use 48 bits (6 bytes) as four 12-bit integers. */
            word64 r_word = readUnalignedWord64(r);
            sword16 v0 =  r_word        & 0xfff;
            sword16 v1 = (r_word >> 12) & 0xfff;
            sword16 v2 = (r_word >> 24) & 0xfff;
            sword16 v3 = (r_word >> 36) & 0xfff;

            p[i] = v0;
            i += v0 < KYBER_Q;
            p[i] = v1;
            i += v1 < KYBER_Q;
            p[i] = v2;
            i += v2 < KYBER_Q;
            p[i] = v3;
            i += v3 < KYBER_Q;

            /* Move over used bytes. */
            r += 6;
        }
        for (; (i < len) && (j < rLen); j += 6) {
            /* Use 48 bits (6 bytes) as four 12-bit integers. */
            word64 r_word = readUnalignedWord64(r);
            sword16 v0 =  r_word        & 0xfff;
            sword16 v1 = (r_word >> 12) & 0xfff;
            sword16 v2 = (r_word >> 24) & 0xfff;
            sword16 v3 = (r_word >> 36) & 0xfff;

            /* Reject first 12-bit integer if greater than or equal to q. */
            if (v0 < KYBER_Q) {
                p[i++] = v0;
            }
            /* Check second if we don't have enough integers yet.
             * Reject second 12-bit integer if greater than or equal to q. */
            if ((i < len) && (v1 < KYBER_Q)) {
                p[i++] = v1;
            }
            /* Check second if we don't have enough integers yet.
             * Reject third 12-bit integer if greater than or equal to q. */
            if ((i < len) && (v2 < KYBER_Q)) {
                p[i++] = v2;
            }
            /* Check second if we don't have enough integers yet.
             * Reject fourth 12-bit integer if greater than or equal to q. */
            if ((i < len) && (v3 < KYBER_Q)) {
                p[i++] = v3;
            }

            /* Move over used bytes. */
            r += 6;
        }
    }
#endif

    return i;
}
#endif

#if !(defined(WOLFSSL_ARMASM) && defined(__aarch64__))
/* Deterministically generate a matrix (or transpose) of uniform integers mod q.
 *
 * Seed used with XOF to generate random bytes.
 *
 * @param  [in]   prf         XOF object.
 * @param  [out]  a           Matrix of uniform integers.
 * @param  [in]   kp          Number of dimensions. kp x kp polynomials.
 * @param  [in]   seed        Bytes to seed XOF generation.
 * @param  [in]   transposed  Whether A or A^T is generated.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails. Only possible when
 * WOLFSSL_SMALL_STACK is defined.
 */
static int kyber_gen_matrix_c(KYBER_PRF_T* prf, sword16* a, int kp, byte* seed,
    int transposed)
{
#ifdef WOLFSSL_SMALL_STACK
    byte* rand;
#else
    byte rand[GEN_MATRIX_SIZE + 2];
#endif
    byte extSeed[KYBER_SYM_SZ + 2];
    int ret = 0;
    int i;

    XMEMCPY(extSeed, seed, KYBER_SYM_SZ);

#ifdef WOLFSSL_SMALL_STACK
    /* Allocate large amount of memory to hold random bytes to be samples. */
    rand = (byte*)XMALLOC(GEN_MATRIX_SIZE + 2, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (rand == NULL) {
        ret = MEMORY_E;
    }
#endif

#if !defined(WOLFSSL_KYBER_SMALL) && defined(WC_64BIT_CPU)
    /* Loading 64 bits, only using 48 bits. Loading 2 bytes more than used. */
    rand[GEN_MATRIX_SIZE+0] = 0xff;
    rand[GEN_MATRIX_SIZE+1] = 0xff;
#endif

    /* Generate each vector of polynomials. */
    for (i = 0; (ret == 0) && (i < kp); i++, a += kp * KYBER_N) {
        int j;
        /* Generate each polynomial in vector from seed with indices. */
        for (j = 0; (ret == 0) && (j < kp); j++) {
            if (transposed) {
                extSeed[KYBER_SYM_SZ + 0] = i;
                extSeed[KYBER_SYM_SZ + 1] = j;
            }
            else {
                extSeed[KYBER_SYM_SZ + 0] = j;
                extSeed[KYBER_SYM_SZ + 1] = i;
            }
            /* Absorb the index specific seed. */
            ret = kyber_xof_absorb(prf, extSeed, sizeof(extSeed));
            if (ret == 0) {
                /* Create out based on the seed. */
                ret = kyber_xof_squeezeblocks(prf, rand, GEN_MATRIX_NBLOCKS);
            }
            if (ret == 0) {
                unsigned int ctr;

                /* Sample random bytes to create a polynomial. */
                ctr = kyber_rej_uniform_c(a + j * KYBER_N, KYBER_N, rand,
                    GEN_MATRIX_SIZE);
                /* Create more blocks if too many rejected. */
                while (ctr < KYBER_N) {
                    kyber_xof_squeezeblocks(prf, rand, 1);
                    ctr += kyber_rej_uniform_c(a + j * KYBER_N + ctr,
                        KYBER_N - ctr, rand, XOF_BLOCK_SIZE);
                }
            }
        }
    }

#ifdef WOLFSSL_SMALL_STACK
    /* Dispose of temporary buffer. */
    XFREE(rand, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}
#endif

/* Deterministically generate a matrix (or transpose) of uniform integers mod q.
 *
 * Seed used with XOF to generate random bytes.
 *
 * @param  [in]   prf         XOF object.
 * @param  [out]  a           Matrix of uniform integers.
 * @param  [in]   kp          Number of dimensions. kp x kp polynomials.
 * @param  [in]   seed        Bytes to seed XOF generation.
 * @param  [in]   transposed  Whether A or A^T is generated.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails. Only possible when
 * WOLFSSL_SMALL_STACK is defined.
 */
int kyber_gen_matrix(KYBER_PRF_T* prf, sword16* a, int kp, byte* seed,
    int transposed)
{
    int ret;

#if defined(WOLFSSL_KYBER512) || defined(WOLFSSL_WC_ML_KEM_512)
    if (kp == KYBER512_K) {
#if defined(WOLFSSL_ARMASM) && defined(__aarch64__)
        ret = kyber_gen_matrix_k2_aarch64(a, seed, transposed);
#else
    #ifdef USE_INTEL_SPEEDUP
        if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
            ret = kyber_gen_matrix_k2_avx2(a, seed, transposed);
            RESTORE_VECTOR_REGISTERS();
        }
        else
    #endif
        {
            ret = kyber_gen_matrix_c(prf, a, KYBER512_K, seed, transposed);
        }
#endif
    }
    else
#endif
#if defined(WOLFSSL_KYBER768) || defined(WOLFSSL_WC_ML_KEM_768)
    if (kp == KYBER768_K) {
#if defined(WOLFSSL_ARMASM) && defined(__aarch64__)
        ret = kyber_gen_matrix_k3_aarch64(a, seed, transposed);
#else
    #ifdef USE_INTEL_SPEEDUP
        if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
            ret = kyber_gen_matrix_k3_avx2(a, seed, transposed);
            RESTORE_VECTOR_REGISTERS();
        }
        else
    #endif
        {
            ret = kyber_gen_matrix_c(prf, a, KYBER768_K, seed, transposed);
        }
#endif
    }
    else
#endif
#if defined(WOLFSSL_KYBER1024) || defined(WOLFSSL_WC_ML_KEM_1024)
    if (kp == KYBER1024_K) {
#if defined(WOLFSSL_ARMASM) && defined(__aarch64__)
        ret = kyber_gen_matrix_k4_aarch64(a, seed, transposed);
#else
    #ifdef USE_INTEL_SPEEDUP
        if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
            ret = kyber_gen_matrix_k4_avx2(a, seed, transposed);
            RESTORE_VECTOR_REGISTERS();
        }
        else
    #endif
        {
            ret = kyber_gen_matrix_c(prf, a, KYBER1024_K, seed, transposed);
        }
#endif
    }
    else
#endif
    {
        ret = BAD_STATE_E;
    }

    (void)prf;

    return ret;
}

/******************************************************************************/

/* Subtract one 2 bit value from another out of a larger number.
 *
 * @param  [in]  d  Value containing sequential 2 bit values.
 * @param  [in]  i  Start index of the two values in 2 bits each.
 * @return  Difference of the two values with range 0..2.
 */
#define ETA2_SUB(d, i) \
    (((sword16)(((d) >> ((i) * 4 + 0)) & 0x3)) - \
     ((sword16)(((d) >> ((i) * 4 + 2)) & 0x3)))

/* Compute polynomial with coefficients distributed according to a centered
 * binomial distribution with parameter eta2 from uniform random bytes.
 *
 * @param [out]  p  Polynomial computed.
 * @param [in]   r  Random bytes.
 */
static void kyber_cbd_eta2(sword16* p, const byte* r)
{
    unsigned int i;

#ifndef WORD64_AVAILABLE
    /* Calculate eight integer coefficients at a time. */
    for (i = 0; i < KYBER_N; i += 8) {
    #ifdef WOLFSSL_KYBER_SMALL
        unsigned int j;
    #endif
        /* Take the next 4 bytes, little endian, as a 32 bit value. */
    #ifdef BIG_ENDIAN_ORDER
        word32 t = ByteReverseWord32(*(word32*)r);
    #else
        word32 t = *(word32*)r;
    #endif
        word32 d;
        /* Add second bits to first. */
        d  = (t >> 0) & 0x55555555;
        d += (t >> 1) & 0x55555555;
        /* Values 0, 1 or 2 in consecutive 2 bits.
         * 0 - 1/4, 1 - 2/4, 2 - 1/4. */

    #ifdef WOLFSSL_KYBER_SMALL
        for (j = 0; j < 8; j++) {
            p[i + j] = ETA2_SUB(d, j);
        }
    #else
        p[i + 0] = ETA2_SUB(d, 0);
        p[i + 1] = ETA2_SUB(d, 1);
        p[i + 2] = ETA2_SUB(d, 2);
        p[i + 3] = ETA2_SUB(d, 3);
        p[i + 4] = ETA2_SUB(d, 4);
        p[i + 5] = ETA2_SUB(d, 5);
        p[i + 6] = ETA2_SUB(d, 6);
        p[i + 7] = ETA2_SUB(d, 7);
    #endif
        /* -2 - 1/16, -1 - 4/16, 0 - 6/16, 1 - 4/16, 2 - 1/16  */

        /* Move over used bytes. */
        r += 4;
    }
#else
    /* Calculate sixteen integer coefficients at a time. */
    for (i = 0; i < KYBER_N; i += 16) {
    #ifdef WOLFSSL_KYBER_SMALL
        unsigned int j;
    #endif
        /* Take the next 8 bytes, little endian, as a 64 bit value. */
    #ifdef BIG_ENDIAN_ORDER
        word64 t = ByteReverseWord64(readUnalignedWord64(r));
    #else
        word64 t = readUnalignedWord64(r);
    #endif
        word64 d;
        /* Add second bits to first. */
        d  = (t >> 0) & 0x5555555555555555L;
        d += (t >> 1) & 0x5555555555555555L;
        /* Values 0, 1 or 2 in consecutive 2 bits.
         * 0 - 1/4, 1 - 2/4, 2 - 1/4. */

    #ifdef WOLFSSL_KYBER_SMALL
        for (j = 0; j < 16; j++) {
            p[i + j] = ETA2_SUB(d, j);
        }
    #else
        p[i +  0] = ETA2_SUB(d,  0);
        p[i +  1] = ETA2_SUB(d,  1);
        p[i +  2] = ETA2_SUB(d,  2);
        p[i +  3] = ETA2_SUB(d,  3);
        p[i +  4] = ETA2_SUB(d,  4);
        p[i +  5] = ETA2_SUB(d,  5);
        p[i +  6] = ETA2_SUB(d,  6);
        p[i +  7] = ETA2_SUB(d,  7);
        p[i +  8] = ETA2_SUB(d,  8);
        p[i +  9] = ETA2_SUB(d,  9);
        p[i + 10] = ETA2_SUB(d, 10);
        p[i + 11] = ETA2_SUB(d, 11);
        p[i + 12] = ETA2_SUB(d, 12);
        p[i + 13] = ETA2_SUB(d, 13);
        p[i + 14] = ETA2_SUB(d, 14);
        p[i + 15] = ETA2_SUB(d, 15);
    #endif
        /* -2 - 1/16, -1 - 4/16, 0 - 6/16, 1 - 4/16, 2 - 1/16  */

        /* Move over used bytes. */
        r += 8;
    }
#endif
}

#if defined(WOLFSSL_KYBER512) || defined(WOLFSSL_WC_ML_KEM_512)
/* Subtract one 3 bit value from another out of a larger number.
 *
 * @param  [in]  d  Value containing sequential 3 bit values.
 * @param  [in]  i  Start index of the two values in 3 bits each.
 * @return  Difference of the two values with range 0..3.
 */
#define ETA3_SUB(d, i) \
    (((sword16)(((d) >> ((i) * 6 + 0)) & 0x7)) - \
     ((sword16)(((d) >> ((i) * 6 + 3)) & 0x7)))

/* Compute polynomial with coefficients distributed according to a centered
 * binomial distribution with parameter eta3 from uniform random bytes.
 *
 * @param [out]  p  Polynomial computed.
 * @param [in]   r  Random bytes.
 */
static void kyber_cbd_eta3(sword16* p, const byte* r)
{
    unsigned int i;

#if defined(WOLFSSL_SMALL_STACK) || defined(WOLFSSL_KYBER_NO_LARGE_CODE) || \
    defined(BIG_ENDIAN_ORDER)
#ifndef WORD64_AVAILABLE
    /* Calculate four integer coefficients at a time. */
    for (i = 0; i < KYBER_N; i += 4) {
    #ifdef WOLFSSL_KYBER_SMALL
        unsigned int j;
    #endif
        /* Take the next 3 bytes, little endian, as a 24 bit value. */
        word32 t = (((word32)(r[0])) <<  0) |
                   (((word32)(r[1])) <<  8) |
                   (((word32)(r[2])) << 16);
        word32 d;
        /* Add second and third bits to first. */
        d  = (t >> 0) & 0x00249249;
        d += (t >> 1) & 0x00249249;
        d += (t >> 2) & 0x00249249;
        /* Values 0, 1, 2 or 3 in consecutive 3 bits.
         * 0 - 1/8, 1 - 3/8, 2 - 3/8, 3 - 1/8. */

    #ifdef WOLFSSL_KYBER_SMALL
        for (j = 0; j < 4; j++) {
            p[i + j] = ETA3_SUB(d, j);
        }
    #else
        p[i + 0] = ETA3_SUB(d, 0);
        p[i + 1] = ETA3_SUB(d, 1);
        p[i + 2] = ETA3_SUB(d, 2);
        p[i + 3] = ETA3_SUB(d, 3);
    #endif
        /* -3-1/64, -2-6/64, -1-15/64, 0-20/64, 1-15/64, 2-6/64, 3-1/64 */

        /* Move over used bytes. */
        r += 3;
    }
#else
    /* Calculate eight integer coefficients at a time. */
    for (i = 0; i < KYBER_N; i += 8) {
    #ifdef WOLFSSL_KYBER_SMALL
        unsigned int j;
    #endif
        /* Take the next 6 bytes, little endian, as a 48 bit value. */
        word64 t = (((word64)(r[0])) <<  0) |
                   (((word64)(r[1])) <<  8) |
                   (((word64)(r[2])) << 16) |
                   (((word64)(r[3])) << 24) |
                   (((word64)(r[4])) << 32) |
                   (((word64)(r[5])) << 40);
        word64 d;
        /* Add second and third bits to first. */
        d  = (t >> 0) & 0x0000249249249249L;
        d += (t >> 1) & 0x0000249249249249L;
        d += (t >> 2) & 0x0000249249249249L;
        /* Values 0, 1, 2 or 3 in consecutive 3 bits.
         * 0 - 1/8, 1 - 3/8, 2 - 3/8, 3 - 1/8. */

    #ifdef WOLFSSL_KYBER_SMALL
        for (j = 0; j < 8; j++) {
            p[i + j] = ETA3_SUB(d, j);
        }
    #else
        p[i + 0] = ETA3_SUB(d, 0);
        p[i + 1] = ETA3_SUB(d, 1);
        p[i + 2] = ETA3_SUB(d, 2);
        p[i + 3] = ETA3_SUB(d, 3);
        p[i + 4] = ETA3_SUB(d, 4);
        p[i + 5] = ETA3_SUB(d, 5);
        p[i + 6] = ETA3_SUB(d, 6);
        p[i + 7] = ETA3_SUB(d, 7);
    #endif
        /* -3-1/64, -2-6/64, -1-15/64, 0-20/64, 1-15/64, 2-6/64, 3-1/64 */

        /* Move over used bytes. */
        r += 6;
    }
#endif /* WORD64_AVAILABLE */
#else
    /* Calculate eight integer coefficients at a time. */
    for (i = 0; i < KYBER_N; i += 16) {
        const word32* r32 = (const word32*)r;
        /* Take the next 12 bytes, little endian, as 24 bit values. */
        word32 t0 =   r32[0]                          & 0xffffff;
        word32 t1 = ((r32[0] >> 24) | (r32[1] <<  8)) & 0xffffff;
        word32 t2 = ((r32[1] >> 16) | (r32[2] << 16)) & 0xffffff;
        word32 t3 =   r32[2] >>  8                              ;
        word32 d0;
        word32 d1;
        word32 d2;
        word32 d3;

        /* Add second and third bits to first. */
        d0  = (t0 >> 0) & 0x00249249;
        d0 += (t0 >> 1) & 0x00249249;
        d0 += (t0 >> 2) & 0x00249249;
        d1  = (t1 >> 0) & 0x00249249;
        d1 += (t1 >> 1) & 0x00249249;
        d1 += (t1 >> 2) & 0x00249249;
        d2  = (t2 >> 0) & 0x00249249;
        d2 += (t2 >> 1) & 0x00249249;
        d2 += (t2 >> 2) & 0x00249249;
        d3  = (t3 >> 0) & 0x00249249;
        d3 += (t3 >> 1) & 0x00249249;
        d3 += (t3 >> 2) & 0x00249249;
        /* Values 0, 1, 2 or 3 in consecutive 3 bits.
         * 0 - 1/8, 1 - 3/8, 2 - 3/8, 3 - 1/8. */

        p[i +  0] = ETA3_SUB(d0, 0);
        p[i +  1] = ETA3_SUB(d0, 1);
        p[i +  2] = ETA3_SUB(d0, 2);
        p[i +  3] = ETA3_SUB(d0, 3);
        p[i +  4] = ETA3_SUB(d1, 0);
        p[i +  5] = ETA3_SUB(d1, 1);
        p[i +  6] = ETA3_SUB(d1, 2);
        p[i +  7] = ETA3_SUB(d1, 3);
        p[i +  8] = ETA3_SUB(d2, 0);
        p[i +  9] = ETA3_SUB(d2, 1);
        p[i + 10] = ETA3_SUB(d2, 2);
        p[i + 11] = ETA3_SUB(d2, 3);
        p[i + 12] = ETA3_SUB(d3, 0);
        p[i + 13] = ETA3_SUB(d3, 1);
        p[i + 14] = ETA3_SUB(d3, 2);
        p[i + 15] = ETA3_SUB(d3, 3);
        /* -3-1/64, -2-6/64, -1-15/64, 0-20/64, 1-15/64, 2-6/64, 3-1/64 */

        /* Move over used bytes. */
        r += 12;
    }
#endif /* WOLFSSL_SMALL_STACK || WOLFSSL_KYBER_NO_LARGE_CODE || BIG_ENDIAN_ORDER        */
}
#endif

#if !(defined(__aarch64__) && defined(WOLFSSL_ARMASM))

/* Get noise/error by calculating random bytes and sampling to a binomial
 * distribution.
 *
 * @param  [in, out]  prf   Pseudo-random function object.
 * @param  [out]      p     Polynomial.
 * @param  [in]       seed  Seed to use when calculating random.
 * @param  [in]       eta1  Size of noise/error integers.
 * @return  0 on success.
 */
static int kyber_get_noise_eta1_c(KYBER_PRF_T* prf, sword16* p,
    const byte* seed, byte eta1)
{
    int ret;

    (void)eta1;

#if defined(WOLFSSL_KYBER512) || defined(WOLFSSL_WC_ML_KEM_512)
    if (eta1 == KYBER_CBD_ETA3) {
        byte rand[ETA3_RAND_SIZE];

        /* Calculate random bytes from seed with PRF. */
        ret = kyber_prf(prf, rand, sizeof(rand), seed);
        if (ret == 0) {
            /* Sample for values in range -3..3 from 3 bits of random. */
            kyber_cbd_eta3(p, rand);
         }
    }
    else
#endif
    {
        byte rand[ETA2_RAND_SIZE];

        /* Calculate random bytes from seed with PRF. */
        ret = kyber_prf(prf, rand, sizeof(rand), seed);
        if (ret == 0) {
            /* Sample for values in range -2..2 from 2 bits of random. */
            kyber_cbd_eta2(p, rand);
        }
    }

    return ret;
}

/* Get noise/error by calculating random bytes and sampling to a binomial
 * distribution. Values -2..2
 *
 * @param  [in, out]  prf   Pseudo-random function object.
 * @param  [out]      p     Polynomial.
 * @param  [in]       seed  Seed to use when calculating random.
 * @return  0 on success.
 */
static int kyber_get_noise_eta2_c(KYBER_PRF_T* prf, sword16* p,
    const byte* seed)
{
    int ret;
    byte rand[ETA2_RAND_SIZE];

    /* Calculate random bytes from seed with PRF. */
    ret = kyber_prf(prf, rand, sizeof(rand), seed);
    if (ret == 0) {
        kyber_cbd_eta2(p, rand);
    }

    return ret;
}

#endif

#ifdef USE_INTEL_SPEEDUP
#define PRF_RAND_SZ   (2 * SHA3_256_BYTES)

#if defined(WOLFSSL_KYBER768) || defined(WOLFSSL_WC_ML_KEM_768) || \
    defined(WOLFSSL_KYBER1024) || defined(WOLFSSL_WC_ML_KEM_1024)
/* Get the noise/error by calculating random bytes.
 *
 * @param  [out]  rand  Random number byte array.
 * @param  [in]   seed  Seed to generate random from.
 * @param  [in]   o     Offset of seed count.
 */
static void kyber_get_noise_x4_eta2_avx2(byte* rand, byte* seed, byte o)
{
    int i;
    word64 state[25 * 4];

    for (i = 0; i < 4; i++) {
        state[4*4 + i] = 0x1f00 + i + o;
    }

    kyber_sha3_256_blocksx4_seed_avx2(state, seed);
    kyber_redistribute_16_rand_avx2(state, rand + 0 * ETA2_RAND_SIZE,
        rand + 1 * ETA2_RAND_SIZE, rand + 2 * ETA2_RAND_SIZE,
        rand + 3 * ETA2_RAND_SIZE);
}
#endif

#if defined(WOLFSSL_KYBER512) || defined(WOLFSSL_WC_ML_KEM_512)
/* Get the noise/error by calculating random bytes.
 *
 * @param  [out]  rand  Random number byte array.
 * @param  [in]   seed  Seed to generate random from.
 * @param  [in]   o     Offset of seed count.
 */
static void kyber_get_noise_x4_eta3_avx2(byte* rand, byte* seed)
{
    word64 state[25 * 4];
    int i;

    state[4*4 + 0] = 0x1f00 + 0;
    state[4*4 + 1] = 0x1f00 + 1;
    state[4*4 + 2] = 0x1f00 + 2;
    state[4*4 + 3] = 0x1f00 + 3;

    kyber_sha3_256_blocksx4_seed_avx2(state, seed);
    kyber_redistribute_17_rand_avx2(state, rand + 0 * PRF_RAND_SZ,
        rand + 1 * PRF_RAND_SZ, rand + 2 * PRF_RAND_SZ,
        rand + 3 * PRF_RAND_SZ);
    i = SHA3_256_BYTES;
    kyber_sha3_blocksx4_avx2(state);
    kyber_redistribute_8_rand_avx2(state, rand + i + 0 * PRF_RAND_SZ,
        rand + i + 1 * PRF_RAND_SZ, rand + i + 2 * PRF_RAND_SZ,
        rand + i + 3 * PRF_RAND_SZ);
}

/* Get noise/error by calculating random bytes and sampling to a binomial
 * distribution. Values -2..2
 *
 * @param  [in, out]  prf   Pseudo-random function object.
 * @param  [out]      p     Polynomial.
 * @param  [in]       seed  Seed to use when calculating random.
 * @return  0 on success.
 */
static int kyber_get_noise_eta2_avx2(KYBER_PRF_T* prf, sword16* p,
    const byte* seed)
{
    int ret;
    byte rand[ETA2_RAND_SIZE];

    /* Calculate random bytes from seed with PRF. */
    ret = kyber_prf(prf, rand, sizeof(rand), seed);
    if (ret == 0) {
        kyber_cbd_eta2_avx2(p, rand);
    }

    return ret;
}

/* Get the noise/error by calculating random bytes and sampling to a binomial
 * distribution.
 *
 * @param  [in, out]  prf   Pseudo-random function object.
 * @param  [out]      vec1  First Vector of polynomials.
 * @param  [out]      vec2  Second Vector of polynomials.
 * @param  [out]      poly  Polynomial.
 * @param  [in]       seed  Seed to use when calculating random.
 * @return  0 on success.
 */
static int kyber_get_noise_k2_avx2(KYBER_PRF_T* prf, sword16* vec1,
    sword16* vec2, sword16* poly, byte* seed)
{
    int ret = 0;
    byte rand[4 * PRF_RAND_SZ];

    kyber_get_noise_x4_eta3_avx2(rand, seed);
    kyber_cbd_eta3_avx2(vec1          , rand + 0 * PRF_RAND_SZ);
    kyber_cbd_eta3_avx2(vec1 + KYBER_N, rand + 1 * PRF_RAND_SZ);
    if (poly == NULL) {
        kyber_cbd_eta3_avx2(vec2          , rand + 2 * PRF_RAND_SZ);
        kyber_cbd_eta3_avx2(vec2 + KYBER_N, rand + 3 * PRF_RAND_SZ);
    }
    else {
        kyber_cbd_eta2_avx2(vec2          , rand + 2 * PRF_RAND_SZ);
        kyber_cbd_eta2_avx2(vec2 + KYBER_N, rand + 3 * PRF_RAND_SZ);

        seed[KYBER_SYM_SZ] = 4;
        ret = kyber_get_noise_eta2_avx2(prf, poly, seed);
    }

    return ret;
}
#endif

#if defined(WOLFSSL_KYBER768) || defined(WOLFSSL_WC_ML_KEM_768)
/* Get the noise/error by calculating random bytes and sampling to a binomial
 * distribution.
 *
 * @param  [out]      vec1  First Vector of polynomials.
 * @param  [out]      vec2  Second Vector of polynomials.
 * @param  [out]      poly  Polynomial.
 * @param  [in]       seed  Seed to use when calculating random.
 * @return  0 on success.
 */
static int kyber_get_noise_k3_avx2(sword16* vec1, sword16* vec2, sword16* poly,
    byte* seed)
{
    byte rand[4 * ETA2_RAND_SIZE];

    kyber_get_noise_x4_eta2_avx2(rand, seed, 0);
    kyber_cbd_eta2_avx2(vec1              , rand + 0 * ETA2_RAND_SIZE);
    kyber_cbd_eta2_avx2(vec1 + 1 * KYBER_N, rand + 1 * ETA2_RAND_SIZE);
    kyber_cbd_eta2_avx2(vec1 + 2 * KYBER_N, rand + 2 * ETA2_RAND_SIZE);
    kyber_cbd_eta2_avx2(vec2              , rand + 3 * ETA2_RAND_SIZE);
    kyber_get_noise_x4_eta2_avx2(rand, seed, 4);
    kyber_cbd_eta2_avx2(vec2 + 1 * KYBER_N, rand + 0 * ETA2_RAND_SIZE);
    kyber_cbd_eta2_avx2(vec2 + 2 * KYBER_N, rand + 1 * ETA2_RAND_SIZE);
    if (poly != NULL) {
        kyber_cbd_eta2_avx2(poly, rand + 2 * ETA2_RAND_SIZE);
    }

    return 0;
}
#endif

#if defined(WOLFSSL_KYBER1024) || defined(WOLFSSL_WC_ML_KEM_1024)
/* Get the noise/error by calculating random bytes and sampling to a binomial
 * distribution.
 *
 * @param  [in, out]  prf   Pseudo-random function object.
 * @param  [out]      vec1  First Vector of polynomials.
 * @param  [out]      vec2  Second Vector of polynomials.
 * @param  [out]      poly  Polynomial.
 * @param  [in]       seed  Seed to use when calculating random.
 * @return  0 on success.
 */
static int kyber_get_noise_k4_avx2(KYBER_PRF_T* prf, sword16* vec1,
    sword16* vec2, sword16* poly, byte* seed)
{
    int ret = 0;
    byte rand[4 * ETA2_RAND_SIZE];

    (void)prf;

    kyber_get_noise_x4_eta2_avx2(rand, seed, 0);
    kyber_cbd_eta2_avx2(vec1              , rand + 0 * ETA2_RAND_SIZE);
    kyber_cbd_eta2_avx2(vec1 + 1 * KYBER_N, rand + 1 * ETA2_RAND_SIZE);
    kyber_cbd_eta2_avx2(vec1 + 2 * KYBER_N, rand + 2 * ETA2_RAND_SIZE);
    kyber_cbd_eta2_avx2(vec1 + 3 * KYBER_N, rand + 3 * ETA2_RAND_SIZE);
    kyber_get_noise_x4_eta2_avx2(rand, seed, 4);
    kyber_cbd_eta2_avx2(vec2              , rand + 0 * ETA2_RAND_SIZE);
    kyber_cbd_eta2_avx2(vec2 + 1 * KYBER_N, rand + 1 * ETA2_RAND_SIZE);
    kyber_cbd_eta2_avx2(vec2 + 2 * KYBER_N, rand + 2 * ETA2_RAND_SIZE);
    kyber_cbd_eta2_avx2(vec2 + 3 * KYBER_N, rand + 3 * ETA2_RAND_SIZE);
    if (poly != NULL) {
        seed[KYBER_SYM_SZ] = 8;
        ret = kyber_get_noise_eta2_c(prf, poly, seed);
    }

    return ret;
}
#endif
#endif /* USE_INTEL_SPEEDUP */

#if defined(__aarch64__) && defined(WOLFSSL_ARMASM)

#define PRF_RAND_SZ   (2 * SHA3_256_BYTES)

/* Get the noise/error by calculating random bytes.
 *
 * @param  [out]  rand  Random number byte array.
 * @param  [in]   seed  Seed to generate random from.
 * @param  [in]   o     Offset of seed count.
 */
static void kyber_get_noise_x3_eta2_aarch64(byte* rand, byte* seed, byte o)
{
    word64* state = (word64*)rand;

    state[0*25 + 4] = 0x1f00 + 0 + o;
    state[1*25 + 4] = 0x1f00 + 1 + o;
    state[2*25 + 4] = 0x1f00 + 2 + o;

    kyber_shake256_blocksx3_seed_neon(state, seed);
}

#if defined(WOLFSSL_KYBER512) || defined(WOLFSSL_WC_ML_KEM_512)
/* Get the noise/error by calculating random bytes.
 *
 * @param  [out]  rand  Random number byte array.
 * @param  [in]   seed  Seed to generate random from.
 * @param  [in]   o     Offset of seed count.
 */
static void kyber_get_noise_x3_eta3_aarch64(byte* rand, byte* seed, byte o)
{
    word64 state[3 * 25];

    state[0*25 + 4] = 0x1f00 + 0 + o;
    state[1*25 + 4] = 0x1f00 + 1 + o;
    state[2*25 + 4] = 0x1f00 + 2 + o;

    kyber_shake256_blocksx3_seed_neon(state, seed);
    XMEMCPY(rand + 0 * ETA3_RAND_SIZE, state + 0*25, SHA3_256_BYTES);
    XMEMCPY(rand + 1 * ETA3_RAND_SIZE, state + 1*25, SHA3_256_BYTES);
    XMEMCPY(rand + 2 * ETA3_RAND_SIZE, state + 2*25, SHA3_256_BYTES);
    kyber_sha3_blocksx3_neon(state);
    rand += SHA3_256_BYTES;
    XMEMCPY(rand + 0 * ETA3_RAND_SIZE, state + 0*25,
        ETA3_RAND_SIZE - SHA3_256_BYTES);
    XMEMCPY(rand + 1 * ETA3_RAND_SIZE, state + 1*25,
        ETA3_RAND_SIZE - SHA3_256_BYTES);
    XMEMCPY(rand + 2 * ETA3_RAND_SIZE, state + 2*25,
        ETA3_RAND_SIZE - SHA3_256_BYTES);
}

/* Get the noise/error by calculating random bytes.
 *
 * @param  [out]  rand  Random number byte array.
 * @param  [in]   seed  Seed to generate random from.
 * @param  [in]   o     Offset of seed count.
 * @return  0 on success.
 */
static void kyber_get_noise_eta3_aarch64(byte* rand, byte* seed, byte o)
{
    word64 state[25];

    state[0] = ((word64*)seed)[0];
    state[1] = ((word64*)seed)[1];
    state[2] = ((word64*)seed)[2];
    state[3] = ((word64*)seed)[3];
    state[4] = 0x1f00 + o;
    XMEMSET(state + 5, 0, sizeof(*state) * (25 - 5));
    state[16] = W64LIT(0x8000000000000000);
    BlockSha3(state);
    XMEMCPY(rand                 , state, SHA3_256_BYTES);
    BlockSha3(state);
    XMEMCPY(rand + SHA3_256_BYTES, state, ETA3_RAND_SIZE - SHA3_256_BYTES);
}

/* Get the noise/error by calculating random bytes and sampling to a binomial
 * distribution.
 *
 * @param  [out]      vec1  First Vector of polynomials.
 * @param  [out]      vec2  Second Vector of polynomials.
 * @param  [out]      poly  Polynomial.
 * @param  [in]       seed  Seed to use when calculating random.
 * @return  0 on success.
 */
static int kyber_get_noise_k2_aarch64(sword16* vec1, sword16* vec2,
    sword16* poly, byte* seed)
{
    int ret = 0;
    byte rand[3 * 25 * 8];

    kyber_get_noise_x3_eta3_aarch64(rand, seed, 0);
    kyber_cbd_eta3(vec1          , rand + 0 * ETA3_RAND_SIZE);
    kyber_cbd_eta3(vec1 + KYBER_N, rand + 1 * ETA3_RAND_SIZE);
    if (poly == NULL) {
        kyber_cbd_eta3(vec2          , rand + 2 * ETA3_RAND_SIZE);
        kyber_get_noise_eta3_aarch64(rand, seed, 3);
        kyber_cbd_eta3(vec2 + KYBER_N, rand                     );
    }
    else {
        kyber_get_noise_x3_eta2_aarch64(rand, seed, 2);
        kyber_cbd_eta2(vec2          , rand + 0 * 25 * 8);
        kyber_cbd_eta2(vec2 + KYBER_N, rand + 1 * 25 * 8);
        kyber_cbd_eta2(poly          , rand + 2 * 25 * 8);
    }

    return ret;
}
#endif

#if defined(WOLFSSL_KYBER768) || defined(WOLFSSL_WC_ML_KEM_768)
/* Get the noise/error by calculating random bytes.
 *
 * @param  [out]  rand  Random number byte array.
 * @param  [in]   seed  Seed to generate random from.
 * @param  [in]   o     Offset of seed count.
 * @return  0 on success.
 */
static void kyber_get_noise_eta2_aarch64(byte* rand, byte* seed, byte o)
{
    word64* state = (word64*)rand;

    state[0] = ((word64*)seed)[0];
    state[1] = ((word64*)seed)[1];
    state[2] = ((word64*)seed)[2];
    state[3] = ((word64*)seed)[3];
    /* Transposed value same as not. */
    state[4] = 0x1f00 + o;
    XMEMSET(state + 5, 0, sizeof(*state) * (25 - 5));
    state[16] = W64LIT(0x8000000000000000);
    BlockSha3(state);
}

/* Get the noise/error by calculating random bytes and sampling to a binomial
 * distribution.
 *
 * @param  [out]      vec1  First Vector of polynomials.
 * @param  [out]      vec2  Second Vector of polynomials.
 * @param  [out]      poly  Polynomial.
 * @param  [in]       seed  Seed to use when calculating random.
 * @return  0 on success.
 */
static int kyber_get_noise_k3_aarch64(sword16* vec1, sword16* vec2,
     sword16* poly, byte* seed)
{
    byte rand[3 * 25 * 8];

    kyber_get_noise_x3_eta2_aarch64(rand, seed, 0);
    kyber_cbd_eta2(vec1              , rand + 0 * 25 * 8);
    kyber_cbd_eta2(vec1 + 1 * KYBER_N, rand + 1 * 25 * 8);
    kyber_cbd_eta2(vec1 + 2 * KYBER_N, rand + 2 * 25 * 8);
    kyber_get_noise_x3_eta2_aarch64(rand, seed, 3);
    kyber_cbd_eta2(vec2              , rand + 0 * 25 * 8);
    kyber_cbd_eta2(vec2 + 1 * KYBER_N, rand + 1 * 25 * 8);
    kyber_cbd_eta2(vec2 + 2 * KYBER_N, rand + 2 * 25 * 8);
    if (poly != NULL) {
        kyber_get_noise_eta2_aarch64(rand, seed, 6);
        kyber_cbd_eta2(poly              , rand + 0 * 25 * 8);
    }

    return 0;
}
#endif

#if defined(WOLFSSL_KYBER1024) || defined(WOLFSSL_WC_ML_KEM_1024)
/* Get the noise/error by calculating random bytes and sampling to a binomial
 * distribution.
 *
 * @param  [out]      vec1  First Vector of polynomials.
 * @param  [out]      vec2  Second Vector of polynomials.
 * @param  [out]      poly  Polynomial.
 * @param  [in]       seed  Seed to use when calculating random.
 * @return  0 on success.
 */
static int kyber_get_noise_k4_aarch64(sword16* vec1, sword16* vec2,
    sword16* poly, byte* seed)
{
    int ret = 0;
    byte rand[3 * 25 * 8];

    kyber_get_noise_x3_eta2_aarch64(rand, seed, 0);
    kyber_cbd_eta2(vec1              , rand + 0 * 25 * 8);
    kyber_cbd_eta2(vec1 + 1 * KYBER_N, rand + 1 * 25 * 8);
    kyber_cbd_eta2(vec1 + 2 * KYBER_N, rand + 2 * 25 * 8);
    kyber_get_noise_x3_eta2_aarch64(rand, seed, 3);
    kyber_cbd_eta2(vec1 + 3 * KYBER_N, rand + 0 * 25 * 8);
    kyber_cbd_eta2(vec2              , rand + 1 * 25 * 8);
    kyber_cbd_eta2(vec2 + 1 * KYBER_N, rand + 2 * 25 * 8);
    kyber_get_noise_x3_eta2_aarch64(rand, seed, 6);
    kyber_cbd_eta2(vec2 + 2 * KYBER_N, rand + 0 * 25 * 8);
    kyber_cbd_eta2(vec2 + 3 * KYBER_N, rand + 1 * 25 * 8);
    if (poly != NULL) {
        kyber_cbd_eta2(poly,               rand + 2 * 25 * 8);
    }

    return ret;
}
#endif
#endif /* __aarch64__ && WOLFSSL_ARMASM */

#if !(defined(__aarch64__) && defined(WOLFSSL_ARMASM))

/* Get the noise/error by calculating random bytes and sampling to a binomial
 * distribution.
 *
 * @param  [in, out]  prf   Pseudo-random function object.
 * @param  [in]       kp    Number of polynomials in vector.
 * @param  [out]      vec1  First Vector of polynomials.
 * @param  [in]       eta1  Size of noise/error integers with first vector.
 * @param  [out]      vec2  Second Vector of polynomials.
 * @param  [in]       eta2  Size of noise/error integers with second vector.
 * @param  [out]      poly  Polynomial.
 * @param  [in]       seed  Seed to use when calculating random.
 * @return  0 on success.
 */
static int kyber_get_noise_c(KYBER_PRF_T* prf, int kp, sword16* vec1, int eta1,
    sword16* vec2, int eta2, sword16* poly, byte* seed)
{
    int ret = 0;
    int i;

    /* First noise generation has a seed with 0x00 appended. */
    seed[KYBER_SYM_SZ] = 0;
    /* Generate noise as private key. */
    for (i = 0; (ret == 0) && (i < kp); i++) {
        /* Generate noise for each dimension of vector. */
        ret = kyber_get_noise_eta1_c(prf, vec1 + i * KYBER_N, seed, eta1);
        /* Increment value of appended byte. */
        seed[KYBER_SYM_SZ]++;
    }
    /* Generate noise for error. */
    for (i = 0; (ret == 0) && (i < kp); i++) {
        /* Generate noise for each dimension of vector. */
        ret = kyber_get_noise_eta1_c(prf, vec2 + i * KYBER_N, seed, eta2);
        /* Increment value of appended byte. */
        seed[KYBER_SYM_SZ]++;
    }
    if ((ret == 0) && (poly != NULL)) {
        /* Generating random error polynomial. */
        ret = kyber_get_noise_eta2_c(prf, poly, seed);
    }

    return ret;
}

#endif /* __aarch64__ && WOLFSSL_ARMASM */

/* Get the noise/error by calculating random bytes and sampling to a binomial
 * distribution.
 *
 * @param  [in, out]  prf   Pseudo-random function object.
 * @param  [in]       kp    Number of polynomials in vector.
 * @param  [out]      vec1  First Vector of polynomials.
 * @param  [out]      vec2  Second Vector of polynomials.
 * @param  [out]      poly  Polynomial.
 * @param  [in]       seed  Seed to use when calculating random.
 * @return  0 on success.
 */
int kyber_get_noise(KYBER_PRF_T* prf, int kp, sword16* vec1,
    sword16* vec2, sword16* poly, byte* seed)
{
    int ret;

#if defined(WOLFSSL_KYBER512) || defined(WOLFSSL_WC_ML_KEM_512)
    if (kp == KYBER512_K) {
#if defined(WOLFSSL_ARMASM) && defined(__aarch64__)
        ret = kyber_get_noise_k2_aarch64(vec1, vec2, poly, seed);
#else
    #ifdef USE_INTEL_SPEEDUP
        if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
            ret = kyber_get_noise_k2_avx2(prf, vec1, vec2, poly, seed);
            RESTORE_VECTOR_REGISTERS();
        }
        else
    #endif
        if (poly == NULL) {
            ret = kyber_get_noise_c(prf, kp, vec1, KYBER_CBD_ETA3, vec2,
                KYBER_CBD_ETA3, NULL, seed);
        }
        else {
            ret = kyber_get_noise_c(prf, kp, vec1, KYBER_CBD_ETA3, vec2,
                KYBER_CBD_ETA2, poly, seed);
        }
#endif
    }
    else
#endif
#if defined(WOLFSSL_KYBER768) || defined(WOLFSSL_WC_ML_KEM_768)
    if (kp == KYBER768_K) {
#if defined(WOLFSSL_ARMASM) && defined(__aarch64__)
        ret = kyber_get_noise_k3_aarch64(vec1, vec2, poly, seed);
#else
    #ifdef USE_INTEL_SPEEDUP
        if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
            ret = kyber_get_noise_k3_avx2(vec1, vec2, poly, seed);
            RESTORE_VECTOR_REGISTERS();
        }
        else
    #endif
        {
            ret = kyber_get_noise_c(prf, kp, vec1, KYBER_CBD_ETA2, vec2,
                KYBER_CBD_ETA2, poly, seed);
        }
#endif
    }
    else
#endif
#if defined(WOLFSSL_KYBER1024) || defined(WOLFSSL_WC_ML_KEM_1024)
    if (kp == KYBER1024_K) {
#if defined(WOLFSSL_ARMASM) && defined(__aarch64__)
        ret = kyber_get_noise_k4_aarch64(vec1, vec2, poly, seed);
#else
    #ifdef USE_INTEL_SPEEDUP
        if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
            ret = kyber_get_noise_k4_avx2(prf, vec1, vec2, poly, seed);
            RESTORE_VECTOR_REGISTERS();
        }
        else
    #endif
        {
            ret = kyber_get_noise_c(prf, kp, vec1, KYBER_CBD_ETA2, vec2,
                KYBER_CBD_ETA2, poly, seed);
        }
#endif
    }
    else
#endif
    {
        ret = BAD_STATE_E;
    }

    (void)prf;

    return ret;
}

/******************************************************************************/

#if !(defined(__aarch64__) && defined(WOLFSSL_ARMASM))
/* Compare two byte arrays of equal size.
 *
 * @param [in]  a   First array to compare.
 * @param [in]  b   Second array to compare.
 * @param [in]  sz  Size of arrays in bytes.
 * @return  0 on success.
 * @return  -1 on failure.
 */
static int kyber_cmp_c(const byte* a, const byte* b, int sz)
{
    int i;
    byte r = 0;

    /* Constant time comparison of the encapsulated message and cipher text. */
    for (i = 0; i < sz; i++) {
        r |= a[i] ^ b[i];
    }
    return 0 - ((-(word32)r) >> 31);
}
#endif

/* Compare two byte arrays of equal size.
 *
 * @param [in]  a   First array to compare.
 * @param [in]  b   Second array to compare.
 * @param [in]  sz  Size of arrays in bytes.
 * @return  0 on success.
 * @return  -1 on failure.
 */
int kyber_cmp(const byte* a, const byte* b, int sz)
{
#if defined(__aarch64__) && defined(WOLFSSL_ARMASM)
    return kyber_cmp_neon(a, b, sz);
#else
    int fail;

#ifdef USE_INTEL_SPEEDUP
    if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        fail = kyber_cmp_avx2(a, b, sz);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
        fail = kyber_cmp_c(a, b, sz);
    }

    return fail;
#endif
}

/******************************************************************************/

#if !defined(WOLFSSL_ARMASM)

/* Conditional subtraction of q to each coefficient of a polynomial.
 *
 * @param  [in, out]  p  Polynomial.
 */
static KYBER_NOINLINE void kyber_csubq_c(sword16* p)
{
    unsigned int i;

    for (i = 0; i < KYBER_N; ++i) {
        sword16 t = p[i] - KYBER_Q;
        /* When top bit set, -ve number - need to add q back. */
        p[i] = ((t >> 15) & KYBER_Q) + t;
    }
}

#elif defined(__aarch64__)

#define kyber_csubq_c   kyber_csubq_neon

#elif defined(WOLFSSL_ARMASM_THUMB2)

#define kyber_csubq_c   kyber_thumb2_csubq

#else

#define kyber_csubq_c   kyber_arm32_csubq

#endif

/******************************************************************************/

#if defined(CONV_WITH_DIV) || !defined(WORD64_AVAILABLE)

/* Compress value.
 *
 * Uses div operator that may be slow.
 *
 * @param  [in]  v  Vector of polynomials.
 * @param  [in]  i  Index of polynomial in vector.
 * @param  [in]  j  Index into polynomial.
 * @param  [in]  k  Offset from indices.
 * @param  [in]  s  Shift amount to apply to value being compressed.
 * @param  [in]  m  Mask to apply get the require number of bits.
 * @return  Compressed value.
 */
#define TO_COMP_WORD_VEC(v, i, j, k, s, m) \
    ((((word32)v[i * KYBER_N + j + k] << s) + KYBER_Q_HALF) / KYBER_Q) & m

/* Compress value to 10 bits.
 *
 * Uses mul instead of div.
 *
 * @param  [in]  v  Vector of polynomials.
 * @param  [in]  i  Index of polynomial in vector.
 * @param  [in]  j  Index into polynomial.
 * @param  [in]  k  Offset from indices.
 * @return  Compressed value.
 */
#define TO_COMP_WORD_10(v, i, j, k) \
    TO_COMP_WORD_VEC(v, i, j, k, 10, 0x3ff)

/* Compress value to 11 bits.
 *
 * Uses mul instead of div.
 *
 * @param  [in]  v  Vector of polynomials.
 * @param  [in]  i  Index of polynomial in vector.
 * @param  [in]  j  Index into polynomial.
 * @param  [in]  k  Offset from indices.
 * @return  Compressed value.
 */
#define TO_COMP_WORD_11(v, i, j, k) \
    TO_COMP_WORD_VEC(v, i, j, k, 11, 0x7ff)

#else

/* Multiplier that does div q.
 * ((1 << 53) + KYBER_Q_HALF) / KYBER_Q
 */
#define KYBER_V53         0x275f6ed0176UL
/* Multiplier times half of q.
 * KYBER_V53 * (KYBER_Q_HALF + 1)
 */
#define KYBER_V53_HALF    0x10013afb768076UL

/* Multiplier that does div q.
 * ((1 << 54) + KYBER_Q_HALF) / KYBER_Q
 */
#define KYBER_V54         0x4ebedda02ecUL
/* Multiplier times half of q.
 * KYBER_V54 * (KYBER_Q_HALF + 1)
 */
#define KYBER_V54_HALF    0x200275f6ed00ecUL

/* Compress value to 10 bits.
 *
 * Uses mul instead of div.
 *
 * @param  [in]  v  Vector of polynomials.
 * @param  [in]  i  Index of polynomial in vector.
 * @param  [in]  j  Index into polynomial.
 * @param  [in]  k  Offset from indices.
 * @return  Compressed value.
 */
#define TO_COMP_WORD_10(v, i, j, k) \
    ((((KYBER_V54 << 10) * (v)[(i) * KYBER_N + (j) + (k)]) + KYBER_V54_HALF) >> 54)

/* Compress value to 11 bits.
 *
 * Uses mul instead of div.
 * Only works for values in range: 0..3228
 *
 * @param  [in]  v  Vector of polynomials.
 * @param  [in]  i  Index of polynomial in vector.
 * @param  [in]  j  Index into polynomial.
 * @param  [in]  k  Offset from indices.
 * @return  Compressed value.
 */
#define TO_COMP_WORD_11(v, i, j, k) \
    ((((KYBER_V53 << 11) * (v)[(i) * KYBER_N + (j) + (k)]) + KYBER_V53_HALF) >> 53)

#endif /* CONV_WITH_DIV */

#if defined(WOLFSSL_KYBER512) || defined(WOLFSSL_WC_ML_KEM_512) || \
    defined(WOLFSSL_KYBER768) || defined(WOLFSSL_WC_ML_KEM_768)
/* Compress the vector of polynomials into a byte array with 10 bits each.
 *
 * @param  [out]  b       Array of bytes.
 * @param  [in]   v       Vector of polynomials.
 * @param  [in]   kp      Number of polynomials in vector.
 */
static void kyber_vec_compress_10_c(byte* r, sword16* v, unsigned int kp)
{
    unsigned int i;
    unsigned int j;

    for (i = 0; i < kp; i++) {
        /* Reduce each coefficient to mod q. */
        kyber_csubq_c(v + i * KYBER_N);
        /* All values are now positive. */
    }

    /* Each polynomial. */
    for (i = 0; i < kp; i++) {
#if defined(WOLFSSL_SMALL_STACK) || defined(WOLFSSL_KYBER_NO_LARGE_CODE) || \
    defined(BIG_ENDIAN_ORDER)
        /* Each 4 polynomial coefficients. */
        for (j = 0; j < KYBER_N; j += 4) {
        #ifdef WOLFSSL_KYBER_SMALL
            unsigned int k;
            sword16 t[4];
            /* Compress four polynomial values to 10 bits each. */
            for (k = 0; k < 4; k++) {
                t[k] = TO_COMP_WORD_10(v, i, j, k);
            }

            /* Pack four 10-bit values into byte array. */
            r[ 0] = (t[0] >> 0);
            r[ 1] = (t[0] >> 8) | (t[1] << 2);
            r[ 2] = (t[1] >> 6) | (t[2] << 4);
            r[ 3] = (t[2] >> 4) | (t[3] << 6);
            r[ 4] = (t[3] >> 2);
        #else
            /* Compress four polynomial values to 10 bits each. */
            sword16 t0 = TO_COMP_WORD_10(v, i, j, 0);
            sword16 t1 = TO_COMP_WORD_10(v, i, j, 1);
            sword16 t2 = TO_COMP_WORD_10(v, i, j, 2);
            sword16 t3 = TO_COMP_WORD_10(v, i, j, 3);

            /* Pack four 10-bit values into byte array. */
            r[ 0] = (t0 >> 0);
            r[ 1] = (t0 >> 8) | (t1 << 2);
            r[ 2] = (t1 >> 6) | (t2 << 4);
            r[ 3] = (t2 >> 4) | (t3 << 6);
            r[ 4] = (t3 >> 2);
        #endif

            /* Move over set bytes. */
            r += 5;
        }
#else
        /* Each 16 polynomial coefficients. */
        for (j = 0; j < KYBER_N; j += 16) {
            /* Compress four polynomial values to 10 bits each. */
            sword16 t0  = TO_COMP_WORD_10(v, i, j, 0);
            sword16 t1  = TO_COMP_WORD_10(v, i, j, 1);
            sword16 t2  = TO_COMP_WORD_10(v, i, j, 2);
            sword16 t3  = TO_COMP_WORD_10(v, i, j, 3);
            sword16 t4  = TO_COMP_WORD_10(v, i, j, 4);
            sword16 t5  = TO_COMP_WORD_10(v, i, j, 5);
            sword16 t6  = TO_COMP_WORD_10(v, i, j, 6);
            sword16 t7  = TO_COMP_WORD_10(v, i, j, 7);
            sword16 t8  = TO_COMP_WORD_10(v, i, j, 8);
            sword16 t9  = TO_COMP_WORD_10(v, i, j, 9);
            sword16 t10 = TO_COMP_WORD_10(v, i, j, 10);
            sword16 t11 = TO_COMP_WORD_10(v, i, j, 11);
            sword16 t12 = TO_COMP_WORD_10(v, i, j, 12);
            sword16 t13 = TO_COMP_WORD_10(v, i, j, 13);
            sword16 t14 = TO_COMP_WORD_10(v, i, j, 14);
            sword16 t15 = TO_COMP_WORD_10(v, i, j, 15);

            word32* r32 = (word32*)r;
            /* Pack sixteen 10-bit values into byte array. */
            r32[0] =  t0        | ((word32)t1  << 10) | ((word32)t2  << 20) |
                                  ((word32)t3  << 30);
            r32[1] = (t3  >> 2) | ((word32)t4  <<  8) | ((word32)t5  << 18) |
                                  ((word32)t6  << 28);
            r32[2] = (t6  >> 4) | ((word32)t7  <<  6) | ((word32)t8  << 16) |
                                  ((word32)t9  << 26);
            r32[3] = (t9  >> 6) | ((word32)t10 <<  4) | ((word32)t11 << 14) |
                                  ((word32)t12 << 24);
            r32[4] = (t12 >> 8) | ((word32)t13 <<  2) | ((word32)t14 << 12) |
                                  ((word32)t15 << 22);

            /* Move over set bytes. */
            r += 20;
        }
#endif
    }
}

/* Compress the vector of polynomials into a byte array with 10 bits each.
 *
 * @param  [out]  b       Array of bytes.
 * @param  [in]   v       Vector of polynomials.
 * @param  [in]   kp      Number of polynomials in vector.
 */
void kyber_vec_compress_10(byte* r, sword16* v, unsigned int kp)
{
#ifdef USE_INTEL_SPEEDUP
    if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        kyber_compress_10_avx2(r, v, kp);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
        kyber_vec_compress_10_c(r, v, kp);
    }
}
#endif

#if defined(WOLFSSL_KYBER1024) || defined(WOLFSSL_WC_ML_KEM_1024)
/* Compress the vector of polynomials into a byte array with 11 bits each.
 *
 * @param  [out]  b       Array of bytes.
 * @param  [in]   v       Vector of polynomials.
 */
static void kyber_vec_compress_11_c(byte* r, sword16* v)
{
    unsigned int i;
    unsigned int j;
#ifdef WOLFSSL_KYBER_SMALL
    unsigned int k;
#endif

    for (i = 0; i < 4; i++) {
        /* Reduce each coefficient to mod q. */
        kyber_csubq_c(v + i * KYBER_N);
        /* All values are now positive. */
    }

    /* Each polynomial. */
    for (i = 0; i < 4; i++) {
        /* Each 8 polynomial coefficients. */
        for (j = 0; j < KYBER_N; j += 8) {
        #ifdef WOLFSSL_KYBER_SMALL
            sword16 t[8];
            /* Compress eight polynomial values to 11 bits each. */
            for (k = 0; k < 8; k++) {
                t[k] = TO_COMP_WORD_11(v, i, j, k);
            }

            /* Pack eight 11-bit values into byte array. */
            r[ 0] = (t[0] >>  0);
            r[ 1] = (t[0] >>  8) | (t[1] << 3);
            r[ 2] = (t[1] >>  5) | (t[2] << 6);
            r[ 3] = (t[2] >>  2);
            r[ 4] = (t[2] >> 10) | (t[3] << 1);
            r[ 5] = (t[3] >>  7) | (t[4] << 4);
            r[ 6] = (t[4] >>  4) | (t[5] << 7);
            r[ 7] = (t[5] >>  1);
            r[ 8] = (t[5] >>  9) | (t[6] << 2);
            r[ 9] = (t[6] >>  6) | (t[7] << 5);
            r[10] = (t[7] >>  3);
        #else
            /* Compress eight polynomial values to 11 bits each. */
            sword16 t0 = TO_COMP_WORD_11(v, i, j, 0);
            sword16 t1 = TO_COMP_WORD_11(v, i, j, 1);
            sword16 t2 = TO_COMP_WORD_11(v, i, j, 2);
            sword16 t3 = TO_COMP_WORD_11(v, i, j, 3);
            sword16 t4 = TO_COMP_WORD_11(v, i, j, 4);
            sword16 t5 = TO_COMP_WORD_11(v, i, j, 5);
            sword16 t6 = TO_COMP_WORD_11(v, i, j, 6);
            sword16 t7 = TO_COMP_WORD_11(v, i, j, 7);

            /* Pack eight 11-bit values into byte array. */
            r[ 0] = (t0 >>  0);
            r[ 1] = (t0 >>  8) | (t1 << 3);
            r[ 2] = (t1 >>  5) | (t2 << 6);
            r[ 3] = (t2 >>  2);
            r[ 4] = (t2 >> 10) | (t3 << 1);
            r[ 5] = (t3 >>  7) | (t4 << 4);
            r[ 6] = (t4 >>  4) | (t5 << 7);
            r[ 7] = (t5 >>  1);
            r[ 8] = (t5 >>  9) | (t6 << 2);
            r[ 9] = (t6 >>  6) | (t7 << 5);
            r[10] = (t7 >>  3);
        #endif

            /* Move over set bytes. */
            r += 11;
        }
    }
}

/* Compress the vector of polynomials into a byte array with 11 bits each.
 *
 * @param  [out]  b       Array of bytes.
 * @param  [in]   v       Vector of polynomials.
 */
void kyber_vec_compress_11(byte* r, sword16* v)
{
#ifdef USE_INTEL_SPEEDUP
    if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        kyber_compress_11_avx2(r, v, 4);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
        kyber_vec_compress_11_c(r, v);
    }
}
#endif

/* Decompress a 10 bit value.
 *
 * @param  [in]  v  Vector of polynomials.
 * @param  [in]  i  Index of polynomial in vector.
 * @param  [in]  j  Index into polynomial.
 * @param  [in]  k  Offset from indices.
 * @param  [in]  t  Value to decompress.
 * @return  Decompressed value.
 */
#define DECOMP_10(v, i, j, k, t) \
    v[(i) * KYBER_N + 4 * (j) + (k)] = \
        (word16)((((word32)((t) & 0x3ff) * KYBER_Q) + 512) >> 10)

/* Decompress an 11 bit value.
 *
 * @param  [in]  v  Vector of polynomials.
 * @param  [in]  i  Index of polynomial in vector.
 * @param  [in]  j  Index into polynomial.
 * @param  [in]  k  Offset from indices.
 * @param  [in]  t  Value to decompress.
 * @return  Decompressed value.
 */
#define DECOMP_11(v, i, j, k, t) \
    v[(i) * KYBER_N + 8 * (j) + (k)] = \
        (word16)((((word32)((t) & 0x7ff) * KYBER_Q) + 1024) >> 11)

#if defined(WOLFSSL_KYBER512) || defined(WOLFSSL_WC_ML_KEM_512) || \
    defined(WOLFSSL_KYBER768) || defined(WOLFSSL_WC_ML_KEM_768)
/* Decompress the byte array of packed 10 bits into vector of polynomials.
 *
 * @param  [out]  v       Vector of polynomials.
 * @param  [in]   b       Array of bytes.
 * @param  [in]   kp      Number of polynomials in vector.
 */
static void kyber_vec_decompress_10_c(sword16* v, const unsigned char* b,
    unsigned int kp)
{
    unsigned int i;
    unsigned int j;
#ifdef WOLFSSL_KYBER_SMALL
    unsigned int k;
#endif

    /* Each polynomial. */
    for (i = 0; i < kp; i++) {
        /* Each 4 polynomial coefficients. */
        for (j = 0; j < KYBER_N / 4; j++) {
        #ifdef WOLFSSL_KYBER_SMALL
            word16 t[4];
            /* Extract out 4 values of 10 bits each. */
            t[0] = (b[0] >> 0) | ((word16)b[ 1] << 8);
            t[1] = (b[1] >> 2) | ((word16)b[ 2] << 6);
            t[2] = (b[2] >> 4) | ((word16)b[ 3] << 4);
            t[3] = (b[3] >> 6) | ((word16)b[ 4] << 2);
            b += 5;

            /* Decompress 4 values. */
            for (k = 0; k < 4; k++) {
                DECOMP_10(v, i, j, k, t[k]);
            }
        #else
            /* Extract out 4 values of 10 bits each. */
            sword16 t0 = (b[0] >> 0) | ((word16)b[ 1] << 8);
            sword16 t1 = (b[1] >> 2) | ((word16)b[ 2] << 6);
            sword16 t2 = (b[2] >> 4) | ((word16)b[ 3] << 4);
            sword16 t3 = (b[3] >> 6) | ((word16)b[ 4] << 2);
            b += 5;

            /* Decompress 4 values. */
            DECOMP_10(v, i, j, 0, t0);
            DECOMP_10(v, i, j, 1, t1);
            DECOMP_10(v, i, j, 2, t2);
            DECOMP_10(v, i, j, 3, t3);
        #endif
        }
    }
}

/* Decompress the byte array of packed 10 bits into vector of polynomials.
 *
 * @param  [out]  v       Vector of polynomials.
 * @param  [in]   b       Array of bytes.
 * @param  [in]   kp      Number of polynomials in vector.
 */
void kyber_vec_decompress_10(sword16* v, const unsigned char* b,
    unsigned int kp)
{
#ifdef USE_INTEL_SPEEDUP
    if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        kyber_decompress_10_avx2(v, b, kp);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
        kyber_vec_decompress_10_c(v, b, kp);
    }
}
#endif
#if defined(WOLFSSL_KYBER1024) || defined(WOLFSSL_WC_ML_KEM_1024)
/* Decompress the byte array of packed 11 bits into vector of polynomials.
 *
 * @param  [out]  v       Vector of polynomials.
 * @param  [in]   b       Array of bytes.
 */
static void kyber_vec_decompress_11_c(sword16* v, const unsigned char* b)
{
    unsigned int i;
    unsigned int j;
#ifdef WOLFSSL_KYBER_SMALL
    unsigned int k;
#endif

    /* Each polynomial. */
    for (i = 0; i < 4; i++) {
        /* Each 8 polynomial coefficients. */
        for (j = 0; j < KYBER_N / 8; j++) {
        #ifdef WOLFSSL_KYBER_SMALL
            word16 t[8];
            /* Extract out 8 values of 11 bits each. */
            t[0] = (b[0] >> 0) | ((word16)b[ 1] << 8);
            t[1] = (b[1] >> 3) | ((word16)b[ 2] << 5);
            t[2] = (b[2] >> 6) | ((word16)b[ 3] << 2) |
                   ((word16)b[4] << 10);
            t[3] = (b[4] >> 1) | ((word16)b[ 5] << 7);
            t[4] = (b[5] >> 4) | ((word16)b[ 6] << 4);
            t[5] = (b[6] >> 7) | ((word16)b[ 7] << 1) |
                   ((word16)b[8] <<  9);
            t[6] = (b[8] >> 2) | ((word16)b[ 9] << 6);
            t[7] = (b[9] >> 5) | ((word16)b[10] << 3);
            b += 11;

            /* Decompress 8 values. */
            for (k = 0; k < 8; k++) {
                DECOMP_11(v, i, j, k, t[k]);
            }
        #else
            /* Extract out 8 values of 11 bits each. */
            sword16 t0 = (b[0] >> 0) | ((word16)b[ 1] << 8);
            sword16 t1 = (b[1] >> 3) | ((word16)b[ 2] << 5);
            sword16 t2 = (b[2] >> 6) | ((word16)b[ 3] << 2) |
                   ((word16)b[4] << 10);
            sword16 t3 = (b[4] >> 1) | ((word16)b[ 5] << 7);
            sword16 t4 = (b[5] >> 4) | ((word16)b[ 6] << 4);
            sword16 t5 = (b[6] >> 7) | ((word16)b[ 7] << 1) |
                   ((word16)b[8] <<  9);
            sword16 t6 = (b[8] >> 2) | ((word16)b[ 9] << 6);
            sword16 t7 = (b[9] >> 5) | ((word16)b[10] << 3);
            b += 11;

            /* Decompress 8 values. */
            DECOMP_11(v, i, j, 0, t0);
            DECOMP_11(v, i, j, 1, t1);
            DECOMP_11(v, i, j, 2, t2);
            DECOMP_11(v, i, j, 3, t3);
            DECOMP_11(v, i, j, 4, t4);
            DECOMP_11(v, i, j, 5, t5);
            DECOMP_11(v, i, j, 6, t6);
            DECOMP_11(v, i, j, 7, t7);
        #endif
        }
    }
}

/* Decompress the byte array of packed 11 bits into vector of polynomials.
 *
 * @param  [out]  v       Vector of polynomials.
 * @param  [in]   b       Array of bytes.
 */
void kyber_vec_decompress_11(sword16* v, const unsigned char* b)
{
#ifdef USE_INTEL_SPEEDUP
    if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        kyber_decompress_11_avx2(v, b, 4);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
        kyber_vec_decompress_11_c(v, b);
    }
}
#endif

#ifdef CONV_WITH_DIV

/* Compress value.
 *
 * Uses div operator that may be slow.
 *
 * @param  [in]  v  Vector of polynomials.
 * @param  [in]  i  Index into polynomial.
 * @param  [in]  j  Offset from indices.
 * @param  [in]  s  Shift amount to apply to value being compressed.
 * @param  [in]  m  Mask to apply get the require number of bits.
 * @return  Compressed value.
 */
#define TO_COMP_WORD(v, i, j, s, m) \
    ((((word32)v[i + j] << s) + KYBER_Q_HALF) / KYBER_Q) & m

/* Compress value to 4 bits.
 *
 * Uses mul instead of div.
 *
 * @param  [in]  p  Polynomial.
 * @param  [in]  i  Index into polynomial.
 * @param  [in]  j  Offset from indices.
 * @return  Compressed value.
 */
#define TO_COMP_WORD_4(p, i, j) \
    TO_COMP_WORD(p, i, j, 4, 0xf)

/* Compress value to 5 bits.
 *
 * Uses mul instead of div.
 *
 * @param  [in]  p  Polynomial.
 * @param  [in]  i  Index into polynomial.
 * @param  [in]  j  Offset from indices.
 * @return  Compressed value.
 */
#define TO_COMP_WORD_5(p, i, j) \
    TO_COMP_WORD(p, i, j, 5, 0x1f)

#else

/* Multiplier that does div q. */
#define KYBER_V28         ((word32)(((1U << 28) + KYBER_Q_HALF)) / KYBER_Q)
/* Multiplier times half of q. */
#define KYBER_V28_HALF    ((word32)(KYBER_V28 * (KYBER_Q_HALF + 1)))

/* Multiplier that does div q. */
#define KYBER_V27         ((word32)(((1U << 27) + KYBER_Q_HALF)) / KYBER_Q)
/* Multiplier times half of q. */
#define KYBER_V27_HALF    ((word32)(KYBER_V27 * KYBER_Q_HALF))

/* Compress value to 4 bits.
 *
 * Uses mul instead of div.
 *
 * @param  [in]  p  Polynomial.
 * @param  [in]  i  Index into polynomial.
 * @param  [in]  j  Offset from indices.
 * @return  Compressed value.
 */
#define TO_COMP_WORD_4(p, i, j) \
    ((((KYBER_V28 << 4) * (p)[(i) + (j)]) + KYBER_V28_HALF) >> 28)

/* Compress value to 5 bits.
 *
 * Uses mul instead of div.
 *
 * @param  [in]  p  Polynomial.
 * @param  [in]  i  Index into polynomial.
 * @param  [in]  j  Offset from indices.
 * @return  Compressed value.
 */
#define TO_COMP_WORD_5(p, i, j) \
    ((((KYBER_V27 << 5) * (p)[(i) + (j)]) + KYBER_V27_HALF) >> 27)

#endif /* CONV_WITH_DIV */

#if defined(WOLFSSL_KYBER512) || defined(WOLFSSL_WC_ML_KEM_512) || \
    defined(WOLFSSL_KYBER768) || defined(WOLFSSL_WC_ML_KEM_768)
/* Compress a polynomial into byte array - on coefficients into 4 bits.
 *
 * @param  [out]  b       Array of bytes.
 * @param  [in]   p       Polynomial.
 */
static void kyber_compress_4_c(byte* b, sword16* p)
{
    unsigned int i;
#ifdef WOLFSSL_KYBER_SMALL
    unsigned int j;
    byte t[8];
#endif

    /* Reduce each coefficients to mod q. */
    kyber_csubq_c(p);
    /* All values are now positive. */

    /* Each 8 polynomial coefficients. */
    for (i = 0; i < KYBER_N; i += 8) {
    #ifdef WOLFSSL_KYBER_SMALL
        /* Compress eight polynomial values to 4 bits each. */
        for (j = 0; j < 8; j++) {
            t[j] = TO_COMP_WORD_4(p, i, j);
        }

        b[0] = t[0] | (t[1] << 4);
        b[1] = t[2] | (t[3] << 4);
        b[2] = t[4] | (t[5] << 4);
        b[3] = t[6] | (t[7] << 4);
    #else
        /* Compress eight polynomial values to 4 bits each. */
        byte t0 = TO_COMP_WORD_4(p, i, 0);
        byte t1 = TO_COMP_WORD_4(p, i, 1);
        byte t2 = TO_COMP_WORD_4(p, i, 2);
        byte t3 = TO_COMP_WORD_4(p, i, 3);
        byte t4 = TO_COMP_WORD_4(p, i, 4);
        byte t5 = TO_COMP_WORD_4(p, i, 5);
        byte t6 = TO_COMP_WORD_4(p, i, 6);
        byte t7 = TO_COMP_WORD_4(p, i, 7);

        /* Pack eight 4-bit values into byte array. */
        b[0] = t0 | (t1 << 4);
        b[1] = t2 | (t3 << 4);
        b[2] = t4 | (t5 << 4);
        b[3] = t6 | (t7 << 4);
    #endif

        /* Move over set bytes. */
        b += 4;
    }
}

/* Compress a polynomial into byte array - on coefficients into 4 bits.
 *
 * @param  [out]  b       Array of bytes.
 * @param  [in]   p       Polynomial.
 */
void kyber_compress_4(byte* b, sword16* p)
{
#ifdef USE_INTEL_SPEEDUP
    if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        kyber_compress_4_avx2(b, p);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
        kyber_compress_4_c(b, p);
    }
}
#endif
#if defined(WOLFSSL_KYBER1024) || defined(WOLFSSL_WC_ML_KEM_1024)
/* Compress a polynomial into byte array - on coefficients into 5 bits.
 *
 * @param  [out]  b       Array of bytes.
 * @param  [in]   p       Polynomial.
 */
static void kyber_compress_5_c(byte* b, sword16* p)
{
    unsigned int i;
#ifdef WOLFSSL_KYBER_SMALL
    unsigned int j;
    byte t[8];
#endif

    /* Reduce each coefficients to mod q. */
    kyber_csubq_c(p);
    /* All values are now positive. */

    for (i = 0; i < KYBER_N; i += 8) {
    #ifdef WOLFSSL_KYBER_SMALL
        /* Compress eight polynomial values to 5 bits each. */
        for (j = 0; j < 8; j++) {
            t[j] = TO_COMP_WORD_5(p, i, j);
        }

        /* Pack 5 bits into byte array. */
        b[0] = (t[0] >> 0) | (t[1] << 5);
        b[1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
        b[2] = (t[3] >> 1) | (t[4] << 4);
        b[3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
        b[4] = (t[6] >> 2) | (t[7] << 3);
    #else
        /* Compress eight polynomial values to 5 bits each. */
        byte t0 = TO_COMP_WORD_5(p, i, 0);
        byte t1 = TO_COMP_WORD_5(p, i, 1);
        byte t2 = TO_COMP_WORD_5(p, i, 2);
        byte t3 = TO_COMP_WORD_5(p, i, 3);
        byte t4 = TO_COMP_WORD_5(p, i, 4);
        byte t5 = TO_COMP_WORD_5(p, i, 5);
        byte t6 = TO_COMP_WORD_5(p, i, 6);
        byte t7 = TO_COMP_WORD_5(p, i, 7);

        /* Pack eight 5-bit values into byte array. */
        b[0] = (t0 >> 0) | (t1 << 5);
        b[1] = (t1 >> 3) | (t2 << 2) | (t3 << 7);
        b[2] = (t3 >> 1) | (t4 << 4);
        b[3] = (t4 >> 4) | (t5 << 1) | (t6 << 6);
        b[4] = (t6 >> 2) | (t7 << 3);
    #endif

        /* Move over set bytes. */
        b += 5;
    }
}

/* Compress a polynomial into byte array - on coefficients into 5 bits.
 *
 * @param  [out]  b       Array of bytes.
 * @param  [in]   p       Polynomial.
 */
void kyber_compress_5(byte* b, sword16* p)
{
#ifdef USE_INTEL_SPEEDUP
    if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        kyber_compress_5_avx2(b, p);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
        kyber_compress_5_c(b, p);
    }
}
#endif

/* Decompress a 4 bit value.
 *
 * @param  [in]  p  Polynomial.
 * @param  [in]  i  Index into polynomial.
 * @param  [in]  j  Offset from indices.
 * @param  [in]  t  Value to decompress.
 * @return  Decompressed value.
 */
#define DECOMP_4(p, i, j, t) \
    p[(i) + (j)] = ((word16)((t) * KYBER_Q) + 8) >> 4

/* Decompress a 5 bit value.
 *
 * @param  [in]  p  Polynomial.
 * @param  [in]  i  Index into polynomial.
 * @param  [in]  j  Offset from indices.
 * @param  [in]  t  Value to decompress.
 * @return  Decompressed value.
 */
#define DECOMP_5(p, i, j, t) \
    p[(i) + (j)] = (((word32)((t) & 0x1f) * KYBER_Q) + 16) >> 5

#if defined(WOLFSSL_KYBER512) || defined(WOLFSSL_WC_ML_KEM_512) || \
    defined(WOLFSSL_KYBER768) || defined(WOLFSSL_WC_ML_KEM_768)
/* Decompress the byte array of packed 4 bits into polynomial.
 *
 * @param  [out]  p       Polynomial.
 * @param  [in]   b       Array of bytes.
 */
static void kyber_decompress_4_c(sword16* p, const unsigned char* b)
{
    unsigned int i;

    /* 2 coefficients at a time. */
    for (i = 0; i < KYBER_N; i += 2) {
        /* 2 coefficients decompressed from one byte. */
        DECOMP_4(p, i, 0, b[0] & 0xf);
        DECOMP_4(p, i, 1, b[0] >>  4);
        b += 1;
    }
}

/* Decompress the byte array of packed 4 bits into polynomial.
 *
 * @param  [out]  p       Polynomial.
 * @param  [in]   b       Array of bytes.
 */
void kyber_decompress_4(sword16* p, const unsigned char* b)
{
#ifdef USE_INTEL_SPEEDUP
    if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        kyber_decompress_4_avx2(p, b);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
        kyber_decompress_4_c(p, b);
    }
}
#endif
#if defined(WOLFSSL_KYBER1024) || defined(WOLFSSL_WC_ML_KEM_1024)
/* Decompress the byte array of packed 5 bits into polynomial.
 *
 * @param  [out]  p       Polynomial.
 * @param  [in]   b       Array of bytes.
 */
static void kyber_decompress_5_c(sword16* p, const unsigned char* b)
{
    unsigned int i;

    /* Each 8 polynomial coefficients. */
    for (i = 0; i < KYBER_N; i += 8) {
    #ifdef WOLFSSL_KYBER_SMALL
        unsigned int j;
        byte t[8];

        /* Extract out 8 values of 5 bits each. */
        t[0] = (b[0] >> 0);
        t[1] = (b[0] >> 5) | (b[1] << 3);
        t[2] = (b[1] >> 2);
        t[3] = (b[1] >> 7) | (b[2] << 1);
        t[4] = (b[2] >> 4) | (b[3] << 4);
        t[5] = (b[3] >> 1);
        t[6] = (b[3] >> 6) | (b[4] << 2);
        t[7] = (b[4] >> 3);
        b += 5;

        /* Decompress 8 values. */
        for (j = 0; j < 8; j++) {
            DECOMP_5(p, i, j, t[j]);
        }
    #else
        /* Extract out 8 values of 5 bits each. */
        byte t0 = (b[0] >> 0);
        byte t1 = (b[0] >> 5) | (b[1] << 3);
        byte t2 = (b[1] >> 2);
        byte t3 = (b[1] >> 7) | (b[2] << 1);
        byte t4 = (b[2] >> 4) | (b[3] << 4);
        byte t5 = (b[3] >> 1);
        byte t6 = (b[3] >> 6) | (b[4] << 2);
        byte t7 = (b[4] >> 3);
        b += 5;

        /* Decompress 8 values. */
        DECOMP_5(p, i, 0, t0);
        DECOMP_5(p, i, 1, t1);
        DECOMP_5(p, i, 2, t2);
        DECOMP_5(p, i, 3, t3);
        DECOMP_5(p, i, 4, t4);
        DECOMP_5(p, i, 5, t5);
        DECOMP_5(p, i, 6, t6);
        DECOMP_5(p, i, 7, t7);
    #endif
    }
}

/* Decompress the byte array of packed 5 bits into polynomial.
 *
 * @param  [out]  p       Polynomial.
 * @param  [in]   b       Array of bytes.
 */
void kyber_decompress_5(sword16* p, const unsigned char* b)
{
#ifdef USE_INTEL_SPEEDUP
    if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        kyber_decompress_5_avx2(p, b);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
        kyber_decompress_5_c(p, b);
    }
}
#endif

/******************************************************************************/

#if !(defined(__aarch64__) && defined(WOLFSSL_ARMASM))
/* Convert bit from byte to 0 or (KYBER_Q + 1) / 2.
 *
 * Constant time implementation.
 * XOR in kyber_opt_blocker to ensure optimizer doesn't know what will be ANDed
 * with KYBER_Q_1_HALF and can't optimize to non-constant time code.
 *
 * @param  [out]  p    Polynomial to hold converted value.
 * @param  [in]   msg  Message to get bit from byte from.
 * @param  [in]   i    Index of byte from message.
 * @param  [in]   j    Index of bit in byte.
 */
#define FROM_MSG_BIT(p, msg, i, j) \
    ((p)[8 * (i) + (j)] = (((sword16)0 - (sword16)(((msg)[i] >> (j)) & 1)) ^ \
                          kyber_opt_blocker) & KYBER_Q_1_HALF)

/* Convert message to polynomial.
 *
 * @param  [out]  p    Polynomial.
 * @param  [in]   msg  Message as a byte array.
 */
static void kyber_from_msg_c(sword16* p, const byte* msg)
{
    unsigned int i;

    /* For each byte of the message. */
    for (i = 0; i < KYBER_N / 8; i++) {
    #ifdef WOLFSSL_KYBER_SMALL
        unsigned int j;
        /* For each bit of the message. */
        for (j = 0; j < 8; j++) {
            FROM_MSG_BIT(p, msg, i, j);
        }
    #else
        FROM_MSG_BIT(p, msg, i, 0);
        FROM_MSG_BIT(p, msg, i, 1);
        FROM_MSG_BIT(p, msg, i, 2);
        FROM_MSG_BIT(p, msg, i, 3);
        FROM_MSG_BIT(p, msg, i, 4);
        FROM_MSG_BIT(p, msg, i, 5);
        FROM_MSG_BIT(p, msg, i, 6);
        FROM_MSG_BIT(p, msg, i, 7);
    #endif
    }
}

/* Convert message to polynomial.
 *
 * @param  [out]  p    Polynomial.
 * @param  [in]   msg  Message as a byte array.
 */
void kyber_from_msg(sword16* p, const byte* msg)
{
#ifdef USE_INTEL_SPEEDUP
    if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        kyber_from_msg_avx2(p, msg);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
        kyber_from_msg_c(p, msg);
    }
}

#ifdef CONV_WITH_DIV

/* Convert to value to bit.
 *
 * Uses div operator that may be slow.
 *
 * @param  [out]  m   Message.
 * @param  [in]   p   Polynomial.
 * @param  [in]   i   Index of byte in message.
 * @param  [in]   j   Index of bit in byte.
 */
#define TO_MSG_BIT(m, p, i, j) \
    m[i] |= (((((sword16)p[8 * i + j] << 1) + KYBER_Q_HALF) / KYBER_Q) & 1) << j

#else

/* Multiplier that does div q. */
#define KYBER_V31       (((1U << 31) + (KYBER_Q / 2)) / KYBER_Q)
/* 2 * multiplier that does div q. Only need bit 32 of result. */
#define KYBER_V31_2     ((word32)(KYBER_V31 * 2))
/* Multiplier times half of q. */
#define KYBER_V31_HALF    ((word32)(KYBER_V31 * KYBER_Q_HALF))

/* Convert to value to bit.
 *
 * Uses mul instead of div.
 *
 * @param  [out]  m   Message.
 * @param  [in]   p   Polynomial.
 * @param  [in]   i   Index of byte in message.
 * @param  [in]   j   Index of bit in byte.
 */
#define TO_MSG_BIT(m, p, i, j) \
    (m)[i] |= ((word32)((KYBER_V31_2 * (p)[8 * (i) + (j)]) + KYBER_V31_HALF) >> 31) << (j)

#endif /* CONV_WITH_DIV */

/* Convert polynomial to message.
 *
 * @param  [out]  msg  Message as a byte array.
 * @param  [in]   p    Polynomial.
 */
static void kyber_to_msg_c(byte* msg, sword16* p)
{
    unsigned int i;

    /* Reduce each coefficient to mod q. */
    kyber_csubq_c(p);
    /* All values are now in range. */

    for (i = 0; i < KYBER_N / 8; i++) {
    #ifdef WOLFSSL_KYBER_SMALL
        unsigned int j;
        msg[i] = 0;
        for (j = 0; j < 8; j++) {
            TO_MSG_BIT(msg, p, i, j);
        }
    #else
        msg[i] = 0;
        TO_MSG_BIT(msg, p, i, 0);
        TO_MSG_BIT(msg, p, i, 1);
        TO_MSG_BIT(msg, p, i, 2);
        TO_MSG_BIT(msg, p, i, 3);
        TO_MSG_BIT(msg, p, i, 4);
        TO_MSG_BIT(msg, p, i, 5);
        TO_MSG_BIT(msg, p, i, 6);
        TO_MSG_BIT(msg, p, i, 7);
    #endif
    }
}

/* Convert polynomial to message.
 *
 * @param  [out]  msg  Message as a byte array.
 * @param  [in]   p    Polynomial.
 */
void kyber_to_msg(byte* msg, sword16* p)
{
#ifdef USE_INTEL_SPEEDUP
     if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        /* Convert the polynomial into a array of bytes (message). */
        kyber_to_msg_avx2(msg, p);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
        kyber_to_msg_c(msg, p);
    }
}
#else
/* Convert message to polynomial.
 *
 * @param  [out]  p    Polynomial.
 * @param  [in]   msg  Message as a byte array.
 */
void kyber_from_msg(sword16* p, const byte* msg)
{
    kyber_from_msg_neon(p, msg);
}

/* Convert polynomial to message.
 *
 * @param  [out]  msg  Message as a byte array.
 * @param  [in]   p    Polynomial.
 */
void kyber_to_msg(byte* msg, sword16* p)
{
    kyber_to_msg_neon(msg, p);
}
#endif

/******************************************************************************/

/* Convert bytes to polynomial.
 *
 * Consecutive 12 bits hold each coefficient of polynomial.
 * Used in decoding private and public keys.
 *
 * @param  [out]  p  Vector of polynomials.
 * @param  [in]   b  Array of bytes.
 * @param  [in]   k  Number of polynomials in vector.
 */
static void kyber_from_bytes_c(sword16* p, const byte* b, int k)
{
    int i;
    int j;

    for (j = 0; j < k; j++) {
        for (i = 0; i < KYBER_N / 2; i++) {
            p[2 * i + 0] = ((b[3 * i + 0] >> 0) |
                            ((word16)b[3 * i + 1] << 8)) & 0xfff;
            p[2 * i + 1] = ((b[3 * i + 1] >> 4) |
                            ((word16)b[3 * i + 2] << 4)) & 0xfff;
        }
        p += KYBER_N;
        b += KYBER_POLY_SIZE;
    }
}

/* Convert bytes to polynomial.
 *
 * Consecutive 12 bits hold each coefficient of polynomial.
 * Used in decoding private and public keys.
 *
 * @param  [out]  p  Vector of polynomials.
 * @param  [in]   b  Array of bytes.
 * @param  [in]   k  Number of polynomials in vector.
 */
void kyber_from_bytes(sword16* p, const byte* b, int k)
{
#ifdef USE_INTEL_SPEEDUP
     if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        int i;

        for (i = 0; i < k; i++) {
            kyber_from_bytes_avx2(p, b);
            p += KYBER_N;
            b += KYBER_POLY_SIZE;
        }

        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
        kyber_from_bytes_c(p, b, k);
    }
}

/* Convert polynomial to bytes.
 *
 * Consecutive 12 bits hold each coefficient of polynomial.
 * Used in encoding private and public keys.
 *
 * @param  [out]  b  Array of bytes.
 * @param  [in]   p  Polynomial.
 * @param  [in]   k  Number of polynomials in vector.
 */
static void kyber_to_bytes_c(byte* b, sword16* p, int k)
{
    int i;
    int j;

    /* Reduce each coefficient to mod q. */
    kyber_csubq_c(p);
    /* All values are now positive. */

    for (j = 0; j < k; j++) {
        for (i = 0; i < KYBER_N / 2; i++) {
            word16 t0 = p[2 * i];
            word16 t1 = p[2 * i + 1];
            b[3 * i + 0] = (t0 >> 0);
            b[3 * i + 1] = (t0 >> 8) | t1 << 4;
            b[3 * i + 2] = (t1 >> 4);
        }
        p += KYBER_N;
        b += KYBER_POLY_SIZE;
    }
}

/* Convert polynomial to bytes.
 *
 * Consecutive 12 bits hold each coefficient of polynomial.
 * Used in encoding private and public keys.
 *
 * @param  [out]  b  Array of bytes.
 * @param  [in]   p  Polynomial.
 * @param  [in]   k  Number of polynomials in vector.
 */
void kyber_to_bytes(byte* b, sword16* p, int k)
{
#ifdef USE_INTEL_SPEEDUP
     if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        int i;

        for (i = 0; i < k; i++) {
            kyber_to_bytes_avx2(b, p);
            p += KYBER_N;
            b += KYBER_POLY_SIZE;
        }

        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
        kyber_to_bytes_c(b, p, k);
    }
}

#endif /* WOLFSSL_WC_KYBER */
