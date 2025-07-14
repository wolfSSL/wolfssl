/* wc_mlkem_poly.c
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

/* Implementation based on FIPS 203:
 *   https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
 *
 * Original implementation based on NIST 3rd Round submission package.
 * See link at:
 *   https://csrc.nist.gov/Projects/post-quantum-cryptography/
 *   post-quantum-cryptography-standardization/round-3-submissions
 */

/* Implementation of the functions that operate on polynomials or vectors of
 * polynomials.
 */

/* Possible Kyber options:
 *
 * WOLFSSL_WC_MLKEM                                           Default: OFF
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
 * WOLFSSL_MLKEM_NO_LARGE_CODE                                Default: OFF
 *   Compiles smaller, fast code size with a speed trade-off.
 * WOLFSSL_MLKEM_SMALL                                        Default: OFF
 *   Compiles to small code size with a speed trade-off.
 * WOLFSSL_SMALL_STACK                                        Default: OFF
 *   Use less stack by dynamically allocating local variables.
 *
 * WOLFSSL_MLKEM_NTT_UNROLL                                   Default: OFF
 *   Enable an alternative NTT implementation that may be faster on some
 *   platforms and is smaller in code size.
 * WOLFSSL_MLKEM_INVNTT_UNROLL                                Default: OFF
 *   Enables an alternative inverse NTT implementation that may be faster on
 *   some platforms and is smaller in code size.
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#ifdef WC_MLKEM_NO_ASM
    #undef USE_INTEL_SPEEDUP
    #undef WOLFSSL_ARMASM
    #undef WOLFSSL_RISCV_ASM
#endif

#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <wolfssl/wolfcrypt/cpuid.h>

#ifdef WOLFSSL_WC_MLKEM

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#if defined(WOLFSSL_MLKEM_MAKEKEY_SMALL_MEM) || \
    defined(WOLFSSL_MLKEM_ENCAPSULATE_SMALL_MEM)
static int mlkem_gen_matrix_i(MLKEM_PRF_T* prf, sword16* a, int k, byte* seed,
    int i, int transposed);
static int mlkem_get_noise_i(MLKEM_PRF_T* prf, int k, sword16* vec2,
    byte* seed, int i, int make);
static int mlkem_get_noise_eta2_c(MLKEM_PRF_T* prf, sword16* p,
    const byte* seed);
#endif

/* Declared in wc_mlkem.c to stop compiler optimizer from simplifying. */
extern volatile sword16 mlkem_opt_blocker;

#if defined(USE_INTEL_SPEEDUP) || (defined(__aarch64__) && \
    defined(WOLFSSL_ARMASM))
static word32 cpuid_flags = 0;
#endif

/* Half of Q plus one. Converted message bit value of 1. */
#define MLKEM_Q_1_HALF      ((MLKEM_Q + 1) / 2)
/* Half of Q */
#define MLKEM_Q_HALF        (MLKEM_Q / 2)


/* q^-1 mod 2^16 (inverse of 3329 mod 16384) */
#define MLKEM_QINV       62209

/* Used in Barrett Reduction:
 *    r = a mod q
 * => r = a - ((V * a) >> 26) * q), as V based on 2^26
 * V is the multiplier that gets the quotient after shifting.
 */
#define MLKEM_V          (((1U << 26) + (MLKEM_Q / 2)) / MLKEM_Q)

/* Used in converting to Montgomery form.
 * f is the normalizer = 2^k % m.
 * 16-bit value cast to sword32 in use.
 */
#define MLKEM_F          ((1ULL << 32) % MLKEM_Q)

/* Number of bytes in an output block of SHA-3-128 */
#define SHA3_128_BYTES   (WC_SHA3_128_COUNT * 8)
/* Number of bytes in an output block of SHA-3-256 */
#define SHA3_256_BYTES   (WC_SHA3_256_COUNT * 8)

/* Number of blocks to generate for matrix. */
#define GEN_MATRIX_NBLOCKS \
    ((12 * MLKEM_N / 8 * (1 << 12) / MLKEM_Q + XOF_BLOCK_SIZE) / XOF_BLOCK_SIZE)
/* Number of bytes to generate for matrix. */
#define GEN_MATRIX_SIZE     GEN_MATRIX_NBLOCKS * XOF_BLOCK_SIZE


/* Number of random bytes to generate for ETA3. */
#define ETA3_RAND_SIZE     ((3 * MLKEM_N) / 4)
/* Number of random bytes to generate for ETA2. */
#define ETA2_RAND_SIZE     ((2 * MLKEM_N) / 4)


/* Montgomery reduce a.
 *
 * @param  [in]  a  32-bit value to be reduced.
 * @return  Montgomery reduction result.
 */
#define MLKEM_MONT_RED(a) \
    (sword16)(((a) - (sword32)(((sword16)((sword16)(a) * \
                                (sword16)MLKEM_QINV)) * \
                               (sword32)MLKEM_Q)) >> 16)

/* Barrett reduce a. r = a mod q.
 *
 * Converted division to multiplication.
 *
 * @param  [in]  a  16-bit value to be reduced to range of q.
 * @return  Modulo result.
 */
#define MLKEM_BARRETT_RED(a) \
    (sword16)((sword16)(a) - (sword16)((sword16)( \
        ((sword32)((sword32)MLKEM_V * (sword16)(a))) >> 26) * (word16)MLKEM_Q))


/* Zetas for NTT. */
const sword16 zetas[MLKEM_N / 2] = {
    2285, 2571, 2970, 1812, 1493, 1422,  287,  202,
    3158,  622, 1577,  182,  962, 2127, 1855, 1468,
     573, 2004,  264,  383, 2500, 1458, 1727, 3199,
    2648, 1017,  732,  608, 1787,  411, 3124, 1758,
    1223,  652, 2777, 1015, 2036, 1491, 3047, 1785,
     516, 3321, 3009, 2663, 1711, 2167,  126, 1469,
    2476, 3239, 3058,  830,  107, 1908, 3082, 2378,
    2931,  961, 1821, 2604,  448, 2264,  677, 2054,
    2226,  430,  555,  843, 2078,  871, 1550,  105,
     422,  587,  177, 3094, 3038, 2869, 1574, 1653,
    3083,  778, 1159, 3182, 2552, 1483, 2727, 1119,
    1739,  644, 2457,  349,  418,  329, 3173, 3254,
     817, 1097,  603,  610, 1322, 2044, 1864,  384,
    2114, 3193, 1218, 1994, 2455,  220, 2142, 1670,
    2144, 1799, 2051,  794, 1819, 2475, 2459,  478,
    3221, 3021,  996,  991,  958, 1869, 1522, 1628
};


#if !defined(WOLFSSL_ARMASM)
/* Number-Theoretic Transform.
 *
 * FIPS 203, Algorithm 9: NTT(f)
 * Computes the NTT representation f_hat of the given polynomial f element of
 * R_q.
 *   1: f_hat <- f
 *   2: i <- 1
 *   3: for (len <- 128; len >= 2; len <- len/2)
 *   4:     for (start <- 0; start < 256; start <- start + 2.len)
 *   5:         zeta <- zetas^BitRev_7(i) mod q
 *   6:         i <- i + 1
 *   7:         for (j <- start; j < start + len; j++)
 *   8:             t <- zeta.f[j+len]
 *   9:             f_hat[j+len] <- f_hat[j] - t
 *  10:             f_hat[j] <- f_hat[j] - t
 *  11:         end for
 *  12:     end for
 *  13: end for
 *  14: return f_hat
 *
 * @param  [in, out]  r  Polynomial to transform.
 */
static void mlkem_ntt(sword16* r)
{
#ifdef WOLFSSL_MLKEM_SMALL
    unsigned int len;
    unsigned int k;
    unsigned int j;

    /* Step 2 */
    k = 1;
    /* Step 3 */
    for (len = MLKEM_N / 2; len >= 2; len >>= 1) {
        unsigned int start;
        /* Step 4 */
        for (start = 0; start < MLKEM_N; start = j + len) {
            /* Step 5, 6*/
            sword16 zeta = zetas[k++];
            /* Step 7 */
            for (j = start; j < start + len; ++j) {
                /* Step 8 */
                sword32 p = (sword32)zeta * r[j + len];
                sword16 t = MLKEM_MONT_RED(p);
                sword16 rj = r[j];
                /* Step 9 */
                r[j + len] = rj - t;
                /* Step 10 */
                r[j] = rj + t;
            }
        }
    }

    /* Reduce coefficients with quick algorithm. */
    for (j = 0; j < MLKEM_N; ++j) {
        r[j] = MLKEM_BARRETT_RED(r[j]);
    }
#elif defined(WOLFSSL_MLKEM_NO_LARGE_CODE)
    /* Take out the first iteration. */
    unsigned int len;
    unsigned int k = 1;
    unsigned int j;
    unsigned int start;
    sword16 zeta = zetas[k++];

    for (j = 0; j < MLKEM_N / 2; ++j) {
        sword32 p = (sword32)zeta * r[j + MLKEM_N / 2];
        sword16 t = MLKEM_MONT_RED(p);
        sword16 rj = r[j];
        r[j + MLKEM_N / 2] = rj - t;
        r[j] = rj + t;
    }
    for (len = MLKEM_N / 4; len >= 2; len >>= 1) {
        for (start = 0; start < MLKEM_N; start = j + len) {
            zeta = zetas[k++];
            for (j = start; j < start + len; ++j) {
                sword32 p = (sword32)zeta * r[j + len];
                sword16 t = MLKEM_MONT_RED(p);
                sword16 rj = r[j];
                r[j + len] = rj - t;
                r[j] = rj + t;
            }
        }
    }

    /* Reduce coefficients with quick algorithm. */
    for (j = 0; j < MLKEM_N; ++j) {
        r[j] = MLKEM_BARRETT_RED(r[j]);
    }
#elif defined(WOLFSSL_MLKEM_NTT_UNROLL)
    /* Unroll len loop (Step 3). */
    unsigned int k = 1;
    unsigned int j;
    unsigned int start;
    sword16 zeta = zetas[k++];

    /* len = 128 */
    for (j = 0; j < MLKEM_N / 2; ++j) {
        sword32 p = (sword32)zeta * r[j + MLKEM_N / 2];
        sword16 t = MLKEM_MONT_RED(p);
        sword16 rj = r[j];
        r[j + MLKEM_N / 2] = rj - t;
        r[j] = rj + t;
    }
    /* len = 64 */
    for (start = 0; start < MLKEM_N; start += 2 * 64) {
        zeta = zetas[k++];
        for (j = 0; j < 64; ++j) {
            sword32 p = (sword32)zeta * r[start + j + 64];
            sword16 t = MLKEM_MONT_RED(p);
            sword16 rj = r[start + j];
            r[start + j + 64] = rj - t;
            r[start + j] = rj + t;
        }
    }
    /* len = 32 */
    for (start = 0; start < MLKEM_N; start += 2 * 32) {
        zeta = zetas[k++];
        for (j = 0; j < 32; ++j) {
            sword32 p = (sword32)zeta * r[start + j + 32];
            sword16 t = MLKEM_MONT_RED(p);
            sword16 rj = r[start + j];
            r[start + j + 32] = rj - t;
            r[start + j] = rj + t;
        }
    }
    /* len = 16 */
    for (start = 0; start < MLKEM_N; start += 2 * 16) {
        zeta = zetas[k++];
        for (j = 0; j < 16; ++j) {
            sword32 p = (sword32)zeta * r[start + j + 16];
            sword16 t = MLKEM_MONT_RED(p);
            sword16 rj = r[start + j];
            r[start + j + 16] = rj - t;
            r[start + j] = rj + t;
        }
    }
    /* len = 8 */
    for (start = 0; start < MLKEM_N; start += 2 * 8) {
        zeta = zetas[k++];
        for (j = 0; j < 8; ++j) {
            sword32 p = (sword32)zeta * r[start + j + 8];
            sword16 t = MLKEM_MONT_RED(p);
            sword16 rj = r[start + j];
            r[start + j + 8] = rj - t;
            r[start + j] = rj + t;
        }
    }
    /* len = 4 */
    for (start = 0; start < MLKEM_N; start += 2 * 4) {
        zeta = zetas[k++];
        for (j = 0; j < 4; ++j) {
            sword32 p = (sword32)zeta * r[start + j + 4];
            sword16 t = MLKEM_MONT_RED(p);
            sword16 rj = r[start + j];
            r[start + j + 4] = rj - t;
            r[start + j] = rj + t;
        }
    }
    /* len = 2 */
    for (start = 0; start < MLKEM_N; start += 2 * 2) {
        zeta = zetas[k++];
        for (j = 0; j < 2; ++j) {
            sword32 p = (sword32)zeta * r[start + j + 2];
            sword16 t = MLKEM_MONT_RED(p);
            sword16 rj = r[start + j];
            r[start + j + 2] = rj - t;
            r[start + j] = rj + t;
        }
    }
    /* Reduce coefficients with quick algorithm. */
    for (j = 0; j < MLKEM_N; ++j) {
        r[j] = MLKEM_BARRETT_RED(r[j]);
    }
#else
    /* Unroll len (2, 3, 2) and start loops. */
    unsigned int j;
    sword16 t0;
    sword16 t1;
    sword16 t2;
    sword16 t3;

    /* len = 128,64 */
    sword16 zeta128 = zetas[1];
    sword16 zeta64_0 = zetas[2];
    sword16 zeta64_1 = zetas[3];
    for (j = 0; j < MLKEM_N / 8; j++) {
        sword16 r0 = r[j +   0];
        sword16 r1 = r[j +  32];
        sword16 r2 = r[j +  64];
        sword16 r3 = r[j +  96];
        sword16 r4 = r[j + 128];
        sword16 r5 = r[j + 160];
        sword16 r6 = r[j + 192];
        sword16 r7 = r[j + 224];

        t0 = MLKEM_MONT_RED((sword32)zeta128 * r4);
        t1 = MLKEM_MONT_RED((sword32)zeta128 * r5);
        t2 = MLKEM_MONT_RED((sword32)zeta128 * r6);
        t3 = MLKEM_MONT_RED((sword32)zeta128 * r7);
        r4 = r0 - t0;
        r5 = r1 - t1;
        r6 = r2 - t2;
        r7 = r3 - t3;
        r0 += t0;
        r1 += t1;
        r2 += t2;
        r3 += t3;

        t0 = MLKEM_MONT_RED((sword32)zeta64_0 * r2);
        t1 = MLKEM_MONT_RED((sword32)zeta64_0 * r3);
        t2 = MLKEM_MONT_RED((sword32)zeta64_1 * r6);
        t3 = MLKEM_MONT_RED((sword32)zeta64_1 * r7);
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

    /* len = 32,16,8 */
    for (j = 0; j < MLKEM_N; j += 64) {
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

            t0 = MLKEM_MONT_RED((sword32)zeta32 * r4);
            t1 = MLKEM_MONT_RED((sword32)zeta32 * r5);
            t2 = MLKEM_MONT_RED((sword32)zeta32 * r6);
            t3 = MLKEM_MONT_RED((sword32)zeta32 * r7);
            r4 = r0 - t0;
            r5 = r1 - t1;
            r6 = r2 - t2;
            r7 = r3 - t3;
            r0 += t0;
            r1 += t1;
            r2 += t2;
            r3 += t3;

            t0 = MLKEM_MONT_RED((sword32)zeta16_0 * r2);
            t1 = MLKEM_MONT_RED((sword32)zeta16_0 * r3);
            t2 = MLKEM_MONT_RED((sword32)zeta16_1 * r6);
            t3 = MLKEM_MONT_RED((sword32)zeta16_1 * r7);
            r2 = r0 - t0;
            r3 = r1 - t1;
            r6 = r4 - t2;
            r7 = r5 - t3;
            r0 += t0;
            r1 += t1;
            r4 += t2;
            r5 += t3;

            t0 = MLKEM_MONT_RED((sword32)zeta8_0 * r1);
            t1 = MLKEM_MONT_RED((sword32)zeta8_1 * r3);
            t2 = MLKEM_MONT_RED((sword32)zeta8_2 * r5);
            t3 = MLKEM_MONT_RED((sword32)zeta8_3 * r7);
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

    /* len = 4,2 and Final reduction */
    for (j = 0; j < MLKEM_N; j += 8) {
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

        t0 = MLKEM_MONT_RED((sword32)zeta4 * r4);
        t1 = MLKEM_MONT_RED((sword32)zeta4 * r5);
        t2 = MLKEM_MONT_RED((sword32)zeta4 * r6);
        t3 = MLKEM_MONT_RED((sword32)zeta4 * r7);
        r4 = r0 - t0;
        r5 = r1 - t1;
        r6 = r2 - t2;
        r7 = r3 - t3;
        r0 += t0;
        r1 += t1;
        r2 += t2;
        r3 += t3;

        t0 = MLKEM_MONT_RED((sword32)zeta2_0 * r2);
        t1 = MLKEM_MONT_RED((sword32)zeta2_0 * r3);
        t2 = MLKEM_MONT_RED((sword32)zeta2_1 * r6);
        t3 = MLKEM_MONT_RED((sword32)zeta2_1 * r7);
        r2 = r0 - t0;
        r3 = r1 - t1;
        r6 = r4 - t2;
        r7 = r5 - t3;
        r0 += t0;
        r1 += t1;
        r4 += t2;
        r5 += t3;

        r[j + 0] = MLKEM_BARRETT_RED(r0);
        r[j + 1] = MLKEM_BARRETT_RED(r1);
        r[j + 2] = MLKEM_BARRETT_RED(r2);
        r[j + 3] = MLKEM_BARRETT_RED(r3);
        r[j + 4] = MLKEM_BARRETT_RED(r4);
        r[j + 5] = MLKEM_BARRETT_RED(r5);
        r[j + 6] = MLKEM_BARRETT_RED(r6);
        r[j + 7] = MLKEM_BARRETT_RED(r7);
    }
#endif
}

#if !defined(WOLFSSL_MLKEM_NO_ENCAPSULATE) || \
    !defined(WOLFSSL_MLKEM_NO_DECAPSULATE)
/* Zetas for inverse NTT. */
const sword16 zetas_inv[MLKEM_N / 2] = {
    1701, 1807, 1460, 2371, 2338, 2333,  308,  108,
    2851,  870,  854, 1510, 2535, 1278, 1530, 1185,
    1659, 1187, 3109,  874, 1335, 2111,  136, 1215,
    2945, 1465, 1285, 2007, 2719, 2726, 2232, 2512,
      75,  156, 3000, 2911, 2980,  872, 2685, 1590,
    2210,  602, 1846,  777,  147, 2170, 2551,  246,
    1676, 1755,  460,  291,  235, 3152, 2742, 2907,
    3224, 1779, 2458, 1251, 2486, 2774, 2899, 1103,
    1275, 2652, 1065, 2881,  725, 1508, 2368,  398,
     951,  247, 1421, 3222, 2499,  271,   90,  853,
    1860, 3203, 1162, 1618,  666,  320,    8, 2813,
    1544,  282, 1838, 1293, 2314,  552, 2677, 2106,
    1571,  205, 2918, 1542, 2721, 2597, 2312,  681,
     130, 1602, 1871,  829, 2946, 3065, 1325, 2756,
    1861, 1474, 1202, 2367, 3147, 1752, 2707,  171,
    3127, 3042, 1907, 1836, 1517,  359,  758, 1441
};

/* Inverse Number-Theoretic Transform.
 *
 * FIPS 203, Algorithm 10: NTT^-1(f_hat)
 * Computes the polynomial f element of R_q that corresponds to the given NTT
 * representation f element of T_q.
 *   1: f <- f_hat
 *   2: i <- 127
 *   3: for (len <- 2; len <= 128 ; len <- 2.len)
 *   4:     for (start <- 0; start < 256; start <- start + 2.len)
 *   5:         zeta <- zetas^BitRev_7(i) mod q
 *   6:         i <- i - 1
 *   7:         for (j <- start; j < start + len; j++)
 *   8:             t <- f[j]
 *   9:             f[j] < t + f[j + len]
 *  10:             f[j + len] <- zeta.(f[j+len] - t)
 *  11:         end for
 *  12:     end for
 *  13: end for
 *  14: f <- f.3303 mod q
 *  15: return f
 *
 * @param  [in, out]  r  Polynomial to transform.
 */
static void mlkem_invntt(sword16* r)
{
#ifdef WOLFSSL_MLKEM_SMALL
    unsigned int len;
    unsigned int k;
    unsigned int j;
    sword16 zeta;

    /* Step 2 - table reversed */
    k = 0;
    /* Step 3 */
    for (len = 2; len <= MLKEM_N / 2; len <<= 1) {
        unsigned int start;
        /* Step 4 */
        for (start = 0; start < MLKEM_N; start = j + len) {
            /* Step 5, 6 */
            zeta = zetas_inv[k++];
            /* Step 7 */
            for (j = start; j < start + len; ++j) {
                sword32 p;
                /* Step 8 */
                sword16 rj = r[j];
                sword16 rjl = r[j + len];
                /* Step 9 */
                sword16 t = rj + rjl;
                r[j] = MLKEM_BARRETT_RED(t);
                /* Step 10 */
                rjl = rj - rjl;
                p = (sword32)zeta * rjl;
                r[j + len] = MLKEM_MONT_RED(p);
            }
        }
    }

    /* Step 14 */
    zeta = zetas_inv[127];
    for (j = 0; j < MLKEM_N; ++j) {
        sword32 p = (sword32)zeta * r[j];
        r[j] = MLKEM_MONT_RED(p);
    }
#elif defined(WOLFSSL_MLKEM_NO_LARGE_CODE)
    /* Take out last iteration. */
    unsigned int len;
    unsigned int k;
    unsigned int j;
    sword16 zeta;
    sword16 zeta2;

    k = 0;
    for (len = 2; len <= MLKEM_N / 4; len <<= 1) {
        unsigned int start;
        for (start = 0; start < MLKEM_N; start = j + len) {
            zeta = zetas_inv[k++];
            for (j = start; j < start + len; ++j) {
                sword32 p;
                sword16 rj = r[j];
                sword16 rjl = r[j + len];
                sword16 t = rj + rjl;
                r[j] = MLKEM_BARRETT_RED(t);
                rjl = rj - rjl;
                p = (sword32)zeta * rjl;
                r[j + len] = MLKEM_MONT_RED(p);
            }
        }
    }

    zeta = zetas_inv[126];
    zeta2 = zetas_inv[127];
    for (j = 0; j < MLKEM_N / 2; ++j) {
        sword32 p;
        sword16 rj = r[j];
        sword16 rjl = r[j + MLKEM_N / 2];
        sword16 t = rj + rjl;
        rjl = rj - rjl;
        p = (sword32)zeta * rjl;
        r[j] = t;
        r[j + MLKEM_N / 2] = MLKEM_MONT_RED(p);

        p = (sword32)zeta2 * r[j];
        r[j] = MLKEM_MONT_RED(p);
        p = (sword32)zeta2 * r[j + MLKEM_N / 2];
        r[j + MLKEM_N / 2] = MLKEM_MONT_RED(p);
    }
#elif defined(WOLFSSL_MLKEM_INVNTT_UNROLL)
    /* Unroll len loop (Step 3). */
    unsigned int k;
    unsigned int j;
    unsigned int start;
    sword16 zeta;
    sword16 zeta2;

    k = 0;
    /* len = 2 */
    for (start = 0; start < MLKEM_N; start += 2 * 2) {
        zeta = zetas_inv[k++];
        for (j = 0; j < 2; ++j) {
            sword32 p;
            sword16 rj = r[start + j];
            sword16 rjl = r[start + j + 2];
            sword16 t = rj + rjl;
            r[start + j] = t;
            rjl = rj - rjl;
            p = (sword32)zeta * rjl;
            r[start + j + 2] = MLKEM_MONT_RED(p);
        }
    }
    /* len = 4 */
    for (start = 0; start < MLKEM_N; start += 2 * 4) {
        zeta = zetas_inv[k++];
        for (j = 0; j < 4; ++j) {
            sword32 p;
            sword16 rj = r[start + j];
            sword16 rjl = r[start + j + 4];
            sword16 t = rj + rjl;
            r[start + j] = t;
            rjl = rj - rjl;
            p = (sword32)zeta * rjl;
            r[start + j + 4] = MLKEM_MONT_RED(p);
        }
    }
    /* len = 8 */
    for (start = 0; start < MLKEM_N; start += 2 * 8) {
        zeta = zetas_inv[k++];
        for (j = 0; j < 8; ++j) {
            sword32 p;
            sword16 rj = r[start + j];
            sword16 rjl = r[start + j + 8];
            sword16 t = rj + rjl;
            /* Reduce. */
            r[start + j] = MLKEM_BARRETT_RED(t);
            rjl = rj - rjl;
            p = (sword32)zeta * rjl;
            r[start + j + 8] = MLKEM_MONT_RED(p);
        }
    }
    /* len = 16 */
    for (start = 0; start < MLKEM_N; start += 2 * 16) {
        zeta = zetas_inv[k++];
        for (j = 0; j < 16; ++j) {
            sword32 p;
            sword16 rj = r[start + j];
            sword16 rjl = r[start + j + 16];
            sword16 t = rj + rjl;
            r[start + j] = t;
            rjl = rj - rjl;
            p = (sword32)zeta * rjl;
            r[start + j + 16] = MLKEM_MONT_RED(p);
        }
    }
    /* len = 32 */
    for (start = 0; start < MLKEM_N; start += 2 * 32) {
        zeta = zetas_inv[k++];
        for (j = 0; j < 32; ++j) {
            sword32 p;
            sword16 rj = r[start + j];
            sword16 rjl = r[start + j + 32];
            sword16 t = rj + rjl;
            r[start + j] = t;
            rjl = rj - rjl;
            p = (sword32)zeta * rjl;
            r[start + j + 32] = MLKEM_MONT_RED(p);
        }
    }
    /* len = 64 */
    for (start = 0; start < MLKEM_N; start += 2 * 64) {
        zeta = zetas_inv[k++];
        for (j = 0; j < 64; ++j) {
            sword32 p;
            sword16 rj = r[start + j];
            sword16 rjl = r[start + j + 64];
            sword16 t = rj + rjl;
            /* Reduce. */
            r[start + j] = MLKEM_BARRETT_RED(t);
            rjl = rj - rjl;
            p = (sword32)zeta * rjl;
            r[start + j + 64] = MLKEM_MONT_RED(p);
        }
    }
    /* len = 128, 256 */
    zeta = zetas_inv[126];
    zeta2 = zetas_inv[127];
    for (j = 0; j < MLKEM_N / 2; ++j) {
        sword32 p;
        sword16 rj = r[j];
        sword16 rjl = r[j + MLKEM_N / 2];
        sword16 t = rj + rjl;
        rjl = rj - rjl;
        p = (sword32)zeta * rjl;
        r[j] = t;
        r[j + MLKEM_N / 2] = MLKEM_MONT_RED(p);

        p = (sword32)zeta2 * r[j];
        r[j] = MLKEM_MONT_RED(p);
        p = (sword32)zeta2 * r[j + MLKEM_N / 2];
        r[j + MLKEM_N / 2] = MLKEM_MONT_RED(p);
    }
#else
    /* Unroll len (2, 3, 3) and start loops. */
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

    for (j = 0; j < MLKEM_N; j += 8) {
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
        t0 = MLKEM_MONT_RED(p);
        p = (sword32)zeta2_0 * (sword16)(r1 - r3);
        t1 = MLKEM_MONT_RED(p);
        p = (sword32)zeta2_1 * (sword16)(r4 - r6);
        t2 = MLKEM_MONT_RED(p);
        p = (sword32)zeta2_1 * (sword16)(r5 - r7);
        t3 = MLKEM_MONT_RED(p);
        r0 += r2;
        r1 += r3;
        r4 += r6;
        r5 += r7;
        r2 = t0;
        r3 = t1;
        r6 = t2;
        r7 = t3;

        p = (sword32)zeta4 * (sword16)(r0 - r4);
        t0 = MLKEM_MONT_RED(p);
        p = (sword32)zeta4 * (sword16)(r1 - r5);
        t1 = MLKEM_MONT_RED(p);
        p = (sword32)zeta4 * (sword16)(r2 - r6);
        t2 = MLKEM_MONT_RED(p);
        p = (sword32)zeta4 * (sword16)(r3 - r7);
        t3 = MLKEM_MONT_RED(p);
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

    for (j = 0; j < MLKEM_N; j += 64) {
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
            t0 = MLKEM_MONT_RED(p);
            p = (sword32)zeta8_1 * (sword16)(r2 - r3);
            t1 = MLKEM_MONT_RED(p);
            p = (sword32)zeta8_2 * (sword16)(r4 - r5);
            t2 = MLKEM_MONT_RED(p);
            p = (sword32)zeta8_3 * (sword16)(r6 - r7);
            t3 = MLKEM_MONT_RED(p);
            r0 = MLKEM_BARRETT_RED(r0 + r1);
            r2 = MLKEM_BARRETT_RED(r2 + r3);
            r4 = MLKEM_BARRETT_RED(r4 + r5);
            r6 = MLKEM_BARRETT_RED(r6 + r7);
            r1 = t0;
            r3 = t1;
            r5 = t2;
            r7 = t3;

            p = (sword32)zeta16_0 * (sword16)(r0 - r2);
            t0 = MLKEM_MONT_RED(p);
            p = (sword32)zeta16_0 * (sword16)(r1 - r3);
            t1 = MLKEM_MONT_RED(p);
            p = (sword32)zeta16_1 * (sword16)(r4 - r6);
            t2 = MLKEM_MONT_RED(p);
            p = (sword32)zeta16_1 * (sword16)(r5 - r7);
            t3 = MLKEM_MONT_RED(p);
            r0 += r2;
            r1 += r3;
            r4 += r6;
            r5 += r7;
            r2 = t0;
            r3 = t1;
            r6 = t2;
            r7 = t3;

            p = (sword32)zeta32 * (sword16)(r0 - r4);
            t0 = MLKEM_MONT_RED(p);
            p = (sword32)zeta32 * (sword16)(r1 - r5);
            t1 = MLKEM_MONT_RED(p);
            p = (sword32)zeta32 * (sword16)(r2 - r6);
            t2 = MLKEM_MONT_RED(p);
            p = (sword32)zeta32 * (sword16)(r3 - r7);
            t3 = MLKEM_MONT_RED(p);
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
    for (j = 0; j < MLKEM_N / 8; j++) {
        sword16 r0 = r[j +   0];
        sword16 r1 = r[j +  32];
        sword16 r2 = r[j +  64];
        sword16 r3 = r[j +  96];
        sword16 r4 = r[j + 128];
        sword16 r5 = r[j + 160];
        sword16 r6 = r[j + 192];
        sword16 r7 = r[j + 224];

        p = (sword32)zeta64_0 * (sword16)(r0 - r2);
        t0 = MLKEM_MONT_RED(p);
        p = (sword32)zeta64_0 * (sword16)(r1 - r3);
        t1 = MLKEM_MONT_RED(p);
        p = (sword32)zeta64_1 * (sword16)(r4 - r6);
        t2 = MLKEM_MONT_RED(p);
        p = (sword32)zeta64_1 * (sword16)(r5 - r7);
        t3 = MLKEM_MONT_RED(p);
        r0 = MLKEM_BARRETT_RED(r0 + r2);
        r1 = MLKEM_BARRETT_RED(r1 + r3);
        r4 = MLKEM_BARRETT_RED(r4 + r6);
        r5 = MLKEM_BARRETT_RED(r5 + r7);
        r2 = t0;
        r3 = t1;
        r6 = t2;
        r7 = t3;

        p = (sword32)zeta128 * (sword16)(r0 - r4);
        t0 = MLKEM_MONT_RED(p);
        p = (sword32)zeta128 * (sword16)(r1 - r5);
        t1 = MLKEM_MONT_RED(p);
        p = (sword32)zeta128 * (sword16)(r2 - r6);
        t2 = MLKEM_MONT_RED(p);
        p = (sword32)zeta128 * (sword16)(r3 - r7);
        t3 = MLKEM_MONT_RED(p);
        r0 += r4;
        r1 += r5;
        r2 += r6;
        r3 += r7;
        r4 = t0;
        r5 = t1;
        r6 = t2;
        r7 = t3;

        p = (sword32)zeta256 * r0;
        r0 = MLKEM_MONT_RED(p);
        p = (sword32)zeta256 * r1;
        r1 = MLKEM_MONT_RED(p);
        p = (sword32)zeta256 * r2;
        r2 = MLKEM_MONT_RED(p);
        p = (sword32)zeta256 * r3;
        r3 = MLKEM_MONT_RED(p);
        p = (sword32)zeta256 * r4;
        r4 = MLKEM_MONT_RED(p);
        p = (sword32)zeta256 * r5;
        r5 = MLKEM_MONT_RED(p);
        p = (sword32)zeta256 * r6;
        r6 = MLKEM_MONT_RED(p);
        p = (sword32)zeta256 * r7;
        r7 = MLKEM_MONT_RED(p);

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
#endif

/* Multiplication of polynomials in Zq[X]/(X^2-zeta).
 *
 * Used for multiplication of elements in Rq in NTT domain.
 *
 * FIPS 203, Algorithm 12: BaseCaseMultiply(a0, a1, b0, b1, zeta)
 * Computes the product of two degree-one polynomials with respect to a
 * quadratic modulus.
 *   1: c0 <- a0.b0 + a1.b1.zeta
 *   2: c1 <- a0.b1 + a1.b0
 *   3: return (c0, c1)
 *
 * @param  [out]  r     Result polynomial.
 * @param  [in]   a     First factor.
 * @param  [in]   b     Second factor.
 * @param  [in]   zeta  Integer defining the reduction polynomial.
 */
static void mlkem_basemul(sword16* r, const sword16* a, const sword16* b,
    sword16 zeta)
{
    sword16 r0;
    sword16 a0 = a[0];
    sword16 a1 = a[1];
    sword16 b0 = b[0];
    sword16 b1 = b[1];
    sword32 p1;
    sword32 p2;

    /* Step 1 */
    p1   = (sword32)a0 * b0;
    p2   = (sword32)a1 * b1;
    r0   = MLKEM_MONT_RED(p2);
    p2   = (sword32)zeta * r0;
    p2  += p1;
    r[0] = MLKEM_MONT_RED(p2);

    /* Step 2 */
    p1   = (sword32)a0 * b1;
    p2   = (sword32)a1 * b0;
    p1  += p2;
    r[1] = MLKEM_MONT_RED(p1);
}

/* Multiply two polynomials in NTT domain. r = a * b.
 *
 * FIPS 203, Algorithm 11: MultiplyNTTs(f_hat, g_hat)
 * Computes the product (in the ring T_q) of two NTT representations.
 *   1: for (i <- 0; i < 128; i++)
 *   2:     (h_hat[2i],h_hat[2i+1]) <-
 *              BaseCaseMultiply(f_hat[2i],f_hat[2i+1],g_hat[2i],g_hat[2i+1],
 *                               zetas^(BitRev_7(i)+1)
 *   3: end for
 *   4: return h_hat
 *
 * @param  [out]  r  Result polynomial.
 * @param  [in]   a  First polynomial multiplier.
 * @param  [in]   b  Second polynomial multiplier.
 */
static void mlkem_basemul_mont(sword16* r, const sword16* a, const sword16* b)
{
    const sword16* zeta = zetas + 64;

#if defined(WOLFSSL_MLKEM_SMALL)
    /* Two multiplications per loop. */
    unsigned int i;
    /* Step 1 */
    for (i = 0; i < MLKEM_N; i += 4, zeta++) {
        /* Step 2 */
        mlkem_basemul(r + i + 0, a + i + 0, b + i + 0,  zeta[0]);
        mlkem_basemul(r + i + 2, a + i + 2, b + i + 2, -zeta[0]);
    }
#elif defined(WOLFSSL_MLKEM_NO_LARGE_CODE)
    /* Four multiplications per loop. */
    unsigned int i;
    for (i = 0; i < MLKEM_N; i += 8, zeta += 2) {
        mlkem_basemul(r + i + 0, a + i + 0, b + i + 0,  zeta[0]);
        mlkem_basemul(r + i + 2, a + i + 2, b + i + 2, -zeta[0]);
        mlkem_basemul(r + i + 4, a + i + 4, b + i + 4,  zeta[1]);
        mlkem_basemul(r + i + 6, a + i + 6, b + i + 6, -zeta[1]);
    }
#else
    /* Eight multiplications per loop. */
    unsigned int i;
    for (i = 0; i < MLKEM_N; i += 16, zeta += 4) {
        mlkem_basemul(r + i +  0, a + i +  0, b + i +  0,  zeta[0]);
        mlkem_basemul(r + i +  2, a + i +  2, b + i +  2, -zeta[0]);
        mlkem_basemul(r + i +  4, a + i +  4, b + i +  4,  zeta[1]);
        mlkem_basemul(r + i +  6, a + i +  6, b + i +  6, -zeta[1]);
        mlkem_basemul(r + i +  8, a + i +  8, b + i +  8,  zeta[2]);
        mlkem_basemul(r + i + 10, a + i + 10, b + i + 10, -zeta[2]);
        mlkem_basemul(r + i + 12, a + i + 12, b + i + 12,  zeta[3]);
        mlkem_basemul(r + i + 14, a + i + 14, b + i + 14, -zeta[3]);
    }
#endif
}

/* Multiply two polynomials in NTT domain and add to result. r += a * b.
 *
 * FIPS 203, Algorithm 11: MultiplyNTTs(f_hat, g_hat)
 * Computes the product (in the ring T_q) of two NTT representations.
 *   1: for (i <- 0; i < 128; i++)
 *   2:     (h_hat[2i],h_hat[2i+1]) <-
 *              BaseCaseMultiply(f_hat[2i],f_hat[2i+1],g_hat[2i],g_hat[2i+1],
 *                               zetas^(BitRev_7(i)+1)
 *   3: end for
 *   4: return h_hat
 * Add h_hat to r.
 *
 * @param  [in, out]  r  Result polynomial.
 * @param  [in]       a  First polynomial multiplier.
 * @param  [in]       b  Second polynomial multiplier.
 */
static void mlkem_basemul_mont_add(sword16* r, const sword16* a,
    const sword16* b)
{
    const sword16* zeta = zetas + 64;

#if defined(WOLFSSL_MLKEM_SMALL)
    /* Two multiplications per loop. */
    unsigned int i;
    for (i = 0; i < MLKEM_N; i += 4, zeta++) {
        sword16 t0[2];
        sword16 t2[2];

        mlkem_basemul(t0, a + i + 0, b + i + 0,  zeta[0]);
        mlkem_basemul(t2, a + i + 2, b + i + 2, -zeta[0]);

        r[i + 0] += t0[0];
        r[i + 1] += t0[1];
        r[i + 2] += t2[0];
        r[i + 3] += t2[1];
    }
#elif defined(WOLFSSL_MLKEM_NO_LARGE_CODE)
    /* Four multiplications per loop. */
    unsigned int i;
    for (i = 0; i < MLKEM_N; i += 8, zeta += 2) {
        sword16 t0[2];
        sword16 t2[2];
        sword16 t4[2];
        sword16 t6[2];

        mlkem_basemul(t0, a + i + 0, b + i + 0,  zeta[0]);
        mlkem_basemul(t2, a + i + 2, b + i + 2, -zeta[0]);
        mlkem_basemul(t4, a + i + 4, b + i + 4,  zeta[1]);
        mlkem_basemul(t6, a + i + 6, b + i + 6, -zeta[1]);

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
    /* Eight multiplications per loop. */
    unsigned int i;
    for (i = 0; i < MLKEM_N; i += 16, zeta += 4) {
        sword16 t0[2];
        sword16 t2[2];
        sword16 t4[2];
        sword16 t6[2];
        sword16 t8[2];
        sword16 t10[2];
        sword16 t12[2];
        sword16 t14[2];

        mlkem_basemul(t0, a + i + 0, b + i + 0,  zeta[0]);
        mlkem_basemul(t2, a + i + 2, b + i + 2, -zeta[0]);
        mlkem_basemul(t4, a + i + 4, b + i + 4,  zeta[1]);
        mlkem_basemul(t6, a + i + 6, b + i + 6, -zeta[1]);
        mlkem_basemul(t8, a + i + 8, b + i + 8,  zeta[2]);
        mlkem_basemul(t10, a + i + 10, b + i + 10, -zeta[2]);
        mlkem_basemul(t12, a + i + 12, b + i + 12,  zeta[3]);
        mlkem_basemul(t14, a + i + 14, b + i + 14, -zeta[3]);

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
 * @param  [out]  r  Result polynomial.
 * @param  [in]   a  First vector polynomial to multiply with.
 * @param  [in]   b  Second vector polynomial to multiply with.
 * @param  [in]   k  Number of polynomials in vector.
 */
static void mlkem_pointwise_acc_mont(sword16* r, const sword16* a,
    const sword16* b, unsigned int k)
{
    unsigned int i;

    mlkem_basemul_mont(r, a, b);
#ifdef WOLFSSL_MLKEM_SMALL
    for (i = 1; i < k; ++i) {
        mlkem_basemul_mont_add(r, a + i * MLKEM_N, b + i * MLKEM_N);
    }
#else
    for (i = 1; i < k - 1; ++i) {
        mlkem_basemul_mont_add(r, a + i * MLKEM_N, b + i * MLKEM_N);
    }
    mlkem_basemul_mont_add(r, a + (k - 1) * MLKEM_N, b + (k - 1) * MLKEM_N);
#endif
}

/******************************************************************************/

/* Initialize Kyber implementation.
 */
void mlkem_init(void)
{
#if defined(USE_INTEL_SPEEDUP) || (defined(__aarch64__) && \
    defined(WOLFSSL_ARMASM))
    cpuid_flags = cpuid_get_flags();
#endif
}

/******************************************************************************/

#if defined(__aarch64__) && defined(WOLFSSL_ARMASM)

#ifndef WOLFSSL_MLKEM_NO_MAKE_KEY
/* Generate a public-private key pair from randomly generated data.
 *
 * FIPS 203, Algorithm 13: K-PKE.KeyGen(d)
 *   ...
 *   16: s_hat <- NTT(s)
 *   17: e_hat <- NTT(e)
 *   18: t^hat <- A_hat o s_hat + e_hat
 *   ...
 *
 * @param  [in, out]  s  Private key vector of polynomials.
 * @param  [out]      t  Public key vector of polynomials.
 * @param  [in]       e  Error values as a vector of polynomials. Modified.
 * @param  [in]       a  Random values in an array of vectors of polynomials.
 * @param  [in]       k  Number of polynomials in vector.
 */
void mlkem_keygen(sword16* s, sword16* t, sword16* e, const sword16* a, int k)
{
    int i;

#ifndef WOLFSSL_AARCH64_NO_SQRDMLSH
    if (IS_AARCH64_RDM(cpuid_flags)) {
        /* Transform private key. All of result used in public key calculation.
         * Step 16: s_hat = NTT(s) */
        for (i = 0; i < k; ++i) {
            mlkem_ntt_sqrdmlsh(s + i * MLKEM_N);
        }

        /* For each polynomial in the vectors.
         * Step 17, Step 18: Calculate public from A_hat, s_hat and e_hat. */
        for (i = 0; i < k; ++i) {
            /* Multiply a by private into public polynomial.
             * Step 18: ... A_hat o s_hat ... */
            mlkem_pointwise_acc_mont(t + i * MLKEM_N, a + i * k * MLKEM_N, s,
                k);
            /* Convert public polynomial to Montgomery form.
             * Step 18: ... MontRed(A_hat o s_hat) ... */
            mlkem_to_mont_sqrdmlsh(t + i * MLKEM_N);
            /* Transform error values polynomial.
             * Step 17: e_hat = NTT(e) */
            mlkem_ntt_sqrdmlsh(e + i * MLKEM_N);
            /* Add errors to public key and reduce.
             * Step 18: t_hat = BarrettRed(MontRed(A_hat o s_hat) + e_hat) */
            mlkem_add_reduce(t + i * MLKEM_N, e + i * MLKEM_N);
        }
    }
    else
#endif
    {
        /* Transform private key. All of result used in public key calculation.
         * Step 16: s_hat = NTT(s) */
        for (i = 0; i < k; ++i) {
            mlkem_ntt(s + i * MLKEM_N);
        }

        /* For each polynomial in the vectors.
         * Step 17, Step 18: Calculate public from A_hat, s_hat and e_hat. */
        for (i = 0; i < k; ++i) {
            /* Multiply a by private into public polynomial.
             * Step 18: ... A_hat o s_hat ... */
            mlkem_pointwise_acc_mont(t + i * MLKEM_N, a + i * k * MLKEM_N, s,
                k);
            /* Convert public polynomial to Montgomery form.
             * Step 18: ... MontRed(A_hat o s_hat) ... */
            mlkem_to_mont(t + i * MLKEM_N);
            /* Transform error values polynomial.
             * Step 17: e_hat = NTT(e) */
            mlkem_ntt(e + i * MLKEM_N);
            /* Add errors to public key and reduce.
             * Step 18: t_hat = BarrettRed(MontRed(A_hat o s_hat) + e_hat) */
            mlkem_add_reduce(t + i * MLKEM_N, e + i * MLKEM_N);
        }
    }
}
#endif /* WOLFSSL_MLKEM_NO_MAKE_KEY */

#if !defined(WOLFSSL_MLKEM_NO_ENCAPSULATE) || \
    !defined(WOLFSSL_MLKEM_NO_DECAPSULATE)
/* Encapsulate message.
 *
 * FIPS 203, Algorithm 14: K-PKE.Encrypt(ek_PKE, m, r)
 *   ...
 *   Step 18: y_hat <- NTT(y)
 *   Step 19: u <- InvNTT(A_hat_trans o y_hat) + e_1)
 *   ...
 *   Step 21: v <- InvNTT(t_hat_trans o y_hat) + e_2 + mu)
 *   ...
 *
 * @param  [in]   t   Public key vector of polynomials.
 * @param  [out]  u   Vector of polynomials.
 * @param  [out]  v   Polynomial.
 * @param  [in]   a   Array of vector of polynomials.
 * @param  [in]   y   Vector of polynomials.
 * @param  [in]   e1  Error Vector of polynomials.
 * @param  [in]   e2  Error polynomial.
 * @param  [in]   m   Message polynomial.
 * @param  [in]   k   Number of polynomials in vector.
 * @return  0 on success.
 *
 */
void mlkem_encapsulate(const sword16* t, sword16* u , sword16* v,
    const sword16* a, sword16* y, const sword16* e1, const sword16* e2,
    const sword16* m, int k)
{
    int i;

#ifndef WOLFSSL_AARCH64_NO_SQRDMLSH
    if (IS_AARCH64_RDM(cpuid_flags)) {
        /* Transform y. All of result used in calculation of u and v.
         * Step 18: y_hat <- NTT(y) */
        for (i = 0; i < k; ++i) {
            mlkem_ntt_sqrdmlsh(y + i * MLKEM_N);
        }

        /* For each polynomial in the vectors.
         * Step 19: u <- InvNTT(A_hat_trans o y_hat) + e_1) */
        for (i = 0; i < k; ++i) {
            /* Multiply at by y into u polynomial.
             * Step 19: ... A_hat_trans o y_hat ... */
            mlkem_pointwise_acc_mont(u + i * MLKEM_N, a + i * k * MLKEM_N, y,
                k);
            /* Inverse transform u  polynomial.
             * Step 19: ... InvNTT(A_hat_trans o y_hat) ... */
            mlkem_invntt_sqrdmlsh(u  + i * MLKEM_N);
            /* Add errors to u  and reduce.
             * Step 19: u <- InvNTT(A_hat_trans o y_hat) + e_1) */
            mlkem_add_reduce(u  + i * MLKEM_N, e1 + i * MLKEM_N);
        }

        /* Multiply public key by y into v polynomial.
         * Step 21: ... t_hat_trans o y_hat ... */
        mlkem_pointwise_acc_mont(v, t, y, k);
        /* Inverse transform v.
         * Step 22: ... InvNTT(t_hat_trans o y_hat) ... */
        mlkem_invntt_sqrdmlsh(v);
    }
    else
#endif
    {
        /* Transform y. All of result used in calculation of u and v.
         * Step 18: y_hat <- NTT(y) */
        for (i = 0; i < k; ++i) {
            mlkem_ntt(y + i * MLKEM_N);
        }

        /* For each polynomial in the vectors.
         * Step 19: u <- InvNTT(A_hat_trans o y_hat) + e_1) */
        for (i = 0; i < k; ++i) {
            /* Multiply at by y into u polynomial.
             * Step 19: ... A_hat_trans o y_hat ... */
            mlkem_pointwise_acc_mont(u + i * MLKEM_N, a + i * k * MLKEM_N, y,
                k);
            /* Inverse transform u  polynomial.
             * Step 19: ... InvNTT(A_hat_trans o y_hat) ... */
            mlkem_invntt(u + i * MLKEM_N);
            /* Add errors to u and reduce.
             * Step 19: u <- InvNTT(A_hat_trans o y_hat) + e_1) */
            mlkem_add_reduce(u + i * MLKEM_N, e1 + i * MLKEM_N);
        }

        /* Multiply public key by y into v polynomial.
         * Step 21: ... t_hat_trans o y_hat ... */
        mlkem_pointwise_acc_mont(v, t, y, k);
        /* Inverse transform v.
         * Step 22: ... InvNTT(t_hat_trans o y_hat) ... */
        mlkem_invntt(v);
    }
    /* Add errors and message to v and reduce.
     * Step 21: v <- InvNTT(t_hat_trans o y_hat) + e_2 + mu) */
    mlkem_add3_reduce(v, e2, m);
}
#endif /* !WOLFSSL_MLKEM_NO_ENCAPSULATE || !WOLFSSL_MLKEM_NO_DECAPSULATE */

#ifndef WOLFSSL_MLKEM_NO_DECAPSULATE
/* Decapsulate message.
 *
 * FIPS 203, Algorithm 15: K-PKE.Decrypt(dk_PKE,c)
 * Uses the decryption key to decrypt a ciphertext.
 *   ...
 *   6: w <- v' - InvNTT(s_hat_trans o NTT(u'))
 *   ...
 *
 * @param  [in]   s  Decryption key as vector of polynomials.
 * @param  [out]  w  Message polynomial.
 * @param  [in]   u  Vector of polynomials containing error.
 * @param  [in]   v  Encapsulated message polynomial.
 * @param  [in]   k  Number of polynomials in vector.
 */
void mlkem_decapsulate(const sword16* s, sword16* w, sword16* u,
    const sword16* v, int k)
{
    int i;

#ifndef WOLFSSL_AARCH64_NO_SQRDMLSH
    if (IS_AARCH64_RDM(cpuid_flags)) {
        /* Transform u. All of result used in calculation of w.
         * Step 6: ... NTT(u') */
        for (i = 0; i < k; ++i) {
            mlkem_ntt_sqrdmlsh(u + i * MLKEM_N);
        }

        /* Multiply private key by u into w polynomial.
         * Step 6: ... s_hat_trans o NTT(u') */
        mlkem_pointwise_acc_mont(w, s, u, k);
        /* Inverse transform w.
         * Step 6: ... InvNTT(s_hat_trans o NTT(u')) */
        mlkem_invntt_sqrdmlsh(w);
    }
    else
#endif
    {
        /* Transform u. All of result used in calculation of w.
         * Step 6: ... NTT(u') */
        for (i = 0; i < k; ++i) {
            mlkem_ntt(u + i * MLKEM_N);
        }

        /* Multiply private key by u into w polynomial.
         * Step 6: ... s_hat_trans o NTT(u') */
        mlkem_pointwise_acc_mont(w, s, u, k);
        /* Inverse transform w.
         * Step 6: ... InvNTT(s_hat_trans o NTT(u')) */
        mlkem_invntt(w);
    }
    /* Subtract errors (in w) out of v and reduce into w.
     * Step 6: w <- v' - InvNTT(s_hat_trans o NTT(u')) */
    mlkem_rsub_reduce(w, v);
}
#endif /* !WOLFSSL_MLKEM_NO_DECAPSULATE */

#else

#ifndef WOLFSSL_MLKEM_NO_MAKE_KEY

#if !defined(WOLFSSL_MLKEM_SMALL) && !defined(WOLFSSL_MLKEM_NO_LARGE_CODE)
/* Number-Theoretic Transform.
 *
 * FIPS 203, Algorithm 9: NTT(f)
 * Computes the NTT representation f_hat of the given polynomial f element of
 * R_q.
 *   1: f_hat <- f
 *   2: i <- 1
 *   3: for (len <- 128; len >= 2; len <- len/2)
 *   4:     for (start <- 0; start < 256; start <- start + 2.len)
 *   5:         zeta <- zetas^BitRev_7(i) mod q
 *   6:         i <- i + 1
 *   7:         for (j <- start; j < start + len; j++)
 *   8:             t <- zeta.f[j+len]
 *   9:             f_hat[j+len] <- f_hat[j] - t
 *  10:             f_hat[j] <- f_hat[j] - t
 *  11:         end for
 *  12:     end for
 *  13: end for
 *  14: return f_hat
 *
 * @param  [in, out]  r  Polynomial to transform.
 */
static void mlkem_ntt_add_to(sword16* r, sword16* a)
{
#if defined(WOLFSSL_MLKEM_NTT_UNROLL)
    /* Unroll len loop (Step 3). */
    unsigned int k = 1;
    unsigned int j;
    unsigned int start;
    sword16 zeta = zetas[k++];

    /* len = 128 */
    for (j = 0; j < MLKEM_N / 2; ++j) {
        sword32 p = (sword32)zeta * r[j + MLKEM_N / 2];
        sword16 t = MLKEM_MONT_RED(p);
        sword16 rj = r[j];
        r[j + MLKEM_N / 2] = rj - t;
        r[j] = rj + t;
    }
    /* len = 64 */
    for (start = 0; start < MLKEM_N; start += 2 * 64) {
        zeta = zetas[k++];
        for (j = 0; j < 64; ++j) {
            sword32 p = (sword32)zeta * r[start + j + 64];
            sword16 t = MLKEM_MONT_RED(p);
            sword16 rj = r[start + j];
            r[start + j + 64] = rj - t;
            r[start + j] = rj + t;
        }
    }
    /* len = 32 */
    for (start = 0; start < MLKEM_N; start += 2 * 32) {
        zeta = zetas[k++];
        for (j = 0; j < 32; ++j) {
            sword32 p = (sword32)zeta * r[start + j + 32];
            sword16 t = MLKEM_MONT_RED(p);
            sword16 rj = r[start + j];
            r[start + j + 32] = rj - t;
            r[start + j] = rj + t;
        }
    }
    /* len = 16 */
    for (start = 0; start < MLKEM_N; start += 2 * 16) {
        zeta = zetas[k++];
        for (j = 0; j < 16; ++j) {
            sword32 p = (sword32)zeta * r[start + j + 16];
            sword16 t = MLKEM_MONT_RED(p);
            sword16 rj = r[start + j];
            r[start + j + 16] = rj - t;
            r[start + j] = rj + t;
        }
    }
    /* len = 8 */
    for (start = 0; start < MLKEM_N; start += 2 * 8) {
        zeta = zetas[k++];
        for (j = 0; j < 8; ++j) {
            sword32 p = (sword32)zeta * r[start + j + 8];
            sword16 t = MLKEM_MONT_RED(p);
            sword16 rj = r[start + j];
            r[start + j + 8] = rj - t;
            r[start + j] = rj + t;
        }
    }
    /* len = 4 */
    for (start = 0; start < MLKEM_N; start += 2 * 4) {
        zeta = zetas[k++];
        for (j = 0; j < 4; ++j) {
            sword32 p = (sword32)zeta * r[start + j + 4];
            sword16 t = MLKEM_MONT_RED(p);
            sword16 rj = r[start + j];
            r[start + j + 4] = rj - t;
            r[start + j] = rj + t;
        }
    }
    /* len = 2 */
    for (start = 0; start < MLKEM_N; start += 2 * 2) {
        zeta = zetas[k++];
        for (j = 0; j < 2; ++j) {
            sword32 p = (sword32)zeta * r[start + j + 2];
            sword16 t = MLKEM_MONT_RED(p);
            sword16 rj = r[start + j];
            r[start + j + 2] = rj - t;
            r[start + j] = rj + t;
        }
    }
    /* Reduce coefficients with quick algorithm. */
    for (j = 0; j < MLKEM_N; ++j) {
        sword16 t = a[j] + r[j];
        a[j] = MLKEM_BARRETT_RED(t);
    }
#else /* !WOLFSSL_MLKEM_NTT_UNROLL */
    /* Unroll len (2, 3, 2) and start loops. */
    unsigned int j;
    sword16 t0;
    sword16 t1;
    sword16 t2;
    sword16 t3;

    /* len = 128,64 */
    sword16 zeta128 = zetas[1];
    sword16 zeta64_0 = zetas[2];
    sword16 zeta64_1 = zetas[3];
    for (j = 0; j < MLKEM_N / 8; j++) {
        sword16 r0 = r[j +   0];
        sword16 r1 = r[j +  32];
        sword16 r2 = r[j +  64];
        sword16 r3 = r[j +  96];
        sword16 r4 = r[j + 128];
        sword16 r5 = r[j + 160];
        sword16 r6 = r[j + 192];
        sword16 r7 = r[j + 224];

        t0 = MLKEM_MONT_RED((sword32)zeta128 * r4);
        t1 = MLKEM_MONT_RED((sword32)zeta128 * r5);
        t2 = MLKEM_MONT_RED((sword32)zeta128 * r6);
        t3 = MLKEM_MONT_RED((sword32)zeta128 * r7);
        r4 = r0 - t0;
        r5 = r1 - t1;
        r6 = r2 - t2;
        r7 = r3 - t3;
        r0 += t0;
        r1 += t1;
        r2 += t2;
        r3 += t3;

        t0 = MLKEM_MONT_RED((sword32)zeta64_0 * r2);
        t1 = MLKEM_MONT_RED((sword32)zeta64_0 * r3);
        t2 = MLKEM_MONT_RED((sword32)zeta64_1 * r6);
        t3 = MLKEM_MONT_RED((sword32)zeta64_1 * r7);
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

    /* len = 32,16,8 */
    for (j = 0; j < MLKEM_N; j += 64) {
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

            t0 = MLKEM_MONT_RED((sword32)zeta32 * r4);
            t1 = MLKEM_MONT_RED((sword32)zeta32 * r5);
            t2 = MLKEM_MONT_RED((sword32)zeta32 * r6);
            t3 = MLKEM_MONT_RED((sword32)zeta32 * r7);
            r4 = r0 - t0;
            r5 = r1 - t1;
            r6 = r2 - t2;
            r7 = r3 - t3;
            r0 += t0;
            r1 += t1;
            r2 += t2;
            r3 += t3;

            t0 = MLKEM_MONT_RED((sword32)zeta16_0 * r2);
            t1 = MLKEM_MONT_RED((sword32)zeta16_0 * r3);
            t2 = MLKEM_MONT_RED((sword32)zeta16_1 * r6);
            t3 = MLKEM_MONT_RED((sword32)zeta16_1 * r7);
            r2 = r0 - t0;
            r3 = r1 - t1;
            r6 = r4 - t2;
            r7 = r5 - t3;
            r0 += t0;
            r1 += t1;
            r4 += t2;
            r5 += t3;

            t0 = MLKEM_MONT_RED((sword32)zeta8_0 * r1);
            t1 = MLKEM_MONT_RED((sword32)zeta8_1 * r3);
            t2 = MLKEM_MONT_RED((sword32)zeta8_2 * r5);
            t3 = MLKEM_MONT_RED((sword32)zeta8_3 * r7);
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

    /* len = 4,2 and Final reduction */
    for (j = 0; j < MLKEM_N; j += 8) {
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

        t0 = MLKEM_MONT_RED((sword32)zeta4 * r4);
        t1 = MLKEM_MONT_RED((sword32)zeta4 * r5);
        t2 = MLKEM_MONT_RED((sword32)zeta4 * r6);
        t3 = MLKEM_MONT_RED((sword32)zeta4 * r7);
        r4 = r0 - t0;
        r5 = r1 - t1;
        r6 = r2 - t2;
        r7 = r3 - t3;
        r0 += t0;
        r1 += t1;
        r2 += t2;
        r3 += t3;

        t0 = MLKEM_MONT_RED((sword32)zeta2_0 * r2);
        t1 = MLKEM_MONT_RED((sword32)zeta2_0 * r3);
        t2 = MLKEM_MONT_RED((sword32)zeta2_1 * r6);
        t3 = MLKEM_MONT_RED((sword32)zeta2_1 * r7);
        r2 = r0 - t0;
        r3 = r1 - t1;
        r6 = r4 - t2;
        r7 = r5 - t3;
        r0 += t0;
        r1 += t1;
        r4 += t2;
        r5 += t3;

        r0 += a[j + 0];
        r1 += a[j + 1];
        r2 += a[j + 2];
        r3 += a[j + 3];
        r4 += a[j + 4];
        r5 += a[j + 5];
        r6 += a[j + 6];
        r7 += a[j + 7];

        a[j + 0] = MLKEM_BARRETT_RED(r0);
        a[j + 1] = MLKEM_BARRETT_RED(r1);
        a[j + 2] = MLKEM_BARRETT_RED(r2);
        a[j + 3] = MLKEM_BARRETT_RED(r3);
        a[j + 4] = MLKEM_BARRETT_RED(r4);
        a[j + 5] = MLKEM_BARRETT_RED(r5);
        a[j + 6] = MLKEM_BARRETT_RED(r6);
        a[j + 7] = MLKEM_BARRETT_RED(r7);
    }
#endif /* !WOLFSSL_MLKEM_NTT_UNROLL */
}
#endif /* !WOLFSSL_MLKEM_SMALL && !WOLFSSL_MLKEM_NO_LARGE_CODE */

#ifndef WOLFSSL_MLKEM_MAKEKEY_SMALL_MEM
/* Generate a public-private key pair from randomly generated data.
 *
 * FIPS 203, Algorithm 13: K-PKE.KeyGen(d)
 *   ...
 *   16: s_hat <- NTT(s)
 *   17: e_hat <- NTT(e)
 *   18: t^hat <- A_hat o s_hat + e_hat
 *   ...
 *
 * @param  [in, out]  s  Private key vector of polynomials.
 * @param  [out]      t  Public key vector of polynomials.
 * @param  [in]       e  Error values as a vector of polynomials. Modified.
 * @param  [in]       a  Random values in an array of vectors of polynomials.
 * @param  [in]       k  Number of polynomials in vector.
 */
static void mlkem_keygen_c(sword16* s, sword16* t, sword16* e, const sword16* a,
    int k)
{
    int i;

    /* Transform private key. All of result used in public key calculation
     * Step 16: s_hat = NTT(s) */
    for (i = 0; i < k; ++i) {
        mlkem_ntt(s + i * MLKEM_N);
    }

    /* For each polynomial in the vectors.
     * Step 17, Step 18: Calculate public from A_hat, s_hat and e_hat. */
    for (i = 0; i < k; ++i) {
        unsigned int j;

        /* Multiply a by private into public polynomial.
         * Step 18: ... A_hat o s_hat ... */
        mlkem_pointwise_acc_mont(t + i * MLKEM_N, a + i * k * MLKEM_N, s, k);
        /* Convert public polynomial to Montgomery form.
         * Step 18: ... MontRed(A_hat o s_hat) ... */
        for (j = 0; j < MLKEM_N; ++j) {
            sword32 n = t[i * MLKEM_N + j] * (sword32)MLKEM_F;
            t[i * MLKEM_N + j] = MLKEM_MONT_RED(n);
        }
        /* Transform error values polynomial.
         * Step 17: e_hat = NTT(e) */
#if defined(WOLFSSL_MLKEM_SMALL) || defined(WOLFSSL_MLKEM_NO_LARGE_CODE)
        mlkem_ntt(e + i * MLKEM_N);
        /* Add errors to public key and reduce.
         * Step 18: t_hat = BarrettRed(MontRed(A_hat o s_hat) + e_hat) */
        for (j = 0; j < MLKEM_N; ++j) {
            sword16 n = t[i * MLKEM_N + j] + e[i * MLKEM_N + j];
            t[i * MLKEM_N + j] = MLKEM_BARRETT_RED(n);
        }
#else
        /* Add errors to public key and reduce.
         * Step 18: t_hat = BarrettRed(MontRed(A_hat o s_hat) + e_hat) */
        mlkem_ntt_add_to(e + i * MLKEM_N, t + i * MLKEM_N);
#endif
    }
}

/* Generate a public-private key pair from randomly generated data.
 *
 * FIPS 203, Algorithm 13: K-PKE.KeyGen(d)
 *   ...
 *   16: s_hat <- NTT(s)
 *   17: e_hat <- NTT(e)
 *   18: t^hat <- A_hat o s_hat + e_hat
 *   ...
 *
 * @param  [in, out]  s  Private key vector of polynomials.
 * @param  [out]      t  Public key vector of polynomials.
 * @param  [in]       e  Error values as a vector of polynomials. Modified.
 * @param  [in]       a  Random values in an array of vectors of polynomials.
 * @param  [in]       k  Number of polynomials in vector.
 */
void mlkem_keygen(sword16* s, sword16* t, sword16* e, const sword16* a, int k)
{
#ifdef USE_INTEL_SPEEDUP
    if ((IS_INTEL_AVX2(cpuid_flags)) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        /* Alg 13: Steps 16-18 */
        mlkem_keygen_avx2(s, t, e, a, k);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
        /* Alg 13: Steps 16-18 */
        mlkem_keygen_c(s, t, e, a, k);
    }
}

#else /* WOLFSSL_MLKEM_MAKEKEY_SMALL_MEM */

/* Generate a public-private key pair from randomly generated data.
 *
 * FIPS 203, Algorithm 13: K-PKE.KeyGen(d)
 *   3: for (i <- 0; i < k; i++)                         > generate matrix A_hat
 *   ... (generate A[i])
 *   7: end for
 *   ...
 *   9:      s[i] <- SamplePolyCBD_eta_1(PRF_eta_1(rho, N))
 *   ...
 *  16: s_hat <- NTT(s)
 *  17: e_hat <- NTT(e)
 *  18: t^hat <- A_hat o s_hat + e_hat
 *   ...
 *
 * @param  [in, out]  s      Private key vector of polynomials.
 * @param  [out]      tv     Public key vector of polynomials.
 * @param  [in]       prf    XOF object.
 * @param  [in]       tv     Temporary vector of polynomials.
 * @param  [in]       k      Number of polynomials in vector.
 * @param  [in]       rho    Random seed to generate matrix A from.
 * @param  [in]       sigma  Random seed to generate noise from.
 */
int mlkem_keygen_seeds(sword16* s, sword16* t, MLKEM_PRF_T* prf,
    sword16* tv, int k, byte* rho, byte* sigma)
{
    int i;
    int ret = 0;
    sword16* ai = tv;
    sword16* e = tv;

    /* Transform private key. All of result used in public key calculation
     * Step 16: s_hat = NTT(s) */
    for (i = 0; i < k; ++i) {
        mlkem_ntt(s + i * MLKEM_N);
    }

    /* For each polynomial in the vectors.
     * Step 17, Step 18: Calculate public from A_hat, s_hat and e_hat. */
    for (i = 0; i < k; ++i) {
        unsigned int j;

        /* Generate a vector of matrix A.
         * Steps 4-6: generate A[i] */
        ret = mlkem_gen_matrix_i(prf, ai, k, rho, i, 0);
        if (ret != 0) {
           break;
        }

        /* Multiply a by private into public polynomial.
         * Step 18: ... A_hat o s_hat ... */
        mlkem_pointwise_acc_mont(t + i * MLKEM_N, ai, s, k);
        /* Convert public polynomial to Montgomery form.
         * Step 18: ... MontRed(A_hat o s_hat) ... */
        for (j = 0; j < MLKEM_N; ++j) {
            sword32 n = t[i * MLKEM_N + j] * (sword32)MLKEM_F;
            t[i * MLKEM_N + j] = MLKEM_MONT_RED(n);
        }

        /* Generate noise using PRF.
         * Step 9: s[i] <- SamplePolyCBD_eta_1(PRF_eta_1(rho, N)) */
        ret = mlkem_get_noise_i(prf, k, e, sigma, i, 1);
        if (ret != 0) {
           break;
        }
        /* Transform error values polynomial.
         * Step 17: e_hat = NTT(e) */
#if defined(WOLFSSL_MLKEM_SMALL) || defined(WOLFSSL_MLKEM_NO_LARGE_CODE)
        mlkem_ntt(e);
        /* Add errors to public key and reduce.
         * Step 18: t_hat = BarrettRed(MontRed(A_hat o s_hat) + e_hat) */
        for (j = 0; j < MLKEM_N; ++j) {
            sword16 n = t[i * MLKEM_N + j] + e[j];
            t[i * MLKEM_N + j] = MLKEM_BARRETT_RED(n);
        }
#else
        /* Add errors to public key and reduce.
         * Step 18: t_hat = BarrettRed(MontRed(A_hat o s_hat) + e_hat) */
        mlkem_ntt_add_to(e, t + i * MLKEM_N);
#endif
    }

    return ret;
}

#endif /* WOLFSSL_MLKEM_MAKEKEY_SMALL_MEM */
#endif /* !WOLFSSL_MLKEM_NO_MAKE_KEY */

#if !defined(WOLFSSL_MLKEM_NO_ENCAPSULATE) || \
    !defined(WOLFSSL_MLKEM_NO_DECAPSULATE)
#ifndef WOLFSSL_MLKEM_ENCAPSULATE_SMALL_MEM
/* Encapsulate message.
 *
 * @param  [in]   pub  Public key vector of polynomials.
 * @param  [out]  u    Vector of polynomials.
 * @param  [out]  v    Polynomial.
 * @param  [in]   a    Array of vector of polynomials.
 * @param  [in]   y    Vector of polynomials.
 * @param  [in]   e1   Error Vector of polynomials.
 * @param  [in]   e2   Error polynomial.
 * @param  [in]   m    Message polynomial.
 * @param  [in]   k    Number of polynomials in vector.
 * @return  0 on success.
 */
static void mlkem_encapsulate_c(const sword16* pub, sword16* u, sword16* v,
    const sword16* a, sword16* y, const sword16* e1, const sword16* e2,
    const sword16* m, int k)
{
    int i;

    /* Transform y. All of result used in calculation of u and v. */
    for (i = 0; i < k; ++i) {
        mlkem_ntt(y + i * MLKEM_N);
    }

    /* For each polynomial in the vectors. */
    for (i = 0; i < k; ++i) {
        unsigned int j;

        /* Multiply at by y into u polynomial. */
        mlkem_pointwise_acc_mont(u + i * MLKEM_N, a + i * k * MLKEM_N, y, k);
        /* Inverse transform u polynomial. */
        mlkem_invntt(u + i * MLKEM_N);
        /* Add errors to u and reduce. */
#if defined(WOLFSSL_MLKEM_SMALL) || defined(WOLFSSL_MLKEM_NO_LARGE_CODE)
        for (j = 0; j < MLKEM_N; ++j) {
            sword16 t = u[i * MLKEM_N + j] + e1[i * MLKEM_N + j];
            u[i * MLKEM_N + j] = MLKEM_BARRETT_RED(t);
        }
#else
        for (j = 0; j < MLKEM_N; j += 8) {
            sword16 t0 = u[i * MLKEM_N + j + 0] + e1[i * MLKEM_N + j + 0];
            sword16 t1 = u[i * MLKEM_N + j + 1] + e1[i * MLKEM_N + j + 1];
            sword16 t2 = u[i * MLKEM_N + j + 2] + e1[i * MLKEM_N + j + 2];
            sword16 t3 = u[i * MLKEM_N + j + 3] + e1[i * MLKEM_N + j + 3];
            sword16 t4 = u[i * MLKEM_N + j + 4] + e1[i * MLKEM_N + j + 4];
            sword16 t5 = u[i * MLKEM_N + j + 5] + e1[i * MLKEM_N + j + 5];
            sword16 t6 = u[i * MLKEM_N + j + 6] + e1[i * MLKEM_N + j + 6];
            sword16 t7 = u[i * MLKEM_N + j + 7] + e1[i * MLKEM_N + j + 7];
            u[i * MLKEM_N + j + 0] = MLKEM_BARRETT_RED(t0);
            u[i * MLKEM_N + j + 1] = MLKEM_BARRETT_RED(t1);
            u[i * MLKEM_N + j + 2] = MLKEM_BARRETT_RED(t2);
            u[i * MLKEM_N + j + 3] = MLKEM_BARRETT_RED(t3);
            u[i * MLKEM_N + j + 4] = MLKEM_BARRETT_RED(t4);
            u[i * MLKEM_N + j + 5] = MLKEM_BARRETT_RED(t5);
            u[i * MLKEM_N + j + 6] = MLKEM_BARRETT_RED(t6);
            u[i * MLKEM_N + j + 7] = MLKEM_BARRETT_RED(t7);
        }
#endif
    }

    /* Multiply public key by y into v polynomial. */
    mlkem_pointwise_acc_mont(v, pub, y, k);
    /* Inverse transform v. */
    mlkem_invntt(v);
    /* Add errors and message to v and reduce. */
    for (i = 0; i < MLKEM_N; ++i) {
        sword16 t = v[i] + e2[i] + m[i];
        v[i] = MLKEM_BARRETT_RED(t);
    }
}

/* Encapsulate message.
 *
 * @param  [in]   pub  Public key vector of polynomials.
 * @param  [out]  u    Vector of polynomials.
 * @param  [out]  v    Polynomial.
 * @param  [in]   a    Array of vector of polynomials.
 * @param  [in]   y    Vector of polynomials.
 * @param  [in]   e1   Error Vector of polynomials.
 * @param  [in]   e2   Error polynomial.
 * @param  [in]   m    Message polynomial.
 * @param  [in]   k    Number of polynomials in vector.
 * @return  0 on success.
 */
void mlkem_encapsulate(const sword16* pub, sword16* u, sword16* v,
    const sword16* a, sword16* y, const sword16* e1, const sword16* e2,
    const sword16* m, int k)
{
#ifdef USE_INTEL_SPEEDUP
    if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        mlkem_encapsulate_avx2(pub, u, v, a, y, e1, e2, m, k);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
        mlkem_encapsulate_c(pub, u, v, a, y, e1, e2, m, k);
    }
}

#else

/* Encapsulate message.
 *
 * @param  [in]       pub    Public key vector of polynomials.
 * @param  [in]       prf    XOF object.
 * @param  [out]      u      Vector of polynomials.
 * @param  [in, out]  tp     Polynomial.
 * @param  [in]       y      Vector of polynomials.
 * @param  [in]       k      Number of polynomials in vector.
 * @param  [in]       msg    Message to encapsulate.
 * @param  [in]       seed   Random seed to generate matrix A from.
 * @param  [in]       coins  Random seed to generate noise from.
 */
int mlkem_encapsulate_seeds(const sword16* pub, MLKEM_PRF_T* prf, sword16* u,
    sword16* tp, sword16* y, int k, const byte* msg, byte* seed, byte* coins)
{
    int ret = 0;
    int i;
    sword16* a = tp;
    sword16* e1 = tp;
    sword16* v = tp;
    sword16* e2 = tp + MLKEM_N;
    sword16* m = y;

    /* Transform y. All of result used in calculation of u and v. */
    for (i = 0; i < k; ++i) {
        mlkem_ntt(y + i * MLKEM_N);
    }

    /* For each polynomial in the vectors. */
    for (i = 0; i < k; ++i) {
        unsigned int j;

        /* Generate a vector of matrix A. */
        ret = mlkem_gen_matrix_i(prf, a, k, seed, i, 1);
        if (ret != 0) {
           break;
        }

        /* Multiply at by y into u polynomial. */
        mlkem_pointwise_acc_mont(u + i * MLKEM_N, a, y, k);
        /* Inverse transform u polynomial. */
        mlkem_invntt(u + i * MLKEM_N);

        /* Generate noise using PRF. */
        ret = mlkem_get_noise_i(prf, k, e1, coins, i, 0);
        if (ret != 0) {
           break;
        }
        /* Add errors to u and reduce. */
#if defined(WOLFSSL_MLKEM_SMALL) || defined(WOLFSSL_MLKEM_NO_LARGE_CODE)
        for (j = 0; j < MLKEM_N; ++j) {
            sword16 t = u[i * MLKEM_N + j] + e1[j];
            u[i * MLKEM_N + j] = MLKEM_BARRETT_RED(t);
        }
#else
        for (j = 0; j < MLKEM_N; j += 8) {
            sword16 t0 = u[i * MLKEM_N + j + 0] + e1[j + 0];
            sword16 t1 = u[i * MLKEM_N + j + 1] + e1[j + 1];
            sword16 t2 = u[i * MLKEM_N + j + 2] + e1[j + 2];
            sword16 t3 = u[i * MLKEM_N + j + 3] + e1[j + 3];
            sword16 t4 = u[i * MLKEM_N + j + 4] + e1[j + 4];
            sword16 t5 = u[i * MLKEM_N + j + 5] + e1[j + 5];
            sword16 t6 = u[i * MLKEM_N + j + 6] + e1[j + 6];
            sword16 t7 = u[i * MLKEM_N + j + 7] + e1[j + 7];
            u[i * MLKEM_N + j + 0] = MLKEM_BARRETT_RED(t0);
            u[i * MLKEM_N + j + 1] = MLKEM_BARRETT_RED(t1);
            u[i * MLKEM_N + j + 2] = MLKEM_BARRETT_RED(t2);
            u[i * MLKEM_N + j + 3] = MLKEM_BARRETT_RED(t3);
            u[i * MLKEM_N + j + 4] = MLKEM_BARRETT_RED(t4);
            u[i * MLKEM_N + j + 5] = MLKEM_BARRETT_RED(t5);
            u[i * MLKEM_N + j + 6] = MLKEM_BARRETT_RED(t6);
            u[i * MLKEM_N + j + 7] = MLKEM_BARRETT_RED(t7);
        }
#endif
    }

    /* Multiply public key by y into v polynomial. */
    mlkem_pointwise_acc_mont(v, pub, y, k);
    /* Inverse transform v. */
    mlkem_invntt(v);

    mlkem_from_msg(m, msg);

    /* Generate noise using PRF. */
    coins[WC_ML_KEM_SYM_SZ] = 2 * k;
    ret = mlkem_get_noise_eta2_c(prf, e2, coins);
    if (ret == 0) {
        /* Add errors and message to v and reduce. */
    #if defined(WOLFSSL_MLKEM_SMALL) || defined(WOLFSSL_MLKEM_NO_LARGE_CODE)
        for (i = 0; i < MLKEM_N; ++i) {
            sword16 t = v[i] + e2[i] + m[i];
            v[i] = MLKEM_BARRETT_RED(t);
        }
    #else
        for (i = 0; i < MLKEM_N; i += 8) {
            sword16 t0 = v[i + 0] + e2[i + 0] + m[i + 0];
            sword16 t1 = v[i + 1] + e2[i + 1] + m[i + 1];
            sword16 t2 = v[i + 2] + e2[i + 2] + m[i + 2];
            sword16 t3 = v[i + 3] + e2[i + 3] + m[i + 3];
            sword16 t4 = v[i + 4] + e2[i + 4] + m[i + 4];
            sword16 t5 = v[i + 5] + e2[i + 5] + m[i + 5];
            sword16 t6 = v[i + 6] + e2[i + 6] + m[i + 6];
            sword16 t7 = v[i + 7] + e2[i + 7] + m[i + 7];
            v[i + 0] = MLKEM_BARRETT_RED(t0);
            v[i + 1] = MLKEM_BARRETT_RED(t1);
            v[i + 2] = MLKEM_BARRETT_RED(t2);
            v[i + 3] = MLKEM_BARRETT_RED(t3);
            v[i + 4] = MLKEM_BARRETT_RED(t4);
            v[i + 5] = MLKEM_BARRETT_RED(t5);
            v[i + 6] = MLKEM_BARRETT_RED(t6);
            v[i + 7] = MLKEM_BARRETT_RED(t7);
        }
    #endif
    }

    return ret;
}
#endif
#endif /* !WOLFSSL_MLKEM_NO_ENCAPSULATE || !WOLFSSL_MLKEM_NO_DECAPSULATE */

#ifndef WOLFSSL_MLKEM_NO_DECAPSULATE

/* Decapsulate message.
 *
 * FIPS 203, Algorithm 15: K-PKE.Decrypt(dk_PKE,c)
 * Uses the decryption key to decrypt a ciphertext.
 *   ...
 *   6: w <- v' - InvNTT(s_hat_trans o NTT(u'))
 *   ...
 *
 * @param  [in]   s  Private key vector of polynomials.
 * @param  [out]  w  Message polynomial.
 * @param  [in]   u  Vector of polynomials containing error.
 * @param  [in]   v  Encapsulated message polynomial.
 * @param  [in]   k  Number of polynomials in vector.
 */
static void mlkem_decapsulate_c(const sword16* s, sword16* w, sword16* u,
    const sword16* v, int k)
{
    int i;

    /* Transform u. All of result used in calculation of w.
     * Step 6: ... NTT(u') */
    for (i = 0; i < k; ++i) {
        mlkem_ntt(u + i * MLKEM_N);
    }

    /* Multiply private key by u into w polynomial.
     * Step 6: ... s_hat_trans o NTT(u') */
    mlkem_pointwise_acc_mont(w, s, u, k);
    /* Inverse transform w.
     * Step 6: ... InvNTT(s_hat_trans o NTT(u')) */
    mlkem_invntt(w);
    /* Subtract errors (in w) out of v and reduce into w.
     * Step 6: w <- v' - InvNTT(s_hat_trans o NTT(u')) */
    for (i = 0; i < MLKEM_N; ++i) {
        sword16 t = v[i] - w[i];
        w[i] = MLKEM_BARRETT_RED(t);
    }
}

/* Decapsulate message.
 *
 * FIPS 203, Algorithm 15: K-PKE.Decrypt(dk_PKE,c)
 * Uses the decryption key to decrypt a ciphertext.
 *   ...
 *   6: w <- v' - InvNTT(s_hat_trans o NTT(u'))
 *   ...
 *
 * @param  [in]   s  Private key vector of polynomials.
 * @param  [out]  w  Message polynomial.
 * @param  [in]   u  Vector of polynomials containing error.
 * @param  [in]   v   Encapsulated message polynomial.
 * @param  [in]   k   Number of polynomials in vector.
 */
void mlkem_decapsulate(const sword16* s, sword16* w, sword16* u,
    const sword16* v, int k)
{
#ifdef USE_INTEL_SPEEDUP
    if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        mlkem_decapsulate_avx2(s, w, u, v, k);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
        mlkem_decapsulate_c(s, w, u, v, k);
    }
}

#endif /* !WOLFSSL_MLKEM_ NO_DECAPSULATE */
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
static int mlkem_gen_matrix_k2_avx2(sword16* a, byte* seed, int transposed)
{
    int i;
#ifdef WOLFSSL_SMALL_STACK
    byte *rand = NULL;
    word64 *state = NULL;
#else
    byte rand[4 * GEN_MATRIX_SIZE + 2];
    word64 state[25 * 4];
#endif
    unsigned int ctr0;
    unsigned int ctr1;
    unsigned int ctr2;
    unsigned int ctr3;
    byte* p;

#ifdef WOLFSSL_SMALL_STACK
    rand = (byte*)XMALLOC(4 * GEN_MATRIX_SIZE + 2, NULL,
                          DYNAMIC_TYPE_TMP_BUFFER);
    state = (word64*)XMALLOC(sizeof(word64) * 25 * 4, NULL,
                          DYNAMIC_TYPE_TMP_BUFFER);
    if ((rand == NULL) || (state == NULL)) {
        XFREE(rand, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(state, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }
#endif

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

    mlkem_sha3_128_blocksx4_seed_avx2(state, seed);
    mlkem_redistribute_21_rand_avx2(state, rand + 0 * GEN_MATRIX_SIZE,
        rand + 1 * GEN_MATRIX_SIZE, rand + 2 * GEN_MATRIX_SIZE,
        rand + 3 * GEN_MATRIX_SIZE);
    for (i = SHA3_128_BYTES; i < GEN_MATRIX_SIZE; i += SHA3_128_BYTES) {
        sha3_blocksx4_avx2(state);
        mlkem_redistribute_21_rand_avx2(state, rand + i + 0 * GEN_MATRIX_SIZE,
            rand + i + 1 * GEN_MATRIX_SIZE, rand + i + 2 * GEN_MATRIX_SIZE,
            rand + i + 3 * GEN_MATRIX_SIZE);
    }

    /* Sample random bytes to create a polynomial. */
    p = rand;
    ctr0 = mlkem_rej_uniform_n_avx2(a + 0 * MLKEM_N, MLKEM_N, p,
        GEN_MATRIX_SIZE);
    p += GEN_MATRIX_SIZE;
    ctr1 = mlkem_rej_uniform_n_avx2(a + 1 * MLKEM_N, MLKEM_N, p,
        GEN_MATRIX_SIZE);
    p += GEN_MATRIX_SIZE;
    ctr2 = mlkem_rej_uniform_n_avx2(a + 2 * MLKEM_N, MLKEM_N, p,
        GEN_MATRIX_SIZE);
    p += GEN_MATRIX_SIZE;
    ctr3 = mlkem_rej_uniform_n_avx2(a + 3 * MLKEM_N, MLKEM_N, p,
        GEN_MATRIX_SIZE);
    /* Create more blocks if too many rejected. */
    while ((ctr0 < MLKEM_N) || (ctr1 < MLKEM_N) || (ctr2 < MLKEM_N) ||
           (ctr3 < MLKEM_N)) {
        sha3_blocksx4_avx2(state);
        mlkem_redistribute_21_rand_avx2(state, rand + 0 * GEN_MATRIX_SIZE,
            rand + 1 * GEN_MATRIX_SIZE, rand + 2 * GEN_MATRIX_SIZE,
            rand + 3 * GEN_MATRIX_SIZE);

        p = rand;
        ctr0 += mlkem_rej_uniform_avx2(a + 0 * MLKEM_N + ctr0, MLKEM_N - ctr0,
            p, XOF_BLOCK_SIZE);
        p += GEN_MATRIX_SIZE;
        ctr1 += mlkem_rej_uniform_avx2(a + 1 * MLKEM_N + ctr1, MLKEM_N - ctr1,
            p, XOF_BLOCK_SIZE);
        p += GEN_MATRIX_SIZE;
        ctr2 += mlkem_rej_uniform_avx2(a + 2 * MLKEM_N + ctr2, MLKEM_N - ctr2,
            p, XOF_BLOCK_SIZE);
        p += GEN_MATRIX_SIZE;
        ctr3 += mlkem_rej_uniform_avx2(a + 3 * MLKEM_N + ctr3, MLKEM_N - ctr3,
            p, XOF_BLOCK_SIZE);
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(rand, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(state, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

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
static int mlkem_gen_matrix_k3_avx2(sword16* a, byte* seed, int transposed)
{
    int i;
    int k;
#ifdef WOLFSSL_SMALL_STACK
    byte *rand = NULL;
    word64 *state = NULL;
#else
    byte rand[4 * GEN_MATRIX_SIZE + 2];
    word64 state[25 * 4];
#endif
    unsigned int ctr0;
    unsigned int ctr1;
    unsigned int ctr2;
    unsigned int ctr3;
    byte* p;

#ifdef WOLFSSL_SMALL_STACK
    rand = (byte*)XMALLOC(4 * GEN_MATRIX_SIZE + 2, NULL,
                          DYNAMIC_TYPE_TMP_BUFFER);
    state = (word64*)XMALLOC(sizeof(word64) * 25 * 4, NULL,
                          DYNAMIC_TYPE_TMP_BUFFER);
    if ((rand == NULL) || (state == NULL)) {
        XFREE(rand, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(state, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }
#endif

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

        mlkem_sha3_128_blocksx4_seed_avx2(state, seed);
        mlkem_redistribute_21_rand_avx2(state,
            rand + 0 * GEN_MATRIX_SIZE, rand + 1 * GEN_MATRIX_SIZE,
            rand + 2 * GEN_MATRIX_SIZE, rand + 3 * GEN_MATRIX_SIZE);
        for (i = SHA3_128_BYTES; i < GEN_MATRIX_SIZE; i += SHA3_128_BYTES) {
            sha3_blocksx4_avx2(state);
            mlkem_redistribute_21_rand_avx2(state,
                rand + i + 0 * GEN_MATRIX_SIZE, rand + i + 1 * GEN_MATRIX_SIZE,
                rand + i + 2 * GEN_MATRIX_SIZE, rand + i + 3 * GEN_MATRIX_SIZE);
        }

        /* Sample random bytes to create a polynomial. */
        p = rand;
        ctr0 = mlkem_rej_uniform_n_avx2(a + 0 * MLKEM_N, MLKEM_N, p,
            GEN_MATRIX_SIZE);
        p += GEN_MATRIX_SIZE;
        ctr1 = mlkem_rej_uniform_n_avx2(a + 1 * MLKEM_N, MLKEM_N, p,
            GEN_MATRIX_SIZE);
        p += GEN_MATRIX_SIZE;
        ctr2 = mlkem_rej_uniform_n_avx2(a + 2 * MLKEM_N, MLKEM_N, p,
            GEN_MATRIX_SIZE);
        p += GEN_MATRIX_SIZE;
        ctr3 = mlkem_rej_uniform_n_avx2(a + 3 * MLKEM_N, MLKEM_N, p,
            GEN_MATRIX_SIZE);
        /* Create more blocks if too many rejected. */
        while ((ctr0 < MLKEM_N) || (ctr1 < MLKEM_N) || (ctr2 < MLKEM_N) ||
               (ctr3 < MLKEM_N)) {
            sha3_blocksx4_avx2(state);
            mlkem_redistribute_21_rand_avx2(state, rand + 0 * GEN_MATRIX_SIZE,
                rand + 1 * GEN_MATRIX_SIZE, rand + 2 * GEN_MATRIX_SIZE,
                rand + 3 * GEN_MATRIX_SIZE);

            p = rand;
            ctr0 += mlkem_rej_uniform_avx2(a + 0 * MLKEM_N + ctr0,
                MLKEM_N - ctr0, p, XOF_BLOCK_SIZE);
            p += GEN_MATRIX_SIZE;
            ctr1 += mlkem_rej_uniform_avx2(a + 1 * MLKEM_N + ctr1,
                MLKEM_N - ctr1, p, XOF_BLOCK_SIZE);
            p += GEN_MATRIX_SIZE;
            ctr2 += mlkem_rej_uniform_avx2(a + 2 * MLKEM_N + ctr2,
                MLKEM_N - ctr2, p, XOF_BLOCK_SIZE);
            p += GEN_MATRIX_SIZE;
            ctr3 += mlkem_rej_uniform_avx2(a + 3 * MLKEM_N + ctr3,
                MLKEM_N - ctr3, p, XOF_BLOCK_SIZE);
        }

        a += 4 * MLKEM_N;
    }

    readUnalignedWords64(state, seed, 4);
    /* Transposed value same as not. */
    state[4] = 0x1f0000 + (2 << 8) + 2;
    XMEMSET(state + 5, 0, sizeof(*state) * (25 - 5));
    state[20] = W64LIT(0x8000000000000000);
    for (i = 0; i < GEN_MATRIX_SIZE; i += SHA3_128_BYTES) {
#ifndef WC_SHA3_NO_ASM
        if (IS_INTEL_BMI2(cpuid_flags)) {
            sha3_block_bmi2(state);
        }
        else if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0))
        {
            sha3_block_avx2(state);
            RESTORE_VECTOR_REGISTERS();
        }
        else
#endif /* !WC_SHA3_NO_ASM */
        {
            BlockSha3(state);
        }
        XMEMCPY(rand + i, state, SHA3_128_BYTES);
    }
    ctr0 = mlkem_rej_uniform_n_avx2(a, MLKEM_N, rand, GEN_MATRIX_SIZE);
    while (ctr0 < MLKEM_N) {
#ifndef WC_SHA3_NO_ASM
        if (IS_INTEL_BMI2(cpuid_flags)) {
            sha3_block_bmi2(state);
        }
        else if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0))
        {
            sha3_block_avx2(state);
            RESTORE_VECTOR_REGISTERS();
        }
        else
#endif /* !WC_SHA3_NO_ASM */
        {
            BlockSha3(state);
        }
        XMEMCPY(rand, state, SHA3_128_BYTES);
        ctr0 += mlkem_rej_uniform_avx2(a + ctr0, MLKEM_N - ctr0, rand,
            XOF_BLOCK_SIZE);
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(rand, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(state, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

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
static int mlkem_gen_matrix_k4_avx2(sword16* a, byte* seed, int transposed)
{
    int i;
    int k;
#ifdef WOLFSSL_SMALL_STACK
    byte *rand = NULL;
    word64 *state = NULL;
#else
    byte rand[4 * GEN_MATRIX_SIZE + 2];
    word64 state[25 * 4];
#endif
    unsigned int ctr0;
    unsigned int ctr1;
    unsigned int ctr2;
    unsigned int ctr3;
    byte* p;

#ifdef WOLFSSL_SMALL_STACK
    rand = (byte*)XMALLOC(4 * GEN_MATRIX_SIZE + 2, NULL,
                          DYNAMIC_TYPE_TMP_BUFFER);
    state = (word64*)XMALLOC(sizeof(word64) * 25 * 4, NULL,
                          DYNAMIC_TYPE_TMP_BUFFER);
    if ((rand == NULL) || (state == NULL)) {
        XFREE(rand, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(state, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }
#endif

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

        mlkem_sha3_128_blocksx4_seed_avx2(state, seed);
        mlkem_redistribute_21_rand_avx2(state,
            rand + 0 * GEN_MATRIX_SIZE, rand + 1 * GEN_MATRIX_SIZE,
            rand + 2 * GEN_MATRIX_SIZE, rand + 3 * GEN_MATRIX_SIZE);
        for (i = SHA3_128_BYTES; i < GEN_MATRIX_SIZE; i += SHA3_128_BYTES) {
            sha3_blocksx4_avx2(state);
            mlkem_redistribute_21_rand_avx2(state,
                rand + i + 0 * GEN_MATRIX_SIZE, rand + i + 1 * GEN_MATRIX_SIZE,
                rand + i + 2 * GEN_MATRIX_SIZE, rand + i + 3 * GEN_MATRIX_SIZE);
        }

        /* Sample random bytes to create a polynomial. */
        p = rand;
        ctr0 = mlkem_rej_uniform_n_avx2(a + 0 * MLKEM_N, MLKEM_N, p,
            GEN_MATRIX_SIZE);
        p += GEN_MATRIX_SIZE;
        ctr1 = mlkem_rej_uniform_n_avx2(a + 1 * MLKEM_N, MLKEM_N, p,
            GEN_MATRIX_SIZE);
        p += GEN_MATRIX_SIZE;
        ctr2 = mlkem_rej_uniform_n_avx2(a + 2 * MLKEM_N, MLKEM_N, p,
            GEN_MATRIX_SIZE);
        p += GEN_MATRIX_SIZE;
        ctr3 = mlkem_rej_uniform_n_avx2(a + 3 * MLKEM_N, MLKEM_N, p,
            GEN_MATRIX_SIZE);
        /* Create more blocks if too many rejected. */
        while ((ctr0 < MLKEM_N) || (ctr1 < MLKEM_N) || (ctr2 < MLKEM_N) ||
               (ctr3 < MLKEM_N)) {
            sha3_blocksx4_avx2(state);
            mlkem_redistribute_21_rand_avx2(state, rand + 0 * GEN_MATRIX_SIZE,
                rand + 1 * GEN_MATRIX_SIZE, rand + 2 * GEN_MATRIX_SIZE,
                rand + 3 * GEN_MATRIX_SIZE);

            p = rand;
            ctr0 += mlkem_rej_uniform_avx2(a + 0 * MLKEM_N + ctr0,
                MLKEM_N - ctr0, p, XOF_BLOCK_SIZE);
            p += GEN_MATRIX_SIZE;
            ctr1 += mlkem_rej_uniform_avx2(a + 1 * MLKEM_N + ctr1,
                MLKEM_N - ctr1, p, XOF_BLOCK_SIZE);
            p += GEN_MATRIX_SIZE;
            ctr2 += mlkem_rej_uniform_avx2(a + 2 * MLKEM_N + ctr2,
                MLKEM_N - ctr2, p, XOF_BLOCK_SIZE);
            p += GEN_MATRIX_SIZE;
            ctr3 += mlkem_rej_uniform_avx2(a + 3 * MLKEM_N + ctr3,
                MLKEM_N - ctr3, p, XOF_BLOCK_SIZE);
        }

        a += 4 * MLKEM_N;
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(rand, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(state, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

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
static int mlkem_gen_matrix_k2_aarch64(sword16* a, byte* seed, int transposed)
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

    mlkem_shake128_blocksx3_seed_neon(state, seed);
    /* Sample random bytes to create a polynomial. */
    p = (byte*)st;
    ctr0 = mlkem_rej_uniform_neon(a + 0 * MLKEM_N, MLKEM_N, p, XOF_BLOCK_SIZE);
    p += 25 * 8;
    ctr1 = mlkem_rej_uniform_neon(a + 1 * MLKEM_N, MLKEM_N, p, XOF_BLOCK_SIZE);
    p += 25 * 8;
    ctr2 = mlkem_rej_uniform_neon(a + 2 * MLKEM_N, MLKEM_N, p, XOF_BLOCK_SIZE);
    while ((ctr0 < MLKEM_N) || (ctr1 < MLKEM_N) || (ctr2 < MLKEM_N)) {
        mlkem_sha3_blocksx3_neon(st);

        p = (byte*)st;
        ctr0 += mlkem_rej_uniform_neon(a + 0 * MLKEM_N + ctr0, MLKEM_N - ctr0,
            p, XOF_BLOCK_SIZE);
        p += 25 * 8;
        ctr1 += mlkem_rej_uniform_neon(a + 1 * MLKEM_N + ctr1, MLKEM_N - ctr1,
            p, XOF_BLOCK_SIZE);
        p += 25 * 8;
        ctr2 += mlkem_rej_uniform_neon(a + 2 * MLKEM_N + ctr2, MLKEM_N - ctr2,
            p, XOF_BLOCK_SIZE);
    }

    a += 3 * MLKEM_N;

    readUnalignedWords64(state, seed, 4);
    /* Transposed value same as not. */
    state[4] = 0x1f0000 + (1 << 8) + 1;
    XMEMSET(state + 5, 0, sizeof(*state) * (25 - 5));
    state[20] = W64LIT(0x8000000000000000);
    BlockSha3(state);
    p = (byte*)state;
    ctr0 = mlkem_rej_uniform_neon(a, MLKEM_N, p, XOF_BLOCK_SIZE);
    while (ctr0 < MLKEM_N) {
        BlockSha3(state);
        ctr0 += mlkem_rej_uniform_neon(a + ctr0, MLKEM_N - ctr0, p,
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
static int mlkem_gen_matrix_k3_aarch64(sword16* a, byte* seed, int transposed)
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

        mlkem_shake128_blocksx3_seed_neon(state, seed);
        /* Sample random bytes to create a polynomial. */
        p = (byte*)st;
        ctr0 = mlkem_rej_uniform_neon(a + 0 * MLKEM_N, MLKEM_N, p,
            XOF_BLOCK_SIZE);
        p += 25 * 8;
        ctr1 = mlkem_rej_uniform_neon(a + 1 * MLKEM_N, MLKEM_N, p,
            XOF_BLOCK_SIZE);
        p +=25 * 8;
        ctr2 = mlkem_rej_uniform_neon(a + 2 * MLKEM_N, MLKEM_N, p,
            XOF_BLOCK_SIZE);
        /* Create more blocks if too many rejected. */
        while ((ctr0 < MLKEM_N) || (ctr1 < MLKEM_N) || (ctr2 < MLKEM_N)) {
            mlkem_sha3_blocksx3_neon(st);

            p = (byte*)st;
            ctr0 += mlkem_rej_uniform_neon(a + 0 * MLKEM_N + ctr0,
                MLKEM_N - ctr0, p, XOF_BLOCK_SIZE);
            p += 25 * 8;
            ctr1 += mlkem_rej_uniform_neon(a + 1 * MLKEM_N + ctr1,
                MLKEM_N - ctr1, p, XOF_BLOCK_SIZE);
            p += 25 * 8;
            ctr2 += mlkem_rej_uniform_neon(a + 2 * MLKEM_N + ctr2,
                MLKEM_N - ctr2, p, XOF_BLOCK_SIZE);
        }

        a += 3 * MLKEM_N;
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
static int mlkem_gen_matrix_k4_aarch64(sword16* a, byte* seed, int transposed)
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

        mlkem_shake128_blocksx3_seed_neon(state, seed);
        /* Sample random bytes to create a polynomial. */
        p = (byte*)st;
        ctr0 = mlkem_rej_uniform_neon(a + 0 * MLKEM_N, MLKEM_N, p,
            XOF_BLOCK_SIZE);
        p += 25 * 8;
        ctr1 = mlkem_rej_uniform_neon(a + 1 * MLKEM_N, MLKEM_N, p,
            XOF_BLOCK_SIZE);
        p += 25 * 8;
        ctr2 = mlkem_rej_uniform_neon(a + 2 * MLKEM_N, MLKEM_N, p,
            XOF_BLOCK_SIZE);
        /* Create more blocks if too many rejected. */
        while ((ctr0 < MLKEM_N) || (ctr1 < MLKEM_N) || (ctr2 < MLKEM_N)) {
            mlkem_sha3_blocksx3_neon(st);

            p = (byte*)st;
            ctr0 += mlkem_rej_uniform_neon(a + 0 * MLKEM_N + ctr0,
                MLKEM_N - ctr0, p, XOF_BLOCK_SIZE);
            p += 25 * 8;
            ctr1 += mlkem_rej_uniform_neon(a + 1 * MLKEM_N + ctr1,
                MLKEM_N - ctr1, p, XOF_BLOCK_SIZE);
            p += 25 * 8;
            ctr2 += mlkem_rej_uniform_neon(a + 2 * MLKEM_N + ctr2,
                MLKEM_N - ctr2, p, XOF_BLOCK_SIZE);
        }

        a += 3 * MLKEM_N;
    }

    readUnalignedWords64(state, seed, 4);
    /* Transposed value same as not. */
    state[4] = 0x1f0000 + (3 << 8) + 3;
    XMEMSET(state + 5, 0, sizeof(*state) * (25 - 5));
    state[20] = W64LIT(0x8000000000000000);
    BlockSha3(state);
    p = (byte*)state;
    ctr0 = mlkem_rej_uniform_neon(a, MLKEM_N, p, XOF_BLOCK_SIZE);
    while (ctr0 < MLKEM_N) {
        BlockSha3(state);
        ctr0 += mlkem_rej_uniform_neon(a + ctr0, MLKEM_N - ctr0, p,
            XOF_BLOCK_SIZE);
    }

    return 0;
}
#endif
#endif /* USE_INTEL_SPEEDUP */

#if !(defined(WOLFSSL_ARMASM) && defined(__aarch64__))
/* Absorb the seed data for squeezing out pseudo-random data.
 *
 * FIPS 203, Section 4.1:
 * 1. XOF.init() = SHA128.Init().
 * 2. XOF.Absorb(ctx,str) = SHAKE128.Absorb(ctx,str).
 *
 * @param  [in, out]  shake128  SHAKE-128 object.
 * @param  [in]       seed      Data to absorb.
 * @param  [in]       len       Length of data to absorb in bytes.
 * @return  0 on success always.
 */
static int mlkem_xof_absorb(wc_Shake* shake128, byte* seed, int len)
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
 * FIPS 203, Section 4.1:
 * 3. XOF.Absorb(ctx,l) = SHAKE128.Squeeze(ctx,8.l).
 *
 * @param  [in, out]  shake128  SHAKE-128 object.
 * @param  [out]      out       Buffer to write to.
 * @param  [in]       blocks    Number of blocks to write.
 * @return  0 on success always.
 */
static int mlkem_xof_squeezeblocks(wc_Shake* shake128, byte* out, int blocks)
{
    return wc_Shake128_SqueezeBlocks(shake128, out, blocks);
}
#endif

/* New/Initialize SHA-3 object.
 *
 * FIPS 203, Section 4.1:
 * H(s) := SHA3-256(s)
 *
 * @param  [in, out]  hash    SHA-3 object.
 * @param  [in]       heap    Dynamic memory allocator hint.
 * @param  [in]       devId   Device id.
 * @return  0 on success always.
 */
int mlkem_hash_new(wc_Sha3* hash, void* heap, int devId)
{
    return wc_InitSha3_256(hash, heap, devId);
}

/* Free SHA-3 object.
 *
 * FIPS 203, Section 4.1:
 * H(s) := SHA3-256(s)
 *
 * @param  [in, out]  hash  SHA-3 object.
 */
void mlkem_hash_free(wc_Sha3* hash)
{
    wc_Sha3_256_Free(hash);
}

/* Hash data using SHA3-256 with SHA-3 object.
 *
 * FIPS 203, Section 4.1:
 * H(s) := SHA3-256(s)
 *
 * @param  [in, out]  hash     SHA-3 object.
 * @param  [io]       data     Data to be hashed.
 * @param  [in]       dataLen  Length of data in bytes.
 * @param  [out]      out      Hash of data.
 * @return  0 on success.
 */
int mlkem_hash256(wc_Sha3* hash, const byte* data, word32 dataLen, byte* out)
{
    int ret;

    /* Process all data. */
    ret = wc_Sha3_256_Update(hash, data, dataLen);
    if (ret == 0) {
        /* Calculate Hash of data passed in an re-initialize. */
        ret = wc_Sha3_256_Final(hash, out);
    }

    return ret;
}

/* Hash one or two blocks of data using SHA3-512 with SHA-3 object.
 *
 * FIPS 203, Section 4.1:
 * G(s) := SHA3-512(s)
 *
 * @param  [in, out]  hash      SHA-3 object.
 * @param  [io]       data1     First block of data to be hashed.
 * @param  [in]       data1Len  Length of first block of data in bytes.
 * @param  [io]       data2     Second block of data to be hashed. May be NULL.
 * @param  [in]       data2Len  Length of second block of data in bytes.
 * @param  [out]      out       Hash of all data.
 * @return  0 on success.
 */
int mlkem_hash512(wc_Sha3* hash, const byte* data1, word32 data1Len,
    const byte* data2, word32 data2Len, byte* out)
{
    int ret;

    /* Process first block of data. */
    ret = wc_Sha3_512_Update(hash, data1, data1Len);
    /* Check if there is a second block of data. */
    if ((ret == 0) && (data2Len > 0)) {
        /* Process second block of data. */
        ret = wc_Sha3_512_Update(hash, data2, data2Len);
    }
    if (ret == 0) {
        /* Calculate Hash of data passed in an re-initialize. */
        ret = wc_Sha3_512_Final(hash, out);
    }

    return ret;
}

/* Initialize SHAKE-256 object.
 *
 * @param  [in, out]  shake256  SHAKE-256 object.
 */
void mlkem_prf_init(wc_Shake* prf)
{
    XMEMSET(prf->s, 0, sizeof(prf->s));
}

/* New/Initialize SHAKE-256 object.
 *
 * FIPS 203, Section 4.1:
 * PRF_eta(s,b) := SHA256(s||b,8.64.eta)
 *
 * @param  [in, out]  shake256  SHAKE-256 object.
 * @param  [in]       heap      Dynamic memory allocator hint.
 * @param  [in]       devId     Device id.
 * @return  0 on success always.
 */
int mlkem_prf_new(wc_Shake* prf, void* heap, int devId)
{
    return wc_InitShake256(prf, heap, devId);
}

/* Free SHAKE-256 object.
 *
 * FIPS 203, Section 4.1:
 * PRF_eta(s,b) := SHA256(s||b,8.64.eta)
 *
 * @param  [in, out]  shake256  SHAKE-256 object.
 */
void mlkem_prf_free(wc_Shake* prf)
{
    wc_Shake256_Free(prf);
}

#if !(defined(WOLFSSL_ARMASM) && defined(__aarch64__))
/* Create pseudo-random data from the key using SHAKE-256.
 *
 * FIPS 203, Section 4.1:
 * PRF_eta(s,b) := SHA256(s||b,8.64.eta)
 *
 * @param  [in, out]  shake256  SHAKE-256 object.
 * @param  [out]      out       Buffer to write to.
 * @param  [in]       outLen    Number of bytes to write.
 * @param  [in]       key       Data to derive from. Must be:
 *                                WC_ML_KEM_SYM_SZ + 1 bytes in length.
 * @return  0 on success always.
 */
static int mlkem_prf(wc_Shake* shake256, byte* out, unsigned int outLen,
    const byte* key)
{
#ifdef USE_INTEL_SPEEDUP
    word64 state[25];

    (void)shake256;

    /* Put first WC_ML_KEM_SYM_SZ bytes og key into blank state. */
    readUnalignedWords64(state, key, WC_ML_KEM_SYM_SZ / sizeof(word64));
    /* Last byte in with end of content marker. */
    state[WC_ML_KEM_SYM_SZ / 8] = 0x1f00 | key[WC_ML_KEM_SYM_SZ];
    /* Set rest of state to 0. */
    XMEMSET(state + WC_ML_KEM_SYM_SZ / 8 + 1, 0,
        (25 - WC_ML_KEM_SYM_SZ / 8 - 1) * sizeof(word64));
    /* ... except for rate marker. */
    state[WC_SHA3_256_COUNT - 1] = W64LIT(0x8000000000000000);

    /* Generate as much output as is required. */
    while (outLen > 0) {
        /* Get as much of an output block as is needed. */
        unsigned int len = min(outLen, WC_SHA3_256_BLOCK_SIZE);

        /* Perform a block operation on the state for next block of output. */
#ifndef WC_SHA3_NO_ASM
        if (IS_INTEL_BMI2(cpuid_flags)) {
            sha3_block_bmi2(state);
        }
        else if (IS_INTEL_AVX2(cpuid_flags) &&
                 (SAVE_VECTOR_REGISTERS2() == 0)) {
            sha3_block_avx2(state);
            RESTORE_VECTOR_REGISTERS();
        }
        else
#endif /* !WC_SHA3_NO_ASM */
        {
            BlockSha3(state);
        }

        /* Copy the state as output. */
        XMEMCPY(out, state, len);
        /* Update output pointer and length. */
        out += len;
        outLen -= len;
    }

    return 0;
#else
    int ret;

    /* Process all data. */
    ret = wc_Shake256_Update(shake256, key, WC_ML_KEM_SYM_SZ + 1);
    if (ret == 0) {
        /* Calculate Hash of data passed in an re-initialize. */
        ret = wc_Shake256_Final(shake256, out, outLen);
    }

    return ret;
#endif
}
#endif

#ifdef WOLFSSL_MLKEM_KYBER
#ifdef USE_INTEL_SPEEDUP
/* Create pseudo-random key from the seed using SHAKE-256.
 *
 * @param  [in]  seed      Data to derive from.
 * @param  [in]  seedLen   Length of data to derive from in bytes.
 * @param  [out] out       Buffer to write to.
 * @param  [in]  outLen    Number of bytes to derive.
 * @return  0 on success always.
 */
int mlkem_kdf(byte* seed, int seedLen, byte* out, int outLen)
{
    word64 state[25];
    word32 len64 = seedLen / 8;

    readUnalignedWords64(state, seed, len64);
    state[len64] = 0x1f;
    XMEMSET(state + len64 + 1, 0, (25 - len64 - 1) * sizeof(word64));
    state[WC_SHA3_256_COUNT - 1] = W64LIT(0x8000000000000000);

#ifndef WC_SHA3_NO_ASM
    if (IS_INTEL_BMI2(cpuid_flags)) {
        sha3_block_bmi2(state);
    }
    else if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        sha3_block_avx2(state);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
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
int mlkem_kdf(byte* seed, int seedLen, byte* out, int outLen)
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
#endif

#ifndef WOLFSSL_NO_ML_KEM
/* Derive the secret from z and cipher text.
 *
 * @param [in, out]  shake256  SHAKE-256 object.
 * @param [in]       z         Implicit rejection value.
 * @param [in]       ct        Cipher text.
 * @param [in]       ctSz      Length of cipher text in bytes.
 * @param [out]      ss        Shared secret.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation failed.
 * @return  Other negative when a hash error occurred.
 */
int mlkem_derive_secret(wc_Shake* shake256, const byte* z, const byte* ct,
    word32 ctSz, byte* ss)
{
    int ret;

#ifdef USE_INTEL_SPEEDUP
    XMEMCPY(shake256->t, z, WC_ML_KEM_SYM_SZ);
    XMEMCPY(shake256->t, ct, WC_SHA3_256_COUNT * 8 - WC_ML_KEM_SYM_SZ);
    shake256->i = WC_ML_KEM_SYM_SZ;
    ct += WC_SHA3_256_COUNT * 8 - WC_ML_KEM_SYM_SZ;
    ctSz -= WC_SHA3_256_COUNT * 8 - WC_ML_KEM_SYM_SZ;
    ret = wc_Shake256_Update(shake256, ct, ctSz);
    if (ret == 0) {
        ret = wc_Shake256_Final(shake256, ss, WC_ML_KEM_SS_SZ);
    }
#else
    ret = wc_Shake256_Update(shake256, z, WC_ML_KEM_SYM_SZ);
    if (ret == 0) {
        ret = wc_Shake256_Update(shake256, ct, ctSz);
    }
    if (ret == 0) {
        ret = wc_Shake256_Final(shake256, ss, WC_ML_KEM_SS_SZ);
    }
#endif

    return ret;
}
#endif

#if !defined(WOLFSSL_ARMASM)
/* Rejection sampling on uniform random bytes to generate uniform random
 * integers mod q.
 *
 * FIPS 203, Algorithm 7: SampleNTT(B)
 * Takes a 32-byte seed and two indices as input and outputs a pseudorandom
 * element of T_q.
 *   ...
 *   4: while j < 256 do
 *   5:     (ctx,C) <- XOF.Squeeze(ctx,3)
 *   6:     d1 <- C[0] + 256.(C[1] mod 16)
 *   7:     d2 <- lower(C[1] / 16) + 16.C[2]
 *   8:     if d1 < q then
 *   9:         a_hat[j] <- d1
 *  10:         j <- j + 1
 *  11:     end if
 *  12:     if d2 < q and j < 256 then
 *  13:         a_hat[j] <- d2
 *  14:         j <- j + 1
 *  15:     end if
 *  16: end while
 *  ...
 *
 * @param  [out]  p     Uniform random integers mod q.
 * @param  [in]   len   Maximum number of integers.
 * @param  [in]   r     Uniform random bytes buffer.
 * @param  [in]   rLen  Length of random data in buffer.
 * @return  Number of integers sampled.
 */
static unsigned int mlkem_rej_uniform_c(sword16* p, unsigned int len,
    const byte* r, unsigned int rLen)
{
    unsigned int i;
    unsigned int j;

#if defined(WOLFSSL_MLKEM_SMALL) || !defined(WC_64BIT_CPU) || \
    defined(BIG_ENDIAN_ORDER)
    /* Keep sampling until maximum number of integers reached or buffer used up.
     * Step 4. */
    for (i = 0, j = 0; (i < len) && (j <= rLen - 3); j += 3) {
        /* Step 5 - caller generates and now using 3 bytes of it. */
        /* Use 24 bits (3 bytes) as two 12 bits integers. */
        /* Step 6. */
        sword16 v0 = ((r[0] >> 0) | ((word16)r[1] << 8)) & 0xFFF;
        /* Step 7. */
        sword16 v1 = ((r[1] >> 4) | ((word16)r[2] << 4)) & 0xFFF;

        /* Reject first 12-bit integer if greater than or equal to q.
         * Step 8 */
        if (v0 < MLKEM_Q) {
            /* Steps 9-10 */
            p[i++] = v0;
        }
        /* Check second if we don't have enough integers yet.
         * Reject second 12-bit integer if greater than or equal to q.
         * Step 12 */
        if ((i < len) && (v1 < MLKEM_Q)) {
            /* Steps 13-14 */
            p[i++] = v1;
        }

        /* Move over used bytes. */
        r += 3;
    }
#else
    /* Unroll loops. Minimal work per loop. */
    unsigned int minJ;

    /* Calculate minimum number of 6 byte data blocks to get all required
     * numbers assuming no rejections. */
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

        p[i] = v0;
        i += (v0 < MLKEM_Q);
        p[i] = v1;
        i += (v1 < MLKEM_Q);
        p[i] = v2;
        i += (v2 < MLKEM_Q);
        p[i] = v3;
        i += (v3 < MLKEM_Q);

        /* Move over used bytes. */
        r += 6;
    }
    /* Check whether we have all the numbers we need. */
    if (j < rLen) {
        /* Keep trying until we have less than 4 numbers to find or data is used
         * up. */
        for (; (i + 4 < len) && (j < rLen); j += 6) {
            /* Use 48 bits (6 bytes) as four 12-bit integers. */
            word64 r_word = readUnalignedWord64(r);
            sword16 v0 =  r_word        & 0xfff;
            sword16 v1 = (r_word >> 12) & 0xfff;
            sword16 v2 = (r_word >> 24) & 0xfff;
            sword16 v3 = (r_word >> 36) & 0xfff;

            p[i] = v0;
            i += (v0 < MLKEM_Q);
            p[i] = v1;
            i += (v1 < MLKEM_Q);
            p[i] = v2;
            i += (v2 < MLKEM_Q);
            p[i] = v3;
            i += (v3 < MLKEM_Q);

            /* Move over used bytes. */
            r += 6;
        }
        /* Keep trying until we have all the numbers we need or the data is used
         * up. */
        for (; (i < len) && (j < rLen); j += 6) {
            /* Use 48 bits (6 bytes) as four 12-bit integers. */
            word64 r_word = readUnalignedWord64(r);
            sword16 v0 =  r_word        & 0xfff;
            sword16 v1 = (r_word >> 12) & 0xfff;
            sword16 v2 = (r_word >> 24) & 0xfff;
            sword16 v3 = (r_word >> 36) & 0xfff;

            /* Reject first 12-bit integer if greater than or equal to q. */
            if (v0 < MLKEM_Q) {
                p[i++] = v0;
            }
            /* Check second if we don't have enough integers yet.
             * Reject second 12-bit integer if greater than or equal to q. */
            if ((i < len) && (v1 < MLKEM_Q)) {
                p[i++] = v1;
            }
            /* Check second if we don't have enough integers yet.
             * Reject third 12-bit integer if greater than or equal to q. */
            if ((i < len) && (v2 < MLKEM_Q)) {
                p[i++] = v2;
            }
            /* Check second if we don't have enough integers yet.
             * Reject fourth 12-bit integer if greater than or equal to q. */
            if ((i < len) && (v3 < MLKEM_Q)) {
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

#if !defined(WOLFSSL_MLKEM_MAKEKEY_SMALL_MEM) || \
    !defined(WOLFSSL_MLKEM_ENCAPSULATE_SMALL_MEM)

#if !(defined(WOLFSSL_ARMASM) && defined(__aarch64__))
/* Deterministically generate a matrix (or transpose) of uniform integers mod q.
 *
 * Seed used with XOF to generate random bytes.
 *
 * FIPS 203, Algorithm 13: K-PKE.KeyGen(d)
 *   ...
 *   3: for (i <- 0; i < k; i++)
 *   4:     for (j <- 0; j < k; j++)
 *   5:         A_hat[i,j] <- SampleNTT(rho||j||i)
 *   6:     end for
 *   7: end for
 *   ...
 * FIPS 203, Algorithm 14: K-PKE.Encrypt(ek_PKE,m,r)
 *   ...
 *   4: for (i <- 0; i < k; i++)
 *   5:     for (j <- 0; j < k; j++)
 *   6:         A_hat[i,j] <- SampleNTT(rho||j||i)  (Transposed is rho||i||j)
 *   7:     end for
 *   8: end for
 *   ...
 * FIPS 203, Algorithm 7: SampleNTT(B)
 * Takes a 32-byte seed and two indices as input and outputs a pseudorandom
 * element of T_q.
 *   1: ctx <- XOF.init()
 *   2: ctx <- XOF.Absorb(ctx,B)
 *   3: j <- 0
 *   4: while j < 256 do
 *   5:     (ctx,C) <- XOF.Squeeze(ctx,3)
 *   ...
 *  16: end while
 *  17: return a_hat
 *
 * @param  [in]   prf         XOF object.
 * @param  [out]  a           Matrix of uniform integers.
 * @param  [in]   k           Number of dimensions. k x k polynomials.
 * @param  [in]   seed        Bytes to seed XOF generation.
 * @param  [in]   transposed  Whether A or A^T is generated.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails. Only possible when
 * WOLFSSL_SMALL_STACK is defined.
 */
static int mlkem_gen_matrix_c(MLKEM_PRF_T* prf, sword16* a, int k, byte* seed,
    int transposed)
{
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    byte* rand;
#else
    byte rand[GEN_MATRIX_SIZE + 2];
#endif
    byte extSeed[WC_ML_KEM_SYM_SZ + 2];
    int ret = 0;
    int i;

    /* Copy seed into buffer than has space for i and j to be appended. */
    XMEMCPY(extSeed, seed, WC_ML_KEM_SYM_SZ);

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    /* Allocate large amount of memory to hold random bytes to be samples. */
    rand = (byte*)XMALLOC(GEN_MATRIX_SIZE + 2, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (rand == NULL) {
        ret = MEMORY_E;
    }
#endif

#if !defined(WOLFSSL_MLKEM_SMALL) && defined(WC_64BIT_CPU)
    /* Loading 64 bits, only using 48 bits. Loading 2 bytes more than used. */
    if (ret == 0) {
        rand[GEN_MATRIX_SIZE+0] = 0xff;
        rand[GEN_MATRIX_SIZE+1] = 0xff;
    }
#endif

    /* Generate each vector of polynomials.
     * Alg 13, Step 3. Alg 14, Step 4. */
    for (i = 0; (ret == 0) && (i < k); i++, a += k * MLKEM_N) {
        int j;
        /* Generate each polynomial in vector from seed with indices.
         * Alg 13, Step 4. Alg 14, Step 5. */
        for (j = 0; (ret == 0) && (j < k); j++) {
            if (transposed) {
                /* Alg 14, Step 6: .. rho||i||j ... */
                extSeed[WC_ML_KEM_SYM_SZ + 0] = i;
                extSeed[WC_ML_KEM_SYM_SZ + 1] = j;
            }
            else {
                /* Alg 13, Step 5: .. rho||j||i ... */
                extSeed[WC_ML_KEM_SYM_SZ + 0] = j;
                extSeed[WC_ML_KEM_SYM_SZ + 1] = i;
            }
            /* Absorb the index specific seed.
             * Alg 7, Step 1-2 */
            ret = mlkem_xof_absorb(prf, extSeed, sizeof(extSeed));
            if (ret == 0) {
                /* Create data based on the seed.
                 * Alg 7, Step 5. Generating enough to, on average, be able to
                 * get enough valid values. */
                ret = mlkem_xof_squeezeblocks(prf, rand, GEN_MATRIX_NBLOCKS);
            }
            if (ret == 0) {
                unsigned int ctr;

                /* Sample random bytes to create a polynomial.
                 * Alg 7, Step 3 - implicitly counter is 0.
                 * Alg 7, Step 4-16. */
                ctr = mlkem_rej_uniform_c(a + j * MLKEM_N, MLKEM_N, rand,
                    GEN_MATRIX_SIZE);
                /* Create more blocks if too many rejected.
                 * Alg 7, Step 4. */
                while (ctr < MLKEM_N) {
                    /* Alg 7, Step 5. */
                    mlkem_xof_squeezeblocks(prf, rand, 1);
                    /* Alg 7, Step 4-16. */
                    ctr += mlkem_rej_uniform_c(a + j * MLKEM_N + ctr,
                        MLKEM_N - ctr, rand, XOF_BLOCK_SIZE);
                }
            }
        }
    }

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
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
 * FIPS 203, Algorithm 13: K-PKE.KeyGen(d), Steps 3-7
 * FIPS 203, Algorithm 14: K-PKE.Encrypt(ek_PKE,m,r), Steps 4-8
 *
 * @param  [in]   prf         XOF object.
 * @param  [out]  a           Matrix of uniform integers.
 * @param  [in]   k           Number of dimensions. k x k polynomials.
 * @param  [in]   seed        Bytes to seed XOF generation.
 * @param  [in]   transposed  Whether A or A^T is generated.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails. Only possible when
 * WOLFSSL_SMALL_STACK is defined.
 */
int mlkem_gen_matrix(MLKEM_PRF_T* prf, sword16* a, int k, byte* seed,
    int transposed)
{
    int ret;

#if defined(WOLFSSL_KYBER512) || defined(WOLFSSL_WC_ML_KEM_512)
    if (k == WC_ML_KEM_512_K) {
#if defined(WOLFSSL_ARMASM) && defined(__aarch64__)
        ret = mlkem_gen_matrix_k2_aarch64(a, seed, transposed);
#else
    #ifdef USE_INTEL_SPEEDUP
        if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
            ret = mlkem_gen_matrix_k2_avx2(a, seed, transposed);
            RESTORE_VECTOR_REGISTERS();
        }
        else
    #endif
        {
            ret = mlkem_gen_matrix_c(prf, a, WC_ML_KEM_512_K, seed, transposed);
        }
#endif
    }
    else
#endif
#if defined(WOLFSSL_KYBER768) || defined(WOLFSSL_WC_ML_KEM_768)
    if (k == WC_ML_KEM_768_K) {
#if defined(WOLFSSL_ARMASM) && defined(__aarch64__)
        ret = mlkem_gen_matrix_k3_aarch64(a, seed, transposed);
#else
    #ifdef USE_INTEL_SPEEDUP
        if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
            ret = mlkem_gen_matrix_k3_avx2(a, seed, transposed);
            RESTORE_VECTOR_REGISTERS();
        }
        else
    #endif
        {
            ret = mlkem_gen_matrix_c(prf, a, WC_ML_KEM_768_K, seed, transposed);
        }
#endif
    }
    else
#endif
#if defined(WOLFSSL_KYBER1024) || defined(WOLFSSL_WC_ML_KEM_1024)
    if (k == WC_ML_KEM_1024_K) {
#if defined(WOLFSSL_ARMASM) && defined(__aarch64__)
        ret = mlkem_gen_matrix_k4_aarch64(a, seed, transposed);
#else
    #ifdef USE_INTEL_SPEEDUP
        if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
            ret = mlkem_gen_matrix_k4_avx2(a, seed, transposed);
            RESTORE_VECTOR_REGISTERS();
        }
        else
    #endif
        {
            ret = mlkem_gen_matrix_c(prf, a, WC_ML_KEM_1024_K, seed,
                transposed);
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

#endif

#if defined(WOLFSSL_MLKEM_MAKEKEY_SMALL_MEM) || \
    defined(WOLFSSL_MLKEM_ENCAPSULATE_SMALL_MEM)

/* Deterministically generate a matrix (or transpose) of uniform integers mod q.
 *
 * Seed used with XOF to generate random bytes.
 *
 * FIPS 203, Algorithm 13: K-PKE.KeyGen(d)
 * ...
 * 4:     for (j <- 0; j < k; j++)
 * 5:         A_hat[i,j] <- SampleNTT(rho||j||i)
 * 6:     end for
 * ...
 * FIPS 203, Algorithm 14: K-PKE.Encrypt(ek_PKE,m,r)
 * ...
 * 5:     for (j <- 0; j < k; j++)
 * 6:         A_hat[i,j] <- SampleNTT(rho||j||i)  (Transposed is rho||i||j)
 * 7:     end for
 * ...
 *
 * @param  [in]   prf         XOF object.
 * @param  [out]  a           Matrix of uniform integers.
 * @param  [in]   k           Number of dimensions. k x k polynomials.
 * @param  [in]   seed        Bytes to seed XOF generation.
 * @param  [in]   i           Index of vector to generate.
 * @param  [in]   transposed  Whether A or A^T is generated.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails. Only possible when
 * WOLFSSL_SMALL_STACK is defined.
 */
static int mlkem_gen_matrix_i(MLKEM_PRF_T* prf, sword16* a, int k, byte* seed,
    int i, int transposed)
{
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    byte* rand;
#else
    byte rand[GEN_MATRIX_SIZE + 2];
#endif
    byte extSeed[WC_ML_KEM_SYM_SZ + 2];
    int ret = 0;
    int j;

    XMEMCPY(extSeed, seed, WC_ML_KEM_SYM_SZ);

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    /* Allocate large amount of memory to hold random bytes to be samples. */
    rand = (byte*)XMALLOC(GEN_MATRIX_SIZE + 2, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (rand == NULL) {
        ret = MEMORY_E;
    }
#endif

#if !defined(WOLFSSL_MLKEM_SMALL) && defined(WC_64BIT_CPU)
    /* Loading 64 bits, only using 48 bits. Loading 2 bytes more than used. */
    if (ret == 0) {
        rand[GEN_MATRIX_SIZE+0] = 0xff;
        rand[GEN_MATRIX_SIZE+1] = 0xff;
    }
#endif

    /* Generate each polynomial in vector from seed with indices.
     * Alg 13, Step 4. Alg 14, Step 5. */
    for (j = 0; (ret == 0) && (j < k); j++) {
        if (transposed) {
            /* Alg 14, Step 6: .. rho||i||j ... */
            extSeed[WC_ML_KEM_SYM_SZ + 0] = i;
            extSeed[WC_ML_KEM_SYM_SZ + 1] = j;
        }
        else {
            /* Alg 13, Step 5: .. rho||j||i ... */
            extSeed[WC_ML_KEM_SYM_SZ + 0] = j;
            extSeed[WC_ML_KEM_SYM_SZ + 1] = i;
        }
        /* Absorb the index specific seed.
         * Alg 7, Step 1-2 */
        ret = mlkem_xof_absorb(prf, extSeed, sizeof(extSeed));
        if (ret == 0) {
            /* Create out based on the seed.
             * Alg 7, Step 5. Generating enough to, on average, be able to get
             * enough valid values. */
            ret = mlkem_xof_squeezeblocks(prf, rand, GEN_MATRIX_NBLOCKS);
        }
        if (ret == 0) {
            unsigned int ctr;

            /* Sample random bytes to create a polynomial.
             * Alg 7, Step 3 - implicitly counter is 0.
             * Alg 7, Step 4-16. */
            ctr = mlkem_rej_uniform_c(a + j * MLKEM_N, MLKEM_N, rand,
                GEN_MATRIX_SIZE);
            /* Create more blocks if too many rejected.
             * Alg 7, Step 4. */
            while (ctr < MLKEM_N) {
                /* Alg 7, Step 5. */
                mlkem_xof_squeezeblocks(prf, rand, 1);
                /* Alg 7, Step 4-16. */
                ctr += mlkem_rej_uniform_c(a + j * MLKEM_N + ctr,
                    MLKEM_N - ctr, rand, XOF_BLOCK_SIZE);
            }
        }
    }

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    /* Dispose of temporary buffer. */
    XFREE(rand, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}

#endif


/******************************************************************************/

/* Subtract one 2 bit value from another out of a larger number.
 *
 * FIPS 203, Algorithm 8: SmaplePolyCBD_eta(B)
 * Takes a seed as input and outputs a pseudorandom sample from the distribution
 * D_eta(R_q).
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
 * FIPS 203, Algorithm 8: SmaplePolyCBD_eta(B)
 * Takes a seed as input and outputs a pseudorandom sample from the distribution
 * D_eta(R_q).
 *
 * @param [out]  p  Polynomial computed.
 * @param [in]   r  Random bytes.
 */
static void mlkem_cbd_eta2(sword16* p, const byte* r)
{
    unsigned int i;

#ifndef WORD64_AVAILABLE
    /* Calculate eight integer coefficients at a time. */
    for (i = 0; i < MLKEM_N; i += 8) {
    #ifdef WOLFSSL_MLKEM_SMALL
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

    #ifdef WOLFSSL_MLKEM_SMALL
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
    for (i = 0; i < MLKEM_N; i += 16) {
    #ifdef WOLFSSL_MLKEM_SMALL
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

    #ifdef WOLFSSL_MLKEM_SMALL
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
 * FIPS 203, Algorithm 8: SmaplePolyCBD_eta(B)
 * Takes a seed as input and outputs a pseudorandom sample from the distribution
 * D_eta(R_q).
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
 * FIPS 203, Algorithm 8: SmaplePolyCBD_eta(B)
 * Takes a seed as input and outputs a pseudorandom sample from the distribution
 * D_eta(R_q).
 *
 * @param [out]  p  Polynomial computed.
 * @param [in]   r  Random bytes.
 */
static void mlkem_cbd_eta3(sword16* p, const byte* r)
{
    unsigned int i;

#if defined(WOLFSSL_SMALL_STACK) || defined(WOLFSSL_MLKEM_NO_LARGE_CODE) || \
    defined(BIG_ENDIAN_ORDER)
#ifndef WORD64_AVAILABLE
    /* Calculate four integer coefficients at a time. */
    for (i = 0; i < MLKEM_N; i += 4) {
    #ifdef WOLFSSL_MLKEM_SMALL
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

    #ifdef WOLFSSL_MLKEM_SMALL
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
    for (i = 0; i < MLKEM_N; i += 8) {
    #ifdef WOLFSSL_MLKEM_SMALL
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

    #ifdef WOLFSSL_MLKEM_SMALL
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
    for (i = 0; i < MLKEM_N; i += 16) {
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
#endif /* WOLFSSL_SMALL_STACK || WOLFSSL_MLKEM_NO_LARGE_CODE ||
        * BIG_ENDIAN_ORDER */
}
#endif

#if !(defined(__aarch64__) && defined(WOLFSSL_ARMASM))

/* Get noise/error by calculating random bytes and sampling to a binomial
 * distribution.
 *
 * FIPS 203, Algorithm 13: K-PKE.KeyGen(d)
 *   ...
 *   9:     s[i] <- SamplePolyCBD_eta_1(PRF_eta_1(rho, N))
 *   ...
 *  13:     e[i] <- SamplePolyCBD_eta_1(PRF_eta_1(rho, N))
 *   ...
 * FIPS 203, Algorithm 14: K-PKE.Encrypt(ek_PKE,m,r)
 *   ...
 *  10:     y[i] <- SamplePolyCBD_eta_1(PRF_eta_1(r, N))
 *   ...
 *
 * @param  [in, out]  prf   Pseudo-random function object.
 * @param  [out]      p     Polynomial.
 * @param  [in]       seed  Seed to use when calculating random.
 * @param  [in]       eta1  Size of noise/error integers.
 * @return  0 on success.
 */
static int mlkem_get_noise_eta1_c(MLKEM_PRF_T* prf, sword16* p,
    const byte* seed, byte eta1)
{
    int ret;

    (void)eta1;

#if defined(WOLFSSL_KYBER512) || defined(WOLFSSL_WC_ML_KEM_512)
    if (eta1 == MLKEM_CBD_ETA3) {
        byte rand[ETA3_RAND_SIZE];

        /* Calculate random bytes from seed with PRF. */
        ret = mlkem_prf(prf, rand, sizeof(rand), seed);
        if (ret == 0) {
            /* Sample for values in range -3..3 from 3 bits of random. */
            mlkem_cbd_eta3(p, rand);
         }
    }
    else
#endif
    {
        byte rand[ETA2_RAND_SIZE];

        /* Calculate random bytes from seed with PRF. */
        ret = mlkem_prf(prf, rand, sizeof(rand), seed);
        if (ret == 0) {
            /* Sample for values in range -2..2 from 2 bits of random. */
            mlkem_cbd_eta2(p, rand);
        }
    }

    return ret;
}

/* Get noise/error by calculating random bytes and sampling to a binomial
 * distribution. Values -2..2
 *
 * FIPS 203, Algorithm 14: K-PKE.Encrypt(ek_PKE,m,r)
 *   ...
 *  14:     e1[i] <- SamplePolyCBD_eta_2(PRF_eta_2(r, N))
 *   ...
 *  17:     e2[i] <- SamplePolyCBD_eta_2(PRF_eta_2(r, N))
 *   ...
 *
 * @param  [in, out]  prf   Pseudo-random function object.
 * @param  [out]      p     Polynomial.
 * @param  [in]       seed  Seed to use when calculating random.
 * @return  0 on success.
 */
static int mlkem_get_noise_eta2_c(MLKEM_PRF_T* prf, sword16* p,
    const byte* seed)
{
    int ret;
    byte rand[ETA2_RAND_SIZE];

    /* Calculate random bytes from seed with PRF. */
    ret = mlkem_prf(prf, rand, sizeof(rand), seed);
    if (ret == 0) {
        mlkem_cbd_eta2(p, rand);
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
 * FIPS 203, Algorithm 14: K-PKE.Encrypt(ek_PKE,m,r)
 *   ...
 *  14:     e1[i] <- SamplePolyCBD_eta_2(PRF_eta_2(r, N))
 *   ...
 *  17:     e2[i] <- SamplePolyCBD_eta_2(PRF_eta_2(r, N))
 *   ...
 *
 * @param  [out]  rand  Random number byte array.
 * @param  [in]   seed  Seed to generate random from.
 * @param  [in]   o     Offset of seed count.
 */
static void mlkem_get_noise_x4_eta2_avx2(byte* rand, byte* seed, byte o)
{
    int i;
    word64 state[25 * 4];

    for (i = 0; i < 4; i++) {
        state[4*4 + i] = 0x1f00 + i + o;
    }

    mlkem_sha3_256_blocksx4_seed_avx2(state, seed);
    mlkem_redistribute_16_rand_avx2(state, rand + 0 * ETA2_RAND_SIZE,
        rand + 1 * ETA2_RAND_SIZE, rand + 2 * ETA2_RAND_SIZE,
        rand + 3 * ETA2_RAND_SIZE);
}
#endif

#if defined(WOLFSSL_KYBER512) || defined(WOLFSSL_WC_ML_KEM_512) || \
    defined(WOLFSSL_KYBER1024) || defined(WOLFSSL_WC_ML_KEM_1024)
/* Get noise/error by calculating random bytes and sampling to a binomial
 * distribution. Values -2..2
 *
 * FIPS 203, Algorithm 14: K-PKE.Encrypt(ek_PKE,m,r)
 *   ...
 *  14:     e1[i] <- SamplePolyCBD_eta_2(PRF_eta_2(r, N))
 *   ...
 *  17:     e2[i] <- SamplePolyCBD_eta_2(PRF_eta_2(r, N))
 *   ...
 *
 * @param  [in, out]  prf   Pseudo-random function object.
 * @param  [out]      p     Polynomial.
 * @param  [in]       seed  Seed to use when calculating random.
 * @return  0 on success.
 */
static int mlkem_get_noise_eta2_avx2(MLKEM_PRF_T* prf, sword16* p,
    const byte* seed)
{
    word64 state[25];

    (void)prf;

    /* Put first WC_ML_KEM_SYM_SZ bytes og key into blank state. */
    readUnalignedWords64(state, seed, WC_ML_KEM_SYM_SZ / sizeof(word64));
    /* Last byte in with end of content marker. */
    state[WC_ML_KEM_SYM_SZ / 8] = 0x1f00 | seed[WC_ML_KEM_SYM_SZ];
    /* Set rest of state to 0. */
    XMEMSET(state + WC_ML_KEM_SYM_SZ / 8 + 1, 0,
        (25 - WC_ML_KEM_SYM_SZ / 8 - 1) * sizeof(word64));
    /* ... except for rate marker. */
    state[WC_SHA3_256_COUNT - 1] = W64LIT(0x8000000000000000);

    /* Perform a block operation on the state for next block of output. */
#ifndef WC_SHA3_NO_ASM
    if (IS_INTEL_BMI2(cpuid_flags)) {
        sha3_block_bmi2(state);
    }
    else if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        sha3_block_avx2(state);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif /* !WC_SHA3_NO_ASM */
    {
        BlockSha3(state);
    }
    mlkem_cbd_eta2_avx2(p, (byte*)state);

    return 0;
}
#endif

#if defined(WOLFSSL_KYBER512) || defined(WOLFSSL_WC_ML_KEM_512)
/* Get the noise/error by calculating random bytes.
 *
 * FIPS 203, Algorithm 14: K-PKE.Encrypt(ek_PKE,m,r)
 *   ...
 *  14:     e1[i] <- SamplePolyCBD_eta_2(PRF_eta_2(r, N))
 *   ...
 *  17:     e2[i] <- SamplePolyCBD_eta_2(PRF_eta_2(r, N))
 *   ...
 *
 * @param  [out]  rand  Random number byte array.
 * @param  [in]   seed  Seed to generate random from.
 * @param  [in]   o     Offset of seed count.
 */
static void mlkem_get_noise_x4_eta3_avx2(byte* rand, byte* seed)
{
    word64 state[25 * 4];
    int i;

    state[4*4 + 0] = 0x1f00 + 0;
    state[4*4 + 1] = 0x1f00 + 1;
    state[4*4 + 2] = 0x1f00 + 2;
    state[4*4 + 3] = 0x1f00 + 3;

    mlkem_sha3_256_blocksx4_seed_avx2(state, seed);
    mlkem_redistribute_17_rand_avx2(state, rand + 0 * PRF_RAND_SZ,
        rand + 1 * PRF_RAND_SZ, rand + 2 * PRF_RAND_SZ,
        rand + 3 * PRF_RAND_SZ);
    i = SHA3_256_BYTES;
    sha3_blocksx4_avx2(state);
    mlkem_redistribute_8_rand_avx2(state, rand + i + 0 * PRF_RAND_SZ,
        rand + i + 1 * PRF_RAND_SZ, rand + i + 2 * PRF_RAND_SZ,
        rand + i + 3 * PRF_RAND_SZ);
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
static int mlkem_get_noise_k2_avx2(MLKEM_PRF_T* prf, sword16* vec1,
    sword16* vec2, sword16* poly, byte* seed)
{
    int ret = 0;
#ifdef WOLFSSL_SMALL_STACK
    byte *rand;
#else
    byte rand[4 * PRF_RAND_SZ];
#endif

#ifdef WOLFSSL_SMALL_STACK
    rand = (byte*)XMALLOC(4 * PRF_RAND_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (rand == NULL)
        return MEMORY_E;
#endif

    mlkem_get_noise_x4_eta3_avx2(rand, seed);
    mlkem_cbd_eta3_avx2(vec1          , rand + 0 * PRF_RAND_SZ);
    mlkem_cbd_eta3_avx2(vec1 + MLKEM_N, rand + 1 * PRF_RAND_SZ);
    if (poly == NULL) {
        mlkem_cbd_eta3_avx2(vec2          , rand + 2 * PRF_RAND_SZ);
        mlkem_cbd_eta3_avx2(vec2 + MLKEM_N, rand + 3 * PRF_RAND_SZ);
    }
    else {
        mlkem_cbd_eta2_avx2(vec2          , rand + 2 * PRF_RAND_SZ);
        mlkem_cbd_eta2_avx2(vec2 + MLKEM_N, rand + 3 * PRF_RAND_SZ);

        seed[WC_ML_KEM_SYM_SZ] = 4;
        ret = mlkem_get_noise_eta2_avx2(prf, poly, seed);
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(rand, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

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
static int mlkem_get_noise_k3_avx2(sword16* vec1, sword16* vec2, sword16* poly,
    byte* seed)
{
    byte rand[4 * ETA2_RAND_SIZE];

    mlkem_get_noise_x4_eta2_avx2(rand, seed, 0);
    mlkem_cbd_eta2_avx2(vec1              , rand + 0 * ETA2_RAND_SIZE);
    mlkem_cbd_eta2_avx2(vec1 + 1 * MLKEM_N, rand + 1 * ETA2_RAND_SIZE);
    mlkem_cbd_eta2_avx2(vec1 + 2 * MLKEM_N, rand + 2 * ETA2_RAND_SIZE);
    mlkem_cbd_eta2_avx2(vec2              , rand + 3 * ETA2_RAND_SIZE);
    mlkem_get_noise_x4_eta2_avx2(rand, seed, 4);
    mlkem_cbd_eta2_avx2(vec2 + 1 * MLKEM_N, rand + 0 * ETA2_RAND_SIZE);
    mlkem_cbd_eta2_avx2(vec2 + 2 * MLKEM_N, rand + 1 * ETA2_RAND_SIZE);
    if (poly != NULL) {
        mlkem_cbd_eta2_avx2(poly, rand + 2 * ETA2_RAND_SIZE);
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
static int mlkem_get_noise_k4_avx2(MLKEM_PRF_T* prf, sword16* vec1,
    sword16* vec2, sword16* poly, byte* seed)
{
    int ret = 0;
    byte rand[4 * ETA2_RAND_SIZE];

    (void)prf;

    mlkem_get_noise_x4_eta2_avx2(rand, seed, 0);
    mlkem_cbd_eta2_avx2(vec1              , rand + 0 * ETA2_RAND_SIZE);
    mlkem_cbd_eta2_avx2(vec1 + 1 * MLKEM_N, rand + 1 * ETA2_RAND_SIZE);
    mlkem_cbd_eta2_avx2(vec1 + 2 * MLKEM_N, rand + 2 * ETA2_RAND_SIZE);
    mlkem_cbd_eta2_avx2(vec1 + 3 * MLKEM_N, rand + 3 * ETA2_RAND_SIZE);
    mlkem_get_noise_x4_eta2_avx2(rand, seed, 4);
    mlkem_cbd_eta2_avx2(vec2              , rand + 0 * ETA2_RAND_SIZE);
    mlkem_cbd_eta2_avx2(vec2 + 1 * MLKEM_N, rand + 1 * ETA2_RAND_SIZE);
    mlkem_cbd_eta2_avx2(vec2 + 2 * MLKEM_N, rand + 2 * ETA2_RAND_SIZE);
    mlkem_cbd_eta2_avx2(vec2 + 3 * MLKEM_N, rand + 3 * ETA2_RAND_SIZE);
    if (poly != NULL) {
        seed[WC_ML_KEM_SYM_SZ] = 8;
        ret = mlkem_get_noise_eta2_avx2(prf, poly, seed);
    }

    return ret;
}
#endif
#endif /* USE_INTEL_SPEEDUP */

#if defined(__aarch64__) && defined(WOLFSSL_ARMASM)

#define PRF_RAND_SZ   (2 * SHA3_256_BYTES)

/* Get the noise/error by calculating random bytes.
 *
 * FIPS 203, Algorithm 14: K-PKE.Encrypt(ek_PKE,m,r)
 *   ...
 *  14:     e1[i] <- SamplePolyCBD_eta_2(PRF_eta_2(r, N))
 *   ...
 *  17:     e2[i] <- SamplePolyCBD_eta_2(PRF_eta_2(r, N))
 *   ...
 *
 * @param  [out]  rand  Random number byte array.
 * @param  [in]   seed  Seed to generate random from.
 * @param  [in]   o     Offset of seed count.
 */
static void mlkem_get_noise_x3_eta2_aarch64(byte* rand, byte* seed, byte o)
{
    word64* state = (word64*)rand;

    state[0*25 + 4] = 0x1f00 + 0 + o;
    state[1*25 + 4] = 0x1f00 + 1 + o;
    state[2*25 + 4] = 0x1f00 + 2 + o;

    mlkem_shake256_blocksx3_seed_neon(state, seed);
}

#if defined(WOLFSSL_KYBER512) || defined(WOLFSSL_WC_ML_KEM_512)
/* Get the noise/error by calculating random bytes.
 *
 * FIPS 203, Algorithm 14: K-PKE.Encrypt(ek_PKE,m,r)
 *   ...
 *  14:     e1[i] <- SamplePolyCBD_eta_2(PRF_eta_2(r, N))
 *   ...
 *  17:     e2[i] <- SamplePolyCBD_eta_2(PRF_eta_2(r, N))
 *   ...
 *
 * @param  [out]  rand  Random number byte array.
 * @param  [in]   seed  Seed to generate random from.
 * @param  [in]   o     Offset of seed count.
 */
static void mlkem_get_noise_x3_eta3_aarch64(byte* rand, byte* seed, byte o)
{
    word64 state[3 * 25];

    state[0*25 + 4] = 0x1f00 + 0 + o;
    state[1*25 + 4] = 0x1f00 + 1 + o;
    state[2*25 + 4] = 0x1f00 + 2 + o;

    mlkem_shake256_blocksx3_seed_neon(state, seed);
    XMEMCPY(rand + 0 * ETA3_RAND_SIZE, state + 0*25, SHA3_256_BYTES);
    XMEMCPY(rand + 1 * ETA3_RAND_SIZE, state + 1*25, SHA3_256_BYTES);
    XMEMCPY(rand + 2 * ETA3_RAND_SIZE, state + 2*25, SHA3_256_BYTES);
    mlkem_sha3_blocksx3_neon(state);
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
 * FIPS 203, Algorithm 14: K-PKE.Encrypt(ek_PKE,m,r)
 *   ...
 *  14:     e1[i] <- SamplePolyCBD_eta_2(PRF_eta_2(r, N))
 *   ...
 *  17:     e2[i] <- SamplePolyCBD_eta_2(PRF_eta_2(r, N))
 *   ...
 *
 * @param  [out]  rand  Random number byte array.
 * @param  [in]   seed  Seed to generate random from.
 * @param  [in]   o     Offset of seed count.
 * @return  0 on success.
 */
static void mlkem_get_noise_eta3_aarch64(byte* rand, byte* seed, byte o)
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
static int mlkem_get_noise_k2_aarch64(sword16* vec1, sword16* vec2,
    sword16* poly, byte* seed)
{
    int ret = 0;
    byte rand[3 * 25 * 8];

    mlkem_get_noise_x3_eta3_aarch64(rand, seed, 0);
    mlkem_cbd_eta3(vec1          , rand + 0 * ETA3_RAND_SIZE);
    mlkem_cbd_eta3(vec1 + MLKEM_N, rand + 1 * ETA3_RAND_SIZE);
    if (poly == NULL) {
        mlkem_cbd_eta3(vec2          , rand + 2 * ETA3_RAND_SIZE);
        mlkem_get_noise_eta3_aarch64(rand, seed, 3);
        mlkem_cbd_eta3(vec2 + MLKEM_N, rand                     );
    }
    else {
        mlkem_get_noise_x3_eta2_aarch64(rand, seed, 2);
        mlkem_cbd_eta2(vec2          , rand + 0 * 25 * 8);
        mlkem_cbd_eta2(vec2 + MLKEM_N, rand + 1 * 25 * 8);
        mlkem_cbd_eta2(poly          , rand + 2 * 25 * 8);
    }

    return ret;
}
#endif

#if defined(WOLFSSL_KYBER768) || defined(WOLFSSL_WC_ML_KEM_768)
/* Get the noise/error by calculating random bytes.
 *
 * FIPS 203, Algorithm 14: K-PKE.Encrypt(ek_PKE,m,r)
 *   ...
 *  14:     e1[i] <- SamplePolyCBD_eta_2(PRF_eta_2(r, N))
 *   ...
 *  17:     e2[i] <- SamplePolyCBD_eta_2(PRF_eta_2(r, N))
 *   ...
 *
 * @param  [out]  rand  Random number byte array.
 * @param  [in]   seed  Seed to generate random from.
 * @param  [in]   o     Offset of seed count.
 * @return  0 on success.
 */
static void mlkem_get_noise_eta2_aarch64(byte* rand, byte* seed, byte o)
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
static int mlkem_get_noise_k3_aarch64(sword16* vec1, sword16* vec2,
     sword16* poly, byte* seed)
{
    byte rand[3 * 25 * 8];

    mlkem_get_noise_x3_eta2_aarch64(rand, seed, 0);
    mlkem_cbd_eta2(vec1              , rand + 0 * 25 * 8);
    mlkem_cbd_eta2(vec1 + 1 * MLKEM_N, rand + 1 * 25 * 8);
    mlkem_cbd_eta2(vec1 + 2 * MLKEM_N, rand + 2 * 25 * 8);
    mlkem_get_noise_x3_eta2_aarch64(rand, seed, 3);
    mlkem_cbd_eta2(vec2              , rand + 0 * 25 * 8);
    mlkem_cbd_eta2(vec2 + 1 * MLKEM_N, rand + 1 * 25 * 8);
    mlkem_cbd_eta2(vec2 + 2 * MLKEM_N, rand + 2 * 25 * 8);
    if (poly != NULL) {
        mlkem_get_noise_eta2_aarch64(rand, seed, 6);
        mlkem_cbd_eta2(poly              , rand + 0 * 25 * 8);
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
static int mlkem_get_noise_k4_aarch64(sword16* vec1, sword16* vec2,
    sword16* poly, byte* seed)
{
    int ret = 0;
    byte rand[3 * 25 * 8];

    mlkem_get_noise_x3_eta2_aarch64(rand, seed, 0);
    mlkem_cbd_eta2(vec1              , rand + 0 * 25 * 8);
    mlkem_cbd_eta2(vec1 + 1 * MLKEM_N, rand + 1 * 25 * 8);
    mlkem_cbd_eta2(vec1 + 2 * MLKEM_N, rand + 2 * 25 * 8);
    mlkem_get_noise_x3_eta2_aarch64(rand, seed, 3);
    mlkem_cbd_eta2(vec1 + 3 * MLKEM_N, rand + 0 * 25 * 8);
    mlkem_cbd_eta2(vec2              , rand + 1 * 25 * 8);
    mlkem_cbd_eta2(vec2 + 1 * MLKEM_N, rand + 2 * 25 * 8);
    mlkem_get_noise_x3_eta2_aarch64(rand, seed, 6);
    mlkem_cbd_eta2(vec2 + 2 * MLKEM_N, rand + 0 * 25 * 8);
    mlkem_cbd_eta2(vec2 + 3 * MLKEM_N, rand + 1 * 25 * 8);
    if (poly != NULL) {
        mlkem_cbd_eta2(poly,               rand + 2 * 25 * 8);
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
 * @param  [in]       k     Number of polynomials in vector.
 * @param  [out]      vec1  First Vector of polynomials.
 * @param  [in]       eta1  Size of noise/error integers with first vector.
 * @param  [out]      vec2  Second Vector of polynomials.
 * @param  [in]       eta2  Size of noise/error integers with second vector.
 * @param  [out]      poly  Polynomial.
 * @param  [in]       seed  Seed to use when calculating random.
 * @return  0 on success.
 */
static int mlkem_get_noise_c(MLKEM_PRF_T* prf, int k, sword16* vec1, int eta1,
    sword16* vec2, int eta2, sword16* poly, byte* seed)
{
    int ret = 0;
    int i;

    /* First noise generation has a seed with 0x00 appended. */
    seed[WC_ML_KEM_SYM_SZ] = 0;
    /* Generate noise as private key. */
    for (i = 0; (ret == 0) && (i < k); i++) {
        /* Generate noise for each dimension of vector. */
        ret = mlkem_get_noise_eta1_c(prf, vec1 + i * MLKEM_N, seed, eta1);
        /* Increment value of appended byte. */
        seed[WC_ML_KEM_SYM_SZ]++;
    }
    if ((ret == 0) && (vec2 != NULL)) {
        /* Generate noise for error. */
        for (i = 0; (ret == 0) && (i < k); i++) {
            /* Generate noise for each dimension of vector. */
            ret = mlkem_get_noise_eta1_c(prf, vec2 + i * MLKEM_N, seed, eta2);
            /* Increment value of appended byte. */
            seed[WC_ML_KEM_SYM_SZ]++;
        }
    }
    else {
        seed[WC_ML_KEM_SYM_SZ] = 2 * k;
    }
    if ((ret == 0) && (poly != NULL)) {
        /* Generating random error polynomial. */
        ret = mlkem_get_noise_eta2_c(prf, poly, seed);
    }

    return ret;
}

#endif /* __aarch64__ && WOLFSSL_ARMASM */

/* Get the noise/error by calculating random bytes and sampling to a binomial
 * distribution.
 *
 * @param  [in, out]  prf   Pseudo-random function object.
 * @param  [in]       k     Number of polynomials in vector.
 * @param  [out]      vec1  First Vector of polynomials.
 * @param  [out]      vec2  Second Vector of polynomials.
 * @param  [out]      poly  Polynomial.
 * @param  [in]       seed  Seed to use when calculating random.
 * @return  0 on success.
 */
int mlkem_get_noise(MLKEM_PRF_T* prf, int k, sword16* vec1, sword16* vec2,
    sword16* poly, byte* seed)
{
    int ret;

#if defined(WOLFSSL_KYBER512) || defined(WOLFSSL_WC_ML_KEM_512)
    if (k == WC_ML_KEM_512_K) {
#if defined(WOLFSSL_ARMASM) && defined(__aarch64__)
        ret = mlkem_get_noise_k2_aarch64(vec1, vec2, poly, seed);
#else
    #ifdef USE_INTEL_SPEEDUP
        if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
            ret = mlkem_get_noise_k2_avx2(prf, vec1, vec2, poly, seed);
            RESTORE_VECTOR_REGISTERS();
        }
        else
    #endif
        if (poly == NULL) {
            ret = mlkem_get_noise_c(prf, k, vec1, MLKEM_CBD_ETA3, vec2,
                MLKEM_CBD_ETA3, NULL, seed);
        }
        else {
            ret = mlkem_get_noise_c(prf, k, vec1, MLKEM_CBD_ETA3, vec2,
                MLKEM_CBD_ETA2, poly, seed);
        }
#endif
    }
    else
#endif
#if defined(WOLFSSL_KYBER768) || defined(WOLFSSL_WC_ML_KEM_768)
    if (k == WC_ML_KEM_768_K) {
#if defined(WOLFSSL_ARMASM) && defined(__aarch64__)
        ret = mlkem_get_noise_k3_aarch64(vec1, vec2, poly, seed);
#else
    #ifdef USE_INTEL_SPEEDUP
        if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
            ret = mlkem_get_noise_k3_avx2(vec1, vec2, poly, seed);
            RESTORE_VECTOR_REGISTERS();
        }
        else
    #endif
        {
            ret = mlkem_get_noise_c(prf, k, vec1, MLKEM_CBD_ETA2, vec2,
                MLKEM_CBD_ETA2, poly, seed);
        }
#endif
    }
    else
#endif
#if defined(WOLFSSL_KYBER1024) || defined(WOLFSSL_WC_ML_KEM_1024)
    if (k == WC_ML_KEM_1024_K) {
#if defined(WOLFSSL_ARMASM) && defined(__aarch64__)
        ret = mlkem_get_noise_k4_aarch64(vec1, vec2, poly, seed);
#else
    #ifdef USE_INTEL_SPEEDUP
        if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
            ret = mlkem_get_noise_k4_avx2(prf, vec1, vec2, poly, seed);
            RESTORE_VECTOR_REGISTERS();
        }
        else
    #endif
        {
            ret = mlkem_get_noise_c(prf, k, vec1, MLKEM_CBD_ETA2, vec2,
                MLKEM_CBD_ETA2, poly, seed);
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

#if defined(WOLFSSL_MLKEM_MAKEKEY_SMALL_MEM) || \
    defined(WOLFSSL_MLKEM_ENCAPSULATE_SMALL_MEM)
/* Get the noise/error by calculating random bytes and sampling to a binomial
 * distribution.
 *
 * @param  [in, out]  prf   Pseudo-random function object.
 * @param  [in]       k     Number of polynomials in vector.
 * @param  [out]      vec2  Second Vector of polynomials.
 * @param  [in]       seed  Seed to use when calculating random.
 * @param  [in]       i     Index of vector to generate.
 * @param  [in]       make  Indicates generation is for making a key.
 * @return  0 on success.
 */
static int mlkem_get_noise_i(MLKEM_PRF_T* prf, int k, sword16* vec2,
    byte* seed, int i, int make)
{
    int ret;

    /* Initialize the PRF (generating matrix A leaves it in uninitialized
     * state). */
    mlkem_prf_init(prf);

    /* Set index of polynomial of second vector into seed. */
    seed[WC_ML_KEM_SYM_SZ] = k + i;
#if defined(WOLFSSL_KYBER512) || defined(WOLFSSL_WC_ML_KEM_512)
    if ((k == WC_ML_KEM_512_K) && make) {
        ret = mlkem_get_noise_eta1_c(prf, vec2, seed, MLKEM_CBD_ETA3);
    }
    else
#endif
    {
        ret = mlkem_get_noise_eta1_c(prf, vec2, seed, MLKEM_CBD_ETA2);
    }

    (void)make;
    return ret;
}
#endif

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
static int mlkem_cmp_c(const byte* a, const byte* b, int sz)
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
int mlkem_cmp(const byte* a, const byte* b, int sz)
{
#if defined(__aarch64__) && defined(WOLFSSL_ARMASM)
    return mlkem_cmp_neon(a, b, sz);
#else
    int fail;

#ifdef USE_INTEL_SPEEDUP
    if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        fail = mlkem_cmp_avx2(a, b, sz);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
        fail = mlkem_cmp_c(a, b, sz);
    }

    return fail;
#endif
}

/******************************************************************************/

#if !defined(WOLFSSL_ARMASM)

/* Conditional subtraction of q to each coefficient of a polynomial.
 *
 * FIPS 203, Section 4.2.1, Compression and decompression
 *
 * @param  [in, out]  p  Polynomial.
 */
static MLKEM_NOINLINE void mlkem_csubq_c(sword16* p)
{
    unsigned int i;

    for (i = 0; i < MLKEM_N; ++i) {
        sword16 t = p[i] - MLKEM_Q;
        /* When top bit set, -ve number - need to add q back. */
        p[i] = ((t >> 15) & MLKEM_Q) + t;
    }
}

#elif defined(__aarch64__)

/* Conditional subtraction of q to each coefficient of a polynomial.
 *
 * FIPS 203, Section 4.2.1, Compression and decompression
 *
 * @param  [in, out]  p  Polynomial.
 */
#define mlkem_csubq_c   mlkem_csubq_neon

#elif defined(WOLFSSL_ARMASM_THUMB2)

/* Conditional subtraction of q to each coefficient of a polynomial.
 *
 * FIPS 203, Section 4.2.1, Compression and decompression
 *
 * @param  [in, out]  p  Polynomial.
 */
#define mlkem_csubq_c   mlkem_thumb2_csubq

#else

/* Conditional subtraction of q to each coefficient of a polynomial.
 *
 * FIPS 203, Section 4.2.1, Compression and decompression
 *
 * @param  [in, out]  p  Polynomial.
 */
#define mlkem_csubq_c   mlkem_arm32_csubq

#endif

/******************************************************************************/

#if defined(CONV_WITH_DIV) || !defined(WORD64_AVAILABLE)

/* Compress value.
 *
 * Uses div operator that may be slow.
 *
 * FIPS 203, Section 4.2.1, Compression and decompression
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
    ((((word32)v[i * MLKEM_N + j + k] << s) + MLKEM_Q_HALF) / MLKEM_Q) & m

/* Compress value to 10 bits.
 *
 * Uses mul instead of div.
 *
 * FIPS 203, Section 4.2.1, Compression and decompression
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
 * FIPS 203, Section 4.2.1, Compression and decompression
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
 * ((1 << 53) + MLKEM_Q_HALF) / MLKEM_Q
 */
#define MLKEM_V53         0x275f6ed0176UL
/* Multiplier times half of q.
 * MLKEM_V53 * (MLKEM_Q_HALF + 1)
 */
#define MLKEM_V53_HALF    0x10013afb768076UL

/* Multiplier that does div q.
 * ((1 << 54) + MLKEM_Q_HALF) / MLKEM_Q
 */
#define MLKEM_V54         0x4ebedda02ecUL
/* Multiplier times half of q.
 * MLKEM_V54 * (MLKEM_Q_HALF + 1)
 */
#define MLKEM_V54_HALF    0x200275f6ed00ecUL

/* Compress value to 10 bits.
 *
 * Uses mul instead of div.
 *
 * FIPS 203, Section 4.2.1, Compression and decompression
 *
 * @param  [in]  v  Vector of polynomials.
 * @param  [in]  i  Index of polynomial in vector.
 * @param  [in]  j  Index into polynomial.
 * @param  [in]  k  Offset from indices.
 * @return  Compressed value.
 */
#define TO_COMP_WORD_10(v, i, j, k) \
    ((((MLKEM_V54 << 10) * (v)[(i) * MLKEM_N + (j) + (k)]) + \
      MLKEM_V54_HALF) >> 54)

/* Compress value to 11 bits.
 *
 * Uses mul instead of div.
 * Only works for values in range: 0..3228
 *
 * FIPS 203, Section 4.2.1, Compression and decompression
 *
 * @param  [in]  v  Vector of polynomials.
 * @param  [in]  i  Index of polynomial in vector.
 * @param  [in]  j  Index into polynomial.
 * @param  [in]  k  Offset from indices.
 * @return  Compressed value.
 */
#define TO_COMP_WORD_11(v, i, j, k) \
    ((((MLKEM_V53 << 11) * (v)[(i) * MLKEM_N + (j) + (k)]) + \
      MLKEM_V53_HALF) >> 53)

#endif /* CONV_WITH_DIV */

#if !defined(WOLFSSL_MLKEM_NO_ENCAPSULATE) || \
    !defined(WOLFSSL_MLKEM_NO_DECAPSULATE)
#if defined(WOLFSSL_KYBER512) || defined(WOLFSSL_WC_ML_KEM_512) || \
    defined(WOLFSSL_KYBER768) || defined(WOLFSSL_WC_ML_KEM_768)
/* Compress the vector of polynomials into a byte array with 10 bits each.
 *
 * FIPS 203, Section 4.2.1, Compression and decompression
 *
 * @param  [out]  b  Array of bytes.
 * @param  [in]   v  Vector of polynomials.
 * @param  [in]   k  Number of polynomials in vector.
 */
static void mlkem_vec_compress_10_c(byte* r, sword16* v, unsigned int k)
{
    unsigned int i;
    unsigned int j;

    for (i = 0; i < k; i++) {
        /* Reduce each coefficient to mod q. */
        mlkem_csubq_c(v + i * MLKEM_N);
        /* All values are now positive. */
    }

    /* Each polynomial. */
    for (i = 0; i < k; i++) {
#if defined(WOLFSSL_SMALL_STACK) || defined(WOLFSSL_MLKEM_NO_LARGE_CODE) || \
    defined(BIG_ENDIAN_ORDER)
        /* Each 4 polynomial coefficients. */
        for (j = 0; j < MLKEM_N; j += 4) {
        #ifdef WOLFSSL_MLKEM_SMALL
            unsigned int l;
            sword16 t[4];
            /* Compress four polynomial values to 10 bits each. */
            for (l = 0; l < 4; l++) {
                t[l] = TO_COMP_WORD_10(v, i, j, l);
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
        for (j = 0; j < MLKEM_N; j += 16) {
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
 * FIPS 203, Section 4.2.1, Compression and decompression
 *
 * @param  [out]  b  Array of bytes.
 * @param  [in]   v  Vector of polynomials.
 * @param  [in]   k  Number of polynomials in vector.
 */
void mlkem_vec_compress_10(byte* r, sword16* v, unsigned int k)
{
#ifdef USE_INTEL_SPEEDUP
    if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        mlkem_compress_10_avx2(r, v, k);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
        mlkem_vec_compress_10_c(r, v, k);
    }
}
#endif

#if defined(WOLFSSL_KYBER1024) || defined(WOLFSSL_WC_ML_KEM_1024)
/* Compress the vector of polynomials into a byte array with 11 bits each.
 *
 * FIPS 203, Section 4.2.1, Compression and decompression
 *
 * @param  [out]  b       Array of bytes.
 * @param  [in]   v       Vector of polynomials.
 */
static void mlkem_vec_compress_11_c(byte* r, sword16* v)
{
    unsigned int i;
    unsigned int j;
#ifdef WOLFSSL_MLKEM_SMALL
    unsigned int k;
#endif

    for (i = 0; i < 4; i++) {
        /* Reduce each coefficient to mod q. */
        mlkem_csubq_c(v + i * MLKEM_N);
        /* All values are now positive. */
    }

    /* Each polynomial. */
    for (i = 0; i < 4; i++) {
        /* Each 8 polynomial coefficients. */
        for (j = 0; j < MLKEM_N; j += 8) {
        #ifdef WOLFSSL_MLKEM_SMALL
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
 * FIPS 203, Section 4.2.1, Compression and decompression
 *
 * @param  [out]  b       Array of bytes.
 * @param  [in]   v       Vector of polynomials.
 */
void mlkem_vec_compress_11(byte* r, sword16* v)
{
#ifdef USE_INTEL_SPEEDUP
    if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        mlkem_compress_11_avx2(r, v, 4);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
        mlkem_vec_compress_11_c(r, v);
    }
}
#endif
#endif /* !WOLFSSL_MLKEM_NO_ENCAPSULATE || !WOLFSSL_MLKEM_NO_DECAPSULATE */

#ifndef WOLFSSL_MLKEM_NO_DECAPSULATE
/* Decompress a 10 bit value.
 *
 * FIPS 203, Section 4.2.1, Compression and decompression
 *
 * @param  [in]  v  Vector of polynomials.
 * @param  [in]  i  Index of polynomial in vector.
 * @param  [in]  j  Index into polynomial.
 * @param  [in]  k  Offset from indices.
 * @param  [in]  t  Value to decompress.
 * @return  Decompressed value.
 */
#define DECOMP_10(v, i, j, k, t) \
    v[(i) * MLKEM_N + 4 * (j) + (k)] = \
        (word16)((((word32)((t) & 0x3ff) * MLKEM_Q) + 512) >> 10)

/* Decompress an 11 bit value.
 *
 * FIPS 203, Section 4.2.1, Compression and decompression
 *
 * @param  [in]  v  Vector of polynomials.
 * @param  [in]  i  Index of polynomial in vector.
 * @param  [in]  j  Index into polynomial.
 * @param  [in]  k  Offset from indices.
 * @param  [in]  t  Value to decompress.
 * @return  Decompressed value.
 */
#define DECOMP_11(v, i, j, k, t) \
    v[(i) * MLKEM_N + 8 * (j) + (k)] = \
        (word16)((((word32)((t) & 0x7ff) * MLKEM_Q) + 1024) >> 11)

#if defined(WOLFSSL_KYBER512) || defined(WOLFSSL_WC_ML_KEM_512) || \
    defined(WOLFSSL_KYBER768) || defined(WOLFSSL_WC_ML_KEM_768)
/* Decompress the byte array of packed 10 bits into vector of polynomials.
 *
 * FIPS 203, Section 4.2.1, Compression and decompression
 *
 * @param  [out]  v  Vector of polynomials.
 * @param  [in]   b  Array of bytes.
 * @param  [in]   k  Number of polynomials in vector.
 */
static void mlkem_vec_decompress_10_c(sword16* v, const byte* b, unsigned int k)
{
    unsigned int i;
    unsigned int j;
#ifdef WOLFSSL_MLKEM_SMALL
    unsigned int l;
#endif

    /* Each polynomial. */
    for (i = 0; i < k; i++) {
        /* Each 4 polynomial coefficients. */
        for (j = 0; j < MLKEM_N / 4; j++) {
        #ifdef WOLFSSL_MLKEM_SMALL
            word16 t[4];
            /* Extract out 4 values of 10 bits each. */
            t[0] = (b[0] >> 0) | ((word16)b[ 1] << 8);
            t[1] = (b[1] >> 2) | ((word16)b[ 2] << 6);
            t[2] = (b[2] >> 4) | ((word16)b[ 3] << 4);
            t[3] = (b[3] >> 6) | ((word16)b[ 4] << 2);
            b += 5;

            /* Decompress 4 values. */
            for (l = 0; l < 4; l++) {
                DECOMP_10(v, i, j, l, t[l]);
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
 * FIPS 203, Section 4.2.1, Compression and decompression
 *
 * @param  [out]  v  Vector of polynomials.
 * @param  [in]   b  Array of bytes.
 * @param  [in]   k  Number of polynomials in vector.
 */
void mlkem_vec_decompress_10(sword16* v, const byte* b, unsigned int k)
{
#ifdef USE_INTEL_SPEEDUP
    if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        mlkem_decompress_10_avx2(v, b, k);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
        mlkem_vec_decompress_10_c(v, b, k);
    }
}
#endif
#if defined(WOLFSSL_KYBER1024) || defined(WOLFSSL_WC_ML_KEM_1024)
/* Decompress the byte array of packed 11 bits into vector of polynomials.
 *
 * FIPS 203, Section 4.2.1, Compression and decompression
 *
 * @param  [out]  v       Vector of polynomials.
 * @param  [in]   b       Array of bytes.
 */
static void mlkem_vec_decompress_11_c(sword16* v, const byte* b)
{
    unsigned int i;
    unsigned int j;
#ifdef WOLFSSL_MLKEM_SMALL
    unsigned int l;
#endif

    /* Each polynomial. */
    for (i = 0; i < 4; i++) {
        /* Each 8 polynomial coefficients. */
        for (j = 0; j < MLKEM_N / 8; j++) {
        #ifdef WOLFSSL_MLKEM_SMALL
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
            for (l = 0; l < 8; l++) {
                DECOMP_11(v, i, j, l, t[l]);
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
 * FIPS 203, Section 4.2.1, Compression and decompression
 *
 * @param  [out]  v       Vector of polynomials.
 * @param  [in]   b       Array of bytes.
 */
void mlkem_vec_decompress_11(sword16* v, const byte* b)
{
#ifdef USE_INTEL_SPEEDUP
    if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        mlkem_decompress_11_avx2(v, b, 4);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
        mlkem_vec_decompress_11_c(v, b);
    }
}
#endif
#endif /* !WOLFSSL_MLKEM_NO_DECAPSULATE */

#ifdef CONV_WITH_DIV

/* Compress value.
 *
 * Uses div operator that may be slow.
 *
 * FIPS 203, Section 4.2.1, Compression and decompression
 *
 * @param  [in]  v  Vector of polynomials.
 * @param  [in]  i  Index into polynomial.
 * @param  [in]  j  Offset from indices.
 * @param  [in]  s  Shift amount to apply to value being compressed.
 * @param  [in]  m  Mask to apply get the require number of bits.
 * @return  Compressed value.
 */
#define TO_COMP_WORD(v, i, j, s, m) \
    ((((word32)v[i + j] << s) + MLKEM_Q_HALF) / MLKEM_Q) & m

/* Compress value to 4 bits.
 *
 * Uses mul instead of div.
 *
 * FIPS 203, Section 4.2.1, Compression and decompression
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
 * FIPS 203, Section 4.2.1, Compression and decompression
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
#define MLKEM_V28         ((word32)(((1U << 28) + MLKEM_Q_HALF)) / MLKEM_Q)
/* Multiplier times half of q. */
#define MLKEM_V28_HALF    ((word32)(MLKEM_V28 * (MLKEM_Q_HALF + 1)))

/* Multiplier that does div q. */
#define MLKEM_V27         ((word32)(((1U << 27) + MLKEM_Q_HALF)) / MLKEM_Q)
/* Multiplier times half of q. */
#define MLKEM_V27_HALF    ((word32)(MLKEM_V27 * MLKEM_Q_HALF))

/* Compress value to 4 bits.
 *
 * Uses mul instead of div.
 *
 * FIPS 203, Section 4.2.1, Compression and decompression
 *
 * @param  [in]  p  Polynomial.
 * @param  [in]  i  Index into polynomial.
 * @param  [in]  j  Offset from indices.
 * @return  Compressed value.
 */
#define TO_COMP_WORD_4(p, i, j) \
    ((((MLKEM_V28 << 4) * (p)[(i) + (j)]) + MLKEM_V28_HALF) >> 28)

/* Compress value to 5 bits.
 *
 * Uses mul instead of div.
 *
 * FIPS 203, Section 4.2.1, Compression and decompression
 *
 * @param  [in]  p  Polynomial.
 * @param  [in]  i  Index into polynomial.
 * @param  [in]  j  Offset from indices.
 * @return  Compressed value.
 */
#define TO_COMP_WORD_5(p, i, j) \
    ((((MLKEM_V27 << 5) * (p)[(i) + (j)]) + MLKEM_V27_HALF) >> 27)

#endif /* CONV_WITH_DIV */

#if !defined(WOLFSSL_MLKEM_NO_ENCAPSULATE) || \
    !defined(WOLFSSL_MLKEM_NO_DECAPSULATE)
#if defined(WOLFSSL_KYBER512) || defined(WOLFSSL_WC_ML_KEM_512) || \
    defined(WOLFSSL_KYBER768) || defined(WOLFSSL_WC_ML_KEM_768)
/* Compress a polynomial into byte array - on coefficients into 4 bits.
 *
 * FIPS 203, Section 4.2.1, Compression and decompression
 *
 * @param  [out]  b       Array of bytes.
 * @param  [in]   p       Polynomial.
 */
static void mlkem_compress_4_c(byte* b, sword16* p)
{
    unsigned int i;
#ifdef WOLFSSL_MLKEM_SMALL
    unsigned int j;
    byte t[8];
#endif

    /* Reduce each coefficients to mod q. */
    mlkem_csubq_c(p);
    /* All values are now positive. */

    /* Each 8 polynomial coefficients. */
    for (i = 0; i < MLKEM_N; i += 8) {
    #ifdef WOLFSSL_MLKEM_SMALL
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
 * FIPS 203, Section 4.2.1, Compression and decompression
 *
 * @param  [out]  b       Array of bytes.
 * @param  [in]   p       Polynomial.
 */
void mlkem_compress_4(byte* b, sword16* p)
{
#ifdef USE_INTEL_SPEEDUP
    if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        mlkem_compress_4_avx2(b, p);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
        mlkem_compress_4_c(b, p);
    }
}
#endif
#if defined(WOLFSSL_KYBER1024) || defined(WOLFSSL_WC_ML_KEM_1024)
/* Compress a polynomial into byte array - on coefficients into 5 bits.
 *
 * FIPS 203, Section 4.2.1, Compression and decompression
 *
 * @param  [out]  b       Array of bytes.
 * @param  [in]   p       Polynomial.
 */
static void mlkem_compress_5_c(byte* b, sword16* p)
{
    unsigned int i;
#ifdef WOLFSSL_MLKEM_SMALL
    unsigned int j;
    byte t[8];
#endif

    /* Reduce each coefficients to mod q. */
    mlkem_csubq_c(p);
    /* All values are now positive. */

    for (i = 0; i < MLKEM_N; i += 8) {
    #ifdef WOLFSSL_MLKEM_SMALL
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
 * FIPS 203, Section 4.2.1, Compression and decompression
 *
 * @param  [out]  b       Array of bytes.
 * @param  [in]   p       Polynomial.
 */
void mlkem_compress_5(byte* b, sword16* p)
{
#ifdef USE_INTEL_SPEEDUP
    if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        mlkem_compress_5_avx2(b, p);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
        mlkem_compress_5_c(b, p);
    }
}
#endif
#endif /* !WOLFSSL_MLKEM_NO_ENCAPSULATE || !WOLFSSL_MLKEM_NO_DECAPSULATE */

#ifndef WOLFSSL_MLKEM_NO_DECAPSULATE
/* Decompress a 4 bit value.
 *
 * FIPS 203, Section 4.2.1, Compression and decompression
 *
 * @param  [in]  p  Polynomial.
 * @param  [in]  i  Index into polynomial.
 * @param  [in]  j  Offset from indices.
 * @param  [in]  t  Value to decompress.
 * @return  Decompressed value.
 */
#define DECOMP_4(p, i, j, t) \
    p[(i) + (j)] = ((word16)((t) * MLKEM_Q) + 8) >> 4

/* Decompress a 5 bit value.
 *
 * FIPS 203, Section 4.2.1, Compression and decompression
 *
 * @param  [in]  p  Polynomial.
 * @param  [in]  i  Index into polynomial.
 * @param  [in]  j  Offset from indices.
 * @param  [in]  t  Value to decompress.
 * @return  Decompressed value.
 */
#define DECOMP_5(p, i, j, t) \
    p[(i) + (j)] = (((word32)((t) & 0x1f) * MLKEM_Q) + 16) >> 5

#if defined(WOLFSSL_KYBER512) || defined(WOLFSSL_WC_ML_KEM_512) || \
    defined(WOLFSSL_KYBER768) || defined(WOLFSSL_WC_ML_KEM_768)
/* Decompress the byte array of packed 4 bits into polynomial.
 *
 * FIPS 203, Section 4.2.1, Compression and decompression
 *
 * @param  [out]  p       Polynomial.
 * @param  [in]   b       Array of bytes.
 */
static void mlkem_decompress_4_c(sword16* p, const byte* b)
{
    unsigned int i;

    /* 2 coefficients at a time. */
    for (i = 0; i < MLKEM_N; i += 2) {
        /* 2 coefficients decompressed from one byte. */
        DECOMP_4(p, i, 0, b[0] & 0xf);
        DECOMP_4(p, i, 1, b[0] >>  4);
        b += 1;
    }
}

/* Decompress the byte array of packed 4 bits into polynomial.
 *
 * FIPS 203, Section 4.2.1, Compression and decompression
 *
 * @param  [out]  p       Polynomial.
 * @param  [in]   b       Array of bytes.
 */
void mlkem_decompress_4(sword16* p, const byte* b)
{
#ifdef USE_INTEL_SPEEDUP
    if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        mlkem_decompress_4_avx2(p, b);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
        mlkem_decompress_4_c(p, b);
    }
}
#endif
#if defined(WOLFSSL_KYBER1024) || defined(WOLFSSL_WC_ML_KEM_1024)
/* Decompress the byte array of packed 5 bits into polynomial.
 *
 * FIPS 203, Section 4.2.1, Compression and decompression
 *
 * @param  [out]  p       Polynomial.
 * @param  [in]   b       Array of bytes.
 */
static void mlkem_decompress_5_c(sword16* p, const byte* b)
{
    unsigned int i;

    /* Each 8 polynomial coefficients. */
    for (i = 0; i < MLKEM_N; i += 8) {
    #ifdef WOLFSSL_MLKEM_SMALL
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
 * FIPS 203, Section 4.2.1, Compression and decompression
 *
 * @param  [out]  p       Polynomial.
 * @param  [in]   b       Array of bytes.
 */
void mlkem_decompress_5(sword16* p, const byte* b)
{
#ifdef USE_INTEL_SPEEDUP
    if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        mlkem_decompress_5_avx2(p, b);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
        mlkem_decompress_5_c(p, b);
    }
}
#endif
#endif /* !WOLFSSL_MLKEM_NO_DECAPSULATE */

/******************************************************************************/

#if !(defined(__aarch64__) && defined(WOLFSSL_ARMASM))
#if !defined(WOLFSSL_MLKEM_NO_ENCAPSULATE) || \
    !defined(WOLFSSL_MLKEM_NO_DECAPSULATE)
/* Convert bit from byte to 0 or (MLKEM_Q + 1) / 2.
 *
 * Constant time implementation.
 * XOR in mlkem_opt_blocker to ensure optimizer doesn't know what will be ANDed
 * with MLKEM_Q_1_HALF and can't optimize to non-constant time code.
 *
 * FIPS 203, Algorithm 6: ByteDecode_d(B)
 *
 * @param  [out]  p    Polynomial to hold converted value.
 * @param  [in]   msg  Message to get bit from byte from.
 * @param  [in]   i    Index of byte from message.
 * @param  [in]   j    Index of bit in byte.
 */
#define FROM_MSG_BIT(p, msg, i, j) \
    ((p)[8 * (i) + (j)] = (((sword16)0 - (sword16)(((msg)[i] >> (j)) & 1)) ^ \
                          mlkem_opt_blocker) & MLKEM_Q_1_HALF)

/* Convert message to polynomial.
 *
 * FIPS 203, Algorithm 6: ByteDecode_d(B)
 *
 * @param  [out]  p    Polynomial.
 * @param  [in]   msg  Message as a byte array.
 */
static void mlkem_from_msg_c(sword16* p, const byte* msg)
{
    unsigned int i;

    /* For each byte of the message. */
    for (i = 0; i < MLKEM_N / 8; i++) {
    #ifdef WOLFSSL_MLKEM_SMALL
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
 * FIPS 203, Algorithm 6: ByteDecode_d(B)
 *
 * @param  [out]  p    Polynomial.
 * @param  [in]   msg  Message as a byte array.
 */
void mlkem_from_msg(sword16* p, const byte* msg)
{
#ifdef USE_INTEL_SPEEDUP
    if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        mlkem_from_msg_avx2(p, msg);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
        mlkem_from_msg_c(p, msg);
    }
}
#endif

#ifndef WOLFSSL_MLKEM_NO_DECAPSULATE
#ifdef CONV_WITH_DIV

/* Convert to value to bit.
 *
 * Uses div operator that may be slow.
 *
 * FIPS 203, Algorithm 6: ByteEncode_d(F)
 *
 * @param  [out]  m   Message.
 * @param  [in]   p   Polynomial.
 * @param  [in]   i   Index of byte in message.
 * @param  [in]   j   Index of bit in byte.
 */
#define TO_MSG_BIT(m, p, i, j) \
    m[i] |= (((((sword16)p[8 * i + j] << 1) + MLKEM_Q_HALF) / MLKEM_Q) & 1) << j

#else

/* Multiplier that does div q. */
#define MLKEM_V31       (((1U << 31) + (MLKEM_Q / 2)) / MLKEM_Q)
/* 2 * multiplier that does div q. Only need bit 32 of result. */
#define MLKEM_V31_2     ((word32)(MLKEM_V31 * 2))
/* Multiplier times half of q. */
#define MLKEM_V31_HALF    ((word32)(MLKEM_V31 * MLKEM_Q_HALF))

/* Convert to value to bit.
 *
 * Uses mul instead of div.
 *
 * FIPS 203, Algorithm 6: ByteEncode_d(F)
 *
 * @param  [out]  m   Message.
 * @param  [in]   p   Polynomial.
 * @param  [in]   i   Index of byte in message.
 * @param  [in]   j   Index of bit in byte.
 */
#define TO_MSG_BIT(m, p, i, j) \
    (m)[i] |= ((word32)((MLKEM_V31_2 * (p)[8 * (i) + (j)]) + \
                        MLKEM_V31_HALF) >> 31) << (j)

#endif /* CONV_WITH_DIV */

/* Convert polynomial to message.
 *
 * FIPS 203, Algorithm 6: ByteEncode_d(F)
 *
 * @param  [out]  msg  Message as a byte array.
 * @param  [in]   p    Polynomial.
 */
static void mlkem_to_msg_c(byte* msg, sword16* p)
{
    unsigned int i;

    /* Reduce each coefficient to mod q. */
    mlkem_csubq_c(p);
    /* All values are now in range. */

    for (i = 0; i < MLKEM_N / 8; i++) {
    #ifdef WOLFSSL_MLKEM_SMALL
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
 * FIPS 203, Algorithm 6: ByteEncode_d(F)
 *
 * @param  [out]  msg  Message as a byte array.
 * @param  [in]   p    Polynomial.
 */
void mlkem_to_msg(byte* msg, sword16* p)
{
#ifdef USE_INTEL_SPEEDUP
     if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        /* Convert the polynomial into a array of bytes (message). */
        mlkem_to_msg_avx2(msg, p);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
        mlkem_to_msg_c(msg, p);
    }
}
#endif /* !WOLFSSL_MLKEM_NO_DECAPSULATE */
#else
#if !defined(WOLFSSL_MLKEM_NO_ENCAPSULATE) || \
    !defined(WOLFSSL_MLKEM_NO_DECAPSULATE)
/* Convert message to polynomial.
 *
 * FIPS 203, Algorithm 6: ByteDecode_d(B)
 *
 * @param  [out]  p    Polynomial.
 * @param  [in]   msg  Message as a byte array.
 */
void mlkem_from_msg(sword16* p, const byte* msg)
{
    mlkem_from_msg_neon(p, msg);
}
#endif /* !WOLFSSL_MLKEM_NO_ENCAPSULATE || !WOLFSSL_MLKEM_NO_DECAPSULATE */

#ifndef WOLFSSL_MLKEM_NO_DECAPSULATE
/* Convert polynomial to message.
 *
 * FIPS 203, Algorithm 6: ByteEncode_d(F)
 *
 * @param  [out]  msg  Message as a byte array.
 * @param  [in]   p    Polynomial.
 */
void mlkem_to_msg(byte* msg, sword16* p)
{
    mlkem_to_msg_neon(msg, p);
}
#endif /* WOLFSSL_MLKEM_NO_DECAPSULATE */
#endif /* !(__aarch64__ && WOLFSSL_ARMASM) */

/******************************************************************************/

/* Convert bytes to polynomial.
 *
 * Consecutive 12 bits hold each coefficient of polynomial.
 * Used in decoding private and public keys.
 *
 * FIPS 203, Algorithm 6: ByteDecode_d(B)
 *
 * @param  [out]  p  Vector of polynomials.
 * @param  [in]   b  Array of bytes.
 * @param  [in]   k  Number of polynomials in vector.
 */
static void mlkem_from_bytes_c(sword16* p, const byte* b, int k)
{
    int i;
    int j;

    for (j = 0; j < k; j++) {
        for (i = 0; i < MLKEM_N / 2; i++) {
            p[2 * i + 0] = ((b[3 * i + 0] >> 0) |
                            ((word16)b[3 * i + 1] << 8)) & 0xfff;
            p[2 * i + 1] = ((b[3 * i + 1] >> 4) |
                            ((word16)b[3 * i + 2] << 4)) & 0xfff;
        }
        p += MLKEM_N;
        b += WC_ML_KEM_POLY_SIZE;
    }
}

/* Convert bytes to polynomial.
 *
 * Consecutive 12 bits hold each coefficient of polynomial.
 * Used in decoding private and public keys.
 *
 * FIPS 203, Algorithm 6: ByteDecode_d(B)
 *
 * @param  [out]  p  Vector of polynomials.
 * @param  [in]   b  Array of bytes.
 * @param  [in]   k  Number of polynomials in vector.
 */
void mlkem_from_bytes(sword16* p, const byte* b, int k)
{
#ifdef USE_INTEL_SPEEDUP
     if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        int i;

        for (i = 0; i < k; i++) {
            mlkem_from_bytes_avx2(p, b);
            p += MLKEM_N;
            b += WC_ML_KEM_POLY_SIZE;
        }

        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
        mlkem_from_bytes_c(p, b, k);
    }
}

/* Convert polynomial to bytes.
 *
 * Consecutive 12 bits hold each coefficient of polynomial.
 * Used in encoding private and public keys.
 *
 * FIPS 203, Algorithm 6: ByteEncode_d(F)
 *
 * @param  [out]  b  Array of bytes.
 * @param  [in]   p  Polynomial.
 * @param  [in]   k  Number of polynomials in vector.
 */
static void mlkem_to_bytes_c(byte* b, sword16* p, int k)
{
    int i;
    int j;

    /* Reduce each coefficient to mod q. */
    mlkem_csubq_c(p);
    /* All values are now positive. */

    for (j = 0; j < k; j++) {
        for (i = 0; i < MLKEM_N / 2; i++) {
            word16 t0 = p[2 * i];
            word16 t1 = p[2 * i + 1];
            b[3 * i + 0] = (t0 >> 0);
            b[3 * i + 1] = (t0 >> 8) | t1 << 4;
            b[3 * i + 2] = (t1 >> 4);
        }
        p += MLKEM_N;
        b += WC_ML_KEM_POLY_SIZE;
    }
}

/* Convert polynomial to bytes.
 *
 * Consecutive 12 bits hold each coefficient of polynomial.
 * Used in encoding private and public keys.
 *
 * FIPS 203, Algorithm 6: ByteEncode_d(F)
 *
 * @param  [out]  b  Array of bytes.
 * @param  [in]   p  Polynomial.
 * @param  [in]   k  Number of polynomials in vector.
 */
void mlkem_to_bytes(byte* b, sword16* p, int k)
{
#ifdef USE_INTEL_SPEEDUP
     if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        int i;

        for (i = 0; i < k; i++) {
            mlkem_to_bytes_avx2(b, p);
            p += MLKEM_N;
            b += WC_ML_KEM_POLY_SIZE;
        }

        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
        mlkem_to_bytes_c(b, p, k);
    }
}

#endif /* WOLFSSL_WC_MLKEM */
