/* riscv-sha512.c
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


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_RISCV_ASM
#if !defined(NO_SHA512) || defined(WOLFSSL_SHA384)

#if FIPS_VERSION3_LT(6,0,0) && defined(HAVE_FIPS)
    #undef HAVE_FIPS
#else
    #if defined(HAVE_FIPS) && FIPS_VERSION3_GE(6,0,0)
    /* set NO_WRAPPERS before headers, use direct internal f()s not wrappers */
        #define FIPS_NO_WRAPPERS
    #endif
#endif

#include <wolfssl/wolfcrypt/sha512.h>
#if FIPS_VERSION3_GE(6,0,0)
    const unsigned int wolfCrypt_FIPS_sha512_ro_sanity[2] =
                                                     { 0x1a2b3c4d, 0x00000014 };
    int wolfCrypt_FIPS_SHA512_sanity(void)
    {
        return 0;
    }
#endif
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <wolfssl/wolfcrypt/port/riscv/riscv-64-asm.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* Constants to add in each round. */
static const word64 K512[80] = {
    W64LIT(0x428a2f98d728ae22), W64LIT(0x7137449123ef65cd),
    W64LIT(0xb5c0fbcfec4d3b2f), W64LIT(0xe9b5dba58189dbbc),
    W64LIT(0x3956c25bf348b538), W64LIT(0x59f111f1b605d019),
    W64LIT(0x923f82a4af194f9b), W64LIT(0xab1c5ed5da6d8118),
    W64LIT(0xd807aa98a3030242), W64LIT(0x12835b0145706fbe),
    W64LIT(0x243185be4ee4b28c), W64LIT(0x550c7dc3d5ffb4e2),
    W64LIT(0x72be5d74f27b896f), W64LIT(0x80deb1fe3b1696b1),
    W64LIT(0x9bdc06a725c71235), W64LIT(0xc19bf174cf692694),
    W64LIT(0xe49b69c19ef14ad2), W64LIT(0xefbe4786384f25e3),
    W64LIT(0x0fc19dc68b8cd5b5), W64LIT(0x240ca1cc77ac9c65),
    W64LIT(0x2de92c6f592b0275), W64LIT(0x4a7484aa6ea6e483),
    W64LIT(0x5cb0a9dcbd41fbd4), W64LIT(0x76f988da831153b5),
    W64LIT(0x983e5152ee66dfab), W64LIT(0xa831c66d2db43210),
    W64LIT(0xb00327c898fb213f), W64LIT(0xbf597fc7beef0ee4),
    W64LIT(0xc6e00bf33da88fc2), W64LIT(0xd5a79147930aa725),
    W64LIT(0x06ca6351e003826f), W64LIT(0x142929670a0e6e70),
    W64LIT(0x27b70a8546d22ffc), W64LIT(0x2e1b21385c26c926),
    W64LIT(0x4d2c6dfc5ac42aed), W64LIT(0x53380d139d95b3df),
    W64LIT(0x650a73548baf63de), W64LIT(0x766a0abb3c77b2a8),
    W64LIT(0x81c2c92e47edaee6), W64LIT(0x92722c851482353b),
    W64LIT(0xa2bfe8a14cf10364), W64LIT(0xa81a664bbc423001),
    W64LIT(0xc24b8b70d0f89791), W64LIT(0xc76c51a30654be30),
    W64LIT(0xd192e819d6ef5218), W64LIT(0xd69906245565a910),
    W64LIT(0xf40e35855771202a), W64LIT(0x106aa07032bbd1b8),
    W64LIT(0x19a4c116b8d2d0c8), W64LIT(0x1e376c085141ab53),
    W64LIT(0x2748774cdf8eeb99), W64LIT(0x34b0bcb5e19b48a8),
    W64LIT(0x391c0cb3c5c95a63), W64LIT(0x4ed8aa4ae3418acb),
    W64LIT(0x5b9cca4f7763e373), W64LIT(0x682e6ff3d6b2b8a3),
    W64LIT(0x748f82ee5defb2fc), W64LIT(0x78a5636f43172f60),
    W64LIT(0x84c87814a1f0ab72), W64LIT(0x8cc702081a6439ec),
    W64LIT(0x90befffa23631e28), W64LIT(0xa4506cebde82bde9),
    W64LIT(0xbef9a3f7b2c67915), W64LIT(0xc67178f2e372532b),
    W64LIT(0xca273eceea26619c), W64LIT(0xd186b8c721c0c207),
    W64LIT(0xeada7dd6cde0eb1e), W64LIT(0xf57d4f7fee6ed178),
    W64LIT(0x06f067aa72176fba), W64LIT(0x0a637dc5a2c898a6),
    W64LIT(0x113f9804bef90dae), W64LIT(0x1b710b35131c471b),
    W64LIT(0x28db77f523047d84), W64LIT(0x32caab7b40c72493),
    W64LIT(0x3c9ebe0a15c9bebc), W64LIT(0x431d67c49c100d4c),
    W64LIT(0x4cc5d4becb3e42b6), W64LIT(0x597f299cfc657e2a),
    W64LIT(0x5fcb6fab3ad6faec), W64LIT(0x6c44198c4a475817)
};

static int InitSha512(wc_Sha512* sha512, void* heap, int devId)
{
   int ret = 0;

    if (sha512 == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        sha512->heap = heap;
    #ifdef WOLF_CRYPTO_CB
        sha512->devId = devId;
    #endif
        (void)devId;
    #ifdef WOLFSSL_SMALL_STACK_CACHE
        sha512->W = NULL;
    #endif

    #ifdef WOLFSSL_HASH_FLAGS
        sha512->flags = 0;
    #endif
    }

    return ret;
}

/* Initialze SHA-512 object for hashing.
 *
 * @param [in, out] sha512  SHA-512 object.
 */
static void InitSha512_State(wc_Sha512* sha512)
{
    /* Set initial hash values. */
#ifndef WOLFSSL_RISCV_VECTOR_CRYPTO_ASM
    sha512->digest[0] = W64LIT(0x6a09e667f3bcc908);
    sha512->digest[1] = W64LIT(0xbb67ae8584caa73b);
    sha512->digest[2] = W64LIT(0x3c6ef372fe94f82b);
    sha512->digest[3] = W64LIT(0xa54ff53a5f1d36f1);
    sha512->digest[4] = W64LIT(0x510e527fade682d1);
    sha512->digest[5] = W64LIT(0x9b05688c2b3e6c1f);
    sha512->digest[6] = W64LIT(0x1f83d9abfb41bd6b);
    sha512->digest[7] = W64LIT(0x5be0cd19137e2179);
#else
    /* f, e, b, a, h, g, d, c */
    sha512->digest[0] = W64LIT(0x9b05688c2b3e6c1f);
    sha512->digest[1] = W64LIT(0x510e527fade682d1);
    sha512->digest[2] = W64LIT(0xbb67ae8584caa73b);
    sha512->digest[3] = W64LIT(0x6a09e667f3bcc908);
    sha512->digest[4] = W64LIT(0x5be0cd19137e2179);
    sha512->digest[5] = W64LIT(0x1f83d9abfb41bd6b);
    sha512->digest[6] = W64LIT(0xa54ff53a5f1d36f1);
    sha512->digest[7] = W64LIT(0x3c6ef372fe94f82b);
#endif

    /* No hashed data. */
    sha512->buffLen = 0;
    /* No data hashed. */
    sha512->loLen   = 0;
    sha512->hiLen   = 0;
}

#if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
#if !defined(WOLFSSL_NOSHA512_224)
/**
 * Initialize given wc_Sha512 structure with value specific to sha512/224.
 * Note that sha512/224 has different initial hash value from sha512.
 * The initial hash value consists of eight 64bit words. They are given
 * in FIPS180-4.
 */
static void InitSha512_224_State(wc_Sha512* sha512)
{
#ifndef WOLFSSL_RISCV_VECTOR_CRYPTO_ASM
    sha512->digest[0] = W64LIT(0x8c3d37c819544da2);
    sha512->digest[1] = W64LIT(0x73e1996689dcd4d6);
    sha512->digest[2] = W64LIT(0x1dfab7ae32ff9c82);
    sha512->digest[3] = W64LIT(0x679dd514582f9fcf);
    sha512->digest[4] = W64LIT(0x0f6d2b697bd44da8);
    sha512->digest[5] = W64LIT(0x77e36f7304c48942);
    sha512->digest[6] = W64LIT(0x3f9d85a86a1d36c8);
    sha512->digest[7] = W64LIT(0x1112e6ad91d692a1);
#else
    /* f, e, b, a, h, g, d, c */
    sha512->digest[0] = W64LIT(0x77e36f7304c48942);
    sha512->digest[1] = W64LIT(0x0f6d2b697bd44da8);
    sha512->digest[2] = W64LIT(0x73e1996689dcd4d6);
    sha512->digest[3] = W64LIT(0x8c3d37c819544da2);
    sha512->digest[4] = W64LIT(0x1112e6ad91d692a1);
    sha512->digest[5] = W64LIT(0x3f9d85a86a1d36c8);
    sha512->digest[6] = W64LIT(0x679dd514582f9fcf);
    sha512->digest[7] = W64LIT(0x1dfab7ae32ff9c82);
#endif

    /* No hashed data. */
    sha512->buffLen = 0;
    /* No data hashed. */
    sha512->loLen   = 0;
    sha512->hiLen   = 0;
}
#endif /* !WOLFSSL_NOSHA512_224 */
#endif /* !HAVE_FIPS && !HAVE_SELFTEST */

#if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
#if !defined(WOLFSSL_NOSHA512_256)
/**
 * Initialize given wc_Sha512 structure with value specific to sha512/256.
 * Note that sha512/256 has different initial hash value from sha512.
 * The initial hash value consists of eight 64bit words. They are given
 * in FIPS180-4.
 */
static void InitSha512_256_State(wc_Sha512* sha512)
{
#ifndef WOLFSSL_RISCV_VECTOR_CRYPTO_ASM
    sha512->digest[0] = W64LIT(0x22312194fc2bf72c);
    sha512->digest[1] = W64LIT(0x9f555fa3c84c64c2);
    sha512->digest[2] = W64LIT(0x2393b86b6f53b151);
    sha512->digest[3] = W64LIT(0x963877195940eabd);
    sha512->digest[4] = W64LIT(0x96283ee2a88effe3);
    sha512->digest[5] = W64LIT(0xbe5e1e2553863992);
    sha512->digest[6] = W64LIT(0x2b0199fc2c85b8aa);
    sha512->digest[7] = W64LIT(0x0eb72ddc81c52ca2);
#else
    /* f, e, b, a, h, g, d, c */
    sha512->digest[0] = W64LIT(0xbe5e1e2553863992);
    sha512->digest[1] = W64LIT(0x96283ee2a88effe3);
    sha512->digest[2] = W64LIT(0x9f555fa3c84c64c2);
    sha512->digest[3] = W64LIT(0x22312194fc2bf72c);
    sha512->digest[4] = W64LIT(0x0eb72ddc81c52ca2);
    sha512->digest[5] = W64LIT(0x2b0199fc2c85b8aa);
    sha512->digest[6] = W64LIT(0x963877195940eabd);
    sha512->digest[7] = W64LIT(0x2393b86b6f53b151);
#endif

    /* No hashed data. */
    sha512->buffLen = 0;
    /* No data hashed. */
    sha512->loLen   = 0;
    sha512->hiLen   = 0;
}
#endif /* !WOLFSSL_NOSHA512_256 */
#endif /* !HAVE_FIPS && !HAVE_SELFTEST */

/* More data hashed, add length to 64-bit cumulative total.
 *
 * @param [in, out] sha512  SHA-512 object. Assumed not NULL.
 * @param [in]      len     Length to add.
 */
static WC_INLINE void AddLength(wc_Sha512* sha512, word32 len)
{
    word32 tmp = sha512->loLen;
    if ((sha512->loLen += len) < tmp)
        sha512->hiLen++;                       /* carry low to high */
}

#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION

/* Load a word with bytes reversed. */
#define LOAD_DWORD_REV(r, o, p, t0, t1, t2, t3) \
    "lbu    " #t0 ", " #o "+4(" #p ")\n\t"      \
    "lbu    " #t1 ", " #o "+5(" #p ")\n\t"      \
    "lbu    " #t2 ", " #o "+6(" #p ")\n\t"      \
    "lbu    " #r ", " #o "+7(" #p ")\n\t"       \
    "slli   " #t0 ", " #t0 ", 24\n\t"           \
    "slli   " #t1 ", " #t1 ", 16\n\t"           \
    "slli   " #t2 ", " #t2 ", 8\n\t"            \
    "or     " #r ", " #r ", " #t0 "\n\t"        \
    "or     " #r ", " #r ", " #t1 "\n\t"        \
    "or     " #r ", " #r ", " #t2 "\n\t"        \
    "lbu    " #t0 ", " #o "+0(" #p ")\n\t"      \
    "lbu    " #t1 ", " #o "+1(" #p ")\n\t"      \
    "lbu    " #t2 ", " #o "+2(" #p ")\n\t"      \
    "lbu    " #t3 ", " #o "+3(" #p ")\n\t"      \
    "slli   " #t0 ", " #t0 ", 56\n\t"           \
    "slli   " #t1 ", " #t1 ", 48\n\t"           \
    "slli   " #t2 ", " #t2 ", 40\n\t"           \
    "slli   " #t3 ", " #t3 ", 32\n\t"           \
    "or     " #r ", " #r ", " #t0 "\n\t"        \
    "or     " #r ", " #r ", " #t1 "\n\t"        \
    "or     " #r ", " #r ", " #t2 "\n\t"        \
    "or     " #r ", " #r ", " #t3 "\n\t"

#endif

#ifndef WOLFSSL_RISCV_VECTOR_CRYPTO_ASM

#ifdef WOLFSSL_RISCV_SCALAR_CRYPTO_ASM

/* SHA-512 SUM0 operation. */
#define SHA512SUM0(rd, rs1)                                         \
    ASM_WORD((0b000100000100 << 20) | (0b001 << 12) | 0b0010011 |   \
             (rs1 << 15) | (rd << 7))
/* SHA-512 SUM1 operation. */
#define SHA512SUM1(rd, rs1)                                         \
    ASM_WORD((0b000100000101 << 20) | (0b001 << 12) | 0b0010011 |   \
             (rs1 << 15) | (rd << 7))
/* SHA-512 SIGMA0 operation. */
#define SHA512SIG0(rd, rs1)                                         \
    ASM_WORD((0b000100000110 << 20) | (0b001 << 12) | 0b0010011 |   \
             (rs1 << 15) | (rd << 7))
/* SHA-512 SIGMA1 operation. */
#define SHA512SIG1(rd, rs1)                                         \
    ASM_WORD((0b000100000111 << 20) | (0b001 << 12) | 0b0010011 |   \
             (rs1 << 15) | (rd << 7))

/* One round of compression. */
#define RND(a, b, c, d, e, f, g, h, w, k)                       \
    /* Get e and a */                                           \
    "mv     a4, " #e "\n\t"                                     \
    "mv     a5, " #a "\n\t"                                     \
    /* Sigma1(e) */                                             \
    SHA512SUM1(REG_A4, REG_A4)                                  \
    /* Sigma0(a) */                                             \
    SHA512SUM0(REG_A5, REG_A5)                                  \
    /* Maj(a, b, c) = t5 */                                     \
    /* Ch(e, f, g) = t6 */                                      \
    /* a ^ b */                                                 \
    "xor    t4, " #a ", " #b "\n\t"                             \
    /* f ^ g */                                                 \
    "xor    t6, " #f ", " #g "\n\t"                             \
    /* b ^ c */                                                 \
    "xor    t5, " #b ", " #c "\n\t"                             \
    /* (f ^ g) & e */                                           \
    "and    t6, t6, " #e "\n\t"                                 \
    /* (a^b) & (b^c) */                                         \
    "and    t5, t5, t4\n\t"                                     \
    /* ((f ^ g) & e) ^ g */                                     \
    "xor    t6, t6, " #g "\n\t"                                 \
    /* ((a^b) & (b^c)) ^ b */                                   \
    "xor    t5, t5, " #b "\n\t"                                 \
    /* sigma1 + Ch */                                           \
    "add    t4, a4, t6\n\t"                                     \
    /* K + W */                                                 \
    "add    t6, " #k ", " #w "\n\t"                             \
    /* sigma1 + Ch + K + W = 't0'-h */                          \
    "add    t4, t4, t6\n\t"                                     \
    /* h + sigma1 + Ch + K + W = 't0' = h */                    \
    "add    " #h ", " #h ", t4\n\t"                             \
    /* Sigma0(a) + Maj = 't1' */                                \
    "add    t5, a5, t5\n\t"                                     \
    /* d += 't0' */                                             \
    "add    " #d ", " #d ", " #h "\n\t"                         \
    /* h += 't1' */                                             \
    "add    " #h ", " #h ", t5\n\t"

#define W_UPDATE(w0, w1, w9, w14, reg_w0, reg_w1, reg_w9, reg_w14)  \
    /* Gamma0(W[1]) */                                              \
    SHA512SIG0(REG_A4, reg_w1)                                      \
    /* Gamma1(W[i-2]) = Gamma1(W[14]) */                            \
    SHA512SIG1(REG_A5, reg_w14)                                     \
    /* Gamma1(W[14]) + W[9] */                                      \
    "add    a5, a5, " #w9 "\n\t"                                    \
    /* Gamma0(W[1]) + W[i-16] = Gamma0(W[1]) + W[0] */              \
    "add    " #w0 ", " #w0 ", a4\n\t"                               \
    /* W[0] = Gamma1(W[14]) + W[9] + Gamma0(W[1]) + W[0] */         \
    "add    " #w0 ", a5, " #w0 "\n\t"

#else

/* SHA-512 SUM0 operation. */
#define SHA512SUM0(rd, rs1)                                     \
    "slli   t5, " #rs1 ", 36\n\t"                               \
    "srli   t4, " #rs1 ", 28\n\t"                               \
    "slli   t6, " #rs1 ", 30\n\t"                               \
    "or     t4, t4, t5\n\t"                                     \
    "srli   t5, " #rs1 ", 34\n\t"                               \
    "xor    t4, t4, t6\n\t"                                     \
    "slli   t6, " #rs1 ", 25\n\t"                               \
    "xor    t4, t4, t5\n\t"                                     \
    "srli   " #rd ", " #rs1 ", 39\n\t"                          \
    "xor    t4, t4, t6\n\t"                                     \
    "xor    " #rd ", " #rd ", t4\n\t"

/* SHA-512 SUM1 operation. */
#define SHA512SUM1(rd, rs1)                                     \
    "slli   t5, " #rs1 ", 50\n\t"                               \
    "srli   t4, " #rs1 ", 14\n\t"                               \
    "slli   t6, " #rs1 ", 46\n\t"                               \
    "or     t4, t4, t5\n\t"                                     \
    "srli   t5, " #rs1 ", 18\n\t"                               \
    "xor    t4, t4, t6\n\t"                                     \
    "slli   t6, " #rs1 ", 23\n\t"                               \
    "xor    t4, t4, t5\n\t"                                     \
    "srli   " #rd ", " #rs1 ", 41\n\t"                          \
    "xor    t4, t4, t6\n\t"                                     \
    "xor    " #rd ", " #rd ", t4\n\t"

/* SHA-512 SIGMA0 operation. */
#define SHA512SIG0(rd, rs1)                                     \
    "slli   t5, " #rs1 ", 63\n\t"                               \
    "srli   t6, " #rs1 ", 1\n\t"                                \
    "slli   t4, " #rs1 ", 56\n\t"                               \
    "or     t6, t6, t5\n\t"                                     \
    "srli   t5, " #rs1 ", 8\n\t"                                \
    "xor    t6, t6, t4\n\t"                                     \
    "srli   " #rd ", " #rs1 ", 7\n\t"                           \
    "xor    t6, t6, t5\n\t"                                     \
    "xor    " #rd ", " #rd ", t6\n\t"

/* SHA-512 SIGMA1 operation. */
#define SHA512SIG1(rd, rs1)                                     \
    "slli   t5, " #rs1 ", 45\n\t"                               \
    "srli   t6, " #rs1 ", 19\n\t"                               \
    "slli   t4, " #rs1 ", 3\n\t"                                \
    "or     t6, t6, t5\n\t"                                     \
    "srli   t5, " #rs1 ", 61\n\t"                               \
    "xor    t6, t6, t4\n\t"                                     \
    "srli   " #rd ", " #rs1 ", 6\n\t"                           \
    "xor    t6, t6, t5\n\t"                                     \
    "xor    " #rd ", " #rd ", t6\n\t"

/* One round of compression. */
#define RND(a, b, c, d, e, f, g, h, w, k)                       \
    /* Sigma1(e) */                                             \
    SHA512SUM1(a4, e)                                           \
    /* Sigma0(a) */                                             \
    SHA512SUM0(a5, a)                                           \
    /* Maj(a, b, c) = t5 */                                     \
    /* Ch(e, f, g) = t6 */                                      \
    /* a ^ b */                                                 \
    "xor    t4, " #a ", " #b "\n\t"                             \
    /* f ^ g */                                                 \
    "xor    t6, " #f ", " #g "\n\t"                             \
    /* b ^ c */                                                 \
    "xor    t5, " #b ", " #c "\n\t"                             \
    /* (f ^ g) & e */                                           \
    "and    t6, t6, " #e "\n\t"                                 \
    /* (a^b) & (b^c) */                                         \
    "and    t5, t5, t4\n\t"                                     \
    /* ((f ^ g) & e) ^ g */                                     \
    "xor    t6, t6, " #g "\n\t"                                 \
    /* ((a^b) & (b^c)) ^ b */                                   \
    "xor    t5, t5, " #b "\n\t"                                 \
    /* sigma1 + Ch */                                           \
    "add    t4, a4, t6\n\t"                                     \
    /* K + W */                                                 \
    "add    t6, " #k ", " #w "\n\t"                             \
    /* sigma1 + Ch + K + W = 't0'-h */                          \
    "add    t4, t4, t6\n\t"                                     \
    /* h + sigma1 + Ch + K + W = 't0' = h */                    \
    "add    " #h ", " #h ", t4\n\t"                             \
    /* Sigma0(a) + Maj = 't1' */                                \
    "add    t5, a5, t5\n\t"                                     \
    /* d += 't0' */                                             \
    "add    " #d ", " #d ", " #h "\n\t"                         \
    /* h += 't1' */                                             \
    "add    " #h ", " #h ", t5\n\t"

/* Two message schedule updates. */
#define W_UPDATE(w0, w1, w9, w14, reg_w0, reg_w1, reg_w9, reg_14)   \
    /* Gamma0(W[1]) */                                              \
    SHA512SIG0(a4, w1)                                              \
    /* Gamma1(W[i-2]) = Gamma1(W[14]) */                            \
    SHA512SIG1(a5, w14)                                             \
    /* Gamma1(W[14]) + W[9] */                                      \
    "add    a5, a5, " #w9 "\n\t"                                    \
    /* Gamma0(W[1]) + W[i-16] = Gamma0(W[1]) + W[0] */              \
    "add    " #w0 ", " #w0 ", a4\n\t"                               \
    /* W[0] = Gamma1(W[14]) + W[9] + Gamma0(W[1]) + W[0] */         \
    "add    " #w0 ", a5, " #w0 "\n\t"


#endif /* WOLFSSL_RISCV_SCALAR_CRYPTO_ASM */

#define RND2_W(a, b, c, d, e, f, g, h, o, w2o, w9o, w10o)       \
    /* Get k[i] */                                              \
    "ld     a6, " #o "(%[k])\n\t"                               \
    /* Get k[i+1] */                                            \
    "ld     a7, " #o "+8(%[k])\n\t"                             \
    RND(a, b, c, d, e, f, g, h, s1, a6)                         \
    /* Get W[1] */                                              \
    "ld     s2, " #o "+8(sp)\n\t"                               \
    /* Get W[9] */                                              \
    "ld     s3, " #w9o "(sp)\n\t"                               \
    W_UPDATE(s1, s2, s3, s4, REG_S1, REG_S2, REG_S3, REG_S4)    \
    RND(h, a, b, c, d, e, f, g, s2, a7)                         \
    "mv     s4, s1\n\t"                                         \
    /* Get W[2] */                                              \
    "ld     s1, " #w2o "(sp)\n\t"                               \
    /* Get W[10] */                                             \
    "ld     s3, " #w10o "(sp)\n\t"                              \
    W_UPDATE(s2, s1, s3, s5, REG_S2, REG_S1, REG_S3, REG_S5)    \
    "sd     s4, " #o "(sp)\n\t"                                 \
    "mv     s5, s2\n\t"                                         \
    "sd     s2, " #o "+8(sp)\n\t"

/* Sixteen rounds of compression with message scheduling. */
#define RND16()                                                     \
    RND2_W(t0, t1, t2, t3, s8, s9, s10, s11,   0,  16,  72,  80)    \
    RND2_W(s10, s11, t0, t1, t2, t3, s8, s9,  16,  32,  88,  96)    \
    RND2_W(s8, s9, s10, s11, t0, t1, t2, t3,  32,  48, 104, 112)    \
    RND2_W(t2, t3, s8, s9, s10, s11, t0, t1,  48,  64, 120,   0)    \
    RND2_W(t0, t1, t2, t3, s8, s9, s10, s11,  64,  80,   8,  16)    \
    RND2_W(s10, s11, t0, t1, t2, t3, s8, s9,  80,  96,  24,  32)    \
    RND2_W(s8, s9, s10, s11, t0, t1, t2, t3,  96, 112,  40,  48)    \
    RND2_W(t2, t3, s8, s9, s10, s11, t0, t1, 112,   0,  56,  64)

#define RND2(a, b, c, d, e, f, g, h, o)     \
    /* Get k[i] */                          \
    "ld     a6, " #o "(%[k])\n\t"           \
    /* Get W[0] */                          \
    "ld     s1, " #o "(sp)\n\t"             \
    RND(a, b, c, d, e, f, g, h, s1, a6)     \
    /* Get k[i] */                          \
    "ld     a6, " #o "+8(%[k])\n\t"         \
    /* Get W[1] */                          \
    "ld     s1, " #o "+8(sp)\n\t"           \
    RND(h, a, b, c, d, e, f, g, s1, a6)

/* Sixteen rounds of compression only. */
#define RND16_LAST()                               \
    RND2(t0, t1, t2, t3, s8, s9, s10, s11,   0)    \
    RND2(s10, s11, t0, t1, t2, t3, s8, s9,  16)    \
    RND2(s8, s9, s10, s11, t0, t1, t2, t3,  32)    \
    RND2(t2, t3, s8, s9, s10, s11, t0, t1,  48)    \
    RND2(t0, t1, t2, t3, s8, s9, s10, s11,  64)    \
    RND2(s10, s11, t0, t1, t2, t3, s8, s9,  80)    \
    RND2(s8, s9, s10, s11, t0, t1, t2, t3,  96)    \
    RND2(t2, t3, s8, s9, s10, s11, t0, t1, 112)

/* Transform the message data.
 *
 * @param [in, out] sha512  SHA-512 object.
 * @param [in]      data    Buffer of data to hash.
 * @param [in]      blocks  Number of blocks of data to hash.
 */
static WC_INLINE void Sha512Transform(wc_Sha512* sha512, const byte* data,
    word32 blocks)
{
    word64* k = (word64*)K512;

    __asm__ __volatile__ (
        "addi   sp, sp, -128\n\t"

        /* Load digest. */
        "ld     t0, 0(%[digest])\n\t"
        "ld     t1, 8(%[digest])\n\t"
        "ld     t2, 16(%[digest])\n\t"
        "ld     t3, 24(%[digest])\n\t"
        "ld     s8, 32(%[digest])\n\t"
        "ld     s9, 40(%[digest])\n\t"
        "ld     s10, 48(%[digest])\n\t"
        "ld     s11, 56(%[digest])\n\t"

        /* 5 rounds of 16 per block - 4 loops of 16 and 1 final 16. */
        "slli   %[blocks], %[blocks], 2\n\t"

    "\n1:\n\t"
        /* beginning of SHA512 block operation */
        /* Load W */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        LOAD_DWORD_REV(t4,  0, %[data], a4, a5, a6, a7)
        LOAD_DWORD_REV(s1,  8, %[data], a4, a5, a6, a7)
        LOAD_DWORD_REV(s2, 16, %[data], a4, a5, a6, a7)
        LOAD_DWORD_REV(s3, 24, %[data], a4, a5, a6, a7)
        LOAD_DWORD_REV(s4, 32, %[data], a4, a5, a6, a7)
        LOAD_DWORD_REV(s5, 40, %[data], a4, a5, a6, a7)
        LOAD_DWORD_REV(s6, 48, %[data], a4, a5, a6, a7)
        LOAD_DWORD_REV(s7, 56, %[data], a4, a5, a6, a7)
#else
        "ld     t4,  0(%[data])\n\t"
        "ld     s1,  8(%[data])\n\t"
        "ld     s2, 16(%[data])\n\t"
        "ld     s3, 24(%[data])\n\t"
        "ld     s4, 32(%[data])\n\t"
        "ld     s5, 40(%[data])\n\t"
        "ld     s6, 48(%[data])\n\t"
        "ld     s7, 56(%[data])\n\t"
        REV8(REG_T4, REG_T4)
        REV8(REG_S1, REG_S1)
        REV8(REG_S2, REG_S2)
        REV8(REG_S3, REG_S3)
        REV8(REG_S4, REG_S4)
        REV8(REG_S5, REG_S5)
        REV8(REG_S6, REG_S6)
        REV8(REG_S7, REG_S7)
#endif
        "sd    t4,  0(sp)\n\t"
        "sd    s1,  8(sp)\n\t"
        "sd    s2, 16(sp)\n\t"
        "sd    s3, 24(sp)\n\t"
        "sd    s4, 32(sp)\n\t"
        "sd    s5, 40(sp)\n\t"
        "sd    s6, 48(sp)\n\t"
        "sd    s7, 56(sp)\n\t"
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        LOAD_DWORD_REV(t4,  64, %[data], a4, a5, a6, a7)
        LOAD_DWORD_REV(s1,  72, %[data], a4, a5, a6, a7)
        LOAD_DWORD_REV(s2,  80, %[data], a4, a5, a6, a7)
        LOAD_DWORD_REV(s3,  88, %[data], a4, a5, a6, a7)
        LOAD_DWORD_REV(s4,  96, %[data], a4, a5, a6, a7)
        LOAD_DWORD_REV(s5, 104, %[data], a4, a5, a6, a7)
        LOAD_DWORD_REV(s6, 112, %[data], a4, a5, a6, a7)
        LOAD_DWORD_REV(s7, 120, %[data], a4, a5, a6, a7)
#else
        "ld    t4,  64(%[data])\n\t"
        "ld    s1,  72(%[data])\n\t"
        "ld    s2,  80(%[data])\n\t"
        "ld    s3,  88(%[data])\n\t"
        "ld    s4,  96(%[data])\n\t"
        "ld    s5, 104(%[data])\n\t"
        "ld    s6, 112(%[data])\n\t"
        "ld    s7, 120(%[data])\n\t"
        REV8(REG_T4, REG_T4)
        REV8(REG_S1, REG_S1)
        REV8(REG_S2, REG_S2)
        REV8(REG_S3, REG_S3)
        REV8(REG_S4, REG_S4)
        REV8(REG_S5, REG_S5)
        REV8(REG_S6, REG_S6)
        REV8(REG_S7, REG_S7)
#endif
        "sd    t4,  64(sp)\n\t"
        "sd    s1,  72(sp)\n\t"
        "sd    s2,  80(sp)\n\t"
        "sd    s3,  88(sp)\n\t"
        "sd    s4,  96(sp)\n\t"
        "sd    s5, 104(sp)\n\t"
        "sd    s6, 112(sp)\n\t"
        "sd    s7, 120(sp)\n\t"

    "\n2:\n\t"
        /* Get W[0] */
        "ld     s1, 0(sp)\n\t"
        /* Get W[14] */
        "ld     s4, 112(sp)\n\t"
        /* Get W[15] */
        "ld     s5, 120(sp)\n\t"
        "addi   %[blocks], %[blocks], -1\n\t"
        RND16()
        "andi   a4, %[blocks], 3\n\t"
        "add    %[k], %[k], 128\n\t"
        "bnez   a4, 2b \n\t"
        RND16_LAST()
        "addi   %[k], %[k], -512\n\t"

        "# Add working vars back into digest state.\n\t"
        "ld     t4, 0(%[digest])\n\t"
        "ld     s1, 8(%[digest])\n\t"
        "ld     s2, 16(%[digest])\n\t"
        "ld     s3, 24(%[digest])\n\t"
        "ld     s4, 32(%[digest])\n\t"
        "ld     s5, 40(%[digest])\n\t"
        "ld     s6, 48(%[digest])\n\t"
        "ld     s7, 56(%[digest])\n\t"
        "add    t0, t0, t4\n\t"
        "add    t1, t1, s1\n\t"
        "add    t2, t2, s2\n\t"
        "add    t3, t3, s3\n\t"
        "add    s8, s8, s4\n\t"
        "add    s9, s9, s5\n\t"
        "add    s10, s10, s6\n\t"
        "add    s11, s11, s7\n\t"

        /* Store digest. */
        "sd     t0, 0(%[digest])\n\t"
        "sd     t1, 8(%[digest])\n\t"
        "sd     t2, 16(%[digest])\n\t"
        "sd     t3, 24(%[digest])\n\t"
        "sd     s8, 32(%[digest])\n\t"
        "sd     s9, 40(%[digest])\n\t"
        "sd     s10, 48(%[digest])\n\t"
        "sd     s11, 56(%[digest])\n\t"

        "add    %[data], %[data], 128\n\t"
        "bnez   %[blocks], 1b \n\t"

        "addi   sp, sp, 128\n\t"

        : [blocks] "+r" (blocks), [data] "+r" (data), [k] "+r" (k)
        : [digest] "r" (sha512->digest)
        : "cc", "memory", "t0", "t1", "t2", "t3", "t4", "t5", "t6",
          "a4", "a5", "a6", "a7",
          "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10",
          "s11"
    );
}

#else

/* Two rounds of compression using low two W values.
 * Assumes K has been added into W values.
 */
#define VSHA2CL_VV(vd, vs1, vs2)                    \
    ASM_WORD((0b101111 << 26) | (0b1 << 25) |       \
             (0b010 << 12) | (0b1110111 << 0) |     \
             (vd << 7) | (vs1 << 15) | (vs2 << 20))

/* Two rounds of compression using upper two W values.
 * Assumes K has been added into W values.
 */
#define VSHA2CH_VV(vd, vs1, vs2)                    \
    ASM_WORD((0b101110 << 26) | (0b1 << 25) |       \
             (0b010 << 12) | (0b1110111 << 0) |     \
             (vd << 7) | (vs1 << 15) | (vs2 << 20))

/* Update 4 W values - message scheduling. */
#define VSHA2MS_VV(vd, vs1, vs2)                    \
    ASM_WORD((0b101101 << 26) | (0b1 << 25) |       \
             (0b010 << 12) | (0b1110111 << 0) |     \
             (vd << 7) | (vs1 << 15) | (vs2 << 20))

#define RND4(w0, w2, w4, w6, k)                     \
    /* Four rounds of compression. */               \
    VADD_VV(REG_V14, w0, k)                         \
    VMV_X_S(REG_T1, w2)                             \
    VSHA2CL_VV(REG_V10, REG_V14, REG_V8)            \
    VMV_V_V(REG_V12, w4)                            \
    VSHA2CH_VV(REG_V8, REG_V14, REG_V10)            \
    /* Update 4 W values - message schedule. */     \
    VMV_S_X(REG_V12, REG_T1)                        \
    VSHA2MS_VV(w0, w6, REG_V12)

#define RND4_LAST(w, k)                             \
    /* Four rounds of compression. */               \
    VADD_VV(REG_V14, w, k)                          \
    VSHA2CL_VV(REG_V10, REG_V14, REG_V8)            \
    VSHA2CH_VV(REG_V8, REG_V14, REG_V10)

#define RND16(k)                                    \
    RND4(REG_V0, REG_V2, REG_V4, REG_V6, (k + 0))   \
    RND4(REG_V2, REG_V4, REG_V6, REG_V0, (k + 2))   \
    RND4(REG_V4, REG_V6, REG_V0, REG_V2, (k + 4))   \
    RND4(REG_V6, REG_V0, REG_V2, REG_V4, (k + 6))

#define RND16_LAST(k)           \
    RND4_LAST(REG_V0, (k + 0))  \
    RND4_LAST(REG_V2, (k + 2))  \
    RND4_LAST(REG_V4, (k + 4))  \
    RND4_LAST(REG_V6, (k + 6))

/* Transform the message data.
 *
 * @param [in, out] sha512  SHA-512 object.
 * @param [in]      data    Buffer of data to hash.
 * @param [in]      blocks  Number of blocks of data to hash.
 */
static void Sha512Transform(wc_Sha512* sha512, const byte* data,
    word32 blocks)
{
    word64* k = (word64*)K512;

    __asm__ __volatile__ (
        VSETIVLI(REG_ZERO, 4, 1, 1, 0b011, 0b001)

        /* Load: a|b|e|f, c|d|g|h
         *       3 2 1 0  3 2 1 0
         */
        "mv     t0, %[digest]\n\t"
        VL4RE64_V(REG_V8, REG_T0)

    "\n1:\n\t"
        VMVR_V(REG_V28, REG_V8, 4)

        /* Load 16 W into 8 vectors of 2 64-bit words. */
        "mv     t0, %[data]\n\t"
        VL8RE64_V(REG_V0, REG_T0)
        VREV8(REG_V0, REG_V0)
        VREV8(REG_V2, REG_V2)
        VREV8(REG_V4, REG_V4)
        VREV8(REG_V6, REG_V6)

        "mv     t0, %[k]\n\t"
        VL8RE64_V(REG_V16, REG_T0)
        RND16(REG_V16)
        "addi   t0, %[k], 128\n\t"
        VL8RE64_V(REG_V16, REG_T0)
        RND16(REG_V16)
        "addi   t0, %[k], 256\n\t"
        VL8RE64_V(REG_V16, REG_T0)
        RND16(REG_V16)
        "addi   t0, %[k], 384\n\t"
        VL8RE64_V(REG_V16, REG_T0)
        RND16(REG_V16)
        "addi   t0, %[k], 512\n\t"
        VL8RE64_V(REG_V16, REG_T0)
        RND16_LAST(REG_V16)

        VADD_VV(REG_V8, REG_V8, REG_V28)
        VADD_VV(REG_V10, REG_V10, REG_V30)

        "addi   %[blocks], %[blocks], -1\n\t"
        "add    %[data], %[data], 128\n\t"
        "bnez   %[blocks], 1b \n\t"

        "mv     t0, %[digest]\n\t"
        VS4R_V(REG_V8, REG_T0)

        : [blocks] "+r" (blocks), [data] "+r" (data), [k] "+r" (k)
        : [digest] "r" (sha512->digest)
        : "cc", "memory", "t0", "t1"
    );
}

#endif /* WOLFSSL_RISCV_VECTOR_CRYPTO_ASM */

/* Update the hash with data.
 *
 * @param [in, out] sha512  SHA-512 object.
 * @param [in]      data    Buffer of data to hash.
 * @param [in]      len     Number of bytes in buffer to hash.
 * @return  0 on success.
 */
static WC_INLINE int Sha512Update(wc_Sha512* sha512, const byte* data,
    word32 len)
{
    word32 add;
    word32 blocks;

    /* only perform actions if a buffer is passed in */
    if (len > 0) {
        AddLength(sha512, len);

        if (sha512->buffLen > 0) {
             /* fill leftover buffer with data */
             add = min(len, WC_SHA512_BLOCK_SIZE - sha512->buffLen);
             XMEMCPY((byte*)(sha512->buffer) + sha512->buffLen, data, add);
             sha512->buffLen += add;
             data            += add;
             len             -= add;
             if (sha512->buffLen == WC_SHA512_BLOCK_SIZE) {
                 Sha512Transform(sha512, (byte*)sha512->buffer, 1);
                 sha512->buffLen = 0;
             }
        }

        /* number of blocks in a row to complete */
        blocks = len / WC_SHA512_BLOCK_SIZE;

        if (blocks > 0) {
            Sha512Transform(sha512, data, blocks);
            data += blocks * WC_SHA512_BLOCK_SIZE;
            len  -= blocks * WC_SHA512_BLOCK_SIZE;
        }

        if (len > 0) {
            /* copy over any remaining data leftover */
            XMEMCPY(sha512->buffer, data, len);
            sha512->buffLen = len;
        }
    }

    /* account for possibility of not used if len = 0 */
    (void)add;
    (void)blocks;

    return 0;
}

/* Finalize the hash and put into buffer.
 *
 * @param [in, out] sha512   SHA-512 object.
 * @param [out]     hash     Buffer to hold hash result.
 * @param [in]      hashLen  Length of hash to write out.
 */
static WC_INLINE void Sha512Final(wc_Sha512* sha512, byte* hash, int hashLen)
{
    byte* local;
    byte hashBuf[WC_SHA512_DIGEST_SIZE];
    byte* hashRes = hash;

    if (hashLen < WC_SHA512_DIGEST_SIZE) {
        hashRes = hashBuf;
    }

    local = (byte*)sha512->buffer;
    local[sha512->buffLen++] = 0x80;     /* add 1 */

    /* pad with zeros */
    if (sha512->buffLen > WC_SHA512_PAD_SIZE) {
        XMEMSET(&local[sha512->buffLen], 0,
            WC_SHA512_BLOCK_SIZE - sha512->buffLen);
        Sha512Transform(sha512, (byte*)sha512->buffer, 1);
        sha512->buffLen = 0;
    }
    XMEMSET(&local[sha512->buffLen], 0, WC_SHA512_PAD_SIZE - sha512->buffLen);

    /* put lengths in bits */
    sha512->hiLen = (sha512->loLen >> (8*sizeof(sha512->loLen) - 3)) +
        (sha512->hiLen << 3);
    sha512->loLen = sha512->loLen << 3;

    sha512->buffer[WC_SHA512_BLOCK_SIZE / sizeof(word64) - 2] = sha512->hiLen;
    sha512->buffer[WC_SHA512_BLOCK_SIZE / sizeof(word64) - 1] = sha512->loLen;

    /* store lengths */
    __asm__ __volatile__ (
        /* Reverse byte order of 64-bit words. */
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "ld     t0, 112(%[buff])\n\t"
        "ld     t1, 120(%[buff])\n\t"
        REV8(REG_T0, REG_T0)
        REV8(REG_T1, REG_T1)
#else
        LOAD_DWORD_REV(t0, 112, %[buff], t2, t3, t4, t5)
        LOAD_DWORD_REV(t1, 120, %[buff], t2, t3, t4, t5)
#endif
        "sd     t0, 112(%[buff])\n\t"
        "sd     t1, 120(%[buff])\n\t"
        :
        : [buff] "r" (sha512->buffer)
        : "cc", "memory", "t0", "t1", "t2", "t3", "t4", "t5"
    );

    Sha512Transform(sha512, (byte*)sha512->buffer, 1);

    __asm__ __volatile__ (
        /* Reverse byte order of 64-bit words. */
#if defined(WOLFSSL_RISCV_VECTOR_CRYPTO_ASM)
        VSETIVLI(REG_ZERO, 4, 1, 1, 0b011, 0b001)
        "mv     t0, %[digest]\n\t"
        VL4RE64_V(REG_V4, REG_T0)
        VREV8(REG_V4, REG_V4)
        VREV8(REG_V6, REG_V6)
        VSETIVLI(REG_ZERO, 2, 1, 1, 0b011, 0b000)
        /* e|f, a|b, g|h, c|d
         * 1 0  1 0  1 0  1 0 */
        VSLIDEDOWN_VI(REG_V0, REG_V5, 1) /* a */
        VSLIDEDOWN_VI(REG_V1, REG_V7, 1) /* c */
        VSLIDEDOWN_VI(REG_V2, REG_V4, 1) /* e */
        VSLIDEDOWN_VI(REG_V3, REG_V6, 1) /* g */
        VSLIDEUP_VI(REG_V0, REG_V5, 1)
        VSLIDEUP_VI(REG_V1, REG_V7, 1)
        VSLIDEUP_VI(REG_V2, REG_V4, 1)
        VSLIDEUP_VI(REG_V3, REG_V6, 1)
        "mv     t0, %[hash]\n\t"
        VS4R_V(REG_V0, REG_T0)
#elif defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
        VSETIVLI(REG_ZERO, 4, 1, 1, 0b011, 0b001)
        "mv     t0, %[digest]\n\t"
        VL4RE64_V(REG_V0, REG_T0)
        VREV8(REG_V0, REG_V0)
        VREV8(REG_V2, REG_V2)
        "mv     t0, %[hash]\n\t"
        VS4R_V(REG_V0, REG_T0)
#elif defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "ld     t0, 0(%[digest])\n\t"
        "ld     t1, 8(%[digest])\n\t"
        "ld     t2, 16(%[digest])\n\t"
        "ld     t3, 24(%[digest])\n\t"
        "ld     s8, 32(%[digest])\n\t"
        "ld     s9, 40(%[digest])\n\t"
        "ld     s10, 48(%[digest])\n\t"
        "ld     s11, 56(%[digest])\n\t"
        REV8(REG_T0, REG_T0)
        REV8(REG_T1, REG_T1)
        REV8(REG_T2, REG_T2)
        REV8(REG_T3, REG_T3)
        REV8(REG_S8, REG_S8)
        REV8(REG_S9, REG_S9)
        REV8(REG_S10, REG_S10)
        REV8(REG_S11, REG_S11)
        "sd     t0, 0(%[hash])\n\t"
        "sd     t1, 8(%[hash])\n\t"
        "sd     t2, 16(%[hash])\n\t"
        "sd     t3, 24(%[hash])\n\t"
        "sd     s8, 32(%[hash])\n\t"
        "sd     s9, 40(%[hash])\n\t"
        "sd     s10, 48(%[hash])\n\t"
        "sd     s11, 56(%[hash])\n\t"
#else
        LOAD_DWORD_REV(t0,  0, %[digest], a4, a5, a6, a7)
        LOAD_DWORD_REV(t1,  8, %[digest], a4, a5, a6, a7)
        LOAD_DWORD_REV(t2,  16, %[digest], a4, a5, a6, a7)
        LOAD_DWORD_REV(t3,  24, %[digest], a4, a5, a6, a7)
        LOAD_DWORD_REV(s8,  32, %[digest], a4, a5, a6, a7)
        LOAD_DWORD_REV(s9,  40, %[digest], a4, a5, a6, a7)
        LOAD_DWORD_REV(s10,  48, %[digest], a4, a5, a6, a7)
        LOAD_DWORD_REV(s11,  56, %[digest], a4, a5, a6, a7)
        "sd     t0, 0(%[hash])\n\t"
        "sd     t1, 8(%[hash])\n\t"
        "sd     t2, 16(%[hash])\n\t"
        "sd     t3, 24(%[hash])\n\t"
        "sd     s8, 32(%[hash])\n\t"
        "sd     s9, 40(%[hash])\n\t"
        "sd     s10, 48(%[hash])\n\t"
        "sd     s11, 56(%[hash])\n\t"
#endif
        :
        : [digest] "r" (sha512->digest), [hash] "r" (hashRes)
        : "cc", "memory", "t0", "t1", "t2", "t3", "t4", "t5", "t6",
          "s8", "s9", "s10", "s11", "a4", "a5", "a6", "a7"
    );

    if (hashRes == hashBuf) {
        XMEMCPY(hash, hashBuf, hashLen);
    }
}


#ifndef NO_SHA512

/* Initialize SHA-512 object for hashing.
 *
 * @param [in, out] sha512  SHA-512 object.
 * @param [in]      heap    Dynamic memory hint.
 * @param [in]      devId   Device Id.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sha512 is NULL.
 */
int wc_InitSha512_ex(wc_Sha512* sha512, void* heap, int devId)
{
    int ret = InitSha512(sha512, heap, devId);
    if (ret == 0) {
        InitSha512_State(sha512);
    }
    return ret;
}

/* Initialize SHA-512 object for hashing.
 *
 * @param [in, out] sha512  SHA-512 object.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sha512 is NULL.
 */
int wc_InitSha512(wc_Sha512* sha512)
{
    return wc_InitSha512_ex(sha512, NULL, INVALID_DEVID);
}

/* Free the SHA-512 hash.
 *
 * @param [in] sha512  SHA-512 object.
 */
void wc_Sha512Free(wc_Sha512* sha512)
{
    /* No dynamic memory allocated. */
    (void)sha512;
}

/* Update the hash with data.
 *
 * @param [in, out] sha512  SHA-512 object.
 * @param [in]      data    Buffer of data to hash.
 * @param [in]      len     Number of bytes in buffer to hash.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sha512 is NULL.
 * @return  BAD_FUNC_ARG when data is NULL but len is not 0.
 */
int wc_Sha512Update(wc_Sha512* sha512, const byte* data, word32 len)
{
    int ret;

    /* Validate parameters. */
    if ((sha512 == NULL) || ((data == NULL) && (len != 0))) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = Sha512Update(sha512, data, len);
    }

    return ret;
}

/* Put the current hash into buffer.
 *
 * @param [in, out] sha512   SHA-512 object.
 * @param [out]     hash     Buffer to hold hash result.
 * @param [in]      hashLen  Length of hash to write out.
 */
static void Sha512FinalRaw(wc_Sha512* sha512, byte* hash, int hashLen)
{
    word32 digest[WC_SHA512_DIGEST_SIZE / sizeof(word32)];

    ByteReverseWords64((word64*)digest, (word64*)sha512->digest,
        WC_SHA512_DIGEST_SIZE);
    XMEMCPY(hash, digest, hashLen);
}

/* Put the current hash into buffer.
 *
 * @param [in, out] sha512   SHA-512 object.
 * @param [out]     hash     Buffer to hold hash result.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sha512 or hash is NULL.
 */
int wc_Sha512FinalRaw(wc_Sha512* sha512, byte* hash)
{
    int ret = 0;

    /* Validate parameters. */
    if ((sha512 == NULL) || (hash == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        Sha512FinalRaw(sha512, hash, WC_SHA512_DIGEST_SIZE);
    }

    return ret;
}

/* Finalize the hash and put into buffer.
 *
 * @param [in, out] sha512  SHA-512 object.
 * @param [out]     hash    Buffer to hold hash result.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sha512 or hash is NULL.
 */
int wc_Sha512Final(wc_Sha512* sha512, byte* hash)
{
    int ret = 0;

    /* Validate parameters. */
    if ((sha512 == NULL) || (hash == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        /* Finalize hash. */
        Sha512Final(sha512, hash, WC_SHA512_DIGEST_SIZE);
        /* Restart SHA-512 object for next hash. */
        InitSha512_State(sha512);
    }

    return ret;
}

/* Finalize the hash and put into buffer but don't modify state.
 *
 * @param [in, out] sha512  SHA-512 object.
 * @param [out]     hash    Buffer to hold hash result.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sha512 or hash is NULL.
 */
int wc_Sha512GetHash(wc_Sha512* sha512, byte* hash)
{
    int ret;

    /* Validate parameters. */
    if ((sha512 == NULL) || (hash == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        wc_Sha512 tmpSha512;
        /* Create a copy of the hash to finalize. */
        ret = wc_Sha512Copy(sha512, &tmpSha512);
        if (ret == 0) {
            /* Finalize copy. */
            Sha512Final(&tmpSha512, hash, WC_SHA512_DIGEST_SIZE);
            wc_Sha512Free(&tmpSha512);
        }
    }

    return ret;
}

#ifdef WOLFSSL_HASH_FLAGS
/* Set flags of SHA-512 object.
 *
 * @param [in, out] sha512  SHA-512 object.
 * @param [in]      flags   Flags to set.
 * @return  0 on success.
 */
int wc_Sha512SetFlags(wc_Sha512* sha512, word32 flags)
{
    /* Check we have an object to use. */
    if (sha512 != NULL) {
        sha512->flags = flags;
    }
    return 0;
}
/* Get flags of SHA-512 object.
 *
 * @param [in]  sha512  SHA-512 object.
 * @param [out] flags   Flags from SHA-512 object.
 * @return  0 on success.
 */
int wc_Sha512GetFlags(wc_Sha512* sha512, word32* flags)
{
    /* Check we have an object and return parameter to use. */
    if ((sha512 != NULL) && (flags != NULL)) {
        *flags = sha512->flags;
    }
    return 0;
}
#endif

/* Deep copy the SHA-512 object.
 *
 * @param [in]  src  SHA-512 object to copy.
 * @param [out] dst  SHA-512 object to fill.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when src or dst is NULL.
 */
int wc_Sha512Copy(wc_Sha512* src, wc_Sha512* dst)
{
    int ret = 0;

    /* Validate parameters. */
    if ((src == NULL) || (dst == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        XMEMCPY(dst, src, sizeof(wc_Sha512));
    }

    return ret;
}

#ifdef OPENSSL_EXTRA
/* Update the hash with one block of data.
 *
 * @param [in, out] sha512  SHA-512 object.
 * @param [in]      data    Buffer of data to hash.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sha512 or data is NULL.
 */
int wc_Sha512Transform(wc_Sha512* sha512, const unsigned char* data)
{
    int ret = 0;

    /* Validate parameters. */
    if ((sha512 == NULL) || (data == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ByteReverseWords((word32*)sha512->buffer, (word32*)data, WC_SHA512_BLOCK_SIZE);
        Sha512Transform(sha512, (byte*)sha512->buffer, 1);
    }

    return ret;
}
#endif

#if defined(WOLFSSL_HAVE_LMS) && !defined(WOLFSSL_LMS_FULL_HASH)
/* Update the hash with one block of data and optionally get hash.
 *
 * @param [in, out] sha512  SHA-512 object.
 * @param [in]      data    Buffer of data to hash.
 * @param [out]     hash    Buffer to hold hash. May be NULL.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sha512 or data is NULL.
 */
int wc_Sha512HashBlock(wc_Sha512* sha512, const unsigned char* data,
    unsigned char* hash)
{
    int ret = 0;

    /* Validate parameters. */
    if ((sha512 == NULL) || (data == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        /* Hash block. */
        Sha512Transform(sha512, data, 1);

        if (hash != NULL) {
            /* Reverse bytes in digest. */
            word32* hash32 = (word32*)hash;
            word32* digest = (word32*)sha512->digest;
            hash32[0] = ByteReverseWord32(digest[0]);
            hash32[1] = ByteReverseWord32(digest[1]);
            hash32[2] = ByteReverseWord32(digest[2]);
            hash32[3] = ByteReverseWord32(digest[3]);
            hash32[4] = ByteReverseWord32(digest[4]);
            hash32[5] = ByteReverseWord32(digest[5]);
            hash32[6] = ByteReverseWord32(digest[6]);
            hash32[7] = ByteReverseWord32(digest[7]);
            /* Reset state. */
        #ifndef WOLFSSL_RISCV_VECTOR_CRYPTO_ASM
            sha512->digest[0] = 0x6A09E667L;
            sha512->digest[1] = 0xBB67AE85L;
            sha512->digest[2] = 0x3C6EF372L;
            sha512->digest[3] = 0xA54FF53AL;
            sha512->digest[4] = 0x510E527FL;
            sha512->digest[5] = 0x9B05688CL;
            sha512->digest[6] = 0x1F83D9ABL;
            sha512->digest[7] = 0x5BE0CD19L;
        #else
            /* f, e, b, a, h, g, d, c */
            sha512->digest[0] = 0x9B05688CL;
            sha512->digest[1] = 0x510E527FL;
            sha512->digest[2] = 0xBB67AE85L;
            sha512->digest[3] = 0x6A09E667L;
            sha512->digest[4] = 0x5BE0CD19L;
            sha512->digest[5] = 0x1F83D9ABL;
            sha512->digest[6] = 0xA54FF53AL;
            sha512->digest[7] = 0x3C6EF372L;
        #endif
        }
    }

    return ret;
}
#endif /* WOLFSSL_HAVE_LMS && !WOLFSSL_LMS_FULL_HASH */

#if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)

#if !defined(WOLFSSL_NOSHA512_224)

int wc_InitSha512_224_ex(wc_Sha512* sha512, void* heap, int devId)
{
    int ret = InitSha512(sha512, heap, devId);
    if (ret == 0) {
        InitSha512_224_State(sha512);
    }
    return ret;
}
int wc_InitSha512_224(wc_Sha512* sha512)
{
    return wc_InitSha512_224_ex(sha512, NULL, INVALID_DEVID);
}
int wc_Sha512_224Update(wc_Sha512* sha512, const byte* data, word32 len)
{
    return wc_Sha512Update(sha512, data, len);
}
int wc_Sha512_224FinalRaw(wc_Sha512* sha512, byte* hash)
{
    int ret = 0;

    /* Validate parameters. */
    if ((sha512 == NULL) || (hash == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        Sha512FinalRaw(sha512, hash, WC_SHA512_224_DIGEST_SIZE);
    }

    return ret;
}
int wc_Sha512_224Final(wc_Sha512* sha512, byte* hash)
{
    int ret = 0;

    /* Validate parameters. */
    if ((sha512 == NULL) || (hash == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        /* Finalize hash. */
        Sha512Final(sha512, hash, WC_SHA512_224_DIGEST_SIZE);
        /* Restart SHA-512 object for next hash. */
        InitSha512_224_State(sha512);
    }

    return ret;
}
void wc_Sha512_224Free(wc_Sha512* sha512)
{
    wc_Sha512Free(sha512);
}
int wc_Sha512_224GetHash(wc_Sha512* sha512, byte* hash)
{
    int ret;

    /* Validate parameters. */
    if ((sha512 == NULL) || (hash == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        wc_Sha512 tmpSha512;
        /* Create a copy of the hash to finalize. */
        ret = wc_Sha512Copy(sha512, &tmpSha512);
        if (ret == 0) {
            /* Finalize copy. */
            Sha512Final(&tmpSha512, hash, WC_SHA512_224_DIGEST_SIZE);
            wc_Sha512Free(&tmpSha512);
        }
    }

    return ret;
}
int wc_Sha512_224Copy(wc_Sha512* src, wc_Sha512* dst)
{
    return wc_Sha512Copy(src, dst);
}

#ifdef WOLFSSL_HASH_FLAGS
int wc_Sha512_224SetFlags(wc_Sha512* sha512, word32 flags)
{
    return wc_Sha512SetFlags(sha512, flags);
}
int wc_Sha512_224GetFlags(wc_Sha512* sha512, word32* flags)
{
    return wc_Sha512GetFlags(sha512, flags);
}
#endif /* WOLFSSL_HASH_FLAGS */

#if defined(OPENSSL_EXTRA)
int wc_Sha512_224Transform(wc_Sha512* sha512, const unsigned char* data)
{
    return wc_Sha512Transform(sha512, data);
}
#endif /* OPENSSL_EXTRA */

#endif /* !WOLFSSL_NOSHA512_224 */

#if !defined(WOLFSSL_NOSHA512_256)

int wc_InitSha512_256_ex(wc_Sha512* sha512, void* heap, int devId)
{
    int ret = InitSha512(sha512, heap, devId);
    if (ret == 0) {
        InitSha512_256_State(sha512);
    }
    return ret;
}
int wc_InitSha512_256(wc_Sha512* sha512)
{
    return wc_InitSha512_256_ex(sha512, NULL, INVALID_DEVID);
}
int wc_Sha512_256Update(wc_Sha512* sha512, const byte* data, word32 len)
{
    return wc_Sha512Update(sha512, data, len);
}
int wc_Sha512_256FinalRaw(wc_Sha512* sha512, byte* hash)
{
    int ret = 0;

    /* Validate parameters. */
    if ((sha512 == NULL) || (hash == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        Sha512FinalRaw(sha512, hash, WC_SHA512_256_DIGEST_SIZE);
    }

    return ret;
}
int wc_Sha512_256Final(wc_Sha512* sha512, byte* hash)
{
    int ret = 0;

    /* Validate parameters. */
    if ((sha512 == NULL) || (hash == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        /* Finalize hash. */
        Sha512Final(sha512, hash, WC_SHA512_256_DIGEST_SIZE);
        /* Restart SHA-512 object for next hash. */
        InitSha512_256_State(sha512);
    }

    return ret;
}
void wc_Sha512_256Free(wc_Sha512* sha512)
{
    wc_Sha512Free(sha512);
}
int wc_Sha512_256GetHash(wc_Sha512* sha512, byte* hash)
{
    int ret;

    /* Validate parameters. */
    if ((sha512 == NULL) || (hash == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        wc_Sha512 tmpSha512;
        /* Create a copy of the hash to finalize. */
        ret = wc_Sha512Copy(sha512, &tmpSha512);
        if (ret == 0) {
            /* Finalize copy. */
            Sha512Final(&tmpSha512, hash, WC_SHA512_256_DIGEST_SIZE);
            wc_Sha512Free(&tmpSha512);
        }
    }

    return ret;
}
int wc_Sha512_256Copy(wc_Sha512* src, wc_Sha512* dst)
{
    return wc_Sha512Copy(src, dst);
}

#ifdef WOLFSSL_HASH_FLAGS
int wc_Sha512_256SetFlags(wc_Sha512* sha512, word32 flags)
{
    return wc_Sha512SetFlags(sha512, flags);
}
int wc_Sha512_256GetFlags(wc_Sha512* sha512, word32* flags)
{
    return wc_Sha512GetFlags(sha512, flags);
}
#endif /* WOLFSSL_HASH_FLAGS */

#if defined(OPENSSL_EXTRA)
int wc_Sha512_256Transform(wc_Sha512* sha512, const unsigned char* data)
{
    return wc_Sha512Transform(sha512, data);
}
#endif /* OPENSSL_EXTRA */

#endif /* !WOLFSSL_NOSHA512_224 */

#endif /* !HAVE_FIPS && !HAVE_SELFTEST */

#endif /* !NO_SHA512 */


#ifdef WOLFSSL_SHA384

/* Initialze SHA-384 object for hashing.
 *
 * @param [in, out] sha384  SHA-384 object.
 */
static void InitSha384(wc_Sha384* sha384)
{
    /* Set initial hash values. */
#ifndef WOLFSSL_RISCV_VECTOR_CRYPTO_ASM
    sha384->digest[0] = W64LIT(0xcbbb9d5dc1059ed8);
    sha384->digest[1] = W64LIT(0x629a292a367cd507);
    sha384->digest[2] = W64LIT(0x9159015a3070dd17);
    sha384->digest[3] = W64LIT(0x152fecd8f70e5939);
    sha384->digest[4] = W64LIT(0x67332667ffc00b31);
    sha384->digest[5] = W64LIT(0x8eb44a8768581511);
    sha384->digest[6] = W64LIT(0xdb0c2e0d64f98fa7);
    sha384->digest[7] = W64LIT(0x47b5481dbefa4fa4);
#else
    /* f, e, b, a, h, g, d, c */
    sha384->digest[0] = W64LIT(0x8eb44a8768581511);
    sha384->digest[1] = W64LIT(0x67332667ffc00b31);
    sha384->digest[2] = W64LIT(0x629a292a367cd507);
    sha384->digest[3] = W64LIT(0xcbbb9d5dc1059ed8);
    sha384->digest[4] = W64LIT(0x47b5481dbefa4fa4);
    sha384->digest[5] = W64LIT(0xdb0c2e0d64f98fa7);
    sha384->digest[6] = W64LIT(0x152fecd8f70e5939);
    sha384->digest[7] = W64LIT(0x9159015a3070dd17);
#endif

    /* No hashed data. */
    sha384->buffLen = 0;
    /* No data hashed. */
    sha384->loLen   = 0;
    sha384->hiLen   = 0;
}

/* Initialize SHA-384 object for hashing.
 *
 * @param [in, out] sha384  SHA-384 object.
 * @param [in]      heap    Dynamic memory hint.
 * @param [in]      devId   Device Id.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sha384 is NULL.
 */
int wc_InitSha384_ex(wc_Sha384* sha384, void* heap, int devId)
{
    int ret = InitSha512(sha384, heap, devId);
    if (ret == 0) {
        InitSha384(sha384);
    }
    return ret;
}

/* Initialize SHA-384 object for hashing.
 *
 * @param [in, out] sha384  SHA-384 object.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sha384 is NULL.
 */
int wc_InitSha384(wc_Sha384* sha384)
{
    return wc_InitSha384_ex(sha384, NULL, INVALID_DEVID);
}

/* Update the hash with data.
 *
 * @param [in, out] sha384  SHA-384 object.
 * @param [in]      data    Buffer of data to hash.
 * @param [in]      len     Number of bytes in buffer to hash.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sha384 is NULL.
 * @return  BAD_FUNC_ARG when data is NULL but len is not 0.
 */
int wc_Sha384Update(wc_Sha384* sha384, const byte* data, word32 len)
{
    int ret;

    /* Validate parameters. */
    if ((sha384 == NULL) || ((data == NULL) && (len > 0))) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = Sha512Update((wc_Sha512 *)sha384, data, len);
    }

    return ret;
}

/* Put the current hash into buffer.
 *
 * @param [in, out] sha384   SHA-384 object.
 * @param [out]     hash     Buffer to hold hash result.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sha384 or hash is NULL.
 */
int wc_Sha384FinalRaw(wc_Sha384* sha384, byte* hash)
{
    word64 digest[WC_SHA384_DIGEST_SIZE / sizeof(word64)];

    if (sha384 == NULL || hash == NULL) {
        return BAD_FUNC_ARG;
    }

    ByteReverseWords64((word64*)digest, (word64*)sha384->digest,
        WC_SHA384_DIGEST_SIZE);
    XMEMCPY(hash, digest, WC_SHA384_DIGEST_SIZE);

    return 0;
}

/* Finalize the hash and put into buffer.
 *
 * @param [in, out] sha384  SHA-384 object.
 * @param [out]     hash    Buffer to hold hash result.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sha384 or hash is NULL.
 */
int wc_Sha384Final(wc_Sha384* sha384, byte* hash)
{
    int ret = 0;

    /* Validate parameters. */
    if ((sha384 == NULL) || (hash == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        /* Finalize hash. */
        Sha512Final((wc_Sha512*)sha384, hash, WC_SHA384_DIGEST_SIZE);
        /* Restart SHA-384 object for next hash. */
        InitSha384(sha384);
    }

    return ret;
}

/* Free the SHA-384 hash.
 *
 * @param [in] sha384  SHA-384 object.
 */
void wc_Sha384Free(wc_Sha384* sha384)
{
    /* No dynamic memory allocated. */
    (void)sha384;
}

/* Finalize the hash and put into buffer but don't modify state.
 *
 * @param [in, out] sha384  SHA-384 object.
 * @param [out]     hash    Buffer to hold hash result.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sha384 or hash is NULL.
 */
int wc_Sha384GetHash(wc_Sha384* sha384, byte* hash)
{
    int ret;

    /* Validate parameters. */
    if ((sha384 == NULL) || (hash == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        wc_Sha384 tmpSha384;
        /* Create a copy of the hash to finalize. */
        ret = wc_Sha384Copy(sha384, &tmpSha384);
        if (ret == 0) {
            /* Finalize copy. */
            ret = wc_Sha384Final(&tmpSha384, hash);
        }
    }

    return ret;
}

#ifdef WOLFSSL_HASH_FLAGS
/* Set flags of SHA-384 object.
 *
 * @param [in, out] sha384  SHA-384 object.
 * @param [in]      flags   Flags to set.
 * @return  0 on success.
 */
int wc_Sha384SetFlags(wc_Sha384* sha384, word32 flags)
{
    /* Check we have an object to use. */
    if (sha384 != NULL) {
        sha384->flags = flags;
    }
    return 0;
}
/* Get flags of SHA-384 object.
 *
 * @param [in]  sha384  SHA-384 object.
 * @param [out] flags   Flags from SHA-384 object.
 * @return  0 on success.
 */
int wc_Sha384GetFlags(wc_Sha384* sha384, word32* flags)
{
    /* Check we have an object and return parameter to use. */
    if ((sha384 != NULL) && (flags != NULL)) {
        *flags = sha384->flags;
    }
    return 0;
}
#endif

/* Deep copy the SHA-384 object.
 *
 * @param [in]  src  SHA-384 object to copy.
 * @param [out] dst  SHA-384 object to fill.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when src or dst is NULL.
 */
int wc_Sha384Copy(wc_Sha384* src, wc_Sha384* dst)
{
    int ret = 0;

    /* Validate parameters. */
    if ((src == NULL) || (dst == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        XMEMCPY(dst, src, sizeof(wc_Sha384));
    }

    return ret;
}

#endif /* WOLFSSL_SHA384 */

#endif /* !NO_SHA512 || WOLFSSL_SHA384 */
#endif /* WOLFSSL_RISCV_ASM */
