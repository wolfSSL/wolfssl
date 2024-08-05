/* riscv-sha256.c
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
#if !defined(NO_SHA256) || defined(WOLFSSL_SHA224)

#if FIPS_VERSION3_LT(6,0,0) && defined(HAVE_FIPS)
    #undef HAVE_FIPS
#else
    #if defined(HAVE_FIPS) && FIPS_VERSION3_GE(6,0,0)
    /* set NO_WRAPPERS before headers, use direct internal f()s not wrappers */
        #define FIPS_NO_WRAPPERS
    #endif
#endif

#include <wolfssl/wolfcrypt/sha256.h>
#if FIPS_VERSION3_GE(6,0,0)
    const unsigned int wolfCrypt_FIPS_sha256_ro_sanity[2] =
                                                     { 0x1a2b3c4d, 0x00000014 };
    int wolfCrypt_FIPS_SHA256_sanity(void)
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
static const FLASH_QUALIFIER ALIGN32 word32 K[64] = {
    0x428A2F98L, 0x71374491L, 0xB5C0FBCFL, 0xE9B5DBA5L, 0x3956C25BL,
    0x59F111F1L, 0x923F82A4L, 0xAB1C5ED5L, 0xD807AA98L, 0x12835B01L,
    0x243185BEL, 0x550C7DC3L, 0x72BE5D74L, 0x80DEB1FEL, 0x9BDC06A7L,
    0xC19BF174L, 0xE49B69C1L, 0xEFBE4786L, 0x0FC19DC6L, 0x240CA1CCL,
    0x2DE92C6FL, 0x4A7484AAL, 0x5CB0A9DCL, 0x76F988DAL, 0x983E5152L,
    0xA831C66DL, 0xB00327C8L, 0xBF597FC7L, 0xC6E00BF3L, 0xD5A79147L,
    0x06CA6351L, 0x14292967L, 0x27B70A85L, 0x2E1B2138L, 0x4D2C6DFCL,
    0x53380D13L, 0x650A7354L, 0x766A0ABBL, 0x81C2C92EL, 0x92722C85L,
    0xA2BFE8A1L, 0xA81A664BL, 0xC24B8B70L, 0xC76C51A3L, 0xD192E819L,
    0xD6990624L, 0xF40E3585L, 0x106AA070L, 0x19A4C116L, 0x1E376C08L,
    0x2748774CL, 0x34B0BCB5L, 0x391C0CB3L, 0x4ED8AA4AL, 0x5B9CCA4FL,
    0x682E6FF3L, 0x748F82EEL, 0x78A5636FL, 0x84C87814L, 0x8CC70208L,
    0x90BEFFFAL, 0xA4506CEBL, 0xBEF9A3F7L, 0xC67178F2L
};

/* Initialze SHA-256 object for hashing.
 *
 * @param [in, out] sha256  SHA-256 object.
 */
static void InitSha256(wc_Sha256* sha256)
{
    /* Set initial hash values. */
#ifndef WOLFSSL_RISCV_VECTOR_CRYPTO_ASM
    sha256->digest[0] = 0x6A09E667L;
    sha256->digest[1] = 0xBB67AE85L;
    sha256->digest[2] = 0x3C6EF372L;
    sha256->digest[3] = 0xA54FF53AL;
    sha256->digest[4] = 0x510E527FL;
    sha256->digest[5] = 0x9B05688CL;
    sha256->digest[6] = 0x1F83D9ABL;
    sha256->digest[7] = 0x5BE0CD19L;
#else
    /* f, e, b, a, h, g, d, c */
    sha256->digest[0] = 0x9B05688CL;
    sha256->digest[1] = 0x510E527FL;
    sha256->digest[2] = 0xBB67AE85L;
    sha256->digest[3] = 0x6A09E667L;
    sha256->digest[4] = 0x5BE0CD19L;
    sha256->digest[5] = 0x1F83D9ABL;
    sha256->digest[6] = 0xA54FF53AL;
    sha256->digest[7] = 0x3C6EF372L;
#endif

    /* No hashed data. */
    sha256->buffLen = 0;
    /* No data hashed. */
    sha256->loLen   = 0;
    sha256->hiLen   = 0;

#ifdef WOLFSSL_HASH_FLAGS
    sha256->flags = 0;
#endif
}

/* More data hashed, add length to 64-bit cumulative total.
 *
 * @param [in, out] sha256  SHA-256 object. Assumed not NULL.
 * @param [in]      len     Length to add.
 */
static WC_INLINE void AddLength(wc_Sha256* sha256, word32 len)
{
    word32 tmp = sha256->loLen;
    if ((sha256->loLen += len) < tmp)
        sha256->hiLen++;                       /* carry low to high */
}

#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION

/* Load a word with bytes reversed. */
#define LOAD_WORD_REV(r, o, p, t0, t1, t2)  \
    "lbu    " #t0 ", " #o "(" #p ")\n\t"    \
    "lbu    " #t1 ", " #o "+1(" #p ")\n\t"  \
    "lbu    " #t2 ", " #o "+2(" #p ")\n\t"  \
    "lbu    " #r ", " #o "+3(" #p ")\n\t"   \
    "slli   " #t0 ", " #t0 ", 24\n\t"       \
    "slli   " #t1 ", " #t1 ", 16\n\t"       \
    "slli   " #t2 ", " #t2 ", 8\n\t"        \
    "or     " #r ", " #r ", " #t0 "\n\t"    \
    "or     " #r ", " #r ", " #t1 "\n\t"    \
    "or     " #r ", " #r ", " #t2 "\n\t"

/* Load a word with bytes reversed. */
#define LOAD_DWORD_REV(r, o, p, t0, t1, t2, t3) \
    "lbu    " #t0 ", " #o "(" #p ")\n\t"        \
    "lbu    " #t1 ", " #o "+1(" #p ")\n\t"      \
    "lbu    " #t2 ", " #o "+2(" #p ")\n\t"      \
    "lbu    " #r ", " #o "+3(" #p ")\n\t"       \
    "slli   " #t0 ", " #t0 ", 24\n\t"           \
    "slli   " #t1 ", " #t1 ", 16\n\t"           \
    "slli   " #t2 ", " #t2 ", 8\n\t"            \
    "or     " #r ", " #r ", " #t0 "\n\t"        \
    "or     " #r ", " #r ", " #t1 "\n\t"        \
    "or     " #r ", " #r ", " #t2 "\n\t"        \
    "lbu    " #t0 ", " #o "+4(" #p ")\n\t"      \
    "lbu    " #t1 ", " #o "+5(" #p ")\n\t"      \
    "lbu    " #t2 ", " #o "+6(" #p ")\n\t"      \
    "lbu    " #t3 ", " #o "+7(" #p ")\n\t"      \
    "slli   " #t0 ", " #t0 ", 56\n\t"           \
    "slli   " #t1 ", " #t1 ", 48\n\t"           \
    "slli   " #t2 ", " #t2 ", 40\n\t"           \
    "slli   " #t3 ", " #t3 ", 32\n\t"           \
    "or     " #r ", " #r ", " #t0 "\n\t"        \
    "or     " #r ", " #r ", " #t1 "\n\t"        \
    "or     " #r ", " #r ", " #t2 "\n\t"        \
    "or     " #r ", " #r ", " #t3 "\n\t"

#define PACK_BB(rd, rs1, rs2, rrd, rrs1, rrs2)  \
    "slli   " #rd ", " #rs1 ", 32\n\t"          \
    "slli   " #rs2 ", " #rs2 ", 32\n\t"         \
    "srli   " #rd ", " #rs1 ", 32\n\t"          \
    "or     " #rd ", " #rd ", " #rs2 "\n\t"

#else

#define PACK_BB(rd, rs1, rs2, rrd, rrs1, rrs2)  \
    PACK(rrd, rrs1, rrs2)

#endif

#ifndef WOLFSSL_RISCV_VECTOR_CRYPTO_ASM

#ifdef WOLFSSL_RISCV_SCALAR_CRYPTO_ASM

/* SHA-256 SUM0 operation. */
#define SHA256SUM0(rd, rs1)                                         \
    ASM_WORD((0b000100000000 << 20) | (0b001 << 12) | 0b0010011 |   \
             (rs1 << 15) | (rd << 7))
/* SHA-256 SUM1 operation. */
#define SHA256SUM1(rd, rs1)                                         \
    ASM_WORD((0b000100000001 << 20) | (0b001 << 12) | 0b0010011 |   \
             (rs1 << 15) | (rd << 7))
/* SHA-256 SIGMA0 operation. */
#define SHA256SIG0(rd, rs1)                                         \
    ASM_WORD((0b000100000010 << 20) | (0b001 << 12) | 0b0010011 |   \
             (rs1 << 15) | (rd << 7))
/* SHA-256 SIGMA1 operation. */
#define SHA256SIG1(rd, rs1)                                         \
    ASM_WORD((0b000100000011 << 20) | (0b001 << 12) | 0b0010011 |   \
             (rs1 << 15) | (rd << 7))

/* One round of compression. */
#define RND(a, b, c, d, e, f, g, h, w, k)                       \
    /* Get e and a */                                           \
    "mv     a4, " #e "\n\t"                                     \
    "mv     a5, " #a "\n\t"                                     \
    /* Sigma1(e) */                                             \
    SHA256SUM1(REG_A4, REG_A4)                                  \
    /* Sigma0(a) */                                             \
    SHA256SUM0(REG_A5, REG_A5)                                  \
    /* Maj(a, b, c) = t5 */                                     \
    /* Ch(e, f, g) = t6 */                                      \
    /* f ^ g */                                                 \
    "xor    t6, " #f ", " #g "\n\t"                             \
    /* a ^ b */                                                 \
    "xor    t4, " #a ", " #b "\n\t"                             \
    /* b ^ c */                                                 \
    "xor    t5, " #b ", " #c "\n\t"                             \
    /* (f ^ g) & e */                                           \
    "and    t6, t6, " #e "\n\t"                                 \
    /* h + sigma1 */                                            \
    "addw   " #h ", " #h ", a4\n\t"                             \
    /* (a^b) & (b^c) */                                         \
    "and    t5, t5, t4\n\t"                                     \
    /* ((f ^ g) & e) ^ g */                                     \
    "xor    t6, t6, " #g "\n\t"                                 \
    /* K + W */                                                 \
    "addw   t4, " #k ", " #w "\n\t"                             \
    /* ((a^b) & (b^c)) ^ b */                                   \
    "xor    t5, t5, " #b "\n\t"                                 \
    /* h + sigma1 + Ch */                                       \
    "addw   " #h ", " #h ", t6\n\t"                             \
    /* 't0' = h + sigma1 + Ch + K + W */                        \
    "addw   " #h ", " #h ", t4\n\t"                             \
    /* Sigma0(a) + Maj = 't1' */                                \
    "addw   t5, a5, t5\n\t"                                     \
    /* d += 't0' */                                             \
    "addw   " #d ", " #d ", " #h "\n\t"                         \
    /* 't0' += 't1' */                                          \
    "addw   " #h ", " #h ", t5\n\t"

/* Two message schedule updates. */
#define W_UPDATE_2(w0, w1, w4, w5, w7, reg_w0, reg_w1, reg_w7)  \
    /* W[i-15] = W[1] */                                        \
    "srli   t4, " #w0 ", 32\n\t"                                \
    /* W[i-7] = W[9] */                                         \
    "srli   t6, " #w4 ", 32\n\t"                                \
    /* Gamma0(W[1]) */                                          \
    SHA256SIG0(REG_A4, REG_T4)                                  \
    /* Gamma1(W[i-2]) = Gamma1(W[14]) */                        \
    SHA256SIG1(REG_A5, reg_w7)                                  \
    /* Gamma1(W[14]) + W[9] */                                  \
    "addw   a5, a5, t6\n\t"                                     \
    /* Gamma0(W[1]) + W[i-16] = Gamma0(W[1]) + W[0] */          \
    "addw   " #w0 ", " #w0 ", a4\n\t"                           \
    /* W[i+1-2] = W[15] */                                      \
    "srli   t5, " #w7 ", 32\n\t"                                \
    /* W[0] = Gamma1(W[14]) + W[9] + Gamma0(W[1]) + W[0] */     \
    "addw   " #w0 ", a5, " #w0 "\n\t"                           \
                                                                \
    /* W[i+1-16] = W[1] = t4 */                                 \
    /* Gamma0(W[i+1-15]) = Gamma0(W[2]) */                      \
    SHA256SIG0(REG_A6, reg_w1)                                  \
    /* Gamma1(W[i+1-2]) = Gamma1(W[15]) */                      \
    SHA256SIG1(REG_A7, REG_T5)                                  \
    /* Gamma1(W[15]) + W[i+1-7] = Gamma1(W[15]) + W[10] */      \
    "addw   a7, a7, " #w5 "\n\t"                                \
    /* Gamma0(W[2]) + W[i+1-16] = Gamma0(W[2]) + W[1] */        \
    "addw   t5, a6, t4\n\t"                                     \
    /* Gamma1(W[i-2]) + W[i-7] + Gamma0(W[i-15]) + W[i-16] */   \
    "addw   a7, a7, t5\n\t"                                     \
    /* Place in W[i+1-16] = W[1] */                             \
    PACK_BB(w0, w0, a7, reg_w0, reg_w0, REG_A7)

#else

/* SHA-256 SIGMA1 operation. */
#define SHA256SIG1(rd, rs1)                                     \
    "slliw  t6, " #rs1 ", 15\n\t"                               \
    "srliw  t5, " #rs1 ", 17\n\t"                               \
    "slliw  t4, " #rs1 ", 13\n\t"                               \
    "srliw  " #rd ", " #rs1 ", 19\n\t"                          \
    "or     t6, t6, t5\n\t"                                     \
    "srliw  t5, " #rs1 ", 10\n\t"                               \
    "xor    " #rd ", "#rd ", t4\n\t"                            \
    "xor    t6, t6, t5\n\t"                                     \
    "xor    " #rd ", " #rd ", t6\n\t"                           \

/* One round of compression. */
#define RND(a, b, c, d, e, f, g, h, w, k)                       \
    /* a4 = Sigma1(e) */                                        \
    "slliw  t5, " #e ", 26\n\t"                                 \
    "srliw  t4, " #e ", 6\n\t"                                  \
    "slliw  t6, " #e ", 21\n\t"                                 \
    "srliw  a4, " #e ", 11\n\t"                                 \
    "slliw  a5, " #e ", 7\n\t"                                  \
    "or     t4, t4, t5\n\t"                                     \
    "xor    a4, a4, t6\n\t"                                     \
    "srliw  t5, " #e ", 25\n\t"                                 \
    "xor    t4, t4, a5\n\t"                                     \
    "xor    a4, a4, t5\n\t"                                     \
    /* a5 = Sigma0(a) */                                        \
    "slliw  t5, " #a ", 30\n\t"                                 \
    "xor    a4, a4, t4\n\t"                                     \
    "srliw  t4, " #a ", 2\n\t"                                  \
    "slliw  t6, " #a ", 19\n\t"                                 \
    /* h + sigma1 */                                            \
    "addw   " #h ", " #h ", a4\n\t"                             \
    "srliw  a5, " #a ", 13\n\t"                                 \
    "slliw  a4, " #a ", 10\n\t"                                 \
    "or     t4, t4, t5\n\t"                                     \
    "xor    a5, a5, t6\n\t"                                     \
    "srliw  t6, " #a ", 22\n\t"                                 \
    "xor    t4, t4, a4\n\t"                                     \
    "xor    a5, a5, t6\n\t"                                     \
    /* Maj(a, b, c) = t5 */                                     \
    /* Ch(e, f, g) = t6 */                                      \
    /* f ^ g */                                                 \
    "xor    t6, " #f ", " #g "\n\t"                             \
    /* a ^ b */                                                 \
    "xor    t5, " #a ", " #b "\n\t"                             \
    /* b ^ c */                                                 \
    "xor    a4, " #b ", " #c "\n\t"                             \
    "xor    a5, a5, t4\n\t"                                     \
    /* (f ^ g) & e */                                           \
    "and    t6, t6, " #e "\n\t"                                 \
    /* (a^b) & (b^c) */                                         \
    "and    t5, t5, a4\n\t"                                     \
    /* ((f ^ g) & e) ^ g */                                     \
    "xor    t6, t6, " #g "\n\t"                                 \
    /* K + W */                                                 \
    "addw   a4, " #k ", " #w "\n\t"                             \
    /* h + sigma1 + Ch */                                       \
    "addw   " #h ", " #h ", t6\n\t"                             \
    /* ((a^b) & (b^c)) ^ b */                                   \
    "xor    t5, t5, " #b "\n\t"                                 \
    /* 't0' = h + sigma1 + Ch + K + W */                        \
    "addw   " #h ", " #h ", a4\n\t"                             \
    /* 't1' = Sigma0(a) + Maj */                                \
    "addw   t5, a5, t5\n\t"                                     \
    /* d += 't0' */                                             \
    "addw   " #d ", " #d ", " #h "\n\t"                         \
    /* h = 't0' + 't1' */                                       \
    "addw   " #h ", " #h ", t5\n\t"

/* Two message schedule updates. */
#define W_UPDATE_2(w0, w1, w4, w5, w7, reg_w0, reg_w1, reg_w7)  \
    /* W[i-15] = W[1] */                                        \
    "srli   a7, " #w0 ", 32\n\t"                                \
    /* W[i-7] = W[9] */                                         \
    "srli   a6, " #w4 ", 32\n\t"                                \
    /* Gamma0(W[1]) */                                          \
    "slliw  t4, a7, 25\n\t"                                     \
    "srliw  t5, a7, 7\n\t"                                      \
    "slliw  t6, a7, 14\n\t"                                     \
    "srliw  a4, a7, 18\n\t"                                     \
    "or     t4, t4, t5\n\t"                                     \
    "srliw  t5, a7, 3\n\t"                                      \
    "xor    a4, a4, t6\n\t"                                     \
    "xor    t4, t4, t5\n\t"                                     \
    /* Gamma1(W[i-2]) = Gamma1(W[14]) */                        \
    "slliw  t6, " #w7 ", 15\n\t"                                \
    "srliw  t5, " #w7 ", 17\n\t"                                \
    "xor    a4, a4, t4\n\t"                                     \
    "slliw  t4, " #w7 ", 13\n\t"                                \
    "srliw  a5, " #w7 ", 19\n\t"                                \
    "or     t6, t6, t5\n\t"                                     \
    "srliw  t5, " #w7 ", 10\n\t"                                \
    "xor    a5, a5, t4\n\t"                                     \
    "xor    t6, t6, t5\n\t"                                     \
    "xor    a5, a5, t6\n\t"                                     \
    /* Gamma0(W[1]) + W[i-16] = Gamma0(W[1]) + W[0] */          \
    "addw   " #w0 ", " #w0 ", a4\n\t"                           \
    /* Gamma1(W[14]) + W[9] */                                  \
    "addw   a5, a5, a6\n\t"                                     \
    /* W[0] = Gamma1(W[14]) + W[9] + Gamma0(W[1]) + W[0] */     \
    "addw   " #w0 ", a5, " #w0 "\n\t"                           \
                                                                \
    /* W[i+1-16] = W[1] = a7 */                                 \
    /* W[i+1-2] = W[15] */                                      \
    "srli   a4, " #w7 ", 32\n\t"                                \
    /* Gamma0(W[i+1-15]) = Gamma0(W[2]) */                      \
    "slliw  t4, " #w1 ", 25\n\t"                                \
    "srliw  t5, " #w1 ", 7\n\t"                                 \
    "slliw  t6, " #w1 ", 14\n\t"                                \
    "srliw  a6, " #w1 ", 18\n\t"                                \
    "or     t4, t4, t5\n\t"                                     \
    "srliw  t5, " #w1 ", 3\n\t"                                 \
    "xor    a6, a6, t6\n\t"                                     \
    "xor    t4, t4, t5\n\t"                                     \
    /* Gamma1(W[i+1-2]) = Gamma1(W[15]) */                      \
    "slliw  t6, a4, 15\n\t"                                     \
    "srliw  t5, a4, 17\n\t"                                     \
    "xor    a6, a6, t4\n\t"                                     \
    "slliw  t4, a4, 13\n\t"                                     \
    "srliw  a5, a4, 19\n\t"                                     \
    "or     t6, t6, t5\n\t"                                     \
    "srliw  t5, a4, 10\n\t"                                     \
    "xor    a5, a5, t4\n\t"                                     \
    "xor    t6, t6, t5\n\t"                                     \
    "xor    a5, a5, t6\n\t"                                     \
    /* Gamma0(W[2]) + W[i+1-16] = Gamma0(W[2]) + W[1] */        \
    "addw   t5, a6, a7\n\t"                                     \
    /* Gamma1(W[15]) + W[i+1-7] = Gamma1(W[15]) + W[10] */      \
    "addw   a5, a5, " #w5 "\n\t"                                \
    /* Gamma1(W[i-2]) + W[i-7] + Gamma0(W[i-15]) + W[i-16] */   \
    "addw   a5, a5, t5\n\t"                                     \
    /* Place in W[i+1-16] = W[1] */                             \
    PACK_BB(w0, w0, a5, reg_w0, reg_w0, REG_A5)

#endif /* WOLFSSL_RISCV_SCALAR_CRYPTO_ASM */

/* Two rounds of compression. */
#define RND2(a, b, c, d, e, f, g, h, w, o)  \
    /* Get k[i], k[i+1] */                  \
    "ld     a6, " #o "(%[k])\n\t"           \
    RND(a, b, c, d, e, f, g, h, w, a6)      \
    /* Move  k[i+1] down */                 \
    "srli   a6, a6, 32\n\t"                 \
    /* Move  W[i] down */                   \
    "srli   a7, " #w ", 32\n\t"             \
    RND(h, a, b, c, d, e, f, g, a7, a6)

/* Sixteen rounds of compression with message scheduling. */
#define RND16()                                             \
    RND2(t0, t1, t2, t3, s8, s9, s10, s11, s0,  0)          \
    W_UPDATE_2(s0, s1, s4, s5, s7, REG_S0, REG_S1, REG_S7)  \
    RND2(s10, s11, t0, t1, t2, t3, s8, s9, s1,  8)          \
    W_UPDATE_2(s1, s2, s5, s6, s0, REG_S1, REG_S2, REG_S0)  \
    RND2(s8, s9, s10, s11, t0, t1, t2, t3, s2, 16)          \
    W_UPDATE_2(s2, s3, s6, s7, s1, REG_S2, REG_S3, REG_S1)  \
    RND2(t2, t3, s8, s9, s10, s11, t0, t1, s3, 24)          \
    W_UPDATE_2(s3, s4, s7, s0, s2, REG_S3, REG_S4, REG_S2)  \
    RND2(t0, t1, t2, t3, s8, s9, s10, s11, s4, 32)          \
    W_UPDATE_2(s4, s5, s0, s1, s3, REG_S4, REG_S5, REG_S3)  \
    RND2(s10, s11, t0, t1, t2, t3, s8, s9, s5, 40)          \
    W_UPDATE_2(s5, s6, s1, s2, s4, REG_S5, REG_S6, REG_S4)  \
    RND2(s8, s9, s10, s11, t0, t1, t2, t3, s6, 48)          \
    W_UPDATE_2(s6, s7, s2, s3, s5, REG_S6, REG_S7, REG_S5)  \
    RND2(t2, t3, s8, s9, s10, s11, t0, t1, s7, 56)          \
    W_UPDATE_2(s7, s0, s3, s4, s6, REG_S7, REG_S0, REG_S6)

/* Sixteen rounds of compression only. */
#define RND16_LAST()                                \
    RND2(t0, t1, t2, t3, s8, s9, s10, s11, s0,  0)  \
    RND2(s10, s11, t0, t1, t2, t3, s8, s9, s1,  8)  \
    RND2(s8, s9, s10, s11, t0, t1, t2, t3, s2, 16)  \
    RND2(t2, t3, s8, s9, s10, s11, t0, t1, s3, 24)  \
    RND2(t0, t1, t2, t3, s8, s9, s10, s11, s4, 32)  \
    RND2(s10, s11, t0, t1, t2, t3, s8, s9, s5, 40)  \
    RND2(s8, s9, s10, s11, t0, t1, t2, t3, s6, 48)  \
    RND2(t2, t3, s8, s9, s10, s11, t0, t1, s7, 56)

/* Transform the message data.
 *
 * @param [in, out] sha256  SHA-256 object.
 * @param [in]      data    Buffer of data to hash.
 * @param [in]      blocks  Number of blocks of data to hash.
 */
static WC_INLINE void Sha256Transform(wc_Sha256* sha256, const byte* data,
    word32 blocks)
{
    word32* k = (word32*)K;

    __asm__ __volatile__ (
        /* Load digest. */
        "ld     t0, 0(%[digest])\n\t"
        "ld     t2, 8(%[digest])\n\t"
        "ld     s8, 16(%[digest])\n\t"
        "ld     s10, 24(%[digest])\n\t"
        "srli   t1, t0, 32\n\t"
        "srli   t3, t2, 32\n\t"
        "srli   s9, s8, 32\n\t"
        "srli   s11, s10, 32\n\t"

        /* 4 rounds of 16 per block. */
        "slli   %[blocks], %[blocks], 2\n\t"

    "\n1:\n\t"
        /* beginning of SHA256 block operation */
        /* Load W */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        LOAD_DWORD_REV(s0,  0, %[data], a4, a5, a6, a7)
        LOAD_DWORD_REV(s1,  8, %[data], a4, a5, a6, a7)
        LOAD_DWORD_REV(s2, 16, %[data], a4, a5, a6, a7)
        LOAD_DWORD_REV(s3, 24, %[data], a4, a5, a6, a7)
        LOAD_DWORD_REV(s4, 32, %[data], a4, a5, a6, a7)
        LOAD_DWORD_REV(s5, 40, %[data], a4, a5, a6, a7)
        LOAD_DWORD_REV(s6, 48, %[data], a4, a5, a6, a7)
        LOAD_DWORD_REV(s7, 56, %[data], a4, a5, a6, a7)
#else
        "lwu    a4, 0(%[data])\n\t"
        "lwu    s0, 4(%[data])\n\t"
        "lwu    a5, 8(%[data])\n\t"
        "lwu    s1, 12(%[data])\n\t"
        "lwu    a6, 16(%[data])\n\t"
        "lwu    s2, 20(%[data])\n\t"
        "lwu    a7, 24(%[data])\n\t"
        "lwu    s3, 28(%[data])\n\t"
        PACK_BB(s0, s0, a4, REG_S0, REG_S0, REG_A4)
        PACK_BB(s1, s1, a5, REG_S1, REG_S1, REG_A5)
        PACK_BB(s2, s2, a6, REG_S2, REG_S2, REG_A6)
        PACK_BB(s3, s3, a7, REG_S3, REG_S3, REG_A7)
        REV8(REG_S0, REG_S0)
        REV8(REG_S1, REG_S1)
        REV8(REG_S2, REG_S2)
        REV8(REG_S3, REG_S3)
        "lwu    a4, 32(%[data])\n\t"
        "lwu    s4, 36(%[data])\n\t"
        "lwu    a5, 40(%[data])\n\t"
        "lwu    s5, 44(%[data])\n\t"
        "lwu    a6, 48(%[data])\n\t"
        "lwu    s6, 52(%[data])\n\t"
        "lwu    a7, 56(%[data])\n\t"
        "lwu    s7, 60(%[data])\n\t"
        PACK_BB(s4, s4, a4, REG_S4, REG_S4, REG_A4)
        PACK_BB(s5, s5, a5, REG_S5, REG_S5, REG_A5)
        PACK_BB(s6, s6, a6, REG_S6, REG_S6, REG_A6)
        PACK_BB(s7, s7, a7, REG_S7, REG_S7, REG_A7)
        REV8(REG_S4, REG_S4)
        REV8(REG_S5, REG_S5)
        REV8(REG_S6, REG_S6)
        REV8(REG_S7, REG_S7)
#endif

        /* Subtract one as there are only 3 loops. */
        "addi   %[blocks], %[blocks], -1\n\t"
    "\n2:\n\t"
        RND16()
        "addi   %[blocks], %[blocks], -1\n\t"
        "add    %[k], %[k], 64\n\t"
        "andi   a4, %[blocks], 3\n\t"
        "bnez   a4, 2b \n\t"
        RND16_LAST()
        "addi   %[k], %[k], -192\n\t"

        "# Add working vars back into digest state.\n\t"
        "ld     a4, 0(%[digest])\n\t"
        "ld     a5, 8(%[digest])\n\t"
        "ld     a6, 16(%[digest])\n\t"
        "ld     a7, 24(%[digest])\n\t"
        "addw   t0, t0, a4\n\t"
        "addw   t2, t2, a5\n\t"
        "addw   s8, s8, a6\n\t"
        "addw   s10, s10, a7\n\t"
        "srli   a4, a4, 32\n\t"
        "srli   a5, a5, 32\n\t"
        "srli   a6, a6, 32\n\t"
        "srli   a7, a7, 32\n\t"
        "addw   t1, t1, a4\n\t"
        "addw   t3, t3, a5\n\t"
        "addw   s9, s9, a6\n\t"
        "addw   s11, s11, a7\n\t"

        /* Store digest. */
        "sw     t0, 0(%[digest])\n\t"
        "sw     t1, 4(%[digest])\n\t"
        "sw     t2, 8(%[digest])\n\t"
        "sw     t3, 12(%[digest])\n\t"
        "sw     s8, 16(%[digest])\n\t"
        "sw     s9, 20(%[digest])\n\t"
        "sw     s10, 24(%[digest])\n\t"
        "sw     s11, 28(%[digest])\n\t"

        "add    %[data], %[data], 64\n\t"
        "bnez   %[blocks], 1b \n\t"

        : [blocks] "+r" (blocks), [data] "+r" (data), [k] "+r" (k)
        : [digest] "r" (sha256->digest)
        : "cc", "memory", "t0", "t1", "t2", "t3", "t4", "t5", "t6",
          "a4", "a5", "a6", "a7",
          "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10",
          "s11"
    );
}

#else

/* Two rounds of compression using low two 32-bit W values.
 * Assumes K has been added into W values.
 */
#define VSHA2CL_VV(vd, vs1, vs2)                    \
    ASM_WORD((0b101111 << 26) | (0b1 << 25) |       \
             (0b010 << 12) | (0b1110111 << 0) |     \
             (vd << 7) | (vs1 << 15) | (vs2 << 20))

/* Two rounds of compression using upper two 32-bit W values.
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

#define RND4(w0, w1, w2, w3, k)                     \
    /* Four rounds of compression. */               \
    VADD_VV(REG_V7, w0, k)                          \
    VMV_X_S(REG_T1, w1)                             \
    VSHA2CL_VV(REG_V5, REG_V7, REG_V4)              \
    VMV_V_V(REG_V6, w2)                             \
    VSHA2CH_VV(REG_V4, REG_V7, REG_V5)              \
    /* Update 4 W values - message schedule. */     \
    VMV_S_X(REG_V6, REG_T1)                         \
    VSHA2MS_VV(w0, w3, REG_V6)

#define RND4_LAST(w, k)                             \
    /* Four rounds of compression. */               \
    VADD_VV(REG_V7, w, k)                           \
    VSHA2CL_VV(REG_V5, REG_V7, REG_V4)              \
    VSHA2CH_VV(REG_V4, REG_V7, REG_V5)

#define RND16(k)                                    \
    RND4(REG_V0, REG_V1, REG_V2, REG_V3, (k + 0))   \
    RND4(REG_V1, REG_V2, REG_V3, REG_V0, (k + 1))   \
    RND4(REG_V2, REG_V3, REG_V0, REG_V1, (k + 2))   \
    RND4(REG_V3, REG_V0, REG_V1, REG_V2, (k + 3))

#define RND16_LAST(k)           \
    RND4_LAST(REG_V0, (k + 0))  \
    RND4_LAST(REG_V1, (k + 1))  \
    RND4_LAST(REG_V2, (k + 2))  \
    RND4_LAST(REG_V3, (k + 3))

/* Transform the message data.
 *
 * @param [in, out] sha256  SHA-256 object.
 * @param [in]      data    Buffer of data to hash.
 * @param [in]      blocks  Number of blocks of data to hash.
 */
static void Sha256Transform(wc_Sha256* sha256, const byte* data,
    word32 blocks)
{
    word32* k = (word32*)K;

    __asm__ __volatile__ (
        VSETIVLI(REG_ZERO, 4, 1, 1, 0b010, 0b000)

        /* Load: a|b|e|f, c|d|g|h
         *       3 2 1 0  3 2 1 0
         */
        "mv     t0, %[digest]\n\t"
        VL2RE32_V(REG_V4, REG_T0)

        "mv     t0, %[k]\n\t"
        VL8RE32_V(REG_V8, REG_T0)
        "addi   t0, %[k], 128\n\t"
        VL8RE32_V(REG_V16, REG_T0)

    "\n1:\n\t"
        VMV_V_V(REG_V30, REG_V4)
        VMV_V_V(REG_V31, REG_V5)

        /* Load 16 W into 4 vectors of 4 32-bit words. */
        "mv     t0, %[data]\n\t"
        VL4RE32_V(REG_V0, REG_T0)
        VREV8(REG_V0, REG_V0)
        VREV8(REG_V1, REG_V1)
        VREV8(REG_V2, REG_V2)
        VREV8(REG_V3, REG_V3)

        RND16(REG_V8)
        RND16(REG_V12)
        RND16(REG_V16)
        RND16_LAST(REG_V20)

        VADD_VV(REG_V4, REG_V4, REG_V30)
        VADD_VV(REG_V5, REG_V5, REG_V31)

        "addi   %[blocks], %[blocks], -1\n\t"
        "add    %[data], %[data], 64\n\t"
        "bnez   %[blocks], 1b \n\t"

        "mv     t0, %[digest]\n\t"
        VS2R_V(REG_V4, REG_T0)

        : [blocks] "+r" (blocks), [data] "+r" (data), [k] "+r" (k)
        : [digest] "r" (sha256->digest)
        : "cc", "memory", "t0", "t1"
    );
}

#endif /* WOLFSSL_RISCV_VECTOR_CRYPTO_ASM */

/* Update the hash with data.
 *
 * @param [in, out] sha256  SHA-256 object.
 * @param [in]      data    Buffer of data to hash.
 * @param [in]      len     Number of bytes in buffer to hash.
 * @return  0 on success.
 */
static WC_INLINE int Sha256Update(wc_Sha256* sha256, const byte* data,
    word32 len)
{
    word32 add;
    word32 blocks;

    /* only perform actions if a buffer is passed in */
    if (len > 0) {
        AddLength(sha256, len);

        if (sha256->buffLen > 0) {
             /* fill leftover buffer with data */
             add = min(len, WC_SHA256_BLOCK_SIZE - sha256->buffLen);
             XMEMCPY((byte*)(sha256->buffer) + sha256->buffLen, data, add);
             sha256->buffLen += add;
             data            += add;
             len             -= add;
             if (sha256->buffLen == WC_SHA256_BLOCK_SIZE) {
                 Sha256Transform(sha256, (byte*)sha256->buffer, 1);
                 sha256->buffLen = 0;
             }
        }

        /* number of blocks in a row to complete */
        blocks = len / WC_SHA256_BLOCK_SIZE;

        if (blocks > 0) {
            Sha256Transform(sha256, data, blocks);
            data += blocks * WC_SHA256_BLOCK_SIZE;
            len  -= blocks * WC_SHA256_BLOCK_SIZE;
        }

        if (len > 0) {
            /* copy over any remaining data leftover */
            XMEMCPY(sha256->buffer, data, len);
            sha256->buffLen = len;
        }
    }

    /* account for possibility of not used if len = 0 */
    (void)add;
    (void)blocks;

    return 0;
}

/* Finalize the hash and put into buffer.
 *
 * @param [in, out] sha256  SHA-256 object.
 * @param [out]     hash    Buffer to hold hash result.
 */
static WC_INLINE void Sha256Final(wc_Sha256* sha256, byte* hash)
{
    byte* local;

    local = (byte*)sha256->buffer;
    local[sha256->buffLen++] = 0x80;     /* add 1 */

    /* pad with zeros */
    if (sha256->buffLen > WC_SHA256_PAD_SIZE) {
        XMEMSET(&local[sha256->buffLen], 0,
            WC_SHA256_BLOCK_SIZE - sha256->buffLen);
        Sha256Transform(sha256, (byte*)sha256->buffer, 1);
        sha256->buffLen = 0;
    }
    XMEMSET(&local[sha256->buffLen], 0, WC_SHA256_PAD_SIZE - sha256->buffLen);

    /* put lengths in bits */
    sha256->hiLen = (sha256->loLen >> (8*sizeof(sha256->loLen) - 3)) +
        (sha256->hiLen << 3);
    sha256->loLen = sha256->loLen << 3;

    XMEMCPY(&local[WC_SHA256_PAD_SIZE], &sha256->hiLen, sizeof(word32));
    XMEMCPY(&local[WC_SHA256_PAD_SIZE + sizeof(word32)], &sha256->loLen,
        sizeof(word32));

    /* store lengths */
    __asm__ __volatile__ (
        /* Reverse byte order of 32-bit words. */
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "ld     t1, 56(%[buff])\n\t"
        REV8(REG_T1, REG_T1)
        "srli   t0, t1, 32\n\t"
        "sw     t0, 56(%[buff])\n\t"
        "sw     t1, 60(%[buff])\n\t"
#else
        LOAD_WORD_REV(t0, 56, %[buff], t2, t3, t4)
        LOAD_WORD_REV(t1, 60, %[buff], t2, t3, t4)
        "sw     t0, 56(%[buff])\n\t"
        "sw     t1, 60(%[buff])\n\t"
#endif
        :
        : [buff] "r" (sha256->buffer)
        : "cc", "memory", "t0", "t1", "t2", "t3", "t4"
    );

    Sha256Transform(sha256, (byte*)sha256->buffer, 1);

    __asm__ __volatile__ (
        /* Reverse byte order of 32-bit words. */
#if defined(WOLFSSL_RISCV_VECTOR_CRYPTO_ASM)
        VSETIVLI(REG_ZERO, 4, 1, 1, 0b010, 0b000)
        "mv     t0, %[digest]\n\t"
        VL2RE32_V(REG_V8, REG_T0)
        VREV8(REG_V8, REG_V8)
        VREV8(REG_V9, REG_V9)
        /* a|b|e|f, c|d|g|h
         * 3 2 1 0  3 2 1 0 */
        VSLIDEDOWN_VI(REG_V0, REG_V8, 3) /* a */
        VSLIDEDOWN_VI(REG_V2, REG_V8, 2) /* b */
        VSLIDEDOWN_VI(REG_V1, REG_V8, 1) /* e */
        VSLIDEDOWN_VI(REG_V3, REG_V9, 3) /* c */
        VSLIDEDOWN_VI(REG_V4, REG_V9, 2) /* d */
        VSLIDEDOWN_VI(REG_V5, REG_V9, 1) /* g */
        /* -|-|-|a, -|-|-|e */
        VSLIDEUP_VI(REG_V0, REG_V2, 1)
        /* -|-|b|a, -|-|-|e */
        VSLIDEUP_VI(REG_V0, REG_V3, 2)
        /* -|c|b|a, -|-|-|e */
        VSLIDEUP_VI(REG_V0, REG_V4, 3)
        /* d|c|b|a, -|-|-|e */
        VSLIDEUP_VI(REG_V1, REG_V8, 1)
        /* d|c|b|a, -|-|f|e */
        VSLIDEUP_VI(REG_V1, REG_V5, 2)
        /* d|c|b|a, -|g|f|e */
        VSLIDEUP_VI(REG_V1, REG_V9, 3)
        /* d|c|b|a, h|g|f|e */
        "mv     t0, %[hash]\n\t"
        VS2R_V(REG_V0, REG_T0)
#elif defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
        VSETIVLI(REG_ZERO, 4, 1, 1, 0b010, 0b000)
        "mv     t0, %[digest]\n\t"
        VL2RE32_V(REG_V0, REG_T0)
        VREV8(REG_V0, REG_V0)
        VREV8(REG_V1, REG_V1)
        "mv     t0, %[hash]\n\t"
        VS2R_V(REG_V0, REG_T0)
#elif defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "ld     t1, 0(%[digest])\n\t"
        "ld     t3, 8(%[digest])\n\t"
        "ld     a5, 16(%[digest])\n\t"
        "ld     a7, 24(%[digest])\n\t"
        REV8(REG_T1, REG_T1)
        REV8(REG_T3, REG_T3)
        REV8(REG_A5, REG_A5)
        REV8(REG_A7, REG_A7)
        "srli   t0, t1, 32\n\t"
        "srli   t2, t3, 32\n\t"
        "srli   a4, a5, 32\n\t"
        "srli   a6, a7, 32\n\t"
        "sw     t0, 0(%[hash])\n\t"
        "sw     t1, 4(%[hash])\n\t"
        "sw     t2, 8(%[hash])\n\t"
        "sw     t3, 12(%[hash])\n\t"
        "sw     a4, 16(%[hash])\n\t"
        "sw     a5, 20(%[hash])\n\t"
        "sw     a6, 24(%[hash])\n\t"
        "sw     a7, 28(%[hash])\n\t"
#else
        LOAD_WORD_REV(t0, 0, %[digest], t2, t3, t4)
        LOAD_WORD_REV(t1, 4, %[digest], t2, t3, t4)
        LOAD_WORD_REV(a4, 8, %[digest], t2, t3, t4)
        LOAD_WORD_REV(a5, 12, %[digest], t2, t3, t4)
        "sw     t0, 0(%[hash])\n\t"
        "sw     t1, 4(%[hash])\n\t"
        "sw     a4, 8(%[hash])\n\t"
        "sw     a5, 12(%[hash])\n\t"
        LOAD_WORD_REV(t0, 16, %[digest], t2, t3, t4)
        LOAD_WORD_REV(t1, 20, %[digest], t2, t3, t4)
        LOAD_WORD_REV(a4, 24, %[digest], t2, t3, t4)
        LOAD_WORD_REV(a5, 28, %[digest], t2, t3, t4)
        "sw     t0, 16(%[hash])\n\t"
        "sw     t1, 20(%[hash])\n\t"
        "sw     a4, 24(%[hash])\n\t"
        "sw     a5, 28(%[hash])\n\t"
#endif
        :
        : [digest] "r" (sha256->digest), [hash] "r" (hash)
        : "cc", "memory", "t0", "t1", "t2", "t3", "t4", "t5", "t6",
          "a4", "a5", "a6", "a7"
    );
}


#ifndef NO_SHA256

/* Initialize SHA-256 object for hashing.
 *
 * @param [in, out] sha256  SHA-256 object.
 * @param [in]      heap    Dynamic memory hint.
 * @param [in]      devId   Device Id.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sha256 is NULL.
 */
int wc_InitSha256_ex(wc_Sha256* sha256, void* heap, int devId)
{
    int ret = 0;

    /* Validate parameters. */
    if (sha256 == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        sha256->heap = heap;
    #ifdef WOLF_CRYPTO_CB
        sha256->devId = devId;
    #endif
        (void)devId;

        InitSha256(sha256);
    }

    return ret;
}

/* Initialize SHA-256 object for hashing.
 *
 * @param [in, out] sha256  SHA-256 object.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sha256 is NULL.
 */
int wc_InitSha256(wc_Sha256* sha256)
{
    return wc_InitSha256_ex(sha256, NULL, INVALID_DEVID);
}

/* Free the SHA-256 hash.
 *
 * @param [in] sha256  SHA-256 object.
 */
void wc_Sha256Free(wc_Sha256* sha256)
{
    /* No dynamic memory allocated. */
    (void)sha256;
}

/* Update the hash with data.
 *
 * @param [in, out] sha256  SHA-256 object.
 * @param [in]      data    Buffer of data to hash.
 * @param [in]      len     Number of bytes in buffer to hash.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sha256 is NULL.
 * @return  BAD_FUNC_ARG when data is NULL but len is not 0.
 */
int wc_Sha256Update(wc_Sha256* sha256, const byte* data, word32 len)
{
    int ret;

    /* Validate parameters. */
    if ((sha256 == NULL) || ((data == NULL) && (len != 0))) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = Sha256Update(sha256, data, len);
    }

    return ret;
}

/* Put the current hash into buffer.
 *
 * @param [in, out] sha256  SHA-256 object.
 * @param [out]     hash    Buffer to hold hash result.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sha256 or hash is NULL.
 */
int wc_Sha256FinalRaw(wc_Sha256* sha256, byte* hash)
{
    int ret = 0;

    /* Validate parameters. */
    if ((sha256 == NULL) || (hash == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
    #ifdef LITTLE_ENDIAN_ORDER
        word32 digest[WC_SHA256_DIGEST_SIZE / sizeof(word32)];

        ByteReverseWords((word32*)digest, (word32*)sha256->digest,
            WC_SHA256_DIGEST_SIZE);
        XMEMCPY(hash, digest, WC_SHA256_DIGEST_SIZE);
    #else
        XMEMCPY(hash, sha256->digest, WC_SHA256_DIGEST_SIZE);
    #endif
    }

    return ret;
}

/* Finalize the hash and put into buffer.
 *
 * @param [in, out] sha256  SHA-256 object.
 * @param [out]     hash    Buffer to hold hash result.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sha256 or hash is NULL.
 */
int wc_Sha256Final(wc_Sha256* sha256, byte* hash)
{
    int ret = 0;

    /* Validate parameters. */
    if ((sha256 == NULL) || (hash == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        /* Finalize hash. */
        Sha256Final(sha256, hash);
        /* Restart SHA-256 object for next hash. */
        InitSha256(sha256);
    }

    return ret;
}

/* Finalize the hash and put into buffer but don't modify state.
 *
 * @param [in, out] sha256  SHA-256 object.
 * @param [out]     hash    Buffer to hold hash result.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sha256 or hash is NULL.
 */
int wc_Sha256GetHash(wc_Sha256* sha256, byte* hash)
{
    int ret;

    /* Validate parameters. */
    if ((sha256 == NULL) || (hash == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        wc_Sha256 tmpSha256;
        /* Create a copy of the hash to finalize. */
        ret = wc_Sha256Copy(sha256, &tmpSha256);
        if (ret == 0) {
            /* Finalize copy. */
            Sha256Final(&tmpSha256, hash);
        }
    }

    return ret;
}

#ifdef WOLFSSL_HASH_FLAGS
/* Set flags of SHA-256 object.
 *
 * @param [in, out] sha256  SHA-256 object.
 * @param [in]      flags   Flags to set.
 * @return  0 on success.
 */
int wc_Sha256SetFlags(wc_Sha256* sha256, word32 flags)
{
    /* Check we have an object to use. */
    if (sha256 != NULL) {
        sha256->flags = flags;
    }
    return 0;
}
/* Get flags of SHA-256 object.
 *
 * @param [in]  sha256  SHA-256 object.
 * @param [out] flags   Flags from SHA-256 object.
 * @return  0 on success.
 */
int wc_Sha256GetFlags(wc_Sha256* sha256, word32* flags)
{
    /* Check we have an object and return parameter to use. */
    if ((sha256 != NULL) && (flags != NULL)) {
        *flags = sha256->flags;
    }
    return 0;
}
#endif

/* Deep copy the SHA-256 object.
 *
 * @param [in]  src  SHA-256 object to copy.
 * @param [out] dst  SHA-256 object to fill.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when src or dst is NULL.
 */
int wc_Sha256Copy(wc_Sha256* src, wc_Sha256* dst)
{
    int ret = 0;

    /* Validate parameters. */
    if ((src == NULL) || (dst == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        XMEMCPY(dst, src, sizeof(wc_Sha256));
    }

    return ret;
}

#ifdef OPENSSL_EXTRA
/* Update the hash with one block of data.
 *
 * @param [in, out] sha256  SHA-256 object.
 * @param [in]      data    Buffer of data to hash.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sha256 or data is NULL.
 */
int wc_Sha256Transform(wc_Sha256* sha256, const unsigned char* data)
{
    int ret = 0;

    /* Validate parameters. */
    if ((sha256 == NULL) || (data == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
    #ifdef LITTLE_ENDIAN_ORDER
        ByteReverseWords(sha256->buffer, (word32*)data, WC_SHA256_BLOCK_SIZE);
    #else
        XMEMCPY(sha256->buffer, data, WC_SHA256_BLOCK_SIZE);
    #endif
        Sha256Transform(sha256, (byte*)sha256->buffer, 1);
    }

    return ret;
}
#endif

#if defined(WOLFSSL_HAVE_LMS) && !defined(WOLFSSL_LMS_FULL_HASH)
/* Update the hash with one block of data and optionally get hash.
 *
 * @param [in, out] sha256  SHA-256 object.
 * @param [in]      data    Buffer of data to hash.
 * @param [out]     hash    Buffer to hold hash. May be NULL.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sha256 or data is NULL.
 */
int wc_Sha256HashBlock(wc_Sha256* sha256, const unsigned char* data,
    unsigned char* hash)
{
    int ret = 0;

    /* Validate parameters. */
    if ((sha256 == NULL) || (data == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        /* Hash block. */
        Sha256Transform(sha256, data, 1);

        if (hash != NULL) {
            /* Reverse bytes in digest. */
        #ifdef LITTLE_ENDIAN_ORDER
            word32* hash32 = (word32*)hash;
            word32* digest = (word32*)sha256->digest;
            hash32[0] = ByteReverseWord32(digest[0]);
            hash32[1] = ByteReverseWord32(digest[1]);
            hash32[2] = ByteReverseWord32(digest[2]);
            hash32[3] = ByteReverseWord32(digest[3]);
            hash32[4] = ByteReverseWord32(digest[4]);
            hash32[5] = ByteReverseWord32(digest[5]);
            hash32[6] = ByteReverseWord32(digest[6]);
            hash32[7] = ByteReverseWord32(digest[7]);
        #else
            XMEMCPY(hash, sha256->digest, WC_SHA256_DIGEST_SIZE);
        #endif
            /* Reset state. */
        #ifndef WOLFSSL_RISCV_VECTOR_CRYPTO_ASM
            sha256->digest[0] = 0x6A09E667L;
            sha256->digest[1] = 0xBB67AE85L;
            sha256->digest[2] = 0x3C6EF372L;
            sha256->digest[3] = 0xA54FF53AL;
            sha256->digest[4] = 0x510E527FL;
            sha256->digest[5] = 0x9B05688CL;
            sha256->digest[6] = 0x1F83D9ABL;
            sha256->digest[7] = 0x5BE0CD19L;
        #else
            /* f, e, b, a, h, g, d, c */
            sha256->digest[0] = 0x9B05688CL;
            sha256->digest[1] = 0x510E527FL;
            sha256->digest[2] = 0xBB67AE85L;
            sha256->digest[3] = 0x6A09E667L;
            sha256->digest[4] = 0x5BE0CD19L;
            sha256->digest[5] = 0x1F83D9ABL;
            sha256->digest[6] = 0xA54FF53AL;
            sha256->digest[7] = 0x3C6EF372L;
        #endif
        }
    }

    return ret;
}
#endif /* WOLFSSL_HAVE_LMS && !WOLFSSL_LMS_FULL_HASH */

#endif /* !NO_SHA256 */


#ifdef WOLFSSL_SHA224

/* Initialze SHA-224 object for hashing.
 *
 * @param [in, out] sha224  SHA-224 object.
 */
static void InitSha224(wc_Sha224* sha224)
{
    /* Set initial hash values. */
#ifndef WOLFSSL_RISCV_VECTOR_CRYPTO_ASM
    sha224->digest[0] = 0xc1059ed8;
    sha224->digest[1] = 0x367cd507;
    sha224->digest[2] = 0x3070dd17;
    sha224->digest[3] = 0xf70e5939;
    sha224->digest[4] = 0xffc00b31;
    sha224->digest[5] = 0x68581511;
    sha224->digest[6] = 0x64f98fa7;
    sha224->digest[7] = 0xbefa4fa4;
#else
    /* f, e, b, a, h, g, d, c */
    sha224->digest[0] = 0x68581511;
    sha224->digest[1] = 0xffc00b31;
    sha224->digest[2] = 0x367cd507;
    sha224->digest[3] = 0xc1059ed8;
    sha224->digest[4] = 0xbefa4fa4;
    sha224->digest[5] = 0x64f98fa7;
    sha224->digest[6] = 0xf70e5939;
    sha224->digest[7] = 0x3070dd17;
#endif

    /* No hashed data. */
    sha224->buffLen = 0;
    /* No data hashed. */
    sha224->loLen   = 0;
    sha224->hiLen   = 0;

#ifdef WOLFSSL_HASH_FLAGS
    sha224->flags = 0;
#endif
}

/* Initialize SHA-224 object for hashing.
 *
 * @param [in, out] sha224  SHA-224 object.
 * @param [in]      heap    Dynamic memory hint.
 * @param [in]      devId   Device Id.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sha224 is NULL.
 */
int wc_InitSha224_ex(wc_Sha224* sha224, void* heap, int devId)
{
    int ret = 0;

    /* Validate parameters. */
    if (sha224 == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        sha224->heap = heap;
        (void)devId;

        InitSha224(sha224);
    }

    return ret;
}

/* Initialize SHA-224 object for hashing.
 *
 * @param [in, out] sha224  SHA-224 object.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sha224 is NULL.
 */
int wc_InitSha224(wc_Sha224* sha224)
{
    return wc_InitSha224_ex(sha224, NULL, INVALID_DEVID);
}

/* Update the hash with data.
 *
 * @param [in, out] sha224  SHA-224 object.
 * @param [in]      data    Buffer of data to hash.
 * @param [in]      len     Number of bytes in buffer to hash.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sha224 is NULL.
 * @return  BAD_FUNC_ARG when data is NULL but len is not 0.
 */
int wc_Sha224Update(wc_Sha224* sha224, const byte* data, word32 len)
{
    int ret;

    /* Validate parameters. */
    if ((sha224 == NULL) || ((data == NULL) && (len > 0))) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = Sha256Update((wc_Sha256 *)sha224, data, len);
    }

    return ret;
}

/* Finalize the hash and put into buffer.
 *
 * @param [in, out] sha224  SHA-224 object.
 * @param [out]     hash    Buffer to hold hash result.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sha224 or hash is NULL.
 */
int wc_Sha224Final(wc_Sha224* sha224, byte* hash)
{
    int ret = 0;

    /* Validate parameters. */
    if ((sha224 == NULL) || (hash == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        word32 hashTmp[WC_SHA256_DIGEST_SIZE/sizeof(word32)];
        /* Finalize hash. */
        Sha256Final((wc_Sha256*)sha224, (byte*)hashTmp);
        /* Return only 224 bits. */
        XMEMCPY(hash, hashTmp, WC_SHA224_DIGEST_SIZE);
        /* Restart SHA-256 object for next hash. */
        InitSha224(sha224);
    }

    return ret;
}

/* Free the SHA-224 hash.
 *
 * @param [in] sha224  SHA-224 object.
 */
void wc_Sha224Free(wc_Sha224* sha224)
{
    /* No dynamic memory allocated. */
    (void)sha224;
}

/* Finalize the hash and put into buffer but don't modify state.
 *
 * @param [in, out] sha224  SHA-224 object.
 * @param [out]     hash    Buffer to hold hash result.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when sha224 or hash is NULL.
 */
int wc_Sha224GetHash(wc_Sha224* sha224, byte* hash)
{
    int ret;

    /* Validate parameters. */
    if ((sha224 == NULL) || (hash == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        wc_Sha224 tmpSha224;
        /* Create a copy of the hash to finalize. */
        ret = wc_Sha224Copy(sha224, &tmpSha224);
        if (ret == 0) {
            /* Finalize copy. */
            ret = wc_Sha224Final(&tmpSha224, hash);
        }
    }

    return ret;
}

#ifdef WOLFSSL_HASH_FLAGS
/* Set flags of SHA-224 object.
 *
 * @param [in, out] sha224  SHA-224 object.
 * @param [in]      flags   Flags to set.
 * @return  0 on success.
 */
int wc_Sha224SetFlags(wc_Sha224* sha224, word32 flags)
{
    /* Check we have an object to use. */
    if (sha224 != NULL) {
        sha224->flags = flags;
    }
    return 0;
}
/* Get flags of SHA-224 object.
 *
 * @param [in]  sha224  SHA-224 object.
 * @param [out] flags   Flags from SHA-224 object.
 * @return  0 on success.
 */
int wc_Sha224GetFlags(wc_Sha224* sha224, word32* flags)
{
    /* Check we have an object and return parameter to use. */
    if ((sha224 != NULL) && (flags != NULL)) {
        *flags = sha224->flags;
    }
    return 0;
}
#endif

/* Deep copy the SHA-224 object.
 *
 * @param [in]  src  SHA-224 object to copy.
 * @param [out] dst  SHA-224 object to fill.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when src or dst is NULL.
 */
int wc_Sha224Copy(wc_Sha224* src, wc_Sha224* dst)
{
    int ret = 0;

    /* Validate parameters. */
    if ((src == NULL) || (dst == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        XMEMCPY(dst, src, sizeof(wc_Sha224));
    }

    return ret;
}

#endif /* WOLFSSL_SHA224 */

#endif /* !NO_SHA256 || WOLFSSL_SHA224 */
#endif /* WOLFSSL_RISCV_ASM */
