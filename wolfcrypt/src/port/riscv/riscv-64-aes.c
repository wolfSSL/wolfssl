/* riscv-64-aes.c
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
#include <wolfssl/wolfcrypt/port/riscv/riscv-64-asm.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#if !defined(NO_AES)

#include <wolfssl/wolfcrypt/aes.h>

#include <wolfssl/wolfcrypt/logging.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifdef WOLFSSL_RISCV_ASM

/* Copy a 16-byte value from in to out.
 *
 * @param [out] out  16-byte value destination.
 * @param [in]  in   16-byte value source.
 */
static WC_INLINE void memcpy16(byte* out, const byte* in)
{
    word64* out64 = (word64*)out;
    word64* in64  = (word64*)in;

    out64[0] = in64[0];
    out64[1] = in64[1];
}

#ifdef WOLFSSL_RISCV_BIT_MANIPULATION

/* Reverse bits in each byte of 64-bit register. */
#define BREV8(rd, rs)                                       \
    ASM_WORD(0b01101000011100000101000000010011 |           \
             (rs << 15) | (rd << 7))

#endif /* WOLFSSL_RISCV_BIT_MANIPULATION */

#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION

/* Reverse bits in each byte of 128-bit vector register. */
#define VBREV8(vd, vs2) \
    ASM_WORD((0b010010 << 26) | (0b1 << 25) | (0b1000 << 15) | \
             (0b010 << 12) | (0b1010111 << 0) | \
             (vs2 << 20) | (vd << 7))
#endif


/* Vector register set if equal: vd[i] = vs1[i] == vs2[i] ? 1 : 0 */
#define VMSEQ_VV(vd, vs1, vs2)                      \
    ASM_WORD((0b011000 << 26) | (0b1 << 25) |       \
             (0b000 << 12) | (0b1010111 << 0) |     \
             (vs2 << 20) | (vs1 << 15) | (vd << 7))
/* Vector register set if equal: vd[i] = vs1[i] != vs2[i] ? 1 : 0 */
#define VMSNE_VV(vd, vs1, vs2)                      \
    ASM_WORD((0b011001 << 26) | (0b1 << 25) |       \
             (0b000 << 12) | (0b1010111 << 0) |     \
             (vs2 << 20) | (vs1 << 15) | (vd << 7))

/* rd = Count of vs2[i] that has a value of 1. */
#define VCPOP_M(rd, vs2)                            \
    ASM_WORD((0b010000 << 26) | (0b1 << 25) |       \
             (0b10000 << 15) |                      \
             (0b010 << 12) | (0b1010111 << 0) |     \
             (vs2 << 20) | (rd << 7))

#if defined(WOLFSSL_RISCV_VECTOR_CRYPTO_ASM)

/*
 * Vector crypto instruction implementation of base operations.
 */

/* Vector AES-128 forward key schedule computation. */
#define VAESKF1_VI(rd, rs2, rnum)                   \
    ASM_WORD((0b100010 << 26) | (0b1 << 25) |       \
             (0b010 << 12) | (0b1110111 << 0) |     \
             (rd << 7) | (rnum << 15) | (rs2 << 20))
/* Vector AES-256 forward key schedule computation. */
#define VAESKF2_VI(rd, rs2, rnum)                   \
    ASM_WORD((0b101010 << 26) | (0b1 << 25) |       \
             (0b010 << 12) | (0b1110111 << 0) |     \
             (rd << 7) | (rnum << 15) | (rs2 << 20))

/* Vector AES round zero encryption/decryption. */
#define VAESZ_VS(rd, rs2)                           \
    ASM_WORD((0b101001 << 26) | (0b1 << 25) |       \
             (0b00111 << 15) | (0b010 << 12) |      \
             (0b1110111 << 0) |                     \
             (rd << 7) | (rs2 << 20))
/* Vector AES middle-round encryption. */
#define VAESEM_VS(rd, rs2)                          \
    ASM_WORD((0b101001 << 26) | (0b1 << 25) |       \
             (0b00010 << 15) | (0b010 << 12) |      \
             (0b1110111 << 0) |                     \
             (rd << 7) | (rs2 << 20))
/* Vector AES final-round encryption. */
#define VAESEF_VS(rd, rs2)                          \
    ASM_WORD((0b101001 << 26) | (0b1 << 25) |       \
             (0b00011 << 15) | (0b010 << 12) |      \
             (0b1110111 << 0) |                     \
             (rd << 7) | (rs2 << 20))
/* Vector AES middle-round decryption. */
#define VAESDM_VS(rd, rs2)                          \
    ASM_WORD((0b101001 << 26) | (0b1 << 25) |       \
             (0b00000 << 15) | (0b010 << 12) |      \
             (0b1110111 << 0) |                     \
             (rd << 7) | (rs2 << 20))
/* Vector AES final-round decryption. */
#define VAESDF_VS(rd, rs2)                          \
    ASM_WORD((0b101001 << 26) | (0b1 << 25) |       \
             (0b00001 << 15) | (0b010 << 12) |      \
             (0b1110111 << 0) |                     \
             (rd << 7) | (rs2 << 20))

/* Set the key and/or IV into the AES object.
 *
 * Creates the key schedule from the key.
 * Uses Vector Cryptographic instructions.
 *
 * @param [in] aes     AES object.
 * @param [in] key     Secret key to use.
 * @param [in] keyLen  Length of key in bytes.
 * @param [in] iv      Initialization Vector (IV) to use. May be NULL.
 * @param [in] dir     Direction of crypt: AES_ENCRYPT, AES_DECRYPT.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when aes or key is NULL.
 * @return  BAD_FUNC_ARG when keyLen/dir is not supported or valid.
 */
int wc_AesSetKey(Aes* aes, const byte* key, word32 keyLen, const byte* iv,
    int dir)
{
    int ret = 0;

    /* Validate parameters. */
    if ((aes == NULL) || (key == NULL)) {
        ret = BAD_FUNC_ARG;
    }
#ifdef WOLFSSL_AES_128
    else if ((keyLen == 16) && (dir == AES_ENCRYPTION)) {
        __asm__ __volatile__ (
            VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
            "mv          t0, %[key]\n\t"
            VL1RE32_V(REG_V0, REG_T0)
            "mv          t0, %[ks]\n\t"
            VAESKF1_VI(REG_V1,  REG_V0, 1)
            VAESKF1_VI(REG_V2,  REG_V1, 2)
            VAESKF1_VI(REG_V3,  REG_V2, 3)
            VAESKF1_VI(REG_V4,  REG_V3, 4)
            VAESKF1_VI(REG_V5,  REG_V4, 5)
            VAESKF1_VI(REG_V6,  REG_V5, 6)
            VAESKF1_VI(REG_V7,  REG_V6, 7)
            VAESKF1_VI(REG_V8,  REG_V7, 8)
            VAESKF1_VI(REG_V9,  REG_V8, 9)
            VAESKF1_VI(REG_V10, REG_V9, 10)
            VS8R_V(REG_V0, REG_T0)
            "add        t0, t0, 128\n\t"
            VS2R_V(REG_V8, REG_T0)
            "add        t0, t0, 96\n\t"
            VS1R_V(REG_V10, REG_T0)
            :
            : [ks] "r" (aes->key), [key] "r" (key)
            : "memory", "t0", "t1", "t2"
        );
        aes->rounds = 10;
    }
#ifdef HAVE_AES_DECRYPT
    else if ((keyLen == 16) && (dir == AES_DECRYPTION)) {
        __asm__ __volatile__ (
            VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
            "mv          t0, %[key]\n\t"
            VL1RE32_V(REG_V10, REG_T0)
            "mv          t0, %[ks]\n\t"
            VAESKF1_VI(REG_V9, REG_V10, 1)
            VAESKF1_VI(REG_V8, REG_V9 , 2)
            VAESKF1_VI(REG_V7, REG_V8 , 3)
            VAESKF1_VI(REG_V6, REG_V7 , 4)
            VAESKF1_VI(REG_V5, REG_V6 , 5)
            VAESKF1_VI(REG_V4, REG_V5 , 6)
            VAESKF1_VI(REG_V3, REG_V4 , 7)
            VAESKF1_VI(REG_V2, REG_V3 , 8)
            VAESKF1_VI(REG_V1, REG_V2 , 9)
            VAESKF1_VI(REG_V0, REG_V1 , 10)
            VS8R_V(REG_V0, REG_T0)
            "add        t0, t0, 128\n\t"
            VS2R_V(REG_V8, REG_T0)
            "add        t0, t0, 96\n\t"
            VS1R_V(REG_V10, REG_T0)
            :
            : [ks] "r" (aes->key), [key] "r" (key)
            : "memory", "t0", "t1", "t2"
        );
        aes->rounds = 10;
    }
#endif
#endif
#ifdef WOLFSSL_AES_192

/* One round of computing key schedule for AES-192. */
#define AES_192_ROUND(d, s, r)                          \
            /* Place key[3] in v16[3] */                \
            VSLIDEDOWN_VI(REG_V17, s, 3)                \
            VSLIDEUP_VI(REG_V16, REG_V17, 3)            \
            /* Place key[5] in s[3] */                  \
            VSLIDEUP_VI(s, REG_V14, 3)                  \
            /* key'[0] = key[0] ^ ks1(key[5]) */        \
            /* key'[1] = key[1] ^ key'[0]     */        \
            /* key'[2] = key[2] ^ key'[1]     */        \
            /* key'[3] = key[5] ^ key'[2]     */        \
            VAESKF1_VI(d, s, r)                         \
            /* key'[3] = key[3] ^ key[5] ^ key'[2] */   \
            VXOR_VV(d, d, REG_V16)                      \
            /* key'[3] = key[3] ^ key'[2] */            \
            VSLIDEUP_VI(REG_V16, REG_V14, 3)            \
            VXOR_VV(d, d, REG_V16)                      \
            /* key'[4] = key[4] ^ key'[3] */            \
            VSLIDEDOWN_VI(REG_V15, d, 3)                \
            VXOR_VV(REG_V13, REG_V13, REG_V15)          \
            /* key'[5] = key[5] ^ key'[4] */            \
            VXOR_VV(REG_V14, REG_V14, REG_V13)          \

/* Store 6 words.
 * V13[0] and V14[0] contain last two words. */
#define AES_192_STORE(d)                                \
            VS1R_V(d, REG_T0)                           \
            "addi        t0, t0, 16\n\t"                \
            VSLIDEUP_VI(REG_V13, REG_V14, 1)            \
            VSETIVLI(REG_X0, 2, 1, 1, 0b010, 0b000)     \
            VS1R_V(REG_V13, REG_T0)                     \
            "addi        t0, t0, 8\n\t"                 \
            VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)

    else if ((keyLen == 24) && (dir == AES_ENCRYPTION)) {
        /* Not supported with specific instructions - make it work anyway! */
        __asm__ __volatile__ (
            VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
            "mv          t0, %[key]\n\t"
            VL1RE32_V(REG_V0, REG_T0)
            VSETIVLI(REG_X0, 1, 1, 1, 0b010, 0b000)
            "addi        t0, t0, 16\n\t"
            VL1RE32_V(REG_V13, REG_T0)
            "addi        t0, t0, 4\n\t"
            VL1RE32_V(REG_V14, REG_T0)
            VXOR_VV(REG_V16, REG_V16, REG_V16)
            VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)

            "mv          t0, %[ks]\n\t"

            /* Round 0 */
            AES_192_STORE(REG_V0)
            /* Round 1 */
            AES_192_ROUND(REG_V1, REG_V0, 1)
            AES_192_STORE(REG_V1)
            /* Round 2 */
            AES_192_ROUND(REG_V0, REG_V1, 2)
            AES_192_STORE(REG_V0)
            /* Round 3 */
            AES_192_ROUND(REG_V1, REG_V0, 3)
            AES_192_STORE(REG_V1)
            /* Round 4 */
            AES_192_ROUND(REG_V0, REG_V1, 4)
            AES_192_STORE(REG_V0)
            /* Round 5 */
            AES_192_ROUND(REG_V1, REG_V0, 5)
            AES_192_STORE(REG_V1)
            /* Round 6 */
            AES_192_ROUND(REG_V0, REG_V1, 6)
            AES_192_STORE(REG_V0)
            /* Round 7 */
            AES_192_ROUND(REG_V1, REG_V0, 7)
            AES_192_STORE(REG_V1)
            /* Round 8 */
            AES_192_ROUND(REG_V0, REG_V1, 8)
            "addi        t0, t0, 32\n\t"
            VS1R_V(REG_V0, REG_T0)
            /* Only need 52 32-bit words - 13 rounds x 4 32-bit words. */
            :
            : [ks] "r" (aes->key), [key] "r" (key)
            : "memory", "t0"
        );
        aes->rounds = 12;
    }
#ifdef HAVE_AES_DECRYPT
    else if ((keyLen == 24) && (dir == AES_DECRYPTION)) {
        /* Not supported with specific instructions - make it work anyway! */
        __asm__ __volatile__ (
            VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
            "mv          t0, %[key]\n\t"
            VL1RE32_V(REG_V0, REG_T0)
            VSETIVLI(REG_X0, 1, 1, 1, 0b010, 0b000)
            "addi        t0, t0, 16\n\t"
            VL1RE32_V(REG_V13, REG_T0)
            "addi        t0, t0, 4\n\t"
            VL1RE32_V(REG_V14, REG_T0)
            VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
            VXOR_VV(REG_V16, REG_V16, REG_V16)

            "addi        t0, %[ks], 224\n\t"
            VS1R_V(REG_V0, REG_T0)

            "mv          t0, %[ks]\n\t"

            /* Round 0 */
            AES_192_STORE(REG_V0)
            /* Round 1 */
            AES_192_ROUND(REG_V1, REG_V0, 1)
            AES_192_STORE(REG_V1)
            /* Round 2 */
            AES_192_ROUND(REG_V0, REG_V1, 2)
            AES_192_STORE(REG_V0)
            /* Round 3 */
            AES_192_ROUND(REG_V1, REG_V0, 3)
            AES_192_STORE(REG_V1)
            /* Round 4 */
            AES_192_ROUND(REG_V0, REG_V1, 4)
            AES_192_STORE(REG_V0)
            /* Round 5 */
            AES_192_ROUND(REG_V1, REG_V0, 5)
            AES_192_STORE(REG_V1)
            /* Round 6 */
            AES_192_ROUND(REG_V0, REG_V1, 6)
            AES_192_STORE(REG_V0)
            /* Round 7 */
            AES_192_ROUND(REG_V1, REG_V0, 7)
            AES_192_STORE(REG_V1)
            /* Round 8 */
            AES_192_ROUND(REG_V0, REG_V1, 8)
            VS1R_V(REG_V0, REG_T0)
            /* Only need 52 32-bit words - 13 rounds x 4 32-bit words. */

            /* Invert the order of the round keys. */
            "mv          t0, %[ks]\n\t"
            VL4RE32_V(REG_V0, REG_T0)
            "addi        t0, %[ks], 64\n\t"
            VL2RE32_V(REG_V4, REG_T0)
            "addi        t1, %[ks], 112\n\t"
            VL4RE32_V(REG_V8, REG_T1)
            "addi        t1, %[ks], 176\n\t"
            VL2RE32_V(REG_V12, REG_T1)
            VMV_V_V(REG_V21, REG_V0 )
            VMV_V_V(REG_V20, REG_V1 )
            VMV_V_V(REG_V19, REG_V2 )
            VMV_V_V(REG_V18, REG_V3 )
            VMV_V_V(REG_V17, REG_V4 )
            VMV_V_V(REG_V16, REG_V5 )
            VMV_V_V(REG_V5 , REG_V8 )
            VMV_V_V(REG_V4 , REG_V9 )
            VMV_V_V(REG_V3 , REG_V10)
            VMV_V_V(REG_V2 , REG_V11)
            VMV_V_V(REG_V1 , REG_V12)
            VMV_V_V(REG_V0 , REG_V13)
            "mv          t0, %[ks]\n\t"
            VS4R_V(REG_V0, REG_T0)
            "addi        t0, %[ks], 64\n\t"
            VS2R_V(REG_V4, REG_T0)
            "addi        t1, %[ks], 112\n\t"
            VS4R_V(REG_V16, REG_T1)
            "addi        t1, %[ks], 176\n\t"
            VS2R_V(REG_V20, REG_T1)
            :
            : [ks] "r" (aes->key), [key] "r" (key)
            : "memory", "t0", "t1"
        );
        aes->rounds = 12;
    }
#endif
#endif
#ifdef WOLFSSL_AES_256
    else if ((keyLen == 32) && (dir == AES_ENCRYPTION)) {
        __asm__ __volatile__ (
            VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
            "mv          t0, %[key]\n\t"
            VL2RE32_V(REG_V0, REG_T0)
            "mv          t0, %[ks]\n\t"
            VMV_V_V(REG_V14, REG_V0)
            VMV_V_V(REG_V13, REG_V1)
            VAESKF2_VI(REG_V14, REG_V13, 2)
            VMV_V_V(REG_V2, REG_V14)
            VAESKF2_VI(REG_V13, REG_V14, 3)
            VMV_V_V(REG_V3, REG_V13)
            VAESKF2_VI(REG_V14, REG_V13, 4)
            VMV_V_V(REG_V4, REG_V14)
            VAESKF2_VI(REG_V13, REG_V14, 5)
            VMV_V_V(REG_V5, REG_V13)
            VAESKF2_VI(REG_V14, REG_V13, 6)
            VMV_V_V(REG_V6, REG_V14)
            VAESKF2_VI(REG_V13, REG_V14, 7)
            VMV_V_V(REG_V7, REG_V13)
            VAESKF2_VI(REG_V14, REG_V13, 8)
            VMV_V_V(REG_V8, REG_V14)
            VAESKF2_VI(REG_V13, REG_V14, 9)
            VMV_V_V(REG_V9, REG_V13)
            VAESKF2_VI(REG_V14, REG_V13, 10)
            VMV_V_V(REG_V10, REG_V14)
            VAESKF2_VI(REG_V13, REG_V14, 11)
            VMV_V_V(REG_V11, REG_V13)
            VAESKF2_VI(REG_V14, REG_V13, 12)
            VMV_V_V(REG_V12, REG_V14)
            VAESKF2_VI(REG_V13, REG_V14, 13)
            VAESKF2_VI(REG_V14, REG_V13, 14)
            VS8R_V(REG_V0, REG_T0)
            "add        t0, t0, 128\n\t"
            VSR_V(REG_V8, REG_T0, 4)
            "add        t0, t0, 64\n\t"
            VSR_V(REG_V12, REG_T0, 2)
            "add        t0, t0, 32\n\t"
            VSR_V(REG_V14, REG_T0, 1)
            :
            : [ks] "r" (aes->key), [key] "r" (key)
            : "memory", "t0", "t1", "t2"
        );
        aes->rounds = 14;
    }
#ifdef HAVE_AES_DECRYPT
    else if ((keyLen == 32) && (dir == AES_DECRYPTION)) {
        __asm__ __volatile__ (
            VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
            "mv          t0, %[key]\n\t"
            VL2RE32_V(REG_V0, REG_T0)
            VMV_V_V(REG_V13, REG_V1)
            VMV_V_V(REG_V14, REG_V0)
            "mv          t0, %[ks]\n\t"
            VAESKF2_VI(REG_V0, REG_V1, 2)
            VMV_V_V(REG_V12, REG_V0)
            VAESKF2_VI(REG_V1, REG_V0, 3)
            VMV_V_V(REG_V11, REG_V1)
            VAESKF2_VI(REG_V0, REG_V1, 4)
            VMV_V_V(REG_V10, REG_V0)
            VAESKF2_VI(REG_V1, REG_V0, 5)
            VMV_V_V(REG_V9 , REG_V1)
            VAESKF2_VI(REG_V0, REG_V1, 6)
            VMV_V_V(REG_V8 , REG_V0)
            VAESKF2_VI(REG_V1, REG_V0, 7)
            VMV_V_V(REG_V7 , REG_V1)
            VAESKF2_VI(REG_V0, REG_V1, 8)
            VMV_V_V(REG_V6 , REG_V0)
            VAESKF2_VI(REG_V1, REG_V0, 9)
            VMV_V_V(REG_V5 , REG_V1)
            VAESKF2_VI(REG_V0, REG_V1, 10)
            VMV_V_V(REG_V4 , REG_V0)
            VAESKF2_VI(REG_V1, REG_V0, 11)
            VMV_V_V(REG_V3 , REG_V1)
            VAESKF2_VI(REG_V0, REG_V1, 12)
            VMV_V_V(REG_V2 , REG_V0)
            VAESKF2_VI(REG_V1, REG_V0, 13)
            VAESKF2_VI(REG_V0, REG_V1, 14)
            VS8R_V(REG_V0, REG_T0)
            "add        t0, t0, 128\n\t"
            VSR_V(REG_V8, REG_T0, 4)
            "add        t0, t0, 64\n\t"
            VSR_V(REG_V12, REG_T0, 2)
            "add        t0, t0, 32\n\t"
            VSR_V(REG_V14, REG_T0, 1)
            :
            : [ks] "r" (aes->key), [key] "r" (key)
            : "memory", "t0", "t1", "t2"
        );
        aes->rounds = 14;
    }
#endif
#endif
    else {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Set the IV. */
        ret = wc_AesSetIV(aes, iv);
    }
    if (ret == 0) {
        /* Finish setting the AES object. */
        aes->keylen = keyLen;
#if defined(WOLFSSL_AES_CFB) || defined(WOLFSSL_AES_COUNTER) || \
    defined(WOLFSSL_AES_OFB)
        aes->left = 0;
#endif
    }

    return ret;
}

#if defined(WOLFSSL_AES_DIRECT) || defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
/* Encrypt a block using AES.
 *
 * Uses Vector Cryptographic instructions.
 *
 * @param [in]  aes  AES object.
 * @param [in]  in   Block to encrypt.
 * @param [out] out  Encrypted block.
 */
static void wc_AesEncrypt(Aes* aes, const byte* in, byte* out)
{
    word32* key = aes->key;

    __asm__ __volatile__ (
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
        /* Load key[0..7]. */
        "mv         t0, %[key]\n\t"
        VL8RE32_V(REG_V0, REG_T0)
        /* Load key[8..9]. */
        "addi       t0, t0, 128\n\t"
        VL2RE32_V(REG_V8, REG_T0)
        /* Check for 11 rounds. */
        "li         t4, 11\n\t"
        "ble        %[rounds], t4, L_aes_encrypt_loaded\n\t"
        /* Load key[10..11]. */
        "addi       t0, t0, 32\n\t"
        VL2RE32_V(REG_V10, REG_T0)
        /* Check for 13 rounds. */
        "li         t4, 13\n\t"
        "ble        %[rounds], t4, L_aes_encrypt_loaded\n\t"
        /* Load key[12..13]. */
        "addi       t0, t0, 32\n\t"
        VL2RE32_V(REG_V12, REG_T0)
      "L_aes_encrypt_loaded:\n\t"
        /* Load last round's key */
        "addi       t0, %[key], 224\n\t"
        VL1RE32_V(REG_V14, REG_T0)

        /* Load block. */
        "mv         t0, %[in]\n\t"
        VL1RE32_V(REG_V15, REG_T0)

        /* Encrypt 10 rounds. */
        VAESZ_VS(REG_V15, REG_V0)
        VAESEM_VS(REG_V15, REG_V1)
        VAESEM_VS(REG_V15, REG_V2)
        VAESEM_VS(REG_V15, REG_V3)
        VAESEM_VS(REG_V15, REG_V4)
        VAESEM_VS(REG_V15, REG_V5)
        VAESEM_VS(REG_V15, REG_V6)
        VAESEM_VS(REG_V15, REG_V7)
        VAESEM_VS(REG_V15, REG_V8)
        VAESEM_VS(REG_V15, REG_V9)
        /* Check for 11 rounds. */
        "li         t4, 11\n\t"
        "ble        %[rounds], t4, L_aes_encrypt_done\n\t"
        VAESEM_VS(REG_V15, REG_V10)
        VAESEM_VS(REG_V15, REG_V11)
        /* Check for 13 rounds. */
        "li         t4, 13\n\t"
        "ble        %[rounds], t4, L_aes_encrypt_done\n\t"
        VAESEM_VS(REG_V15, REG_V12)
        VAESEM_VS(REG_V15, REG_V13)
      "L_aes_encrypt_done:\n\t"
        /* Last round. */
        VAESEF_VS(REG_V15, REG_V14)

        /* Store encrypted block. */
        "mv         t0, %[out]\n\t"
        VS1R_V(REG_V15, REG_T0)

        :
        : [in] "r" (in), [out] "r" (out), [key] "r" (key),
          [rounds] "r" (aes->rounds)
        : "memory", "t0", "t1", "t2", "t4"
    );
}
#endif

#ifdef HAVE_AES_DECRYPT
#ifdef WOLFSSL_AES_DIRECT
/* Decrypt a block using AES.
 *
 * Uses Vector Cryptographic instructions.
 *
 * @param [in]  aes  AES object.
 * @param [in]  in   Block to decrypt.
 * @param [out] out  Decrypted block.
 */
static void wc_AesDecrypt(Aes* aes, const byte* in, byte* out)
{
    word32* key = aes->key;

    __asm__ __volatile__ (
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
        /* Load key[0..7]. */
        "mv         t0, %[key]\n\t"
        VL8RE32_V(REG_V0, REG_T0)
        /* Load key[8..9]. */
        "addi       t0, t0, 128\n\t"
        VL2RE32_V(REG_V8, REG_T0)
        /* Check for 11 rounds. */
        "li         t4, 11\n\t"
        "ble        %[rounds], t4, L_aes_decrypt_loaded\n\t"
        /* Load key[10..11]. */
        "addi       t0, t0, 32\n\t"
        VL2RE32_V(REG_V10, REG_T0)
        /* Check for 13 rounds. */
        "li         t4, 13\n\t"
        "ble        %[rounds], t4, L_aes_decrypt_loaded\n\t"
        /* Load key[12..13]. */
        "addi       t0, t0, 32\n\t"
        VL2RE32_V(REG_V12, REG_T0)
      "L_aes_decrypt_loaded:\n\t"
        /* Load last round's key */
        "addi       t0, %[key], 224\n\t"
        VL1RE32_V(REG_V14, REG_T0)

        /* Load block. */
        "mv         t0, %[in]\n\t"
        VL1RE32_V(REG_V15, REG_T0)

        /* Decrypt 10 rounds. */
        VAESZ_VS(REG_V15, REG_V0)
        VAESDM_VS(REG_V15, REG_V1)
        VAESDM_VS(REG_V15, REG_V2)
        VAESDM_VS(REG_V15, REG_V3)
        VAESDM_VS(REG_V15, REG_V4)
        VAESDM_VS(REG_V15, REG_V5)
        VAESDM_VS(REG_V15, REG_V6)
        VAESDM_VS(REG_V15, REG_V7)
        VAESDM_VS(REG_V15, REG_V8)
        VAESDM_VS(REG_V15, REG_V9)
        /* Check for 11 rounds. */
        "li         t4, 11\n\t"
        "ble        %[rounds], t4, L_aes_decrypt_done\n\t"
        VAESDM_VS(REG_V15, REG_V10)
        VAESDM_VS(REG_V15, REG_V11)
        /* Check for 13 rounds. */
        "li         t4, 13\n\t"
        "ble        %[rounds], t4, L_aes_decrypt_done\n\t"
        VAESDM_VS(REG_V15, REG_V12)
        VAESDM_VS(REG_V15, REG_V13)
      "L_aes_decrypt_done:\n\t"
        /* Last round. */
        VAESDF_VS(REG_V15, REG_V14)

        /* Store decrypted block. */
        "mv         t0, %[out]\n\t"
        VS1R_V(REG_V15, REG_T0)

        :
        : [in] "r" (in), [out] "r" (out), [key] "r" (key),
          [rounds] "r" (aes->rounds)
        : "memory", "t0", "t1", "t2", "t4"
    );
}
#endif /* WOLFSSL_AES_DIRECT */
#endif /* HAVE_AES_DECRYPT */

/* AES-CBC */
#ifdef HAVE_AES_CBC
/* Encrypt blocks of data using AES-CBC.
 *
 * Uses Vector Cryptographic instructions.
 *
 * @param [in]  aes  AES object.
 * @param [out] out  Encrypted blocks.
 * @param [in]  in   Blocks to encrypt.
 * @param pin]  sz   Number of bytes to encrypt.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when aes, out or in is NULL.
 * @return  BAD_LENGTH_E when sz is not a multiple of AES_BLOCK_SIZE.
 */
int wc_AesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    int ret = 0;
    word32 blocks = sz / AES_BLOCK_SIZE;

    /* Validate parameters. */
    if ((aes == NULL) || (out == NULL) || (in == NULL)) {
        ret = BAD_FUNC_ARG;
    }
#ifdef WOLFSSL_AES_CBC_LENGTH_CHECKS
    /* Ensure a multiple of blocks is to be encrypted.  */
    if ((ret == 0) && (sz % AES_BLOCK_SIZE)) {
        ret = BAD_LENGTH_E;
    }
#endif

    if ((ret == 0) && (sz > 0)) {
        switch (aes->rounds) {
#ifdef WOLFSSL_AES_128
        case 10:
            __asm__ __volatile__ (
                VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)

                /* Load key[0..7]. */
                "mv         t0, %[key]\n\t"
                VL8RE32_V(REG_V0, REG_T0)
                /* Load key[8..9]. */
                "addi       t0, t0, 128\n\t"
                VL2RE32_V(REG_V8, REG_T0)
                /* Load last round's key */
                "addi       t0, %[key], 224\n\t"
                VL1RE32_V(REG_V10, REG_T0)
                /* Load the IV. */
                "mv         t0, %[reg]\n\t"
                VL1RE32_V(REG_V11, REG_T0)

              "L_aes_cbc_128_encrypt_block_loop:\n\t"
                /* Load input. */
                "mv         t0, %[in]\n\t"
                VL1RE32_V(REG_V15, REG_T0)
                VXOR_VV(REG_V15, REG_V15, REG_V11)

                VAESZ_VS(REG_V15, REG_V0)
                VAESEM_VS(REG_V15, REG_V1)
                VAESEM_VS(REG_V15, REG_V2)
                VAESEM_VS(REG_V15, REG_V3)
                VAESEM_VS(REG_V15, REG_V4)
                VAESEM_VS(REG_V15, REG_V5)
                VAESEM_VS(REG_V15, REG_V6)
                VAESEM_VS(REG_V15, REG_V7)
                VAESEM_VS(REG_V15, REG_V8)
                VAESEM_VS(REG_V15, REG_V9)
                VAESEF_VS(REG_V15, REG_V10)

                "mv         t0, %[out]\n\t"
                VS1R_V(REG_V15, REG_T0)
                VMV_V_V(REG_V11, REG_V15)

                "addi        %[in], %[in], 16\n\t"
                "addi        %[out], %[out], 16\n\t"
                /* Loop if more elements to process. */
                "addi       %[blocks], %[blocks], -1\n\t"
                "bnez       %[blocks], L_aes_cbc_128_encrypt_block_loop\n\t"

                "mv         t0, %[reg]\n\t"
                VS1R_V(REG_V11, REG_T0)
                : [blocks] "+r" (blocks)
                : [in] "r" (in), [out] "r" (out), [key] "r" (aes->key),
                  [reg] "r" (aes->reg)
                : "memory", "t0", "t1", "t2", "t4"
            );
            break;
#endif
#ifdef WOLFSSL_AES_192
        case 12:
            __asm__ __volatile__ (
                VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)

                /* Load key[0..7]. */
                "mv         t0, %[key]\n\t"
                VL8RE32_V(REG_V0, REG_T0)
                /* Load key[8..11]. */
                "addi       t0, t0, 128\n\t"
                VL4RE32_V(REG_V8, REG_T0)
                /* Load last round's key */
                "addi       t0, %[key], 224\n\t"
                VL1RE32_V(REG_V12, REG_T0)
                /* Load the IV. */
                "mv         t0, %[reg]\n\t"
                VL1RE32_V(REG_V13, REG_T0)

              "L_aes_cbc_192_encrypt_block_loop:\n\t"
                /* Load input. */
                "mv         t0, %[in]\n\t"
                VL1RE32_V(REG_V15, REG_T0)
                VXOR_VV(REG_V15, REG_V15, REG_V13)

                VAESZ_VS(REG_V15, REG_V0)
                VAESEM_VS(REG_V15, REG_V1)
                VAESEM_VS(REG_V15, REG_V2)
                VAESEM_VS(REG_V15, REG_V3)
                VAESEM_VS(REG_V15, REG_V4)
                VAESEM_VS(REG_V15, REG_V5)
                VAESEM_VS(REG_V15, REG_V6)
                VAESEM_VS(REG_V15, REG_V7)
                VAESEM_VS(REG_V15, REG_V8)
                VAESEM_VS(REG_V15, REG_V9)
                VAESEM_VS(REG_V15, REG_V10)
                VAESEM_VS(REG_V15, REG_V11)
                VAESEF_VS(REG_V15, REG_V12)

                "mv         t0, %[out]\n\t"
                VS1R_V(REG_V15, REG_T0)
                VMV_V_V(REG_V13, REG_V15)

                "addi        %[in], %[in], 16\n\t"
                "addi        %[out], %[out], 16\n\t"
                /* Loop if more elements to process. */
                "addi       %[blocks], %[blocks], -1\n\t"
                "bnez       %[blocks], L_aes_cbc_192_encrypt_block_loop\n\t"

                "mv         t0, %[reg]\n\t"
                VS1R_V(REG_V13, REG_T0)
                : [blocks] "+r" (blocks)
                : [in] "r" (in), [out] "r" (out), [key] "r" (aes->key),
                  [reg] "r" (aes->reg)
                : "memory", "t0", "t1", "t2", "t4"
            );
            break;
#endif
#ifdef WOLFSSL_AES_256
        case 14:
            __asm__ __volatile__ (
                VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)

                /* Load key[0..7]. */
                "mv         t0, %[key]\n\t"
                VL8RE32_V(REG_V0, REG_T0)
                /* Load key[8..11]. */
                "addi       t0, t0, 128\n\t"
                VL4RE32_V(REG_V8, REG_T0)
                /* Load key[12..13]. */
                "addi       t0, t0, 64\n\t"
                VL2RE32_V(REG_V12, REG_T0)
                /* Load last round's key */
                "addi       t0, %[key], 224\n\t"
                VL1RE32_V(REG_V14, REG_T0)
                /* Load the IV. */
                "mv         t0, %[reg]\n\t"
                VL1RE32_V(REG_V16, REG_T0)

              "L_aes_cbc_256_encrypt_block_loop:\n\t"
                /* Load input. */
                "mv         t0, %[in]\n\t"
                VL1RE32_V(REG_V15, REG_T0)
                VXOR_VV(REG_V15, REG_V15, REG_V16)

                VAESZ_VS(REG_V15, REG_V0)
                VAESEM_VS(REG_V15, REG_V1)
                VAESEM_VS(REG_V15, REG_V2)
                VAESEM_VS(REG_V15, REG_V3)
                VAESEM_VS(REG_V15, REG_V4)
                VAESEM_VS(REG_V15, REG_V5)
                VAESEM_VS(REG_V15, REG_V6)
                VAESEM_VS(REG_V15, REG_V7)
                VAESEM_VS(REG_V15, REG_V8)
                VAESEM_VS(REG_V15, REG_V9)
                VAESEM_VS(REG_V15, REG_V10)
                VAESEM_VS(REG_V15, REG_V11)
                VAESEM_VS(REG_V15, REG_V12)
                VAESEM_VS(REG_V15, REG_V13)
                VAESEF_VS(REG_V15, REG_V14)

                "mv         t0, %[out]\n\t"
                VS1R_V(REG_V15, REG_T0)
                VMV_V_V(REG_V16, REG_V15)

                "addi        %[in], %[in], 16\n\t"
                "addi        %[out], %[out], 16\n\t"
                /* Loop if more elements to process. */
                "addi       %[blocks], %[blocks], -1\n\t"
                "bnez       %[blocks], L_aes_cbc_256_encrypt_block_loop\n\t"

                "mv         t0, %[reg]\n\t"
                VS1R_V(REG_V16, REG_T0)
                : [blocks] "+r" (blocks)
                : [in] "r" (in), [out] "r" (out), [key] "r" (aes->key),
                  [reg] "r" (aes->reg)
                : "memory", "t0", "t1", "t2", "t4"
            );
            break;
#endif
        }
    }

    return ret;
}

#ifdef HAVE_AES_DECRYPT
/* Decrypt blocks of data using AES-CBC.
 *
 * Uses Vector Cryptographic instructions.
 *
 * @param [in]  aes  AES object.
 * @param [out] out  Decrypted blocks.
 * @param [in]  in   Blocks to decrypt.
 * @param pin]  sz   Number of bytes to decrypt.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when aes, out or in is NULL.
 * @return  BAD_FUNC_ARG when sz is not a multiple of AES_BLOCK_SIZE.
 * @return  BAD_LENGTH_E when sz is not a multiple of AES_BLOCK_SIZE.
 */
int wc_AesCbcDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    int ret = 0;
    word32 blocks = sz / AES_BLOCK_SIZE;

    /* Validate parameters. */
    if ((aes == NULL) || (out == NULL) || (in == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Ensure a multiple of blocks is being decrypted.  */
    if ((ret == 0) && (sz % AES_BLOCK_SIZE)) {
#ifdef WOLFSSL_AES_CBC_LENGTH_CHECKS
        ret = BAD_LENGTH_E;
#else
        ret = BAD_FUNC_ARG;
#endif
    }

    if ((ret == 0) && (sz > 0)) {
        switch (aes->rounds) {
#ifdef WOLFSSL_AES_128
        case 10:
            __asm__ __volatile__ (
                VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)

                /* Load key[0..7]. */
                "mv         t0, %[key]\n\t"
                VL8RE32_V(REG_V0, REG_T0)
                /* Load key[8..9]. */
                "addi       t0, t0, 128\n\t"
                VL2RE32_V(REG_V8, REG_T0)
                /* Load last round's key */
                "addi       t0, %[key], 224\n\t"
                VL1RE32_V(REG_V10, REG_T0)
                /* Load the IV. */
                "mv         t0, %[reg]\n\t"
                VL1RE32_V(REG_V11, REG_T0)

              "L_aes_cbc_128_decrypt_block_loop:\n\t"
                /* Load input. */
                "mv         t0, %[in]\n\t"
                VL1RE32_V(REG_V15, REG_T0)
                VMV_V_V(REG_V14, REG_V15)

                VAESZ_VS(REG_V15, REG_V0)
                VAESDM_VS(REG_V15, REG_V1)
                VAESDM_VS(REG_V15, REG_V2)
                VAESDM_VS(REG_V15, REG_V3)
                VAESDM_VS(REG_V15, REG_V4)
                VAESDM_VS(REG_V15, REG_V5)
                VAESDM_VS(REG_V15, REG_V6)
                VAESDM_VS(REG_V15, REG_V7)
                VAESDM_VS(REG_V15, REG_V8)
                VAESDM_VS(REG_V15, REG_V9)
                VAESDF_VS(REG_V15, REG_V10)
                VXOR_VV(REG_V15, REG_V15, REG_V11)

                "mv         t0, %[out]\n\t"
                VS1R_V(REG_V15, REG_T0)
                VMV_V_V(REG_V11, REG_V14)

                "addi        %[in], %[in], 16\n\t"
                "addi        %[out], %[out], 16\n\t"
                /* Loop if more elements to process. */
                "addi       %[blocks], %[blocks], -1\n\t"
                "bnez       %[blocks], L_aes_cbc_128_decrypt_block_loop\n\t"

                "mv         t0, %[reg]\n\t"
                VS1R_V(REG_V11, REG_T0)
                : [blocks] "+r" (blocks)
                : [in] "r" (in), [out] "r" (out), [key] "r" (aes->key),
                  [reg] "r" (aes->reg)
                : "memory", "t0", "t1", "t2", "t4"
            );
            break;
#endif
#ifdef WOLFSSL_AES_192
        case 12:
            __asm__ __volatile__ (
                VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)

                /* Load key[0..7]. */
                "mv         t0, %[key]\n\t"
                VL8RE32_V(REG_V0, REG_T0)
                /* Load key[8..11]. */
                "addi       t0, t0, 128\n\t"
                VL4RE32_V(REG_V8, REG_T0)
                /* Load last round's key */
                "addi       t0, %[key], 224\n\t"
                VL1RE32_V(REG_V12, REG_T0)
                /* Load the IV. */
                "mv         t0, %[reg]\n\t"
                VL1RE32_V(REG_V13, REG_T0)

              "L_aes_cbc_192_decrypt_block_loop:\n\t"
                /* Load input. */
                "mv         t0, %[in]\n\t"
                VL1RE32_V(REG_V15, REG_T0)
                VMV_V_V(REG_V14, REG_V15)

                VAESZ_VS(REG_V15, REG_V0)
                VAESDM_VS(REG_V15, REG_V1)
                VAESDM_VS(REG_V15, REG_V2)
                VAESDM_VS(REG_V15, REG_V3)
                VAESDM_VS(REG_V15, REG_V4)
                VAESDM_VS(REG_V15, REG_V5)
                VAESDM_VS(REG_V15, REG_V6)
                VAESDM_VS(REG_V15, REG_V7)
                VAESDM_VS(REG_V15, REG_V8)
                VAESDM_VS(REG_V15, REG_V9)
                VAESDM_VS(REG_V15, REG_V10)
                VAESDM_VS(REG_V15, REG_V11)
                VAESDF_VS(REG_V15, REG_V12)
                VXOR_VV(REG_V15, REG_V15, REG_V13)

                "mv         t0, %[out]\n\t"
                VS1R_V(REG_V15, REG_T0)
                VMV_V_V(REG_V13, REG_V14)

                "addi        %[in], %[in], 16\n\t"
                "addi        %[out], %[out], 16\n\t"
                /* Loop if more elements to process. */
                "addi       %[blocks], %[blocks], -1\n\t"
                "bnez       %[blocks], L_aes_cbc_192_decrypt_block_loop\n\t"

                "mv         t0, %[reg]\n\t"
                VS1R_V(REG_V13, REG_T0)
                : [blocks] "+r" (blocks)
                : [in] "r" (in), [out] "r" (out), [key] "r" (aes->key),
                  [reg] "r" (aes->reg)
                : "memory", "t0", "t1", "t2", "t4"
            );
            break;
#endif
#ifdef WOLFSSL_AES_256
        case 14:
            __asm__ __volatile__ (
                VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)

                /* Load key[0..7]. */
                "mv         t0, %[key]\n\t"
                VL8RE32_V(REG_V0, REG_T0)
                /* Load key[8..11]. */
                "addi       t0, t0, 128\n\t"
                VL4RE32_V(REG_V8, REG_T0)
                /* Load key[12..13]. */
                "addi       t0, t0, 64\n\t"
                VL2RE32_V(REG_V12, REG_T0)
                /* Load last round's key */
                "addi       t0, %[key], 224\n\t"
                VL1RE32_V(REG_V14, REG_T0)
                /* Load the IV. */
                "mv         t0, %[reg]\n\t"
                VL1RE32_V(REG_V16, REG_T0)

              "L_aes_cbc_256_decrypt_block_loop:\n\t"
                /* Load input. */
                "mv         t0, %[in]\n\t"
                VL1RE32_V(REG_V15, REG_T0)
                VMV_V_V(REG_V17, REG_V15)

                VAESZ_VS(REG_V15, REG_V0)
                VAESDM_VS(REG_V15, REG_V1)
                VAESDM_VS(REG_V15, REG_V2)
                VAESDM_VS(REG_V15, REG_V3)
                VAESDM_VS(REG_V15, REG_V4)
                VAESDM_VS(REG_V15, REG_V5)
                VAESDM_VS(REG_V15, REG_V6)
                VAESDM_VS(REG_V15, REG_V7)
                VAESDM_VS(REG_V15, REG_V8)
                VAESDM_VS(REG_V15, REG_V9)
                VAESDM_VS(REG_V15, REG_V10)
                VAESDM_VS(REG_V15, REG_V11)
                VAESDM_VS(REG_V15, REG_V12)
                VAESDM_VS(REG_V15, REG_V13)
                VAESDF_VS(REG_V15, REG_V14)
                VXOR_VV(REG_V15, REG_V15, REG_V16)

                "mv         t0, %[out]\n\t"
                VS1R_V(REG_V15, REG_T0)
                VMV_V_V(REG_V16, REG_V17)

                "addi        %[in], %[in], 16\n\t"
                "addi        %[out], %[out], 16\n\t"
                /* Loop if more elements to process. */
                "addi       %[blocks], %[blocks], -1\n\t"
                "bnez       %[blocks], L_aes_cbc_256_decrypt_block_loop\n\t"

                "mv         t0, %[reg]\n\t"
                VS1R_V(REG_V16, REG_T0)
                : [blocks] "+r" (blocks)
                : [in] "r" (in), [out] "r" (out), [key] "r" (aes->key),
                  [reg] "r" (aes->reg)
                : "memory", "t0", "t1", "t2", "t4"
            );
            break;
#endif
        }
    }

    return ret;
}
#endif /* HAVE_AES_DECRYPT */

/* Don't need generic implementation. */
#define HAVE_AES_CBC_ENC_DEC

#endif /* HAVE_AES_CBC */

/* AES-CTR */
#ifdef WOLFSSL_AES_COUNTER
/* Encrypt blocks using AES-CTR.
 *
 * Uses Vector Cryptographic instructions.
 *
 * @param [in]  aes     AES object.
 * @param [out] out     Encrypted blocks.
 * @param [in]  in      Blocks to encrypt.
 * @param [in]  blocks  Number of blocks to encrypt.
 */
static void wc_aes_ctr_encrypt_asm(Aes* aes, byte* out, const byte* in,
    word32 blocks)
{
    switch(aes->rounds) {
#ifdef WOLFSSL_AES_128
    case 10:
        __asm__ __volatile__ (
            VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)

            /* Load key[0..7]. */
            "mv         t0, %[key]\n\t"
            VL8RE32_V(REG_V0, REG_T0)
            /* Load key[8..9]. */
            "addi       t0, t0, 128\n\t"
            VL2RE32_V(REG_V8, REG_T0)
            /* Load last round's key */
            "addi       t0, %[key], 224\n\t"
            VL1RE32_V(REG_V10, REG_T0)
            /* Load the counter. */
            "mv         t0, %[reg]\n\t"
            VL1RE32_V(REG_V16, REG_T0)
            "li         t2, 1 \n\t"

          "L_aes_ctr_128_encrypt_block_loop:\n\t"
            VMV_V_V(REG_V15, REG_V16)
            VSETIVLI(REG_X0, 2, 0, 0, 0b011, 0b000)
            VREV8(REG_V16, REG_V16)
            VSLIDEDOWN_VI(REG_V17, REG_V16, 1)
            VXOR_VV(REG_V18, REG_V18, REG_V18)
            VADD_VI(REG_V17, REG_V17, 1)
            VMSEQ_VV(REG_V18, REG_V18, REG_V17)
            VSLIDEUP_VI(REG_V16, REG_V17, 1)
            VADD_VV(REG_V16, REG_V16, REG_V18)
            VREV8(REG_V16, REG_V16)
            VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)

            VAESZ_VS(REG_V15, REG_V0)
            VAESEM_VS(REG_V15, REG_V1)
            VAESEM_VS(REG_V15, REG_V2)
            VAESEM_VS(REG_V15, REG_V3)
            VAESEM_VS(REG_V15, REG_V4)
            VAESEM_VS(REG_V15, REG_V5)
            VAESEM_VS(REG_V15, REG_V6)
            VAESEM_VS(REG_V15, REG_V7)
            VAESEM_VS(REG_V15, REG_V8)
            VAESEM_VS(REG_V15, REG_V9)
            VAESEF_VS(REG_V15, REG_V10)

            /* Load input. */
            "mv         t0, %[in]\n\t"
            VL1RE32_V(REG_V17, REG_T0)
            VXOR_VV(REG_V15, REG_V15, REG_V17)

            "mv         t0, %[out]\n\t"
            VS1R_V(REG_V15, REG_T0)

            "addi        %[in], %[in], 16\n\t"
            "addi        %[out], %[out], 16\n\t"
            /* Loop if more elements to process. */
            "addi       %[blocks], %[blocks], -1\n\t"
            "bnez       %[blocks], L_aes_ctr_128_encrypt_block_loop\n\t"

            "mv         t0, %[reg]\n\t"
            VS1R_V(REG_V16, REG_T0)
            : [blocks] "+r" (blocks)
            : [in] "r" (in), [out] "r" (out), [key] "r" (aes->key),
              [reg] "r" (aes->reg)
            : "memory", "t0", "t1", "t2", "t4"
        );
        break;
#endif
#ifdef WOLFSSL_AES_192
    case 12:
        __asm__ __volatile__ (
            VSETIVLI(REG_X0, 4, 0, 0, 0b010, 0b000)

            /* Load key[0..7]. */
            "mv         t0, %[key]\n\t"
            VL8RE32_V(REG_V0, REG_T0)
            /* Load key[8..11]. */
            "addi       t0, t0, 128\n\t"
            VL4RE32_V(REG_V8, REG_T0)
            /* Load last round's key */
            "addi       t0, %[key], 224\n\t"
            VL1RE32_V(REG_V12, REG_T0)
            /* Load the counter. */
            "mv         t0, %[reg]\n\t"
            VL1RE32_V(REG_V16, REG_T0)
            "li         t2, 1 \n\t"

          "L_aes_ctr_192_encrypt_block_loop:\n\t"
            VMV_V_V(REG_V15, REG_V16)
            VSETIVLI(REG_X0, 2, 0, 0, 0b011, 0b000)
            VREV8(REG_V16, REG_V16)
            VSLIDEDOWN_VI(REG_V17, REG_V16, 1)
            VXOR_VV(REG_V18, REG_V18, REG_V18)
            VADD_VI(REG_V17, REG_V17, 1)
            VMSEQ_VV(REG_V18, REG_V18, REG_V17)
            VSLIDEUP_VI(REG_V16, REG_V17, 1)
            VADD_VV(REG_V16, REG_V16, REG_V18)
            VREV8(REG_V16, REG_V16)
            VSETIVLI(REG_X0, 4, 0, 0, 0b010, 0b000)

            VAESZ_VS(REG_V15, REG_V0)
            VAESEM_VS(REG_V15, REG_V1)
            VAESEM_VS(REG_V15, REG_V2)
            VAESEM_VS(REG_V15, REG_V3)
            VAESEM_VS(REG_V15, REG_V4)
            VAESEM_VS(REG_V15, REG_V5)
            VAESEM_VS(REG_V15, REG_V6)
            VAESEM_VS(REG_V15, REG_V7)
            VAESEM_VS(REG_V15, REG_V8)
            VAESEM_VS(REG_V15, REG_V9)
            VAESEM_VS(REG_V15, REG_V10)
            VAESEM_VS(REG_V15, REG_V11)
            VAESEF_VS(REG_V15, REG_V12)

            /* Load input. */
            "mv         t0, %[in]\n\t"
            VL1RE32_V(REG_V17, REG_T0)
            VXOR_VV(REG_V15, REG_V15, REG_V17)

            "mv         t0, %[out]\n\t"
            VS1R_V(REG_V15, REG_T0)

            "addi        %[in], %[in], 16\n\t"
            "addi        %[out], %[out], 16\n\t"
            /* Loop if more elements to process. */
            "addi       %[blocks], %[blocks], -1\n\t"
            "bnez       %[blocks], L_aes_ctr_192_encrypt_block_loop\n\t"

            "mv         t0, %[reg]\n\t"
            VS1R_V(REG_V16, REG_T0)
            : [blocks] "+r" (blocks)
            : [in] "r" (in), [out] "r" (out), [key] "r" (aes->key),
              [reg] "r" (aes->reg)
            : "memory", "t0", "t1", "t2", "t4"
        );
        break;
#endif
#ifdef WOLFSSL_AES_256
    case 14:
        __asm__ __volatile__ (
            VSETIVLI(REG_X0, 4, 0, 0, 0b010, 0b000)

            /* Load key[0..7]. */
            "mv         t0, %[key]\n\t"
            VL8RE32_V(REG_V0, REG_T0)
            /* Load key[8..11]. */
            "addi       t0, t0, 128\n\t"
            VL4RE32_V(REG_V8, REG_T0)
            /* Load key[12..13]. */
            "addi       t0, t0, 64\n\t"
            VL2RE32_V(REG_V12, REG_T0)
            /* Load last round's key */
            "addi       t0, %[key], 224\n\t"
            VL1RE32_V(REG_V14, REG_T0)
            /* Load the counter. */
            "mv         t0, %[reg]\n\t"
            VL1RE32_V(REG_V16, REG_T0)
            "li         t2, 1 \n\t"

          "L_aes_ctr_256_encrypt_block_loop:\n\t"
            VMV_V_V(REG_V15, REG_V16)
            VSETIVLI(REG_X0, 2, 0, 0, 0b011, 0b000)
            VREV8(REG_V16, REG_V16)
            VSLIDEDOWN_VI(REG_V17, REG_V16, 1)
            VXOR_VV(REG_V18, REG_V18, REG_V18)
            VADD_VI(REG_V17, REG_V17, 1)
            VMSEQ_VV(REG_V18, REG_V18, REG_V17)
            VSLIDEUP_VI(REG_V16, REG_V17, 1)
            VADD_VV(REG_V16, REG_V16, REG_V18)
            VREV8(REG_V16, REG_V16)
            VSETIVLI(REG_X0, 4, 0, 0, 0b010, 0b000)

            VAESZ_VS(REG_V15, REG_V0)
            VAESEM_VS(REG_V15, REG_V1)
            VAESEM_VS(REG_V15, REG_V2)
            VAESEM_VS(REG_V15, REG_V3)
            VAESEM_VS(REG_V15, REG_V4)
            VAESEM_VS(REG_V15, REG_V5)
            VAESEM_VS(REG_V15, REG_V6)
            VAESEM_VS(REG_V15, REG_V7)
            VAESEM_VS(REG_V15, REG_V8)
            VAESEM_VS(REG_V15, REG_V9)
            VAESEM_VS(REG_V15, REG_V10)
            VAESEM_VS(REG_V15, REG_V11)
            VAESEM_VS(REG_V15, REG_V12)
            VAESEM_VS(REG_V15, REG_V13)
            VAESEF_VS(REG_V15, REG_V14)

            /* Load input. */
            "mv         t0, %[in]\n\t"
            VL1RE32_V(REG_V17, REG_T0)
            VXOR_VV(REG_V15, REG_V15, REG_V17)

            "mv         t0, %[out]\n\t"
            VS1R_V(REG_V15, REG_T0)

            "addi        %[in], %[in], 16\n\t"
            "addi        %[out], %[out], 16\n\t"
            /* Loop if more elements to process. */
            "addi       %[blocks], %[blocks], -1\n\t"
            "bnez       %[blocks], L_aes_ctr_256_encrypt_block_loop\n\t"

            "mv         t0, %[reg]\n\t"
            VS1R_V(REG_V16, REG_T0)
            "mv         t0, %[reg]\n\t"
            : [blocks] "+r" (blocks)
            : [in] "r" (in), [out] "r" (out), [key] "r" (aes->key),
              [reg] "r" (aes->reg)
            : "memory", "t0", "t1", "t2", "t4"
        );
        break;
#endif
    }
}

/* Encrypt blocks of data using AES-CTR.
 *
 * Uses Vector Cryptographic instructions.
 *
 * @param [in]  aes  AES object.
 * @param [out] out  Encrypted blocks.
 * @param [in]  in   Blocks to encrypt.
 * @param [in]  sz   Number of bytes to encrypt.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when aes, out or in is NULL.
 * @return  BAD_FUNC_ARG when key size in AES object is not supported.
 */
int wc_AesCtrEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
   int ret = 0;
   word32 processed;

    /* Validate parameters. */
    if ((aes == NULL) || (out == NULL) || (in == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Check key size is supported. */
        switch (aes->rounds) {
        #ifdef WOLFSSL_AES_128
            case 10: /* AES 128 BLOCK */
        #endif /* WOLFSSL_AES_128 */
        #ifdef WOLFSSL_AES_192
            case 12: /* AES 192 BLOCK */
        #endif /* WOLFSSL_AES_192 */
        #ifdef WOLFSSL_AES_256
            case 14: /* AES 256 BLOCK */
        #endif /* WOLFSSL_AES_256 */
                break;
            default:
                WOLFSSL_MSG("Bad AES-CTR round value");
                ret = BAD_FUNC_ARG;
        }
    }

    if (ret == 0) {
        /* Use up any unused bytes left in aes->tmp */
        processed = min(aes->left, sz);
        if (processed > 0) {
            /* XOR in encrypted counter.  */
            xorbufout(out, in, (byte*)aes->tmp + AES_BLOCK_SIZE - aes->left,
                processed);
            out += processed;
            in += processed;
            aes->left -= processed;
            sz -= processed;
        }

        /* Do whole blocks of data. */
        while (sz >= AES_BLOCK_SIZE) {
            word32 blocks = sz / AES_BLOCK_SIZE;

            wc_aes_ctr_encrypt_asm(aes, out, in, blocks);

            processed = blocks * AES_BLOCK_SIZE;
            out += processed;
            in  += processed;
            sz  -= processed;
            aes->left = 0;
        }

        if (sz > 0) {
            /* Encrypt counter and store in aes->tmp.
             * Use up aes->tmp to encrypt data less than a block.
             */
            static const byte zeros[AES_BLOCK_SIZE] = {
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            };

            wc_aes_ctr_encrypt_asm(aes, (byte*)aes->tmp, zeros, 1);
            /* XOR in encrypted counter. */
            xorbufout(out, in, aes->tmp, sz);
            aes->left = AES_BLOCK_SIZE - sz;
        }
    }

    return ret;
}

/* Don't need generic implementation. */
#define HAVE_AES_COUNTER_ENC

#endif /* WOLFSSL_AES_COUNTER */

#elif defined(WOLFSSL_RISCV_SCALAR_CRYPTO_ASM)

/*
 * Scalar crypto instruction implementation of base operations.
 */

/* AES key schedule SBox operation. */
#define AES64KS1I(rd, rs1, rnum)                            \
    ASM_WORD(0b00110001000000000001000000010011 |           \
             (((rd) << 7) | ((rs1) << 15) | (rnum) << 20))
/* AES key schedule operation. */
#define AES64KS2(rd, rs1, rs2)                              \
    ASM_WORD(0b01111110000000000000000000110011 |           \
             (((rd) << 7) | ((rs1) << 15) | (rs2) << 20))
/* AES inverse MixColums step. */
#define AES64IM(rd, rs1)                                    \
    ASM_WORD(0b00110000000000000001000000010011 |           \
             ((rd) << 7) | ((rs1) << 15))

/* Perform computation of one round of key schedule for AES-128 encryption. */
#define AES64_128_KS_RND_INS(rnum, o1, o2)                  \
            AES64KS1I(REG_T2, REG_T1, rnum)                 \
            AES64KS2(REG_T0, REG_T2, REG_T0)                \
            AES64KS2(REG_T1, REG_T0, REG_T1)                \
            "sd        t0, " #o1 "(%[ks])\n\t"              \
            "sd        t1, " #o2 "(%[ks])\n\t"
/* Perform computation of one round of key schedule for AES-128 decryption. */
#define AES64_128_INV_KS_RND_INS(rnum, o1, o2)              \
            AES64KS1I(REG_T2, REG_T1, rnum)                 \
            AES64KS2(REG_T0, REG_T2, REG_T0)                \
            AES64KS2(REG_T1, REG_T0, REG_T1)                \
            AES64IM(REG_T2, REG_T0)                         \
            AES64IM(REG_T3, REG_T1)                         \
            "sd        t2, " #o1 "(%[ks])\n\t"              \
            "sd        t3, " #o2 "(%[ks])\n\t"

/* Perform computation of numbered round of key schedule for AES-128 encryption.
 */
#define AES64_128_KS_RND(rnum)                              \
    AES64_128_KS_RND_INS((rnum), ((rnum) + 1) * 16,         \
        ((rnum) + 1) * 16 + 8)
/* Perform computation of numbered round of key schedule for AES-128 decryption.
 */
#define AES64_128_INV_KS_RND(rnum, o)                       \
    AES64_128_INV_KS_RND_INS((rnum), (o) * 16, (o) * 16 + 8)
/* Perform computation of numbered last round of key schedule for AES-128
 * decryption. */
#define AES64_128_INV_KS_LRND(rnum, o)                      \
    AES64_128_KS_RND_INS((rnum), (o) * 16, (o) * 16 + 8)


/* Perform computation of one round of key schedule for AES-192 encryption. */
#define AES64_192_KS_RND_INS(rnum, o1, o2, o3)              \
            AES64KS1I(REG_T3, REG_T2, rnum)                 \
            AES64KS2(REG_T0, REG_T3, REG_T0)                \
            AES64KS2(REG_T1, REG_T0, REG_T1)                \
            AES64KS2(REG_T2, REG_T1, REG_T2)                \
            "sd        t0, " #o1 "(%[ks])\n\t"              \
            "sd        t1, " #o2 "(%[ks])\n\t"              \
            "sd        t2, " #o3 "(%[ks])\n\t"
/* Perform computation of one round of key schedule for AES-192 decryption. */
#define AES64_192_INV_KS_RND_INS(rnum, o1, o2, o3)          \
            AES64KS1I(REG_T3, REG_T2, rnum)                 \
            AES64KS2(REG_T0, REG_T3, REG_T0)                \
            AES64KS2(REG_T1, REG_T0, REG_T1)                \
            AES64KS2(REG_T2, REG_T1, REG_T2)                \
            AES64IM(REG_T3, REG_T0)                         \
            AES64IM(REG_T4, REG_T1)                         \
            AES64IM(REG_T5, REG_T2)                         \
            "sd        t3, " #o1 "(%[ks])\n\t"              \
            "sd        t4, " #o2 "(%[ks])\n\t"              \
            "sd        t5, " #o3 "(%[ks])\n\t"
/* Perform computation of last round of key schedule for AES-192 decryption. */
#define AES64_192_KS_LRND_INS(rnum, o1, o2)                 \
            AES64KS1I(REG_T3, REG_T2, rnum)                 \
            AES64KS2(REG_T0, REG_T3, REG_T0)                \
            AES64KS2(REG_T1, REG_T0, REG_T1)                \
            "sd        t0, " #o1 "(%[ks])\n\t"              \
            "sd        t1, " #o2 "(%[ks])\n\t"              \

/* Perform computation of numbered round of key schedule for AES-192 encryption.
 */
#define AES64_192_KS_RND(rnum)                              \
    AES64_192_KS_RND_INS((rnum), ((rnum) + 1) * 24,         \
        ((rnum) + 1) * 24 + 8, ((rnum) + 1) * 24 + 16)
/* Perform computation of numbered round of key schedule for AES-192 decryption.
 */
#define AES64_192_INV_KS_RND(rnum, o1, o2, o3)              \
    AES64_192_INV_KS_RND_INS((rnum), (o1) * 8, (o2) * 8,    \
        (o3) * 8)
/* Perform computation of numbered last round of key schedule for AES-192
 * encryption. */
#define AES64_192_KS_LRND(rnum)                             \
    AES64_192_KS_LRND_INS((rnum), ((rnum) + 1) * 24,        \
        ((rnum) + 1) * 24 + 8)
/* Perform computation of numbered last round of key schedule for AES-192
 * decryption. */
#define AES64_192_INV_KS_LRND(rnum)                         \
    AES64_192_KS_LRND_INS((rnum), 0, 8)


/* Perform computation of one round of key schedule for AES-256 encryption. */
#define AES64_256_KS_RND_INS(rnum, o1, o2, o3, o4)          \
            AES64KS1I(REG_T4, REG_T3, rnum)                 \
            AES64KS2(REG_T0, REG_T4, REG_T0)                \
            AES64KS2(REG_T1, REG_T0, REG_T1)                \
            AES64KS1I(REG_T4, REG_T1, 10)                   \
            AES64KS2(REG_T2, REG_T4, REG_T2)                \
            AES64KS2(REG_T3, REG_T2, REG_T3)                \
            "sd        t0, " #o1 "(%[ks])\n\t"              \
            "sd        t1, " #o2 "(%[ks])\n\t"              \
            "sd        t2, " #o3 "(%[ks])\n\t"              \
            "sd        t3, " #o4 "(%[ks])\n\t"
/* Perform computation of one round of key schedule for AES-256 decryption. */
#define AES64_256_INV_KS_RND_INS(rnum, o1, o2, o3, o4)      \
            AES64KS1I(REG_T4, REG_T3, rnum)                 \
            AES64KS2(REG_T0, REG_T4, REG_T0)                \
            AES64KS2(REG_T1, REG_T0, REG_T1)                \
            AES64KS1I(REG_T4, REG_T1, 10)                   \
            AES64KS2(REG_T2, REG_T4, REG_T2)                \
            AES64KS2(REG_T3, REG_T2, REG_T3)                \
            AES64IM(REG_T4, REG_T0)                         \
            AES64IM(REG_T5, REG_T1)                         \
            "sd        t4, " #o1 "(%[ks])\n\t"              \
            "sd        t5, " #o2 "(%[ks])\n\t"              \
            AES64IM(REG_T4, REG_T2)                         \
            AES64IM(REG_T5, REG_T3)                         \
            "sd        t4, " #o3 "(%[ks])\n\t"              \
            "sd        t5, " #o4 "(%[ks])\n\t"
/* Perform computation of last round of key schedule for AES-256 decryption. */
#define AES64_256_KS_LRND_INS(rnum, o1, o2)                 \
            AES64KS1I(REG_T4, REG_T3, rnum)                 \
            AES64KS2(REG_T0, REG_T4, REG_T0)                \
            AES64KS2(REG_T1, REG_T0, REG_T1)                \
            "sd        t0, " #o1 "(%[ks])\n\t"              \
            "sd        t1, " #o2 "(%[ks])\n\t"              \

/* Perform computation of numbered round of key schedule for AES-256 encryption.
 */
#define AES64_256_KS_RND(rnum)                              \
    AES64_256_KS_RND_INS((rnum), ((rnum) + 1) * 32,         \
        ((rnum) + 1) * 32 + 8, ((rnum) + 1) * 32 + 16,      \
        ((rnum) + 1) * 32 + 24)
/* Perform computation of numbered round of key schedule for AES-256 decryption.
 */
#define AES64_256_INV_KS_RND(rnum, o)                       \
    AES64_256_INV_KS_RND_INS((rnum), (o) * 32,              \
        (o) * 32 + 8, (o) * 32 - 16, (o) * 32 - 8)
/* Perform computation of numbered last round of key schedule for AES-256
 * encryption. */
#define AES64_256_KS_LRND(rnum)                             \
    AES64_256_KS_LRND_INS((rnum), ((rnum) + 1) * 32,        \
        ((rnum) + 1) * 32 + 8)
/* Perform computation of numbered last round of key schedule for AES-256
 * decryption. */
#define AES64_256_INV_KS_LRND(rnum)                         \
    AES64_256_KS_LRND_INS((rnum), 0, 8)

/* Set the key and/or IV into the AES object.
 *
 * Creates the key schedule from the key.
 * Uses Cryptographic instructions.
 *
 * @param [in] aes     AES object.
 * @param [in] key     Secret key to use.
 * @param [in] keyLen  Length of key in bytes.
 * @param [in] iv      Initialization Vector (IV) to use. May be NULL.
 * @param [in] dir     Direction of crypt: AES_ENCRYPT, AES_DECRYPT.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when aes or key is NULL.
 * @return  BAD_FUNC_ARG when keyLen/dir is not supported or valid.
 */
int wc_AesSetKey(Aes* aes, const byte* key, word32 keyLen, const byte* iv,
    int dir)
{
    int ret = 0;

    /* Validate parameters. */
    if ((aes == NULL) || (key == NULL)) {
        ret = BAD_FUNC_ARG;
    }
#ifdef WOLFSSL_AES_128
    else if ((keyLen == 16) && (dir == AES_ENCRYPTION)) {
        __asm__ __volatile__ (
            "ld        t0, 0(%[key])\n\t"
            "ld        t1, 8(%[key])\n\t"
            "sd        t0, 0(%[ks])\n\t"
            "sd        t1, 8(%[ks])\n\t"
            AES64_128_KS_RND(0)
            AES64_128_KS_RND(1)
            AES64_128_KS_RND(2)
            AES64_128_KS_RND(3)
            AES64_128_KS_RND(4)
            AES64_128_KS_RND(5)
            AES64_128_KS_RND(6)
            AES64_128_KS_RND(7)
            AES64_128_KS_RND(8)
            AES64_128_KS_RND(9)
            "sd        t0, 224(%[ks])\n\t"
            "sd        t1, 232(%[ks])\n\t"
            :
            : [ks] "r" (aes->key), [key] "r" (key)
            : "memory", "t0", "t1", "t2"
        );
        aes->rounds = 10;
    }
#ifdef HAVE_AES_DECRYPT
    else if ((keyLen == 16) && (dir == AES_DECRYPTION)) {
        __asm__ __volatile__ (
            "ld        t0, 0(%[key])\n\t"
            "ld        t1, 8(%[key])\n\t"
            "sd        t0, 160(%[ks])\n\t"
            "sd        t1, 168(%[ks])\n\t"
            AES64_128_INV_KS_RND(0, 9)
            AES64_128_INV_KS_RND(1, 8)
            AES64_128_INV_KS_RND(2, 7)
            AES64_128_INV_KS_RND(3, 6)
            AES64_128_INV_KS_RND(4, 5)
            AES64_128_INV_KS_RND(5, 4)
            AES64_128_INV_KS_RND(6, 3)
            AES64_128_INV_KS_RND(7, 2)
            AES64_128_INV_KS_RND(8, 1)
            AES64_128_INV_KS_LRND(9, 0)
            "sd        t4, 224(%[ks])\n\t"
            "sd        t5, 232(%[ks])\n\t"
            :
            : [ks] "r" (aes->key), [key] "r" (key)
            : "memory", "t0", "t1", "t2", "t3"
        );
        aes->rounds = 10;
    }
#endif
#endif
#ifdef WOLFSSL_AES_192
    else if ((keyLen == 24) && (dir == AES_ENCRYPTION)) {
        __asm__ __volatile__ (
            "ld        t0,  0(%[key])\n\t"
            "ld        t1,  8(%[key])\n\t"
            "ld        t2, 16(%[key])\n\t"
            "sd        t0,  0(%[ks])\n\t"
            "sd        t1,  8(%[ks])\n\t"
            "sd        t2, 16(%[ks])\n\t"
            AES64_192_KS_RND(0)
            AES64_192_KS_RND(1)
            AES64_192_KS_RND(2)
            AES64_192_KS_RND(3)
            AES64_192_KS_RND(4)
            AES64_192_KS_RND(5)
            AES64_192_KS_RND(6)
            AES64_192_KS_LRND(7)
            "sd        t0, 224(%[ks])\n\t"
            "sd        t1, 232(%[ks])\n\t"
            :
            : [ks] "r" (aes->key), [key] "r" (key)
            : "memory", "t0", "t1", "t2", "t3"
        );
        aes->rounds = 12;
    }
#ifdef HAVE_AES_DECRYPT
    else if ((keyLen == 24) && (dir == AES_DECRYPTION)) {
        __asm__ __volatile__ (
            "ld        t0,  0(%[key])\n\t"
            "ld        t1,  8(%[key])\n\t"
            "ld        t2, 16(%[key])\n\t"
            AES64IM(REG_T3, REG_T2)
            "sd        t0, 192(%[ks])\n\t"
            "sd        t1, 200(%[ks])\n\t"
            "sd        t3, 176(%[ks])\n\t"
            AES64_192_INV_KS_RND(0, 23, 20, 21)
            AES64_192_INV_KS_RND(1, 18, 19, 16)
            AES64_192_INV_KS_RND(2, 17, 14, 15)
            AES64_192_INV_KS_RND(3, 12, 13, 10)
            AES64_192_INV_KS_RND(4, 11,  8,  9)
            AES64_192_INV_KS_RND(5,  6,  7,  4)
            AES64_192_INV_KS_RND(6,  5,  2,  3)
            AES64_192_INV_KS_LRND(7)
            "sd        t4, 224(%[ks])\n\t"
            "sd        t5, 232(%[ks])\n\t"
            :
            : [ks] "r" (aes->key), [key] "r" (key)
            : "memory", "t0", "t1", "t2", "t3", "t4", "t5"
        );
        aes->rounds = 12;
    }
#endif
#endif
#ifdef WOLFSSL_AES_256
    else if ((keyLen == 32) && (dir == AES_ENCRYPTION)) {
        __asm__ __volatile__ (
            "ld        t0,  0(%[key])\n\t"
            "ld        t1,  8(%[key])\n\t"
            "ld        t2, 16(%[key])\n\t"
            "ld        t3, 24(%[key])\n\t"
            "sd        t0,  0(%[ks])\n\t"
            "sd        t1,  8(%[ks])\n\t"
            "sd        t2, 16(%[ks])\n\t"
            "sd        t3, 24(%[ks])\n\t"
            AES64_256_KS_RND(0)
            AES64_256_KS_RND(1)
            AES64_256_KS_RND(2)
            AES64_256_KS_RND(3)
            AES64_256_KS_RND(4)
            AES64_256_KS_RND(5)
            AES64_256_KS_LRND(6)
            :
            : [ks] "r" (aes->key), [key] "r" (key)
            : "memory", "t0", "t1", "t2", "t3", "t4"
        );
        aes->rounds = 14;
    }
#ifdef HAVE_AES_DECRYPT
    else if ((keyLen == 32) && (dir == AES_DECRYPTION)) {
        __asm__ __volatile__ (
            "ld        t0,  0(%[key])\n\t"
            "ld        t1,  8(%[key])\n\t"
            "ld        t2, 16(%[key])\n\t"
            "ld        t3, 24(%[key])\n\t"
            "sd        t0, 224(%[ks])\n\t"
            "sd        t1, 232(%[ks])\n\t"
            AES64IM(REG_T4, REG_T2)
            AES64IM(REG_T5, REG_T3)
            "sd        t4, 208(%[ks])\n\t"
            "sd        t5, 216(%[ks])\n\t"
            AES64_256_INV_KS_RND(0, 6)
            AES64_256_INV_KS_RND(1, 5)
            AES64_256_INV_KS_RND(2, 4)
            AES64_256_INV_KS_RND(3, 3)
            AES64_256_INV_KS_RND(4, 2)
            AES64_256_INV_KS_RND(5, 1)
            AES64_256_INV_KS_LRND(6)
            :
            : [ks] "r" (aes->key), [key] "r" (key)
            : "memory", "t0", "t1", "t2", "t3", "t4", "t5"
        );
        aes->rounds = 14;
    }
#endif
#endif
    else {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Set the IV. */
        ret = wc_AesSetIV(aes, iv);
    }
    if (ret == 0) {
        /* Finish setting the AES object. */
        aes->keylen = keyLen;
#if defined(WOLFSSL_AES_CFB) || defined(WOLFSSL_AES_COUNTER) || \
    defined(WOLFSSL_AES_OFB)
        aes->left = 0;
#endif
    }

    return ret;
}


/* AES middle round encryption with 64-bit registers. */
#define AES64ESM(rd, rs1, rs2)                      \
    ASM_WORD(0b00110110000000000000000000110011 |   \
             (rd << 7) | (rs1 << 15) | (rs2 << 20))
/* AES final round encryption with 64-bit registers. */
#define AES64ES(rd, rs1, rs2)                       \
    ASM_WORD(0b00110010000000000000000000110011 |   \
             (rd << 7) | (rs1 << 15) | (rs2 << 20))

/* Two rounds of encryption.
 * kr01 - offset of first half of key for second round.
 * kr02 - offset of second half of key for second round.
 * kr03 - offset of first half of key for next round.
 * kr04 - offset of second half of key for next round.
 */
#define AESENC_2_ROUNDS(kro1, kro2, kro3, kro4)     \
    "ld          a5, " #kro1 " (%[key])\n\t"        \
    "ld          a6, " #kro2 " (%[key])\n\t"        \
    AES64ESM(REG_T2, REG_T0, REG_T1)                \
    AES64ESM(REG_T3, REG_T1, REG_T0)                \
    "xor         t2, t2, a3\n\t"                    \
    "xor         t3, t3, a4\n\t"                    \
    AES64ESM(REG_T0, REG_T2, REG_T3)                \
    AES64ESM(REG_T1, REG_T3, REG_T2)                \
    "xor         t0, t0, a5\n\t"                    \
    "xor         t1, t1, a6\n\t"                    \
    "ld          a3, " #kro3 " (%[key])\n\t"        \
    "ld          a4, " #kro4 " (%[key])\n\t"

/* Last round of encryption. */
#define AESENC_LAST_ROUND()                         \
    AES64ES(REG_T2, REG_T0, REG_T1)                 \
    AES64ES(REG_T3, REG_T1, REG_T0)                 \
    "xor         t2, t2, a3\n\t"                    \
    "xor         t3, t3, a4\n\t"

/* AES middle round decryption with 64-bit registers. */
#define AES64DSM(rd, rs1, rs2)                      \
    ASM_WORD(0b00111110000000000000000000110011 |   \
             (rd << 7) | (rs1 << 15) | (rs2 << 20))
/* AES final round decryption with 64-bit registers. */
#define AES64DS(rd, rs1, rs2) \
    ASM_WORD(0b00111010000000000000000000110011 | \
             (rd << 7) | (rs1 << 15) | (rs2 << 20))

/* Two rounds of decryption.
 * kr01 - offset of first half of key for second round.
 * kr02 - offset of second half of key for second round.
 * kr03 - offset of first half of key for next round.
 * kr04 - offset of second half of key for next round.
 */
#define AESDEC_2_ROUNDS(kro1, kro2, kro3, kro4)     \
    "ld          a5, " #kro1 " (%[key])\n\t"        \
    "ld          a6, " #kro2 " (%[key])\n\t"        \
    AES64DSM(REG_T2, REG_T0, REG_T1)                \
    AES64DSM(REG_T3, REG_T1, REG_T0)                \
    "xor         t2, t2, a3\n\t"                    \
    "xor         t3, t3, a4\n\t"                    \
    AES64DSM(REG_T0, REG_T2, REG_T3)                \
    AES64DSM(REG_T1, REG_T3, REG_T2)                \
    "xor         t0, t0, a5\n\t"                    \
    "xor         t1, t1, a6\n\t"                    \
    "ld          a3, " #kro3 " (%[key])\n\t"        \
    "ld          a4, " #kro4 " (%[key])\n\t"

/* Last round of decryption. */
#define AESDEC_LAST_ROUND()                         \
    AES64DS(REG_T2, REG_T0, REG_T1)                 \
    AES64DS(REG_T3, REG_T1, REG_T0)                 \
    "xor         t2, t2, a3\n\t"                    \
    "xor         t3, t3, a4\n\t"                    \

#if defined(WOLFSSL_AES_DIRECT) || defined(HAVE_AES_CBC) || \
    defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
/* Encrypt a block using AES.
 *
 * @param [in]  aes  AES object.
 * @param [in]  in   Block to encrypt.
 * @param [out] out  Encrypted block.
 */
static void wc_AesEncrypt(Aes* aes, const byte* in, byte* out)
{
    __asm__ __volatile__ (
        "ld          t2, 0(%[in])\n\t"
        "ld          t3, 8(%[in])\n\t"
        "ld          a3, 0(%[key])\n\t"
        "ld          a4, 8(%[key])\n\t"
        "ld          a5, 16(%[key])\n\t"
        "ld          a6, 24(%[key])\n\t"
        "xor         t2, t2, a3\n\t"
        "xor         t3, t3, a4\n\t"
        AES64ESM(REG_T0, REG_T2, REG_T3)
        AES64ESM(REG_T1, REG_T3, REG_T2)
        "xor         t0, t0, a5\n\t"
        "xor         t1, t1, a6\n\t"
        "ld          a3, 32(%[key])\n\t"
        "ld          a4, 40(%[key])\n\t"
        AESENC_2_ROUNDS(48, 56, 64, 72)
        AESENC_2_ROUNDS(80, 88, 96, 104)
        AESENC_2_ROUNDS(112, 120, 128, 136)
        AESENC_2_ROUNDS(144, 152, 160, 168)
        "li          t4, 11\n\t"
        "ble         %[rounds], t4, L_aes_encrypt_done\n\t"
        AESENC_2_ROUNDS(176, 184, 192, 200)
        "li          t4, 13\n\t"
        "ble         %[rounds], t4, L_aes_encrypt_done\n\t"
        AESENC_2_ROUNDS(208, 216, 224, 232)
      "L_aes_encrypt_done:\n\t"
        AESENC_LAST_ROUND()
        "sd          t2, 0(%[out])\n\t"
        "sd          t3, 8(%[out])\n\t"
        :
        : [in] "r" (in), [out] "r" (out), [key] "r" (aes->key),
          [rounds] "r" (aes->rounds)
        : "memory", "t0", "t1", "t2", "t3", "t4", "a3", "a4", "a5", "a6"
    );
}
#endif

#ifdef HAVE_AES_DECRYPT
#if defined(WOLFSSL_AES_DIRECT) || defined(HAVE_AES_CBC)
/* Decrypt a block using AES.
 *
 * @param [in]  aes  AES object.
 * @param [in]  in   Block to decrypt.
 * @param [out] out  Decrypted block.
 */
static void wc_AesDecrypt(Aes* aes, const byte* in, byte* out)
{
    __asm__ __volatile__ (
        "ld          t2, 0(%[in])\n\t"
        "ld          t3, 8(%[in])\n\t"
        "ld          a3, 0(%[key])\n\t"
        "ld          a4, 8(%[key])\n\t"
        "ld          a5, 16(%[key])\n\t"
        "ld          a6, 24(%[key])\n\t"
        "xor         t2, t2, a3\n\t"
        "xor         t3, t3, a4\n\t"
        AES64DSM(REG_T0, REG_T2, REG_T3)
        AES64DSM(REG_T1, REG_T3, REG_T2)
        "xor         t0, t0, a5\n\t"
        "xor         t1, t1, a6\n\t"
        "ld          a3, 32(%[key])\n\t"
        "ld          a4, 40(%[key])\n\t"
        AESDEC_2_ROUNDS(48, 56, 64, 72)
        AESDEC_2_ROUNDS(80, 88, 96, 104)
        AESDEC_2_ROUNDS(112, 120, 128, 136)
        AESDEC_2_ROUNDS(144, 152, 160, 168)
        "li          t4, 11\n\t"
        "ble         %[rounds], t4, L_aes_decrypt_done\n\t"
        AESDEC_2_ROUNDS(176, 184, 192, 200)
        "li          t4, 13\n\t"
        "ble         %[rounds], t4, L_aes_decrypt_done\n\t"
        AESDEC_2_ROUNDS(208, 216, 224, 232)
      "L_aes_decrypt_done:\n\t"
        AESDEC_LAST_ROUND()
        "sd          t2, 0(%[out])\n\t"
        "sd          t3, 8(%[out])\n\t"
        :
        : [in] "r" (in), [out] "r" (out), [key] "r" (aes->key),
          [rounds] "r" (aes->rounds)
        : "memory", "t0", "t1", "t2", "t3", "t4", "a3", "a4", "a5", "a6"
    );
}
#endif
#endif /* HAVE_AES_DECRYPT */

#else

/*
 * Standard instructions implementation of base operations.
 */

/* Load a word with bytes reversed. */
#define LOAD_WORD_REV(r, o, p)                      \
        "lbu        t4, " #o "(" #p ")\n\t"         \
        "lbu        t5, " #o "+1(" #p ")\n\t"       \
        "lbu        t6, " #o "+2(" #p ")\n\t"       \
        "lbu        " #r ", " #o "+3(" #p ")\n\t"   \
        "slli       t4, t4, 24\n\t"                 \
        "slli       t5, t5, 16\n\t"                 \
        "slli       t6, t6, 8\n\t"                  \
        "or         " #r ", " #r ", t4\n\t"         \
        "or         " #r ", " #r ", t5\n\t"         \
        "or         " #r ", " #r ", t6\n\t"

/* Store a word with bytes reversed. */
#define STORE_WORD_REV(r, o, p)                     \
        "srli       t0, " #r ", 24\n\t"             \
        "srli       t1, " #r ", 16\n\t"             \
        "srli       t2, " #r ", 8\n\t"              \
        "sb         t0, " #o "+0(" #p ")\n\t"       \
        "sb         t1, " #o "+1(" #p ")\n\t"       \
        "sb         t2, " #o "+2(" #p ")\n\t"       \
        "sb         " #r ", " #o "+3(" #p ")\n\t"

/* AES encryption table. */
static const FLASH_QUALIFIER word32 Te[4][256] = {
{
    0xc66363a5U, 0xf87c7c84U, 0xee777799U, 0xf67b7b8dU,
    0xfff2f20dU, 0xd66b6bbdU, 0xde6f6fb1U, 0x91c5c554U,
    0x60303050U, 0x02010103U, 0xce6767a9U, 0x562b2b7dU,
    0xe7fefe19U, 0xb5d7d762U, 0x4dababe6U, 0xec76769aU,
    0x8fcaca45U, 0x1f82829dU, 0x89c9c940U, 0xfa7d7d87U,
    0xeffafa15U, 0xb25959ebU, 0x8e4747c9U, 0xfbf0f00bU,
    0x41adadecU, 0xb3d4d467U, 0x5fa2a2fdU, 0x45afafeaU,
    0x239c9cbfU, 0x53a4a4f7U, 0xe4727296U, 0x9bc0c05bU,
    0x75b7b7c2U, 0xe1fdfd1cU, 0x3d9393aeU, 0x4c26266aU,
    0x6c36365aU, 0x7e3f3f41U, 0xf5f7f702U, 0x83cccc4fU,
    0x6834345cU, 0x51a5a5f4U, 0xd1e5e534U, 0xf9f1f108U,
    0xe2717193U, 0xabd8d873U, 0x62313153U, 0x2a15153fU,
    0x0804040cU, 0x95c7c752U, 0x46232365U, 0x9dc3c35eU,
    0x30181828U, 0x379696a1U, 0x0a05050fU, 0x2f9a9ab5U,
    0x0e070709U, 0x24121236U, 0x1b80809bU, 0xdfe2e23dU,
    0xcdebeb26U, 0x4e272769U, 0x7fb2b2cdU, 0xea75759fU,
    0x1209091bU, 0x1d83839eU, 0x582c2c74U, 0x341a1a2eU,
    0x361b1b2dU, 0xdc6e6eb2U, 0xb45a5aeeU, 0x5ba0a0fbU,
    0xa45252f6U, 0x763b3b4dU, 0xb7d6d661U, 0x7db3b3ceU,
    0x5229297bU, 0xdde3e33eU, 0x5e2f2f71U, 0x13848497U,
    0xa65353f5U, 0xb9d1d168U, 0x00000000U, 0xc1eded2cU,
    0x40202060U, 0xe3fcfc1fU, 0x79b1b1c8U, 0xb65b5bedU,
    0xd46a6abeU, 0x8dcbcb46U, 0x67bebed9U, 0x7239394bU,
    0x944a4adeU, 0x984c4cd4U, 0xb05858e8U, 0x85cfcf4aU,
    0xbbd0d06bU, 0xc5efef2aU, 0x4faaaae5U, 0xedfbfb16U,
    0x864343c5U, 0x9a4d4dd7U, 0x66333355U, 0x11858594U,
    0x8a4545cfU, 0xe9f9f910U, 0x04020206U, 0xfe7f7f81U,
    0xa05050f0U, 0x783c3c44U, 0x259f9fbaU, 0x4ba8a8e3U,
    0xa25151f3U, 0x5da3a3feU, 0x804040c0U, 0x058f8f8aU,
    0x3f9292adU, 0x219d9dbcU, 0x70383848U, 0xf1f5f504U,
    0x63bcbcdfU, 0x77b6b6c1U, 0xafdada75U, 0x42212163U,
    0x20101030U, 0xe5ffff1aU, 0xfdf3f30eU, 0xbfd2d26dU,
    0x81cdcd4cU, 0x180c0c14U, 0x26131335U, 0xc3ecec2fU,
    0xbe5f5fe1U, 0x359797a2U, 0x884444ccU, 0x2e171739U,
    0x93c4c457U, 0x55a7a7f2U, 0xfc7e7e82U, 0x7a3d3d47U,
    0xc86464acU, 0xba5d5de7U, 0x3219192bU, 0xe6737395U,
    0xc06060a0U, 0x19818198U, 0x9e4f4fd1U, 0xa3dcdc7fU,
    0x44222266U, 0x542a2a7eU, 0x3b9090abU, 0x0b888883U,
    0x8c4646caU, 0xc7eeee29U, 0x6bb8b8d3U, 0x2814143cU,
    0xa7dede79U, 0xbc5e5ee2U, 0x160b0b1dU, 0xaddbdb76U,
    0xdbe0e03bU, 0x64323256U, 0x743a3a4eU, 0x140a0a1eU,
    0x924949dbU, 0x0c06060aU, 0x4824246cU, 0xb85c5ce4U,
    0x9fc2c25dU, 0xbdd3d36eU, 0x43acacefU, 0xc46262a6U,
    0x399191a8U, 0x319595a4U, 0xd3e4e437U, 0xf279798bU,
    0xd5e7e732U, 0x8bc8c843U, 0x6e373759U, 0xda6d6db7U,
    0x018d8d8cU, 0xb1d5d564U, 0x9c4e4ed2U, 0x49a9a9e0U,
    0xd86c6cb4U, 0xac5656faU, 0xf3f4f407U, 0xcfeaea25U,
    0xca6565afU, 0xf47a7a8eU, 0x47aeaee9U, 0x10080818U,
    0x6fbabad5U, 0xf0787888U, 0x4a25256fU, 0x5c2e2e72U,
    0x381c1c24U, 0x57a6a6f1U, 0x73b4b4c7U, 0x97c6c651U,
    0xcbe8e823U, 0xa1dddd7cU, 0xe874749cU, 0x3e1f1f21U,
    0x964b4bddU, 0x61bdbddcU, 0x0d8b8b86U, 0x0f8a8a85U,
    0xe0707090U, 0x7c3e3e42U, 0x71b5b5c4U, 0xcc6666aaU,
    0x904848d8U, 0x06030305U, 0xf7f6f601U, 0x1c0e0e12U,
    0xc26161a3U, 0x6a35355fU, 0xae5757f9U, 0x69b9b9d0U,
    0x17868691U, 0x99c1c158U, 0x3a1d1d27U, 0x279e9eb9U,
    0xd9e1e138U, 0xebf8f813U, 0x2b9898b3U, 0x22111133U,
    0xd26969bbU, 0xa9d9d970U, 0x078e8e89U, 0x339494a7U,
    0x2d9b9bb6U, 0x3c1e1e22U, 0x15878792U, 0xc9e9e920U,
    0x87cece49U, 0xaa5555ffU, 0x50282878U, 0xa5dfdf7aU,
    0x038c8c8fU, 0x59a1a1f8U, 0x09898980U, 0x1a0d0d17U,
    0x65bfbfdaU, 0xd7e6e631U, 0x844242c6U, 0xd06868b8U,
    0x824141c3U, 0x299999b0U, 0x5a2d2d77U, 0x1e0f0f11U,
    0x7bb0b0cbU, 0xa85454fcU, 0x6dbbbbd6U, 0x2c16163aU,
},
{
    0xa5c66363U, 0x84f87c7cU, 0x99ee7777U, 0x8df67b7bU,
    0x0dfff2f2U, 0xbdd66b6bU, 0xb1de6f6fU, 0x5491c5c5U,
    0x50603030U, 0x03020101U, 0xa9ce6767U, 0x7d562b2bU,
    0x19e7fefeU, 0x62b5d7d7U, 0xe64dababU, 0x9aec7676U,
    0x458fcacaU, 0x9d1f8282U, 0x4089c9c9U, 0x87fa7d7dU,
    0x15effafaU, 0xebb25959U, 0xc98e4747U, 0x0bfbf0f0U,
    0xec41adadU, 0x67b3d4d4U, 0xfd5fa2a2U, 0xea45afafU,
    0xbf239c9cU, 0xf753a4a4U, 0x96e47272U, 0x5b9bc0c0U,
    0xc275b7b7U, 0x1ce1fdfdU, 0xae3d9393U, 0x6a4c2626U,
    0x5a6c3636U, 0x417e3f3fU, 0x02f5f7f7U, 0x4f83ccccU,
    0x5c683434U, 0xf451a5a5U, 0x34d1e5e5U, 0x08f9f1f1U,
    0x93e27171U, 0x73abd8d8U, 0x53623131U, 0x3f2a1515U,
    0x0c080404U, 0x5295c7c7U, 0x65462323U, 0x5e9dc3c3U,
    0x28301818U, 0xa1379696U, 0x0f0a0505U, 0xb52f9a9aU,
    0x090e0707U, 0x36241212U, 0x9b1b8080U, 0x3ddfe2e2U,
    0x26cdebebU, 0x694e2727U, 0xcd7fb2b2U, 0x9fea7575U,
    0x1b120909U, 0x9e1d8383U, 0x74582c2cU, 0x2e341a1aU,
    0x2d361b1bU, 0xb2dc6e6eU, 0xeeb45a5aU, 0xfb5ba0a0U,
    0xf6a45252U, 0x4d763b3bU, 0x61b7d6d6U, 0xce7db3b3U,
    0x7b522929U, 0x3edde3e3U, 0x715e2f2fU, 0x97138484U,
    0xf5a65353U, 0x68b9d1d1U, 0x00000000U, 0x2cc1ededU,
    0x60402020U, 0x1fe3fcfcU, 0xc879b1b1U, 0xedb65b5bU,
    0xbed46a6aU, 0x468dcbcbU, 0xd967bebeU, 0x4b723939U,
    0xde944a4aU, 0xd4984c4cU, 0xe8b05858U, 0x4a85cfcfU,
    0x6bbbd0d0U, 0x2ac5efefU, 0xe54faaaaU, 0x16edfbfbU,
    0xc5864343U, 0xd79a4d4dU, 0x55663333U, 0x94118585U,
    0xcf8a4545U, 0x10e9f9f9U, 0x06040202U, 0x81fe7f7fU,
    0xf0a05050U, 0x44783c3cU, 0xba259f9fU, 0xe34ba8a8U,
    0xf3a25151U, 0xfe5da3a3U, 0xc0804040U, 0x8a058f8fU,
    0xad3f9292U, 0xbc219d9dU, 0x48703838U, 0x04f1f5f5U,
    0xdf63bcbcU, 0xc177b6b6U, 0x75afdadaU, 0x63422121U,
    0x30201010U, 0x1ae5ffffU, 0x0efdf3f3U, 0x6dbfd2d2U,
    0x4c81cdcdU, 0x14180c0cU, 0x35261313U, 0x2fc3ececU,
    0xe1be5f5fU, 0xa2359797U, 0xcc884444U, 0x392e1717U,
    0x5793c4c4U, 0xf255a7a7U, 0x82fc7e7eU, 0x477a3d3dU,
    0xacc86464U, 0xe7ba5d5dU, 0x2b321919U, 0x95e67373U,
    0xa0c06060U, 0x98198181U, 0xd19e4f4fU, 0x7fa3dcdcU,
    0x66442222U, 0x7e542a2aU, 0xab3b9090U, 0x830b8888U,
    0xca8c4646U, 0x29c7eeeeU, 0xd36bb8b8U, 0x3c281414U,
    0x79a7dedeU, 0xe2bc5e5eU, 0x1d160b0bU, 0x76addbdbU,
    0x3bdbe0e0U, 0x56643232U, 0x4e743a3aU, 0x1e140a0aU,
    0xdb924949U, 0x0a0c0606U, 0x6c482424U, 0xe4b85c5cU,
    0x5d9fc2c2U, 0x6ebdd3d3U, 0xef43acacU, 0xa6c46262U,
    0xa8399191U, 0xa4319595U, 0x37d3e4e4U, 0x8bf27979U,
    0x32d5e7e7U, 0x438bc8c8U, 0x596e3737U, 0xb7da6d6dU,
    0x8c018d8dU, 0x64b1d5d5U, 0xd29c4e4eU, 0xe049a9a9U,
    0xb4d86c6cU, 0xfaac5656U, 0x07f3f4f4U, 0x25cfeaeaU,
    0xafca6565U, 0x8ef47a7aU, 0xe947aeaeU, 0x18100808U,
    0xd56fbabaU, 0x88f07878U, 0x6f4a2525U, 0x725c2e2eU,
    0x24381c1cU, 0xf157a6a6U, 0xc773b4b4U, 0x5197c6c6U,
    0x23cbe8e8U, 0x7ca1ddddU, 0x9ce87474U, 0x213e1f1fU,
    0xdd964b4bU, 0xdc61bdbdU, 0x860d8b8bU, 0x850f8a8aU,
    0x90e07070U, 0x427c3e3eU, 0xc471b5b5U, 0xaacc6666U,
    0xd8904848U, 0x05060303U, 0x01f7f6f6U, 0x121c0e0eU,
    0xa3c26161U, 0x5f6a3535U, 0xf9ae5757U, 0xd069b9b9U,
    0x91178686U, 0x5899c1c1U, 0x273a1d1dU, 0xb9279e9eU,
    0x38d9e1e1U, 0x13ebf8f8U, 0xb32b9898U, 0x33221111U,
    0xbbd26969U, 0x70a9d9d9U, 0x89078e8eU, 0xa7339494U,
    0xb62d9b9bU, 0x223c1e1eU, 0x92158787U, 0x20c9e9e9U,
    0x4987ceceU, 0xffaa5555U, 0x78502828U, 0x7aa5dfdfU,
    0x8f038c8cU, 0xf859a1a1U, 0x80098989U, 0x171a0d0dU,
    0xda65bfbfU, 0x31d7e6e6U, 0xc6844242U, 0xb8d06868U,
    0xc3824141U, 0xb0299999U, 0x775a2d2dU, 0x111e0f0fU,
    0xcb7bb0b0U, 0xfca85454U, 0xd66dbbbbU, 0x3a2c1616U,
},
{
    0x63a5c663U, 0x7c84f87cU, 0x7799ee77U, 0x7b8df67bU,
    0xf20dfff2U, 0x6bbdd66bU, 0x6fb1de6fU, 0xc55491c5U,
    0x30506030U, 0x01030201U, 0x67a9ce67U, 0x2b7d562bU,
    0xfe19e7feU, 0xd762b5d7U, 0xabe64dabU, 0x769aec76U,
    0xca458fcaU, 0x829d1f82U, 0xc94089c9U, 0x7d87fa7dU,
    0xfa15effaU, 0x59ebb259U, 0x47c98e47U, 0xf00bfbf0U,
    0xadec41adU, 0xd467b3d4U, 0xa2fd5fa2U, 0xafea45afU,
    0x9cbf239cU, 0xa4f753a4U, 0x7296e472U, 0xc05b9bc0U,
    0xb7c275b7U, 0xfd1ce1fdU, 0x93ae3d93U, 0x266a4c26U,
    0x365a6c36U, 0x3f417e3fU, 0xf702f5f7U, 0xcc4f83ccU,
    0x345c6834U, 0xa5f451a5U, 0xe534d1e5U, 0xf108f9f1U,
    0x7193e271U, 0xd873abd8U, 0x31536231U, 0x153f2a15U,
    0x040c0804U, 0xc75295c7U, 0x23654623U, 0xc35e9dc3U,
    0x18283018U, 0x96a13796U, 0x050f0a05U, 0x9ab52f9aU,
    0x07090e07U, 0x12362412U, 0x809b1b80U, 0xe23ddfe2U,
    0xeb26cdebU, 0x27694e27U, 0xb2cd7fb2U, 0x759fea75U,
    0x091b1209U, 0x839e1d83U, 0x2c74582cU, 0x1a2e341aU,
    0x1b2d361bU, 0x6eb2dc6eU, 0x5aeeb45aU, 0xa0fb5ba0U,
    0x52f6a452U, 0x3b4d763bU, 0xd661b7d6U, 0xb3ce7db3U,
    0x297b5229U, 0xe33edde3U, 0x2f715e2fU, 0x84971384U,
    0x53f5a653U, 0xd168b9d1U, 0x00000000U, 0xed2cc1edU,
    0x20604020U, 0xfc1fe3fcU, 0xb1c879b1U, 0x5bedb65bU,
    0x6abed46aU, 0xcb468dcbU, 0xbed967beU, 0x394b7239U,
    0x4ade944aU, 0x4cd4984cU, 0x58e8b058U, 0xcf4a85cfU,
    0xd06bbbd0U, 0xef2ac5efU, 0xaae54faaU, 0xfb16edfbU,
    0x43c58643U, 0x4dd79a4dU, 0x33556633U, 0x85941185U,
    0x45cf8a45U, 0xf910e9f9U, 0x02060402U, 0x7f81fe7fU,
    0x50f0a050U, 0x3c44783cU, 0x9fba259fU, 0xa8e34ba8U,
    0x51f3a251U, 0xa3fe5da3U, 0x40c08040U, 0x8f8a058fU,
    0x92ad3f92U, 0x9dbc219dU, 0x38487038U, 0xf504f1f5U,
    0xbcdf63bcU, 0xb6c177b6U, 0xda75afdaU, 0x21634221U,
    0x10302010U, 0xff1ae5ffU, 0xf30efdf3U, 0xd26dbfd2U,
    0xcd4c81cdU, 0x0c14180cU, 0x13352613U, 0xec2fc3ecU,
    0x5fe1be5fU, 0x97a23597U, 0x44cc8844U, 0x17392e17U,
    0xc45793c4U, 0xa7f255a7U, 0x7e82fc7eU, 0x3d477a3dU,
    0x64acc864U, 0x5de7ba5dU, 0x192b3219U, 0x7395e673U,
    0x60a0c060U, 0x81981981U, 0x4fd19e4fU, 0xdc7fa3dcU,
    0x22664422U, 0x2a7e542aU, 0x90ab3b90U, 0x88830b88U,
    0x46ca8c46U, 0xee29c7eeU, 0xb8d36bb8U, 0x143c2814U,
    0xde79a7deU, 0x5ee2bc5eU, 0x0b1d160bU, 0xdb76addbU,
    0xe03bdbe0U, 0x32566432U, 0x3a4e743aU, 0x0a1e140aU,
    0x49db9249U, 0x060a0c06U, 0x246c4824U, 0x5ce4b85cU,
    0xc25d9fc2U, 0xd36ebdd3U, 0xacef43acU, 0x62a6c462U,
    0x91a83991U, 0x95a43195U, 0xe437d3e4U, 0x798bf279U,
    0xe732d5e7U, 0xc8438bc8U, 0x37596e37U, 0x6db7da6dU,
    0x8d8c018dU, 0xd564b1d5U, 0x4ed29c4eU, 0xa9e049a9U,
    0x6cb4d86cU, 0x56faac56U, 0xf407f3f4U, 0xea25cfeaU,
    0x65afca65U, 0x7a8ef47aU, 0xaee947aeU, 0x08181008U,
    0xbad56fbaU, 0x7888f078U, 0x256f4a25U, 0x2e725c2eU,
    0x1c24381cU, 0xa6f157a6U, 0xb4c773b4U, 0xc65197c6U,
    0xe823cbe8U, 0xdd7ca1ddU, 0x749ce874U, 0x1f213e1fU,
    0x4bdd964bU, 0xbddc61bdU, 0x8b860d8bU, 0x8a850f8aU,
    0x7090e070U, 0x3e427c3eU, 0xb5c471b5U, 0x66aacc66U,
    0x48d89048U, 0x03050603U, 0xf601f7f6U, 0x0e121c0eU,
    0x61a3c261U, 0x355f6a35U, 0x57f9ae57U, 0xb9d069b9U,
    0x86911786U, 0xc15899c1U, 0x1d273a1dU, 0x9eb9279eU,
    0xe138d9e1U, 0xf813ebf8U, 0x98b32b98U, 0x11332211U,
    0x69bbd269U, 0xd970a9d9U, 0x8e89078eU, 0x94a73394U,
    0x9bb62d9bU, 0x1e223c1eU, 0x87921587U, 0xe920c9e9U,
    0xce4987ceU, 0x55ffaa55U, 0x28785028U, 0xdf7aa5dfU,
    0x8c8f038cU, 0xa1f859a1U, 0x89800989U, 0x0d171a0dU,
    0xbfda65bfU, 0xe631d7e6U, 0x42c68442U, 0x68b8d068U,
    0x41c38241U, 0x99b02999U, 0x2d775a2dU, 0x0f111e0fU,
    0xb0cb7bb0U, 0x54fca854U, 0xbbd66dbbU, 0x163a2c16U,
},
{
    0x6363a5c6U, 0x7c7c84f8U, 0x777799eeU, 0x7b7b8df6U,
    0xf2f20dffU, 0x6b6bbdd6U, 0x6f6fb1deU, 0xc5c55491U,
    0x30305060U, 0x01010302U, 0x6767a9ceU, 0x2b2b7d56U,
    0xfefe19e7U, 0xd7d762b5U, 0xababe64dU, 0x76769aecU,
    0xcaca458fU, 0x82829d1fU, 0xc9c94089U, 0x7d7d87faU,
    0xfafa15efU, 0x5959ebb2U, 0x4747c98eU, 0xf0f00bfbU,
    0xadadec41U, 0xd4d467b3U, 0xa2a2fd5fU, 0xafafea45U,
    0x9c9cbf23U, 0xa4a4f753U, 0x727296e4U, 0xc0c05b9bU,
    0xb7b7c275U, 0xfdfd1ce1U, 0x9393ae3dU, 0x26266a4cU,
    0x36365a6cU, 0x3f3f417eU, 0xf7f702f5U, 0xcccc4f83U,
    0x34345c68U, 0xa5a5f451U, 0xe5e534d1U, 0xf1f108f9U,
    0x717193e2U, 0xd8d873abU, 0x31315362U, 0x15153f2aU,
    0x04040c08U, 0xc7c75295U, 0x23236546U, 0xc3c35e9dU,
    0x18182830U, 0x9696a137U, 0x05050f0aU, 0x9a9ab52fU,
    0x0707090eU, 0x12123624U, 0x80809b1bU, 0xe2e23ddfU,
    0xebeb26cdU, 0x2727694eU, 0xb2b2cd7fU, 0x75759feaU,
    0x09091b12U, 0x83839e1dU, 0x2c2c7458U, 0x1a1a2e34U,
    0x1b1b2d36U, 0x6e6eb2dcU, 0x5a5aeeb4U, 0xa0a0fb5bU,
    0x5252f6a4U, 0x3b3b4d76U, 0xd6d661b7U, 0xb3b3ce7dU,
    0x29297b52U, 0xe3e33eddU, 0x2f2f715eU, 0x84849713U,
    0x5353f5a6U, 0xd1d168b9U, 0x00000000U, 0xeded2cc1U,
    0x20206040U, 0xfcfc1fe3U, 0xb1b1c879U, 0x5b5bedb6U,
    0x6a6abed4U, 0xcbcb468dU, 0xbebed967U, 0x39394b72U,
    0x4a4ade94U, 0x4c4cd498U, 0x5858e8b0U, 0xcfcf4a85U,
    0xd0d06bbbU, 0xefef2ac5U, 0xaaaae54fU, 0xfbfb16edU,
    0x4343c586U, 0x4d4dd79aU, 0x33335566U, 0x85859411U,
    0x4545cf8aU, 0xf9f910e9U, 0x02020604U, 0x7f7f81feU,
    0x5050f0a0U, 0x3c3c4478U, 0x9f9fba25U, 0xa8a8e34bU,
    0x5151f3a2U, 0xa3a3fe5dU, 0x4040c080U, 0x8f8f8a05U,
    0x9292ad3fU, 0x9d9dbc21U, 0x38384870U, 0xf5f504f1U,
    0xbcbcdf63U, 0xb6b6c177U, 0xdada75afU, 0x21216342U,
    0x10103020U, 0xffff1ae5U, 0xf3f30efdU, 0xd2d26dbfU,
    0xcdcd4c81U, 0x0c0c1418U, 0x13133526U, 0xecec2fc3U,
    0x5f5fe1beU, 0x9797a235U, 0x4444cc88U, 0x1717392eU,
    0xc4c45793U, 0xa7a7f255U, 0x7e7e82fcU, 0x3d3d477aU,
    0x6464acc8U, 0x5d5de7baU, 0x19192b32U, 0x737395e6U,
    0x6060a0c0U, 0x81819819U, 0x4f4fd19eU, 0xdcdc7fa3U,
    0x22226644U, 0x2a2a7e54U, 0x9090ab3bU, 0x8888830bU,
    0x4646ca8cU, 0xeeee29c7U, 0xb8b8d36bU, 0x14143c28U,
    0xdede79a7U, 0x5e5ee2bcU, 0x0b0b1d16U, 0xdbdb76adU,
    0xe0e03bdbU, 0x32325664U, 0x3a3a4e74U, 0x0a0a1e14U,
    0x4949db92U, 0x06060a0cU, 0x24246c48U, 0x5c5ce4b8U,
    0xc2c25d9fU, 0xd3d36ebdU, 0xacacef43U, 0x6262a6c4U,
    0x9191a839U, 0x9595a431U, 0xe4e437d3U, 0x79798bf2U,
    0xe7e732d5U, 0xc8c8438bU, 0x3737596eU, 0x6d6db7daU,
    0x8d8d8c01U, 0xd5d564b1U, 0x4e4ed29cU, 0xa9a9e049U,
    0x6c6cb4d8U, 0x5656faacU, 0xf4f407f3U, 0xeaea25cfU,
    0x6565afcaU, 0x7a7a8ef4U, 0xaeaee947U, 0x08081810U,
    0xbabad56fU, 0x787888f0U, 0x25256f4aU, 0x2e2e725cU,
    0x1c1c2438U, 0xa6a6f157U, 0xb4b4c773U, 0xc6c65197U,
    0xe8e823cbU, 0xdddd7ca1U, 0x74749ce8U, 0x1f1f213eU,
    0x4b4bdd96U, 0xbdbddc61U, 0x8b8b860dU, 0x8a8a850fU,
    0x707090e0U, 0x3e3e427cU, 0xb5b5c471U, 0x6666aaccU,
    0x4848d890U, 0x03030506U, 0xf6f601f7U, 0x0e0e121cU,
    0x6161a3c2U, 0x35355f6aU, 0x5757f9aeU, 0xb9b9d069U,
    0x86869117U, 0xc1c15899U, 0x1d1d273aU, 0x9e9eb927U,
    0xe1e138d9U, 0xf8f813ebU, 0x9898b32bU, 0x11113322U,
    0x6969bbd2U, 0xd9d970a9U, 0x8e8e8907U, 0x9494a733U,
    0x9b9bb62dU, 0x1e1e223cU, 0x87879215U, 0xe9e920c9U,
    0xcece4987U, 0x5555ffaaU, 0x28287850U, 0xdfdf7aa5U,
    0x8c8c8f03U, 0xa1a1f859U, 0x89898009U, 0x0d0d171aU,
    0xbfbfda65U, 0xe6e631d7U, 0x4242c684U, 0x6868b8d0U,
    0x4141c382U, 0x9999b029U, 0x2d2d775aU, 0x0f0f111eU,
    0xb0b0cb7bU, 0x5454fca8U, 0xbbbbd66dU, 0x16163a2cU,
}
};

/* Round constant used in computing key schedule. */
static const FLASH_QUALIFIER word32 rcon[] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1B000000, 0x36000000,
    /* for 128-bit blocks, Rijndael never uses more than 10 rcon values */
};

#ifdef HAVE_AES_DECRYPT
/* AES decryption table. */
static const FLASH_QUALIFIER word32 Td[4][256] = {
{
    0x51f4a750U, 0x7e416553U, 0x1a17a4c3U, 0x3a275e96U,
    0x3bab6bcbU, 0x1f9d45f1U, 0xacfa58abU, 0x4be30393U,
    0x2030fa55U, 0xad766df6U, 0x88cc7691U, 0xf5024c25U,
    0x4fe5d7fcU, 0xc52acbd7U, 0x26354480U, 0xb562a38fU,
    0xdeb15a49U, 0x25ba1b67U, 0x45ea0e98U, 0x5dfec0e1U,
    0xc32f7502U, 0x814cf012U, 0x8d4697a3U, 0x6bd3f9c6U,
    0x038f5fe7U, 0x15929c95U, 0xbf6d7aebU, 0x955259daU,
    0xd4be832dU, 0x587421d3U, 0x49e06929U, 0x8ec9c844U,
    0x75c2896aU, 0xf48e7978U, 0x99583e6bU, 0x27b971ddU,
    0xbee14fb6U, 0xf088ad17U, 0xc920ac66U, 0x7dce3ab4U,
    0x63df4a18U, 0xe51a3182U, 0x97513360U, 0x62537f45U,
    0xb16477e0U, 0xbb6bae84U, 0xfe81a01cU, 0xf9082b94U,
    0x70486858U, 0x8f45fd19U, 0x94de6c87U, 0x527bf8b7U,
    0xab73d323U, 0x724b02e2U, 0xe31f8f57U, 0x6655ab2aU,
    0xb2eb2807U, 0x2fb5c203U, 0x86c57b9aU, 0xd33708a5U,
    0x302887f2U, 0x23bfa5b2U, 0x02036abaU, 0xed16825cU,
    0x8acf1c2bU, 0xa779b492U, 0xf307f2f0U, 0x4e69e2a1U,
    0x65daf4cdU, 0x0605bed5U, 0xd134621fU, 0xc4a6fe8aU,
    0x342e539dU, 0xa2f355a0U, 0x058ae132U, 0xa4f6eb75U,
    0x0b83ec39U, 0x4060efaaU, 0x5e719f06U, 0xbd6e1051U,
    0x3e218af9U, 0x96dd063dU, 0xdd3e05aeU, 0x4de6bd46U,
    0x91548db5U, 0x71c45d05U, 0x0406d46fU, 0x605015ffU,
    0x1998fb24U, 0xd6bde997U, 0x894043ccU, 0x67d99e77U,
    0xb0e842bdU, 0x07898b88U, 0xe7195b38U, 0x79c8eedbU,
    0xa17c0a47U, 0x7c420fe9U, 0xf8841ec9U, 0x00000000U,
    0x09808683U, 0x322bed48U, 0x1e1170acU, 0x6c5a724eU,
    0xfd0efffbU, 0x0f853856U, 0x3daed51eU, 0x362d3927U,
    0x0a0fd964U, 0x685ca621U, 0x9b5b54d1U, 0x24362e3aU,
    0x0c0a67b1U, 0x9357e70fU, 0xb4ee96d2U, 0x1b9b919eU,
    0x80c0c54fU, 0x61dc20a2U, 0x5a774b69U, 0x1c121a16U,
    0xe293ba0aU, 0xc0a02ae5U, 0x3c22e043U, 0x121b171dU,
    0x0e090d0bU, 0xf28bc7adU, 0x2db6a8b9U, 0x141ea9c8U,
    0x57f11985U, 0xaf75074cU, 0xee99ddbbU, 0xa37f60fdU,
    0xf701269fU, 0x5c72f5bcU, 0x44663bc5U, 0x5bfb7e34U,
    0x8b432976U, 0xcb23c6dcU, 0xb6edfc68U, 0xb8e4f163U,
    0xd731dccaU, 0x42638510U, 0x13972240U, 0x84c61120U,
    0x854a247dU, 0xd2bb3df8U, 0xaef93211U, 0xc729a16dU,
    0x1d9e2f4bU, 0xdcb230f3U, 0x0d8652ecU, 0x77c1e3d0U,
    0x2bb3166cU, 0xa970b999U, 0x119448faU, 0x47e96422U,
    0xa8fc8cc4U, 0xa0f03f1aU, 0x567d2cd8U, 0x223390efU,
    0x87494ec7U, 0xd938d1c1U, 0x8ccaa2feU, 0x98d40b36U,
    0xa6f581cfU, 0xa57ade28U, 0xdab78e26U, 0x3fadbfa4U,
    0x2c3a9de4U, 0x5078920dU, 0x6a5fcc9bU, 0x547e4662U,
    0xf68d13c2U, 0x90d8b8e8U, 0x2e39f75eU, 0x82c3aff5U,
    0x9f5d80beU, 0x69d0937cU, 0x6fd52da9U, 0xcf2512b3U,
    0xc8ac993bU, 0x10187da7U, 0xe89c636eU, 0xdb3bbb7bU,
    0xcd267809U, 0x6e5918f4U, 0xec9ab701U, 0x834f9aa8U,
    0xe6956e65U, 0xaaffe67eU, 0x21bccf08U, 0xef15e8e6U,
    0xbae79bd9U, 0x4a6f36ceU, 0xea9f09d4U, 0x29b07cd6U,
    0x31a4b2afU, 0x2a3f2331U, 0xc6a59430U, 0x35a266c0U,
    0x744ebc37U, 0xfc82caa6U, 0xe090d0b0U, 0x33a7d815U,
    0xf104984aU, 0x41ecdaf7U, 0x7fcd500eU, 0x1791f62fU,
    0x764dd68dU, 0x43efb04dU, 0xccaa4d54U, 0xe49604dfU,
    0x9ed1b5e3U, 0x4c6a881bU, 0xc12c1fb8U, 0x4665517fU,
    0x9d5eea04U, 0x018c355dU, 0xfa877473U, 0xfb0b412eU,
    0xb3671d5aU, 0x92dbd252U, 0xe9105633U, 0x6dd64713U,
    0x9ad7618cU, 0x37a10c7aU, 0x59f8148eU, 0xeb133c89U,
    0xcea927eeU, 0xb761c935U, 0xe11ce5edU, 0x7a47b13cU,
    0x9cd2df59U, 0x55f2733fU, 0x1814ce79U, 0x73c737bfU,
    0x53f7cdeaU, 0x5ffdaa5bU, 0xdf3d6f14U, 0x7844db86U,
    0xcaaff381U, 0xb968c43eU, 0x3824342cU, 0xc2a3405fU,
    0x161dc372U, 0xbce2250cU, 0x283c498bU, 0xff0d9541U,
    0x39a80171U, 0x080cb3deU, 0xd8b4e49cU, 0x6456c190U,
    0x7bcb8461U, 0xd532b670U, 0x486c5c74U, 0xd0b85742U,
},
{
    0x5051f4a7U, 0x537e4165U, 0xc31a17a4U, 0x963a275eU,
    0xcb3bab6bU, 0xf11f9d45U, 0xabacfa58U, 0x934be303U,
    0x552030faU, 0xf6ad766dU, 0x9188cc76U, 0x25f5024cU,
    0xfc4fe5d7U, 0xd7c52acbU, 0x80263544U, 0x8fb562a3U,
    0x49deb15aU, 0x6725ba1bU, 0x9845ea0eU, 0xe15dfec0U,
    0x02c32f75U, 0x12814cf0U, 0xa38d4697U, 0xc66bd3f9U,
    0xe7038f5fU, 0x9515929cU, 0xebbf6d7aU, 0xda955259U,
    0x2dd4be83U, 0xd3587421U, 0x2949e069U, 0x448ec9c8U,
    0x6a75c289U, 0x78f48e79U, 0x6b99583eU, 0xdd27b971U,
    0xb6bee14fU, 0x17f088adU, 0x66c920acU, 0xb47dce3aU,
    0x1863df4aU, 0x82e51a31U, 0x60975133U, 0x4562537fU,
    0xe0b16477U, 0x84bb6baeU, 0x1cfe81a0U, 0x94f9082bU,
    0x58704868U, 0x198f45fdU, 0x8794de6cU, 0xb7527bf8U,
    0x23ab73d3U, 0xe2724b02U, 0x57e31f8fU, 0x2a6655abU,
    0x07b2eb28U, 0x032fb5c2U, 0x9a86c57bU, 0xa5d33708U,
    0xf2302887U, 0xb223bfa5U, 0xba02036aU, 0x5ced1682U,
    0x2b8acf1cU, 0x92a779b4U, 0xf0f307f2U, 0xa14e69e2U,
    0xcd65daf4U, 0xd50605beU, 0x1fd13462U, 0x8ac4a6feU,
    0x9d342e53U, 0xa0a2f355U, 0x32058ae1U, 0x75a4f6ebU,
    0x390b83ecU, 0xaa4060efU, 0x065e719fU, 0x51bd6e10U,
    0xf93e218aU, 0x3d96dd06U, 0xaedd3e05U, 0x464de6bdU,
    0xb591548dU, 0x0571c45dU, 0x6f0406d4U, 0xff605015U,
    0x241998fbU, 0x97d6bde9U, 0xcc894043U, 0x7767d99eU,
    0xbdb0e842U, 0x8807898bU, 0x38e7195bU, 0xdb79c8eeU,
    0x47a17c0aU, 0xe97c420fU, 0xc9f8841eU, 0x00000000U,
    0x83098086U, 0x48322bedU, 0xac1e1170U, 0x4e6c5a72U,
    0xfbfd0effU, 0x560f8538U, 0x1e3daed5U, 0x27362d39U,
    0x640a0fd9U, 0x21685ca6U, 0xd19b5b54U, 0x3a24362eU,
    0xb10c0a67U, 0x0f9357e7U, 0xd2b4ee96U, 0x9e1b9b91U,
    0x4f80c0c5U, 0xa261dc20U, 0x695a774bU, 0x161c121aU,
    0x0ae293baU, 0xe5c0a02aU, 0x433c22e0U, 0x1d121b17U,
    0x0b0e090dU, 0xadf28bc7U, 0xb92db6a8U, 0xc8141ea9U,
    0x8557f119U, 0x4caf7507U, 0xbbee99ddU, 0xfda37f60U,
    0x9ff70126U, 0xbc5c72f5U, 0xc544663bU, 0x345bfb7eU,
    0x768b4329U, 0xdccb23c6U, 0x68b6edfcU, 0x63b8e4f1U,
    0xcad731dcU, 0x10426385U, 0x40139722U, 0x2084c611U,
    0x7d854a24U, 0xf8d2bb3dU, 0x11aef932U, 0x6dc729a1U,
    0x4b1d9e2fU, 0xf3dcb230U, 0xec0d8652U, 0xd077c1e3U,
    0x6c2bb316U, 0x99a970b9U, 0xfa119448U, 0x2247e964U,
    0xc4a8fc8cU, 0x1aa0f03fU, 0xd8567d2cU, 0xef223390U,
    0xc787494eU, 0xc1d938d1U, 0xfe8ccaa2U, 0x3698d40bU,
    0xcfa6f581U, 0x28a57adeU, 0x26dab78eU, 0xa43fadbfU,
    0xe42c3a9dU, 0x0d507892U, 0x9b6a5fccU, 0x62547e46U,
    0xc2f68d13U, 0xe890d8b8U, 0x5e2e39f7U, 0xf582c3afU,
    0xbe9f5d80U, 0x7c69d093U, 0xa96fd52dU, 0xb3cf2512U,
    0x3bc8ac99U, 0xa710187dU, 0x6ee89c63U, 0x7bdb3bbbU,
    0x09cd2678U, 0xf46e5918U, 0x01ec9ab7U, 0xa8834f9aU,
    0x65e6956eU, 0x7eaaffe6U, 0x0821bccfU, 0xe6ef15e8U,
    0xd9bae79bU, 0xce4a6f36U, 0xd4ea9f09U, 0xd629b07cU,
    0xaf31a4b2U, 0x312a3f23U, 0x30c6a594U, 0xc035a266U,
    0x37744ebcU, 0xa6fc82caU, 0xb0e090d0U, 0x1533a7d8U,
    0x4af10498U, 0xf741ecdaU, 0x0e7fcd50U, 0x2f1791f6U,
    0x8d764dd6U, 0x4d43efb0U, 0x54ccaa4dU, 0xdfe49604U,
    0xe39ed1b5U, 0x1b4c6a88U, 0xb8c12c1fU, 0x7f466551U,
    0x049d5eeaU, 0x5d018c35U, 0x73fa8774U, 0x2efb0b41U,
    0x5ab3671dU, 0x5292dbd2U, 0x33e91056U, 0x136dd647U,
    0x8c9ad761U, 0x7a37a10cU, 0x8e59f814U, 0x89eb133cU,
    0xeecea927U, 0x35b761c9U, 0xede11ce5U, 0x3c7a47b1U,
    0x599cd2dfU, 0x3f55f273U, 0x791814ceU, 0xbf73c737U,
    0xea53f7cdU, 0x5b5ffdaaU, 0x14df3d6fU, 0x867844dbU,
    0x81caaff3U, 0x3eb968c4U, 0x2c382434U, 0x5fc2a340U,
    0x72161dc3U, 0x0cbce225U, 0x8b283c49U, 0x41ff0d95U,
    0x7139a801U, 0xde080cb3U, 0x9cd8b4e4U, 0x906456c1U,
    0x617bcb84U, 0x70d532b6U, 0x74486c5cU, 0x42d0b857U,
},
{
    0xa75051f4U, 0x65537e41U, 0xa4c31a17U, 0x5e963a27U,
    0x6bcb3babU, 0x45f11f9dU, 0x58abacfaU, 0x03934be3U,
    0xfa552030U, 0x6df6ad76U, 0x769188ccU, 0x4c25f502U,
    0xd7fc4fe5U, 0xcbd7c52aU, 0x44802635U, 0xa38fb562U,
    0x5a49deb1U, 0x1b6725baU, 0x0e9845eaU, 0xc0e15dfeU,
    0x7502c32fU, 0xf012814cU, 0x97a38d46U, 0xf9c66bd3U,
    0x5fe7038fU, 0x9c951592U, 0x7aebbf6dU, 0x59da9552U,
    0x832dd4beU, 0x21d35874U, 0x692949e0U, 0xc8448ec9U,
    0x896a75c2U, 0x7978f48eU, 0x3e6b9958U, 0x71dd27b9U,
    0x4fb6bee1U, 0xad17f088U, 0xac66c920U, 0x3ab47dceU,
    0x4a1863dfU, 0x3182e51aU, 0x33609751U, 0x7f456253U,
    0x77e0b164U, 0xae84bb6bU, 0xa01cfe81U, 0x2b94f908U,
    0x68587048U, 0xfd198f45U, 0x6c8794deU, 0xf8b7527bU,
    0xd323ab73U, 0x02e2724bU, 0x8f57e31fU, 0xab2a6655U,
    0x2807b2ebU, 0xc2032fb5U, 0x7b9a86c5U, 0x08a5d337U,
    0x87f23028U, 0xa5b223bfU, 0x6aba0203U, 0x825ced16U,
    0x1c2b8acfU, 0xb492a779U, 0xf2f0f307U, 0xe2a14e69U,
    0xf4cd65daU, 0xbed50605U, 0x621fd134U, 0xfe8ac4a6U,
    0x539d342eU, 0x55a0a2f3U, 0xe132058aU, 0xeb75a4f6U,
    0xec390b83U, 0xefaa4060U, 0x9f065e71U, 0x1051bd6eU,
    0x8af93e21U, 0x063d96ddU, 0x05aedd3eU, 0xbd464de6U,
    0x8db59154U, 0x5d0571c4U, 0xd46f0406U, 0x15ff6050U,
    0xfb241998U, 0xe997d6bdU, 0x43cc8940U, 0x9e7767d9U,
    0x42bdb0e8U, 0x8b880789U, 0x5b38e719U, 0xeedb79c8U,
    0x0a47a17cU, 0x0fe97c42U, 0x1ec9f884U, 0x00000000U,
    0x86830980U, 0xed48322bU, 0x70ac1e11U, 0x724e6c5aU,
    0xfffbfd0eU, 0x38560f85U, 0xd51e3daeU, 0x3927362dU,
    0xd9640a0fU, 0xa621685cU, 0x54d19b5bU, 0x2e3a2436U,
    0x67b10c0aU, 0xe70f9357U, 0x96d2b4eeU, 0x919e1b9bU,
    0xc54f80c0U, 0x20a261dcU, 0x4b695a77U, 0x1a161c12U,
    0xba0ae293U, 0x2ae5c0a0U, 0xe0433c22U, 0x171d121bU,
    0x0d0b0e09U, 0xc7adf28bU, 0xa8b92db6U, 0xa9c8141eU,
    0x198557f1U, 0x074caf75U, 0xddbbee99U, 0x60fda37fU,
    0x269ff701U, 0xf5bc5c72U, 0x3bc54466U, 0x7e345bfbU,
    0x29768b43U, 0xc6dccb23U, 0xfc68b6edU, 0xf163b8e4U,
    0xdccad731U, 0x85104263U, 0x22401397U, 0x112084c6U,
    0x247d854aU, 0x3df8d2bbU, 0x3211aef9U, 0xa16dc729U,
    0x2f4b1d9eU, 0x30f3dcb2U, 0x52ec0d86U, 0xe3d077c1U,
    0x166c2bb3U, 0xb999a970U, 0x48fa1194U, 0x642247e9U,
    0x8cc4a8fcU, 0x3f1aa0f0U, 0x2cd8567dU, 0x90ef2233U,
    0x4ec78749U, 0xd1c1d938U, 0xa2fe8ccaU, 0x0b3698d4U,
    0x81cfa6f5U, 0xde28a57aU, 0x8e26dab7U, 0xbfa43fadU,
    0x9de42c3aU, 0x920d5078U, 0xcc9b6a5fU, 0x4662547eU,
    0x13c2f68dU, 0xb8e890d8U, 0xf75e2e39U, 0xaff582c3U,
    0x80be9f5dU, 0x937c69d0U, 0x2da96fd5U, 0x12b3cf25U,
    0x993bc8acU, 0x7da71018U, 0x636ee89cU, 0xbb7bdb3bU,
    0x7809cd26U, 0x18f46e59U, 0xb701ec9aU, 0x9aa8834fU,
    0x6e65e695U, 0xe67eaaffU, 0xcf0821bcU, 0xe8e6ef15U,
    0x9bd9bae7U, 0x36ce4a6fU, 0x09d4ea9fU, 0x7cd629b0U,
    0xb2af31a4U, 0x23312a3fU, 0x9430c6a5U, 0x66c035a2U,
    0xbc37744eU, 0xcaa6fc82U, 0xd0b0e090U, 0xd81533a7U,
    0x984af104U, 0xdaf741ecU, 0x500e7fcdU, 0xf62f1791U,
    0xd68d764dU, 0xb04d43efU, 0x4d54ccaaU, 0x04dfe496U,
    0xb5e39ed1U, 0x881b4c6aU, 0x1fb8c12cU, 0x517f4665U,
    0xea049d5eU, 0x355d018cU, 0x7473fa87U, 0x412efb0bU,
    0x1d5ab367U, 0xd25292dbU, 0x5633e910U, 0x47136dd6U,
    0x618c9ad7U, 0x0c7a37a1U, 0x148e59f8U, 0x3c89eb13U,
    0x27eecea9U, 0xc935b761U, 0xe5ede11cU, 0xb13c7a47U,
    0xdf599cd2U, 0x733f55f2U, 0xce791814U, 0x37bf73c7U,
    0xcdea53f7U, 0xaa5b5ffdU, 0x6f14df3dU, 0xdb867844U,
    0xf381caafU, 0xc43eb968U, 0x342c3824U, 0x405fc2a3U,
    0xc372161dU, 0x250cbce2U, 0x498b283cU, 0x9541ff0dU,
    0x017139a8U, 0xb3de080cU, 0xe49cd8b4U, 0xc1906456U,
    0x84617bcbU, 0xb670d532U, 0x5c74486cU, 0x5742d0b8U,
},
{
    0xf4a75051U, 0x4165537eU, 0x17a4c31aU, 0x275e963aU,
    0xab6bcb3bU, 0x9d45f11fU, 0xfa58abacU, 0xe303934bU,
    0x30fa5520U, 0x766df6adU, 0xcc769188U, 0x024c25f5U,
    0xe5d7fc4fU, 0x2acbd7c5U, 0x35448026U, 0x62a38fb5U,
    0xb15a49deU, 0xba1b6725U, 0xea0e9845U, 0xfec0e15dU,
    0x2f7502c3U, 0x4cf01281U, 0x4697a38dU, 0xd3f9c66bU,
    0x8f5fe703U, 0x929c9515U, 0x6d7aebbfU, 0x5259da95U,
    0xbe832dd4U, 0x7421d358U, 0xe0692949U, 0xc9c8448eU,
    0xc2896a75U, 0x8e7978f4U, 0x583e6b99U, 0xb971dd27U,
    0xe14fb6beU, 0x88ad17f0U, 0x20ac66c9U, 0xce3ab47dU,
    0xdf4a1863U, 0x1a3182e5U, 0x51336097U, 0x537f4562U,
    0x6477e0b1U, 0x6bae84bbU, 0x81a01cfeU, 0x082b94f9U,
    0x48685870U, 0x45fd198fU, 0xde6c8794U, 0x7bf8b752U,
    0x73d323abU, 0x4b02e272U, 0x1f8f57e3U, 0x55ab2a66U,
    0xeb2807b2U, 0xb5c2032fU, 0xc57b9a86U, 0x3708a5d3U,
    0x2887f230U, 0xbfa5b223U, 0x036aba02U, 0x16825cedU,
    0xcf1c2b8aU, 0x79b492a7U, 0x07f2f0f3U, 0x69e2a14eU,
    0xdaf4cd65U, 0x05bed506U, 0x34621fd1U, 0xa6fe8ac4U,
    0x2e539d34U, 0xf355a0a2U, 0x8ae13205U, 0xf6eb75a4U,
    0x83ec390bU, 0x60efaa40U, 0x719f065eU, 0x6e1051bdU,
    0x218af93eU, 0xdd063d96U, 0x3e05aeddU, 0xe6bd464dU,
    0x548db591U, 0xc45d0571U, 0x06d46f04U, 0x5015ff60U,
    0x98fb2419U, 0xbde997d6U, 0x4043cc89U, 0xd99e7767U,
    0xe842bdb0U, 0x898b8807U, 0x195b38e7U, 0xc8eedb79U,
    0x7c0a47a1U, 0x420fe97cU, 0x841ec9f8U, 0x00000000U,
    0x80868309U, 0x2bed4832U, 0x1170ac1eU, 0x5a724e6cU,
    0x0efffbfdU, 0x8538560fU, 0xaed51e3dU, 0x2d392736U,
    0x0fd9640aU, 0x5ca62168U, 0x5b54d19bU, 0x362e3a24U,
    0x0a67b10cU, 0x57e70f93U, 0xee96d2b4U, 0x9b919e1bU,
    0xc0c54f80U, 0xdc20a261U, 0x774b695aU, 0x121a161cU,
    0x93ba0ae2U, 0xa02ae5c0U, 0x22e0433cU, 0x1b171d12U,
    0x090d0b0eU, 0x8bc7adf2U, 0xb6a8b92dU, 0x1ea9c814U,
    0xf1198557U, 0x75074cafU, 0x99ddbbeeU, 0x7f60fda3U,
    0x01269ff7U, 0x72f5bc5cU, 0x663bc544U, 0xfb7e345bU,
    0x4329768bU, 0x23c6dccbU, 0xedfc68b6U, 0xe4f163b8U,
    0x31dccad7U, 0x63851042U, 0x97224013U, 0xc6112084U,
    0x4a247d85U, 0xbb3df8d2U, 0xf93211aeU, 0x29a16dc7U,
    0x9e2f4b1dU, 0xb230f3dcU, 0x8652ec0dU, 0xc1e3d077U,
    0xb3166c2bU, 0x70b999a9U, 0x9448fa11U, 0xe9642247U,
    0xfc8cc4a8U, 0xf03f1aa0U, 0x7d2cd856U, 0x3390ef22U,
    0x494ec787U, 0x38d1c1d9U, 0xcaa2fe8cU, 0xd40b3698U,
    0xf581cfa6U, 0x7ade28a5U, 0xb78e26daU, 0xadbfa43fU,
    0x3a9de42cU, 0x78920d50U, 0x5fcc9b6aU, 0x7e466254U,
    0x8d13c2f6U, 0xd8b8e890U, 0x39f75e2eU, 0xc3aff582U,
    0x5d80be9fU, 0xd0937c69U, 0xd52da96fU, 0x2512b3cfU,
    0xac993bc8U, 0x187da710U, 0x9c636ee8U, 0x3bbb7bdbU,
    0x267809cdU, 0x5918f46eU, 0x9ab701ecU, 0x4f9aa883U,
    0x956e65e6U, 0xffe67eaaU, 0xbccf0821U, 0x15e8e6efU,
    0xe79bd9baU, 0x6f36ce4aU, 0x9f09d4eaU, 0xb07cd629U,
    0xa4b2af31U, 0x3f23312aU, 0xa59430c6U, 0xa266c035U,
    0x4ebc3774U, 0x82caa6fcU, 0x90d0b0e0U, 0xa7d81533U,
    0x04984af1U, 0xecdaf741U, 0xcd500e7fU, 0x91f62f17U,
    0x4dd68d76U, 0xefb04d43U, 0xaa4d54ccU, 0x9604dfe4U,
    0xd1b5e39eU, 0x6a881b4cU, 0x2c1fb8c1U, 0x65517f46U,
    0x5eea049dU, 0x8c355d01U, 0x877473faU, 0x0b412efbU,
    0x671d5ab3U, 0xdbd25292U, 0x105633e9U, 0xd647136dU,
    0xd7618c9aU, 0xa10c7a37U, 0xf8148e59U, 0x133c89ebU,
    0xa927eeceU, 0x61c935b7U, 0x1ce5ede1U, 0x47b13c7aU,
    0xd2df599cU, 0xf2733f55U, 0x14ce7918U, 0xc737bf73U,
    0xf7cdea53U, 0xfdaa5b5fU, 0x3d6f14dfU, 0x44db8678U,
    0xaff381caU, 0x68c43eb9U, 0x24342c38U, 0xa3405fc2U,
    0x1dc37216U, 0xe2250cbcU, 0x3c498b28U, 0x0d9541ffU,
    0xa8017139U, 0x0cb3de08U, 0xb4e49cd8U, 0x56c19064U,
    0xcb84617bU, 0x32b670d5U, 0x6c5c7448U, 0xb85742d0U,
}
};

#endif /* HAVE_AES_DECRYPT */

/* AES substitute rotated word with round constant application. */
#define AES_SUB_ROT_WORD_RCON(s)            \
            "andi   t5, " #s ", 0xff\n\t"   \
            "slli   t5, t5, 2\n\t"          \
            "add    t5, t5, %[te]\n\t"      \
            "lw     t5, (t5)\n\t"           \
            "li     t6, 0x0000ff00\n\t"     \
            "and    t5, t5, t6\n\t"         \
            "xor    t0, t0, t5\n\t"         \
                                            \
            "srli   t5, " #s ", 22\n\t"     \
            "andi   t5, t5, 0x3fc\n\t"      \
            "add    t5, t5, %[te]\n\t"      \
            "addi   t5, t5, 0x400\n\t"      \
            "lbu    t5, (t5)\n\t"           \
            "xor    t0, t0, t5\n\t"         \
                                            \
            "srli   t5, " #s ", 14\n\t"     \
            "andi   t5, t5, 0x3fc\n\t"      \
            "add    t5, t5, %[te]\n\t"      \
            "li     t6, 0x800\n\t"          \
            "add    t5, t5, t6\n\t"         \
            "lw     t5, (t5)\n\t"           \
            "li     t6, 0xff000000\n\t"     \
            "and    t5, t5, t6\n\t"         \
            "xor    t0, t0, t5\n\t"         \
                                            \
            "srli   t5, " #s ", 6\n\t"      \
            "andi   t5, t5, 0x3fc\n\t"      \
            "add    t5, t5, %[te]\n\t"      \
            "li     t6, 0xc00\n\t"          \
            "add    t5, t5, t6\n\t"         \
            "lw     t5, (t5)\n\t"           \
            "li     t6, 0x00ff0000\n\t"     \
            "and    t5, t5, t6\n\t"         \
            "xor    t0, t0, t5\n\t"         \
                                            \
            "add    t5, %[rcon], a5\n\t"    \
            "lw     t5, (t5)\n\t"           \
            "xor    t0, t0, t5\n\t"

/* AES substitute word. */
#define AES_SUB_WORD(s)                     \
            "srli   t5, " #s ", 6\n\t"      \
            "andi   t5, t5, 0x3fc\n\t"      \
            "add    t5, t5, %[te]\n\t"      \
            "lw     t5, (t5)\n\t"           \
            "li     t6, 0x0000ff00\n\t"     \
            "and    t5, t5, t6\n\t"         \
            "xor    a6, a6, t5\n\t"         \
                                            \
            "andi   t5, " #s ", 0xff\n\t"   \
            "slli   t5, t5, 2\n\t"          \
            "add    t5, t5, %[te]\n\t"      \
            "addi   t5, t5, 0x400\n\t"      \
            "lbu    t5, (t5)\n\t"           \
            "xor    a6, a6, t5\n\t"         \
                                            \
            "srli   t5, " #s ", 22\n\t"     \
            "andi   t5, t5, 0x3fc\n\t"      \
            "add    t5, t5, %[te]\n\t"      \
            "li     t6, 0x800\n\t"          \
            "add    t5, t5, t6\n\t"         \
            "lw     t5, (t5)\n\t"           \
            "li     t6, 0xff000000\n\t"     \
            "and    t5, t5, t6\n\t"         \
            "xor    a6, a6, t5\n\t"         \
                                            \
            "srli   t5, " #s ", 14\n\t"     \
            "andi   t5, t5, 0x3fc\n\t"      \
            "add    t5, t5, %[te]\n\t"      \
            "li     t6, 0xc00\n\t"          \
            "add    t5, t5, t6\n\t"         \
            "lw     t5, (t5)\n\t"           \
            "li     t6, 0x00ff0000\n\t"     \
            "and    t5, t5, t6\n\t"         \
            "xor    a6, a6, t5\n\t"

/* Set the AES key and expand.
 *
 * @param [in]  aes    AES object.
 * @param [in]  key    Block to encrypt.
 * @param [in]  keySz  Number of bytes in key.
 * @param [in]  dir    Direction of crypt: AES_ENCRYPTION or AES_DECRYPTION.
 */
static void AesSetKey_C(Aes* aes, const byte* key, word32 keySz, int dir)
{
    word32* rk = aes->key;

    switch (keySz) {
#if defined(AES_MAX_KEY_SIZE) && AES_MAX_KEY_SIZE >= 128 && \
        defined(WOLFSSL_AES_128)
    case 16:
        __asm__ __volatile__ (
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
            /* Load 4 32-bit words in reverse byte order. */
            LOAD_WORD_REV(t0, 0, %[key])
            LOAD_WORD_REV(t1, 4, %[key])
            LOAD_WORD_REV(t2, 8, %[key])
            LOAD_WORD_REV(t3, 12, %[key])
#else
            "ld     t1, 0(%[key])\n\t"
            "ld     t3, 8(%[key])\n\t"
            REV8(REG_T1, REG_T1)
            REV8(REG_T3, REG_T3)
            "srli   t0, t1, 32\n\t"
            "srli   t2, t3, 32\n\t"
#endif
            /* Store round 0 key. */
            "sw     t0,  0(%[rk])\n\t"
            "sw     t1,  4(%[rk])\n\t"
            "sw     t2,  8(%[rk])\n\t"
            "sw     t3, 12(%[rk])\n\t"

            "li     a4, 10\n\t"
            "mv     a5, x0\n\t"
        "L_aes_set_key_c_16_loop:\n\t"
            "addi   %[rk], %[rk], 16\n\t"
            /* Permute key. */
            AES_SUB_ROT_WORD_RCON(t3)
            "xor    t1, t1, t0\n\t"
            "xor    t2, t2, t1\n\t"
            "xor    t3, t3, t2\n\t"
            /* Store round key. */
            "sw     t0,  0(%[rk])\n\t"
            "sw     t1,  4(%[rk])\n\t"
            "sw     t2,  8(%[rk])\n\t"
            "sw     t3, 12(%[rk])\n\t"

            "addi   a4, a4, -1\n\t"
            "addi   a5, a5, 4\n\t"
            "bnez   a4, L_aes_set_key_c_16_loop\n\t"
            : [rk] "+r" (rk)
            : [key] "r" (key), [te] "r" (Te), [rcon] "r" (rcon)
            : "memory", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "a4", "a5"
        );
        break;
#endif /* 128 */

#if defined(AES_MAX_KEY_SIZE) && AES_MAX_KEY_SIZE >= 192 && \
        defined(WOLFSSL_AES_192)
    case 24:
        __asm__ __volatile__ (
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
            /* Load 6 32-bit words in reverse byte order. */
            LOAD_WORD_REV(t0, 0, %[key])
            LOAD_WORD_REV(t1, 4, %[key])
            LOAD_WORD_REV(t2, 8, %[key])
            LOAD_WORD_REV(t3, 12, %[key])
            LOAD_WORD_REV(a6, 16, %[key])
            LOAD_WORD_REV(a7, 20, %[key])
#else
            "ld     t1, 0(%[key])\n\t"
            "ld     t3, 8(%[key])\n\t"
            "ld     a7, 16(%[key])\n\t"
            REV8(REG_T1, REG_T1)
            REV8(REG_T3, REG_T3)
            REV8(REG_A7, REG_A7)
            "srli   t0, t1, 32\n\t"
            "srli   t2, t3, 32\n\t"
            "srli   a6, a7, 32\n\t"
#endif
            /* Store round 0 key. */
            "sw     t0,  0(%[rk])\n\t"
            "sw     t1,  4(%[rk])\n\t"
            "sw     t2,  8(%[rk])\n\t"
            "sw     t3, 12(%[rk])\n\t"
            "sw     a6, 16(%[rk])\n\t"
            "sw     a7, 20(%[rk])\n\t"

            "li     a4, 8\n\t"
            "mv     a5, x0\n\t"
        "L_aes_set_key_c_24_loop:\n\t"
            "addi   %[rk], %[rk], 24\n\t"
            /* Permute key. */
            AES_SUB_ROT_WORD_RCON(a7)
            "xor    t1, t1, t0\n\t"
            "xor    t2, t2, t1\n\t"
            "xor    t3, t3, t2\n\t"
            "xor    a6, a6, t3\n\t"
            "xor    a7, a7, a6\n\t"
            /* Store round key. */
            "sw     t0,  0(%[rk])\n\t"
            "sw     t1,  4(%[rk])\n\t"
            "sw     t2,  8(%[rk])\n\t"
            "sw     t3, 12(%[rk])\n\t"
            "sw     a6, 16(%[rk])\n\t"
            "sw     a7, 20(%[rk])\n\t"

            "addi   a4, a4, -1\n\t"
            "addi   a5, a5, 4\n\t"
            "bnez   a4, L_aes_set_key_c_24_loop\n\t"

            : [rk] "+r" (rk)
            : [key] "r" (key), [te] "r" (Te), [rcon] "r" (rcon)
            : "memory", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "a4", "a5",
              "a6", "a7"
        );
        break;
#endif /* 192 */

#if defined(AES_MAX_KEY_SIZE) && AES_MAX_KEY_SIZE >= 256 && \
        defined(WOLFSSL_AES_256)
    case 32:
        __asm__ __volatile__ (
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
            /* Load 8 32-bit words in reverse byte order. */
            LOAD_WORD_REV(t0, 0, %[key])
            LOAD_WORD_REV(t1, 4, %[key])
            LOAD_WORD_REV(t2, 8, %[key])
            LOAD_WORD_REV(t3, 12, %[key])
            LOAD_WORD_REV(a6, 16, %[key])
            LOAD_WORD_REV(a7, 20, %[key])
            LOAD_WORD_REV(s1, 24, %[key])
            LOAD_WORD_REV(s2, 28, %[key])
#else
            "ld     t1, 0(%[key])\n\t"
            "ld     t3, 8(%[key])\n\t"
            "ld     a7, 16(%[key])\n\t"
            "ld     s2, 24(%[key])\n\t"
            REV8(REG_T1, REG_T1)
            REV8(REG_T3, REG_T3)
            REV8(REG_A7, REG_A7)
            REV8(REG_S2, REG_S2)
            "srli   t0, t1, 32\n\t"
            "srli   t2, t3, 32\n\t"
            "srli   a6, a7, 32\n\t"
            "srli   s1, s2, 32\n\t"
#endif
            /* Store round 0 key. */
            "sw     t0,  0(%[rk])\n\t"
            "sw     t1,  4(%[rk])\n\t"
            "sw     t2,  8(%[rk])\n\t"
            "sw     t3, 12(%[rk])\n\t"
            "sw     a6, 16(%[rk])\n\t"
            "sw     a7, 20(%[rk])\n\t"
            "sw     s1, 24(%[rk])\n\t"
            "sw     s2, 28(%[rk])\n\t"

            "li     a4, 7\n\t"
            "mv     a5, x0\n\t"
        "L_aes_set_key_c_32_loop:\n\t"
            "addi   %[rk], %[rk], 32\n\t"
            /* Permute key. */
            AES_SUB_ROT_WORD_RCON(s2)
            "xor    t1, t1, t0\n\t"
            "xor    t2, t2, t1\n\t"
            "xor    t3, t3, t2\n\t"
            /* Store half round key. */
            "sw     t0,  0(%[rk])\n\t"
            "sw     t1,  4(%[rk])\n\t"
            "sw     t2,  8(%[rk])\n\t"
            "sw     t3, 12(%[rk])\n\t"

            "addi   a5, a5, 4\n\t"
            "addi   a4, a4, -1\n\t"
            "beqz   a4, L_aes_set_key_c_32_done\n\t"

            AES_SUB_WORD(t3)
            "xor    a7, a7, a6\n\t"
            "xor    s1, s1, a7\n\t"
            "xor    s2, s2, s1\n\t"
            /* Store second half round key. */
            "sw     a6, 16(%[rk])\n\t"
            "sw     a7, 20(%[rk])\n\t"
            "sw     s1, 24(%[rk])\n\t"
            "sw     s2, 28(%[rk])\n\t"

            "beqz   x0, L_aes_set_key_c_32_loop\n\t"
        "L_aes_set_key_c_32_done:\n\t"

            : [rk] "+r" (rk)
            : [key] "r" (key), [te] "r" (Te), [rcon] "r" (rcon)
            : "memory", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "a4", "a5",
              "a6", "a7", "s1", "s2"
        );
        break;
#endif /* 256 */
    }

#if defined(HAVE_AES_DECRYPT)

#define INV_MIXCOL(rki)                     \
            "srli   t5, " #rki ", 22\n\t"   \
            "andi   t5, t5, 0x3fc\n\t"      \
            "add    t5, t5, %[te1]\n\t"     \
            "lbu    t5, (t5)\n\t"           \
            "slli   t5, t5, 2\n\t"          \
            "add    t5, t5, %[td]\n\t"      \
            "lw     t6, (t5)\n\t"           \
            "srli   t5, " #rki ", 14\n\t"   \
            "andi   t5, t5, 0x3fc\n\t"      \
            "add    t5, t5, %[te1]\n\t"     \
            "lbu    t5, (t5)\n\t"           \
            "slli   t5, t5, 2\n\t"          \
            "add    t5, t5, %[td]\n\t"      \
            "addi   t5, t5, 0x400\n\t"      \
            "lw     t5, (t5)\n\t"           \
            "xor    t6, t6, t5\n\t"         \
            "srli   t5, " #rki ", 6\n\t"    \
            "andi   t5, t5, 0x3fc\n\t"      \
            "add    t5, t5, %[te1]\n\t"     \
            "lbu    t5, (t5)\n\t"           \
            "slli   t5, t5, 2\n\t"          \
            "add    t5, t5, %[td]\n\t"      \
            "li     t4, 0x800\n\t"          \
            "add    t5, t5, t4\n\t"         \
            "lw     t5, (t5)\n\t"           \
            "xor    t6, t6, t5\n\t"         \
            "andi   t5, " #rki ", 0xff\n\t" \
            "slli   t5, t5, 2\n\t"          \
            "add    t5, t5, %[te1]\n\t"     \
            "lbu    t5, (t5)\n\t"           \
            "slli   t5, t5, 2\n\t"          \
            "add    t5, t5, %[td]\n\t"      \
            "li     t4, 0xc00\n\t"          \
            "add    t5, t5, t4\n\t"         \
            "lw     t5, (t5)\n\t"           \
            "xor    " #rki ", t6, t5\n\t"

    if (dir == AES_DECRYPTION) {
        int r = aes->rounds;
        rk = aes->key;

        __asm__ __volatile__ (
            /* Change key schedule for decryption. */
            "slli   s1, %[r], 4\n\t"
            "add    s1, s1, %[rk]\n\t"
            "srli   %[r], %[r], 1\n\t"
            "addi   %[r], %[r], -1\n\t"

            /* Swap first two rounds. */
            "ld     t0, 0(%[rk])\n\t"
            "ld     t1, 8(%[rk])\n\t"
            "ld     t2, 0(s1)\n\t"
            "ld     t3, 8(s1)\n\t"
            "sd     t0, 0(s1)\n\t"
            "sd     t1, 8(s1)\n\t"
            "sd     t2, 0(%[rk])\n\t"
            "sd     t3, 8(%[rk])\n\t"

       "L_aes_set_key_inv_mixcol_loop:\n\t"
            "addi   %[rk], %[rk], 16\n\t"
            "addi   s1, s1, -16\n\t"

            "lw     t0,  0(%[rk])\n\t"
            "lw     t1,  4(%[rk])\n\t"
            "lw     t2,  8(%[rk])\n\t"
            "lw     t3, 12(%[rk])\n\t"
            "lw     a4,  0(s1)\n\t"
            "lw     a5,  4(s1)\n\t"
            "lw     a6,  8(s1)\n\t"
            "lw     a7, 12(s1)\n\t"

            INV_MIXCOL(t0)
            INV_MIXCOL(t1)
            INV_MIXCOL(t2)
            INV_MIXCOL(t3)
            INV_MIXCOL(a4)
            INV_MIXCOL(a5)
            INV_MIXCOL(a6)
            INV_MIXCOL(a7)

            "sw     t0,  0(s1)\n\t"
            "sw     t1,  4(s1)\n\t"
            "sw     t2,  8(s1)\n\t"
            "sw     t3, 12(s1)\n\t"
            "sw     a4,  0(%[rk])\n\t"
            "sw     a5,  4(%[rk])\n\t"
            "sw     a6,  8(%[rk])\n\t"
            "sw     a7, 12(%[rk])\n\t"

            "addi   %[r], %[r], -1\n\t"
            "bnez   %[r], L_aes_set_key_inv_mixcol_loop\n\t"

            "lw     t0, 16(%[rk])\n\t"
            "lw     t1, 20(%[rk])\n\t"
            "lw     t2, 24(%[rk])\n\t"
            "lw     t3, 28(%[rk])\n\t"

            INV_MIXCOL(t0)
            INV_MIXCOL(t1)
            INV_MIXCOL(t2)
            INV_MIXCOL(t3)

            "sw     t0, 16(%[rk])\n\t"
            "sw     t1, 20(%[rk])\n\t"
            "sw     t2, 24(%[rk])\n\t"
            "sw     t3, 28(%[rk])\n\t"

            : [rk] "+r" (rk), [r] "+r" (r)
            : [td] "r" (Td), [te1] "r" (Te[1])
            : "memory", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "a4", "a5",
              "a6", "a7", "s1"
       );
   }
#endif /* HAVE_AES_DECRYPT */
}

/* Set the key and/or IV into the AES object.
 *
 * Creates the key schedule from the key.
 * Uses Cryptographic instructions.
 *
 * @param [in] aes     AES object.
 * @param [in] key     Secret key to use.
 * @param [in] keyLen  Length of key in bytes.
 * @param [in] iv      Initialization Vector (IV) to use. May be NULL.
 * @param [in] dir     Direction of crypt: AES_ENCRYPT, AES_DECRYPT.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when aes or key is NULL.
 * @return  BAD_FUNC_ARG when keyLen/dir is not supported or valid.
 */
int wc_AesSetKey(Aes* aes, const byte* key, word32 keyLen, const byte* iv,
    int dir)
{
    int ret = 0;

    /* Validate parameters. */
    if (aes == NULL) {
        ret = BAD_FUNC_ARG;
    }
    /* Check key size is supported by AES object. */
    if ((ret == 0) && (keyLen > (word32)sizeof(aes->key))) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Check key length is supported. */
        switch (keyLen) {
    #if defined(AES_MAX_KEY_SIZE) && (AES_MAX_KEY_SIZE >= 128) && \
        defined(WOLFSSL_AES_128)
        case 16:
    #endif
    #if defined(AES_MAX_KEY_SIZE) && (AES_MAX_KEY_SIZE >= 192) && \
        defined(WOLFSSL_AES_192)
        case 24:
    #endif
    #if defined(AES_MAX_KEY_SIZE) && (AES_MAX_KEY_SIZE >= 256) && \
        defined(WOLFSSL_AES_256)
        case 32:
    #endif
            break;
        default:
            ret = BAD_FUNC_ARG;
        }
    }
#ifndef HAVE_AES_DECRYPT
    if ((ret == 0) && (dir == AES_DECRYPTION)) {
        ret = BAD_FUNC_ARG;
    }
#endif

    if (ret == 0) {
        /* Initialize fields. */
    #if defined(WOLFSSL_AES_CFB) || defined(WOLFSSL_AES_COUNTER) || \
        defined(WOLFSSL_AES_OFB)
        aes->left = 0;
    #endif
        aes->keylen = (int)keyLen;
        aes->rounds = (keyLen / 4) + 6;

        /* Compute the key schedule. */
        AesSetKey_C(aes, key, keyLen, dir);

        /* Set the IV. */
        ret = wc_AesSetIV(aes, iv);
    }

    return ret;
}

#if defined(WOLFSSL_AES_DIRECT) || defined(HAVE_AES_CBC) || \
    defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
/* Encrypt a block using AES.
 *
 * @param [in]  aes  AES object.
 * @param [in]  in   Block to encrypt.
 * @param [out] out  Encrypted block.
 */
static void wc_AesEncrypt(Aes* aes, const byte* in, byte* out)
{
/* A round of encryption from set 2 to 1 registers. */
#define ENC_ROUND_T_S_ASM(o)                    \
        "srliw      t0, a4, 24\n\t"             \
        "srliw      t1, a5, 24\n\t"             \
        "srliw      t2, a6, 24\n\t"             \
        "srliw      t3, a7, 24\n\t"             \
        "slliw      t0, t0, 2\n\t"              \
        "slliw      t1, t1, 2\n\t"              \
        "slliw      t2, t2, 2\n\t"              \
        "slliw      t3, t3, 2\n\t"              \
        "add        t0, t0, %[te]\n\t"          \
        "add        t1, t1, %[te]\n\t"          \
        "add        t2, t2, %[te]\n\t"          \
        "add        t3, t3, %[te]\n\t"          \
        "lw         t5, (t0)\n\t"               \
        "lw         t6, (t1)\n\t"               \
        "lw         s1, (t2)\n\t"               \
        "lw         s2, (t3)\n\t"               \
                                                \
        "addi       t4, %[te], 0x400\n\t"       \
        "srliw      t0, a5, 14\n\t"             \
        "srliw      t1, a6, 14\n\t"             \
        "srliw      t2, a7, 14\n\t"             \
        "srliw      t3, a4, 14\n\t"             \
        "andi       t0, t0, 0x3fc\n\t"          \
        "andi       t1, t1, 0x3fc\n\t"          \
        "andi       t2, t2, 0x3fc\n\t"          \
        "andi       t3, t3, 0x3fc\n\t"          \
        "add        t0, t0, t4\n\t"             \
        "add        t1, t1, t4\n\t"             \
        "add        t2, t2, t4\n\t"             \
        "add        t3, t3, t4\n\t"             \
        "lw         t0, (t0)\n\t"               \
        "lw         t1, (t1)\n\t"               \
        "lw         t2, (t2)\n\t"               \
        "lw         t3, (t3)\n\t"               \
        "xor        t5, t5, t0\n\t"             \
        "xor        t6, t6, t1\n\t"             \
        "xor        s1, s1, t2\n\t"             \
        "xor        s2, s2, t3\n\t"             \
                                                \
        "addi       t4, t4, 0x400\n\t"          \
        "srliw      t0, a6, 6\n\t"              \
        "srliw      t1, a7, 6\n\t"              \
        "srliw      t2, a4, 6\n\t"              \
        "srliw      t3, a5, 6\n\t"              \
        "andi       t0, t0, 0x3fc\n\t"          \
        "andi       t1, t1, 0x3fc\n\t"          \
        "andi       t2, t2, 0x3fc\n\t"          \
        "andi       t3, t3, 0x3fc\n\t"          \
        "add        t0, t0, t4\n\t"             \
        "add        t1, t1, t4\n\t"             \
        "add        t2, t2, t4\n\t"             \
        "add        t3, t3, t4\n\t"             \
        "lw         t0, (t0)\n\t"               \
        "lw         t1, (t1)\n\t"               \
        "lw         t2, (t2)\n\t"               \
        "lw         t3, (t3)\n\t"               \
        "xor        t5, t5, t0\n\t"             \
        "xor        t6, t6, t1\n\t"             \
        "xor        s1, s1, t2\n\t"             \
        "xor        s2, s2, t3\n\t"             \
                                                \
        "addi       t4, t4, 0x400\n\t"          \
        "andi       t0, a7, 0xff\n\t"           \
        "andi       t1, a4, 0xff\n\t"           \
        "andi       t2, a5, 0xff\n\t"           \
        "andi       t3, a6, 0xff\n\t"           \
        "slliw      t0, t0, 2\n\t"              \
        "slliw      t1, t1, 2\n\t"              \
        "slliw      t2, t2, 2\n\t"              \
        "slliw      t3, t3, 2\n\t"              \
        "add        t0, t0, t4\n\t"             \
        "add        t1, t1, t4\n\t"             \
        "add        t2, t2, t4\n\t"             \
        "add        t3, t3, t4\n\t"             \
        "lw         t0, (t0)\n\t"               \
        "lw         t1, (t1)\n\t"               \
        "lw         t2, (t2)\n\t"               \
        "lw         t3, (t3)\n\t"               \
        "xor        t5, t5, t0\n\t"             \
        "xor        t6, t6, t1\n\t"             \
        "xor        s1, s1, t2\n\t"             \
        "xor        s2, s2, t3\n\t"             \
                                                \
        "lw         t0, " #o "(%[rk])\n\t"      \
        "lw         t1, " #o "+4(%[rk])\n\t"    \
        "lw         t2, " #o "+8(%[rk])\n\t"    \
        "lw         t3, " #o "+12(%[rk])\n\t"   \
        "xor        t5, t5, t0\n\t"             \
        "xor        t6, t6, t1\n\t"             \
        "xor        s1, s1, t2\n\t"             \
        "xor        s2, s2, t3\n\t"

/* A round of encryption from set 1 to 2 registers. */
#define ENC_ROUND_S_T_ASM(o)                    \
        "srliw      t0, t5, 24\n\t"             \
        "srliw      t1, t6, 24\n\t"             \
        "srliw      t2, s1, 24\n\t"             \
        "srliw      t3, s2, 24\n\t"             \
        "slliw      t0, t0, 2\n\t"              \
        "slliw      t1, t1, 2\n\t"              \
        "slliw      t2, t2, 2\n\t"              \
        "slliw      t3, t3, 2\n\t"              \
        "add        t0, t0, %[te]\n\t"          \
        "add        t1, t1, %[te]\n\t"          \
        "add        t2, t2, %[te]\n\t"          \
        "add        t3, t3, %[te]\n\t"          \
        "lw         a4, (t0)\n\t"               \
        "lw         a5, (t1)\n\t"               \
        "lw         a6, (t2)\n\t"               \
        "lw         a7, (t3)\n\t"               \
                                                \
        "addi       t4, %[te], 0x400\n\t"       \
        "srliw      t0, t6, 14\n\t"             \
        "srliw      t1, s1, 14\n\t"             \
        "srliw      t2, s2, 14\n\t"             \
        "srliw      t3, t5, 14\n\t"             \
        "andi       t0, t0, 0x3fc\n\t"          \
        "andi       t1, t1, 0x3fc\n\t"          \
        "andi       t2, t2, 0x3fc\n\t"          \
        "andi       t3, t3, 0x3fc\n\t"          \
        "add        t0, t0, t4\n\t"             \
        "add        t1, t1, t4\n\t"             \
        "add        t2, t2, t4\n\t"             \
        "add        t3, t3, t4\n\t"             \
        "lw         t0, (t0)\n\t"               \
        "lw         t1, (t1)\n\t"               \
        "lw         t2, (t2)\n\t"               \
        "lw         t3, (t3)\n\t"               \
        "xor        a4, a4, t0\n\t"             \
        "xor        a5, a5, t1\n\t"             \
        "xor        a6, a6, t2\n\t"             \
        "xor        a7, a7, t3\n\t"             \
                                                \
        "addi       t4, t4, 0x400\n\t"          \
        "srliw      t0, s1, 6\n\t"              \
        "srliw      t1, s2, 6\n\t"              \
        "srliw      t2, t5, 6\n\t"              \
        "srliw      t3, t6, 6\n\t"              \
        "andi       t0, t0, 0x3fc\n\t"          \
        "andi       t1, t1, 0x3fc\n\t"          \
        "andi       t2, t2, 0x3fc\n\t"          \
        "andi       t3, t3, 0x3fc\n\t"          \
        "add        t0, t0, t4\n\t"             \
        "add        t1, t1, t4\n\t"             \
        "add        t2, t2, t4\n\t"             \
        "add        t3, t3, t4\n\t"             \
        "lw         t0, (t0)\n\t"               \
        "lw         t1, (t1)\n\t"               \
        "lw         t2, (t2)\n\t"               \
        "lw         t3, (t3)\n\t"               \
        "xor        a4, a4, t0\n\t"             \
        "xor        a5, a5, t1\n\t"             \
        "xor        a6, a6, t2\n\t"             \
        "xor        a7, a7, t3\n\t"             \
                                                \
        "addi       t4, t4, 0x400\n\t"          \
        "andi       t0, s2, 0xff\n\t"           \
        "andi       t1, t5, 0xff\n\t"           \
        "andi       t2, t6, 0xff\n\t"           \
        "andi       t3, s1, 0xff\n\t"           \
        "slliw      t0, t0, 2\n\t"              \
        "slliw      t1, t1, 2\n\t"              \
        "slliw      t2, t2, 2\n\t"              \
        "slliw      t3, t3, 2\n\t"              \
        "add        t0, t0, t4\n\t"             \
        "add        t1, t1, t4\n\t"             \
        "add        t2, t2, t4\n\t"             \
        "add        t3, t3, t4\n\t"             \
        "lw         t0, (t0)\n\t"               \
        "lw         t1, (t1)\n\t"               \
        "lw         t2, (t2)\n\t"               \
        "lw         t3, (t3)\n\t"               \
        "xor        a4, a4, t0\n\t"             \
        "xor        a5, a5, t1\n\t"             \
        "xor        a6, a6, t2\n\t"             \
        "xor        a7, a7, t3\n\t"             \
                                                \
        "lw         t0, " #o "(%[rk])\n\t"      \
        "lw         t1, " #o "+4(%[rk])\n\t"    \
        "lw         t2, " #o "+8(%[rk])\n\t"    \
        "lw         t3, " #o "+12(%[rk])\n\t"   \
        "xor        a4, a4, t0\n\t"             \
        "xor        a5, a5, t1\n\t"             \
        "xor        a6, a6, t2\n\t"             \
        "xor        a7, a7, t3\n\t"

    __asm__ __volatile__ (
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        /* Load 4 32-bit words in reverse byte order. */
        LOAD_WORD_REV(t0, 0, %[in])
        LOAD_WORD_REV(t1, 4, %[in])
        LOAD_WORD_REV(t2, 8, %[in])
        LOAD_WORD_REV(t3, 12, %[in])
#else
        "ld         t1,  0(%[in])\n\t"
        "ld         t3,  8(%[in])\n\t"
        REV8(REG_T1, REG_T1)
        REV8(REG_T3, REG_T3)
        "srli       t0, t1, 32\n\t"
        "srli       t2, t3, 32\n\t"
#endif
        "lw         a4,  0(%[rk])\n\t"
        "lw         a5,  4(%[rk])\n\t"
        "lw         a6,  8(%[rk])\n\t"
        "lw         a7, 12(%[rk])\n\t"
        /* AddRoundKey */
        "xor        a4, t0, a4\n\t"
        "xor        a5, t1, a5\n\t"
        "xor        a6, t2, a6\n\t"
        "xor        a7, t3, a7\n\t"

        ENC_ROUND_T_S_ASM(16)
        ENC_ROUND_S_T_ASM(32)
        ENC_ROUND_T_S_ASM(48)
        ENC_ROUND_S_T_ASM(64)
        ENC_ROUND_T_S_ASM(80)
        ENC_ROUND_S_T_ASM(96)
        ENC_ROUND_T_S_ASM(112)
        ENC_ROUND_S_T_ASM(128)
        ENC_ROUND_T_S_ASM(144)

        "li          t4, 5\n\t"
        "ble         %[r], t4, L_aes_encrypt_done\n\t"
        ENC_ROUND_S_T_ASM(160)
        ENC_ROUND_T_S_ASM(176)

        "li          t4, 6\n\t"
        "ble         %[r], t4, L_aes_encrypt_done\n\t"
        ENC_ROUND_S_T_ASM(192)
        ENC_ROUND_T_S_ASM(208)
    "L_aes_encrypt_done:\n\t"

        /* Last round. */
        "srliw      t0, s1, 6\n\t"
        "srliw      t1, s2, 6\n\t"
        "srliw      t2, t5, 6\n\t"
        "srliw      t3, t6, 6\n\t"
        "andi       t0, t0, 0x3fc\n\t"
        "andi       t1, t1, 0x3fc\n\t"
        "andi       t2, t2, 0x3fc\n\t"
        "andi       t3, t3, 0x3fc\n\t"
        "add        t0, t0, %[te]\n\t"
        "add        t1, t1, %[te]\n\t"
        "add        t2, t2, %[te]\n\t"
        "add        t3, t3, %[te]\n\t"
        "lw         a4, (t0)\n\t"
        "lw         a5, (t1)\n\t"
        "lw         a6, (t2)\n\t"
        "lw         a7, (t3)\n\t"
        "li         t4, 0x0000ff00\n\t"
        "and        a4, a4, t4\n\t"
        "and        a5, a5, t4\n\t"
        "and        a6, a6, t4\n\t"
        "and        a7, a7, t4\n\t"

        "addi       t4, %[te], 0x400\n\t"
        "andi       t0, s2, 0xff\n\t"
        "andi       t1, t5, 0xff\n\t"
        "andi       t2, t6, 0xff\n\t"
        "andi       t3, s1, 0xff\n\t"
        "slli       t0, t0, 2\n\t"
        "slli       t1, t1, 2\n\t"
        "slli       t2, t2, 2\n\t"
        "slli       t3, t3, 2\n\t"
        "add        t0, t0, t4\n\t"
        "add        t1, t1, t4\n\t"
        "add        t2, t2, t4\n\t"
        "add        t3, t3, t4\n\t"
        "lbu        t0, (t0)\n\t"
        "lbu        t1, (t1)\n\t"
        "lbu        t2, (t2)\n\t"
        "lbu        t3, (t3)\n\t"
        "or         a4, a4, t0\n\t"
        "or         a5, a5, t1\n\t"
        "or         a6, a6, t2\n\t"
        "or         a7, a7, t3\n\t"

        "addi       t4, t4, 0x400\n\t"
        "srliw      t0, t5, 24\n\t"
        "srliw      t1, t6, 24\n\t"
        "srliw      t2, s1, 24\n\t"
        "srliw      t3, s2, 24\n\t"
        "slli       t0, t0, 2\n\t"
        "slli       t1, t1, 2\n\t"
        "slli       t2, t2, 2\n\t"
        "slli       t3, t3, 2\n\t"
        "add        t0, t0, t4\n\t"
        "add        t1, t1, t4\n\t"
        "add        t2, t2, t4\n\t"
        "add        t3, t3, t4\n\t"
        "lw         t0, (t0)\n\t"
        "lw         t1, (t1)\n\t"
        "lw         t2, (t2)\n\t"
        "lw         t3, (t3)\n\t"
        "li         t4, 0xff000000\n\t"
        "and        t0, t0, t4\n\t"
        "and        t1, t1, t4\n\t"
        "and        t2, t2, t4\n\t"
        "and        t3, t3, t4\n\t"
        "or         a4, a4, t0\n\t"
        "or         a5, a5, t1\n\t"
        "or         a6, a6, t2\n\t"
        "or         a7, a7, t3\n\t"

        "li         t4, 0xc00\n\t"
        "add        t4, %[te], t4\n\t"
        "srliw      t0, t6, 14\n\t"
        "srliw      t1, s1, 14\n\t"
        "srliw      t2, s2, 14\n\t"
        "srliw      t3, t5, 14\n\t"
        "andi       t0, t0, 0x3fc\n\t"
        "andi       t1, t1, 0x3fc\n\t"
        "andi       t2, t2, 0x3fc\n\t"
        "andi       t3, t3, 0x3fc\n\t"
        "add        t0, t0, t4\n\t"
        "add        t1, t1, t4\n\t"
        "add        t2, t2, t4\n\t"
        "add        t3, t3, t4\n\t"
        "lw         t0, (t0)\n\t"
        "lw         t1, (t1)\n\t"
        "lw         t2, (t2)\n\t"
        "lw         t3, (t3)\n\t"
        "li         t4, 0x00ff0000\n\t"
        "and        t0, t0, t4\n\t"
        "and        t1, t1, t4\n\t"
        "and        t2, t2, t4\n\t"
        "and        t3, t3, t4\n\t"
        "or         a4, a4, t0\n\t"
        "or         a5, a5, t1\n\t"
        "or         a6, a6, t2\n\t"
        "or         a7, a7, t3\n\t"

        "slli       t4, %[r], 5\n\t"
        "add        t4, %[rk], t4\n\t"
        "lw         t0,  0(t4)\n\t"
        "lw         t1,  4(t4)\n\t"
        "lw         t2,  8(t4)\n\t"
        "lw         t3, 12(t4)\n\t"
        "xor        a4, a4, t0\n\t"
        "xor        a5, a5, t1\n\t"
        "xor        a6, a6, t2\n\t"
        "xor        a7, a7, t3\n\t"

        /* Reverse byte in 32-bit words. */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        STORE_WORD_REV(a4, 0, %[out])
        STORE_WORD_REV(a5, 4, %[out])
        STORE_WORD_REV(a6, 8, %[out])
        STORE_WORD_REV(a7, 12, %[out])
#elif !defined(WOLFSSL_RISCV_BIT_MANIPULATION)
        "slli        t0, a4, 32\n\t"
        "slli        t1, a5, 32\n\t"
        "slli        t2, a6, 32\n\t"
        "slli        t3, a7, 32\n\t"
        "srli        t1, t1, 32\n\t"
        "srli        t3, t3, 32\n\t"
        "or          t1, t1, t0\n\t"
        "or          t3, t3, t2\n\t"
        REV8(REG_T1, REG_T1)
        REV8(REG_T3, REG_T3)
        /* Write encrypted block to output. */
        "sd         t1,  0(%[out])\n\t"
        "sd         t3,  8(%[out])\n\t"
#else
        PACK(REG_T1, REG_A5, REG_A4)
        PACK(REG_T3, REG_A7, REG_A6)
        REV8(REG_T1, REG_T1)
        REV8(REG_T3, REG_T3)
        /* Write encrypted block to output. */
        "sd         t1,  0(%[out])\n\t"
        "sd         t3,  8(%[out])\n\t"
#endif

        :
        : [in] "r" (in), [rk] "r" (aes->key), [te] "r" (Te),
          [r] "r" (aes->rounds >> 1), [out] "r" (out)
        : "memory", "t0", "t1", "t2", "t3", "t4",
          "a4", "a5", "a6", "a7",
          "t5", "t6", "s1", "s2"
    );
}
#endif /* WOLFSSL_AES_DIRECT || HAVE_AES_CBC || HAVE_AESGCM || HAVE_AESCCM */

#if defined(WOLFSSL_AES_DIRECT) || defined(HAVE_AES_CBC)
#ifdef HAVE_AES_DECRYPT
/* AES byte decryption table. */
static const FLASH_QUALIFIER byte Td4[256] =
{
    0x52U, 0x09U, 0x6aU, 0xd5U, 0x30U, 0x36U, 0xa5U, 0x38U,
    0xbfU, 0x40U, 0xa3U, 0x9eU, 0x81U, 0xf3U, 0xd7U, 0xfbU,
    0x7cU, 0xe3U, 0x39U, 0x82U, 0x9bU, 0x2fU, 0xffU, 0x87U,
    0x34U, 0x8eU, 0x43U, 0x44U, 0xc4U, 0xdeU, 0xe9U, 0xcbU,
    0x54U, 0x7bU, 0x94U, 0x32U, 0xa6U, 0xc2U, 0x23U, 0x3dU,
    0xeeU, 0x4cU, 0x95U, 0x0bU, 0x42U, 0xfaU, 0xc3U, 0x4eU,
    0x08U, 0x2eU, 0xa1U, 0x66U, 0x28U, 0xd9U, 0x24U, 0xb2U,
    0x76U, 0x5bU, 0xa2U, 0x49U, 0x6dU, 0x8bU, 0xd1U, 0x25U,
    0x72U, 0xf8U, 0xf6U, 0x64U, 0x86U, 0x68U, 0x98U, 0x16U,
    0xd4U, 0xa4U, 0x5cU, 0xccU, 0x5dU, 0x65U, 0xb6U, 0x92U,
    0x6cU, 0x70U, 0x48U, 0x50U, 0xfdU, 0xedU, 0xb9U, 0xdaU,
    0x5eU, 0x15U, 0x46U, 0x57U, 0xa7U, 0x8dU, 0x9dU, 0x84U,
    0x90U, 0xd8U, 0xabU, 0x00U, 0x8cU, 0xbcU, 0xd3U, 0x0aU,
    0xf7U, 0xe4U, 0x58U, 0x05U, 0xb8U, 0xb3U, 0x45U, 0x06U,
    0xd0U, 0x2cU, 0x1eU, 0x8fU, 0xcaU, 0x3fU, 0x0fU, 0x02U,
    0xc1U, 0xafU, 0xbdU, 0x03U, 0x01U, 0x13U, 0x8aU, 0x6bU,
    0x3aU, 0x91U, 0x11U, 0x41U, 0x4fU, 0x67U, 0xdcU, 0xeaU,
    0x97U, 0xf2U, 0xcfU, 0xceU, 0xf0U, 0xb4U, 0xe6U, 0x73U,
    0x96U, 0xacU, 0x74U, 0x22U, 0xe7U, 0xadU, 0x35U, 0x85U,
    0xe2U, 0xf9U, 0x37U, 0xe8U, 0x1cU, 0x75U, 0xdfU, 0x6eU,
    0x47U, 0xf1U, 0x1aU, 0x71U, 0x1dU, 0x29U, 0xc5U, 0x89U,
    0x6fU, 0xb7U, 0x62U, 0x0eU, 0xaaU, 0x18U, 0xbeU, 0x1bU,
    0xfcU, 0x56U, 0x3eU, 0x4bU, 0xc6U, 0xd2U, 0x79U, 0x20U,
    0x9aU, 0xdbU, 0xc0U, 0xfeU, 0x78U, 0xcdU, 0x5aU, 0xf4U,
    0x1fU, 0xddU, 0xa8U, 0x33U, 0x88U, 0x07U, 0xc7U, 0x31U,
    0xb1U, 0x12U, 0x10U, 0x59U, 0x27U, 0x80U, 0xecU, 0x5fU,
    0x60U, 0x51U, 0x7fU, 0xa9U, 0x19U, 0xb5U, 0x4aU, 0x0dU,
    0x2dU, 0xe5U, 0x7aU, 0x9fU, 0x93U, 0xc9U, 0x9cU, 0xefU,
    0xa0U, 0xe0U, 0x3bU, 0x4dU, 0xaeU, 0x2aU, 0xf5U, 0xb0U,
    0xc8U, 0xebU, 0xbbU, 0x3cU, 0x83U, 0x53U, 0x99U, 0x61U,
    0x17U, 0x2bU, 0x04U, 0x7eU, 0xbaU, 0x77U, 0xd6U, 0x26U,
    0xe1U, 0x69U, 0x14U, 0x63U, 0x55U, 0x21U, 0x0cU, 0x7dU,
};

/* Decrypt a block using AES.
 *
 * @param [in]  aes  AES object.
 * @param [in]  in   Block to decrypt.
 * @param [out] out  Decrypted block.
 */
static void wc_AesDecrypt(Aes* aes, const byte* in, byte* out)
{
/* A round of decryption from set 2 to 1 registers. */
#define DEC_ROUND_T_S_ASM(o)                    \
        "srliw      t0, a4, 24\n\t"             \
        "srliw      t1, a5, 24\n\t"             \
        "srliw      t2, a6, 24\n\t"             \
        "srliw      t3, a7, 24\n\t"             \
        "slliw      t0, t0, 2\n\t"              \
        "slliw      t1, t1, 2\n\t"              \
        "slliw      t2, t2, 2\n\t"              \
        "slliw      t3, t3, 2\n\t"              \
        "add        t0, t0, %[td]\n\t"          \
        "add        t1, t1, %[td]\n\t"          \
        "add        t2, t2, %[td]\n\t"          \
        "add        t3, t3, %[td]\n\t"          \
        "lw         t5, (t0)\n\t"               \
        "lw         t6, (t1)\n\t"               \
        "lw         s1, (t2)\n\t"               \
        "lw         s2, (t3)\n\t"               \
                                                \
        "addi       t4, %[td], 0x400\n\t"       \
        "srliw      t0, a7, 14\n\t"             \
        "srliw      t1, a4, 14\n\t"             \
        "srliw      t2, a5, 14\n\t"             \
        "srliw      t3, a6, 14\n\t"             \
        "andi       t0, t0, 0x3fc\n\t"          \
        "andi       t1, t1, 0x3fc\n\t"          \
        "andi       t2, t2, 0x3fc\n\t"          \
        "andi       t3, t3, 0x3fc\n\t"          \
        "add        t0, t0, t4\n\t"             \
        "add        t1, t1, t4\n\t"             \
        "add        t2, t2, t4\n\t"             \
        "add        t3, t3, t4\n\t"             \
        "lw         t0, (t0)\n\t"               \
        "lw         t1, (t1)\n\t"               \
        "lw         t2, (t2)\n\t"               \
        "lw         t3, (t3)\n\t"               \
        "xor        t5, t5, t0\n\t"             \
        "xor        t6, t6, t1\n\t"             \
        "xor        s1, s1, t2\n\t"             \
        "xor        s2, s2, t3\n\t"             \
                                                \
        "addi       t4, t4, 0x400\n\t"          \
        "srliw      t0, a6, 6\n\t"              \
        "srliw      t1, a7, 6\n\t"              \
        "srliw      t2, a4, 6\n\t"              \
        "srliw      t3, a5, 6\n\t"              \
        "andi       t0, t0, 0x3fc\n\t"          \
        "andi       t1, t1, 0x3fc\n\t"          \
        "andi       t2, t2, 0x3fc\n\t"          \
        "andi       t3, t3, 0x3fc\n\t"          \
        "add        t0, t0, t4\n\t"             \
        "add        t1, t1, t4\n\t"             \
        "add        t2, t2, t4\n\t"             \
        "add        t3, t3, t4\n\t"             \
        "lw         t0, (t0)\n\t"               \
        "lw         t1, (t1)\n\t"               \
        "lw         t2, (t2)\n\t"               \
        "lw         t3, (t3)\n\t"               \
        "xor        t5, t5, t0\n\t"             \
        "xor        t6, t6, t1\n\t"             \
        "xor        s1, s1, t2\n\t"             \
        "xor        s2, s2, t3\n\t"             \
                                                \
        "addi       t4, t4, 0x400\n\t"          \
        "andi       t0, a5, 0xff\n\t"           \
        "andi       t1, a6, 0xff\n\t"           \
        "andi       t2, a7, 0xff\n\t"           \
        "andi       t3, a4, 0xff\n\t"           \
        "slliw      t0, t0, 2\n\t"              \
        "slliw      t1, t1, 2\n\t"              \
        "slliw      t2, t2, 2\n\t"              \
        "slliw      t3, t3, 2\n\t"              \
        "add        t0, t0, t4\n\t"             \
        "add        t1, t1, t4\n\t"             \
        "add        t2, t2, t4\n\t"             \
        "add        t3, t3, t4\n\t"             \
        "lw         t0, (t0)\n\t"               \
        "lw         t1, (t1)\n\t"               \
        "lw         t2, (t2)\n\t"               \
        "lw         t3, (t3)\n\t"               \
        "xor        t5, t5, t0\n\t"             \
        "xor        t6, t6, t1\n\t"             \
        "xor        s1, s1, t2\n\t"             \
        "xor        s2, s2, t3\n\t"             \
                                                \
        "lw         t0, " #o "(%[rk])\n\t"      \
        "lw         t1, " #o "+4(%[rk])\n\t"    \
        "lw         t2, " #o "+8(%[rk])\n\t"    \
        "lw         t3, " #o "+12(%[rk])\n\t"   \
        "xor        t5, t5, t0\n\t"             \
        "xor        t6, t6, t1\n\t"             \
        "xor        s1, s1, t2\n\t"             \
        "xor        s2, s2, t3\n\t"

/* A round of decryption from set 1 to 2 registers. */
#define DEC_ROUND_S_T_ASM(o)                    \
        "srliw      t0, t5, 24\n\t"             \
        "srliw      t1, t6, 24\n\t"             \
        "srliw      t2, s1, 24\n\t"             \
        "srliw      t3, s2, 24\n\t"             \
        "slliw      t0, t0, 2\n\t"              \
        "slliw      t1, t1, 2\n\t"              \
        "slliw      t2, t2, 2\n\t"              \
        "slliw      t3, t3, 2\n\t"              \
        "add        t0, t0, %[td]\n\t"          \
        "add        t1, t1, %[td]\n\t"          \
        "add        t2, t2, %[td]\n\t"          \
        "add        t3, t3, %[td]\n\t"          \
        "lw         a4, (t0)\n\t"               \
        "lw         a5, (t1)\n\t"               \
        "lw         a6, (t2)\n\t"               \
        "lw         a7, (t3)\n\t"               \
                                                \
        "addi       t4, %[td], 0x400\n\t"       \
        "srliw      t0, s2, 14\n\t"             \
        "srliw      t1, t5, 14\n\t"             \
        "srliw      t2, t6, 14\n\t"             \
        "srliw      t3, s1, 14\n\t"             \
        "andi       t0, t0, 0x3fc\n\t"          \
        "andi       t1, t1, 0x3fc\n\t"          \
        "andi       t2, t2, 0x3fc\n\t"          \
        "andi       t3, t3, 0x3fc\n\t"          \
        "add        t0, t0, t4\n\t"             \
        "add        t1, t1, t4\n\t"             \
        "add        t2, t2, t4\n\t"             \
        "add        t3, t3, t4\n\t"             \
        "lw         t0, (t0)\n\t"               \
        "lw         t1, (t1)\n\t"               \
        "lw         t2, (t2)\n\t"               \
        "lw         t3, (t3)\n\t"               \
        "xor        a4, a4, t0\n\t"             \
        "xor        a5, a5, t1\n\t"             \
        "xor        a6, a6, t2\n\t"             \
        "xor        a7, a7, t3\n\t"             \
                                                \
        "addi       t4, t4, 0x400\n\t"          \
        "srliw      t0, s1, 6\n\t"              \
        "srliw      t1, s2, 6\n\t"              \
        "srliw      t2, t5, 6\n\t"              \
        "srliw      t3, t6, 6\n\t"              \
        "andi       t0, t0, 0x3fc\n\t"          \
        "andi       t1, t1, 0x3fc\n\t"          \
        "andi       t2, t2, 0x3fc\n\t"          \
        "andi       t3, t3, 0x3fc\n\t"          \
        "add        t0, t0, t4\n\t"             \
        "add        t1, t1, t4\n\t"             \
        "add        t2, t2, t4\n\t"             \
        "add        t3, t3, t4\n\t"             \
        "lw         t0, (t0)\n\t"               \
        "lw         t1, (t1)\n\t"               \
        "lw         t2, (t2)\n\t"               \
        "lw         t3, (t3)\n\t"               \
        "xor        a4, a4, t0\n\t"             \
        "xor        a5, a5, t1\n\t"             \
        "xor        a6, a6, t2\n\t"             \
        "xor        a7, a7, t3\n\t"             \
                                                \
        "addi       t4, t4, 0x400\n\t"          \
        "andi       t0, t6, 0xff\n\t"           \
        "andi       t1, s1, 0xff\n\t"           \
        "andi       t2, s2, 0xff\n\t"           \
        "andi       t3, t5, 0xff\n\t"           \
        "slliw      t0, t0, 2\n\t"              \
        "slliw      t1, t1, 2\n\t"              \
        "slliw      t2, t2, 2\n\t"              \
        "slliw      t3, t3, 2\n\t"              \
        "add        t0, t0, t4\n\t"             \
        "add        t1, t1, t4\n\t"             \
        "add        t2, t2, t4\n\t"             \
        "add        t3, t3, t4\n\t"             \
        "lw         t0, (t0)\n\t"               \
        "lw         t1, (t1)\n\t"               \
        "lw         t2, (t2)\n\t"               \
        "lw         t3, (t3)\n\t"               \
        "xor        a4, a4, t0\n\t"             \
        "xor        a5, a5, t1\n\t"             \
        "xor        a6, a6, t2\n\t"             \
        "xor        a7, a7, t3\n\t"             \
                                                \
        "lw         t0, " #o "(%[rk])\n\t"      \
        "lw         t1, " #o "+4(%[rk])\n\t"    \
        "lw         t2, " #o "+8(%[rk])\n\t"    \
        "lw         t3, " #o "+12(%[rk])\n\t"   \
        "xor        a4, a4, t0\n\t"             \
        "xor        a5, a5, t1\n\t"             \
        "xor        a6, a6, t2\n\t"             \
        "xor        a7, a7, t3\n\t"

    __asm__ __volatile__ (
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        /* Load 4 32-bit words in reverse byte order. */
        LOAD_WORD_REV(t0, 0, %[in])
        LOAD_WORD_REV(t1, 4, %[in])
        LOAD_WORD_REV(t2, 8, %[in])
        LOAD_WORD_REV(t3, 12, %[in])
#else
        "ld         t1,  0(%[in])\n\t"
        "ld         t3,  8(%[in])\n\t"
        REV8(REG_T1, REG_T1)
        REV8(REG_T3, REG_T3)
        "srli       t0, t1, 32\n\t"
        "srli       t2, t3, 32\n\t"
#endif
        "lw         a4,  0(%[rk])\n\t"
        "lw         a5,  4(%[rk])\n\t"
        "lw         a6,  8(%[rk])\n\t"
        "lw         a7, 12(%[rk])\n\t"
        /* AddRoundKey */
        "xor        a4, t0, a4\n\t"
        "xor        a5, t1, a5\n\t"
        "xor        a6, t2, a6\n\t"
        "xor        a7, t3, a7\n\t"

        DEC_ROUND_T_S_ASM(16)
        DEC_ROUND_S_T_ASM(32)
        DEC_ROUND_T_S_ASM(48)
        DEC_ROUND_S_T_ASM(64)
        DEC_ROUND_T_S_ASM(80)
        DEC_ROUND_S_T_ASM(96)
        DEC_ROUND_T_S_ASM(112)
        DEC_ROUND_S_T_ASM(128)
        DEC_ROUND_T_S_ASM(144)

        "li          t4, 5\n\t"
        "ble         %[r], t4, L_aes_decrypt_done\n\t"
        DEC_ROUND_S_T_ASM(160)
        DEC_ROUND_T_S_ASM(176)

        "li          t4, 6\n\t"
        "ble         %[r], t4, L_aes_decrypt_done\n\t"
        DEC_ROUND_S_T_ASM(192)
        DEC_ROUND_T_S_ASM(208)
    "L_aes_decrypt_done:\n\t"

        /* Last round. */
        "srliw      t0, t5, 24\n\t"
        "srliw      t1, t6, 24\n\t"
        "srliw      t2, s1, 24\n\t"
        "srliw      t3, s2, 24\n\t"
        "add        t0, t0, %[td4]\n\t"
        "add        t1, t1, %[td4]\n\t"
        "add        t2, t2, %[td4]\n\t"
        "add        t3, t3, %[td4]\n\t"
        "lbu        a4, (t0)\n\t"
        "lbu        a5, (t1)\n\t"
        "lbu        a6, (t2)\n\t"
        "lbu        a7, (t3)\n\t"
        "slli       a4, a4, 24\n\t"
        "slli       a5, a5, 24\n\t"
        "slli       a6, a6, 24\n\t"
        "slli       a7, a7, 24\n\t"

        "srliw      t0, s2, 16\n\t"
        "srliw      t1, t5, 16\n\t"
        "srliw      t2, t6, 16\n\t"
        "srliw      t3, s1, 16\n\t"
        "andi       t0, t0, 0xff\n\t"
        "andi       t1, t1, 0xff\n\t"
        "andi       t2, t2, 0xff\n\t"
        "andi       t3, t3, 0xff\n\t"
        "add        t0, t0, %[td4]\n\t"
        "add        t1, t1, %[td4]\n\t"
        "add        t2, t2, %[td4]\n\t"
        "add        t3, t3, %[td4]\n\t"
        "lbu        t0, (t0)\n\t"
        "lbu        t1, (t1)\n\t"
        "lbu        t2, (t2)\n\t"
        "lbu        t3, (t3)\n\t"
        "slli       t0, t0, 16\n\t"
        "slli       t1, t1, 16\n\t"
        "slli       t2, t2, 16\n\t"
        "slli       t3, t3, 16\n\t"
        "or         a4, a4, t0\n\t"
        "or         a5, a5, t1\n\t"
        "or         a6, a6, t2\n\t"
        "or         a7, a7, t3\n\t"

        "srliw      t0, s1, 8\n\t"
        "srliw      t1, s2, 8\n\t"
        "srliw      t2, t5, 8\n\t"
        "srliw      t3, t6, 8\n\t"
        "andi       t0, t0, 0xff\n\t"
        "andi       t1, t1, 0xff\n\t"
        "andi       t2, t2, 0xff\n\t"
        "andi       t3, t3, 0xff\n\t"
        "add        t0, t0, %[td4]\n\t"
        "add        t1, t1, %[td4]\n\t"
        "add        t2, t2, %[td4]\n\t"
        "add        t3, t3, %[td4]\n\t"
        "lbu        t0, (t0)\n\t"
        "lbu        t1, (t1)\n\t"
        "lbu        t2, (t2)\n\t"
        "lbu        t3, (t3)\n\t"
        "slli       t0, t0, 8\n\t"
        "slli       t1, t1, 8\n\t"
        "slli       t2, t2, 8\n\t"
        "slli       t3, t3, 8\n\t"
        "or         a4, a4, t0\n\t"
        "or         a5, a5, t1\n\t"
        "or         a6, a6, t2\n\t"
        "or         a7, a7, t3\n\t"

        "andi       t0, t6, 0xff\n\t"
        "andi       t1, s1, 0xff\n\t"
        "andi       t2, s2, 0xff\n\t"
        "andi       t3, t5, 0xff\n\t"
        "add        t0, t0, %[td4]\n\t"
        "add        t1, t1, %[td4]\n\t"
        "add        t2, t2, %[td4]\n\t"
        "add        t3, t3, %[td4]\n\t"
        "lbu        t0, (t0)\n\t"
        "lbu        t1, (t1)\n\t"
        "lbu        t2, (t2)\n\t"
        "lbu        t3, (t3)\n\t"
        "or         a4, a4, t0\n\t"
        "or         a5, a5, t1\n\t"
        "or         a6, a6, t2\n\t"
        "or         a7, a7, t3\n\t"

        "slli       t4, %[r], 5\n\t"
        "add        t4, %[rk], t4\n\t"
        "lw         t0,  0(t4)\n\t"
        "lw         t1,  4(t4)\n\t"
        "lw         t2,  8(t4)\n\t"
        "lw         t3, 12(t4)\n\t"
        "xor        a4, a4, t0\n\t"
        "xor        a5, a5, t1\n\t"
        "xor        a6, a6, t2\n\t"
        "xor        a7, a7, t3\n\t"

        /* Reverse byte in 32-bit words. */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        STORE_WORD_REV(a4, 0, %[out])
        STORE_WORD_REV(a5, 4, %[out])
        STORE_WORD_REV(a6, 8, %[out])
        STORE_WORD_REV(a7, 12, %[out])
#elif !defined(WOLFSSL_RISCV_BIT_MANIPULATION)
        "slli        t0, a4, 32\n\t"
        "slli        t1, a5, 32\n\t"
        "slli        t2, a6, 32\n\t"
        "slli        t3, a7, 32\n\t"
        "srli        t1, t1, 32\n\t"
        "srli        t3, t3, 32\n\t"
        "or          t1, t1, t0\n\t"
        "or          t3, t3, t2\n\t"
        REV8(REG_T1, REG_T1)
        REV8(REG_T3, REG_T3)
        /* Write encrypted block to output. */
        "sd         t1,  0(%[out])\n\t"
        "sd         t3,  8(%[out])\n\t"
#else
        PACK(REG_T1, REG_A5, REG_A4)
        PACK(REG_T3, REG_A7, REG_A6)
        REV8(REG_T1, REG_T1)
        REV8(REG_T3, REG_T3)
        /* Write encrypted block to output. */
        "sd         t1,  0(%[out])\n\t"
        "sd         t3,  8(%[out])\n\t"
#endif

        :
        : [in] "r" (in), [rk] "r" (aes->key), [td] "r" (Td),
          [r] "r" (aes->rounds >> 1), [out] "r" (out), [td4] "r" (Td4)
        : "memory", "t0", "t1", "t2", "t3", "t4",
          "a4", "a5", "a6", "a7",
          "t5", "t6", "s1", "s2"
    );
}
#endif /* HAVE_AES_DECRYPT */
#endif /* WOLFSSL_AES_DIRECT || HAVE_AES_CBC */

#endif /* WOLFSSL_RISCV_SCALAR_CRYPTO_ASM */

/* AES-CBC */
#if (defined(HAVE_AES_CBC) && !defined(HAVE_AES_CBC_ENC_DEC)) || \
    (defined(WOLFSSL_AES_COUNTER) && !defined(HAVE_AES_COUNTER_ENC)) || \
    (defined(HAVE_AESGCM) && !defined(WOLFSSL_RISCV_VECTOR_GCM)) || \
    defined(HAVE_AESCCM)
/* XOR two 16-byte values, out and in, into out.
 *
 * @param [in, out] out  16-byte value.
 * @param [in]      in   16-byte value.
 */
static WC_INLINE void xorbuf16(byte* out, const byte* in)
{
    word64* out64 = (word64*)out;
    word64* in64  = (word64*)in;

    out64[0] ^= in64[0];
    out64[1] ^= in64[1];
}
#endif

#if (defined(HAVE_AES_CBC) && !defined(HAVE_AES_CBC_ENC_DEC)) || \
    (defined(HAVE_AESGCM) && (!defined(WOLFSSL_RISCV_VECTOR_CRYPTO_ASM) || \
     !defined(WOLFSSL_RISCV_VECTOR_GCM)))
/* XOR two 16-byte values into out.
 *
 * @param [out] out  16-byte value.
 * @param [in]  a    16-byte value.
 * @param [in]  b    16-byte value.
 */
static WC_INLINE void xorbufout16(byte* out, const byte* a, const byte* b)
{
    word64* out64 = (word64*)out;
    word64* a64   = (word64*)a;
    word64* b64   = (word64*)b;

    out64[0] = a64[0] ^ b64[0];
    out64[1] = a64[1] ^ b64[1];
}
#endif

#if defined(HAVE_AES_CBC) && !defined(HAVE_AES_CBC_ENC_DEC)
/* Encrypt blocks of data using AES-CBC.
 *
 * Implementation using wc_AesEncrypt().
 *
 * @param [in]  aes  AES object.
 * @param [out] out  Encrypted blocks.
 * @param [in]  in   Blocks to encrypt.
 * @param pin]  sz   Number of bytes to encrypt.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when aes, out or in is NULL.
 * @return  BAD_LENGTH_E when sz is not a multiple of AES_BLOCK_SIZE.
 */
int wc_AesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    int ret = 0;
    word32 blocks = sz / AES_BLOCK_SIZE;

    /* Validate parameters. */
    if ((aes == NULL) || (out == NULL) || (in == NULL)) {
        ret = BAD_FUNC_ARG;
    }
#ifdef WOLFSSL_AES_CBC_LENGTH_CHECKS
    /* Ensure a multiple of blocks is to be encrypted.  */
    if ((ret == 0) && (sz % AES_BLOCK_SIZE)) {
        ret = BAD_LENGTH_E;
    }
#endif

    if ((ret == 0) && (blocks > 0)) {
        if (in != out) {
            /* Encrypt first block with IV. */
            xorbufout16(out, (byte*)aes->reg, in);
            wc_AesEncrypt(aes, out, out);
            in += AES_BLOCK_SIZE;
            out += AES_BLOCK_SIZE;
            for (blocks--; blocks > 0; blocks--) {
                /* Encrypt a block with previous output block as IV. */
                xorbufout16(out, out - AES_BLOCK_SIZE, in);
                wc_AesEncrypt(aes, out, out);
                in += AES_BLOCK_SIZE;
                out += AES_BLOCK_SIZE;
            }
            /* Copy last output block into AES object as next IV. */
            memcpy16((byte*)aes->reg, out - AES_BLOCK_SIZE);
        }
        /* in and out are same buffer. */
        else {
            byte* data = out;
            /* Encrypt first block with IV. */
            xorbuf16(data, (byte*)aes->reg);
            wc_AesEncrypt(aes, data, data);
            data += AES_BLOCK_SIZE;
            for (blocks--; blocks > 0; blocks--) {
                /* Encrypt a block with previous output block as IV. */
                xorbuf16(data, data - AES_BLOCK_SIZE);
                wc_AesEncrypt(aes, data, data);
                data += AES_BLOCK_SIZE;
            }
            /* Copy last output block into AES object as next IV. */
            memcpy16((byte*)aes->reg, data - AES_BLOCK_SIZE);
        }
    }

    return ret;
}

#ifdef HAVE_AES_DECRYPT
/* Decrypt blocks of data using AES-CBC.
 *
 * Implementation using wc_AesDecrypt().
 *
 * @param [in]  aes  AES object.
 * @param [out] out  Decrypted blocks.
 * @param [in]  in   Blocks to decrypt.
 * @param pin]  sz   Number of bytes to decrypt.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when aes, out or in is NULL.
 * @return  BAD_FUNC_ARG when sz is not a multiple of AES_BLOCK_SIZE.
 * @return  BAD_LENGTH_E when sz is not a multiple of AES_BLOCK_SIZE.
 */
int wc_AesCbcDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    int ret = 0;
    word32 blocks = sz / AES_BLOCK_SIZE;

    /* Validate parameters. */
    if ((aes == NULL) || (out == NULL) || (in == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Ensure a multiple of blocks is being decrypted.  */
    if ((ret == 0) && (sz % AES_BLOCK_SIZE)) {
#ifdef WOLFSSL_AES_CBC_LENGTH_CHECKS
        ret = BAD_LENGTH_E;
#else
        ret = BAD_FUNC_ARG;
#endif
    }

    if ((ret == 0) && (blocks > 0)) {
        if (in != out) {
            /* Decrypt first block with the IV. */
            wc_AesDecrypt(aes, in, out);
            xorbuf16(out, (byte*)aes->reg);
            in += AES_BLOCK_SIZE;
            out += AES_BLOCK_SIZE;
            for (blocks--; blocks > 0; blocks--) {
                /* Decrypt a block with previous input block as IV. */
                wc_AesDecrypt(aes, in, out);
                xorbuf16(out, in - AES_BLOCK_SIZE);
                in += AES_BLOCK_SIZE;
                out += AES_BLOCK_SIZE;
            }
            /* Copy last output block into AES object as next IV. */
            memcpy16((byte*)aes->reg, in - AES_BLOCK_SIZE);
        }
        /* in and out are same buffer. */
        else {
            byte* data = out;
            for (; blocks > 0; blocks -= 2) {
                /* Decrypt block with the IV in aes->reg. */
                memcpy16((byte*)aes->tmp, data);
                wc_AesDecrypt(aes, data, data);
                xorbuf16(data, (byte*)aes->reg);
                if (blocks == 1) {
                    memcpy16((byte*)aes->reg, (byte*)aes->tmp);
                    break;
                }
                data += AES_BLOCK_SIZE;
                /* Decrypt block with the IV in aes->tmp. */
                memcpy16((byte*)aes->reg, data);
                wc_AesDecrypt(aes, data, data);
                xorbuf16(data, (byte*)aes->tmp);
                data += AES_BLOCK_SIZE;
            }
        }
    }

    return ret;
}
#endif
#endif

/* AES-ECB */
#ifdef HAVE_AES_ECB
/* Encrypt blocks of data using AES-ECB.
 *
 * @param [in]  aes  AES object.
 * @param [out] out  Encrypted blocks.
 * @param [in]  in   Blocks to encrypt.
 * @param pin]  sz   Number of bytes to encrypt.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when aes, out or in is NULL.
 * @return  BAD_LENGTH_E when sz is not a multiple of AES_BLOCK_SIZE.
 */
int wc_AesEcbEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    int ret = 0;

    /* Validate parameters. */
    if ((aes == NULL) || (out == NULL) || (in == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Ensure a multiple of blocks is to be encrypted.  */
    if ((ret == 0) && ((sz % AES_BLOCK_SIZE) != 0)) {
        ret = BAD_LENGTH_E;
    }

    if (ret == 0) {
        /* Encrypt block by block. */
        while (sz > 0) {
            wc_AesEncrypt(aes, in, out);
            out += AES_BLOCK_SIZE;
            in += AES_BLOCK_SIZE;
            sz -= AES_BLOCK_SIZE;
        }
    }

    return ret;
}

#ifdef HAVE_AES_DECRYPT
/* Decrypt blocks of data using AES-ECB.
 *
 * @param [in]  aes  AES object.
 * @param [out] out  Encrypted blocks.
 * @param [in]  in   Blocks to encrypt.
 * @param pin]  sz   Number of bytes to encrypt.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when aes, out or in is NULL.
 * @return  BAD_LENGTH_E when sz is not a multiple of AES_BLOCK_SIZE.
 */
int wc_AesEcbDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    int ret = 0;

    /* Validate parameters. */
    if ((aes == NULL) || (out == NULL) || (in == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Ensure a multiple of blocks is to be decrypted.  */
    if ((ret == 0) && ((sz % AES_BLOCK_SIZE) != 0)) {
        ret = BAD_LENGTH_E;
    }

    if (ret == 0) {
        /* Decrypt block by block. */
        while (sz > 0) {
            wc_AesDecrypt(aes, in, out);
            out += AES_BLOCK_SIZE;
            in += AES_BLOCK_SIZE;
            sz -= AES_BLOCK_SIZE;
        }
    }

    return ret;
}
#endif
#endif /* HAVE_AES_ECB */

/* AES-CTR */
#if defined(WOLFSSL_AES_COUNTER) && !defined(HAVE_AES_COUNTER_ENC)
/* Increment AES counter.
 *
 * Big-endian byte ordering.
 *
 * @param [in, out] inOutCtr  Counter value to be incremented.
 */
static WC_INLINE void IncrementAesCounter(byte* inOutCtr)
{
    int i;

    /* Big-endian aray - start at last element and move back. */
    for (i = AES_BLOCK_SIZE - 1; i >= 0; i--) {
        /* Result not zero means no carry. */
        if ((++inOutCtr[i]) != 0) {
            return;
        }
    }
}

/* Encrypt blocks of data using AES-CTR.
 *
 * Implemenation uses wc_AesEncrypt().
 *
 * @param [in]  aes  AES object.
 * @param [out] out  Encrypted blocks.
 * @param [in]  in   Blocks to encrypt.
 * @param [in]  sz   Number of bytes to encrypt.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when aes, out or in is NULL.
 * @return  BAD_FUNC_ARG when key size in AES object is not supported.
 */
int wc_AesCtrEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    byte scratch[AES_BLOCK_SIZE];
    word32 processed;
    int ret = 0;

    /* Validate parameters. */
    if (aes == NULL || out == NULL || in == NULL) {
        ret = BAD_FUNC_ARG;
    }
    if (ret == 0) {
        /* Check key size is supported. */
        switch(aes->rounds) {
        #ifdef WOLFSSL_AES_128
            case 10: /* AES 128 BLOCK */
        #endif /* WOLFSSL_AES_128 */
        #ifdef WOLFSSL_AES_192
            case 12: /* AES 192 BLOCK */
        #endif /* WOLFSSL_AES_192 */
        #ifdef WOLFSSL_AES_256
            case 14: /* AES 256 BLOCK */
        #endif /* WOLFSSL_AES_256 */
                break;
            default:
                WOLFSSL_MSG("Bad AES-CTR round value");
                ret = BAD_FUNC_ARG;
        }
    }

    if (ret == 0) {
        /* Use up any unused bytes left in aes->tmp */
        processed = min(aes->left, sz);
        if (processed > 0) {
            /* XOR in encrypted counter.  */
            xorbufout(out, in, (byte*)aes->tmp + AES_BLOCK_SIZE - aes->left,
                processed);
            out += processed;
            in += processed;
            aes->left -= processed;
            sz -= processed;
        }

        /* Do whole blocks of data. */
        while (sz >= AES_BLOCK_SIZE) {
            wc_AesEncrypt(aes, (byte*)aes->reg, scratch);
            xorbuf16(scratch, in);
            memcpy16(out, scratch);
            IncrementAesCounter((byte*)aes->reg);

            out += AES_BLOCK_SIZE;
            in  += AES_BLOCK_SIZE;
            sz  -= AES_BLOCK_SIZE;
            aes->left = 0;
        }
        ForceZero(scratch, AES_BLOCK_SIZE);

        if (sz > 0) {
            /* Encrypt counter and store in aes->tmp.
             * Use up aes->tmp to encrypt data less than a block.
             */
            wc_AesEncrypt(aes, (byte*)aes->reg, (byte*)aes->tmp);
            IncrementAesCounter((byte*)aes->reg);
            aes->left = AES_BLOCK_SIZE - sz;
            /* XOR in encrypted counter. */
            xorbufout(out, in, aes->tmp, sz);
        }
    }

    return ret;
}

#endif /* WOLFSSL_AES_COUNTER */

#if defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER)
/* Set AES key directly.
 *
 * @param [in] aes     AES object.
 * @param [in] key     Secret key to use.
 * @param [in] keyLen  Length of key in bytes.
 * @param [in] iv      Initialization Vector (IV) to use. May be NULL.
 * @param [in] dir     Direction of crypt: AES_ENCRYPT, AES_DECRYPT.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when aes or key is NULL.
 * @return  BAD_FUNC_ARG when keyLen/dir is not supported or valid.
 */
int wc_AesSetKeyDirect(Aes* aes, const byte* key, word32 keyLen, const byte* iv,
    int dir)
{
    return wc_AesSetKey(aes, key, keyLen, iv, dir);
}
#endif

/* Set the IV.
 *
 * @param [in] aes  AES object.
 * @param [in] iv   Initialization Vector (IV) to set.
 *                  When NULL, an IV of all zeros is set.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when aes is NULL.
 */
int wc_AesSetIV(Aes* aes, const byte* iv)
{
    int ret = 0;

    if (aes == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else if (iv != NULL) {
        memcpy16((byte*)aes->reg, iv);
    }
    else {
        XMEMSET(aes->reg,  0, AES_BLOCK_SIZE);
    }

    return ret;
}

/* AES-DIRECT */
#ifdef WOLFSSL_AES_DIRECT
/* Direct encryption of a block.
 *
 * @param [in]  aes  AES object.
 * @param [out] out  Encrypted block.
 * @param [in]  in   Block to encrypt.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when aes, out, or in is NULL.
 */
int wc_AesEncryptDirect(Aes* aes, byte* out, const byte* in)
{
    int ret = 0;

    if ((aes == NULL) || (out == NULL) || (in == NULL)) {
        WOLFSSL_MSG("Invalid input to wc_AesEncryptDirect");
        ret = BAD_FUNC_ARG;
    }
    if (ret == 0) {
        wc_AesEncrypt(aes, in, out);
    }

    return ret;
}
#ifdef HAVE_AES_DECRYPT
/* Direct decryption of a block.
 *
 * @param [in]  aes  AES object.
 * @param [out] out  Decrypted block.
 * @param [in]  in   Block to decrypt.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when aes, out, or in is NULL.
 */
int wc_AesDecryptDirect(Aes* aes, byte* out, const byte* in)
{
    int ret = 0;

    if ((aes == NULL) || (out == NULL) || (in == NULL)) {
        WOLFSSL_MSG("Invalid input to wc_AesDecryptDirect");
        ret = BAD_FUNC_ARG;
    }
    if (ret == 0) {
        wc_AesDecrypt(aes, in, out);
    }

    return ret;
}
#endif /* HAVE_AES_DECRYPT */
#endif /* WOLFSSL_AES_DIRECT */

#ifdef WOLFSSL_AES_COUNTER

/* Set the key for AES-CTR.
 *
 * @param [in] aes     AES object.
 * @param [in] key     Secret key to use.
 * @param [in] keyLen  Length of key in bytes.
 * @param [in] iv      Initialization Vector (IV) to use. May be NULL.
 * @param [in] dir     Direction of crypt: AES_ENCRYPT, AES_DECRYPT.
 *                     For CTR mode, underlying key is always for encryption.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when aes or key is NULL.
 * @return  BAD_FUNC_ARG when keyLen is not supported or valid.
 */
int wc_AesCtrSetKey(Aes* aes, const byte* key, word32 len, const byte* iv,
    int dir)
{
    (void)dir;
    return wc_AesSetKey(aes, key, len, iv, AES_ENCRYPTION);
}

#endif /* WOLFSSL_AES_COUNTER */

#ifdef HAVE_AESGCM

#if !defined(WOLFSSL_RISCV_VECTOR_GCM) && \
    !defined(WOLFSSL_RISCV_VECTOR_CARRYLESS) && \
    !defined(WOLFSSL_RISCV_CARRYLESS)
/* Shift x in GF2
 *
 * @param [in, out] x  128-bit value to shift.
 */
static WC_INLINE void RIGHTSHIFTX(byte* x)
{
    int i;
    int carryIn = 0;
    byte borrow = (0x00 - (x[15] & 0x01)) & 0xE1;

    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        int carryOut = (x[i] & 0x01) << 7;
        x[i] = (byte) ((x[i] >> 1) | carryIn);
        carryIn = carryOut;
    }
    x[0] ^= borrow;
}

/* Shift right by 4 a big-endian value in little-endian.
 *
 * @param [out] r8  Result of shift.
 * @param [in]  z8  128-bit value to shift.
 */
static WC_INLINE void Shift4_M0(byte *r8, byte *z8)
{
    int i;
    for (i = 15; i > 0; i--)
        r8[i] = (byte)(z8[i-1] << 4) | (byte)(z8[i] >> 4);
    r8[0] = (byte)(z8[0] >> 4);
}

/* Generate 4-bit table.
 *
 * @param [in, out] gcm  GCM object.
 */
void GenerateM0(Gcm* gcm)
{
    int i;
    byte (*m)[AES_BLOCK_SIZE] = gcm->M0;

    /* 0 times -> 0x0 */
    XMEMSET(m[0x0], 0, AES_BLOCK_SIZE);
    /* 1 times -> 0x8 */
    memcpy16(m[0x8], gcm->H);
    /* 2 times -> 0x4 */
    memcpy16(m[0x4], m[0x8]);
    RIGHTSHIFTX(m[0x4]);
    /* 4 times -> 0x2 */
    memcpy16(m[0x2], m[0x4]);
    RIGHTSHIFTX(m[0x2]);
    /* 8 times -> 0x1 */
    memcpy16(m[0x1], m[0x2]);
    RIGHTSHIFTX(m[0x1]);

    /* 0x3 */
    memcpy16(m[0x3], m[0x2]);
    xorbuf16(m[0x3], m[0x1]);

    /* 0x5 -> 0x7 */
    memcpy16(m[0x5], m[0x4]);
    xorbuf16(m[0x5], m[0x1]);
    memcpy16(m[0x6], m[0x4]);
    xorbuf16(m[0x6], m[0x2]);
    memcpy16(m[0x7], m[0x4]);
    xorbuf16(m[0x7], m[0x3]);

    /* 0x9 -> 0xf */
    memcpy16(m[0x9], m[0x8]);
    xorbuf16(m[0x9], m[0x1]);
    memcpy16(m[0xa], m[0x8]);
    xorbuf16(m[0xa], m[0x2]);
    memcpy16(m[0xb], m[0x8]);
    xorbuf16(m[0xb], m[0x3]);
    memcpy16(m[0xc], m[0x8]);
    xorbuf16(m[0xc], m[0x4]);
    memcpy16(m[0xd], m[0x8]);
    xorbuf16(m[0xd], m[0x5]);
    memcpy16(m[0xe], m[0x8]);
    xorbuf16(m[0xe], m[0x6]);
    memcpy16(m[0xf], m[0x8]);
    xorbuf16(m[0xf], m[0x7]);

    for (i = 0; i < 16; i++) {
        Shift4_M0(m[16+i], m[i]);
    }
}
#endif

/* Setup the AES-GCM operation with the key.
 *
 * @param [in] aes  AES object.
 * @param [in] key  Secret key to use.
 * @param [in] ken  Length of key in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when aes or key is NULL.
 * @return  BAD_FUNC_ARG when the key length is not supported.
 */
int wc_AesGcmSetKey(Aes* aes, const byte* key, word32 len)
{
    int  ret = 0;
    byte iv[AES_BLOCK_SIZE];

    if (aes == NULL) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && (len != 16) && (len != 24) && (len != 32)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        XMEMSET(iv, 0, AES_BLOCK_SIZE);
        ret = wc_AesSetKey(aes, key, len, iv, AES_ENCRYPTION);
    }
    if (ret == 0) {
        wc_AesEncrypt(aes, (byte*)aes->reg, aes->gcm.H);
#ifdef WOLFSSL_RISCV_VECTOR_GCM
        /* Vector crypto instructions do bit reversal. */
#elif defined(WOLFSSL_RISCV_VECTOR_CARRYLESS)
        /* Vector crypto instructions do bit reversal. */
#elif defined(WOLFSSL_RISCV_CARRYLESS)
        /* Reverse bits in aes->gcm.H. */
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION
        __asm__ __volatile__ (
            "ld          t0, 0(%[data])\n\t"
            "ld          t1, 8(%[data])\n\t"
            BREV8(REG_T0, REG_T0)
            BREV8(REG_T1, REG_T1)
            "sd          t0, 0(%[data])\n\t"
            "sd          t1, 8(%[data])\n\t"
        :
        : [data] "r" (aes->gcm.H)
        : "memory", "t0", "t1"
        );
#else
        __asm__ __volatile__ (
            "ld          t0, 0(%[data])\n\t"
            "ld          t1, 8(%[data])\n\t"

            /* Swap odd-even bits. */
            "li          t4, 0x5555555555555555\n\t"
            "srli        t2, t0, 1\n\t"
            "srli        t3, t1, 1\n\t"
            "and         t0, t0, t4\n\t"
            "and         t1, t1, t4\n\t"
            "and         t2, t2, t4\n\t"
            "and         t3, t3, t4\n\t"
            "slli        t0, t0, 1\n\t"
            "slli        t1, t1, 1\n\t"
            "or          t0, t0, t2\n\t"
            "or          t1, t1, t3\n\t"
            /* Swap pairs. */
            "li          t4, 0x3333333333333333\n\t"
            "srli        t2, t0, 2\n\t"
            "srli        t3, t1, 2\n\t"
            "and         t0, t0, t4\n\t"
            "and         t1, t1, t4\n\t"
            "and         t2, t2, t4\n\t"
            "and         t3, t3, t4\n\t"
            "slli        t0, t0, 2\n\t"
            "slli        t1, t1, 2\n\t"
            "or          t0, t0, t2\n\t"
            "or          t1, t1, t3\n\t"
            /* Swap nibbles. */
            "li          t4, 0x0f0f0f0f0f0f0f0f\n\t"
            "srli        t2, t0, 4\n\t"
            "srli        t3, t1, 4\n\t"
            "and         t0, t0, t4\n\t"
            "and         t1, t1, t4\n\t"
            "and         t2, t2, t4\n\t"
            "and         t3, t3, t4\n\t"
            "slli        t0, t0, 4\n\t"
            "slli        t1, t1, 4\n\t"
            "or          t0, t0, t2\n\t"
            "or          t1, t1, t3\n\t"

            "sd          t0, 0(%[data])\n\t"
            "sd          t1, 8(%[data])\n\t"
        :
        : [data] "r" (aes->gcm.H)
        : "memory", "t0", "t1", "t2", "t3", "t4"
        );
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION */
#else
        GenerateM0(&aes->gcm);
#endif
    }

    return ret;
}

#ifndef WOLFSSL_RISCV_VECTOR_GCM
/* Encode sz in bytes into array as big-endian number of bits.
 *
 * @param [out] buf  Buffer to encode size into.
 * @param [in]  sz   Size in bytes.
 */
static WC_INLINE void FlattenSzInBits(byte* buf, word32 sz)
{
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
    __asm__ __volatile__ (
        /* sz is only 32-bits */
        /* Multiply by 8 to get size in bits. */
        "slli       %[sz], %[sz], 3\n\t"
        "srli       t0, %[sz], 32\n\t"
        "srli       t1, %[sz], 24\n\t"
        "srli       t2, %[sz], 16\n\t"
        "srli       t3, %[sz], 8\n\t"
        /* Top 3 bytes are 0. */
        "sh         x0   , 0(%[buf])\n\t"
        "sb         x0   , 2(%[buf])\n\t"
        "sb         t0   , 3(%[buf])\n\t"
        "sb         t1   , 4(%[buf])\n\t"
        "sb         t2   , 5(%[buf])\n\t"
        "sb         t3   , 6(%[buf])\n\t"
        "sb         %[sz], 7(%[buf])\n\t"
        : [sz] "+r" (sz)
        : [buf] "r" (buf)
        : "memory", "t0", "t1", "t2", "t3"
    );
#else
    __asm__ __volatile__ (
        "slli       t0, %[sz], 3\n\t"
        REV8(REG_T0, REG_T0)
        "sd         t0, 0(%[buf])\n\t"
        :
        : [sz] "r" (sz), [buf] "r" (buf)
        : "memory", "t0"
    );
#endif
}
#endif

#if defined(WOLFSSL_RISCV_VECTOR_GCM)

/* Vector GHASH: vd = (vd ^ vs1) * vs2 */
#define VGHSH_VV(vd, vs1, vs2)                                              \
    ASM_WORD((0b101100 << 26) | (0b1 << 25) | (0b010 << 12) |               \
             (0b1110111 << 0) | (vs2 << 20) | (vs1 << 15) | (vd << 7))
/* Vector GMULT: vd = vd * vs2 */
#define VGMUL_VV(vd, vs2)                                                   \
    ASM_WORD((0b101000 << 26) | (0b1 << 25) | (0b010 << 12) |               \
             (0b1110111 << 0) | (vs2 << 20) | (0b10001 << 15) | (vd << 7))

/* GHASH Additional Authentication Data (AAD) and cipher text.
 *
 * @param [in]  gcm  GCM object.
 * @param [in]  a    Additional Authentication Data (AAD).
 * @param [in]  aSz  Size of AAD in bytes.
 * @param [in]  c    Cipher text.
 * @param [in]  cSz  Size of cipher text in bytes.
 * @param [out] s    Hash result.
 * @param [in]  sSz  Number of bytes to put into hash result.
 */
void GHASH(Gcm* gcm, const byte* a, word32 aSz, const byte* c, word32 cSz,
    byte* s, word32 sSz)
{
    if (gcm != NULL) {
        byte x[AES_BLOCK_SIZE];
        byte scratch[AES_BLOCK_SIZE];
        byte* h = gcm->H;

        __asm__ __volatile__ (
            VXOR_VV(REG_V0, REG_V0, REG_V0)

            /* Hash in A, the Additional Authentication Data */
            "beqz       %[aSz], L_ghash_aad_done\n\t"
            "beqz       %[a], L_ghash_aad_done\n\t"

            "srli       t3, %[aSz], 4\n\t"
            VSETIVLI(REG_T0, 4, 0, 0, 0b010, 0b000)
            "mv         t0, %[h]\n\t"
            VL1RE32_V(REG_V1, REG_T0)

            "beqz       t3, L_ghash_aad_blocks_done\n\t"
         "L_ghash_aad_loop:\n\t"
            "mv         t0, %[a]\n\t"
            VL1RE32_V(REG_V2, REG_T0)
            VGHSH_VV(REG_V0, REG_V2, REG_V1)
            "addi       %[a], %[a], 16\n\t"
            "addi       t3, t3, -1\n\t"
            "bnez       t3, L_ghash_aad_loop\n\t"
         "L_ghash_aad_blocks_done:\n\t"
            "andi       t3, %[aSz], 0xf\n\t"
            "beqz       t3, L_ghash_aad_done\n\t"
            VXOR_VV(REG_V2, REG_V2, REG_V2)
            "mv         t0, %[scratch]\n\t"
            VS1R_V(REG_V2, REG_T0)
            "mv         t2, t3\n\t"
         "L_ghash_aad_load_byte:\n\t"
            "lb         t0, (%[a])\n\t"
            "sb         t0, (%[scratch])\n\t"
            "addi       %[a], %[a], 1\n\t"
            "addi       %[scratch], %[scratch], 1\n\t"
            "addi       t2, t2, -1\n\t"
            "bnez       t2, L_ghash_aad_load_byte\n\t"
            "sub        %[scratch], %[scratch], t3\n\t"
            "mv         t0, %[scratch]\n\t"
            VL1RE32_V(REG_V2, REG_T0)
            VGHSH_VV(REG_V0, REG_V2, REG_V1)
         "L_ghash_aad_done:\n\t"

            /* Hash in C, the Ciphertext */
            "beqz       %[cSz], L_ghash_ct_done\n\t"
            "beqz       %[c], L_ghash_ct_done\n\t"

            "srli       t3, %[cSz], 4\n\t"
            VSETIVLI(REG_T0, 4, 0, 0, 0b010, 0b000)
            "mv         t0, %[h]\n\t"
            VL1RE32_V(REG_V1, REG_T0)

            "beqz       t3, L_ghash_ct_blocks_done\n\t"
         "L_ghash_ct_loop:\n\t"
            "mv         t0, %[c]\n\t"
            VL1RE32_V(REG_V2, REG_T0)
            VGHSH_VV(REG_V0, REG_V2, REG_V1)
            "addi       %[c], %[c], 16\n\t"
            "addi       t3, t3, -1\n\t"
            "bnez       t3, L_ghash_ct_loop\n\t"
         "L_ghash_ct_blocks_done:\n\t"
            "andi       t3, %[cSz], 0xf\n\t"
            "beqz       t3, L_ghash_ct_done\n\t"
            VXOR_VV(REG_V2, REG_V2, REG_V2)
            "mv         t0, %[scratch]\n\t"
            VS1R_V(REG_V2, REG_T0)
            "mv         t2, t3\n\t"
         "L_ghash_ct_load_byte:\n\t"
            "lb         t0, (%[c])\n\t"
            "sb         t0, (%[scratch])\n\t"
            "addi       %[c], %[c], 1\n\t"
            "addi       %[scratch], %[scratch], 1\n\t"
            "addi       t2, t2, -1\n\t"
            "bnez       t2, L_ghash_ct_load_byte\n\t"
            "sub        %[scratch], %[scratch], t3\n\t"
            "mv         t0, %[scratch]\n\t"
            VL1RE32_V(REG_V2, REG_T0)
            VGHSH_VV(REG_V0, REG_V2, REG_V1)
         "L_ghash_ct_done:\n\t"

            /* Hash in the lengths of A and C in bits */
        #ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
            /* aSz is only 32-bits */
            /* Multiply by 8 do get size in bits. */
            "slli       %[aSz], %[aSz], 3\n\t"
            "srli       t0, %[aSz], 32\n\t"
            "srli       t1, %[aSz], 24\n\t"
            "srli       t2, %[aSz], 16\n\t"
            "srli       t3, %[aSz], 8\n\t"
            /* Top 3 bytes are 0. */
            "sh         x0    , 0(%[scratch])\n\t"
            "sb         x0    , 2(%[scratch])\n\t"
            "sb         t0    , 3(%[scratch])\n\t"
            "sb         t1    , 4(%[scratch])\n\t"
            "sb         t2    , 5(%[scratch])\n\t"
            "sb         t3    , 6(%[scratch])\n\t"
            "sb         %[aSz], 7(%[scratch])\n\t"
            /* cSz is only 32-bits */
            /* Multiply by 8 do get size in bits. */
            "slli       %[cSz], %[cSz], 3\n\t"
            "srli       t0, %[cSz], 32\n\t"
            "srli       t1, %[cSz], 24\n\t"
            "srli       t2, %[cSz], 16\n\t"
            "srli       t3, %[cSz], 8\n\t"
            /* Top 3 bytes are 0. */
            "sh         x0    ,  8(%[scratch])\n\t"
            "sb         x0    , 10(%[scratch])\n\t"
            "sb         t0    , 11(%[scratch])\n\t"
            "sb         t1    , 12(%[scratch])\n\t"
            "sb         t2    , 13(%[scratch])\n\t"
            "sb         t3    , 14(%[scratch])\n\t"
            "sb         %[cSz], 15(%[scratch])\n\t"
        #else
            "slli       t0, %[aSz], 3\n\t"
            REV8(REG_T0, REG_T0)
            "sd         t0, 0(%[scratch])\n\t"
            "slli       t0, %[cSz], 3\n\t"
            REV8(REG_T0, REG_T0)
            "sd         t0, 8(%[scratch])\n\t"
        #endif
            "mv         t0, %[scratch]\n\t"
            VL1RE32_V(REG_V2, REG_T0)
            VGHSH_VV(REG_V0, REG_V2, REG_V1)

            "mv         t1, %[x]\n\t"
            VS1R_V(REG_V0, REG_T1)

            : [a] "+r" (a), [c] "+r" (c) , [aSz] "+r" (aSz), [cSz] "+r" (cSz)
            : [x] "r" (x), [h] "r" (h), [scratch] "r" (scratch)
            : "memory", "t0", "t1", "t2", "t3"
        );

        /* Copy the result into s. */
        XMEMCPY(s, x, sSz);
    }
}

#define HAVE_GHASH

#elif defined(WOLFSSL_RISCV_VECTOR_CARRYLESS)

#define VCLMUL_VV(vd, vs1, vs2) \
    ASM_WORD((0b001100 << 26) | (0b1 << 25) | (0b010 << 12) | \
             (0b1010111 << 0) | (vs2 << 20) | (vs1 << 15) | (vd << 7))
#define VCLMULH_VV(vd, vs1, vs2) \
    ASM_WORD((0b001101 << 26) | (0b1 << 25) | (0b010 << 12) | \
             (0b1010111 << 0) | (vs2 << 20) | (vs1 << 15) | (vd << 7))

/* GMULT, multiply in GF2, x and y into x.
 *
 * @param [in, out]  x  On in, value to GMULT.
 *                      On out, result of GMULT.
 * @param [in]       y  Value to GMULT.
 */
static void GMULT(byte* x, byte* y)
{
    static byte red[16] = {
        0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    __asm__ __volatile__ (
        VSETIVLI(REG_X0, 2, 0, 0, 0b011, 0b000)

        /* 0x87 into both 64-bit elements of v7. */
        "mv          t1, %[red]\n\t"
        VL1RE64_V(REG_V8, REG_T1)

        "mv          t1, %[x]\n\t"
        VL1RE64_V(REG_V0, REG_T1)
        "mv          t0, %[y]\n\t"
        VL1RE64_V(REG_V1, REG_T0)
        /* Reverse x and y. */
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VBREV8(REG_V0, REG_V0)
        VBREV8(REG_V1, REG_V1)
#else
        VSETIVLI(REG_X0, 16, 0, 0, 0b000, 0b000)

        /* Swap odd/even bits. */
        "li          t0, 0x55\n\t"
        VMV_V_X(REG_V4, REG_T0)
        VSRL_VI(REG_V2, REG_V0, 1)
        VSRL_VI(REG_V3, REG_V1, 1)
        VAND_VV(REG_V0, REG_V0, REG_V4)
        VAND_VV(REG_V1, REG_V1, REG_V4)
        VAND_VV(REG_V2, REG_V2, REG_V4)
        VAND_VV(REG_V3, REG_V3, REG_V4)
        VSLL_VI(REG_V0, REG_V0, 1)
        VSLL_VI(REG_V1, REG_V1, 1)
        VOR_VV(REG_V0, REG_V0, REG_V2)
        VOR_VV(REG_V1, REG_V1, REG_V3)
        /* Swap pairs of bits. */
        "li          t0, 0x33\n\t"
        VMV_V_X(REG_V4, REG_T0)
        VSRL_VI(REG_V2, REG_V0, 2)
        VSRL_VI(REG_V3, REG_V1, 2)
        VAND_VV(REG_V0, REG_V0, REG_V4)
        VAND_VV(REG_V1, REG_V1, REG_V4)
        VAND_VV(REG_V2, REG_V2, REG_V4)
        VAND_VV(REG_V3, REG_V3, REG_V4)
        VSLL_VI(REG_V0, REG_V0, 2)
        VSLL_VI(REG_V1, REG_V1, 2)
        VOR_VV(REG_V0, REG_V0, REG_V2)
        VOR_VV(REG_V1, REG_V1, REG_V3)
        /* Swap nibbles. */
        "li          t0, 0x0f\n\t"
        VMV_V_X(REG_V4, REG_T0)
        VSRL_VI(REG_V2, REG_V0, 4)
        VSRL_VI(REG_V3, REG_V1, 4)
        VAND_VV(REG_V0, REG_V0, REG_V4)
        VAND_VV(REG_V1, REG_V1, REG_V4)
        VAND_VV(REG_V2, REG_V2, REG_V4)
        VAND_VV(REG_V3, REG_V3, REG_V4)
        VSLL_VI(REG_V0, REG_V0, 4)
        VSLL_VI(REG_V1, REG_V1, 4)
        VOR_VV(REG_V0, REG_V0, REG_V2)
        VOR_VV(REG_V1, REG_V1, REG_V3)

        VSETIVLI(REG_X0, 2, 0, 0, 0b011, 0b000)
#endif

        /* v2 = (x[1] * y[1])[0] | (x[0] * y[0])[0]  */
        VCLMUL_VV(REG_V2, REG_V0, REG_V1)
        /* v3 = (x[1] * y[1])[1] | (x[0] * y[0])[1]  */
        VCLMULH_VV(REG_V3, REG_V0, REG_V1)
        /* V2 = R[2] | R[0], V3 = R[3] | R[1] */

        /* SWAP 64-bit values from V1 into V6. V6 = V1[0] | V1[1] */
        VSLIDEDOWN_VI(REG_V6, REG_V1, 1)
        VSLIDEUP_VI(REG_V6, REG_V1, 1)
        /* (x[1] * y[0])[0] | (x[0] * y[1])[0]  */
        VCLMUL_VV(REG_V4, REG_V0, REG_V6)
        /* (x[1] * y[0])[1] | (x[0] * y[1])[1]  */
        VCLMULH_VV(REG_V5, REG_V0, REG_V6)
        /* V4 = R[1] | R[1], V5 = R[2] | R[2] */

        VMV_V_V(REG_V1, REG_V3)
        VSLIDEDOWN_VI(REG_V0, REG_V2, 1)
        VSLIDEUP_VI(REG_V1, REG_V0, 1)
        /* V2 =  ---- | R[0], V3 = R[3] | ----, V1 = R[2] | R[1] */

        VMV_V_V(REG_V6, REG_V4)
        /* V7 = ---- | ----, V6 = ---- | R[1] */
        VSLIDEDOWN_VI(REG_V7, REG_V4, 1)
        /* V7 = ---- | R[1], V6 = ---- | R[1] */
        VSLIDEUP_VI(REG_V6, REG_V5, 1)
        /* V7 = ---- | R[1], V6 = R[2] | R[1] */
        VSLIDEDOWN_VI(REG_V0, REG_V5, 1)
        VSLIDEUP_VI(REG_V7, REG_V0, 1)
        /* V7 = R[2] | R[1], V6 = R[2] | R[1] */
        VXOR_VV(REG_V1, REG_V1, REG_V6)
        VXOR_VV(REG_V1, REG_V1, REG_V7)
        /* V2 =  ---- | R[0], V3 = R[3] | ----, V1 = R[2] | R[1] */
        VSLIDEUP_VI(REG_V2, REG_V1, 1)
        VSLIDEDOWN_VI(REG_V5, REG_V3, 1)
        VSLIDEDOWN_VI(REG_V3, REG_V1, 1)
        VSLIDEUP_VI(REG_V3, REG_V5, 1)
        /* V2 =  R[1] | R[0], V3 = R[3] | R[2] */

        /* Reduce */
        /* v0 = (R[3] * 0x87)[0] | (R[2] * 0x87)[0]  */
        VCLMUL_VV(REG_V0, REG_V3, REG_V8)
        /* v1 = (R[3] * 0x87)[1] | (R[2] * 0x87)[1]  */
        VCLMULH_VV(REG_V1, REG_V3, REG_V8)
        /* V0 = r[1] | r[0], V1 = r[2] | r[1] */
        VXOR_VV(REG_V4, REG_V4, REG_V4)
        VXOR_VV(REG_V2, REG_V2, REG_V0)
        VSLIDEUP_VI(REG_V4, REG_V1, 1)
        VXOR_VV(REG_V2, REG_V2, REG_V4)
        VSLIDEDOWN_VI(REG_V3, REG_V1, 1)
        /* v0 = ---- | (r[2] * 0x87)[0]  */
        VCLMUL_VV(REG_V0, REG_V3, REG_V8)
        /* v1 = ---- | (r[2] * 0x87)[1] */
        VCLMULH_VV(REG_V1, REG_V3, REG_V8)
        /* V0 = ---- | r[0] , V1 = ---- | r[1] */
        VSLIDEUP_VI(REG_V0, REG_V1, 1)
        /* V1 = R[1] | R[0] */
        VXOR_VV(REG_V2, REG_V2, REG_V0)

        /* Reverse x. */
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VBREV8(REG_V2, REG_V2)
#else
        VSETIVLI(REG_X0, 16, 0, 0, 0b000, 0b000)

        /* Swap odd/even bits. */
        "li          t0, 0x55\n\t"
        VMV_V_X(REG_V4, REG_T0)
        VSRL_VI(REG_V0, REG_V2, 1)
        VAND_VV(REG_V2, REG_V2, REG_V4)
        VAND_VV(REG_V0, REG_V0, REG_V4)
        VSLL_VI(REG_V2, REG_V2, 1)
        VOR_VV(REG_V2, REG_V2, REG_V0)
        /* Swap pairs of bits. */
        "li          t0, 0x33\n\t"
        VMV_V_X(REG_V4, REG_T0)
        VSRL_VI(REG_V0, REG_V2, 2)
        VAND_VV(REG_V2, REG_V2, REG_V4)
        VAND_VV(REG_V0, REG_V0, REG_V4)
        VSLL_VI(REG_V2, REG_V2, 2)
        VOR_VV(REG_V2, REG_V2, REG_V0)
        /* Swap nibbles. */
        "li          t0, 0x0f\n\t"
        VMV_V_X(REG_V4, REG_T0)
        VSRL_VI(REG_V0, REG_V2, 4)
        VAND_VV(REG_V2, REG_V2, REG_V4)
        VAND_VV(REG_V0, REG_V0, REG_V4)
        VSLL_VI(REG_V2, REG_V2, 4)
        VOR_VV(REG_V2, REG_V2, REG_V0)

        VSETIVLI(REG_X0, 2, 0, 0, 0b011, 0b000)
#endif
        VS1R_V(REG_V2, REG_T1)
        :
        : [x] "r" (x), [y] "r" (y), [red] "r" (red)
        : "memory", "t0", "t1", "t2"
    );
}

/* GHASH Additional Authentication Data (AAD) and cipher text.
 *
 * @param [in]  gcm  GCM object.
 * @param [in]  a    Additional Authentication Data (AAD).
 * @param [in]  aSz  Size of AAD in bytes.
 * @param [in]  c    Cipher text.
 * @param [in]  cSz  Size of cipher text in bytes.
 * @param [out] s    Hash result.
 * @param [in]  sSz  Number of bytes to put into hash result.
 */
void GHASH(Gcm* gcm, const byte* a, word32 aSz, const byte* c, word32 cSz,
    byte* s, word32 sSz)
{
    byte x[AES_BLOCK_SIZE];
    byte scratch[AES_BLOCK_SIZE];
    word32 blocks, partial;
    byte* h;

    if (gcm == NULL) {
        return;
    }

    h = gcm->H;
    XMEMSET(x, 0, AES_BLOCK_SIZE);

    /* Hash in A, the Additional Authentication Data */
    if (aSz != 0 && a != NULL) {
        blocks = aSz / AES_BLOCK_SIZE;
        partial = aSz % AES_BLOCK_SIZE;
        while (blocks--) {
            xorbuf16(x, a);
            GMULT(x, h);
            a += AES_BLOCK_SIZE;
        }
        if (partial != 0) {
            XMEMSET(scratch, 0, AES_BLOCK_SIZE);
            XMEMCPY(scratch, a, partial);
            xorbuf16(x, scratch);
            GMULT(x, h);
        }
    }

    /* Hash in C, the Ciphertext */
    if (cSz != 0 && c != NULL) {
        blocks = cSz / AES_BLOCK_SIZE;
        partial = cSz % AES_BLOCK_SIZE;
        while (blocks--) {
            xorbuf16(x, c);
            GMULT(x, h);
            c += AES_BLOCK_SIZE;
        }
        if (partial != 0) {
            XMEMSET(scratch, 0, AES_BLOCK_SIZE);
            XMEMCPY(scratch, c, partial);
            xorbuf16(x, scratch);
            GMULT(x, h);
        }
    }

    /* Hash in the lengths of A and C in bits */
    FlattenSzInBits(&scratch[0], aSz);
    FlattenSzInBits(&scratch[8], cSz);
    xorbuf16(x, scratch);
    GMULT(x, h);

    /* Copy the result into s. */
    XMEMCPY(s, x, sSz);
}

#define HAVE_GHASH

#elif defined(WOLFSSL_RISCV_CARRYLESS)

/* Bottom half of carryless-multiplication: rd = (rs1 * rs2)[0..63]. */
#define CLMUL(rd, rs1, rs2)                                 \
    ASM_WORD(0b00001010000000000001000000110011 |           \
             (rd << 7) | (rs1 << 15) | (rs2 << 20))
/* Top half of carryless-multiplication: rd = (rs1 * rs2)[64..127]. */
#define CLMULH(rd, rs1, rs2)                                \
    ASM_WORD(0b00001010000000000011000000110011 |           \
             (rd << 7) | (rs1 << 15) | (rs2 << 20))

/* GMULT, multiply in GF2, x and y into x.
 *
 * @param [in, out]  x  On in, value to GMULT.
 *                      On out, result of GMULT.
 * @param [in]       y  Value to GMULT.
 */
static void GMULT(byte* x, byte* y)
{
    __asm__ __volatile__ (
        "ld         t0, 0(%[x])\n\t"
        "ld         t1, 8(%[x])\n\t"
        "ld         t2, 0(%[y])\n\t"
        "ld         t3, 8(%[y])\n\t"
        /* Load reduction value into t6 */
        "li         t6, 0x87\n\t"
        /* Reverse x. y was reversed in wc_AesGcmSetKey. */
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION
        BREV8(REG_T0, REG_T0)
        BREV8(REG_T1, REG_T1)
#else
        /* Swap odd-even bits. */
        "li          a4, 0x5555555555555555\n\t"
        "srli        a2, t0, 1\n\t"
        "srli        a3, t1, 1\n\t"
        "and         t0, t0, a4\n\t"
        "and         t1, t1, a4\n\t"
        "and         a2, a2, a4\n\t"
        "and         a3, a3, a4\n\t"
        "slli        t0, t0, 1\n\t"
        "slli        t1, t1, 1\n\t"
        "or          t0, t0, a2\n\t"
        "or          t1, t1, a3\n\t"
        /* Swap pairs. */
        "li          a4, 0x3333333333333333\n\t"
        "srli        a2, t0, 2\n\t"
        "srli        a3, t1, 2\n\t"
        "and         t0, t0, a4\n\t"
        "and         t1, t1, a4\n\t"
        "and         a2, a2, a4\n\t"
        "and         a3, a3, a4\n\t"
        "slli        t0, t0, 2\n\t"
        "slli        t1, t1, 2\n\t"
        "or          t0, t0, a2\n\t"
        "or          t1, t1, a3\n\t"
        /* Swap nibbles. */
        "li          a4, 0x0f0f0f0f0f0f0f0f\n\t"
        "srli        a2, t0, 4\n\t"
        "srli        a3, t1, 4\n\t"
        "and         t0, t0, a4\n\t"
        "and         t1, t1, a4\n\t"
        "and         a2, a2, a4\n\t"
        "and         a3, a3, a4\n\t"
        "slli        t0, t0, 4\n\t"
        "slli        t1, t1, 4\n\t"
        "or          t0, t0, a2\n\t"
        "or          t1, t1, a3\n\t"
#endif

        /* r[0..1] = x[0] * y[0] */
        CLMUL(REG_A2, REG_T0, REG_T2)
        CLMULH(REG_A3, REG_T0, REG_T2)
        /* r[2..3] = x[1] * y[1] */
        CLMUL(REG_A4, REG_T1, REG_T3)
        CLMULH(REG_A5, REG_T1, REG_T3)
        /* r[1..2] ^= x[1] * y[0] */
        CLMUL(REG_T4, REG_T1, REG_T2)
        CLMULH(REG_T5, REG_T1, REG_T2)
        "xor        a3, a3, t4\n\t"
        "xor        a4, a4, t5\n\t"
        /* r[1..2] ^= x[0] * y[1] */
        CLMUL(REG_T4, REG_T0, REG_T3)
        CLMULH(REG_T5, REG_T0, REG_T3)
        "xor        a3, a3, t4\n\t"
        "xor        a4, a4, t5\n\t"

        /* Reduce */
        CLMUL(REG_T4, REG_A5, REG_T6)
        CLMULH(REG_T5, REG_A5, REG_T6)
        "xor        a3, a3, t4\n\t"
        "xor        a4, a4, t5\n\t"
        CLMUL(REG_T4, REG_A4, REG_T6)
        CLMULH(REG_T5, REG_A4, REG_T6)
        "xor        t0, a2, t4\n\t"
        "xor        t1, a3, t5\n\t"

        /* Reverse x. */
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION
        BREV8(REG_T0, REG_T0)
        BREV8(REG_T1, REG_T1)
#else
        /* Swap odd-even bits. */
        "li          a4, 0x5555555555555555\n\t"
        "srli        a2, t0, 1\n\t"
        "srli        a3, t1, 1\n\t"
        "and         t0, t0, a4\n\t"
        "and         t1, t1, a4\n\t"
        "and         a2, a2, a4\n\t"
        "and         a3, a3, a4\n\t"
        "slli        t0, t0, 1\n\t"
        "slli        t1, t1, 1\n\t"
        "or          t0, t0, a2\n\t"
        "or          t1, t1, a3\n\t"
        /* Swap pairs. */
        "li          a4, 0x3333333333333333\n\t"
        "srli        a2, t0, 2\n\t"
        "srli        a3, t1, 2\n\t"
        "and         t0, t0, a4\n\t"
        "and         t1, t1, a4\n\t"
        "and         a2, a2, a4\n\t"
        "and         a3, a3, a4\n\t"
        "slli        t0, t0, 2\n\t"
        "slli        t1, t1, 2\n\t"
        "or          t0, t0, a2\n\t"
        "or          t1, t1, a3\n\t"
        /* Swap nibbles. */
        "li          a4, 0x0f0f0f0f0f0f0f0f\n\t"
        "srli        a2, t0, 4\n\t"
        "srli        a3, t1, 4\n\t"
        "and         t0, t0, a4\n\t"
        "and         t1, t1, a4\n\t"
        "and         a2, a2, a4\n\t"
        "and         a3, a3, a4\n\t"
        "slli        t0, t0, 4\n\t"
        "slli        t1, t1, 4\n\t"
        "or          t0, t0, a2\n\t"
        "or          t1, t1, a3\n\t"
#endif
        "sd         t0, 0(%[x])\n\t"
        "sd         t1, 8(%[x])\n\t"
        :
        : [x] "r" (x), [y] "r" (y)
        : "memory", "t0", "t1", "t2", "t3", "t4", "t5", "t6",
          "a2", "a3", "a4", "a5"
    );
}

/* GHASH blocks of data.
 *
 * @param [in, out]  x       On in, value to GMULT.
 *                           On out, result of GMULT.
 * @param [in]       y       Value to GMULT.
 * @param [in]       in      Blocks of data to GHASH.
 * @param [in]       blocks  Number of blocks to GHASH.
 */
static void ghash_blocks(byte* x, byte* y, const byte* in, word32 blocks)
{
    __asm__ __volatile__ (
        "ld         t0, 0(%[x])\n\t"
        "ld         t1, 8(%[x])\n\t"
        "ld         t2, 0(%[y])\n\t"
        "ld         t3, 8(%[y])\n\t"
        /* Load reduction value into t6 */
        "li         t6, 0x87\n\t"
        /* Reverse x. y was reversed in wc_AesGcmSetKey. */
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION
        BREV8(REG_T0, REG_T0)
        BREV8(REG_T1, REG_T1)
#else
        /* Swap odd-even bits. */
        "li          a4, 0x5555555555555555\n\t"
        "srli        a2, t0, 1\n\t"
        "srli        a3, t1, 1\n\t"
        "and         t0, t0, a4\n\t"
        "and         t1, t1, a4\n\t"
        "and         a2, a2, a4\n\t"
        "and         a3, a3, a4\n\t"
        "slli        t0, t0, 1\n\t"
        "slli        t1, t1, 1\n\t"
        "or          t0, t0, a2\n\t"
        "or          t1, t1, a3\n\t"
        /* Swap pairs. */
        "li          a4, 0x3333333333333333\n\t"
        "srli        a2, t0, 2\n\t"
        "srli        a3, t1, 2\n\t"
        "and         t0, t0, a4\n\t"
        "and         t1, t1, a4\n\t"
        "and         a2, a2, a4\n\t"
        "and         a3, a3, a4\n\t"
        "slli        t0, t0, 2\n\t"
        "slli        t1, t1, 2\n\t"
        "or          t0, t0, a2\n\t"
        "or          t1, t1, a3\n\t"
        /* Swap nibbles. */
        "li          a4, 0x0f0f0f0f0f0f0f0f\n\t"
        "srli        a2, t0, 4\n\t"
        "srli        a3, t1, 4\n\t"
        "and         t0, t0, a4\n\t"
        "and         t1, t1, a4\n\t"
        "and         a2, a2, a4\n\t"
        "and         a3, a3, a4\n\t"
        "slli        t0, t0, 4\n\t"
        "slli        t1, t1, 4\n\t"
        "or          t0, t0, a2\n\t"
        "or          t1, t1, a3\n\t"
#endif

    "L_ghash_loop:\n\t"
        /* Load input block. */
        "ld          t5, 0(%[in])\n\t"
        "ld          a5, 8(%[in])\n\t"
        /* Reverse bits to match x. */
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION
        BREV8(REG_T5, REG_T5)
        BREV8(REG_A5, REG_A5)
#else
        /* Swap odd-even bits. */
        "li          a4, 0x5555555555555555\n\t"
        "srli        a2, t5, 1\n\t"
        "srli        a3, a5, 1\n\t"
        "and         t5, t5, a4\n\t"
        "and         a5, a5, a4\n\t"
        "and         a2, a2, a4\n\t"
        "and         a3, a3, a4\n\t"
        "slli        t5, t5, 1\n\t"
        "slli        a5, a5, 1\n\t"
        "or          t5, t5, a2\n\t"
        "or          a5, a5, a3\n\t"
        /* Swap pairs. */
        "li          a4, 0x3333333333333333\n\t"
        "srli        a2, t5, 2\n\t"
        "srli        a3, a5, 2\n\t"
        "and         t5, t5, a4\n\t"
        "and         a5, a5, a4\n\t"
        "and         a2, a2, a4\n\t"
        "and         a3, a3, a4\n\t"
        "slli        t5, t5, 2\n\t"
        "slli        a5, a5, 2\n\t"
        "or          t5, t5, a2\n\t"
        "or          a5, a5, a3\n\t"
        /* Swap nibbles. */
        "li          a4, 0x0f0f0f0f0f0f0f0f\n\t"
        "srli        a2, t5, 4\n\t"
        "srli        a3, a5, 4\n\t"
        "and         t5, t5, a4\n\t"
        "and         a5, a5, a4\n\t"
        "and         a2, a2, a4\n\t"
        "and         a3, a3, a4\n\t"
        "slli        t5, t5, 4\n\t"
        "slli        a5, a5, 4\n\t"
        "or          t5, t5, a2\n\t"
        "or          a5, a5, a3\n\t"
#endif
        /* XOR input into x. */
        "xor         t0, t0, t5\n\t"
        "xor         t1, t1, a5\n\t"

        /* r[0..1] = x[0] * y[0] */
        CLMUL(REG_A2, REG_T0, REG_T2)
        CLMULH(REG_A3, REG_T0, REG_T2)
        /* r[2..3] = x[1] * y[1] */
        CLMUL(REG_A4, REG_T1, REG_T3)
        CLMULH(REG_A5, REG_T1, REG_T3)
        /* r[1..2] ^= x[1] * y[0] */
        CLMUL(REG_T4, REG_T1, REG_T2)
        CLMULH(REG_T5, REG_T1, REG_T2)
        "xor        a3, a3, t4\n\t"
        "xor        a4, a4, t5\n\t"
        /* r[1..2] ^= x[0] * y[1] */
        CLMUL(REG_T4, REG_T0, REG_T3)
        CLMULH(REG_T5, REG_T0, REG_T3)
        "xor        a3, a3, t4\n\t"
        "xor        a4, a4, t5\n\t"

        /* Reduce */
        CLMUL(REG_T4, REG_A5, REG_T6)
        CLMULH(REG_T5, REG_A5, REG_T6)
        "xor        a3, a3, t4\n\t"
        "xor        a4, a4, t5\n\t"
        CLMUL(REG_T4, REG_A4, REG_T6)
        CLMULH(REG_T5, REG_A4, REG_T6)
        "xor        t0, a2, t4\n\t"
        "xor        t1, a3, t5\n\t"

        "addi        %[in], %[in], 16\n\t"
        "addi        %[blocks], %[blocks], -1\n\t"
        "bnez        %[blocks], L_ghash_loop\n\t"

        /* Reverse x. */
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION
        BREV8(REG_T0, REG_T0)
        BREV8(REG_T1, REG_T1)
#else
        /* Swap odd-even bits. */
        "li          a4, 0x5555555555555555\n\t"
        "srli        a2, t0, 1\n\t"
        "srli        a3, t1, 1\n\t"
        "and         t0, t0, a4\n\t"
        "and         t1, t1, a4\n\t"
        "and         a2, a2, a4\n\t"
        "and         a3, a3, a4\n\t"
        "slli        t0, t0, 1\n\t"
        "slli        t1, t1, 1\n\t"
        "or          t0, t0, a2\n\t"
        "or          t1, t1, a3\n\t"
        /* Swap pairs. */
        "li          a4, 0x3333333333333333\n\t"
        "srli        a2, t0, 2\n\t"
        "srli        a3, t1, 2\n\t"
        "and         t0, t0, a4\n\t"
        "and         t1, t1, a4\n\t"
        "and         a2, a2, a4\n\t"
        "and         a3, a3, a4\n\t"
        "slli        t0, t0, 2\n\t"
        "slli        t1, t1, 2\n\t"
        "or          t0, t0, a2\n\t"
        "or          t1, t1, a3\n\t"
        /* Swap nibbles. */
        "li          a4, 0x0f0f0f0f0f0f0f0f\n\t"
        "srli        a2, t0, 4\n\t"
        "srli        a3, t1, 4\n\t"
        "and         t0, t0, a4\n\t"
        "and         t1, t1, a4\n\t"
        "and         a2, a2, a4\n\t"
        "and         a3, a3, a4\n\t"
        "slli        t0, t0, 4\n\t"
        "slli        t1, t1, 4\n\t"
        "or          t0, t0, a2\n\t"
        "or          t1, t1, a3\n\t"
#endif
        "sd         t0, 0(%[x])\n\t"
        "sd         t1, 8(%[x])\n\t"
        : [in] "+r" (in), [blocks] "+r" (blocks)
        : [x] "r" (x), [y] "r" (y)
        : "memory", "t0", "t1", "t2", "t3", "t4", "t5", "t6",
          "a2", "a3", "a4", "a5"
    );
}

/* GHASH Additional Authentication Data (AAD) and cipher text.
 *
 * @param [in]  gcm  GCM object.
 * @param [in]  a    Additional Authentication Data (AAD).
 * @param [in]  aSz  Size of AAD in bytes.
 * @param [in]  c    Cipher text.
 * @param [in]  cSz  Size of cipher text in bytes.
 * @param [out] s    Hash result.
 * @param [in]  sSz  Number of bytes to put into hash result.
 */
void GHASH(Gcm* gcm, const byte* a, word32 aSz, const byte* c, word32 cSz,
    byte* s, word32 sSz)
{
    if (gcm != NULL) {
        byte x[AES_BLOCK_SIZE];
        byte scratch[AES_BLOCK_SIZE];
        word32 blocks, partial;
        byte* h = gcm->H;

        XMEMSET(x, 0, AES_BLOCK_SIZE);

        /* Hash in A, the Additional Authentication Data */
        if (aSz != 0 && a != NULL) {
            blocks = aSz / AES_BLOCK_SIZE;
            partial = aSz % AES_BLOCK_SIZE;
            if (blocks > 0) {
                ghash_blocks(x, h, a, blocks);
                a += blocks * AES_BLOCK_SIZE;
            }
            if (partial != 0) {
                XMEMSET(scratch, 0, AES_BLOCK_SIZE);
                XMEMCPY(scratch, a, partial);
                xorbuf16(x, scratch);
                GMULT(x, h);
            }
        }

        /* Hash in C, the Ciphertext */
        if (cSz != 0 && c != NULL) {
            blocks = cSz / AES_BLOCK_SIZE;
            partial = cSz % AES_BLOCK_SIZE;
            if (blocks > 0) {
                ghash_blocks(x, h, c, blocks);
                c += blocks * AES_BLOCK_SIZE;
            }
            if (partial != 0) {
                XMEMSET(scratch, 0, AES_BLOCK_SIZE);
                XMEMCPY(scratch, c, partial);
                xorbuf16(x, scratch);
                GMULT(x, h);
            }
        }

        /* Hash in the lengths of A and C in bits */
        FlattenSzInBits(&scratch[0], aSz);
        FlattenSzInBits(&scratch[8], cSz);
        xorbuf16(x, scratch);
        GMULT(x, h);

        /* Copy the result into s. */
        XMEMCPY(s, x, sSz);
    }
}

#define HAVE_GHASH

#endif /* !WOLFSSL_RISCV_VECTOR_GCM */

#ifdef WOLFSSL_RISCV_VECTOR_CRYPTO_ASM
#ifdef WOLFSSL_RISCV_VECTOR_GCM
/* START script replace AES-GCM RISC-V 64 with hardware vector crypto */
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
static const word32 rev_idx[4] = {
    0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f
};
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */

#ifdef WOLFSSL_AES_128
/* Encrypt data using AES-128-GCM.
 *
 * @param [in]  aes      AES object.
 * @param [out] out      Encrypted data.
 * @param [in]  in       Data to encrypt and GHASH.
 * @param [in]  sz       Number of bytes of data.
 * @param [in]  nonce    Nonce used to calculate first IV.
 * @param [in]  nonceSz  Length of nonce in bytes.
 * @param [out] tag      Authentication tag.
 * @param [in]  tagSz    Length of authentication tag in bytes.
 * @param [in]  aad      Additional Authentication Data (AAD).
 * @param [in]  aadSz    Length of AAD in bytes.
 */
static void Aes128GcmEncrypt(Aes* aes, byte* out, const byte* in, word32 sz,
    const byte* nonce, word32 nonceSz, byte* tag, word32 tagSz,
    const byte* aad, word32 aadSz)
{
    byte counter[AES_BLOCK_SIZE];
    byte scratch[AES_BLOCK_SIZE];
    /* Noticed different optimization levels treated head of array different.
     * Some cases was stack pointer plus offset others was a register containing
     * address. To make uniform for passing in to inline assembly code am using
     * pointers to the head of each local array.
     */
    byte* ctr  = counter;
    byte* key = (byte*)aes->key;

    XMEMSET(counter, 0, AES_BLOCK_SIZE);
    if (nonceSz == GCM_NONCE_MID_SZ) {
        XMEMCPY(counter, nonce, GCM_NONCE_MID_SZ);
        counter[AES_BLOCK_SIZE - 1] = 1;
    }
    else {
#ifdef OPENSSL_EXTRA
        word32 aadTemp = aes->gcm.aadLen;
        aes->gcm.aadLen = 0;
#endif
        GHASH(&aes->gcm, NULL, 0, nonce, nonceSz, counter, AES_BLOCK_SIZE);
#ifdef OPENSSL_EXTRA
        aes->gcm.aadLen = aadTemp;
#endif
    }

    __asm__ __volatile__ (
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)

        /* X=0, get H */
        VXOR_VV(REG_V18, REG_V18, REG_V18)
        "mv         t0, %[h]\n\t"
        VL1RE32_V(REG_V19, REG_T0)

        /* Hash in AAD, the Additional Authentication Data */
        "beqz       %[aSz], L_aes_gcm_128_encrypt_ghash_aad_done\n\t"
        "beqz       %[aad], L_aes_gcm_128_encrypt_ghash_aad_done\n\t"

        "srli       t1, %[aSz], 4\n\t"
        "beqz       t1, L_aes_gcm_128_encrypt_ghash_aad_blocks_done\n\t"

      "L_aes_gcm_128_encrypt_ghash_aad_loop:\n\t"
        "mv         t0, %[aad]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VGHSH_VV(REG_V18, REG_V17, REG_V19)
        "addi       %[aad], %[aad], 16\n\t"
        "addi       t1, t1, -1\n\t"
        "bnez       t1, L_aes_gcm_128_encrypt_ghash_aad_loop\n\t"
      "L_aes_gcm_128_encrypt_ghash_aad_blocks_done:\n\t"
        "andi       t1, %[aSz], 0xf\n\t"
        "beqz       t1, L_aes_gcm_128_encrypt_ghash_aad_done\n\t"
        VXOR_VV(REG_V17, REG_V17, REG_V17)
        "mv         t0, %[scratch]\n\t"
        VS1R_V(REG_V17, REG_T0)
        "mv         t2, t1\n\t"
      "L_aes_gcm_128_encrypt_ghash_aad_load_byte:\n\t"
        "lb         t0, (%[aad])\n\t"
        "sb         t0, (%[scratch])\n\t"
        "addi       %[aad], %[aad], 1\n\t"
        "addi       %[scratch], %[scratch], 1\n\t"
        "addi       t2, t2, -1\n\t"
        "bnez       t2, L_aes_gcm_128_encrypt_ghash_aad_load_byte\n\t"
        "sub        %[scratch], %[scratch], t1\n\t"
        "mv         t0, %[scratch]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VGHSH_VV(REG_V18, REG_V17, REG_V19)
      "L_aes_gcm_128_encrypt_ghash_aad_done:\n\t"
        /* Done Hash in AAD */

#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        "mv         t0, %[rev_idx]\n\t"
        VL1RE32_V(REG_V15, REG_T0)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
        /* Load the counter. */
        "mv         t0, %[ctr]\n\t"
        VL1RE32_V(REG_V16, REG_T0)
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        VSLIDEDOWN_VI(REG_V20, REG_V16, 3)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V21, REG_V15, REG_V20)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
        VMV_V_V(REG_V20, REG_V21)
#else
        VREV8(REG_V20, REG_V20)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
#else
        "lw         t3, 12(%[ctr])\n\t"
        "slli       t3, t3, 32\n\t"
        REV8(REG_T3, REG_T3)
#endif /* !WOLFSSL_RISCV_BASE_BIT_MANIPULATION */

        /* Load key[0..7]. */
        "mv         t0, %[key]\n\t"
        VL8RE32_V(REG_V0, REG_T0)
        /* Load key[8..9]. */
        "addi       t0, t0, 128\n\t"
        VL2RE32_V(REG_V8, REG_T0)
        /* Load last round's key */
        "addi       t0, %[key], 224\n\t"
        VL1RE32_V(REG_V10, REG_T0)

        "beqz       %[sz], L_aes_gcm_128_encrypt_blocks_done\n\t"
        "srli       t4, %[sz], 6\n\t"
        "beqz       t4, L_aes_gcm_128_encrypt_x4_blocks_done\n\t"

        /* Calculate H^[1-4] - GMULT partials */
        VMV_V_V(REG_V21, REG_V19)
        VMV_V_V(REG_V22, REG_V19)
        /* Multiply H * H => H^2 */
        VGMUL_VV(REG_V21, REG_V19)
        VMV_V_V(REG_V23, REG_V21)
        /* Multiply H * H => H^3 */
        VGMUL_VV(REG_V22, REG_V21)
        /* Multiply H^2 * H^2 => H^4 */
        VGMUL_VV(REG_V23, REG_V21)

      "L_aes_gcm_128_encrypt_x4_block_loop:\n\t"
        /* Calculate next 4 counters (+1-4) */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        VMV_V_V(REG_V24, REG_V16)
        VMV_V_V(REG_V25, REG_V16)
        VMV_V_V(REG_V26, REG_V16)
        VMV_V_V(REG_V27, REG_V16)
        VADD_VI(REG_V28, REG_V20, 1)
        VADD_VI(REG_V29, REG_V20, 2)
        VADD_VI(REG_V30, REG_V20, 3)
        VADD_VI(REG_V20, REG_V20, 4)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V17, REG_V15, REG_V28)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
        VMV_V_V(REG_V28, REG_V17)
#else
        VREV8(REG_V28, REG_V28)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V17, REG_V15, REG_V29)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
        VMV_V_V(REG_V29, REG_V17)
#else
        VREV8(REG_V29, REG_V29)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V17, REG_V15, REG_V30)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
        VMV_V_V(REG_V30, REG_V17)
#else
        VREV8(REG_V30, REG_V30)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V31, REG_V15, REG_V20)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
#else
        VREV8(REG_V31, REG_V20)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
#else
        "addi       t0, t3, 1\n\t"
        VMV_V_V(REG_V24, REG_V16)
        "addi       t1, t3, 2\n\t"
        VMV_V_V(REG_V25, REG_V16)
        "addi       t2, t3, 3\n\t"
        VMV_V_V(REG_V26, REG_V16)
        "slli       t0, t0, 32\n\t"
        VMV_V_V(REG_V27, REG_V16)
        "slli       t1, t1, 32\n\t"
        "slli       t2, t2, 32\n\t"
        REV8(REG_T0, REG_T0)
        REV8(REG_T1, REG_T1)
        REV8(REG_T2, REG_T2)
        "addi       t3, t3, 4\n\t"
        VMV_V_X(REG_V28, REG_T0)
        "slli       t0, t3, 32\n\t"
        VMV_V_X(REG_V29, REG_T1)
        REV8(REG_T0, REG_T0)
        VMV_V_X(REG_V30, REG_T2)
        VMV_V_X(REG_V31, REG_T0)
#endif /* !WOLFSSL_RISCV_BASE_BIT_MANIPULATION */
        VSLIDEUP_VI(REG_V24, REG_V28, 3)
        VSLIDEUP_VI(REG_V25, REG_V29, 3)
        VSLIDEUP_VI(REG_V26, REG_V30, 3)
        VSLIDEUP_VI(REG_V27, REG_V31, 3)

        VAESZ_VS(REG_V24, REG_V0)
        VAESZ_VS(REG_V25, REG_V0)
        VAESZ_VS(REG_V26, REG_V0)
        VAESZ_VS(REG_V27, REG_V0)
        VAESEM_VS(REG_V24, REG_V1)
        VAESEM_VS(REG_V24, REG_V2)
        VAESEM_VS(REG_V24, REG_V3)
        VAESEM_VS(REG_V24, REG_V4)
        VAESEM_VS(REG_V24, REG_V5)
        VAESEM_VS(REG_V24, REG_V6)
        VAESEM_VS(REG_V24, REG_V7)
        VAESEM_VS(REG_V24, REG_V8)
        VAESEM_VS(REG_V24, REG_V9)
        VAESEM_VS(REG_V25, REG_V1)
        VAESEM_VS(REG_V25, REG_V2)
        VAESEM_VS(REG_V25, REG_V3)
        VAESEM_VS(REG_V25, REG_V4)
        VAESEM_VS(REG_V25, REG_V5)
        VAESEM_VS(REG_V25, REG_V6)
        VAESEM_VS(REG_V25, REG_V7)
        VAESEM_VS(REG_V25, REG_V8)
        VAESEM_VS(REG_V25, REG_V9)
        VAESEM_VS(REG_V26, REG_V1)
        VAESEM_VS(REG_V26, REG_V2)
        VAESEM_VS(REG_V26, REG_V3)
        VAESEM_VS(REG_V26, REG_V4)
        VAESEM_VS(REG_V26, REG_V5)
        VAESEM_VS(REG_V26, REG_V6)
        VAESEM_VS(REG_V26, REG_V7)
        VAESEM_VS(REG_V26, REG_V8)
        VAESEM_VS(REG_V26, REG_V9)
        VAESEM_VS(REG_V27, REG_V1)
        VAESEM_VS(REG_V27, REG_V2)
        VAESEM_VS(REG_V27, REG_V3)
        VAESEM_VS(REG_V27, REG_V4)
        VAESEM_VS(REG_V27, REG_V5)
        VAESEM_VS(REG_V27, REG_V6)
        VAESEM_VS(REG_V27, REG_V7)
        VAESEM_VS(REG_V27, REG_V8)
        VAESEM_VS(REG_V27, REG_V9)
        VAESEF_VS(REG_V24, REG_V10)
        VAESEF_VS(REG_V25, REG_V10)
        VAESEF_VS(REG_V26, REG_V10)
        VAESEF_VS(REG_V27, REG_V10)

        /* Load input. */
        "mv        t0, %[in]\n\t"
        VL4RE32_V(REG_V28, REG_T0)
        VXOR_VV(REG_V28, REG_V24, REG_V28)
        VXOR_VV(REG_V29, REG_V25, REG_V29)
        VXOR_VV(REG_V30, REG_V26, REG_V30)
        VXOR_VV(REG_V31, REG_V27, REG_V31)
        /* Store output. */
        "mv         t0, %[out]\n\t"
        VS4R_V(REG_V28, REG_T0)
        VGMUL_VV(REG_V28, REG_V23)
        VGMUL_VV(REG_V29, REG_V22)
        VGMUL_VV(REG_V30, REG_V21)
        VGMUL_VV(REG_V31, REG_V19)
        VXOR_VV(REG_V18, REG_V18, REG_V28)
        VXOR_VV(REG_V18, REG_V18, REG_V29)
        VXOR_VV(REG_V18, REG_V18, REG_V30)
        VXOR_VV(REG_V18, REG_V18, REG_V31)
        "addi        %[in], %[in], 64\n\t"
        "addi        %[out], %[out], 64\n\t"
        /* Loop if more elements to process. */
        "addi       t4, t4, -1\n\t"
        "bnez       t4, L_aes_gcm_128_encrypt_x4_block_loop\n\t"
        "andi       %[sz], %[sz], 0x3f\n\t"

      "L_aes_gcm_128_encrypt_x4_blocks_done:\n\t"
        "srli       t2, %[sz], 4\n\t"
        "beqz       t2, L_aes_gcm_128_encrypt_blocks_done\n\t"

      "L_aes_gcm_128_encrypt_block_loop:\n\t"
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        VADD_VI(REG_V20, REG_V20, 1)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V17, REG_V15, REG_V20)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
#else
        VREV8(REG_V17, REG_V20)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
        VMV_V_V(REG_V27, REG_V16)
        VSLIDEUP_VI(REG_V27, REG_V17, 3)
#else
        "addi       t3, t3, 1\n\t"
        "slli       t0, t3, 32\n\t"
        REV8(REG_T0, REG_T0)
        VMV_V_X(REG_V17, REG_T0)
        VMV_V_V(REG_V27, REG_V16)
        VSLIDEUP_VI(REG_V27, REG_V17, 3)
#endif /* !WOLFSSL_RISCV_BASE_BIT_MANIPULATION */

        VAESZ_VS(REG_V27, REG_V0)
        VAESEM_VS(REG_V27, REG_V1)
        VAESEM_VS(REG_V27, REG_V2)
        VAESEM_VS(REG_V27, REG_V3)
        VAESEM_VS(REG_V27, REG_V4)
        VAESEM_VS(REG_V27, REG_V5)
        VAESEM_VS(REG_V27, REG_V6)
        VAESEM_VS(REG_V27, REG_V7)
        VAESEM_VS(REG_V27, REG_V8)
        VAESEM_VS(REG_V27, REG_V9)
        VAESEF_VS(REG_V27, REG_V10)

        /* Load input. */
        "mv         t0, %[in]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VXOR_VV(REG_V27, REG_V27, REG_V17)
        VGHSH_VV(REG_V18, REG_V27, REG_V19)
        /* Store output. */
        "mv         t0, %[out]\n\t"
        VS1R_V(REG_V27, REG_T0)

        "addi        %[in], %[in], 16\n\t"
        "addi        %[out], %[out], 16\n\t"
        /* Loop if more elements to process. */
        "addi       t2, t2, -1\n\t"
        "bnez       t2, L_aes_gcm_128_encrypt_block_loop\n\t"

      "L_aes_gcm_128_encrypt_blocks_done:\n\t"
        "andi       t2, %[sz], 0xf\n\t"
        "beqz       t2, L_aes_gcm_128_encrypt_done\n\t"

        VXOR_VV(REG_V17, REG_V17, REG_V17)
        "mv         t0, %[scratch]\n\t"
        VS1R_V(REG_V17, REG_T0)
        "mv         t1, t2\n\t"
      "L_aes_gcm_128_encrypt_load_byte:\n\t"
        "lb         t0, (%[in])\n\t"
        "sb         t0, (%[scratch])\n\t"
        "addi       %[in], %[in], 1\n\t"
        "addi       %[scratch], %[scratch], 1\n\t"
        "addi       t1, t1, -1\n\t"
        "bnez       t1, L_aes_gcm_128_encrypt_load_byte\n\t"
        "sub        %[scratch], %[scratch], t2\n\t"

        /* Encrypt counter for partial block. */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        VADD_VI(REG_V20, REG_V20, 1)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V17, REG_V15, REG_V20)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
#else
        VREV8(REG_V17, REG_V20)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
        VMV_V_V(REG_V27, REG_V16)
        VSLIDEUP_VI(REG_V27, REG_V17, 3)
#else
        "addi       t3, t3, 1\n\t"
        "slli       t0, t3, 32\n\t"
        REV8(REG_T0, REG_T0)
        VMV_V_X(REG_V17, REG_T0)
        VMV_V_V(REG_V27, REG_V16)
        VSLIDEUP_VI(REG_V27, REG_V17, 3)
#endif /* !WOLFSSL_RISCV_BASE_BIT_MANIPULATION */

        VAESZ_VS(REG_V27, REG_V0)
        VAESEM_VS(REG_V27, REG_V1)
        VAESEM_VS(REG_V27, REG_V2)
        VAESEM_VS(REG_V27, REG_V3)
        VAESEM_VS(REG_V27, REG_V4)
        VAESEM_VS(REG_V27, REG_V5)
        VAESEM_VS(REG_V27, REG_V6)
        VAESEM_VS(REG_V27, REG_V7)
        VAESEM_VS(REG_V27, REG_V8)
        VAESEM_VS(REG_V27, REG_V9)
        VAESEF_VS(REG_V27, REG_V10)

        /* Load scratch. */
        "mv         t0, %[scratch]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VXOR_VV(REG_V27, REG_V27, REG_V17)
        /* Store scratch. */
        VS1R_V(REG_V27, REG_T0)
        "mv         t1, t2\n\t"
      "L_aes_gcm_128_encrypt_store_byte:\n\t"
        "lb         t0, (%[scratch])\n\t"
        "sb         t0, (%[out])\n\t"
        "addi       %[scratch], %[scratch], 1\n\t"
        "addi       %[out], %[out], 1\n\t"
        "addi       t1, t1, -1\n\t"
        "bnez       t1, L_aes_gcm_128_encrypt_store_byte\n\t"
        "li         t1, 16\n\t"
        "sub        t1, t1, t2\n\t"
      "L_aes_gcm_128_encrypt_zero_byte:\n\t"
        "sb         x0, (%[scratch])\n\t"
        "addi       %[scratch], %[scratch], 1\n\t"
        "addi       t1, t1, -1\n\t"
        "bnez       t1, L_aes_gcm_128_encrypt_zero_byte\n\t"
        "addi       %[scratch], %[scratch], -16\n\t"
        "mv         t0, %[scratch]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VGHSH_VV(REG_V18, REG_V17, REG_V19)

      "L_aes_gcm_128_encrypt_done:\n\t"

        /* Hash in the lengths of A and C in bits */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        /* aSz is only 32-bits */
        /* Multiply by 8 do get size in bits. */
        "slli       %[aSz], %[aSz], 3\n\t"
        "srli       t0, %[aSz], 32\n\t"
        "srli       t1, %[aSz], 24\n\t"
        "srli       t2, %[aSz], 16\n\t"
        "srli       t3, %[aSz], 8\n\t"
        /* Top 3 bytes are 0. */
        "sh         x0    , 0(%[scratch])\n\t"
        "sb         x0    , 2(%[scratch])\n\t"
        "sb         t0    , 3(%[scratch])\n\t"
        "sb         t1    , 4(%[scratch])\n\t"
        "sb         t2    , 5(%[scratch])\n\t"
        "sb         t3    , 6(%[scratch])\n\t"
        "sb         %[aSz], 7(%[scratch])\n\t"
        /* sz is only 32-bits */
        /* Multiply by 8 do get size in bits. */
        "slli       %[sz], %[sz], 3\n\t"
        "srli       t0, %[sz], 32\n\t"
        "srli       t1, %[sz], 24\n\t"
        "srli       t2, %[sz], 16\n\t"
        "srli       t3, %[sz], 8\n\t"
        /* Top 3 bytes are 0. */
        "sh         x0   ,  8(%[scratch])\n\t"
        "sb         x0   , 10(%[scratch])\n\t"
        "sb         t0   , 11(%[scratch])\n\t"
        "sb         t1   , 12(%[scratch])\n\t"
        "sb         t2   , 13(%[scratch])\n\t"
        "sb         t3   , 14(%[scratch])\n\t"
        "sb         %[sz], 15(%[scratch])\n\t"
#else
        "slli       t0, %[aSz], 3\n\t"
        REV8(REG_T0, REG_T0)
        "sd         t0, 0(%[scratch])\n\t"
        "slli       t0, %[sz], 3\n\t"
        REV8(REG_T0, REG_T0)
        "sd         t0, 8(%[scratch])\n\t"
#endif /* !WOLFSSL_RISCV_BASE_BIT_MANIPULATION */
        "mv         t0, %[scratch]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VGHSH_VV(REG_V18, REG_V17, REG_V19)

        VAESZ_VS(REG_V16, REG_V0)
        VAESEM_VS(REG_V16, REG_V1)
        VAESEM_VS(REG_V16, REG_V2)
        VAESEM_VS(REG_V16, REG_V3)
        VAESEM_VS(REG_V16, REG_V4)
        VAESEM_VS(REG_V16, REG_V5)
        VAESEM_VS(REG_V16, REG_V6)
        VAESEM_VS(REG_V16, REG_V7)
        VAESEM_VS(REG_V16, REG_V8)
        VAESEM_VS(REG_V16, REG_V9)
        VAESEF_VS(REG_V16, REG_V10)
        VXOR_VV(REG_V18, REG_V18, REG_V16)

        "li         t1, 16\n\t"
        "blt        %[tagSz], t1, L_aes_gcm_128_encrypt_tag_small\n\t"
        "mv         t0, %[tag]\n\t"
        VS1R_V(REG_V18, REG_T0)
        "beqz       x0, L_aes_gcm_128_encrypt_tag_done\n\t"
      "L_aes_gcm_128_encrypt_tag_small:\n\t"
        "mv         t0, %[scratch]\n\t"
        VS1R_V(REG_V18, REG_T0)
        "mv         t1, %[tagSz]\n\t"
      "L_aes_gcm_128_encrypt_store_tag_byte:\n\t"
        "lb         t0, (%[scratch])\n\t"
        "sb         t0, (%[tag])\n\t"
        "addi       %[scratch], %[scratch], 1\n\t"
        "addi       %[tag], %[tag], 1\n\t"
        "addi       t1, t1, -1\n\t"
        "bnez       t1, L_aes_gcm_128_encrypt_store_tag_byte\n\t"
      "L_aes_gcm_128_encrypt_tag_done:\n\t"

        : [out] "+r" (out), [in] "+r" (in), [key] "+r" (key),
          [aSz] "+r" (aadSz), [aad] "+r" (aad), [sz] "+r" (sz)
        : [ctr] "r" (ctr), [scratch] "r" (scratch),
          [h] "r" (aes->gcm.H), [tag] "r" (tag), [tagSz] "r" (tagSz)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
          , [rev_idx] "r" (rev_idx)
#endif
        : "memory", "t0", "t1", "t2", "t3", "t4"
    );

#ifdef OPENSSL_EXTRA
    if ((tag != NULL) && (in != NULL) && (sz != 0)) {
        /* store AAD size for next call */
        aes->gcm.aadLen = aadSz;
    }
#endif
}
#endif /*  WOLFSSL_AES_128 */

#ifdef WOLFSSL_AES_192
/* Encrypt data using AES-192-GCM.
 *
 * @param [in]  aes      AES object.
 * @param [out] out      Encrypted data.
 * @param [in]  in       Data to encrypt and GHASH.
 * @param [in]  sz       Number of bytes of data.
 * @param [in]  nonce    Nonce used to calculate first IV.
 * @param [in]  nonceSz  Length of nonce in bytes.
 * @param [out] tag      Authentication tag.
 * @param [in]  tagSz    Length of authentication tag in bytes.
 * @param [in]  aad      Additional Authentication Data (AAD).
 * @param [in]  aadSz    Length of AAD in bytes.
 */
static void Aes192GcmEncrypt(Aes* aes, byte* out, const byte* in, word32 sz,
    const byte* nonce, word32 nonceSz, byte* tag, word32 tagSz,
    const byte* aad, word32 aadSz)
{
    byte counter[AES_BLOCK_SIZE];
    byte scratch[AES_BLOCK_SIZE];
    /* Noticed different optimization levels treated head of array different.
     * Some cases was stack pointer plus offset others was a register containing
     * address. To make uniform for passing in to inline assembly code am using
     * pointers to the head of each local array.
     */
    byte* ctr  = counter;
    byte* key = (byte*)aes->key;

    XMEMSET(counter, 0, AES_BLOCK_SIZE);
    if (nonceSz == GCM_NONCE_MID_SZ) {
        XMEMCPY(counter, nonce, GCM_NONCE_MID_SZ);
        counter[AES_BLOCK_SIZE - 1] = 1;
    }
    else {
#ifdef OPENSSL_EXTRA
        word32 aadTemp = aes->gcm.aadLen;
        aes->gcm.aadLen = 0;
#endif
        GHASH(&aes->gcm, NULL, 0, nonce, nonceSz, counter, AES_BLOCK_SIZE);
#ifdef OPENSSL_EXTRA
        aes->gcm.aadLen = aadTemp;
#endif
    }

    __asm__ __volatile__ (
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)

        /* X=0, get H */
        VXOR_VV(REG_V18, REG_V18, REG_V18)
        "mv         t0, %[h]\n\t"
        VL1RE32_V(REG_V19, REG_T0)

        /* Hash in AAD, the Additional Authentication Data */
        "beqz       %[aSz], L_aes_gcm_192_encrypt_ghash_aad_done\n\t"
        "beqz       %[aad], L_aes_gcm_192_encrypt_ghash_aad_done\n\t"

        "srli       t1, %[aSz], 4\n\t"
        "beqz       t1, L_aes_gcm_192_encrypt_ghash_aad_blocks_done\n\t"

      "L_aes_gcm_192_encrypt_ghash_aad_loop:\n\t"
        "mv         t0, %[aad]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VGHSH_VV(REG_V18, REG_V17, REG_V19)
        "addi       %[aad], %[aad], 16\n\t"
        "addi       t1, t1, -1\n\t"
        "bnez       t1, L_aes_gcm_192_encrypt_ghash_aad_loop\n\t"
      "L_aes_gcm_192_encrypt_ghash_aad_blocks_done:\n\t"
        "andi       t1, %[aSz], 0xf\n\t"
        "beqz       t1, L_aes_gcm_192_encrypt_ghash_aad_done\n\t"
        VXOR_VV(REG_V17, REG_V17, REG_V17)
        "mv         t0, %[scratch]\n\t"
        VS1R_V(REG_V17, REG_T0)
        "mv         t2, t1\n\t"
      "L_aes_gcm_192_encrypt_ghash_aad_load_byte:\n\t"
        "lb         t0, (%[aad])\n\t"
        "sb         t0, (%[scratch])\n\t"
        "addi       %[aad], %[aad], 1\n\t"
        "addi       %[scratch], %[scratch], 1\n\t"
        "addi       t2, t2, -1\n\t"
        "bnez       t2, L_aes_gcm_192_encrypt_ghash_aad_load_byte\n\t"
        "sub        %[scratch], %[scratch], t1\n\t"
        "mv         t0, %[scratch]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VGHSH_VV(REG_V18, REG_V17, REG_V19)
      "L_aes_gcm_192_encrypt_ghash_aad_done:\n\t"
        /* Done Hash in AAD */

#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        "mv         t0, %[rev_idx]\n\t"
        VL1RE32_V(REG_V15, REG_T0)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
        /* Load the counter. */
        "mv         t0, %[ctr]\n\t"
        VL1RE32_V(REG_V16, REG_T0)
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        VSLIDEDOWN_VI(REG_V20, REG_V16, 3)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V21, REG_V15, REG_V20)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
        VMV_V_V(REG_V20, REG_V21)
#else
        VREV8(REG_V20, REG_V20)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
#else
        "lw         t3, 12(%[ctr])\n\t"
        "slli       t3, t3, 32\n\t"
        REV8(REG_T3, REG_T3)
#endif /* !WOLFSSL_RISCV_BASE_BIT_MANIPULATION */

        /* Load key[0..7]. */
        "mv         t0, %[key]\n\t"
        VL8RE32_V(REG_V0, REG_T0)
        /* Load key[8..11]. */
        "addi       t0, t0, 128\n\t"
        VL4RE32_V(REG_V8, REG_T0)
        /* Load last round's key */
        "addi       t0, %[key], 224\n\t"
        VL1RE32_V(REG_V12, REG_T0)

        "beqz       %[sz], L_aes_gcm_192_encrypt_blocks_done\n\t"
        "srli       t4, %[sz], 6\n\t"
        "beqz       t4, L_aes_gcm_192_encrypt_x4_blocks_done\n\t"

        /* Calculate H^[1-4] - GMULT partials */
        VMV_V_V(REG_V21, REG_V19)
        VMV_V_V(REG_V22, REG_V19)
        /* Multiply H * H => H^2 */
        VGMUL_VV(REG_V21, REG_V19)
        VMV_V_V(REG_V23, REG_V21)
        /* Multiply H * H => H^3 */
        VGMUL_VV(REG_V22, REG_V21)
        /* Multiply H^2 * H^2 => H^4 */
        VGMUL_VV(REG_V23, REG_V21)

      "L_aes_gcm_192_encrypt_x4_block_loop:\n\t"
        /* Calculate next 4 counters (+1-4) */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        VMV_V_V(REG_V24, REG_V16)
        VMV_V_V(REG_V25, REG_V16)
        VMV_V_V(REG_V26, REG_V16)
        VMV_V_V(REG_V27, REG_V16)
        VADD_VI(REG_V28, REG_V20, 1)
        VADD_VI(REG_V29, REG_V20, 2)
        VADD_VI(REG_V30, REG_V20, 3)
        VADD_VI(REG_V20, REG_V20, 4)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V17, REG_V15, REG_V28)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
        VMV_V_V(REG_V28, REG_V17)
#else
        VREV8(REG_V28, REG_V28)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V17, REG_V15, REG_V29)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
        VMV_V_V(REG_V29, REG_V17)
#else
        VREV8(REG_V29, REG_V29)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V17, REG_V15, REG_V30)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
        VMV_V_V(REG_V30, REG_V17)
#else
        VREV8(REG_V30, REG_V30)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V31, REG_V15, REG_V20)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
#else
        VREV8(REG_V31, REG_V20)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
#else
        "addi       t0, t3, 1\n\t"
        VMV_V_V(REG_V24, REG_V16)
        "addi       t1, t3, 2\n\t"
        VMV_V_V(REG_V25, REG_V16)
        "addi       t2, t3, 3\n\t"
        VMV_V_V(REG_V26, REG_V16)
        "slli       t0, t0, 32\n\t"
        VMV_V_V(REG_V27, REG_V16)
        "slli       t1, t1, 32\n\t"
        "slli       t2, t2, 32\n\t"
        REV8(REG_T0, REG_T0)
        REV8(REG_T1, REG_T1)
        REV8(REG_T2, REG_T2)
        "addi       t3, t3, 4\n\t"
        VMV_V_X(REG_V28, REG_T0)
        "slli       t0, t3, 32\n\t"
        VMV_V_X(REG_V29, REG_T1)
        REV8(REG_T0, REG_T0)
        VMV_V_X(REG_V30, REG_T2)
        VMV_V_X(REG_V31, REG_T0)
#endif /* !WOLFSSL_RISCV_BASE_BIT_MANIPULATION */
        VSLIDEUP_VI(REG_V24, REG_V28, 3)
        VSLIDEUP_VI(REG_V25, REG_V29, 3)
        VSLIDEUP_VI(REG_V26, REG_V30, 3)
        VSLIDEUP_VI(REG_V27, REG_V31, 3)

        VAESZ_VS(REG_V24, REG_V0)
        VAESZ_VS(REG_V25, REG_V0)
        VAESZ_VS(REG_V26, REG_V0)
        VAESZ_VS(REG_V27, REG_V0)
        VAESEM_VS(REG_V24, REG_V1)
        VAESEM_VS(REG_V24, REG_V2)
        VAESEM_VS(REG_V24, REG_V3)
        VAESEM_VS(REG_V24, REG_V4)
        VAESEM_VS(REG_V24, REG_V5)
        VAESEM_VS(REG_V24, REG_V6)
        VAESEM_VS(REG_V24, REG_V7)
        VAESEM_VS(REG_V24, REG_V8)
        VAESEM_VS(REG_V24, REG_V9)
        VAESEM_VS(REG_V24, REG_V10)
        VAESEM_VS(REG_V24, REG_V11)
        VAESEM_VS(REG_V25, REG_V1)
        VAESEM_VS(REG_V25, REG_V2)
        VAESEM_VS(REG_V25, REG_V3)
        VAESEM_VS(REG_V25, REG_V4)
        VAESEM_VS(REG_V25, REG_V5)
        VAESEM_VS(REG_V25, REG_V6)
        VAESEM_VS(REG_V25, REG_V7)
        VAESEM_VS(REG_V25, REG_V8)
        VAESEM_VS(REG_V25, REG_V9)
        VAESEM_VS(REG_V25, REG_V10)
        VAESEM_VS(REG_V25, REG_V11)
        VAESEM_VS(REG_V26, REG_V1)
        VAESEM_VS(REG_V26, REG_V2)
        VAESEM_VS(REG_V26, REG_V3)
        VAESEM_VS(REG_V26, REG_V4)
        VAESEM_VS(REG_V26, REG_V5)
        VAESEM_VS(REG_V26, REG_V6)
        VAESEM_VS(REG_V26, REG_V7)
        VAESEM_VS(REG_V26, REG_V8)
        VAESEM_VS(REG_V26, REG_V9)
        VAESEM_VS(REG_V26, REG_V10)
        VAESEM_VS(REG_V26, REG_V11)
        VAESEM_VS(REG_V27, REG_V1)
        VAESEM_VS(REG_V27, REG_V2)
        VAESEM_VS(REG_V27, REG_V3)
        VAESEM_VS(REG_V27, REG_V4)
        VAESEM_VS(REG_V27, REG_V5)
        VAESEM_VS(REG_V27, REG_V6)
        VAESEM_VS(REG_V27, REG_V7)
        VAESEM_VS(REG_V27, REG_V8)
        VAESEM_VS(REG_V27, REG_V9)
        VAESEM_VS(REG_V27, REG_V10)
        VAESEM_VS(REG_V27, REG_V11)
        VAESEF_VS(REG_V24, REG_V12)
        VAESEF_VS(REG_V25, REG_V12)
        VAESEF_VS(REG_V26, REG_V12)
        VAESEF_VS(REG_V27, REG_V12)

        /* Load input. */
        "mv        t0, %[in]\n\t"
        VL4RE32_V(REG_V28, REG_T0)
        VXOR_VV(REG_V28, REG_V24, REG_V28)
        VXOR_VV(REG_V29, REG_V25, REG_V29)
        VXOR_VV(REG_V30, REG_V26, REG_V30)
        VXOR_VV(REG_V31, REG_V27, REG_V31)
        /* Store output. */
        "mv         t0, %[out]\n\t"
        VS4R_V(REG_V28, REG_T0)
        VGMUL_VV(REG_V28, REG_V23)
        VGMUL_VV(REG_V29, REG_V22)
        VGMUL_VV(REG_V30, REG_V21)
        VGMUL_VV(REG_V31, REG_V19)
        VXOR_VV(REG_V18, REG_V18, REG_V28)
        VXOR_VV(REG_V18, REG_V18, REG_V29)
        VXOR_VV(REG_V18, REG_V18, REG_V30)
        VXOR_VV(REG_V18, REG_V18, REG_V31)
        "addi        %[in], %[in], 64\n\t"
        "addi        %[out], %[out], 64\n\t"
        /* Loop if more elements to process. */
        "addi       t4, t4, -1\n\t"
        "bnez       t4, L_aes_gcm_192_encrypt_x4_block_loop\n\t"
        "andi       %[sz], %[sz], 0x3f\n\t"

      "L_aes_gcm_192_encrypt_x4_blocks_done:\n\t"
        "srli       t2, %[sz], 4\n\t"
        "beqz       t2, L_aes_gcm_192_encrypt_blocks_done\n\t"

      "L_aes_gcm_192_encrypt_block_loop:\n\t"
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        VADD_VI(REG_V20, REG_V20, 1)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V17, REG_V15, REG_V20)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
#else
        VREV8(REG_V17, REG_V20)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
        VMV_V_V(REG_V27, REG_V16)
        VSLIDEUP_VI(REG_V27, REG_V17, 3)
#else
        "addi       t3, t3, 1\n\t"
        "slli       t0, t3, 32\n\t"
        REV8(REG_T0, REG_T0)
        VMV_V_X(REG_V17, REG_T0)
        VMV_V_V(REG_V27, REG_V16)
        VSLIDEUP_VI(REG_V27, REG_V17, 3)
#endif /* !WOLFSSL_RISCV_BASE_BIT_MANIPULATION */

        VAESZ_VS(REG_V27, REG_V0)
        VAESEM_VS(REG_V27, REG_V1)
        VAESEM_VS(REG_V27, REG_V2)
        VAESEM_VS(REG_V27, REG_V3)
        VAESEM_VS(REG_V27, REG_V4)
        VAESEM_VS(REG_V27, REG_V5)
        VAESEM_VS(REG_V27, REG_V6)
        VAESEM_VS(REG_V27, REG_V7)
        VAESEM_VS(REG_V27, REG_V8)
        VAESEM_VS(REG_V27, REG_V9)
        VAESEM_VS(REG_V27, REG_V10)
        VAESEM_VS(REG_V27, REG_V11)
        VAESEF_VS(REG_V27, REG_V12)

        /* Load input. */
        "mv         t0, %[in]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VXOR_VV(REG_V27, REG_V27, REG_V17)
        VGHSH_VV(REG_V18, REG_V27, REG_V19)
        /* Store output. */
        "mv         t0, %[out]\n\t"
        VS1R_V(REG_V27, REG_T0)

        "addi        %[in], %[in], 16\n\t"
        "addi        %[out], %[out], 16\n\t"
        /* Loop if more elements to process. */
        "addi       t2, t2, -1\n\t"
        "bnez       t2, L_aes_gcm_192_encrypt_block_loop\n\t"

      "L_aes_gcm_192_encrypt_blocks_done:\n\t"
        "andi       t2, %[sz], 0xf\n\t"
        "beqz       t2, L_aes_gcm_192_encrypt_done\n\t"

        VXOR_VV(REG_V17, REG_V17, REG_V17)
        "mv         t0, %[scratch]\n\t"
        VS1R_V(REG_V17, REG_T0)
        "mv         t1, t2\n\t"
      "L_aes_gcm_192_encrypt_load_byte:\n\t"
        "lb         t0, (%[in])\n\t"
        "sb         t0, (%[scratch])\n\t"
        "addi       %[in], %[in], 1\n\t"
        "addi       %[scratch], %[scratch], 1\n\t"
        "addi       t1, t1, -1\n\t"
        "bnez       t1, L_aes_gcm_192_encrypt_load_byte\n\t"
        "sub        %[scratch], %[scratch], t2\n\t"

        /* Encrypt counter for partial block. */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        VADD_VI(REG_V20, REG_V20, 1)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V17, REG_V15, REG_V20)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
#else
        VREV8(REG_V17, REG_V20)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
        VMV_V_V(REG_V27, REG_V16)
        VSLIDEUP_VI(REG_V27, REG_V17, 3)
#else
        "addi       t3, t3, 1\n\t"
        "slli       t0, t3, 32\n\t"
        REV8(REG_T0, REG_T0)
        VMV_V_X(REG_V17, REG_T0)
        VMV_V_V(REG_V27, REG_V16)
        VSLIDEUP_VI(REG_V27, REG_V17, 3)
#endif /* !WOLFSSL_RISCV_BASE_BIT_MANIPULATION */

        VAESZ_VS(REG_V27, REG_V0)
        VAESEM_VS(REG_V27, REG_V1)
        VAESEM_VS(REG_V27, REG_V2)
        VAESEM_VS(REG_V27, REG_V3)
        VAESEM_VS(REG_V27, REG_V4)
        VAESEM_VS(REG_V27, REG_V5)
        VAESEM_VS(REG_V27, REG_V6)
        VAESEM_VS(REG_V27, REG_V7)
        VAESEM_VS(REG_V27, REG_V8)
        VAESEM_VS(REG_V27, REG_V9)
        VAESEM_VS(REG_V27, REG_V10)
        VAESEM_VS(REG_V27, REG_V11)
        VAESEF_VS(REG_V27, REG_V12)

        /* Load scratch. */
        "mv         t0, %[scratch]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VXOR_VV(REG_V27, REG_V27, REG_V17)
        /* Store scratch. */
        VS1R_V(REG_V27, REG_T0)
        "mv         t1, t2\n\t"
      "L_aes_gcm_192_encrypt_store_byte:\n\t"
        "lb         t0, (%[scratch])\n\t"
        "sb         t0, (%[out])\n\t"
        "addi       %[scratch], %[scratch], 1\n\t"
        "addi       %[out], %[out], 1\n\t"
        "addi       t1, t1, -1\n\t"
        "bnez       t1, L_aes_gcm_192_encrypt_store_byte\n\t"
        "li         t1, 16\n\t"
        "sub        t1, t1, t2\n\t"
      "L_aes_gcm_192_encrypt_zero_byte:\n\t"
        "sb         x0, (%[scratch])\n\t"
        "addi       %[scratch], %[scratch], 1\n\t"
        "addi       t1, t1, -1\n\t"
        "bnez       t1, L_aes_gcm_192_encrypt_zero_byte\n\t"
        "addi       %[scratch], %[scratch], -16\n\t"
        "mv         t0, %[scratch]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VGHSH_VV(REG_V18, REG_V17, REG_V19)

      "L_aes_gcm_192_encrypt_done:\n\t"

        /* Hash in the lengths of A and C in bits */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        /* aSz is only 32-bits */
        /* Multiply by 8 do get size in bits. */
        "slli       %[aSz], %[aSz], 3\n\t"
        "srli       t0, %[aSz], 32\n\t"
        "srli       t1, %[aSz], 24\n\t"
        "srli       t2, %[aSz], 16\n\t"
        "srli       t3, %[aSz], 8\n\t"
        /* Top 3 bytes are 0. */
        "sh         x0    , 0(%[scratch])\n\t"
        "sb         x0    , 2(%[scratch])\n\t"
        "sb         t0    , 3(%[scratch])\n\t"
        "sb         t1    , 4(%[scratch])\n\t"
        "sb         t2    , 5(%[scratch])\n\t"
        "sb         t3    , 6(%[scratch])\n\t"
        "sb         %[aSz], 7(%[scratch])\n\t"
        /* sz is only 32-bits */
        /* Multiply by 8 do get size in bits. */
        "slli       %[sz], %[sz], 3\n\t"
        "srli       t0, %[sz], 32\n\t"
        "srli       t1, %[sz], 24\n\t"
        "srli       t2, %[sz], 16\n\t"
        "srli       t3, %[sz], 8\n\t"
        /* Top 3 bytes are 0. */
        "sh         x0   ,  8(%[scratch])\n\t"
        "sb         x0   , 10(%[scratch])\n\t"
        "sb         t0   , 11(%[scratch])\n\t"
        "sb         t1   , 12(%[scratch])\n\t"
        "sb         t2   , 13(%[scratch])\n\t"
        "sb         t3   , 14(%[scratch])\n\t"
        "sb         %[sz], 15(%[scratch])\n\t"
#else
        "slli       t0, %[aSz], 3\n\t"
        REV8(REG_T0, REG_T0)
        "sd         t0, 0(%[scratch])\n\t"
        "slli       t0, %[sz], 3\n\t"
        REV8(REG_T0, REG_T0)
        "sd         t0, 8(%[scratch])\n\t"
#endif /* !WOLFSSL_RISCV_BASE_BIT_MANIPULATION */
        "mv         t0, %[scratch]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VGHSH_VV(REG_V18, REG_V17, REG_V19)

        VAESZ_VS(REG_V16, REG_V0)
        VAESEM_VS(REG_V16, REG_V1)
        VAESEM_VS(REG_V16, REG_V2)
        VAESEM_VS(REG_V16, REG_V3)
        VAESEM_VS(REG_V16, REG_V4)
        VAESEM_VS(REG_V16, REG_V5)
        VAESEM_VS(REG_V16, REG_V6)
        VAESEM_VS(REG_V16, REG_V7)
        VAESEM_VS(REG_V16, REG_V8)
        VAESEM_VS(REG_V16, REG_V9)
        VAESEM_VS(REG_V16, REG_V10)
        VAESEM_VS(REG_V16, REG_V11)
        VAESEF_VS(REG_V16, REG_V12)
        VXOR_VV(REG_V18, REG_V18, REG_V16)

        "li         t1, 16\n\t"
        "blt        %[tagSz], t1, L_aes_gcm_192_encrypt_tag_small\n\t"
        "mv         t0, %[tag]\n\t"
        VS1R_V(REG_V18, REG_T0)
        "beqz       x0, L_aes_gcm_192_encrypt_tag_done\n\t"
      "L_aes_gcm_192_encrypt_tag_small:\n\t"
        "mv         t0, %[scratch]\n\t"
        VS1R_V(REG_V18, REG_T0)
        "mv         t1, %[tagSz]\n\t"
      "L_aes_gcm_192_encrypt_store_tag_byte:\n\t"
        "lb         t0, (%[scratch])\n\t"
        "sb         t0, (%[tag])\n\t"
        "addi       %[scratch], %[scratch], 1\n\t"
        "addi       %[tag], %[tag], 1\n\t"
        "addi       t1, t1, -1\n\t"
        "bnez       t1, L_aes_gcm_192_encrypt_store_tag_byte\n\t"
      "L_aes_gcm_192_encrypt_tag_done:\n\t"

        : [out] "+r" (out), [in] "+r" (in), [key] "+r" (key),
          [aSz] "+r" (aadSz), [aad] "+r" (aad), [sz] "+r" (sz)
        : [ctr] "r" (ctr), [scratch] "r" (scratch),
          [h] "r" (aes->gcm.H), [tag] "r" (tag), [tagSz] "r" (tagSz)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
          , [rev_idx] "r" (rev_idx)
#endif
        : "memory", "t0", "t1", "t2", "t3", "t4"
    );

#ifdef OPENSSL_EXTRA
    if ((tag != NULL) && (in != NULL) && (sz != 0)) {
        /* store AAD size for next call */
        aes->gcm.aadLen = aadSz;
    }
#endif
}
#endif /*  WOLFSSL_AES_192 */

#ifdef WOLFSSL_AES_256
/* Encrypt data using AES-256-GCM.
 *
 * @param [in]  aes      AES object.
 * @param [out] out      Encrypted data.
 * @param [in]  in       Data to encrypt and GHASH.
 * @param [in]  sz       Number of bytes of data.
 * @param [in]  nonce    Nonce used to calculate first IV.
 * @param [in]  nonceSz  Length of nonce in bytes.
 * @param [out] tag      Authentication tag.
 * @param [in]  tagSz    Length of authentication tag in bytes.
 * @param [in]  aad      Additional Authentication Data (AAD).
 * @param [in]  aadSz    Length of AAD in bytes.
 */
static void Aes256GcmEncrypt(Aes* aes, byte* out, const byte* in, word32 sz,
    const byte* nonce, word32 nonceSz, byte* tag, word32 tagSz,
    const byte* aad, word32 aadSz)
{
    byte counter[AES_BLOCK_SIZE];
    byte scratch[AES_BLOCK_SIZE];
    /* Noticed different optimization levels treated head of array different.
     * Some cases was stack pointer plus offset others was a register containing
     * address. To make uniform for passing in to inline assembly code am using
     * pointers to the head of each local array.
     */
    byte* ctr  = counter;
    byte* key = (byte*)aes->key;

    XMEMSET(counter, 0, AES_BLOCK_SIZE);
    if (nonceSz == GCM_NONCE_MID_SZ) {
        XMEMCPY(counter, nonce, GCM_NONCE_MID_SZ);
        counter[AES_BLOCK_SIZE - 1] = 1;
    }
    else {
#ifdef OPENSSL_EXTRA
        word32 aadTemp = aes->gcm.aadLen;
        aes->gcm.aadLen = 0;
#endif
        GHASH(&aes->gcm, NULL, 0, nonce, nonceSz, counter, AES_BLOCK_SIZE);
#ifdef OPENSSL_EXTRA
        aes->gcm.aadLen = aadTemp;
#endif
    }

    __asm__ __volatile__ (
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)

        /* X=0, get H */
        VXOR_VV(REG_V18, REG_V18, REG_V18)
        "mv         t0, %[h]\n\t"
        VL1RE32_V(REG_V19, REG_T0)

        /* Hash in AAD, the Additional Authentication Data */
        "beqz       %[aSz], L_aes_gcm_256_encrypt_ghash_aad_done\n\t"
        "beqz       %[aad], L_aes_gcm_256_encrypt_ghash_aad_done\n\t"

        "srli       t1, %[aSz], 4\n\t"
        "beqz       t1, L_aes_gcm_256_encrypt_ghash_aad_blocks_done\n\t"

      "L_aes_gcm_256_encrypt_ghash_aad_loop:\n\t"
        "mv         t0, %[aad]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VGHSH_VV(REG_V18, REG_V17, REG_V19)
        "addi       %[aad], %[aad], 16\n\t"
        "addi       t1, t1, -1\n\t"
        "bnez       t1, L_aes_gcm_256_encrypt_ghash_aad_loop\n\t"
      "L_aes_gcm_256_encrypt_ghash_aad_blocks_done:\n\t"
        "andi       t1, %[aSz], 0xf\n\t"
        "beqz       t1, L_aes_gcm_256_encrypt_ghash_aad_done\n\t"
        VXOR_VV(REG_V17, REG_V17, REG_V17)
        "mv         t0, %[scratch]\n\t"
        VS1R_V(REG_V17, REG_T0)
        "mv         t2, t1\n\t"
      "L_aes_gcm_256_encrypt_ghash_aad_load_byte:\n\t"
        "lb         t0, (%[aad])\n\t"
        "sb         t0, (%[scratch])\n\t"
        "addi       %[aad], %[aad], 1\n\t"
        "addi       %[scratch], %[scratch], 1\n\t"
        "addi       t2, t2, -1\n\t"
        "bnez       t2, L_aes_gcm_256_encrypt_ghash_aad_load_byte\n\t"
        "sub        %[scratch], %[scratch], t1\n\t"
        "mv         t0, %[scratch]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VGHSH_VV(REG_V18, REG_V17, REG_V19)
      "L_aes_gcm_256_encrypt_ghash_aad_done:\n\t"
        /* Done Hash in AAD */

#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        "mv         t0, %[rev_idx]\n\t"
        VL1RE32_V(REG_V15, REG_T0)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
        /* Load the counter. */
        "mv         t0, %[ctr]\n\t"
        VL1RE32_V(REG_V16, REG_T0)
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        VSLIDEDOWN_VI(REG_V20, REG_V16, 3)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V21, REG_V15, REG_V20)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
        VMV_V_V(REG_V20, REG_V21)
#else
        VREV8(REG_V20, REG_V20)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
#else
        "lw         t3, 12(%[ctr])\n\t"
        "slli       t3, t3, 32\n\t"
        REV8(REG_T3, REG_T3)
#endif /* !WOLFSSL_RISCV_BASE_BIT_MANIPULATION */

        /* Load key[0..7]. */
        "mv         t0, %[key]\n\t"
        VL8RE32_V(REG_V0, REG_T0)
        /* Load key[8..11]. */
        "addi       t0, t0, 128\n\t"
        VL4RE32_V(REG_V8, REG_T0)
        /* Load key[12..13]. */
        "addi       t0, t0, 64\n\t"
        VL2RE32_V(REG_V12, REG_T0)
        /* Load last round's key */
        "addi       t0, %[key], 224\n\t"
        VL1RE32_V(REG_V14, REG_T0)

        "beqz       %[sz], L_aes_gcm_256_encrypt_blocks_done\n\t"
        "srli       t4, %[sz], 6\n\t"
        "beqz       t4, L_aes_gcm_256_encrypt_x4_blocks_done\n\t"

        /* Calculate H^[1-4] - GMULT partials */
        VMV_V_V(REG_V21, REG_V19)
        VMV_V_V(REG_V22, REG_V19)
        /* Multiply H * H => H^2 */
        VGMUL_VV(REG_V21, REG_V19)
        VMV_V_V(REG_V23, REG_V21)
        /* Multiply H * H => H^3 */
        VGMUL_VV(REG_V22, REG_V21)
        /* Multiply H^2 * H^2 => H^4 */
        VGMUL_VV(REG_V23, REG_V21)

      "L_aes_gcm_256_encrypt_x4_block_loop:\n\t"
        /* Calculate next 4 counters (+1-4) */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        VMV_V_V(REG_V24, REG_V16)
        VMV_V_V(REG_V25, REG_V16)
        VMV_V_V(REG_V26, REG_V16)
        VMV_V_V(REG_V27, REG_V16)
        VADD_VI(REG_V28, REG_V20, 1)
        VADD_VI(REG_V29, REG_V20, 2)
        VADD_VI(REG_V30, REG_V20, 3)
        VADD_VI(REG_V20, REG_V20, 4)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V17, REG_V15, REG_V28)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
        VMV_V_V(REG_V28, REG_V17)
#else
        VREV8(REG_V28, REG_V28)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V17, REG_V15, REG_V29)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
        VMV_V_V(REG_V29, REG_V17)
#else
        VREV8(REG_V29, REG_V29)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V17, REG_V15, REG_V30)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
        VMV_V_V(REG_V30, REG_V17)
#else
        VREV8(REG_V30, REG_V30)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V31, REG_V15, REG_V20)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
#else
        VREV8(REG_V31, REG_V20)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
#else
        "addi       t0, t3, 1\n\t"
        VMV_V_V(REG_V24, REG_V16)
        "addi       t1, t3, 2\n\t"
        VMV_V_V(REG_V25, REG_V16)
        "addi       t2, t3, 3\n\t"
        VMV_V_V(REG_V26, REG_V16)
        "slli       t0, t0, 32\n\t"
        VMV_V_V(REG_V27, REG_V16)
        "slli       t1, t1, 32\n\t"
        "slli       t2, t2, 32\n\t"
        REV8(REG_T0, REG_T0)
        REV8(REG_T1, REG_T1)
        REV8(REG_T2, REG_T2)
        "addi       t3, t3, 4\n\t"
        VMV_V_X(REG_V28, REG_T0)
        "slli       t0, t3, 32\n\t"
        VMV_V_X(REG_V29, REG_T1)
        REV8(REG_T0, REG_T0)
        VMV_V_X(REG_V30, REG_T2)
        VMV_V_X(REG_V31, REG_T0)
#endif /* !WOLFSSL_RISCV_BASE_BIT_MANIPULATION */
        VSLIDEUP_VI(REG_V24, REG_V28, 3)
        VSLIDEUP_VI(REG_V25, REG_V29, 3)
        VSLIDEUP_VI(REG_V26, REG_V30, 3)
        VSLIDEUP_VI(REG_V27, REG_V31, 3)

        VAESZ_VS(REG_V24, REG_V0)
        VAESZ_VS(REG_V25, REG_V0)
        VAESZ_VS(REG_V26, REG_V0)
        VAESZ_VS(REG_V27, REG_V0)
        VAESEM_VS(REG_V24, REG_V1)
        VAESEM_VS(REG_V24, REG_V2)
        VAESEM_VS(REG_V24, REG_V3)
        VAESEM_VS(REG_V24, REG_V4)
        VAESEM_VS(REG_V24, REG_V5)
        VAESEM_VS(REG_V24, REG_V6)
        VAESEM_VS(REG_V24, REG_V7)
        VAESEM_VS(REG_V24, REG_V8)
        VAESEM_VS(REG_V24, REG_V9)
        VAESEM_VS(REG_V24, REG_V10)
        VAESEM_VS(REG_V24, REG_V11)
        VAESEM_VS(REG_V24, REG_V12)
        VAESEM_VS(REG_V24, REG_V13)
        VAESEM_VS(REG_V25, REG_V1)
        VAESEM_VS(REG_V25, REG_V2)
        VAESEM_VS(REG_V25, REG_V3)
        VAESEM_VS(REG_V25, REG_V4)
        VAESEM_VS(REG_V25, REG_V5)
        VAESEM_VS(REG_V25, REG_V6)
        VAESEM_VS(REG_V25, REG_V7)
        VAESEM_VS(REG_V25, REG_V8)
        VAESEM_VS(REG_V25, REG_V9)
        VAESEM_VS(REG_V25, REG_V10)
        VAESEM_VS(REG_V25, REG_V11)
        VAESEM_VS(REG_V25, REG_V12)
        VAESEM_VS(REG_V25, REG_V13)
        VAESEM_VS(REG_V26, REG_V1)
        VAESEM_VS(REG_V26, REG_V2)
        VAESEM_VS(REG_V26, REG_V3)
        VAESEM_VS(REG_V26, REG_V4)
        VAESEM_VS(REG_V26, REG_V5)
        VAESEM_VS(REG_V26, REG_V6)
        VAESEM_VS(REG_V26, REG_V7)
        VAESEM_VS(REG_V26, REG_V8)
        VAESEM_VS(REG_V26, REG_V9)
        VAESEM_VS(REG_V26, REG_V10)
        VAESEM_VS(REG_V26, REG_V11)
        VAESEM_VS(REG_V26, REG_V12)
        VAESEM_VS(REG_V26, REG_V13)
        VAESEM_VS(REG_V27, REG_V1)
        VAESEM_VS(REG_V27, REG_V2)
        VAESEM_VS(REG_V27, REG_V3)
        VAESEM_VS(REG_V27, REG_V4)
        VAESEM_VS(REG_V27, REG_V5)
        VAESEM_VS(REG_V27, REG_V6)
        VAESEM_VS(REG_V27, REG_V7)
        VAESEM_VS(REG_V27, REG_V8)
        VAESEM_VS(REG_V27, REG_V9)
        VAESEM_VS(REG_V27, REG_V10)
        VAESEM_VS(REG_V27, REG_V11)
        VAESEM_VS(REG_V27, REG_V12)
        VAESEM_VS(REG_V27, REG_V13)
        VAESEF_VS(REG_V24, REG_V14)
        VAESEF_VS(REG_V25, REG_V14)
        VAESEF_VS(REG_V26, REG_V14)
        VAESEF_VS(REG_V27, REG_V14)

        /* Load input. */
        "mv        t0, %[in]\n\t"
        VL4RE32_V(REG_V28, REG_T0)
        VXOR_VV(REG_V28, REG_V24, REG_V28)
        VXOR_VV(REG_V29, REG_V25, REG_V29)
        VXOR_VV(REG_V30, REG_V26, REG_V30)
        VXOR_VV(REG_V31, REG_V27, REG_V31)
        /* Store output. */
        "mv         t0, %[out]\n\t"
        VS4R_V(REG_V28, REG_T0)
        VGMUL_VV(REG_V28, REG_V23)
        VGMUL_VV(REG_V29, REG_V22)
        VGMUL_VV(REG_V30, REG_V21)
        VGMUL_VV(REG_V31, REG_V19)
        VXOR_VV(REG_V18, REG_V18, REG_V28)
        VXOR_VV(REG_V18, REG_V18, REG_V29)
        VXOR_VV(REG_V18, REG_V18, REG_V30)
        VXOR_VV(REG_V18, REG_V18, REG_V31)
        "addi        %[in], %[in], 64\n\t"
        "addi        %[out], %[out], 64\n\t"
        /* Loop if more elements to process. */
        "addi       t4, t4, -1\n\t"
        "bnez       t4, L_aes_gcm_256_encrypt_x4_block_loop\n\t"
        "andi       %[sz], %[sz], 0x3f\n\t"

      "L_aes_gcm_256_encrypt_x4_blocks_done:\n\t"
        "srli       t2, %[sz], 4\n\t"
        "beqz       t2, L_aes_gcm_256_encrypt_blocks_done\n\t"

      "L_aes_gcm_256_encrypt_block_loop:\n\t"
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        VADD_VI(REG_V20, REG_V20, 1)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V17, REG_V15, REG_V20)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
#else
        VREV8(REG_V17, REG_V20)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
        VMV_V_V(REG_V27, REG_V16)
        VSLIDEUP_VI(REG_V27, REG_V17, 3)
#else
        "addi       t3, t3, 1\n\t"
        "slli       t0, t3, 32\n\t"
        REV8(REG_T0, REG_T0)
        VMV_V_X(REG_V17, REG_T0)
        VMV_V_V(REG_V27, REG_V16)
        VSLIDEUP_VI(REG_V27, REG_V17, 3)
#endif /* !WOLFSSL_RISCV_BASE_BIT_MANIPULATION */

        VAESZ_VS(REG_V27, REG_V0)
        VAESEM_VS(REG_V27, REG_V1)
        VAESEM_VS(REG_V27, REG_V2)
        VAESEM_VS(REG_V27, REG_V3)
        VAESEM_VS(REG_V27, REG_V4)
        VAESEM_VS(REG_V27, REG_V5)
        VAESEM_VS(REG_V27, REG_V6)
        VAESEM_VS(REG_V27, REG_V7)
        VAESEM_VS(REG_V27, REG_V8)
        VAESEM_VS(REG_V27, REG_V9)
        VAESEM_VS(REG_V27, REG_V10)
        VAESEM_VS(REG_V27, REG_V11)
        VAESEM_VS(REG_V27, REG_V12)
        VAESEM_VS(REG_V27, REG_V13)
        VAESEF_VS(REG_V27, REG_V14)

        /* Load input. */
        "mv         t0, %[in]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VXOR_VV(REG_V27, REG_V27, REG_V17)
        VGHSH_VV(REG_V18, REG_V27, REG_V19)
        /* Store output. */
        "mv         t0, %[out]\n\t"
        VS1R_V(REG_V27, REG_T0)

        "addi        %[in], %[in], 16\n\t"
        "addi        %[out], %[out], 16\n\t"
        /* Loop if more elements to process. */
        "addi       t2, t2, -1\n\t"
        "bnez       t2, L_aes_gcm_256_encrypt_block_loop\n\t"

      "L_aes_gcm_256_encrypt_blocks_done:\n\t"
        "andi       t2, %[sz], 0xf\n\t"
        "beqz       t2, L_aes_gcm_256_encrypt_done\n\t"

        VXOR_VV(REG_V17, REG_V17, REG_V17)
        "mv         t0, %[scratch]\n\t"
        VS1R_V(REG_V17, REG_T0)
        "mv         t1, t2\n\t"
      "L_aes_gcm_256_encrypt_load_byte:\n\t"
        "lb         t0, (%[in])\n\t"
        "sb         t0, (%[scratch])\n\t"
        "addi       %[in], %[in], 1\n\t"
        "addi       %[scratch], %[scratch], 1\n\t"
        "addi       t1, t1, -1\n\t"
        "bnez       t1, L_aes_gcm_256_encrypt_load_byte\n\t"
        "sub        %[scratch], %[scratch], t2\n\t"

        /* Encrypt counter for partial block. */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        VADD_VI(REG_V20, REG_V20, 1)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V17, REG_V15, REG_V20)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
#else
        VREV8(REG_V17, REG_V20)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
        VMV_V_V(REG_V27, REG_V16)
        VSLIDEUP_VI(REG_V27, REG_V17, 3)
#else
        "addi       t3, t3, 1\n\t"
        "slli       t0, t3, 32\n\t"
        REV8(REG_T0, REG_T0)
        VMV_V_X(REG_V17, REG_T0)
        VMV_V_V(REG_V27, REG_V16)
        VSLIDEUP_VI(REG_V27, REG_V17, 3)
#endif /* !WOLFSSL_RISCV_BASE_BIT_MANIPULATION */

        VAESZ_VS(REG_V27, REG_V0)
        VAESEM_VS(REG_V27, REG_V1)
        VAESEM_VS(REG_V27, REG_V2)
        VAESEM_VS(REG_V27, REG_V3)
        VAESEM_VS(REG_V27, REG_V4)
        VAESEM_VS(REG_V27, REG_V5)
        VAESEM_VS(REG_V27, REG_V6)
        VAESEM_VS(REG_V27, REG_V7)
        VAESEM_VS(REG_V27, REG_V8)
        VAESEM_VS(REG_V27, REG_V9)
        VAESEM_VS(REG_V27, REG_V10)
        VAESEM_VS(REG_V27, REG_V11)
        VAESEM_VS(REG_V27, REG_V12)
        VAESEM_VS(REG_V27, REG_V13)
        VAESEF_VS(REG_V27, REG_V14)

        /* Load scratch. */
        "mv         t0, %[scratch]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VXOR_VV(REG_V27, REG_V27, REG_V17)
        /* Store scratch. */
        VS1R_V(REG_V27, REG_T0)
        "mv         t1, t2\n\t"
      "L_aes_gcm_256_encrypt_store_byte:\n\t"
        "lb         t0, (%[scratch])\n\t"
        "sb         t0, (%[out])\n\t"
        "addi       %[scratch], %[scratch], 1\n\t"
        "addi       %[out], %[out], 1\n\t"
        "addi       t1, t1, -1\n\t"
        "bnez       t1, L_aes_gcm_256_encrypt_store_byte\n\t"
        "li         t1, 16\n\t"
        "sub        t1, t1, t2\n\t"
      "L_aes_gcm_256_encrypt_zero_byte:\n\t"
        "sb         x0, (%[scratch])\n\t"
        "addi       %[scratch], %[scratch], 1\n\t"
        "addi       t1, t1, -1\n\t"
        "bnez       t1, L_aes_gcm_256_encrypt_zero_byte\n\t"
        "addi       %[scratch], %[scratch], -16\n\t"
        "mv         t0, %[scratch]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VGHSH_VV(REG_V18, REG_V17, REG_V19)

      "L_aes_gcm_256_encrypt_done:\n\t"

        /* Hash in the lengths of A and C in bits */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        /* aSz is only 32-bits */
        /* Multiply by 8 do get size in bits. */
        "slli       %[aSz], %[aSz], 3\n\t"
        "srli       t0, %[aSz], 32\n\t"
        "srli       t1, %[aSz], 24\n\t"
        "srli       t2, %[aSz], 16\n\t"
        "srli       t3, %[aSz], 8\n\t"
        /* Top 3 bytes are 0. */
        "sh         x0    , 0(%[scratch])\n\t"
        "sb         x0    , 2(%[scratch])\n\t"
        "sb         t0    , 3(%[scratch])\n\t"
        "sb         t1    , 4(%[scratch])\n\t"
        "sb         t2    , 5(%[scratch])\n\t"
        "sb         t3    , 6(%[scratch])\n\t"
        "sb         %[aSz], 7(%[scratch])\n\t"
        /* sz is only 32-bits */
        /* Multiply by 8 do get size in bits. */
        "slli       %[sz], %[sz], 3\n\t"
        "srli       t0, %[sz], 32\n\t"
        "srli       t1, %[sz], 24\n\t"
        "srli       t2, %[sz], 16\n\t"
        "srli       t3, %[sz], 8\n\t"
        /* Top 3 bytes are 0. */
        "sh         x0   ,  8(%[scratch])\n\t"
        "sb         x0   , 10(%[scratch])\n\t"
        "sb         t0   , 11(%[scratch])\n\t"
        "sb         t1   , 12(%[scratch])\n\t"
        "sb         t2   , 13(%[scratch])\n\t"
        "sb         t3   , 14(%[scratch])\n\t"
        "sb         %[sz], 15(%[scratch])\n\t"
#else
        "slli       t0, %[aSz], 3\n\t"
        REV8(REG_T0, REG_T0)
        "sd         t0, 0(%[scratch])\n\t"
        "slli       t0, %[sz], 3\n\t"
        REV8(REG_T0, REG_T0)
        "sd         t0, 8(%[scratch])\n\t"
#endif /* !WOLFSSL_RISCV_BASE_BIT_MANIPULATION */
        "mv         t0, %[scratch]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VGHSH_VV(REG_V18, REG_V17, REG_V19)

        VAESZ_VS(REG_V16, REG_V0)
        VAESEM_VS(REG_V16, REG_V1)
        VAESEM_VS(REG_V16, REG_V2)
        VAESEM_VS(REG_V16, REG_V3)
        VAESEM_VS(REG_V16, REG_V4)
        VAESEM_VS(REG_V16, REG_V5)
        VAESEM_VS(REG_V16, REG_V6)
        VAESEM_VS(REG_V16, REG_V7)
        VAESEM_VS(REG_V16, REG_V8)
        VAESEM_VS(REG_V16, REG_V9)
        VAESEM_VS(REG_V16, REG_V10)
        VAESEM_VS(REG_V16, REG_V11)
        VAESEM_VS(REG_V16, REG_V12)
        VAESEM_VS(REG_V16, REG_V13)
        VAESEF_VS(REG_V16, REG_V14)
        VXOR_VV(REG_V18, REG_V18, REG_V16)

        "li         t1, 16\n\t"
        "blt        %[tagSz], t1, L_aes_gcm_256_encrypt_tag_small\n\t"
        "mv         t0, %[tag]\n\t"
        VS1R_V(REG_V18, REG_T0)
        "beqz       x0, L_aes_gcm_256_encrypt_tag_done\n\t"
      "L_aes_gcm_256_encrypt_tag_small:\n\t"
        "mv         t0, %[scratch]\n\t"
        VS1R_V(REG_V18, REG_T0)
        "mv         t1, %[tagSz]\n\t"
      "L_aes_gcm_256_encrypt_store_tag_byte:\n\t"
        "lb         t0, (%[scratch])\n\t"
        "sb         t0, (%[tag])\n\t"
        "addi       %[scratch], %[scratch], 1\n\t"
        "addi       %[tag], %[tag], 1\n\t"
        "addi       t1, t1, -1\n\t"
        "bnez       t1, L_aes_gcm_256_encrypt_store_tag_byte\n\t"
      "L_aes_gcm_256_encrypt_tag_done:\n\t"

        : [out] "+r" (out), [in] "+r" (in), [key] "+r" (key),
          [aSz] "+r" (aadSz), [aad] "+r" (aad), [sz] "+r" (sz)
        : [ctr] "r" (ctr), [scratch] "r" (scratch),
          [h] "r" (aes->gcm.H), [tag] "r" (tag), [tagSz] "r" (tagSz)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
          , [rev_idx] "r" (rev_idx)
#endif
        : "memory", "t0", "t1", "t2", "t3", "t4"
    );

#ifdef OPENSSL_EXTRA
    if ((tag != NULL) && (in != NULL) && (sz != 0)) {
        /* store AAD size for next call */
        aes->gcm.aadLen = aadSz;
    }
#endif
}
#endif /*  WOLFSSL_AES_256 */

/* Encrypt data using AES-GCM.
 *
 * @param [in]  aes      AES object.
 * @param [out] out      Encrypted data.
 * @param [in]  in       Data to encrypt.
 * @param [in]  sz       Number of bytes of data.
 * @param [in]  nonce    Nonce used to calculate first IV.
 * @param [in]  nonceSz  Length of nonce in bytes.
 * @param [out] tag      Authentication tag.
 * @param [in]  tagSz    Length of authentication tag in bytes.
 * @param [in]  aad      Additional Authentication Data (AAD).
 * @param [in]  aadSz    Length of AAD in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when aes, nonce or tag is NULL.
 * @return  BAD_FUNC_ARG when nonceSz is zero.
 * @return  BAD_FUNC_ARG when aad is NULL but aadSz is not zero.
 * @return  BAD_FUNC_ARG when tagSz is less than WOLFSSL_MIN_AUTH_TAG_SZ or
 *          greater than AES_BLOCK_SIZE.
 * @return  BAD_FUNC_ARG when sz is not zero but in or out is NULL.
 */
int wc_AesGcmEncrypt(Aes* aes, byte* out, const byte* in, word32 sz,
    const byte* nonce, word32 nonceSz, byte* tag, word32 tagSz, const byte* aad,
    word32 aadSz)
{
    int ret = 0;

    /* sanity checks */
    if ((aes == NULL) || (nonce == NULL) || (nonceSz == 0) || (tag == NULL) ||
            ((aad == NULL) && (aadSz > 0)) || ((sz != 0) && ((in == NULL) ||
            (out == NULL)))) {
        WOLFSSL_MSG("a NULL parameter passed in when size is larger than 0");
        ret = BAD_FUNC_ARG;
    }

    if ((ret == 0) && ((tagSz < WOLFSSL_MIN_AUTH_TAG_SZ) ||
            (tagSz > AES_BLOCK_SIZE))) {
        WOLFSSL_MSG("GcmEncrypt tagSz error");
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        switch (aes->rounds) {
        #ifdef WOLFSSL_AES_128
            case 10:
                Aes128GcmEncrypt(aes, out, in, sz, nonce, nonceSz, tag, tagSz,
                    aad, aadSz);
                break;
        #endif
        #ifdef WOLFSSL_AES_192
            case 12:
                Aes192GcmEncrypt(aes, out, in, sz, nonce, nonceSz, tag, tagSz,
                    aad, aadSz);
                break;
        #endif
        #ifdef WOLFSSL_AES_256
            case 14:
                Aes256GcmEncrypt(aes, out, in, sz, nonce, nonceSz, tag, tagSz,
                    aad, aadSz);
                break;
        #endif
            default:
                WOLFSSL_MSG("AES-GCM invalid round number");
                ret = BAD_FUNC_ARG;
        }
    }

    return ret;
}


#ifdef HAVE_AES_DECRYPT

#ifdef WOLFSSL_AES_128
/* Decrypt data using AES-128-GCM.
 *
 * @param [in]  aes      AES object.
 * @param [out] out      Decrypted data.
 * @param [in]  in       Data to decrypt and GHASH.
 * @param [in]  sz       Number of bytes of data.
 * @param [in]  nonce    Nonce used to calculate first IV.
 * @param [in]  nonceSz  Length of nonce in bytes.
 * @param [out] tag      Authentication tag.
 * @param [in]  tagSz    Length of authentication tag in bytes.
 * @param [in]  aad      Additional Authentication Data (AAD).
 * @param [in]  aadSz    Length of AAD in bytes.
 * @return  0 on success.
 * @return  AES_GCM_AUTH_E when authentication tag computed doesn't match
 *          tag passed in.
 */
static int Aes128GcmDecrypt(Aes* aes, byte* out, const byte* in, word32 sz,
    const byte* nonce, word32 nonceSz, const byte* tag, word32 tagSz,
    const byte* aad, word32 aadSz)
{
    int ret = 0;
    byte counter[AES_BLOCK_SIZE];
    byte scratch[AES_BLOCK_SIZE];
    /* Noticed different optimization levels treated head of array different.
     * Some cases was stack pointer plus offset others was a register containing
     * address. To make uniform for passing in to inline assembly code am using
     * pointers to the head of each local array.
     */
    byte* ctr  = counter;
    byte* key = (byte*)aes->key;

    XMEMSET(counter, 0, AES_BLOCK_SIZE);
    if (nonceSz == GCM_NONCE_MID_SZ) {
        XMEMCPY(counter, nonce, GCM_NONCE_MID_SZ);
        counter[AES_BLOCK_SIZE - 1] = 1;
    }
    else {
#ifdef OPENSSL_EXTRA
        word32 aadTemp = aes->gcm.aadLen;
        aes->gcm.aadLen = 0;
#endif
        GHASH(&aes->gcm, NULL, 0, nonce, nonceSz, counter, AES_BLOCK_SIZE);
#ifdef OPENSSL_EXTRA
        aes->gcm.aadLen = aadTemp;
#endif
    }

    __asm__ __volatile__ (
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)

        /* X=0, get H */
        VXOR_VV(REG_V18, REG_V18, REG_V18)
        "mv         t0, %[h]\n\t"
        VL1RE32_V(REG_V19, REG_T0)

        /* Hash in AAD, the Additional Authentication Data */
        "beqz       %[aSz], L_aes_gcm_128_decrypt_ghash_aad_done\n\t"
        "beqz       %[aad], L_aes_gcm_128_decrypt_ghash_aad_done\n\t"

        "srli       t1, %[aSz], 4\n\t"
        "beqz       t1, L_aes_gcm_128_decrypt_ghash_aad_blocks_done\n\t"

      "L_aes_gcm_128_decrypt_ghash_aad_loop:\n\t"
        "mv         t0, %[aad]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VGHSH_VV(REG_V18, REG_V17, REG_V19)
        "addi       %[aad], %[aad], 16\n\t"
        "addi       t1, t1, -1\n\t"
        "bnez       t1, L_aes_gcm_128_decrypt_ghash_aad_loop\n\t"
      "L_aes_gcm_128_decrypt_ghash_aad_blocks_done:\n\t"
        "andi       t1, %[aSz], 0xf\n\t"
        "beqz       t1, L_aes_gcm_128_decrypt_ghash_aad_done\n\t"
        VXOR_VV(REG_V17, REG_V17, REG_V17)
        "mv         t0, %[scratch]\n\t"
        VS1R_V(REG_V17, REG_T0)
        "mv         t2, t1\n\t"
      "L_aes_gcm_128_decrypt_ghash_aad_load_byte:\n\t"
        "lb         t0, (%[aad])\n\t"
        "sb         t0, (%[scratch])\n\t"
        "addi       %[aad], %[aad], 1\n\t"
        "addi       %[scratch], %[scratch], 1\n\t"
        "addi       t2, t2, -1\n\t"
        "bnez       t2, L_aes_gcm_128_decrypt_ghash_aad_load_byte\n\t"
        "sub        %[scratch], %[scratch], t1\n\t"
        "mv         t0, %[scratch]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VGHSH_VV(REG_V18, REG_V17, REG_V19)
      "L_aes_gcm_128_decrypt_ghash_aad_done:\n\t"
        /* Done Hash in AAD */

#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        "mv         t0, %[rev_idx]\n\t"
        VL1RE32_V(REG_V15, REG_T0)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
        /* Load the counter. */
        "mv         t0, %[ctr]\n\t"
        VL1RE32_V(REG_V16, REG_T0)
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        VSLIDEDOWN_VI(REG_V20, REG_V16, 3)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V21, REG_V15, REG_V20)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
        VMV_V_V(REG_V20, REG_V21)
#else
        VREV8(REG_V20, REG_V20)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
#else
        "lw         t3, 12(%[ctr])\n\t"
        "slli       t3, t3, 32\n\t"
        REV8(REG_T3, REG_T3)
#endif /* !WOLFSSL_RISCV_BASE_BIT_MANIPULATION */

        /* Load key[0..7]. */
        "mv         t0, %[key]\n\t"
        VL8RE32_V(REG_V0, REG_T0)
        /* Load key[8..9]. */
        "addi       t0, t0, 128\n\t"
        VL2RE32_V(REG_V8, REG_T0)
        /* Load last round's key */
        "addi       t0, %[key], 224\n\t"
        VL1RE32_V(REG_V10, REG_T0)

        "beqz       %[sz], L_aes_gcm_128_decrypt_blocks_done\n\t"
        "srli       t4, %[sz], 6\n\t"
        "beqz       t4, L_aes_gcm_128_decrypt_x4_blocks_done\n\t"

        /* Calculate H^[1-4] - GMULT partials */
        VMV_V_V(REG_V21, REG_V19)
        VMV_V_V(REG_V22, REG_V19)
        /* Multiply H * H => H^2 */
        VGMUL_VV(REG_V21, REG_V19)
        VMV_V_V(REG_V23, REG_V21)
        /* Multiply H * H => H^3 */
        VGMUL_VV(REG_V22, REG_V21)
        /* Multiply H^2 * H^2 => H^4 */
        VGMUL_VV(REG_V23, REG_V21)

      "L_aes_gcm_128_decrypt_x4_block_loop:\n\t"
        /* Load input. */
        "mv        t0, %[in]\n\t"
        VL4RE32_V(REG_V28, REG_T0)
        VMVR_V(REG_V24, REG_V28, 4)
        VGMUL_VV(REG_V24, REG_V23)
        VGMUL_VV(REG_V25, REG_V22)
        VGMUL_VV(REG_V26, REG_V21)
        VGMUL_VV(REG_V27, REG_V19)
        VXOR_VV(REG_V18, REG_V18, REG_V24)
        VXOR_VV(REG_V18, REG_V18, REG_V25)
        VXOR_VV(REG_V18, REG_V18, REG_V26)
        VXOR_VV(REG_V18, REG_V18, REG_V27)
        /* Calculate next 4 counters (+1-4) */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        VADD_VI(REG_V20, REG_V20, 1)
        VMV_V_V(REG_V24, REG_V16)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V17, REG_V15, REG_V20)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
#else
        VREV8(REG_V17, REG_V20)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
        VSLIDEUP_VI(REG_V24, REG_V17, 3)
        VADD_VI(REG_V20, REG_V20, 1)
        VMV_V_V(REG_V25, REG_V16)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V17, REG_V15, REG_V20)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
#else
        VREV8(REG_V17, REG_V20)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
        VSLIDEUP_VI(REG_V25, REG_V17, 3)
        VADD_VI(REG_V20, REG_V20, 1)
        VMV_V_V(REG_V26, REG_V16)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V17, REG_V15, REG_V20)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
#else
        VREV8(REG_V17, REG_V20)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
        VSLIDEUP_VI(REG_V26, REG_V17, 3)
        VADD_VI(REG_V20, REG_V20, 1)
        VMV_V_V(REG_V27, REG_V16)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V17, REG_V15, REG_V20)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
#else
        VREV8(REG_V17, REG_V20)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
        VSLIDEUP_VI(REG_V27, REG_V17, 3)
#else
        "addi       t0, t3, 1\n\t"
        VMV_V_V(REG_V24, REG_V16)
        "addi       t1, t3, 2\n\t"
        VMV_V_V(REG_V25, REG_V16)
        "slli       t0, t0, 32\n\t"
        VMV_V_V(REG_V26, REG_V16)
        "slli       t1, t1, 32\n\t"
        VMV_V_V(REG_V27, REG_V16)
        REV8(REG_T0, REG_T0)
        REV8(REG_T1, REG_T1)
        VMV_V_X(REG_V20, REG_T0)
        "addi       t0, t3, 3\n\t"
        VSLIDEUP_VI(REG_V24, REG_V20, 3)
        "addi       t3, t3, 4\n\t"
        VMV_V_X(REG_V20, REG_T1)
        "slli       t0, t0, 32\n\t"
        VSLIDEUP_VI(REG_V25, REG_V20, 3)
        "slli       t1, t3, 32\n\t"
        REV8(REG_T0, REG_T0)
        REV8(REG_T1, REG_T1)
        VMV_V_X(REG_V20, REG_T0)
        VSLIDEUP_VI(REG_V26, REG_V20, 3)
        VMV_V_X(REG_V20, REG_T1)
        VSLIDEUP_VI(REG_V27, REG_V20, 3)
#endif /* !WOLFSSL_RISCV_BASE_BIT_MANIPULATION */

        VAESZ_VS(REG_V24, REG_V0)
        VAESZ_VS(REG_V25, REG_V0)
        VAESZ_VS(REG_V26, REG_V0)
        VAESZ_VS(REG_V27, REG_V0)
        VAESEM_VS(REG_V24, REG_V1)
        VAESEM_VS(REG_V24, REG_V2)
        VAESEM_VS(REG_V24, REG_V3)
        VAESEM_VS(REG_V24, REG_V4)
        VAESEM_VS(REG_V24, REG_V5)
        VAESEM_VS(REG_V24, REG_V6)
        VAESEM_VS(REG_V24, REG_V7)
        VAESEM_VS(REG_V24, REG_V8)
        VAESEM_VS(REG_V24, REG_V9)
        VAESEM_VS(REG_V25, REG_V1)
        VAESEM_VS(REG_V25, REG_V2)
        VAESEM_VS(REG_V25, REG_V3)
        VAESEM_VS(REG_V25, REG_V4)
        VAESEM_VS(REG_V25, REG_V5)
        VAESEM_VS(REG_V25, REG_V6)
        VAESEM_VS(REG_V25, REG_V7)
        VAESEM_VS(REG_V25, REG_V8)
        VAESEM_VS(REG_V25, REG_V9)
        VAESEM_VS(REG_V26, REG_V1)
        VAESEM_VS(REG_V26, REG_V2)
        VAESEM_VS(REG_V26, REG_V3)
        VAESEM_VS(REG_V26, REG_V4)
        VAESEM_VS(REG_V26, REG_V5)
        VAESEM_VS(REG_V26, REG_V6)
        VAESEM_VS(REG_V26, REG_V7)
        VAESEM_VS(REG_V26, REG_V8)
        VAESEM_VS(REG_V26, REG_V9)
        VAESEM_VS(REG_V27, REG_V1)
        VAESEM_VS(REG_V27, REG_V2)
        VAESEM_VS(REG_V27, REG_V3)
        VAESEM_VS(REG_V27, REG_V4)
        VAESEM_VS(REG_V27, REG_V5)
        VAESEM_VS(REG_V27, REG_V6)
        VAESEM_VS(REG_V27, REG_V7)
        VAESEM_VS(REG_V27, REG_V8)
        VAESEM_VS(REG_V27, REG_V9)
        VAESEF_VS(REG_V24, REG_V10)
        VAESEF_VS(REG_V25, REG_V10)
        VAESEF_VS(REG_V26, REG_V10)
        VAESEF_VS(REG_V27, REG_V10)
        VXOR_VV(REG_V28, REG_V24, REG_V28)
        VXOR_VV(REG_V29, REG_V25, REG_V29)
        VXOR_VV(REG_V30, REG_V26, REG_V30)
        VXOR_VV(REG_V31, REG_V27, REG_V31)
        /* Store output. */
        "mv         t0, %[out]\n\t"
        VS4R_V(REG_V28, REG_T0)
        "addi        %[in], %[in], 64\n\t"
        "addi        %[out], %[out], 64\n\t"
        /* Loop if more elements to process. */
        "addi       t4, t4, -1\n\t"
        "bnez       t4, L_aes_gcm_128_decrypt_x4_block_loop\n\t"
        "andi       %[sz], %[sz], 0x3f\n\t"

      "L_aes_gcm_128_decrypt_x4_blocks_done:\n\t"
        "srli       t2, %[sz], 4\n\t"
        "beqz       t2, L_aes_gcm_128_decrypt_blocks_done\n\t"

      "L_aes_gcm_128_decrypt_block_loop:\n\t"
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        VADD_VI(REG_V20, REG_V20, 1)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V17, REG_V15, REG_V20)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
#else
        VREV8(REG_V17, REG_V20)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
        VMV_V_V(REG_V27, REG_V16)
        VSLIDEUP_VI(REG_V27, REG_V17, 3)
#else
        "addi       t3, t3, 1\n\t"
        "slli       t0, t3, 32\n\t"
        REV8(REG_T0, REG_T0)
        VMV_V_X(REG_V17, REG_T0)
        VMV_V_V(REG_V27, REG_V16)
        VSLIDEUP_VI(REG_V27, REG_V17, 3)
#endif /* !WOLFSSL_RISCV_BASE_BIT_MANIPULATION */

        VAESZ_VS(REG_V27, REG_V0)
        VAESEM_VS(REG_V27, REG_V1)
        VAESEM_VS(REG_V27, REG_V2)
        VAESEM_VS(REG_V27, REG_V3)
        VAESEM_VS(REG_V27, REG_V4)
        VAESEM_VS(REG_V27, REG_V5)
        VAESEM_VS(REG_V27, REG_V6)
        VAESEM_VS(REG_V27, REG_V7)
        VAESEM_VS(REG_V27, REG_V8)
        VAESEM_VS(REG_V27, REG_V9)
        VAESEF_VS(REG_V27, REG_V10)

        /* Load input. */
        "mv         t0, %[in]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VGHSH_VV(REG_V18, REG_V17, REG_V19)
        VXOR_VV(REG_V27, REG_V27, REG_V17)
        /* Store output. */
        "mv         t0, %[out]\n\t"
        VS1R_V(REG_V27, REG_T0)

        "addi        %[in], %[in], 16\n\t"
        "addi        %[out], %[out], 16\n\t"
        /* Loop if more elements to process. */
        "addi       t2, t2, -1\n\t"
        "bnez       t2, L_aes_gcm_128_decrypt_block_loop\n\t"

      "L_aes_gcm_128_decrypt_blocks_done:\n\t"
        "andi       t2, %[sz], 0xf\n\t"
        "beqz       t2, L_aes_gcm_128_decrypt_done\n\t"

        VXOR_VV(REG_V17, REG_V17, REG_V17)
        "mv         t0, %[scratch]\n\t"
        VS1R_V(REG_V17, REG_T0)
        "mv         t1, t2\n\t"
      "L_aes_gcm_128_decrypt_load_byte:\n\t"
        "lb         t0, (%[in])\n\t"
        "sb         t0, (%[scratch])\n\t"
        "addi       %[in], %[in], 1\n\t"
        "addi       %[scratch], %[scratch], 1\n\t"
        "addi       t1, t1, -1\n\t"
        "bnez       t1, L_aes_gcm_128_decrypt_load_byte\n\t"
        "sub        %[scratch], %[scratch], t2\n\t"
        "mv         t0, %[scratch]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VGHSH_VV(REG_V18, REG_V17, REG_V19)

        /* Encrypt counter for partial block. */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        VADD_VI(REG_V20, REG_V20, 1)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V17, REG_V15, REG_V20)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
#else
        VREV8(REG_V17, REG_V20)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
        VMV_V_V(REG_V27, REG_V16)
        VSLIDEUP_VI(REG_V27, REG_V17, 3)
#else
        "addi       t3, t3, 1\n\t"
        "slli       t0, t3, 32\n\t"
        REV8(REG_T0, REG_T0)
        VMV_V_X(REG_V17, REG_T0)
        VMV_V_V(REG_V27, REG_V16)
        VSLIDEUP_VI(REG_V27, REG_V17, 3)
#endif /* !WOLFSSL_RISCV_BASE_BIT_MANIPULATION */

        VAESZ_VS(REG_V27, REG_V0)
        VAESEM_VS(REG_V27, REG_V1)
        VAESEM_VS(REG_V27, REG_V2)
        VAESEM_VS(REG_V27, REG_V3)
        VAESEM_VS(REG_V27, REG_V4)
        VAESEM_VS(REG_V27, REG_V5)
        VAESEM_VS(REG_V27, REG_V6)
        VAESEM_VS(REG_V27, REG_V7)
        VAESEM_VS(REG_V27, REG_V8)
        VAESEM_VS(REG_V27, REG_V9)
        VAESEF_VS(REG_V27, REG_V10)

        /* Load scratch. */
        "mv         t0, %[scratch]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VXOR_VV(REG_V27, REG_V27, REG_V17)
        /* Store scratch. */
        VS1R_V(REG_V27, REG_T0)
        "mv         t1, t2\n\t"
      "L_aes_gcm_128_decrypt_store_byte:\n\t"
        "lb         t0, (%[scratch])\n\t"
        "sb         t0, (%[out])\n\t"
        "addi       %[scratch], %[scratch], 1\n\t"
        "addi       %[out], %[out], 1\n\t"
        "addi       t1, t1, -1\n\t"
        "bnez       t1, L_aes_gcm_128_decrypt_store_byte\n\t"
        "sub        %[scratch], %[scratch], t2\n\t"

      "L_aes_gcm_128_decrypt_done:\n\t"

        /* Hash in the lengths of A and C in bits */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        /* aSz is only 32-bits */
        /* Multiply by 8 do get size in bits. */
        "slli       %[aSz], %[aSz], 3\n\t"
        "srli       t0, %[aSz], 32\n\t"
        "srli       t1, %[aSz], 24\n\t"
        "srli       t2, %[aSz], 16\n\t"
        "srli       t3, %[aSz], 8\n\t"
        /* Top 3 bytes are 0. */
        "sh         x0    , 0(%[scratch])\n\t"
        "sb         x0    , 2(%[scratch])\n\t"
        "sb         t0    , 3(%[scratch])\n\t"
        "sb         t1    , 4(%[scratch])\n\t"
        "sb         t2    , 5(%[scratch])\n\t"
        "sb         t3    , 6(%[scratch])\n\t"
        "sb         %[aSz], 7(%[scratch])\n\t"
        /* sz is only 32-bits */
        /* Multiply by 8 do get size in bits. */
        "slli       %[sz], %[sz], 3\n\t"
        "srli       t0, %[sz], 32\n\t"
        "srli       t1, %[sz], 24\n\t"
        "srli       t2, %[sz], 16\n\t"
        "srli       t3, %[sz], 8\n\t"
        /* Top 3 bytes are 0. */
        "sh         x0   ,  8(%[scratch])\n\t"
        "sb         x0   , 10(%[scratch])\n\t"
        "sb         t0   , 11(%[scratch])\n\t"
        "sb         t1   , 12(%[scratch])\n\t"
        "sb         t2   , 13(%[scratch])\n\t"
        "sb         t3   , 14(%[scratch])\n\t"
        "sb         %[sz], 15(%[scratch])\n\t"
#else
        "slli       t0, %[aSz], 3\n\t"
        REV8(REG_T0, REG_T0)
        "sd         t0, 0(%[scratch])\n\t"
        "slli       t0, %[sz], 3\n\t"
        REV8(REG_T0, REG_T0)
        "sd         t0, 8(%[scratch])\n\t"
#endif /* !WOLFSSL_RISCV_BASE_BIT_MANIPULATION */
        "mv         t0, %[scratch]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VGHSH_VV(REG_V18, REG_V17, REG_V19)

        VAESZ_VS(REG_V16, REG_V0)
        VAESEM_VS(REG_V16, REG_V1)
        VAESEM_VS(REG_V16, REG_V2)
        VAESEM_VS(REG_V16, REG_V3)
        VAESEM_VS(REG_V16, REG_V4)
        VAESEM_VS(REG_V16, REG_V5)
        VAESEM_VS(REG_V16, REG_V6)
        VAESEM_VS(REG_V16, REG_V7)
        VAESEM_VS(REG_V16, REG_V8)
        VAESEM_VS(REG_V16, REG_V9)
        VAESEF_VS(REG_V16, REG_V10)
        VXOR_VV(REG_V18, REG_V18, REG_V16)

        "li         t1, 16\n\t"
        "blt        %[tagSz], t1, L_aes_gcm_128_decrypt_tag_small\n\t"
        "mv         t0, %[tag]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VXOR_VV(REG_V19, REG_V19, REG_V19)
        VXOR_VV(REG_V18, REG_V18, REG_V17)
        VMSNE_VV(REG_V19, REG_V19, REG_V18)
        VCPOP_M(REG_T0, REG_V19)
        "beqz       x0, L_aes_gcm_128_decrypt_tag_done\n\t"
      "L_aes_gcm_128_decrypt_tag_small:\n\t"
        "mv         t0, %[scratch]\n\t"
        VS1R_V(REG_V18, REG_T0)
        "mv         t1, %[tagSz]\n\t"
        "xor        t0, t0, t0\n\t"
      "L_aes_gcm_128_decrypt_store_tag_byte:\n\t"
        "lb         t2, (%[scratch])\n\t"
        "lb         t3, (%[tag])\n\t"
        "xor        t0, t0, t2\n\t"
        "xor        t0, t0, t3\n\t"
        "addi       %[scratch], %[scratch], 1\n\t"
        "addi       %[tag], %[tag], 1\n\t"
        "addi       t1, t1, -1\n\t"
        "bnez       t1, L_aes_gcm_128_decrypt_store_tag_byte\n\t"
      "L_aes_gcm_128_decrypt_tag_done:\n\t"
        "negw       t0, t0\n\t"
        "sraiw      t0, t0, 31\n\t"
        "andi       %[ret], t0, -180\n\t"

        : [out] "+r" (out), [in] "+r" (in), [key] "+r" (key),
          [aSz] "+r" (aadSz), [aad] "+r" (aad), [ret] "+r" (ret),
          [sz] "+r" (sz)
        : [ctr] "r" (ctr), [scratch] "r" (scratch),
          [h] "r" (aes->gcm.H), [tag] "r" (tag), [tagSz] "r" (tagSz)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
          , [rev_idx] "r" (rev_idx)
#endif
        : "memory", "t0", "t1", "t2", "t3", "t4"
    );

#ifdef OPENSSL_EXTRA
    if ((tag != NULL) && (in != NULL) && (sz != 0)) {
        /* store AAD size for next call */
        aes->gcm.aadLen = aadSz;
    }
#endif

    return ret;
}
#endif /* WOLFSSL_AES_128 */

#ifdef WOLFSSL_AES_192
/* Decrypt data using AES-192-GCM.
 *
 * @param [in]  aes      AES object.
 * @param [out] out      Decrypted data.
 * @param [in]  in       Data to decrypt and GHASH.
 * @param [in]  sz       Number of bytes of data.
 * @param [in]  nonce    Nonce used to calculate first IV.
 * @param [in]  nonceSz  Length of nonce in bytes.
 * @param [out] tag      Authentication tag.
 * @param [in]  tagSz    Length of authentication tag in bytes.
 * @param [in]  aad      Additional Authentication Data (AAD).
 * @param [in]  aadSz    Length of AAD in bytes.
 * @return  0 on success.
 * @return  AES_GCM_AUTH_E when authentication tag computed doesn't match
 *          tag passed in.
 */
static int Aes192GcmDecrypt(Aes* aes, byte* out, const byte* in, word32 sz,
    const byte* nonce, word32 nonceSz, const byte* tag, word32 tagSz,
    const byte* aad, word32 aadSz)
{
    int ret = 0;
    byte counter[AES_BLOCK_SIZE];
    byte scratch[AES_BLOCK_SIZE];
    /* Noticed different optimization levels treated head of array different.
     * Some cases was stack pointer plus offset others was a register containing
     * address. To make uniform for passing in to inline assembly code am using
     * pointers to the head of each local array.
     */
    byte* ctr  = counter;
    byte* key = (byte*)aes->key;

    XMEMSET(counter, 0, AES_BLOCK_SIZE);
    if (nonceSz == GCM_NONCE_MID_SZ) {
        XMEMCPY(counter, nonce, GCM_NONCE_MID_SZ);
        counter[AES_BLOCK_SIZE - 1] = 1;
    }
    else {
#ifdef OPENSSL_EXTRA
        word32 aadTemp = aes->gcm.aadLen;
        aes->gcm.aadLen = 0;
#endif
        GHASH(&aes->gcm, NULL, 0, nonce, nonceSz, counter, AES_BLOCK_SIZE);
#ifdef OPENSSL_EXTRA
        aes->gcm.aadLen = aadTemp;
#endif
    }

    __asm__ __volatile__ (
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)

        /* X=0, get H */
        VXOR_VV(REG_V18, REG_V18, REG_V18)
        "mv         t0, %[h]\n\t"
        VL1RE32_V(REG_V19, REG_T0)

        /* Hash in AAD, the Additional Authentication Data */
        "beqz       %[aSz], L_aes_gcm_192_decrypt_ghash_aad_done\n\t"
        "beqz       %[aad], L_aes_gcm_192_decrypt_ghash_aad_done\n\t"

        "srli       t1, %[aSz], 4\n\t"
        "beqz       t1, L_aes_gcm_192_decrypt_ghash_aad_blocks_done\n\t"

      "L_aes_gcm_192_decrypt_ghash_aad_loop:\n\t"
        "mv         t0, %[aad]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VGHSH_VV(REG_V18, REG_V17, REG_V19)
        "addi       %[aad], %[aad], 16\n\t"
        "addi       t1, t1, -1\n\t"
        "bnez       t1, L_aes_gcm_192_decrypt_ghash_aad_loop\n\t"
      "L_aes_gcm_192_decrypt_ghash_aad_blocks_done:\n\t"
        "andi       t1, %[aSz], 0xf\n\t"
        "beqz       t1, L_aes_gcm_192_decrypt_ghash_aad_done\n\t"
        VXOR_VV(REG_V17, REG_V17, REG_V17)
        "mv         t0, %[scratch]\n\t"
        VS1R_V(REG_V17, REG_T0)
        "mv         t2, t1\n\t"
      "L_aes_gcm_192_decrypt_ghash_aad_load_byte:\n\t"
        "lb         t0, (%[aad])\n\t"
        "sb         t0, (%[scratch])\n\t"
        "addi       %[aad], %[aad], 1\n\t"
        "addi       %[scratch], %[scratch], 1\n\t"
        "addi       t2, t2, -1\n\t"
        "bnez       t2, L_aes_gcm_192_decrypt_ghash_aad_load_byte\n\t"
        "sub        %[scratch], %[scratch], t1\n\t"
        "mv         t0, %[scratch]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VGHSH_VV(REG_V18, REG_V17, REG_V19)
      "L_aes_gcm_192_decrypt_ghash_aad_done:\n\t"
        /* Done Hash in AAD */

#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        "mv         t0, %[rev_idx]\n\t"
        VL1RE32_V(REG_V15, REG_T0)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
        /* Load the counter. */
        "mv         t0, %[ctr]\n\t"
        VL1RE32_V(REG_V16, REG_T0)
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        VSLIDEDOWN_VI(REG_V20, REG_V16, 3)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V21, REG_V15, REG_V20)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
        VMV_V_V(REG_V20, REG_V21)
#else
        VREV8(REG_V20, REG_V20)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
#else
        "lw         t3, 12(%[ctr])\n\t"
        "slli       t3, t3, 32\n\t"
        REV8(REG_T3, REG_T3)
#endif /* !WOLFSSL_RISCV_BASE_BIT_MANIPULATION */

        /* Load key[0..7]. */
        "mv         t0, %[key]\n\t"
        VL8RE32_V(REG_V0, REG_T0)
        /* Load key[8..11]. */
        "addi       t0, t0, 128\n\t"
        VL4RE32_V(REG_V8, REG_T0)
        /* Load last round's key */
        "addi       t0, %[key], 224\n\t"
        VL1RE32_V(REG_V12, REG_T0)

        "beqz       %[sz], L_aes_gcm_192_decrypt_blocks_done\n\t"
        "srli       t4, %[sz], 6\n\t"
        "beqz       t4, L_aes_gcm_192_decrypt_x4_blocks_done\n\t"

        /* Calculate H^[1-4] - GMULT partials */
        VMV_V_V(REG_V21, REG_V19)
        VMV_V_V(REG_V22, REG_V19)
        /* Multiply H * H => H^2 */
        VGMUL_VV(REG_V21, REG_V19)
        VMV_V_V(REG_V23, REG_V21)
        /* Multiply H * H => H^3 */
        VGMUL_VV(REG_V22, REG_V21)
        /* Multiply H^2 * H^2 => H^4 */
        VGMUL_VV(REG_V23, REG_V21)

      "L_aes_gcm_192_decrypt_x4_block_loop:\n\t"
        /* Load input. */
        "mv        t0, %[in]\n\t"
        VL4RE32_V(REG_V28, REG_T0)
        VMVR_V(REG_V24, REG_V28, 4)
        VGMUL_VV(REG_V24, REG_V23)
        VGMUL_VV(REG_V25, REG_V22)
        VGMUL_VV(REG_V26, REG_V21)
        VGMUL_VV(REG_V27, REG_V19)
        VXOR_VV(REG_V18, REG_V18, REG_V24)
        VXOR_VV(REG_V18, REG_V18, REG_V25)
        VXOR_VV(REG_V18, REG_V18, REG_V26)
        VXOR_VV(REG_V18, REG_V18, REG_V27)
        /* Calculate next 4 counters (+1-4) */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        VADD_VI(REG_V20, REG_V20, 1)
        VMV_V_V(REG_V24, REG_V16)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V17, REG_V15, REG_V20)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
#else
        VREV8(REG_V17, REG_V20)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
        VSLIDEUP_VI(REG_V24, REG_V17, 3)
        VADD_VI(REG_V20, REG_V20, 1)
        VMV_V_V(REG_V25, REG_V16)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V17, REG_V15, REG_V20)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
#else
        VREV8(REG_V17, REG_V20)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
        VSLIDEUP_VI(REG_V25, REG_V17, 3)
        VADD_VI(REG_V20, REG_V20, 1)
        VMV_V_V(REG_V26, REG_V16)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V17, REG_V15, REG_V20)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
#else
        VREV8(REG_V17, REG_V20)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
        VSLIDEUP_VI(REG_V26, REG_V17, 3)
        VADD_VI(REG_V20, REG_V20, 1)
        VMV_V_V(REG_V27, REG_V16)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V17, REG_V15, REG_V20)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
#else
        VREV8(REG_V17, REG_V20)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
        VSLIDEUP_VI(REG_V27, REG_V17, 3)
#else
        "addi       t0, t3, 1\n\t"
        VMV_V_V(REG_V24, REG_V16)
        "addi       t1, t3, 2\n\t"
        VMV_V_V(REG_V25, REG_V16)
        "slli       t0, t0, 32\n\t"
        VMV_V_V(REG_V26, REG_V16)
        "slli       t1, t1, 32\n\t"
        VMV_V_V(REG_V27, REG_V16)
        REV8(REG_T0, REG_T0)
        REV8(REG_T1, REG_T1)
        VMV_V_X(REG_V20, REG_T0)
        "addi       t0, t3, 3\n\t"
        VSLIDEUP_VI(REG_V24, REG_V20, 3)
        "addi       t3, t3, 4\n\t"
        VMV_V_X(REG_V20, REG_T1)
        "slli       t0, t0, 32\n\t"
        VSLIDEUP_VI(REG_V25, REG_V20, 3)
        "slli       t1, t3, 32\n\t"
        REV8(REG_T0, REG_T0)
        REV8(REG_T1, REG_T1)
        VMV_V_X(REG_V20, REG_T0)
        VSLIDEUP_VI(REG_V26, REG_V20, 3)
        VMV_V_X(REG_V20, REG_T1)
        VSLIDEUP_VI(REG_V27, REG_V20, 3)
#endif /* !WOLFSSL_RISCV_BASE_BIT_MANIPULATION */

        VAESZ_VS(REG_V24, REG_V0)
        VAESZ_VS(REG_V25, REG_V0)
        VAESZ_VS(REG_V26, REG_V0)
        VAESZ_VS(REG_V27, REG_V0)
        VAESEM_VS(REG_V24, REG_V1)
        VAESEM_VS(REG_V24, REG_V2)
        VAESEM_VS(REG_V24, REG_V3)
        VAESEM_VS(REG_V24, REG_V4)
        VAESEM_VS(REG_V24, REG_V5)
        VAESEM_VS(REG_V24, REG_V6)
        VAESEM_VS(REG_V24, REG_V7)
        VAESEM_VS(REG_V24, REG_V8)
        VAESEM_VS(REG_V24, REG_V9)
        VAESEM_VS(REG_V24, REG_V10)
        VAESEM_VS(REG_V24, REG_V11)
        VAESEM_VS(REG_V25, REG_V1)
        VAESEM_VS(REG_V25, REG_V2)
        VAESEM_VS(REG_V25, REG_V3)
        VAESEM_VS(REG_V25, REG_V4)
        VAESEM_VS(REG_V25, REG_V5)
        VAESEM_VS(REG_V25, REG_V6)
        VAESEM_VS(REG_V25, REG_V7)
        VAESEM_VS(REG_V25, REG_V8)
        VAESEM_VS(REG_V25, REG_V9)
        VAESEM_VS(REG_V25, REG_V10)
        VAESEM_VS(REG_V25, REG_V11)
        VAESEM_VS(REG_V26, REG_V1)
        VAESEM_VS(REG_V26, REG_V2)
        VAESEM_VS(REG_V26, REG_V3)
        VAESEM_VS(REG_V26, REG_V4)
        VAESEM_VS(REG_V26, REG_V5)
        VAESEM_VS(REG_V26, REG_V6)
        VAESEM_VS(REG_V26, REG_V7)
        VAESEM_VS(REG_V26, REG_V8)
        VAESEM_VS(REG_V26, REG_V9)
        VAESEM_VS(REG_V26, REG_V10)
        VAESEM_VS(REG_V26, REG_V11)
        VAESEM_VS(REG_V27, REG_V1)
        VAESEM_VS(REG_V27, REG_V2)
        VAESEM_VS(REG_V27, REG_V3)
        VAESEM_VS(REG_V27, REG_V4)
        VAESEM_VS(REG_V27, REG_V5)
        VAESEM_VS(REG_V27, REG_V6)
        VAESEM_VS(REG_V27, REG_V7)
        VAESEM_VS(REG_V27, REG_V8)
        VAESEM_VS(REG_V27, REG_V9)
        VAESEM_VS(REG_V27, REG_V10)
        VAESEM_VS(REG_V27, REG_V11)
        VAESEF_VS(REG_V24, REG_V12)
        VAESEF_VS(REG_V25, REG_V12)
        VAESEF_VS(REG_V26, REG_V12)
        VAESEF_VS(REG_V27, REG_V12)
        VXOR_VV(REG_V28, REG_V24, REG_V28)
        VXOR_VV(REG_V29, REG_V25, REG_V29)
        VXOR_VV(REG_V30, REG_V26, REG_V30)
        VXOR_VV(REG_V31, REG_V27, REG_V31)
        /* Store output. */
        "mv         t0, %[out]\n\t"
        VS4R_V(REG_V28, REG_T0)
        "addi        %[in], %[in], 64\n\t"
        "addi        %[out], %[out], 64\n\t"
        /* Loop if more elements to process. */
        "addi       t4, t4, -1\n\t"
        "bnez       t4, L_aes_gcm_192_decrypt_x4_block_loop\n\t"
        "andi       %[sz], %[sz], 0x3f\n\t"

      "L_aes_gcm_192_decrypt_x4_blocks_done:\n\t"
        "srli       t2, %[sz], 4\n\t"
        "beqz       t2, L_aes_gcm_192_decrypt_blocks_done\n\t"

      "L_aes_gcm_192_decrypt_block_loop:\n\t"
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        VADD_VI(REG_V20, REG_V20, 1)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V17, REG_V15, REG_V20)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
#else
        VREV8(REG_V17, REG_V20)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
        VMV_V_V(REG_V27, REG_V16)
        VSLIDEUP_VI(REG_V27, REG_V17, 3)
#else
        "addi       t3, t3, 1\n\t"
        "slli       t0, t3, 32\n\t"
        REV8(REG_T0, REG_T0)
        VMV_V_X(REG_V17, REG_T0)
        VMV_V_V(REG_V27, REG_V16)
        VSLIDEUP_VI(REG_V27, REG_V17, 3)
#endif /* !WOLFSSL_RISCV_BASE_BIT_MANIPULATION */

        VAESZ_VS(REG_V27, REG_V0)
        VAESEM_VS(REG_V27, REG_V1)
        VAESEM_VS(REG_V27, REG_V2)
        VAESEM_VS(REG_V27, REG_V3)
        VAESEM_VS(REG_V27, REG_V4)
        VAESEM_VS(REG_V27, REG_V5)
        VAESEM_VS(REG_V27, REG_V6)
        VAESEM_VS(REG_V27, REG_V7)
        VAESEM_VS(REG_V27, REG_V8)
        VAESEM_VS(REG_V27, REG_V9)
        VAESEM_VS(REG_V27, REG_V10)
        VAESEM_VS(REG_V27, REG_V11)
        VAESEF_VS(REG_V27, REG_V12)

        /* Load input. */
        "mv         t0, %[in]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VGHSH_VV(REG_V18, REG_V17, REG_V19)
        VXOR_VV(REG_V27, REG_V27, REG_V17)
        /* Store output. */
        "mv         t0, %[out]\n\t"
        VS1R_V(REG_V27, REG_T0)

        "addi        %[in], %[in], 16\n\t"
        "addi        %[out], %[out], 16\n\t"
        /* Loop if more elements to process. */
        "addi       t2, t2, -1\n\t"
        "bnez       t2, L_aes_gcm_192_decrypt_block_loop\n\t"

      "L_aes_gcm_192_decrypt_blocks_done:\n\t"
        "andi       t2, %[sz], 0xf\n\t"
        "beqz       t2, L_aes_gcm_192_decrypt_done\n\t"

        VXOR_VV(REG_V17, REG_V17, REG_V17)
        "mv         t0, %[scratch]\n\t"
        VS1R_V(REG_V17, REG_T0)
        "mv         t1, t2\n\t"
      "L_aes_gcm_192_decrypt_load_byte:\n\t"
        "lb         t0, (%[in])\n\t"
        "sb         t0, (%[scratch])\n\t"
        "addi       %[in], %[in], 1\n\t"
        "addi       %[scratch], %[scratch], 1\n\t"
        "addi       t1, t1, -1\n\t"
        "bnez       t1, L_aes_gcm_192_decrypt_load_byte\n\t"
        "sub        %[scratch], %[scratch], t2\n\t"
        "mv         t0, %[scratch]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VGHSH_VV(REG_V18, REG_V17, REG_V19)

        /* Encrypt counter for partial block. */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        VADD_VI(REG_V20, REG_V20, 1)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V17, REG_V15, REG_V20)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
#else
        VREV8(REG_V17, REG_V20)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
        VMV_V_V(REG_V27, REG_V16)
        VSLIDEUP_VI(REG_V27, REG_V17, 3)
#else
        "addi       t3, t3, 1\n\t"
        "slli       t0, t3, 32\n\t"
        REV8(REG_T0, REG_T0)
        VMV_V_X(REG_V17, REG_T0)
        VMV_V_V(REG_V27, REG_V16)
        VSLIDEUP_VI(REG_V27, REG_V17, 3)
#endif /* !WOLFSSL_RISCV_BASE_BIT_MANIPULATION */

        VAESZ_VS(REG_V27, REG_V0)
        VAESEM_VS(REG_V27, REG_V1)
        VAESEM_VS(REG_V27, REG_V2)
        VAESEM_VS(REG_V27, REG_V3)
        VAESEM_VS(REG_V27, REG_V4)
        VAESEM_VS(REG_V27, REG_V5)
        VAESEM_VS(REG_V27, REG_V6)
        VAESEM_VS(REG_V27, REG_V7)
        VAESEM_VS(REG_V27, REG_V8)
        VAESEM_VS(REG_V27, REG_V9)
        VAESEM_VS(REG_V27, REG_V10)
        VAESEM_VS(REG_V27, REG_V11)
        VAESEF_VS(REG_V27, REG_V12)

        /* Load scratch. */
        "mv         t0, %[scratch]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VXOR_VV(REG_V27, REG_V27, REG_V17)
        /* Store scratch. */
        VS1R_V(REG_V27, REG_T0)
        "mv         t1, t2\n\t"
      "L_aes_gcm_192_decrypt_store_byte:\n\t"
        "lb         t0, (%[scratch])\n\t"
        "sb         t0, (%[out])\n\t"
        "addi       %[scratch], %[scratch], 1\n\t"
        "addi       %[out], %[out], 1\n\t"
        "addi       t1, t1, -1\n\t"
        "bnez       t1, L_aes_gcm_192_decrypt_store_byte\n\t"
        "sub        %[scratch], %[scratch], t2\n\t"

      "L_aes_gcm_192_decrypt_done:\n\t"

        /* Hash in the lengths of A and C in bits */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        /* aSz is only 32-bits */
        /* Multiply by 8 do get size in bits. */
        "slli       %[aSz], %[aSz], 3\n\t"
        "srli       t0, %[aSz], 32\n\t"
        "srli       t1, %[aSz], 24\n\t"
        "srli       t2, %[aSz], 16\n\t"
        "srli       t3, %[aSz], 8\n\t"
        /* Top 3 bytes are 0. */
        "sh         x0    , 0(%[scratch])\n\t"
        "sb         x0    , 2(%[scratch])\n\t"
        "sb         t0    , 3(%[scratch])\n\t"
        "sb         t1    , 4(%[scratch])\n\t"
        "sb         t2    , 5(%[scratch])\n\t"
        "sb         t3    , 6(%[scratch])\n\t"
        "sb         %[aSz], 7(%[scratch])\n\t"
        /* sz is only 32-bits */
        /* Multiply by 8 do get size in bits. */
        "slli       %[sz], %[sz], 3\n\t"
        "srli       t0, %[sz], 32\n\t"
        "srli       t1, %[sz], 24\n\t"
        "srli       t2, %[sz], 16\n\t"
        "srli       t3, %[sz], 8\n\t"
        /* Top 3 bytes are 0. */
        "sh         x0   ,  8(%[scratch])\n\t"
        "sb         x0   , 10(%[scratch])\n\t"
        "sb         t0   , 11(%[scratch])\n\t"
        "sb         t1   , 12(%[scratch])\n\t"
        "sb         t2   , 13(%[scratch])\n\t"
        "sb         t3   , 14(%[scratch])\n\t"
        "sb         %[sz], 15(%[scratch])\n\t"
#else
        "slli       t0, %[aSz], 3\n\t"
        REV8(REG_T0, REG_T0)
        "sd         t0, 0(%[scratch])\n\t"
        "slli       t0, %[sz], 3\n\t"
        REV8(REG_T0, REG_T0)
        "sd         t0, 8(%[scratch])\n\t"
#endif /* !WOLFSSL_RISCV_BASE_BIT_MANIPULATION */
        "mv         t0, %[scratch]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VGHSH_VV(REG_V18, REG_V17, REG_V19)

        VAESZ_VS(REG_V16, REG_V0)
        VAESEM_VS(REG_V16, REG_V1)
        VAESEM_VS(REG_V16, REG_V2)
        VAESEM_VS(REG_V16, REG_V3)
        VAESEM_VS(REG_V16, REG_V4)
        VAESEM_VS(REG_V16, REG_V5)
        VAESEM_VS(REG_V16, REG_V6)
        VAESEM_VS(REG_V16, REG_V7)
        VAESEM_VS(REG_V16, REG_V8)
        VAESEM_VS(REG_V16, REG_V9)
        VAESEM_VS(REG_V16, REG_V10)
        VAESEM_VS(REG_V16, REG_V11)
        VAESEF_VS(REG_V16, REG_V12)
        VXOR_VV(REG_V18, REG_V18, REG_V16)

        "li         t1, 16\n\t"
        "blt        %[tagSz], t1, L_aes_gcm_192_decrypt_tag_small\n\t"
        "mv         t0, %[tag]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VXOR_VV(REG_V19, REG_V19, REG_V19)
        VXOR_VV(REG_V18, REG_V18, REG_V17)
        VMSNE_VV(REG_V19, REG_V19, REG_V18)
        VCPOP_M(REG_T0, REG_V19)
        "beqz       x0, L_aes_gcm_192_decrypt_tag_done\n\t"
      "L_aes_gcm_192_decrypt_tag_small:\n\t"
        "mv         t0, %[scratch]\n\t"
        VS1R_V(REG_V18, REG_T0)
        "mv         t1, %[tagSz]\n\t"
        "xor        t0, t0, t0\n\t"
      "L_aes_gcm_192_decrypt_store_tag_byte:\n\t"
        "lb         t2, (%[scratch])\n\t"
        "lb         t3, (%[tag])\n\t"
        "xor        t0, t0, t2\n\t"
        "xor        t0, t0, t3\n\t"
        "addi       %[scratch], %[scratch], 1\n\t"
        "addi       %[tag], %[tag], 1\n\t"
        "addi       t1, t1, -1\n\t"
        "bnez       t1, L_aes_gcm_192_decrypt_store_tag_byte\n\t"
      "L_aes_gcm_192_decrypt_tag_done:\n\t"
        "negw       t0, t0\n\t"
        "sraiw      t0, t0, 31\n\t"
        "andi       %[ret], t0, -180\n\t"

        : [out] "+r" (out), [in] "+r" (in), [key] "+r" (key),
          [aSz] "+r" (aadSz), [aad] "+r" (aad), [ret] "+r" (ret),
          [sz] "+r" (sz)
        : [ctr] "r" (ctr), [scratch] "r" (scratch),
          [h] "r" (aes->gcm.H), [tag] "r" (tag), [tagSz] "r" (tagSz)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
          , [rev_idx] "r" (rev_idx)
#endif
        : "memory", "t0", "t1", "t2", "t3", "t4"
    );

#ifdef OPENSSL_EXTRA
    if ((tag != NULL) && (in != NULL) && (sz != 0)) {
        /* store AAD size for next call */
        aes->gcm.aadLen = aadSz;
    }
#endif

    return ret;
}
#endif /* WOLFSSL_AES_192 */

#ifdef WOLFSSL_AES_256
/* Decrypt data using AES-256-GCM.
 *
 * @param [in]  aes      AES object.
 * @param [out] out      Decrypted data.
 * @param [in]  in       Data to decrypt and GHASH.
 * @param [in]  sz       Number of bytes of data.
 * @param [in]  nonce    Nonce used to calculate first IV.
 * @param [in]  nonceSz  Length of nonce in bytes.
 * @param [out] tag      Authentication tag.
 * @param [in]  tagSz    Length of authentication tag in bytes.
 * @param [in]  aad      Additional Authentication Data (AAD).
 * @param [in]  aadSz    Length of AAD in bytes.
 * @return  0 on success.
 * @return  AES_GCM_AUTH_E when authentication tag computed doesn't match
 *          tag passed in.
 */
static int Aes256GcmDecrypt(Aes* aes, byte* out, const byte* in, word32 sz,
    const byte* nonce, word32 nonceSz, const byte* tag, word32 tagSz,
    const byte* aad, word32 aadSz)
{
    int ret = 0;
    byte counter[AES_BLOCK_SIZE];
    byte scratch[AES_BLOCK_SIZE];
    /* Noticed different optimization levels treated head of array different.
     * Some cases was stack pointer plus offset others was a register containing
     * address. To make uniform for passing in to inline assembly code am using
     * pointers to the head of each local array.
     */
    byte* ctr  = counter;
    byte* key = (byte*)aes->key;

    XMEMSET(counter, 0, AES_BLOCK_SIZE);
    if (nonceSz == GCM_NONCE_MID_SZ) {
        XMEMCPY(counter, nonce, GCM_NONCE_MID_SZ);
        counter[AES_BLOCK_SIZE - 1] = 1;
    }
    else {
#ifdef OPENSSL_EXTRA
        word32 aadTemp = aes->gcm.aadLen;
        aes->gcm.aadLen = 0;
#endif
        GHASH(&aes->gcm, NULL, 0, nonce, nonceSz, counter, AES_BLOCK_SIZE);
#ifdef OPENSSL_EXTRA
        aes->gcm.aadLen = aadTemp;
#endif
    }

    __asm__ __volatile__ (
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)

        /* X=0, get H */
        VXOR_VV(REG_V18, REG_V18, REG_V18)
        "mv         t0, %[h]\n\t"
        VL1RE32_V(REG_V19, REG_T0)

        /* Hash in AAD, the Additional Authentication Data */
        "beqz       %[aSz], L_aes_gcm_256_decrypt_ghash_aad_done\n\t"
        "beqz       %[aad], L_aes_gcm_256_decrypt_ghash_aad_done\n\t"

        "srli       t1, %[aSz], 4\n\t"
        "beqz       t1, L_aes_gcm_256_decrypt_ghash_aad_blocks_done\n\t"

      "L_aes_gcm_256_decrypt_ghash_aad_loop:\n\t"
        "mv         t0, %[aad]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VGHSH_VV(REG_V18, REG_V17, REG_V19)
        "addi       %[aad], %[aad], 16\n\t"
        "addi       t1, t1, -1\n\t"
        "bnez       t1, L_aes_gcm_256_decrypt_ghash_aad_loop\n\t"
      "L_aes_gcm_256_decrypt_ghash_aad_blocks_done:\n\t"
        "andi       t1, %[aSz], 0xf\n\t"
        "beqz       t1, L_aes_gcm_256_decrypt_ghash_aad_done\n\t"
        VXOR_VV(REG_V17, REG_V17, REG_V17)
        "mv         t0, %[scratch]\n\t"
        VS1R_V(REG_V17, REG_T0)
        "mv         t2, t1\n\t"
      "L_aes_gcm_256_decrypt_ghash_aad_load_byte:\n\t"
        "lb         t0, (%[aad])\n\t"
        "sb         t0, (%[scratch])\n\t"
        "addi       %[aad], %[aad], 1\n\t"
        "addi       %[scratch], %[scratch], 1\n\t"
        "addi       t2, t2, -1\n\t"
        "bnez       t2, L_aes_gcm_256_decrypt_ghash_aad_load_byte\n\t"
        "sub        %[scratch], %[scratch], t1\n\t"
        "mv         t0, %[scratch]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VGHSH_VV(REG_V18, REG_V17, REG_V19)
      "L_aes_gcm_256_decrypt_ghash_aad_done:\n\t"
        /* Done Hash in AAD */

#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        "mv         t0, %[rev_idx]\n\t"
        VL1RE32_V(REG_V15, REG_T0)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
        /* Load the counter. */
        "mv         t0, %[ctr]\n\t"
        VL1RE32_V(REG_V16, REG_T0)
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        VSLIDEDOWN_VI(REG_V20, REG_V16, 3)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V21, REG_V15, REG_V20)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
        VMV_V_V(REG_V20, REG_V21)
#else
        VREV8(REG_V20, REG_V20)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
#else
        "lw         t3, 12(%[ctr])\n\t"
        "slli       t3, t3, 32\n\t"
        REV8(REG_T3, REG_T3)
#endif /* !WOLFSSL_RISCV_BASE_BIT_MANIPULATION */

        /* Load key[0..7]. */
        "mv         t0, %[key]\n\t"
        VL8RE32_V(REG_V0, REG_T0)
        /* Load key[8..11]. */
        "addi       t0, t0, 128\n\t"
        VL4RE32_V(REG_V8, REG_T0)
        /* Load key[12..13]. */
        "addi       t0, t0, 64\n\t"
        VL2RE32_V(REG_V12, REG_T0)
        /* Load last round's key */
        "addi       t0, %[key], 224\n\t"
        VL1RE32_V(REG_V14, REG_T0)

        "beqz       %[sz], L_aes_gcm_256_decrypt_blocks_done\n\t"
        "srli       t4, %[sz], 6\n\t"
        "beqz       t4, L_aes_gcm_256_decrypt_x4_blocks_done\n\t"

        /* Calculate H^[1-4] - GMULT partials */
        VMV_V_V(REG_V21, REG_V19)
        VMV_V_V(REG_V22, REG_V19)
        /* Multiply H * H => H^2 */
        VGMUL_VV(REG_V21, REG_V19)
        VMV_V_V(REG_V23, REG_V21)
        /* Multiply H * H => H^3 */
        VGMUL_VV(REG_V22, REG_V21)
        /* Multiply H^2 * H^2 => H^4 */
        VGMUL_VV(REG_V23, REG_V21)

      "L_aes_gcm_256_decrypt_x4_block_loop:\n\t"
        /* Load input. */
        "mv        t0, %[in]\n\t"
        VL4RE32_V(REG_V28, REG_T0)
        VMVR_V(REG_V24, REG_V28, 4)
        VGMUL_VV(REG_V24, REG_V23)
        VGMUL_VV(REG_V25, REG_V22)
        VGMUL_VV(REG_V26, REG_V21)
        VGMUL_VV(REG_V27, REG_V19)
        VXOR_VV(REG_V18, REG_V18, REG_V24)
        VXOR_VV(REG_V18, REG_V18, REG_V25)
        VXOR_VV(REG_V18, REG_V18, REG_V26)
        VXOR_VV(REG_V18, REG_V18, REG_V27)
        /* Calculate next 4 counters (+1-4) */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        VADD_VI(REG_V20, REG_V20, 1)
        VMV_V_V(REG_V24, REG_V16)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V17, REG_V15, REG_V20)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
#else
        VREV8(REG_V17, REG_V20)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
        VSLIDEUP_VI(REG_V24, REG_V17, 3)
        VADD_VI(REG_V20, REG_V20, 1)
        VMV_V_V(REG_V25, REG_V16)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V17, REG_V15, REG_V20)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
#else
        VREV8(REG_V17, REG_V20)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
        VSLIDEUP_VI(REG_V25, REG_V17, 3)
        VADD_VI(REG_V20, REG_V20, 1)
        VMV_V_V(REG_V26, REG_V16)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V17, REG_V15, REG_V20)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
#else
        VREV8(REG_V17, REG_V20)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
        VSLIDEUP_VI(REG_V26, REG_V17, 3)
        VADD_VI(REG_V20, REG_V20, 1)
        VMV_V_V(REG_V27, REG_V16)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V17, REG_V15, REG_V20)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
#else
        VREV8(REG_V17, REG_V20)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
        VSLIDEUP_VI(REG_V27, REG_V17, 3)
#else
        "addi       t0, t3, 1\n\t"
        VMV_V_V(REG_V24, REG_V16)
        "addi       t1, t3, 2\n\t"
        VMV_V_V(REG_V25, REG_V16)
        "slli       t0, t0, 32\n\t"
        VMV_V_V(REG_V26, REG_V16)
        "slli       t1, t1, 32\n\t"
        VMV_V_V(REG_V27, REG_V16)
        REV8(REG_T0, REG_T0)
        REV8(REG_T1, REG_T1)
        VMV_V_X(REG_V20, REG_T0)
        "addi       t0, t3, 3\n\t"
        VSLIDEUP_VI(REG_V24, REG_V20, 3)
        "addi       t3, t3, 4\n\t"
        VMV_V_X(REG_V20, REG_T1)
        "slli       t0, t0, 32\n\t"
        VSLIDEUP_VI(REG_V25, REG_V20, 3)
        "slli       t1, t3, 32\n\t"
        REV8(REG_T0, REG_T0)
        REV8(REG_T1, REG_T1)
        VMV_V_X(REG_V20, REG_T0)
        VSLIDEUP_VI(REG_V26, REG_V20, 3)
        VMV_V_X(REG_V20, REG_T1)
        VSLIDEUP_VI(REG_V27, REG_V20, 3)
#endif /* !WOLFSSL_RISCV_BASE_BIT_MANIPULATION */

        VAESZ_VS(REG_V24, REG_V0)
        VAESZ_VS(REG_V25, REG_V0)
        VAESZ_VS(REG_V26, REG_V0)
        VAESZ_VS(REG_V27, REG_V0)
        VAESEM_VS(REG_V24, REG_V1)
        VAESEM_VS(REG_V24, REG_V2)
        VAESEM_VS(REG_V24, REG_V3)
        VAESEM_VS(REG_V24, REG_V4)
        VAESEM_VS(REG_V24, REG_V5)
        VAESEM_VS(REG_V24, REG_V6)
        VAESEM_VS(REG_V24, REG_V7)
        VAESEM_VS(REG_V24, REG_V8)
        VAESEM_VS(REG_V24, REG_V9)
        VAESEM_VS(REG_V24, REG_V10)
        VAESEM_VS(REG_V24, REG_V11)
        VAESEM_VS(REG_V24, REG_V12)
        VAESEM_VS(REG_V24, REG_V13)
        VAESEM_VS(REG_V25, REG_V1)
        VAESEM_VS(REG_V25, REG_V2)
        VAESEM_VS(REG_V25, REG_V3)
        VAESEM_VS(REG_V25, REG_V4)
        VAESEM_VS(REG_V25, REG_V5)
        VAESEM_VS(REG_V25, REG_V6)
        VAESEM_VS(REG_V25, REG_V7)
        VAESEM_VS(REG_V25, REG_V8)
        VAESEM_VS(REG_V25, REG_V9)
        VAESEM_VS(REG_V25, REG_V10)
        VAESEM_VS(REG_V25, REG_V11)
        VAESEM_VS(REG_V25, REG_V12)
        VAESEM_VS(REG_V25, REG_V13)
        VAESEM_VS(REG_V26, REG_V1)
        VAESEM_VS(REG_V26, REG_V2)
        VAESEM_VS(REG_V26, REG_V3)
        VAESEM_VS(REG_V26, REG_V4)
        VAESEM_VS(REG_V26, REG_V5)
        VAESEM_VS(REG_V26, REG_V6)
        VAESEM_VS(REG_V26, REG_V7)
        VAESEM_VS(REG_V26, REG_V8)
        VAESEM_VS(REG_V26, REG_V9)
        VAESEM_VS(REG_V26, REG_V10)
        VAESEM_VS(REG_V26, REG_V11)
        VAESEM_VS(REG_V26, REG_V12)
        VAESEM_VS(REG_V26, REG_V13)
        VAESEM_VS(REG_V27, REG_V1)
        VAESEM_VS(REG_V27, REG_V2)
        VAESEM_VS(REG_V27, REG_V3)
        VAESEM_VS(REG_V27, REG_V4)
        VAESEM_VS(REG_V27, REG_V5)
        VAESEM_VS(REG_V27, REG_V6)
        VAESEM_VS(REG_V27, REG_V7)
        VAESEM_VS(REG_V27, REG_V8)
        VAESEM_VS(REG_V27, REG_V9)
        VAESEM_VS(REG_V27, REG_V10)
        VAESEM_VS(REG_V27, REG_V11)
        VAESEM_VS(REG_V27, REG_V12)
        VAESEM_VS(REG_V27, REG_V13)
        VAESEF_VS(REG_V24, REG_V14)
        VAESEF_VS(REG_V25, REG_V14)
        VAESEF_VS(REG_V26, REG_V14)
        VAESEF_VS(REG_V27, REG_V14)
        VXOR_VV(REG_V28, REG_V24, REG_V28)
        VXOR_VV(REG_V29, REG_V25, REG_V29)
        VXOR_VV(REG_V30, REG_V26, REG_V30)
        VXOR_VV(REG_V31, REG_V27, REG_V31)
        /* Store output. */
        "mv         t0, %[out]\n\t"
        VS4R_V(REG_V28, REG_T0)
        "addi        %[in], %[in], 64\n\t"
        "addi        %[out], %[out], 64\n\t"
        /* Loop if more elements to process. */
        "addi       t4, t4, -1\n\t"
        "bnez       t4, L_aes_gcm_256_decrypt_x4_block_loop\n\t"
        "andi       %[sz], %[sz], 0x3f\n\t"

      "L_aes_gcm_256_decrypt_x4_blocks_done:\n\t"
        "srli       t2, %[sz], 4\n\t"
        "beqz       t2, L_aes_gcm_256_decrypt_blocks_done\n\t"

      "L_aes_gcm_256_decrypt_block_loop:\n\t"
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        VADD_VI(REG_V20, REG_V20, 1)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V17, REG_V15, REG_V20)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
#else
        VREV8(REG_V17, REG_V20)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
        VMV_V_V(REG_V27, REG_V16)
        VSLIDEUP_VI(REG_V27, REG_V17, 3)
#else
        "addi       t3, t3, 1\n\t"
        "slli       t0, t3, 32\n\t"
        REV8(REG_T0, REG_T0)
        VMV_V_X(REG_V17, REG_T0)
        VMV_V_V(REG_V27, REG_V16)
        VSLIDEUP_VI(REG_V27, REG_V17, 3)
#endif /* !WOLFSSL_RISCV_BASE_BIT_MANIPULATION */

        VAESZ_VS(REG_V27, REG_V0)
        VAESEM_VS(REG_V27, REG_V1)
        VAESEM_VS(REG_V27, REG_V2)
        VAESEM_VS(REG_V27, REG_V3)
        VAESEM_VS(REG_V27, REG_V4)
        VAESEM_VS(REG_V27, REG_V5)
        VAESEM_VS(REG_V27, REG_V6)
        VAESEM_VS(REG_V27, REG_V7)
        VAESEM_VS(REG_V27, REG_V8)
        VAESEM_VS(REG_V27, REG_V9)
        VAESEM_VS(REG_V27, REG_V10)
        VAESEM_VS(REG_V27, REG_V11)
        VAESEM_VS(REG_V27, REG_V12)
        VAESEM_VS(REG_V27, REG_V13)
        VAESEF_VS(REG_V27, REG_V14)

        /* Load input. */
        "mv         t0, %[in]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VGHSH_VV(REG_V18, REG_V17, REG_V19)
        VXOR_VV(REG_V27, REG_V27, REG_V17)
        /* Store output. */
        "mv         t0, %[out]\n\t"
        VS1R_V(REG_V27, REG_T0)

        "addi        %[in], %[in], 16\n\t"
        "addi        %[out], %[out], 16\n\t"
        /* Loop if more elements to process. */
        "addi       t2, t2, -1\n\t"
        "bnez       t2, L_aes_gcm_256_decrypt_block_loop\n\t"

      "L_aes_gcm_256_decrypt_blocks_done:\n\t"
        "andi       t2, %[sz], 0xf\n\t"
        "beqz       t2, L_aes_gcm_256_decrypt_done\n\t"

        VXOR_VV(REG_V17, REG_V17, REG_V17)
        "mv         t0, %[scratch]\n\t"
        VS1R_V(REG_V17, REG_T0)
        "mv         t1, t2\n\t"
      "L_aes_gcm_256_decrypt_load_byte:\n\t"
        "lb         t0, (%[in])\n\t"
        "sb         t0, (%[scratch])\n\t"
        "addi       %[in], %[in], 1\n\t"
        "addi       %[scratch], %[scratch], 1\n\t"
        "addi       t1, t1, -1\n\t"
        "bnez       t1, L_aes_gcm_256_decrypt_load_byte\n\t"
        "sub        %[scratch], %[scratch], t2\n\t"
        "mv         t0, %[scratch]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VGHSH_VV(REG_V18, REG_V17, REG_V19)

        /* Encrypt counter for partial block. */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        VADD_VI(REG_V20, REG_V20, 1)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        VSETIVLI(REG_X0, 16, 1, 1, 0b000, 0b000)
        VRGATHER_VV(REG_V17, REG_V15, REG_V20)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
#else
        VREV8(REG_V17, REG_V20)
#endif /* !WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
        VMV_V_V(REG_V27, REG_V16)
        VSLIDEUP_VI(REG_V27, REG_V17, 3)
#else
        "addi       t3, t3, 1\n\t"
        "slli       t0, t3, 32\n\t"
        REV8(REG_T0, REG_T0)
        VMV_V_X(REG_V17, REG_T0)
        VMV_V_V(REG_V27, REG_V16)
        VSLIDEUP_VI(REG_V27, REG_V17, 3)
#endif /* !WOLFSSL_RISCV_BASE_BIT_MANIPULATION */

        VAESZ_VS(REG_V27, REG_V0)
        VAESEM_VS(REG_V27, REG_V1)
        VAESEM_VS(REG_V27, REG_V2)
        VAESEM_VS(REG_V27, REG_V3)
        VAESEM_VS(REG_V27, REG_V4)
        VAESEM_VS(REG_V27, REG_V5)
        VAESEM_VS(REG_V27, REG_V6)
        VAESEM_VS(REG_V27, REG_V7)
        VAESEM_VS(REG_V27, REG_V8)
        VAESEM_VS(REG_V27, REG_V9)
        VAESEM_VS(REG_V27, REG_V10)
        VAESEM_VS(REG_V27, REG_V11)
        VAESEM_VS(REG_V27, REG_V12)
        VAESEM_VS(REG_V27, REG_V13)
        VAESEF_VS(REG_V27, REG_V14)

        /* Load scratch. */
        "mv         t0, %[scratch]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VXOR_VV(REG_V27, REG_V27, REG_V17)
        /* Store scratch. */
        VS1R_V(REG_V27, REG_T0)
        "mv         t1, t2\n\t"
      "L_aes_gcm_256_decrypt_store_byte:\n\t"
        "lb         t0, (%[scratch])\n\t"
        "sb         t0, (%[out])\n\t"
        "addi       %[scratch], %[scratch], 1\n\t"
        "addi       %[out], %[out], 1\n\t"
        "addi       t1, t1, -1\n\t"
        "bnez       t1, L_aes_gcm_256_decrypt_store_byte\n\t"
        "sub        %[scratch], %[scratch], t2\n\t"

      "L_aes_gcm_256_decrypt_done:\n\t"

        /* Hash in the lengths of A and C in bits */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        /* aSz is only 32-bits */
        /* Multiply by 8 do get size in bits. */
        "slli       %[aSz], %[aSz], 3\n\t"
        "srli       t0, %[aSz], 32\n\t"
        "srli       t1, %[aSz], 24\n\t"
        "srli       t2, %[aSz], 16\n\t"
        "srli       t3, %[aSz], 8\n\t"
        /* Top 3 bytes are 0. */
        "sh         x0    , 0(%[scratch])\n\t"
        "sb         x0    , 2(%[scratch])\n\t"
        "sb         t0    , 3(%[scratch])\n\t"
        "sb         t1    , 4(%[scratch])\n\t"
        "sb         t2    , 5(%[scratch])\n\t"
        "sb         t3    , 6(%[scratch])\n\t"
        "sb         %[aSz], 7(%[scratch])\n\t"
        /* sz is only 32-bits */
        /* Multiply by 8 do get size in bits. */
        "slli       %[sz], %[sz], 3\n\t"
        "srli       t0, %[sz], 32\n\t"
        "srli       t1, %[sz], 24\n\t"
        "srli       t2, %[sz], 16\n\t"
        "srli       t3, %[sz], 8\n\t"
        /* Top 3 bytes are 0. */
        "sh         x0   ,  8(%[scratch])\n\t"
        "sb         x0   , 10(%[scratch])\n\t"
        "sb         t0   , 11(%[scratch])\n\t"
        "sb         t1   , 12(%[scratch])\n\t"
        "sb         t2   , 13(%[scratch])\n\t"
        "sb         t3   , 14(%[scratch])\n\t"
        "sb         %[sz], 15(%[scratch])\n\t"
#else
        "slli       t0, %[aSz], 3\n\t"
        REV8(REG_T0, REG_T0)
        "sd         t0, 0(%[scratch])\n\t"
        "slli       t0, %[sz], 3\n\t"
        REV8(REG_T0, REG_T0)
        "sd         t0, 8(%[scratch])\n\t"
#endif /* !WOLFSSL_RISCV_BASE_BIT_MANIPULATION */
        "mv         t0, %[scratch]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VGHSH_VV(REG_V18, REG_V17, REG_V19)

        VAESZ_VS(REG_V16, REG_V0)
        VAESEM_VS(REG_V16, REG_V1)
        VAESEM_VS(REG_V16, REG_V2)
        VAESEM_VS(REG_V16, REG_V3)
        VAESEM_VS(REG_V16, REG_V4)
        VAESEM_VS(REG_V16, REG_V5)
        VAESEM_VS(REG_V16, REG_V6)
        VAESEM_VS(REG_V16, REG_V7)
        VAESEM_VS(REG_V16, REG_V8)
        VAESEM_VS(REG_V16, REG_V9)
        VAESEM_VS(REG_V16, REG_V10)
        VAESEM_VS(REG_V16, REG_V11)
        VAESEM_VS(REG_V16, REG_V12)
        VAESEM_VS(REG_V16, REG_V13)
        VAESEF_VS(REG_V16, REG_V14)
        VXOR_VV(REG_V18, REG_V18, REG_V16)

        "li         t1, 16\n\t"
        "blt        %[tagSz], t1, L_aes_gcm_256_decrypt_tag_small\n\t"
        "mv         t0, %[tag]\n\t"
        VL1RE32_V(REG_V17, REG_T0)
        VXOR_VV(REG_V19, REG_V19, REG_V19)
        VXOR_VV(REG_V18, REG_V18, REG_V17)
        VMSNE_VV(REG_V19, REG_V19, REG_V18)
        VCPOP_M(REG_T0, REG_V19)
        "beqz       x0, L_aes_gcm_256_decrypt_tag_done\n\t"
      "L_aes_gcm_256_decrypt_tag_small:\n\t"
        "mv         t0, %[scratch]\n\t"
        VS1R_V(REG_V18, REG_T0)
        "mv         t1, %[tagSz]\n\t"
        "xor        t0, t0, t0\n\t"
      "L_aes_gcm_256_decrypt_store_tag_byte:\n\t"
        "lb         t2, (%[scratch])\n\t"
        "lb         t3, (%[tag])\n\t"
        "xor        t0, t0, t2\n\t"
        "xor        t0, t0, t3\n\t"
        "addi       %[scratch], %[scratch], 1\n\t"
        "addi       %[tag], %[tag], 1\n\t"
        "addi       t1, t1, -1\n\t"
        "bnez       t1, L_aes_gcm_256_decrypt_store_tag_byte\n\t"
      "L_aes_gcm_256_decrypt_tag_done:\n\t"
        "negw       t0, t0\n\t"
        "sraiw      t0, t0, 31\n\t"
        "andi       %[ret], t0, -180\n\t"

        : [out] "+r" (out), [in] "+r" (in), [key] "+r" (key),
          [aSz] "+r" (aadSz), [aad] "+r" (aad), [ret] "+r" (ret),
          [sz] "+r" (sz)
        : [ctr] "r" (ctr), [scratch] "r" (scratch),
          [h] "r" (aes->gcm.H), [tag] "r" (tag), [tagSz] "r" (tagSz)
#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
          , [rev_idx] "r" (rev_idx)
#endif
        : "memory", "t0", "t1", "t2", "t3", "t4"
    );

#ifdef OPENSSL_EXTRA
    if ((tag != NULL) && (in != NULL) && (sz != 0)) {
        /* store AAD size for next call */
        aes->gcm.aadLen = aadSz;
    }
#endif

    return ret;
}
#endif /* WOLFSSL_AES_256 */

/* Decrypt data using AES-GCM.
 *
 * @param [in]  aes      AES object.
 * @param [out] out      Decrypted data.
 * @param [in]  in       Data to decrypt and GHASH.
 * @param [in]  sz       Number of bytes of data.
 * @param [in]  nonce    Nonce used to calculate first IV.
 * @param [in]  nonceSz  Length of nonce in bytes.
 * @param [out] tag      Authentication tag.
 * @param [in]  tagSz    Length of authentication tag in bytes.
 * @param [in]  aad      Additional Authentication Data (AAD).
 * @param [in]  aadSz    Length of AAD in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when aes, nonce or tag is NULL.
 * @return  BAD_FUNC_ARG when nonceSz is zero.
 * @return  BAD_FUNC_ARG when aad is NULL but aadSz is not zero.
 * @return  BAD_FUNC_ARG when tagSz is less than WOLFSSL_MIN_AUTH_TAG_SZ or
 *          greater than AES_BLOCK_SIZE.
 * @return  BAD_FUNC_ARG when sz is not zero but in or out is NULL.
 * @return  AES_GCM_AUTH_E when authentication tag computed doesn't match
 *          tag passed in.
 */
int wc_AesGcmDecrypt(Aes* aes, byte* out, const byte* in, word32 sz,
    const byte* nonce, word32 nonceSz, const byte* tag, word32 tagSz,
    const byte* aad, word32 aadSz)
{
    int ret = 0;

    /* sanity checks */
    if ((aes == NULL) || (nonce == NULL) || (tag == NULL) ||
            (tagSz > AES_BLOCK_SIZE) || (tagSz < WOLFSSL_MIN_AUTH_TAG_SZ) ||
            ((aad == NULL) && (aadSz > 0)) || (nonceSz == 0) ||
            ((sz != 0) && ((in == NULL) || (out == NULL)))) {
        WOLFSSL_MSG("a NULL parameter passed in when size is larger than 0");
        return BAD_FUNC_ARG;
    }

    if (ret == 0) {
        switch (aes->rounds) {
        #ifdef WOLFSSL_AES_128
            case 10:
                ret = Aes128GcmDecrypt(aes, out, in, sz, nonce, nonceSz, tag,
                    tagSz, aad, aadSz);
                break;
        #endif
        #ifdef WOLFSSL_AES_192
            case 12:
                ret = Aes192GcmDecrypt(aes, out, in, sz, nonce, nonceSz, tag,
                    tagSz, aad, aadSz);
                break;
        #endif
        #ifdef WOLFSSL_AES_256
            case 14:
                ret = Aes256GcmDecrypt(aes, out, in, sz, nonce, nonceSz, tag,
                    tagSz, aad, aadSz);
                break;
        #endif
            default:
                WOLFSSL_MSG("AES-GCM invalid round number");
                ret = BAD_FUNC_ARG;
        }
    }

    return ret;

}

#endif /* HAVE_AES_DECRYPT */

/* END script replace AES-GCM RISC-V 64 with hardware vector crypto */

#define HAVE_AES_GCM_ENC_DEC

#endif /* !WOLFSSL_RISCV_VECTOR_GCM */

#endif /* WOLFSSL_RISCV_VECTOR_CRYPTO_ASM */

/* Implement GHASH if we haven't already. */
#ifndef HAVE_GHASH
/* Remainder values. */
static const word16 R[32] = {
          0x0000,       0x201c,       0x4038,       0x6024,
          0x8070,       0xa06c,       0xc048,       0xe054,
          0x00e1,       0x20fd,       0x40d9,       0x60c5,
          0x8091,       0xa08d,       0xc0a9,       0xe0b5,

          0x0000,       0xc201,       0x8403,       0x4602,
          0x0807,       0xca06,       0x8c04,       0x4e05,
          0x100e,       0xd20f,       0x940d,       0x560c,
          0x1809,       0xda08,       0x9c0a,       0x5e0b,
};

/* GMULT, multiply in GF2, x and y into x.
 *
 * @param [in, out]  x  On in, value to GMULT.
 *                      On out, result of GMULT.
 * @param [in]       y  Value to GMULT.
 */
static WC_INLINE void GMULT(byte *x, byte m[32][AES_BLOCK_SIZE])
{
    int i;
    word64 z8[2] = {0, 0};
    byte a;
    word64* x8 = (word64*)x;
    word64* m8;
    word64 n0, n1, n2, n3;
    byte xi;

    for (i = 15; i > 0; i--) {
        xi = x[i];

        /* XOR in (msn * H) */
        m8 = (word64*)m[xi & 0xf];
        z8[0] ^= m8[0];
        z8[1] ^= m8[1];

        /* Cache top byte for remainder calculations - lost in rotate. */
        a = (byte)(z8[1] >> 56);

        /* Rotate Z by 8-bits */
        z8[1] = (z8[0] >> 56) | (z8[1] << 8);
        z8[0] <<= 8;

        /* XOR in (next significant nibble * H) [pre-rotated by 4 bits] */
        m8 = (word64*)m[16 + (xi >> 4)];
        z8[0] ^= m8[0];
        z8[1] ^= m8[1];

        /* XOR in (msn * remainder) [pre-rotated by 4 bits] */
        z8[0] ^= (word64)R[16 + (a & 0xf)];
        /* XOR in next significant nibble (XORed with H) * remainder */
        m8 = (word64*)m[xi >> 4];
        a ^= (byte)(m8[1] >> 52);
        z8[0] ^= (word64)R[a >> 4];
    }

    xi = x[0];

    /* XOR in most significant nibble * H */
    m8 = (word64*)m[xi & 0xf];
    z8[0] ^= m8[0];
    z8[1] ^= m8[1];

    /* Cache top byte for remainder calculations - lost in rotate. */
    a = (z8[1] >> 56) & 0xf;

    /* Rotate z by 4-bits */
    n3 = z8[1] & W64LIT(0xf0f0f0f0f0f0f0f0);
    n2 = z8[1] & W64LIT(0x0f0f0f0f0f0f0f0f);
    n1 = z8[0] & W64LIT(0xf0f0f0f0f0f0f0f0);
    n0 = z8[0] & W64LIT(0x0f0f0f0f0f0f0f0f);
    z8[1] = (n3 >> 4) | (n2 << 12) | (n0 >> 52);
    z8[0] = (n1 >> 4) | (n0 << 12);

    /* XOR in next significant nibble * H */
    m8 = (word64*)m[xi >> 4];
    z8[0] ^= m8[0];
    z8[1] ^= m8[1];
    /* XOR in most significant nibble * remainder */
    z8[0] ^= (word64)R[a];

    /* Write back result. */
    x8[0] = z8[0];
    x8[1] = z8[1];
}

/* GHASH Additional Authentication Data (AAD) and cipher text.
 *
 * @param [in]  gcm  GCM object.
 * @param [in]  a    Additional Authentication Data (AAD).
 * @param [in]  aSz  Size of AAD in bytes.
 * @param [in]  c    Cipher text.
 * @param [in]  cSz  Size of cipher text in bytes.
 * @param [out] s    Hash result.
 * @param [in]  sSz  Number of bytes to put into hash result.
 */
void GHASH(Gcm* gcm, const byte* a, word32 aSz, const byte* c, word32 cSz,
    byte* s, word32 sSz)
{
    if (gcm != NULL) {
        byte x[AES_BLOCK_SIZE];
        byte scratch[AES_BLOCK_SIZE];
        word32 blocks, partial;

        XMEMSET(x, 0, AES_BLOCK_SIZE);

        /* Hash in A, the Additional Authentication Data */
        if (aSz != 0 && a != NULL) {
            blocks = aSz / AES_BLOCK_SIZE;
            partial = aSz % AES_BLOCK_SIZE;
            while (blocks--) {
                xorbuf16(x, a);
                GMULT(x, gcm->M0);
                a += AES_BLOCK_SIZE;
            }
            if (partial != 0) {
                XMEMSET(scratch, 0, AES_BLOCK_SIZE);
                XMEMCPY(scratch, a, partial);
                xorbuf16(x, scratch);
                GMULT(x, gcm->M0);
            }
        }

        /* Hash in C, the Ciphertext */
        if (cSz != 0 && c != NULL) {
            blocks = cSz / AES_BLOCK_SIZE;
            partial = cSz % AES_BLOCK_SIZE;
            while (blocks--) {
                xorbuf16(x, c);
                GMULT(x, gcm->M0);
                c += AES_BLOCK_SIZE;
            }
            if (partial != 0) {
                XMEMSET(scratch, 0, AES_BLOCK_SIZE);
                XMEMCPY(scratch, c, partial);
                xorbuf16(x, scratch);
                GMULT(x, gcm->M0);
            }
        }

        /* Hash in the lengths of A and C in bits */
        FlattenSzInBits(&scratch[0], aSz);
        FlattenSzInBits(&scratch[8], cSz);
        xorbuf16(x, scratch);
        GMULT(x, gcm->M0);

        /* Copy the result into s. */
        XMEMCPY(s, x, sSz);
    }
}
#endif /* !HAVE_GHASH */

#ifndef HAVE_AES_GCM_ENC_DEC
/* Increment AES-GCM counter.
 *
 * Big-endian byte ordering.
 *
 * @param [in, out] inOutCtr  Counter value to be incremented.
 */
static WC_INLINE void IncrementGcmCounter(byte* inOutCtr)
{
    int i;

    /* Big-endian aray - start at last element and move back. */
    for (i = AES_BLOCK_SIZE - 1; i >= AES_BLOCK_SIZE - CTR_SZ; i--) {
        /* Result not zero means no carry. */
        if ((++inOutCtr[i]) != 0) {
            return;
        }
    }
}

/* Encrypt data using AES-GCM.
 *
 * @param [in]  aes      AES object.
 * @param [out] out      Encrypted data.
 * @param [in]  in       Data to encrypt.
 * @param [in]  sz       Number of bytes of data.
 * @param [in]  nonce    Nonce used to calculate first IV.
 * @param [in]  nonceSz  Length of nonce in bytes.
 * @param [out] tag      Authentication tag.
 * @param [in]  tagSz    Length of authentication tag in bytes.
 * @param [in]  aad      Additional Authentication Data (AAD).
 * @param [in]  aadSz    Length of AAD in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when aes, nonce or tag is NULL.
 * @return  BAD_FUNC_ARG when nonceSz is zero.
 * @return  BAD_FUNC_ARG when aad is NULL but aadSz is not zero.
 * @return  BAD_FUNC_ARG when tagSz is less than WOLFSSL_MIN_AUTH_TAG_SZ or
 *          greater than AES_BLOCK_SIZE.
 * @return  BAD_FUNC_ARG when sz is not zero but in or out is NULL.
 */
int wc_AesGcmEncrypt(Aes* aes, byte* out, const byte* in, word32 sz,
    const byte* nonce, word32 nonceSz, byte* tag, word32 tagSz,
    const byte* aad, word32 aadSz)
{
    int ret = 0;
    word32 blocks = sz / AES_BLOCK_SIZE;
    word32 partial = sz % AES_BLOCK_SIZE;
    const byte* p = in;
    byte* c = out;
    ALIGN16 byte counter[AES_BLOCK_SIZE];
    ALIGN16 byte initialCounter[AES_BLOCK_SIZE];
    ALIGN16 byte scratch[AES_BLOCK_SIZE];

    /* Validate parameters. */
    if ((aes == NULL) || (nonce == NULL) || (nonceSz == 0) || (tag == NULL) ||
            ((aad == NULL) && (aadSz > 0)) || ((sz != 0) && ((in == NULL) ||
            (out == NULL)))) {
        WOLFSSL_MSG("a NULL parameter passed in when size is larger than 0");
        ret = BAD_FUNC_ARG;
    }

    if ((ret == 0) && ((tagSz < WOLFSSL_MIN_AUTH_TAG_SZ) ||
            (tagSz > AES_BLOCK_SIZE))) {
        WOLFSSL_MSG("GcmEncrypt tagSz error");
        ret = BAD_FUNC_ARG;
    }


    if (ret == 0) {
        if (nonceSz == GCM_NONCE_MID_SZ) {
            /* Counter is IV with bottom 4 bytes set to: 0x00,0x00,0x00,0x01. */
            XMEMCPY(counter, nonce, nonceSz);
            XMEMSET(counter + GCM_NONCE_MID_SZ, 0,
                AES_BLOCK_SIZE - GCM_NONCE_MID_SZ - 1);
            counter[AES_BLOCK_SIZE - 1] = 1;
        }
        else {
            /* Counter is GHASH of IV. */
        #ifdef OPENSSL_EXTRA
            word32 aadTemp = aes->gcm.aadLen;
            aes->gcm.aadLen = 0;
        #endif
            GHASH(&aes->gcm, NULL, 0, nonce, nonceSz, counter, AES_BLOCK_SIZE);
        #ifdef OPENSSL_EXTRA
            aes->gcm.aadLen = aadTemp;
        #endif
        }
        memcpy16(initialCounter, counter);

        while (blocks--) {
            IncrementGcmCounter(counter);
            wc_AesEncrypt(aes, counter, scratch);
            xorbufout16(c, scratch, p);
            p += AES_BLOCK_SIZE;
            c += AES_BLOCK_SIZE;
        }

        if (partial != 0) {
            IncrementGcmCounter(counter);
            wc_AesEncrypt(aes, counter, scratch);
            xorbufout(c, scratch, p, partial);
        }
        if (tag) {
            GHASH(&aes->gcm, aad, aadSz, out, sz, tag, tagSz);
            wc_AesEncrypt(aes, initialCounter, scratch);
            xorbuf(tag, scratch, tagSz);
        #ifdef OPENSSL_EXTRA
            if (!in && !sz)
                /* store AAD size for next call */
                aes->gcm.aadLen = aadSz;
        #endif
        }
    }

    return ret;
}

#ifdef HAVE_AES_DECRYPT
/* Decrypt data using AES-GCM.
 *
 * @param [in]  aes      AES object.
 * @param [out] out      Decrypted data.
 * @param [in]  in       Data to decrypt and GHASH.
 * @param [in]  sz       Number of bytes of data.
 * @param [in]  nonce    Nonce used to calculate first IV.
 * @param [in]  nonceSz  Length of nonce in bytes.
 * @param [out] tag      Authentication tag.
 * @param [in]  tagSz    Length of authentication tag in bytes.
 * @param [in]  aad      Additional Authentication Data (AAD).
 * @param [in]  aadSz    Length of AAD in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when aes, nonce or tag is NULL.
 * @return  BAD_FUNC_ARG when nonceSz is zero.
 * @return  BAD_FUNC_ARG when aad is NULL but aadSz is not zero.
 * @return  BAD_FUNC_ARG when tagSz is less than WOLFSSL_MIN_AUTH_TAG_SZ or
 *          greater than AES_BLOCK_SIZE.
 * @return  BAD_FUNC_ARG when sz is not zero but in or out is NULL.
 * @return  AES_GCM_AUTH_E when authentication tag computed doesn't match
 *          tag passed in.
 */
int wc_AesGcmDecrypt(Aes* aes, byte* out, const byte* in, word32 sz,
    const byte* nonce, word32 nonceSz, const byte* tag, word32 tagSz,
    const byte* aad, word32 aadSz)
{
    int ret = 0;
    word32 blocks = sz / AES_BLOCK_SIZE;
    word32 partial = sz % AES_BLOCK_SIZE;
    const byte* c = in;
    byte* p = out;
    ALIGN16 byte counter[AES_BLOCK_SIZE];
    ALIGN16 byte scratch[AES_BLOCK_SIZE];
    ALIGN16 byte Tprime[AES_BLOCK_SIZE];
    ALIGN16 byte EKY0[AES_BLOCK_SIZE];
    sword32 res;

    /* Validate parameters. */
    if ((aes == NULL) || (nonce == NULL) || (tag == NULL) ||
            (tagSz > AES_BLOCK_SIZE) || (tagSz < WOLFSSL_MIN_AUTH_TAG_SZ) ||
            ((aad == NULL) && (aadSz > 0)) || (nonceSz == 0) ||
            ((sz != 0) && ((in == NULL) || (out == NULL)))) {
        WOLFSSL_MSG("a NULL parameter passed in when size is larger than 0");
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        if (nonceSz == GCM_NONCE_MID_SZ) {
            /* Counter is IV with bottom 4 bytes set to: 0x00,0x00,0x00,0x01. */
            XMEMCPY(counter, nonce, nonceSz);
            XMEMSET(counter + GCM_NONCE_MID_SZ, 0,
                AES_BLOCK_SIZE - GCM_NONCE_MID_SZ - 1);
            counter[AES_BLOCK_SIZE - 1] = 1;
        }
        else {
            /* Counter is GHASH of IV. */
        #ifdef OPENSSL_EXTRA
            word32 aadTemp = aes->gcm.aadLen;
            aes->gcm.aadLen = 0;
        #endif
            GHASH(&aes->gcm, NULL, 0, nonce, nonceSz, counter, AES_BLOCK_SIZE);
        #ifdef OPENSSL_EXTRA
            aes->gcm.aadLen = aadTemp;
        #endif
        }

        /* Calc the tag again using received auth data and the cipher text */
        GHASH(&aes->gcm, aad, aadSz, in, sz, Tprime, sizeof(Tprime));
        wc_AesEncrypt(aes, counter, EKY0);
        xorbuf(Tprime, EKY0, sizeof(Tprime));
    #ifdef WC_AES_GCM_DEC_AUTH_EARLY
        /* ConstantCompare returns the cumulative bitwise or of the bitwise xor
         * of the pairwise bytes in the strings.
         */
        res = ConstantCompare(tag, Tprime, tagSz);
        /* convert positive retval from ConstantCompare() to all-1s word, in
         * constant time.
         */
        res = 0 - (sword32)(((word32)(0 - res)) >> 31U);
        ret = res & AES_GCM_AUTH_E;
    }
    if (ret == 0) {
    #endif

    #ifdef OPENSSL_EXTRA
        if (!out) {
            /* authenticated, non-confidential data */
            /* store AAD size for next call */
            aes->gcm.aadLen = aadSz;
        }
    #endif

        while (blocks--) {
            IncrementGcmCounter(counter);
            wc_AesEncrypt(aes, counter, scratch);
            xorbufout16(p, scratch, c);
            p += AES_BLOCK_SIZE;
            c += AES_BLOCK_SIZE;
        }

        if (partial != 0) {
            IncrementGcmCounter(counter);
            wc_AesEncrypt(aes, counter, scratch);
            xorbuf(scratch, c, partial);
            XMEMCPY(p, scratch, partial);
        }

    #ifndef WC_AES_GCM_DEC_AUTH_EARLY
        /* ConstantCompare returns the cumulative bitwise or of the bitwise xor
         * of the pairwise bytes in the strings.
         */
        res = ConstantCompare(tag, Tprime, (int)tagSz);
        /* convert positive retval from ConstantCompare() to all-1s word, in
         * constant time.
         */
        res = 0 - (sword32)(((word32)(0 - res)) >> 31U);
        /* now use res as a mask for constant time return of ret, unless tag
         * mismatch, whereupon AES_GCM_AUTH_E is returned.
         */
        ret = (ret & ~res) | (res & AES_GCM_AUTH_E);
    #endif
    }

    return ret;
}
#endif /* HAVE_AES_DECRYPT */
#endif /* !HAVE_AES_GCM_ENC_DEC */

#endif /* HAVE_AESGCM */

#ifdef HAVE_AESCCM

static void roll_x(Aes* aes, const byte* in, word32 inSz, byte* out)
{
    /* process the bulk of the data */
    while (inSz >= AES_BLOCK_SIZE) {
        xorbuf16(out, in);
        in += AES_BLOCK_SIZE;
        inSz -= AES_BLOCK_SIZE;

        wc_AesEncrypt(aes, out, out);
    }

    /* process remainder of the data */
    if (inSz > 0) {
        xorbuf(out, in, inSz);
        wc_AesEncrypt(aes, out, out);
    }
}


static void roll_auth(Aes* aes, const byte* in, word32 inSz, byte* out)
{
    word32 authLenSz;
    word32 remainder;

    /* encode the length in */
    if (inSz <= 0xFEFF) {
        authLenSz = 2;
        out[0] ^= ((inSz & 0xFF00) >> 8);
        out[1] ^=  (inSz & 0x00FF);
    }
    else {
        authLenSz = 6;
        out[0] ^= 0xFF; out[1] ^= 0xFE;
        out[2] ^= ((inSz & 0xFF000000) >> 24);
        out[3] ^= ((inSz & 0x00FF0000) >> 16);
        out[4] ^= ((inSz & 0x0000FF00) >>  8);
        out[5] ^=  (inSz & 0x000000FF);
    }
    /* Note, the protocol handles auth data up to 2^64, but we are
     * using 32-bit sizes right now, so the bigger data isn't handled.
     */

    /* start fill out the rest of the first block */
    remainder = AES_BLOCK_SIZE - authLenSz;
    if (inSz >= remainder) {
        /* plenty of bulk data to fill the remainder of this block */
        xorbuf(out + authLenSz, in, remainder);
        inSz -= remainder;
        in += remainder;
    }
    else {
        /* not enough bulk data, copy what is available, and pad zero */
        xorbuf(out + authLenSz, in, inSz);
        inSz = 0;
    }
    wc_AesEncrypt(aes, out, out);

    if (inSz > 0)
        roll_x(aes, in, inSz, out);
}


static WC_INLINE void AesCcmCtrInc(byte* B, word32 lenSz)
{
    word32 i;

    for (i = 0; i < lenSz; i++) {
        if (++B[AES_BLOCK_SIZE - 1 - i] != 0) return;
    }
}

/* return 0 on success */
int wc_AesCcmEncrypt(Aes* aes, byte* out, const byte* in, word32 inSz,
                   const byte* nonce, word32 nonceSz,
                   byte* authTag, word32 authTagSz,
                   const byte* authIn, word32 authInSz)
{
    int ret = 0;

    /* sanity check on arguments */
    if ((aes == NULL) || ((inSz != 0) && ((in == NULL) || (out == NULL))) ||
            (nonce == NULL) || (authTag == NULL) || (nonceSz < 7) ||
            (nonceSz > 13)) {
        ret = BAD_FUNC_ARG;
    }

    if ((ret == 0) && (wc_AesCcmCheckTagSize(authTagSz) != 0)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        byte A[AES_BLOCK_SIZE];
        byte B[AES_BLOCK_SIZE];
        byte lenSz;
        byte i;

        XMEMCPY(B+1, nonce, nonceSz);
        lenSz = AES_BLOCK_SIZE - 1 - (byte)nonceSz;
        B[0] = (authInSz > 0 ? 64 : 0)
             + (8 * (((byte)authTagSz - 2) / 2))
             + (lenSz - 1);
        for (i = 0; (i < lenSz) && (i < (byte)sizeof(word32)); i++) {
            B[AES_BLOCK_SIZE - 1 - i] = inSz >> (8 * i);
        }
        for (; i < lenSz; i++) {
            B[AES_BLOCK_SIZE - 1 - i] = 0;
        }

        wc_AesEncrypt(aes, B, A);

        if (authInSz > 0) {
            roll_auth(aes, authIn, authInSz, A);
        }
        if (inSz > 0) {
            roll_x(aes, in, inSz, A);
        }
        XMEMCPY(authTag, A, authTagSz);

        B[0] = lenSz - 1;
        for (i = 0; i < lenSz; i++) {
            B[AES_BLOCK_SIZE - 1 - i] = 0;
        }
        wc_AesEncrypt(aes, B, A);
        xorbuf(authTag, A, authTagSz);

        B[15] = 1;
        while (inSz >= AES_BLOCK_SIZE) {
            wc_AesEncrypt(aes, B, A);
            xorbuf16(A, in);
            memcpy16(out, A);

            AesCcmCtrInc(B, lenSz);
            inSz -= AES_BLOCK_SIZE;
            in += AES_BLOCK_SIZE;
            out += AES_BLOCK_SIZE;
        }
        if (inSz > 0) {
            wc_AesEncrypt(aes, B, A);
            xorbuf(A, in, inSz);
            XMEMCPY(out, A, inSz);
        }

        ForceZero(A, AES_BLOCK_SIZE);
        ForceZero(B, AES_BLOCK_SIZE);
    }

    return ret;
}

#ifdef HAVE_AES_DECRYPT
int  wc_AesCcmDecrypt(Aes* aes, byte* out, const byte* in, word32 inSz,
                   const byte* nonce, word32 nonceSz,
                   const byte* authTag, word32 authTagSz,
                   const byte* authIn, word32 authInSz)
{
    int ret = 0;

    /* sanity check on arguments */
    if ((aes == NULL) || ((inSz != 0) && ((in == NULL) || (out == NULL))) ||
            (nonce == NULL) || (authTag == NULL) || (nonceSz < 7) ||
            (nonceSz > 13)) {
        ret = BAD_FUNC_ARG;
    }

    if ((ret == 0) && (wc_AesCcmCheckTagSize(authTagSz) != 0)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        byte A[AES_BLOCK_SIZE];
        byte B[AES_BLOCK_SIZE];
        byte lenSz;
        byte i;
        byte* o = out;
        word32 oSz = inSz;

        XMEMCPY(B+1, nonce, nonceSz);
        lenSz = AES_BLOCK_SIZE - 1 - (byte)nonceSz;

        B[0] = lenSz - 1;
        for (i = 0; i < lenSz; i++) {
            B[AES_BLOCK_SIZE - 1 - i] = 0;
        }
        B[15] = 1;

        while (oSz >= AES_BLOCK_SIZE) {
            wc_AesEncrypt(aes, B, A);
            xorbuf16(A, in);
            memcpy16(o, A);

            AesCcmCtrInc(B, lenSz);
            oSz -= AES_BLOCK_SIZE;
            in += AES_BLOCK_SIZE;
            o += AES_BLOCK_SIZE;
        }
        if (inSz > 0) {
            wc_AesEncrypt(aes, B, A);
            xorbuf(A, in, oSz);
            XMEMCPY(o, A, oSz);
        }

        for (i = 0; i < lenSz; i++) {
            B[AES_BLOCK_SIZE - 1 - i] = 0;
        }
        wc_AesEncrypt(aes, B, A);

        B[0] = (authInSz > 0 ? 64 : 0)
             + (8 * (((byte)authTagSz - 2) / 2))
             + (lenSz - 1);
        for (i = 0; (i < lenSz) && (i < (byte)sizeof(word32)); i++) {
            B[AES_BLOCK_SIZE - 1 - i] = inSz >> (8 * i);
        }
        for (; i < lenSz; i++) {
            B[AES_BLOCK_SIZE - 1 - i] = 0;
        }

        wc_AesEncrypt(aes, B, A);

        if (authInSz > 0) {
            roll_auth(aes, authIn, authInSz, A);
        }
        if (inSz > 0) {
            roll_x(aes, out, inSz, A);
        }

        B[0] = lenSz - 1;
        for (i = 0; i < lenSz; i++) {
            B[AES_BLOCK_SIZE - 1 - i] = 0;
        }
        wc_AesEncrypt(aes, B, B);
        xorbuf(A, B, authTagSz);

        if (ConstantCompare(A, authTag, authTagSz) != 0) {
            /* If the authTag check fails, don't keep the decrypted data.
             * Unfortunately, you need the decrypted data to calculate the
             * check value. */
            XMEMSET(out, 0, inSz);
            ret = AES_CCM_AUTH_E;
        }

        ForceZero(A, AES_BLOCK_SIZE);
        ForceZero(B, AES_BLOCK_SIZE);
        o = NULL;
    }

    return ret;
}
#endif /* HAVE_AES_DECRYPT */
#endif /* HAVE_AESCCM */

#endif /* WOLFSSL_RISCV_ASM */

#endif /* !NO_AES */

