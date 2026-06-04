/* riscv-64-asm.h
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

#ifndef WOLF_CRYPT_RISCV_64_ASM_H
#define WOLF_CRYPT_RISCV_64_ASM_H

#ifdef WOLFSSL_RISCV_ASM

#define ASM_WORD(i) \
    ".word    " #i "\n\t"


#define REG_X0      0
#define REG_X1      1
#define REG_X2      2
#define REG_X3      3
#define REG_X4      4
#define REG_X5      5
#define REG_X6      6
#define REG_X7      7
#define REG_X8      8
#define REG_X9      9
#define REG_X10     10
#define REG_X11     11
#define REG_X12     12
#define REG_X13     13
#define REG_X14     14
#define REG_X15     15
#define REG_X16     16
#define REG_X17     17
#define REG_X18     18
#define REG_X19     19
#define REG_X20     20
#define REG_X21     21
#define REG_X22     22
#define REG_X23     23
#define REG_X24     24
#define REG_X25     25
#define REG_X26     26
#define REG_X27     27
#define REG_X28     28
#define REG_X29     29
#define REG_X30     30
#define REG_X31     31

#define REG_ZERO    REG_X0
#define REG_RA      REG_X1
#define REG_SP      REG_X2
#define REG_GP      REG_X3
#define REG_TP      REG_X4
#define REG_T0      REG_X5
#define REG_T1      REG_X6
#define REG_T2      REG_X7
#define REG_S0      REG_X8
#define REG_FP      REG_X8
#define REG_S1      REG_X9
#define REG_A0      REG_X10
#define REG_A1      REG_X11
#define REG_A2      REG_X12
#define REG_A3      REG_X13
#define REG_A4      REG_X14
#define REG_A5      REG_X15
#define REG_A6      REG_X16
#define REG_A7      REG_X17
#define REG_S2      REG_X18
#define REG_S3      REG_X19
#define REG_S4      REG_X20
#define REG_S5      REG_X21
#define REG_S6      REG_X22
#define REG_S7      REG_X23
#define REG_S8      REG_X24
#define REG_S9      REG_X25
#define REG_S10     REG_X26
#define REG_S11     REG_X27
#define REG_T3      REG_X28
#define REG_T4      REG_X29
#define REG_T5      REG_X30
#define REG_T6      REG_X31

#define REG_V0      0
#define REG_V1      1
#define REG_V2      2
#define REG_V3      3
#define REG_V4      4
#define REG_V5      5
#define REG_V6      6
#define REG_V7      7
#define REG_V8      8
#define REG_V9      9
#define REG_V10     10
#define REG_V11     11
#define REG_V12     12
#define REG_V13     13
#define REG_V14     14
#define REG_V15     15
#define REG_V16     16
#define REG_V17     17
#define REG_V18     18
#define REG_V19     19
#define REG_V20     20
#define REG_V21     21
#define REG_V22     22
#define REG_V23     23
#define REG_V24     24
#define REG_V25     25
#define REG_V26     26
#define REG_V27     27
#define REG_V28     28
#define REG_V29     29
#define REG_V30     30
#define REG_V31     31


#ifdef WOLFSSL_RISCV_BASE_BIT_MANIPULATION

/* Reverse bytes in 64-bit register. */
#define REV8(rd, rs)                                        \
    ASM_WORD((0b011010111000 << 20) | (0b101 << 12) |       \
             (0b0010011 << 0) |                             \
             (rs << 15) | (rd << 7))

/* Rotate right 32-bit register 5-bit value. */
#define RORIW(rd, rs, imm)                                  \
    ASM_WORD((0b0110000 << 25) | (0b101 << 12) |            \
             (0b0011011 << 0) |                             \
             (imm << 20) | (rs << 15) | (rd << 7))

/* Rotate right 64-bit register 7-bit value. */
#define RORI(rd, rs, imm)                                   \
    ASM_WORD((0b01100 << 27) | (0b101 << 12) |              \
             (0b0010011 << 0) |                             \
             ((imm) << 20) | ((rs) << 15) | ((rd) << 7))

/* rs1 and not rs2 into rd. */
#define ANDN(rd, rs1, rs2)                                  \
    ASM_WORD((0b0100000 << 25) | (0b111 << 12) |            \
             (0b0110011 << 0) |                             \
             ((rs2) << 20) | ((rs1) << 15) | ((rd) << 7))


/* rd = rs1[0..31] | rs2[0..31]. */
#define PACK(rd, rs1, rs2)                                     \
    ASM_WORD((0b0000100 << 25) | (0b100 << 12) | 0b0110011 |   \
             (rs2 << 20) | (rs1 << 15) | (rd << 7))

#endif /* WOLFSSL_RISCV_BASE_BIT_MANIPULATION */

#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY

/* rd = (rs1|rs3 >> imm)[0..63] */
#define FSRI(rd, rs1, rs3, imm)                                     \
    ASM_WORD((0b1 << 26) | (0b101 << 12) | (0b0110011 << 0) |       \
             (rs3 << 27) | (imm << 20) | (rs1 << 15) | (rd << 7))

#endif

/*
 * Load and store
 */

/* 64-bit width when loading. */
#define WIDTH_64  0b111
/* 32-bit width when loading. */
#define WIDTH_32  0b110

/*
 * Scalar load/store helpers.
 *
 * Each macro performs the same operation as the ld/lwu/lw/lh/sd/sw/sh
 * instruction it is named after. By default it expands to that native
 * instruction. When built with WOLFSSL_RISCV_ASM_NO_UNALIGNED - for cores that
 * don't support misaligned access - it checks the effective address alignment
 * at run time and dispatches to the widest supported sequence: word-wise
 * (lwu/sw) when 4-byte aligned, half-wise (lhu/sh) when 2-byte aligned,
 * otherwise byte-wise (lbu/sb). The narrower _BY_BYTE / _BY_HALF / _BY_WORD
 * forms are also exposed for sites that already know the alignment. Values
 * are little-endian, matching the native instructions either way.
 *
 * Bulk variants UNALIGNED_<LD|SD|LWU|LW|SW><N> (N = 2, 4, 8) issue N
 * consecutive accesses starting at o(p) - stride 8 bytes for LD/SD, 4 bytes
 * for LWU/LW/SW. Under WOLFSSL_RISCV_ASM_NO_UNALIGNED they share a single
 * alignment check across all N elements; otherwise they are just N native
 * instructions back-to-back.
 *
 *   r = data register: destination (loads) or source (stores)
 *   o = constant byte offset
 *   p = base address register
 *   t = scratch register - must differ from r and p; clobbered. For stores the
 *       data register r is preserved. Only used when
 *       WOLFSSL_RISCV_ASM_NO_UNALIGNED is defined; ignored otherwise.
 */

/* Apply X to N doublewords at 8-byte stride starting at o(p). */
#define UNALIGNED_DW_REP2(X, r0, r1, o, p, t)                           \
    X(r0, o,    p, t)                                                   \
    X(r1, o+8,  p, t)
#define UNALIGNED_DW_REP4(X, r0, r1, r2, r3, o, p, t)                   \
    X(r0, o,    p, t)                                                   \
    X(r1, o+8,  p, t)                                                   \
    X(r2, o+16, p, t)                                                   \
    X(r3, o+24, p, t)
#define UNALIGNED_DW_REP8(X, r0, r1, r2, r3, r4, r5, r6, r7, o, p, t)   \
    X(r0, o,    p, t)                                                   \
    X(r1, o+8,  p, t)                                                   \
    X(r2, o+16, p, t)                                                   \
    X(r3, o+24, p, t)                                                   \
    X(r4, o+32, p, t)                                                   \
    X(r5, o+40, p, t)                                                   \
    X(r6, o+48, p, t)                                                   \
    X(r7, o+56, p, t)

/* Apply X to N words at 4-byte stride starting at o(p). */
#define UNALIGNED_W_REP2(X, r0, r1, o, p, t)                            \
    X(r0, o,    p, t)                                                   \
    X(r1, o+4,  p, t)
#define UNALIGNED_W_REP4(X, r0, r1, r2, r3, o, p, t)                    \
    X(r0, o,    p, t)                                                   \
    X(r1, o+4,  p, t)                                                   \
    X(r2, o+8,  p, t)                                                   \
    X(r3, o+12, p, t)
#define UNALIGNED_W_REP8(X, r0, r1, r2, r3, r4, r5, r6, r7, o, p, t)    \
    X(r0, o,    p, t)                                                   \
    X(r1, o+4,  p, t)                                                   \
    X(r2, o+8,  p, t)                                                   \
    X(r3, o+12, p, t)                                                   \
    X(r4, o+16, p, t)                                                   \
    X(r5, o+20, p, t)                                                   \
    X(r6, o+24, p, t)                                                   \
    X(r7, o+28, p, t)

#ifndef WOLFSSL_RISCV_ASM_NO_UNALIGNED

/* Load 64-bits. */
#define UNALIGNED_LD(r, o, p, t)                \
    "ld     " #r ", " #o "(" #p ")\n\t"

/* Load 32-bits, zero extended. */
#define UNALIGNED_LWU(r, o, p, t)               \
    "lwu    " #r ", " #o "(" #p ")\n\t"

/* Load 32-bits, sign extended. */
#define UNALIGNED_LW(r, o, p, t)                \
    "lw     " #r ", " #o "(" #p ")\n\t"

/* Load 16-bits, sign extended. */
#define UNALIGNED_LH(r, o, p, t)                \
    "lh     " #r ", " #o "(" #p ")\n\t"

/* Store 64-bits. */
#define UNALIGNED_SD(r, o, p, t)                \
    "sd     " #r ", " #o "(" #p ")\n\t"

/* Store 32-bits. */
#define UNALIGNED_SW(r, o, p, t)                \
    "sw     " #r ", " #o "(" #p ")\n\t"

/* Store 16-bits. */
#define UNALIGNED_SH(r, o, p, t)                \
    "sh     " #r ", " #o "(" #p ")\n\t"

/* Bulk variants - hardware handles unaligned access, so just emit N native
 * instructions. */
#define UNALIGNED_LD2(r0, r1, o, p, t)                              \
    UNALIGNED_DW_REP2(UNALIGNED_LD, r0, r1, o, p, t)
#define UNALIGNED_LD4(r0, r1, r2, r3, o, p, t)                      \
    UNALIGNED_DW_REP4(UNALIGNED_LD, r0, r1, r2, r3, o, p, t)
#define UNALIGNED_LD8(r0, r1, r2, r3, r4, r5, r6, r7, o, p, t)      \
    UNALIGNED_DW_REP8(UNALIGNED_LD,                                 \
        r0, r1, r2, r3, r4, r5, r6, r7, o, p, t)
#define UNALIGNED_SD2(r0, r1, o, p, t)                              \
    UNALIGNED_DW_REP2(UNALIGNED_SD, r0, r1, o, p, t)
#define UNALIGNED_SD4(r0, r1, r2, r3, o, p, t)                      \
    UNALIGNED_DW_REP4(UNALIGNED_SD, r0, r1, r2, r3, o, p, t)
#define UNALIGNED_SD8(r0, r1, r2, r3, r4, r5, r6, r7, o, p, t)      \
    UNALIGNED_DW_REP8(UNALIGNED_SD,                                 \
        r0, r1, r2, r3, r4, r5, r6, r7, o, p, t)
#define UNALIGNED_LWU2(r0, r1, o, p, t)                             \
    UNALIGNED_W_REP2(UNALIGNED_LWU, r0, r1, o, p, t)
#define UNALIGNED_LWU4(r0, r1, r2, r3, o, p, t)                     \
    UNALIGNED_W_REP4(UNALIGNED_LWU, r0, r1, r2, r3, o, p, t)
#define UNALIGNED_LWU8(r0, r1, r2, r3, r4, r5, r6, r7, o, p, t)     \
    UNALIGNED_W_REP8(UNALIGNED_LWU,                                 \
        r0, r1, r2, r3, r4, r5, r6, r7, o, p, t)
#define UNALIGNED_LW2(r0, r1, o, p, t)                              \
    UNALIGNED_W_REP2(UNALIGNED_LW, r0, r1, o, p, t)
#define UNALIGNED_LW4(r0, r1, r2, r3, o, p, t)                      \
    UNALIGNED_W_REP4(UNALIGNED_LW, r0, r1, r2, r3, o, p, t)
#define UNALIGNED_LW8(r0, r1, r2, r3, r4, r5, r6, r7, o, p, t)      \
    UNALIGNED_W_REP8(UNALIGNED_LW,                                  \
        r0, r1, r2, r3, r4, r5, r6, r7, o, p, t)
#define UNALIGNED_SW2(r0, r1, o, p, t)                              \
    UNALIGNED_W_REP2(UNALIGNED_SW, r0, r1, o, p, t)
#define UNALIGNED_SW4(r0, r1, r2, r3, o, p, t)                      \
    UNALIGNED_W_REP4(UNALIGNED_SW, r0, r1, r2, r3, o, p, t)
#define UNALIGNED_SW8(r0, r1, r2, r3, r4, r5, r6, r7, o, p, t)      \
    UNALIGNED_W_REP8(UNALIGNED_SW,                                  \
        r0, r1, r2, r3, r4, r5, r6, r7, o, p, t)

#else

/* Load 64-bits. */
#define UNALIGNED_LD_BY_BYTE(r, o, p, t)        \
    "lbu    " #r ", " #o "+0(" #p ")\n\t"       \
    "lbu    " #t ", " #o "+1(" #p ")\n\t"       \
    "slli   " #t ", " #t ", 8\n\t"              \
    "or     " #r ", " #r ", " #t "\n\t"         \
    "lbu    " #t ", " #o "+2(" #p ")\n\t"       \
    "slli   " #t ", " #t ", 16\n\t"             \
    "or     " #r ", " #r ", " #t "\n\t"         \
    "lbu    " #t ", " #o "+3(" #p ")\n\t"       \
    "slli   " #t ", " #t ", 24\n\t"             \
    "or     " #r ", " #r ", " #t "\n\t"         \
    "lbu    " #t ", " #o "+4(" #p ")\n\t"       \
    "slli   " #t ", " #t ", 32\n\t"             \
    "or     " #r ", " #r ", " #t "\n\t"         \
    "lbu    " #t ", " #o "+5(" #p ")\n\t"       \
    "slli   " #t ", " #t ", 40\n\t"             \
    "or     " #r ", " #r ", " #t "\n\t"         \
    "lbu    " #t ", " #o "+6(" #p ")\n\t"       \
    "slli   " #t ", " #t ", 48\n\t"             \
    "or     " #r ", " #r ", " #t "\n\t"         \
    "lbu    " #t ", " #o "+7(" #p ")\n\t"       \
    "slli   " #t ", " #t ", 56\n\t"             \
    "or     " #r ", " #r ", " #t "\n\t"
#define UNALIGNED_LD_BY_HALF(r, o, p, t)        \
    "lhu    " #r ", " #o "+0(" #p ")\n\t"       \
    "lhu    " #t ", " #o "+2(" #p ")\n\t"       \
    "slli   " #t ", " #t ", 16\n\t"             \
    "or     " #r ", " #r ", " #t "\n\t"         \
    "lhu    " #t ", " #o "+4(" #p ")\n\t"       \
    "slli   " #t ", " #t ", 32\n\t"             \
    "or     " #r ", " #r ", " #t "\n\t"         \
    "lhu    " #t ", " #o "+6(" #p ")\n\t"       \
    "slli   " #t ", " #t ", 48\n\t"             \
    "or     " #r ", " #r ", " #t "\n\t"
#define UNALIGNED_LD_BY_WORD(r, o, p, t)        \
    "lwu    " #r ", " #o "+0(" #p ")\n\t"       \
    "lwu    " #t ", " #o "+4(" #p ")\n\t"       \
    "slli   " #t ", " #t ", 32\n\t"             \
    "or     " #r ", " #r ", " #t "\n\t"
#define UNALIGNED_LD_BY_DWORD(r, o, p, t)       \
    "ld     " #r ", " #o "(" #p ")\n\t"
/* Assumes o is a multiple of 8. */
#define UNALIGNED_LD(r, o, p, t)                \
    "andi   " #t ", " #p ", 7\n\t"              \
    "bnez   " #t ", 1f\n\t"                     \
    UNALIGNED_LD_BY_DWORD(r, o, p, t)           \
    "j      4f\n\t"                             \
    "1:\n\t"                                    \
    "andi   " #t ", " #t ", 3\n\t"              \
    "bnez   " #t ", 2f\n\t"                     \
    UNALIGNED_LD_BY_WORD(r, o, p, t)            \
    "j      4f\n\t"                             \
    "2:\n\t"                                    \
    "andi   " #t ", " #t ", 1\n\t"              \
    "bnez   " #t ", 3f\n\t"                     \
    UNALIGNED_LD_BY_HALF(r, o, p, t)            \
    "j      4f\n\t"                             \
    "3:\n\t"                                    \
    UNALIGNED_LD_BY_BYTE(r, o, p, t)            \
    "4:\n\t"

/* Load 32-bits, zero extended. */
#define UNALIGNED_LWU_BY_BYTE(r, o, p, t)       \
    "lbu    " #r ", " #o "+0(" #p ")\n\t"       \
    "lbu    " #t ", " #o "+1(" #p ")\n\t"       \
    "slli   " #t ", " #t ", 8\n\t"              \
    "or     " #r ", " #r ", " #t "\n\t"         \
    "lbu    " #t ", " #o "+2(" #p ")\n\t"       \
    "slli   " #t ", " #t ", 16\n\t"             \
    "or     " #r ", " #r ", " #t "\n\t"         \
    "lbu    " #t ", " #o "+3(" #p ")\n\t"       \
    "slli   " #t ", " #t ", 24\n\t"             \
    "or     " #r ", " #r ", " #t "\n\t"
#define UNALIGNED_LWU_BY_HALF(r, o, p, t)       \
    "lhu    " #r ", " #o "+0(" #p ")\n\t"       \
    "lhu    " #t ", " #o "+2(" #p ")\n\t"       \
    "slli   " #t ", " #t ", 16\n\t"             \
    "or     " #r ", " #r ", " #t "\n\t"
#define UNALIGNED_LWU_BY_WORD(r, o, p, t)       \
    "lwu    " #r ", " #o "(" #p ")\n\t"
/* Assumes o is a multiple of 4. */
#define UNALIGNED_LWU(r, o, p, t)               \
    "andi   " #t ", " #p ", 3\n\t"              \
    "bnez   " #t ", 1f\n\t"                     \
    UNALIGNED_LWU_BY_WORD(r, o, p, t)           \
    "j      3f\n\t"                             \
    "1:\n\t"                                    \
    "andi   " #t ", " #t ", 1\n\t"              \
    "bnez   " #t ", 2f\n\t"                     \
    UNALIGNED_LWU_BY_HALF(r, o, p, t)           \
    "j      3f\n\t"                             \
    "2:\n\t"                                    \
    UNALIGNED_LWU_BY_BYTE(r, o, p, t)           \
    "3:\n\t"

/* Load 32-bits, sign extended. */
#define UNALIGNED_LW_BY_BYTE(r, o, p, t)        \
    UNALIGNED_LWU_BY_BYTE(r, o, p, t)           \
    "sext.w " #r ", " #r "\n\t"
#define UNALIGNED_LW_BY_HALF(r, o, p, t)        \
    UNALIGNED_LWU_BY_HALF(r, o, p, t)           \
    "sext.w " #r ", " #r "\n\t"
#define UNALIGNED_LW_BY_WORD(r, o, p, t)        \
    "lw     " #r ", " #o "(" #p ")\n\t"
/* Assumes o is a multiple of 4. */
#define UNALIGNED_LW(r, o, p, t)                \
    "andi   " #t ", " #p ", 3\n\t"              \
    "bnez   " #t ", 1f\n\t"                     \
    UNALIGNED_LW_BY_WORD(r, o, p, t)            \
    "j      3f\n\t"                             \
    "1:\n\t"                                    \
    "andi   " #t ", " #t ", 1\n\t"              \
    "bnez   " #t ", 2f\n\t"                     \
    UNALIGNED_LW_BY_HALF(r, o, p, t)            \
    "j      3f\n\t"                             \
    "2:\n\t"                                    \
    UNALIGNED_LW_BY_BYTE(r, o, p, t)            \
    "3:\n\t"

/* Load 16-bits, sign extended. */
#define UNALIGNED_LH_BY_BYTE(r, o, p, t)        \
    "lbu    " #r ", " #o "+0(" #p ")\n\t"       \
    "lb     " #t ", " #o "+1(" #p ")\n\t"       \
    "slli   " #t ", " #t ", 8\n\t"              \
    "or     " #r ", " #r ", " #t "\n\t"
#define UNALIGNED_LH(r, o, p, t)                \
    UNALIGNED_LH_BY_BYTE(r, o, p, t)

/* Store 64-bits. */
#define UNALIGNED_SD_BY_BYTE(r, o, p, t)        \
    "sb     " #r ", " #o "+0(" #p ")\n\t"       \
    "srli   " #t ", " #r ", 8\n\t"              \
    "sb     " #t ", " #o "+1(" #p ")\n\t"       \
    "srli   " #t ", " #r ", 16\n\t"             \
    "sb     " #t ", " #o "+2(" #p ")\n\t"       \
    "srli   " #t ", " #r ", 24\n\t"             \
    "sb     " #t ", " #o "+3(" #p ")\n\t"       \
    "srli   " #t ", " #r ", 32\n\t"             \
    "sb     " #t ", " #o "+4(" #p ")\n\t"       \
    "srli   " #t ", " #r ", 40\n\t"             \
    "sb     " #t ", " #o "+5(" #p ")\n\t"       \
    "srli   " #t ", " #r ", 48\n\t"             \
    "sb     " #t ", " #o "+6(" #p ")\n\t"       \
    "srli   " #t ", " #r ", 56\n\t"             \
    "sb     " #t ", " #o "+7(" #p ")\n\t"
#define UNALIGNED_SD_BY_HALF(r, o, p, t)        \
    "sh     " #r ", " #o "+0(" #p ")\n\t"       \
    "srli   " #t ", " #r ", 16\n\t"             \
    "sh     " #t ", " #o "+2(" #p ")\n\t"       \
    "srli   " #t ", " #r ", 32\n\t"             \
    "sh     " #t ", " #o "+4(" #p ")\n\t"       \
    "srli   " #t ", " #r ", 48\n\t"             \
    "sh     " #t ", " #o "+6(" #p ")\n\t"
#define UNALIGNED_SD_BY_WORD(r, o, p, t)        \
    "sw     " #r ", " #o "+0(" #p ")\n\t"       \
    "srli   " #t ", " #r ", 32\n\t"             \
    "sw     " #t ", " #o "+4(" #p ")\n\t"
#define UNALIGNED_SD_BY_DWORD(r, o, p, t)       \
    "sd     " #r ", " #o "(" #p ")\n\t"
/* Assumes o is a multiple of 8. */
#define UNALIGNED_SD(r, o, p, t)                \
    "andi   " #t ", " #p ", 7\n\t"              \
    "bnez   " #t ", 1f\n\t"                     \
    UNALIGNED_SD_BY_DWORD(r, o, p, t)           \
    "j      4f\n\t"                             \
    "1:\n\t"                                    \
    "andi   " #t ", " #t ", 3\n\t"              \
    "bnez   " #t ", 2f\n\t"                     \
    UNALIGNED_SD_BY_WORD(r, o, p, t)            \
    "j      4f\n\t"                             \
    "2:\n\t"                                    \
    "andi   " #t ", " #t ", 1\n\t"              \
    "bnez   " #t ", 3f\n\t"                     \
    UNALIGNED_SD_BY_HALF(r, o, p, t)            \
    "j      4f\n\t"                             \
    "3:\n\t"                                    \
    UNALIGNED_SD_BY_BYTE(r, o, p, t)            \
    "4:\n\t"

/* Store 32-bits. */
#define UNALIGNED_SW_BY_BYTE(r, o, p, t)        \
    "sb     " #r ", " #o "+0(" #p ")\n\t"       \
    "srli   " #t ", " #r ", 8\n\t"              \
    "sb     " #t ", " #o "+1(" #p ")\n\t"       \
    "srli   " #t ", " #r ", 16\n\t"             \
    "sb     " #t ", " #o "+2(" #p ")\n\t"       \
    "srli   " #t ", " #r ", 24\n\t"             \
    "sb     " #t ", " #o "+3(" #p ")\n\t"
#define UNALIGNED_SW_BY_HALF(r, o, p, t)        \
    "sh     " #r ", " #o "+0(" #p ")\n\t"       \
    "srli   " #t ", " #r ", 16\n\t"             \
    "sh     " #t ", " #o "+2(" #p ")\n\t"
#define UNALIGNED_SW_BY_WORD(r, o, p, t)        \
    "sw     " #r ", " #o "(" #p ")\n\t"
/* Assumes o is a multiple of 4. */
#define UNALIGNED_SW(r, o, p, t)                \
    "andi   " #t ", " #p ", 3\n\t"              \
    "bnez   " #t ", 1f\n\t"                     \
    UNALIGNED_SW_BY_WORD(r, o, p, t)            \
    "j      3f\n\t"                             \
    "1:\n\t"                                    \
    "andi   " #t ", " #t ", 1\n\t"              \
    "bnez   " #t ", 2f\n\t"                     \
    UNALIGNED_SW_BY_HALF(r, o, p, t)            \
    "j      3f\n\t"                             \
    "2:\n\t"                                    \
    UNALIGNED_SW_BY_BYTE(r, o, p, t)            \
    "3:\n\t"

/* Store 16-bits. */
#define UNALIGNED_SH_BY_BYTE(r, o, p, t)        \
    "sb     " #r ", " #o "+0(" #p ")\n\t"       \
    "srli   " #t ", " #r ", 8\n\t"              \
    "sb     " #t ", " #o "+1(" #p ")\n\t"
#define UNALIGNED_SH(r, o, p, t)                \
    UNALIGNED_SH_BY_BYTE(r, o, p, t)

/* Load 2 64-bits. Assumes o is a multiple of 8. */
#define UNALIGNED_LD2(r0, r1, o, p, t)                                  \
    "andi   " #t ", " #p ", 7\n\t"                                      \
    "bnez   " #t ", 1f\n\t"                                             \
    UNALIGNED_DW_REP2(UNALIGNED_LD_BY_DWORD, r0, r1, o, p, t)           \
    "j      4f\n\t"                                                     \
    "1:\n\t"                                                            \
    "andi   " #t ", " #t ", 3\n\t"                                      \
    "bnez   " #t ", 2f\n\t"                                             \
    UNALIGNED_DW_REP2(UNALIGNED_LD_BY_WORD, r0, r1, o, p, t)            \
    "j      4f\n\t"                                                     \
    "2:\n\t"                                                            \
    "andi   " #t ", " #t ", 1\n\t"                                      \
    "bnez   " #t ", 3f\n\t"                                             \
    UNALIGNED_DW_REP2(UNALIGNED_LD_BY_HALF, r0, r1, o, p, t)            \
    "j      4f\n\t"                                                     \
    "3:\n\t"                                                            \
    UNALIGNED_DW_REP2(UNALIGNED_LD_BY_BYTE, r0, r1, o, p, t)            \
    "4:\n\t"

/* Load 4 64-bits. Assumes o is a multiple of 8. */
#define UNALIGNED_LD4(r0, r1, r2, r3, o, p, t)                          \
    "andi   " #t ", " #p ", 7\n\t"                                      \
    "bnez   " #t ", 1f\n\t"                                             \
    UNALIGNED_DW_REP4(UNALIGNED_LD_BY_DWORD, r0, r1, r2, r3, o, p, t)   \
    "j      4f\n\t"                                                     \
    "1:\n\t"                                                            \
    "andi   " #t ", " #t ", 3\n\t"                                      \
    "bnez   " #t ", 2f\n\t"                                             \
    UNALIGNED_DW_REP4(UNALIGNED_LD_BY_WORD, r0, r1, r2, r3, o, p, t)    \
    "j      4f\n\t"                                                     \
    "2:\n\t"                                                            \
    "andi   " #t ", " #t ", 1\n\t"                                      \
    "bnez   " #t ", 3f\n\t"                                             \
    UNALIGNED_DW_REP4(UNALIGNED_LD_BY_HALF, r0, r1, r2, r3, o, p, t)    \
    "j      4f\n\t"                                                     \
    "3:\n\t"                                                            \
    UNALIGNED_DW_REP4(UNALIGNED_LD_BY_BYTE, r0, r1, r2, r3, o, p, t)    \
    "4:\n\t"

/* Load 8 64-bits. Assumes o is a multiple of 8. */
#define UNALIGNED_LD8(r0, r1, r2, r3, r4, r5, r6, r7, o, p, t)          \
    "andi   " #t ", " #p ", 7\n\t"                                      \
    "bnez   " #t ", 1f\n\t"                                             \
    UNALIGNED_DW_REP8(UNALIGNED_LD_BY_DWORD,                            \
        r0, r1, r2, r3, r4, r5, r6, r7, o, p, t)                        \
    "j      4f\n\t"                                                     \
    "1:\n\t"                                                            \
    "andi   " #t ", " #t ", 3\n\t"                                      \
    "bnez   " #t ", 2f\n\t"                                             \
    UNALIGNED_DW_REP8(UNALIGNED_LD_BY_WORD,                             \
        r0, r1, r2, r3, r4, r5, r6, r7, o, p, t)                        \
    "j      4f\n\t"                                                     \
    "2:\n\t"                                                            \
    "andi   " #t ", " #t ", 1\n\t"                                      \
    "bnez   " #t ", 3f\n\t"                                             \
    UNALIGNED_DW_REP8(UNALIGNED_LD_BY_HALF,                             \
        r0, r1, r2, r3, r4, r5, r6, r7, o, p, t)                        \
    "j      4f\n\t"                                                     \
    "3:\n\t"                                                            \
    UNALIGNED_DW_REP8(UNALIGNED_LD_BY_BYTE,                             \
        r0, r1, r2, r3, r4, r5, r6, r7, o, p, t)                        \
    "4:\n\t"

/* Store 2 64-bits. Assumes o is a multiple of 8. */
#define UNALIGNED_SD2(r0, r1, o, p, t)                                  \
    "andi   " #t ", " #p ", 7\n\t"                                      \
    "bnez   " #t ", 1f\n\t"                                             \
    UNALIGNED_DW_REP2(UNALIGNED_SD_BY_DWORD, r0, r1, o, p, t)           \
    "j      4f\n\t"                                                     \
    "1:\n\t"                                                            \
    "andi   " #t ", " #t ", 3\n\t"                                      \
    "bnez   " #t ", 2f\n\t"                                             \
    UNALIGNED_DW_REP2(UNALIGNED_SD_BY_WORD, r0, r1, o, p, t)            \
    "j      4f\n\t"                                                     \
    "2:\n\t"                                                            \
    "andi   " #t ", " #t ", 1\n\t"                                      \
    "bnez   " #t ", 3f\n\t"                                             \
    UNALIGNED_DW_REP2(UNALIGNED_SD_BY_HALF, r0, r1, o, p, t)            \
    "j      4f\n\t"                                                     \
    "3:\n\t"                                                            \
    UNALIGNED_DW_REP2(UNALIGNED_SD_BY_BYTE, r0, r1, o, p, t)            \
    "4:\n\t"

/* Store 4 64-bits. Assumes o is a multiple of 8. */
#define UNALIGNED_SD4(r0, r1, r2, r3, o, p, t)                          \
    "andi   " #t ", " #p ", 7\n\t"                                      \
    "bnez   " #t ", 1f\n\t"                                             \
    UNALIGNED_DW_REP4(UNALIGNED_SD_BY_DWORD, r0, r1, r2, r3, o, p, t)   \
    "j      4f\n\t"                                                     \
    "1:\n\t"                                                            \
    "andi   " #t ", " #t ", 3\n\t"                                      \
    "bnez   " #t ", 2f\n\t"                                             \
    UNALIGNED_DW_REP4(UNALIGNED_SD_BY_WORD, r0, r1, r2, r3, o, p, t)    \
    "j      4f\n\t"                                                     \
    "2:\n\t"                                                            \
    "andi   " #t ", " #t ", 1\n\t"                                      \
    "bnez   " #t ", 3f\n\t"                                             \
    UNALIGNED_DW_REP4(UNALIGNED_SD_BY_HALF, r0, r1, r2, r3, o, p, t)    \
    "j      4f\n\t"                                                     \
    "3:\n\t"                                                            \
    UNALIGNED_DW_REP4(UNALIGNED_SD_BY_BYTE, r0, r1, r2, r3, o, p, t)    \
    "4:\n\t"

/* Store 8 64-bits. Assumes o is a multiple of 8. */
#define UNALIGNED_SD8(r0, r1, r2, r3, r4, r5, r6, r7, o, p, t)          \
    "andi   " #t ", " #p ", 7\n\t"                                      \
    "bnez   " #t ", 1f\n\t"                                             \
    UNALIGNED_DW_REP8(UNALIGNED_SD_BY_DWORD,                            \
        r0, r1, r2, r3, r4, r5, r6, r7, o, p, t)                        \
    "j      4f\n\t"                                                     \
    "1:\n\t"                                                            \
    "andi   " #t ", " #t ", 3\n\t"                                      \
    "bnez   " #t ", 2f\n\t"                                             \
    UNALIGNED_DW_REP8(UNALIGNED_SD_BY_WORD,                             \
        r0, r1, r2, r3, r4, r5, r6, r7, o, p, t)                        \
    "j      4f\n\t"                                                     \
    "2:\n\t"                                                            \
    "andi   " #t ", " #t ", 1\n\t"                                      \
    "bnez   " #t ", 3f\n\t"                                             \
    UNALIGNED_DW_REP8(UNALIGNED_SD_BY_HALF,                             \
        r0, r1, r2, r3, r4, r5, r6, r7, o, p, t)                        \
    "j      4f\n\t"                                                     \
    "3:\n\t"                                                            \
    UNALIGNED_DW_REP8(UNALIGNED_SD_BY_BYTE,                             \
        r0, r1, r2, r3, r4, r5, r6, r7, o, p, t)                        \
    "4:\n\t"

/* Load 2 32-bits, zero extended. Assumes o is a multiple of 4. */
#define UNALIGNED_LWU2(r0, r1, o, p, t)                                 \
    "andi   " #t ", " #p ", 3\n\t"                                      \
    "bnez   " #t ", 1f\n\t"                                             \
    UNALIGNED_W_REP2(UNALIGNED_LWU_BY_WORD, r0, r1, o, p, t)            \
    "j      3f\n\t"                                                     \
    "1:\n\t"                                                            \
    "andi   " #t ", " #t ", 1\n\t"                                      \
    "bnez   " #t ", 2f\n\t"                                             \
    UNALIGNED_W_REP2(UNALIGNED_LWU_BY_HALF, r0, r1, o, p, t)            \
    "j      3f\n\t"                                                     \
    "2:\n\t"                                                            \
    UNALIGNED_W_REP2(UNALIGNED_LWU_BY_BYTE, r0, r1, o, p, t)            \
    "3:\n\t"

/* Load 4 32-bits, zero extended. Assumes o is a multiple of 4. */
#define UNALIGNED_LWU4(r0, r1, r2, r3, o, p, t)                         \
    "andi   " #t ", " #p ", 3\n\t"                                      \
    "bnez   " #t ", 1f\n\t"                                             \
    UNALIGNED_W_REP4(UNALIGNED_LWU_BY_WORD, r0, r1, r2, r3, o, p, t)    \
    "j      3f\n\t"                                                     \
    "1:\n\t"                                                            \
    "andi   " #t ", " #t ", 1\n\t"                                      \
    "bnez   " #t ", 2f\n\t"                                             \
    UNALIGNED_W_REP4(UNALIGNED_LWU_BY_HALF, r0, r1, r2, r3, o, p, t)    \
    "j      3f\n\t"                                                     \
    "2:\n\t"                                                            \
    UNALIGNED_W_REP4(UNALIGNED_LWU_BY_BYTE, r0, r1, r2, r3, o, p, t)    \
    "3:\n\t"

/* Load 8 32-bits, zero extended. Assumes o is a multiple of 4. */
#define UNALIGNED_LWU8(r0, r1, r2, r3, r4, r5, r6, r7, o, p, t)         \
    "andi   " #t ", " #p ", 3\n\t"                                      \
    "bnez   " #t ", 1f\n\t"                                             \
    UNALIGNED_W_REP8(UNALIGNED_LWU_BY_WORD,                             \
        r0, r1, r2, r3, r4, r5, r6, r7, o, p, t)                        \
    "j      3f\n\t"                                                     \
    "1:\n\t"                                                            \
    "andi   " #t ", " #t ", 1\n\t"                                      \
    "bnez   " #t ", 2f\n\t"                                             \
    UNALIGNED_W_REP8(UNALIGNED_LWU_BY_HALF,                             \
        r0, r1, r2, r3, r4, r5, r6, r7, o, p, t)                        \
    "j      3f\n\t"                                                     \
    "2:\n\t"                                                            \
    UNALIGNED_W_REP8(UNALIGNED_LWU_BY_BYTE,                             \
        r0, r1, r2, r3, r4, r5, r6, r7, o, p, t)                        \
    "3:\n\t"

/* Load 2 32-bits, sign extended. Assumes o is a multiple of 4. */
#define UNALIGNED_LW2(r0, r1, o, p, t)                                  \
    "andi   " #t ", " #p ", 3\n\t"                                      \
    "bnez   " #t ", 1f\n\t"                                             \
    UNALIGNED_W_REP2(UNALIGNED_LW_BY_WORD, r0, r1, o, p, t)             \
    "j      3f\n\t"                                                     \
    "1:\n\t"                                                            \
    "andi   " #t ", " #t ", 1\n\t"                                      \
    "bnez   " #t ", 2f\n\t"                                             \
    UNALIGNED_W_REP2(UNALIGNED_LW_BY_HALF, r0, r1, o, p, t)             \
    "j      3f\n\t"                                                     \
    "2:\n\t"                                                            \
    UNALIGNED_W_REP2(UNALIGNED_LW_BY_BYTE, r0, r1, o, p, t)             \
    "3:\n\t"

/* Load 4 32-bits, sign extended. Assumes o is a multiple of 4. */
#define UNALIGNED_LW4(r0, r1, r2, r3, o, p, t)                          \
    "andi   " #t ", " #p ", 3\n\t"                                      \
    "bnez   " #t ", 1f\n\t"                                             \
    UNALIGNED_W_REP4(UNALIGNED_LW_BY_WORD, r0, r1, r2, r3, o, p, t)     \
    "j      3f\n\t"                                                     \
    "1:\n\t"                                                            \
    "andi   " #t ", " #t ", 1\n\t"                                      \
    "bnez   " #t ", 2f\n\t"                                             \
    UNALIGNED_W_REP4(UNALIGNED_LW_BY_HALF, r0, r1, r2, r3, o, p, t)     \
    "j      3f\n\t"                                                     \
    "2:\n\t"                                                            \
    UNALIGNED_W_REP4(UNALIGNED_LW_BY_BYTE, r0, r1, r2, r3, o, p, t)     \
    "3:\n\t"

/* Load 8 32-bits, sign extended. Assumes o is a multiple of 4. */
#define UNALIGNED_LW8(r0, r1, r2, r3, r4, r5, r6, r7, o, p, t)          \
    "andi   " #t ", " #p ", 3\n\t"                                      \
    "bnez   " #t ", 1f\n\t"                                             \
    UNALIGNED_W_REP8(UNALIGNED_LW_BY_WORD,                              \
        r0, r1, r2, r3, r4, r5, r6, r7, o, p, t)                        \
    "j      3f\n\t"                                                     \
    "1:\n\t"                                                            \
    "andi   " #t ", " #t ", 1\n\t"                                      \
    "bnez   " #t ", 2f\n\t"                                             \
    UNALIGNED_W_REP8(UNALIGNED_LW_BY_HALF,                              \
        r0, r1, r2, r3, r4, r5, r6, r7, o, p, t)                        \
    "j      3f\n\t"                                                     \
    "2:\n\t"                                                            \
    UNALIGNED_W_REP8(UNALIGNED_LW_BY_BYTE,                              \
        r0, r1, r2, r3, r4, r5, r6, r7, o, p, t)                        \
    "3:\n\t"

/* Store 2 32-bits. Assumes o is a multiple of 4. */
#define UNALIGNED_SW2(r0, r1, o, p, t)                                  \
    "andi   " #t ", " #p ", 3\n\t"                                      \
    "bnez   " #t ", 1f\n\t"                                             \
    UNALIGNED_W_REP2(UNALIGNED_SW_BY_WORD, r0, r1, o, p, t)             \
    "j      3f\n\t"                                                     \
    "1:\n\t"                                                            \
    "andi   " #t ", " #t ", 1\n\t"                                      \
    "bnez   " #t ", 2f\n\t"                                             \
    UNALIGNED_W_REP2(UNALIGNED_SW_BY_HALF, r0, r1, o, p, t)             \
    "j      3f\n\t"                                                     \
    "2:\n\t"                                                            \
    UNALIGNED_W_REP2(UNALIGNED_SW_BY_BYTE, r0, r1, o, p, t)             \
    "3:\n\t"

/* Store 4 32-bits. Assumes o is a multiple of 4. */
#define UNALIGNED_SW4(r0, r1, r2, r3, o, p, t)                          \
    "andi   " #t ", " #p ", 3\n\t"                                      \
    "bnez   " #t ", 1f\n\t"                                             \
    UNALIGNED_W_REP4(UNALIGNED_SW_BY_WORD, r0, r1, r2, r3, o, p, t)     \
    "j      3f\n\t"                                                     \
    "1:\n\t"                                                            \
    "andi   " #t ", " #t ", 1\n\t"                                      \
    "bnez   " #t ", 2f\n\t"                                             \
    UNALIGNED_W_REP4(UNALIGNED_SW_BY_HALF, r0, r1, r2, r3, o, p, t)     \
    "j      3f\n\t"                                                     \
    "2:\n\t"                                                            \
    UNALIGNED_W_REP4(UNALIGNED_SW_BY_BYTE, r0, r1, r2, r3, o, p, t)     \
    "3:\n\t"

/* Store 8 32-bits. Assumes o is a multiple of 4. */
#define UNALIGNED_SW8(r0, r1, r2, r3, r4, r5, r6, r7, o, p, t)          \
    "andi   " #t ", " #p ", 3\n\t"                                      \
    "bnez   " #t ", 1f\n\t"                                             \
    UNALIGNED_W_REP8(UNALIGNED_SW_BY_WORD,                              \
        r0, r1, r2, r3, r4, r5, r6, r7, o, p, t)                        \
    "j      3f\n\t"                                                     \
    "1:\n\t"                                                            \
    "andi   " #t ", " #t ", 1\n\t"                                      \
    "bnez   " #t ", 2f\n\t"                                             \
    UNALIGNED_W_REP8(UNALIGNED_SW_BY_HALF,                              \
        r0, r1, r2, r3, r4, r5, r6, r7, o, p, t)                        \
    "j      3f\n\t"                                                     \
    "2:\n\t"                                                            \
    UNALIGNED_W_REP8(UNALIGNED_SW_BY_BYTE,                              \
        r0, r1, r2, r3, r4, r5, r6, r7, o, p, t)                        \
    "3:\n\t"

#endif /* !WOLFSSL_RISCV_ASM_NO_UNALIGNED */


#define VLSEG_V(vd, rs1, cnt, width) \
    ASM_WORD(0b0000111 | (width << 12) | (0b10101000 << 20) |   \
        (0 << 28) | ((cnt - 1) << 29) | (vd << 7) | (rs1 << 15))
/* Load 8 Vector registers' 64-bit element. */
#define VLSEG8E64_V(vd, rs1)  VLSEG_V(vd, rs1, 8, WIDTH_64)
/* Load 1 Vector register's 64-bit element. */
#define VLSEG1E64_V(vd, rs1)  VLSEG_V(vd, rs1, 1, WIDTH_64)

#define VSSEG_V(vd, rs1, cnt, width) \
    ASM_WORD(0b0100111 | (width << 12) | (0b10101000 << 20) |   \
        (0 << 28) | ((cnt - 1) << 29) | (vd << 7) | (rs1 << 15))
/* Store 8 Vector registers' 64-bit element. */
#define VSSEG8E64_V(vd, rs1)  VSSEG_V(vd, rs1, 8, WIDTH_64)
/* Store 1 Vector register's 64-bit element. */
#define VSSEG1E64_V(vd, rs1)  VSSEG_V(vd, rs1, 1, WIDTH_64)

/* Load n Vector registers with width-bit components. */
#define VLRE_V(vd, rs1, cnt, width)                             \
    ASM_WORD(0b0000111 | (width << 12) | (0b00101000 << 20) |   \
        (0 << 28) | ((cnt - 1) << 29) | (vd << 7) | (rs1 << 15))
/* Load 1 Vector register with 64-bit components. */
#define VL1RE64_V(vd, rs1)  VLRE_V(vd, rs1, 1, WIDTH_64)
/* Load 2 Vector register with 64-bit components. */
#define VL2RE64_V(vd, rs1)  VLRE_V(vd, rs1, 2, WIDTH_64)
/* Load 4 Vector register with 64-bit components. */
#define VL4RE64_V(vd, rs1)  VLRE_V(vd, rs1, 4, WIDTH_64)
/* Load 8 Vector register with 64-bit components. */
#define VL8RE64_V(vd, rs1)  VLRE_V(vd, rs1, 8, WIDTH_64)
/* Load 1 Vector register with 32-bit components. */
#define VL1RE32_V(vd, rs1)  VLRE_V(vd, rs1, 1, WIDTH_32)
/* Load 2 Vector register with 32-bit components. */
#define VL2RE32_V(vd, rs1)  VLRE_V(vd, rs1, 2, WIDTH_32)
/* Load 4 Vector register with 32-bit components. */
#define VL4RE32_V(vd, rs1)  VLRE_V(vd, rs1, 4, WIDTH_32)
/* Load 8 Vector register with 32-bit components. */
#define VL8RE32_V(vd, rs1)  VLRE_V(vd, rs1, 8, WIDTH_32)

/* Store n Vector register. */
#define VSR_V(vs3, rs1, cnt)                                    \
    ASM_WORD(0b0100111 | (0b00101000 << 20) | (0 << 28) |       \
        ((cnt-1) << 29) | (vs3 << 7) | (rs1 << 15))
/* Store 1 Vector register. */
#define VS1R_V(vs3, rs1)    VSR_V(vs3, rs1, 1)
/* Store 2 Vector register. */
#define VS2R_V(vs3, rs1)    VSR_V(vs3, rs1, 2)
/* Store 4 Vector register. */
#define VS4R_V(vs3, rs1)    VSR_V(vs3, rs1, 4)
/* Store 8 Vector register. */
#define VS8R_V(vs3, rs1)    VSR_V(vs3, rs1, 8)

/* Move from vector register to vector register. */
#define VMV_V_V(vd, vs1)                                        \
    ASM_WORD((0b1010111 << 0) | (0b000 << 12) | (0b1 << 25) |   \
        (0b010111 << 26) | ((vd) << 7) | ((vs1) << 15))
/* Splat register to each component of the vector register. */
#define VMV_V_X(vd, rs1)                                        \
    ASM_WORD((0b1010111 << 0) | (0b100 << 12) | (0b1 << 25) |   \
        (0b010111 << 26) | ((vd) << 7) | ((rs1) << 15))
/* Splat immediate to each component of the vector register. */
#define VMV_V_I(vd, imm)                                        \
    ASM_WORD((0b1010111 << 0) | (0b011 << 12) | (0b1 << 25) |   \
        (0b010111 << 26) | ((vd) << 7) | ((imm) << 15))
/* Move n vector registers to vector registers. */
#define VMVR_V(vd, vs2, n)                                      \
    ASM_WORD((0b1010111 << 0) | (0b011 << 12) | (0b1 << 25) |   \
        (0b100111 << 26) | ((vd) << 7) | ((n-1) << 15) |        \
        ((vs2) << 20))


/*
 * Logic
 */

/* vd = vs2 << rs1 */
#define VSLL_VX(vd, vs2, rs1)                       \
    ASM_WORD((0b100101 << 26) | (0b1 << 25) |       \
             (0b100 << 12) | (0b1010111 << 0) |     \
             (vd << 7) | (rs1 << 15) | (vs2 << 20))
/* vd = vs2 << uimm */
#define VSLL_VI(vd, vs2, uimm)                      \
    ASM_WORD((0b100101 << 26) | (0b1 << 25) |       \
             (0b011 << 12) | (0b1010111 << 0) |     \
             (vd << 7) | (uimm << 15) | (vs2 << 20))
/* vd = vs2 >> rs1 */
#define VSRL_VX(vd, vs2, rs1)                       \
    ASM_WORD((0b101000 << 26) | (0b1 << 25) |       \
             (0b100 << 12) | (0b1010111 << 0) |     \
             (vd << 7) | (rs1 << 15) | (vs2 << 20))
/* vd = vs2 >> uimm */
#define VSRL_VI(vd, vs2, uimm)                      \
    ASM_WORD((0b101000 << 26) | (0b1 << 25) |       \
             (0b011 << 12) | (0b1010111 << 0) |     \
             (vd << 7) | (uimm << 15) | (vs2 << 20))


/*
 * Arithmetic
 */

/* vd = vs2 + [i,] */
#define VADD_VI(vd, vs2, i)                         \
    ASM_WORD((0b000000 << 26) | (0b1 << 25) |       \
             (0b011 << 12) | (0b1010111 << 0) |     \
             (vd << 7) | (i << 15) | (vs2 << 20))
/* vd = vs1 + vs2 */
#define VADD_VV(vd, vs1, vs2)                       \
    ASM_WORD((0b000000 << 26) | (0b1 << 25) |       \
             (0b000 << 12) | (0b1010111 << 0) |     \
             (vs2 << 20) | (vs1 << 15) | (vd << 7))

/* vd = vs1 ^ vs2 */
#define VXOR_VV(vd, vs1, vs2)                       \
    ASM_WORD((0b001011 << 26) | (0b1 << 25) |       \
             (0b000 << 12) | (0b1010111 << 0) |     \
             (vd << 7) | (vs1 << 15) | (vs2 << 20))
/* vd = imm ^ vs2 */
#define VXOR_VI(vd, vs2, imm)                       \
    ASM_WORD((0b001011 << 26) | (0b1 << 25) |       \
             (0b011 << 12) | (0b1010111 << 0) |     \
             (vd << 7) | (imm << 15) | (vs2 << 20))
/* vd = ~vs */
#define VNOT_V(vd, vs)  VXOR_VI(vd, vs, 0b11111)

/* vd = vs1 & vs2 */
#define VAND_VV(vd, vs1, vs2)                       \
    ASM_WORD((0b001001 << 26) | (0b1 << 25) |       \
             (0b000 << 12) | (0b1010111 << 0) |     \
             (vd << 7) | (vs1 << 15) | (vs2 << 20))
/* vd = vs1 & rs2 */
#define VAND_VX(vd, vs2, rs1)                       \
    ASM_WORD((0b001001 << 26) | (0b1 << 25) |       \
             (0b100 << 12) | (0b1010111 << 0) |     \
             (vd << 7) | (rs1 << 15) | (vs2 << 20))
/* vd = vs1 | vs2 */
#define VOR_VV(vd, vs1, vs2)                        \
    ASM_WORD((0b001010 << 26) | (0b1 << 25) |       \
             (0b000 << 12) | (0b1010111 << 0) |     \
             (vd << 7) | (vs1 << 15) | (vs2 << 20))


/* vd = LOW(vs1 * vs2) */
#define VMUL_VV(vd, vs1, vs2)                       \
    ASM_WORD((0b100101 << 26) | (0b1 << 25) |       \
             (0b010 << 12) | (0b1010111 << 0) |     \
             (vs2 << 20) | (vs1 << 15) | (vd << 7))
/* vd = HIGH(vs1 * vs2) - unsigned * unsigned */
#define VMULHU_VV(vd, vs1, vs2)                     \
    ASM_WORD((0b100100 << 26) | (0b1 << 25) |       \
             (0b010 << 12) | (0b1010111 << 0) |     \
             (vs2 << 20) | (vs1 << 15) | (vd << 7))


#define VMERGE_VVM(vd, vs2, vs1)                    \
    ASM_WORD((0b010111 << 26) | (0b0 << 25) |       \
             (0b000 << 12) | (0b1010111 << 0) |     \
             (vs2 << 20) | (vs1 << 15) | (vd << 7))



/*
 * Permute
 */

/* x[rd] = vs2[0] */
#define VMV_X_S(rd, vs2)                            \
    ASM_WORD((0b010000 << 26) | (0b1 << 25) |       \
             (0b010 << 12) | (0b1010111 << 0) |     \
             ((rd) << 7) | ((vs2) << 20))

/* vd[0] = x[rs1] */
#define VMV_S_X(vd, rs1)                            \
    ASM_WORD((0b010000 << 26) | (0b1 << 25) |       \
             (0b110 << 12) | (0b1010111 << 0) |     \
             ((vd) << 7) | ((rs1) << 15))

/* vd[shift..max] = vs2[0..max-shift]
 * Sliding up doesn't change bottom part of destination.
 */
#define VSLIDEUP_VI(vd, vs2, shift)                 \
    ASM_WORD((0b001110 << 26) | (0b1 << 25) |       \
             (0b011 << 12) | (0b1010111 << 0) |     \
             ((vd) << 7) | ((shift) << 15) | ((vs2) << 20))

/* vd[0..max-shift] = vs2[shift..max]
 * Sliding down change top part of destination.
 */
#define VSLIDEDOWN_VI(vd, vs2, shift)               \
    ASM_WORD((0b001111 << 26) | (0b1 << 25) |       \
             (0b011 << 12) | (0b1010111 << 0) |     \
             ((vd) << 7) | ((shift) << 15) | ((vs2) << 20))

/* vd[i] = vs1[vs2[i]] */
#define VRGATHER_VV(vd, vs1, vs2)                   \
    ASM_WORD((0b001100 << 26) | (0b1 << 25) |       \
             (0b000 << 12) | (0b1010111 << 0) |     \
             ((vd) << 7) | ((vs1) << 15) | ((vs2) << 20))

#define VID_V(vd)                                   \
    ASM_WORD((0b010100 << 26) | (0b1 << 25) | (0b00000 << 20) |   \
             (0b10001 << 15) | (0b010 << 12) |      \
             (0b1010111 << 0) | ((vd) << 7))


/*
 * Setting options.
 */

/* Set the options of vector instructions. */
#define VSETIVLI(rd, n, vma, vta, vsew, vlmul) \
    ASM_WORD((0b11 << 30) | (0b111 << 12) | (0b1010111 << 0) |  \
             (rd << 7) | (n << 15) | (vma << 27) |              \
             (vta << 26) | (vsew << 23) | (vlmul << 20))


#if defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) || \
    defined(WOLFSSL_RISCV_VECTOR_CRYPTO_ASM)

/*
 * Vector Bit Manipulation
 */

/* Reverse order of bytes in words of vector register. */
#define VREV8(vd, vs2) \
    ASM_WORD((0b010010 << 26) | (0b1 << 25) | (0b01001<< 15) | \
             (0b010 << 12) | (0b1010111 << 0) |                \
             (vs2 << 20) | (vd << 7))

/* Rotate left bits of vector register. */
#define VROL_VX(vd, vs2, rs) \
    ASM_WORD((0b010101 << 26) | (0b1 << 25) | (0b100 << 12) |    \
             (0b1010111 << 0) |                                  \
             (vs2 << 20) | (rs << 15) | (vd << 7))

/* Rotate right bits of vector register. */
#define VROR_VI(vd, imm, vs2) \
    ASM_WORD((0b01010 << 27) | (0b1 << 25) | (0b011 << 12) |    \
             (0b1010111 << 0) | ((imm >> 5) << 26) |            \
             (vs2 << 20) | ((imm & 0x1f) << 15) | (vd << 7))

/* Vector ANDN - vd = ~vs1 & vs2. */
#define VANDN_VV(vd, vs1, vs2) \
    ASM_WORD((0b000001 << 26) | (0b1 << 25) | (0b000 << 12) |    \
             (0b1010111 << 0) |                                  \
             (vs2 << 20) | (vs1 << 15) | (vd << 7))

#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION ||
        * WOLFSSL_RISCV_VECTOR_CRYPTO_ASM */

#endif /* WOLFSSL_RISCV_ASM */

#endif /* WOLF_CRYPT_RISCV_64_ASM_H */

