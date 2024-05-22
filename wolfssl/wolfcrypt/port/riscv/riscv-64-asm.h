/* riscv-64-asm.h
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

#endif /* WOLFSSL_RISCV_ASM */

#endif /* WOLF_CRYPT_RISCV_64_ASM_H */

