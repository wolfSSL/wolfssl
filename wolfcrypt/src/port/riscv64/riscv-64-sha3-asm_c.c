/* riscv-64-sha3-asm
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

#include <wolfssl/wolfcrypt/libwolfssl_sources_asm.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* Generated using (from wolfssl):
 *   cd ../scripts
 *   ruby ./sha3/sha3.rb riscv64 \
 *       ../wolfssl/wolfcrypt/src/port/riscv64/riscv-64-sha3-asm.c
 */
#ifdef WOLFSSL_RISCV_ASM
#ifdef WOLFSSL_RISCV_ASM_INLINE
#include <wolfssl/wolfcrypt/sha3.h>

#ifdef WOLFSSL_SHA3
#ifdef WOLFSSL_RISCV_VECTOR
XALIGNED(16) static const word64 L_SHA3_transform_vector_r[] = {
    0x0000000000000001UL, 0x0000000000008082UL,
    0x800000000000808aUL, 0x8000000080008000UL,
    0x000000000000808bUL, 0x0000000080000001UL,
    0x8000000080008081UL, 0x8000000000008009UL,
    0x000000000000008aUL, 0x0000000000000088UL,
    0x0000000080008009UL, 0x000000008000000aUL,
    0x000000008000808bUL, 0x800000000000008bUL,
    0x8000000000008089UL, 0x8000000000008003UL,
    0x8000000000008002UL, 0x8000000000000080UL,
    0x000000000000800aUL, 0x800000008000000aUL,
    0x8000000080008081UL, 0x8000000000008080UL,
    0x0000000080000001UL, 0x8000000080008008UL,
};

void BlockSha3(word64* s)
{
    const word64* r = L_SHA3_transform_vector_r;

    __asm__ __volatile__ (
#if defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
    "        .option arch, +v, +zvkb, +zvbb\n\t"
#else
    "        .option arch, +v\n\t"
#endif /* defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
        "vsetivli        zero, 1, e64, m1, ta, ma\n\t"
        "li      t3, 24\n\t"
        "mv      t1, %[r]\n\t"
        "mv      t2, %[s]\n\t"
        "vlseg8e64.v     v0, (t2)\n\t"
        "addi    t2, %[s], 64\n\t"
        "vlseg8e64.v     v8, (t2)\n\t"
        "addi    t2, %[s], 128\n\t"
        "vlseg8e64.v     v16, (t2)\n\t"
        "addi    t2, %[s], 192\n\t"
        "vle64.v v24, (t2)\n\t"
        "\n"
    "L_riscv_64_block_sha3_vector_loop:\n\t"
        /* COLUMN MIX */
        "vxor.vv v25, v0, v5\n\t"
        "vxor.vv v26, v1, v6\n\t"
        "vxor.vv v27, v2, v7\n\t"
        "vxor.vv v28, v3, v8\n\t"
        "vxor.vv v29, v4, v9\n\t"
        "vxor.vv v25, v25, v10\n\t"
        "vxor.vv v26, v26, v11\n\t"
        "vxor.vv v27, v27, v12\n\t"
        "vxor.vv v28, v28, v13\n\t"
        "vxor.vv v29, v29, v14\n\t"
        "vxor.vv v25, v25, v15\n\t"
        "vxor.vv v26, v26, v16\n\t"
        "vxor.vv v27, v27, v17\n\t"
        "vxor.vv v28, v28, v18\n\t"
        "vxor.vv v29, v29, v19\n\t"
        "vxor.vv v25, v25, v20\n\t"
        "vxor.vv v26, v26, v21\n\t"
        "vxor.vv v27, v27, v22\n\t"
        "vxor.vv v28, v28, v23\n\t"
        "vxor.vv v29, v29, v24\n\t"
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
        "li      t2, 63\n\t"
        "vsll.vi v31, v26, 1\n\t"
        "vsrl.vx v30, v26, t2\n\t"
        "vxor.vv v31, v31, v29\n\t"
        "vxor.vv v31, v31, v30\n\t"
        "vxor.vv v0, v0, v31\n\t"
        "vxor.vv v5, v5, v31\n\t"
        "vxor.vv v10, v10, v31\n\t"
        "vxor.vv v15, v15, v31\n\t"
        "vxor.vv v20, v20, v31\n\t"
        "vsll.vi v31, v27, 1\n\t"
        "vsrl.vx v30, v27, t2\n\t"
        "vxor.vv v31, v31, v25\n\t"
        "vxor.vv v31, v31, v30\n\t"
        "vxor.vv v1, v1, v31\n\t"
        "vxor.vv v6, v6, v31\n\t"
        "vxor.vv v11, v11, v31\n\t"
        "vxor.vv v16, v16, v31\n\t"
        "vxor.vv v21, v21, v31\n\t"
        "vsll.vi v31, v28, 1\n\t"
        "vsrl.vx v30, v28, t2\n\t"
        "vxor.vv v31, v31, v26\n\t"
        "vxor.vv v31, v31, v30\n\t"
        "vxor.vv v2, v2, v31\n\t"
        "vxor.vv v7, v7, v31\n\t"
        "vxor.vv v12, v12, v31\n\t"
        "vxor.vv v17, v17, v31\n\t"
        "vxor.vv v22, v22, v31\n\t"
        "vsll.vi v31, v29, 1\n\t"
        "vsrl.vx v30, v29, t2\n\t"
        "vxor.vv v31, v31, v27\n\t"
        "vxor.vv v31, v31, v30\n\t"
        "vxor.vv v3, v3, v31\n\t"
        "vxor.vv v8, v8, v31\n\t"
        "vxor.vv v13, v13, v31\n\t"
        "vxor.vv v18, v18, v31\n\t"
        "vxor.vv v23, v23, v31\n\t"
        "vsll.vi v31, v25, 1\n\t"
        "vsrl.vx v30, v25, t2\n\t"
        "vxor.vv v31, v31, v28\n\t"
        "vxor.vv v31, v31, v30\n\t"
        "vxor.vv v4, v4, v31\n\t"
        "vxor.vv v9, v9, v31\n\t"
        "vxor.vv v14, v14, v31\n\t"
        "vxor.vv v19, v19, v31\n\t"
        "vxor.vv v24, v24, v31\n\t"
#else
        "vror.vi v30, v26, 63\n\t"
        "vror.vi v31, v27, 63\n\t"
        "vxor.vv v30, v30, v29\n\t"
        "vxor.vv v31, v31, v25\n\t"
        "vxor.vv v0, v0, v30\n\t"
        "vxor.vv v5, v5, v30\n\t"
        "vxor.vv v10, v10, v30\n\t"
        "vxor.vv v15, v15, v30\n\t"
        "vxor.vv v20, v20, v30\n\t"
        "vxor.vv v1, v1, v31\n\t"
        "vxor.vv v6, v6, v31\n\t"
        "vxor.vv v11, v11, v31\n\t"
        "vxor.vv v16, v16, v31\n\t"
        "vxor.vv v21, v21, v31\n\t"
        "vror.vi v30, v28, 63\n\t"
        "vror.vi v31, v29, 63\n\t"
        "vror.vi v25, v25, 63\n\t"
        "vxor.vv v30, v30, v26\n\t"
        "vxor.vv v31, v31, v27\n\t"
        "vxor.vv v25, v25, v28\n\t"
        "vxor.vv v2, v2, v30\n\t"
        "vxor.vv v7, v7, v30\n\t"
        "vxor.vv v12, v12, v30\n\t"
        "vxor.vv v17, v17, v30\n\t"
        "vxor.vv v22, v22, v30\n\t"
        "vxor.vv v3, v3, v31\n\t"
        "vxor.vv v8, v8, v31\n\t"
        "vxor.vv v13, v13, v31\n\t"
        "vxor.vv v18, v18, v31\n\t"
        "vxor.vv v23, v23, v31\n\t"
        "vxor.vv v4, v4, v25\n\t"
        "vxor.vv v9, v9, v25\n\t"
        "vxor.vv v14, v14, v25\n\t"
        "vxor.vv v19, v19, v25\n\t"
        "vxor.vv v24, v24, v25\n\t"
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
        /* SWAP ROTL (rho + pi) */
        "vmv.v.v v26, v1\n\t"
        "vmv.v.v v25, v10\n\t"
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
        "li      t2, 63\n\t"
        "vsll.vi v10, v26, 1\n\t"
        "vsrl.vx v26, v26, t2\n\t"
        "vor.vv  v10, v10, v26\n\t"
#else
        "vror.vi v10, v26, 63\n\t"
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
        "vmv.v.v v26, v7\n\t"
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
        "li      t2, 61\n\t"
        "vsll.vi v7, v25, 3\n\t"
        "vsrl.vx v25, v25, t2\n\t"
        "vor.vv  v7, v7, v25\n\t"
#else
        "vror.vi v7, v25, 61\n\t"
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
        "vmv.v.v v25, v11\n\t"
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
        "li      t2, 58\n\t"
        "vsll.vi v11, v26, 6\n\t"
        "vsrl.vx v26, v26, t2\n\t"
        "vor.vv  v11, v11, v26\n\t"
#else
        "vror.vi v11, v26, 58\n\t"
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
        "vmv.v.v v26, v17\n\t"
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
        "li      t2, 54\n\t"
        "vsll.vi v17, v25, 10\n\t"
        "vsrl.vx v25, v25, t2\n\t"
        "vor.vv  v17, v17, v25\n\t"
#else
        "vror.vi v17, v25, 54\n\t"
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
        "vmv.v.v v25, v18\n\t"
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
        "li      t2, 49\n\t"
        "vsll.vi v18, v26, 15\n\t"
        "vsrl.vx v26, v26, t2\n\t"
        "vor.vv  v18, v18, v26\n\t"
#else
        "vror.vi v18, v26, 49\n\t"
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
        "vmv.v.v v26, v3\n\t"
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
        "li      t2, 43\n\t"
        "vsll.vi v3, v25, 21\n\t"
        "vsrl.vx v25, v25, t2\n\t"
        "vor.vv  v3, v3, v25\n\t"
#else
        "vror.vi v3, v25, 43\n\t"
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
        "vmv.v.v v25, v5\n\t"
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
        "li      t2, 36\n\t"
        "vsll.vi v5, v26, 28\n\t"
        "vsrl.vx v26, v26, t2\n\t"
        "vor.vv  v5, v5, v26\n\t"
#else
        "vror.vi v5, v26, 36\n\t"
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
        "vmv.v.v v26, v16\n\t"
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
        "li      t2, 36\n\t"
        "vsrl.vi v16, v25, 28\n\t"
        "vsll.vx v25, v25, t2\n\t"
        "vor.vv  v16, v16, v25\n\t"
#else
        "vror.vi v16, v25, 28\n\t"
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
        "vmv.v.v v25, v8\n\t"
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
        "li      t2, 45\n\t"
        "vsrl.vi v8, v26, 19\n\t"
        "vsll.vx v26, v26, t2\n\t"
        "vor.vv  v8, v8, v26\n\t"
#else
        "vror.vi v8, v26, 19\n\t"
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
        "vmv.v.v v26, v21\n\t"
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
        "li      t2, 55\n\t"
        "vsrl.vi v21, v25, 9\n\t"
        "vsll.vx v25, v25, t2\n\t"
        "vor.vv  v21, v21, v25\n\t"
#else
        "vror.vi v21, v25, 9\n\t"
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
        "vmv.v.v v25, v24\n\t"
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
        "li      t2, 62\n\t"
        "vsll.vi v24, v26, 2\n\t"
        "vsrl.vx v26, v26, t2\n\t"
        "vor.vv  v24, v24, v26\n\t"
#else
        "vror.vi v24, v26, 62\n\t"
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
        "vmv.v.v v26, v4\n\t"
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
        "li      t2, 50\n\t"
        "vsll.vi v4, v25, 14\n\t"
        "vsrl.vx v25, v25, t2\n\t"
        "vor.vv  v4, v4, v25\n\t"
#else
        "vror.vi v4, v25, 50\n\t"
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
        "vmv.v.v v25, v15\n\t"
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
        "li      t2, 37\n\t"
        "vsll.vi v15, v26, 27\n\t"
        "vsrl.vx v26, v26, t2\n\t"
        "vor.vv  v15, v15, v26\n\t"
#else
        "vror.vi v15, v26, 37\n\t"
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
        "vmv.v.v v26, v23\n\t"
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
        "li      t2, 41\n\t"
        "vsrl.vi v23, v25, 23\n\t"
        "vsll.vx v25, v25, t2\n\t"
        "vor.vv  v23, v23, v25\n\t"
#else
        "vror.vi v23, v25, 23\n\t"
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
        "vmv.v.v v25, v19\n\t"
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
        "li      t2, 56\n\t"
        "vsrl.vi v19, v26, 8\n\t"
        "vsll.vx v26, v26, t2\n\t"
        "vor.vv  v19, v19, v26\n\t"
#else
        "vror.vi v19, v26, 8\n\t"
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
        "vmv.v.v v26, v13\n\t"
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
        "li      t2, 56\n\t"
        "vsll.vi v13, v25, 8\n\t"
        "vsrl.vx v25, v25, t2\n\t"
        "vor.vv  v13, v13, v25\n\t"
#else
        "vror.vi v13, v25, 56\n\t"
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
        "vmv.v.v v25, v12\n\t"
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
        "li      t2, 39\n\t"
        "vsll.vi v12, v26, 25\n\t"
        "vsrl.vx v26, v26, t2\n\t"
        "vor.vv  v12, v12, v26\n\t"
#else
        "vror.vi v12, v26, 39\n\t"
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
        "vmv.v.v v26, v2\n\t"
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
        "li      t2, 43\n\t"
        "vsrl.vi v2, v25, 21\n\t"
        "vsll.vx v25, v25, t2\n\t"
        "vor.vv  v2, v2, v25\n\t"
#else
        "vror.vi v2, v25, 21\n\t"
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
        "vmv.v.v v25, v20\n\t"
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
        "li      t2, 62\n\t"
        "vsrl.vi v20, v26, 2\n\t"
        "vsll.vx v26, v26, t2\n\t"
        "vor.vv  v20, v20, v26\n\t"
#else
        "vror.vi v20, v26, 2\n\t"
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
        "vmv.v.v v26, v14\n\t"
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
        "li      t2, 46\n\t"
        "vsll.vi v14, v25, 18\n\t"
        "vsrl.vx v25, v25, t2\n\t"
        "vor.vv  v14, v14, v25\n\t"
#else
        "vror.vi v14, v25, 46\n\t"
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
        "vmv.v.v v25, v22\n\t"
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
        "li      t2, 39\n\t"
        "vsrl.vi v22, v26, 25\n\t"
        "vsll.vx v26, v26, t2\n\t"
        "vor.vv  v22, v22, v26\n\t"
#else
        "vror.vi v22, v26, 25\n\t"
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
        "vmv.v.v v26, v9\n\t"
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
        "li      t2, 61\n\t"
        "vsrl.vi v9, v25, 3\n\t"
        "vsll.vx v25, v25, t2\n\t"
        "vor.vv  v9, v9, v25\n\t"
#else
        "vror.vi v9, v25, 3\n\t"
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
        "vmv.v.v v25, v6\n\t"
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
        "li      t2, 44\n\t"
        "vsll.vi v6, v26, 20\n\t"
        "vsrl.vx v26, v26, t2\n\t"
        "vor.vv  v6, v6, v26\n\t"
#else
        "vror.vi v6, v26, 44\n\t"
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
        "li      t2, 44\n\t"
        "vsrl.vi v1, v25, 20\n\t"
        "vsll.vx v25, v25, t2\n\t"
        "vor.vv  v1, v1, v25\n\t"
        /* ROW MIX (chi) */
        "vmv.v.v v25, v0\n\t"
        "vmv.v.v v26, v1\n\t"
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
        "vnot.v  v30, v1\n\t"
        "vnot.v  v31, v2\n\t"
        "vand.vv v30, v30, v2\n\t"
        "vand.vv v31, v31, v3\n\t"
        "vxor.vv v0, v30, v0\n\t"
        "vxor.vv v1, v31, v1\n\t"
        "vnot.v  v30, v3\n\t"
        "vnot.v  v31, v4\n\t"
        "vand.vv v30, v30, v4\n\t"
        "vand.vv v31, v31, v25\n\t"
        "vnot.v  v25, v25\n\t"
        "vxor.vv v2, v30, v2\n\t"
        "vand.vv v25, v25, v26\n\t"
        "vxor.vv v3, v31, v3\n\t"
        "vxor.vv v4, v25, v4\n\t"
#else
        "vandn.vv        v30, v2, v1\n\t"
        "vandn.vv        v31, v3, v2\n\t"
        "vxor.vv v0, v30, v0\n\t"
        "vxor.vv v1, v31, v1\n\t"
        "vandn.vv        v30, v4, v3\n\t"
        "vandn.vv        v31, v25, v4\n\t"
        "vandn.vv        v25, v26, v25\n\t"
        "vxor.vv v2, v30, v2\n\t"
        "vxor.vv v3, v31, v3\n\t"
        "vxor.vv v4, v25, v4\n\t"
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
        "vmv.v.v v25, v5\n\t"
        "vmv.v.v v26, v6\n\t"
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
        "vnot.v  v30, v6\n\t"
        "vnot.v  v31, v7\n\t"
        "vand.vv v30, v30, v7\n\t"
        "vand.vv v31, v31, v8\n\t"
        "vxor.vv v5, v30, v5\n\t"
        "vxor.vv v6, v31, v6\n\t"
        "vnot.v  v30, v8\n\t"
        "vnot.v  v31, v9\n\t"
        "vand.vv v30, v30, v9\n\t"
        "vand.vv v31, v31, v25\n\t"
        "vnot.v  v25, v25\n\t"
        "vxor.vv v7, v30, v7\n\t"
        "vand.vv v25, v25, v26\n\t"
        "vxor.vv v8, v31, v8\n\t"
        "vxor.vv v9, v25, v9\n\t"
#else
        "vandn.vv        v30, v7, v6\n\t"
        "vandn.vv        v31, v8, v7\n\t"
        "vxor.vv v5, v30, v5\n\t"
        "vxor.vv v6, v31, v6\n\t"
        "vandn.vv        v30, v9, v8\n\t"
        "vandn.vv        v31, v25, v9\n\t"
        "vandn.vv        v25, v26, v25\n\t"
        "vxor.vv v7, v30, v7\n\t"
        "vxor.vv v8, v31, v8\n\t"
        "vxor.vv v9, v25, v9\n\t"
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
        "vmv.v.v v25, v10\n\t"
        "vmv.v.v v26, v11\n\t"
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
        "vnot.v  v30, v11\n\t"
        "vnot.v  v31, v12\n\t"
        "vand.vv v30, v30, v12\n\t"
        "vand.vv v31, v31, v13\n\t"
        "vxor.vv v10, v30, v10\n\t"
        "vxor.vv v11, v31, v11\n\t"
        "vnot.v  v30, v13\n\t"
        "vnot.v  v31, v14\n\t"
        "vand.vv v30, v30, v14\n\t"
        "vand.vv v31, v31, v25\n\t"
        "vnot.v  v25, v25\n\t"
        "vxor.vv v12, v30, v12\n\t"
        "vand.vv v25, v25, v26\n\t"
        "vxor.vv v13, v31, v13\n\t"
        "vxor.vv v14, v25, v14\n\t"
#else
        "vandn.vv        v30, v12, v11\n\t"
        "vandn.vv        v31, v13, v12\n\t"
        "vxor.vv v10, v30, v10\n\t"
        "vxor.vv v11, v31, v11\n\t"
        "vandn.vv        v30, v14, v13\n\t"
        "vandn.vv        v31, v25, v14\n\t"
        "vandn.vv        v25, v26, v25\n\t"
        "vxor.vv v12, v30, v12\n\t"
        "vxor.vv v13, v31, v13\n\t"
        "vxor.vv v14, v25, v14\n\t"
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
        "vmv.v.v v25, v15\n\t"
        "vmv.v.v v26, v16\n\t"
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
        "vnot.v  v30, v16\n\t"
        "vnot.v  v31, v17\n\t"
        "vand.vv v30, v30, v17\n\t"
        "vand.vv v31, v31, v18\n\t"
        "vxor.vv v15, v30, v15\n\t"
        "vxor.vv v16, v31, v16\n\t"
        "vnot.v  v30, v18\n\t"
        "vnot.v  v31, v19\n\t"
        "vand.vv v30, v30, v19\n\t"
        "vand.vv v31, v31, v25\n\t"
        "vnot.v  v25, v25\n\t"
        "vxor.vv v17, v30, v17\n\t"
        "vand.vv v25, v25, v26\n\t"
        "vxor.vv v18, v31, v18\n\t"
        "vxor.vv v19, v25, v19\n\t"
#else
        "vandn.vv        v30, v17, v16\n\t"
        "vandn.vv        v31, v18, v17\n\t"
        "vxor.vv v15, v30, v15\n\t"
        "vxor.vv v16, v31, v16\n\t"
        "vandn.vv        v30, v19, v18\n\t"
        "vandn.vv        v31, v25, v19\n\t"
        "vandn.vv        v25, v26, v25\n\t"
        "vxor.vv v17, v30, v17\n\t"
        "vxor.vv v18, v31, v18\n\t"
        "vxor.vv v19, v25, v19\n\t"
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
        "vmv.v.v v25, v20\n\t"
        "vmv.v.v v26, v21\n\t"
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
        "vnot.v  v30, v21\n\t"
        "vnot.v  v31, v22\n\t"
        "vand.vv v30, v30, v22\n\t"
        "vand.vv v31, v31, v23\n\t"
        "vxor.vv v20, v30, v20\n\t"
        "vxor.vv v21, v31, v21\n\t"
        "vnot.v  v30, v23\n\t"
        "vnot.v  v31, v24\n\t"
        "vand.vv v30, v30, v24\n\t"
        "vand.vv v31, v31, v25\n\t"
        "vnot.v  v25, v25\n\t"
        "vxor.vv v22, v30, v22\n\t"
        "vand.vv v25, v25, v26\n\t"
        "vxor.vv v23, v31, v23\n\t"
        "vxor.vv v24, v25, v24\n\t"
#else
        "vandn.vv        v30, v22, v21\n\t"
        "vandn.vv        v31, v23, v22\n\t"
        "vxor.vv v20, v30, v20\n\t"
        "vxor.vv v21, v31, v21\n\t"
        "vandn.vv        v30, v24, v23\n\t"
        "vandn.vv        v31, v25, v24\n\t"
        "vandn.vv        v25, v26, v25\n\t"
        "vxor.vv v22, v30, v22\n\t"
        "vxor.vv v23, v31, v23\n\t"
        "vxor.vv v24, v25, v24\n\t"
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
        /* IOTA (round constant) */
        "vl1re64.v       v25, (t1)\n\t"
        "addi    t1, t1, 8\n\t"
        "addi    t3, t3, -1\n\t"
        "vxor.vv v0, v0, v25\n\t"
        "bnez    t3, L_riscv_64_block_sha3_vector_loop\n\t"
        "mv      t2, %[s]\n\t"
        "vsseg8e64.v     v0, (t2)\n\t"
        "addi    t2, %[s], 64\n\t"
        "vsseg8e64.v     v8, (t2)\n\t"
        "addi    t2, %[s], 128\n\t"
        "vsseg8e64.v     v16, (t2)\n\t"
        "addi    t2, %[s], 192\n\t"
        "vse64.v v24, (t2)\n\t"
        : [s] "+r" (s)
        : [r] "r" (r)
        : "memory", "t1", "t2", "t3"
#ifdef WOLFSSL_RISCV_VECTOR
        , "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11",
            "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19", "v20",
            "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29",
            "v30", "v31"
#endif /* WOLFSSL_RISCV_VECTOR */
    );
}

#else
XALIGNED(16) static const word64 L_SHA3_transform_riscv_r[] = {
    0x0000000000000001UL, 0x0000000000008082UL,
    0x800000000000808aUL, 0x8000000080008000UL,
    0x000000000000808bUL, 0x0000000080000001UL,
    0x8000000080008081UL, 0x8000000000008009UL,
    0x000000000000008aUL, 0x0000000000000088UL,
    0x0000000080008009UL, 0x000000008000000aUL,
    0x000000008000808bUL, 0x800000000000008bUL,
    0x8000000000008089UL, 0x8000000000008003UL,
    0x8000000000008002UL, 0x8000000000000080UL,
    0x000000000000800aUL, 0x800000008000000aUL,
    0x8000000080008081UL, 0x8000000000008080UL,
    0x0000000080000001UL, 0x8000000080008008UL,
};

void BlockSha3(word64* s)
{
    const word64* r = L_SHA3_transform_riscv_r;

    __asm__ __volatile__ (
        "addi    sp, sp, -32\n\t"
        "li      s0, 24\n\t"
        "ld      t1, 0(%[s])\n\t"
        "ld      t2, 8(%[s])\n\t"
        "ld      t3, 16(%[s])\n\t"
        "ld      t4, 24(%[s])\n\t"
        "ld      t5, 32(%[s])\n\t"
        "ld      t6, 40(%[s])\n\t"
        "ld      a1, 48(%[s])\n\t"
        "ld      a2, 56(%[s])\n\t"
        "ld      a3, 64(%[s])\n\t"
        "ld      a4, 72(%[s])\n\t"
        "ld      a5, 80(%[s])\n\t"
        "ld      a6, 88(%[s])\n\t"
        "ld      a7, 96(%[s])\n\t"
        "ld      s1, 104(%[s])\n\t"
        "ld      s2, 112(%[s])\n\t"
        "ld      s3, 120(%[s])\n\t"
        "ld      s4, 128(%[s])\n\t"
        "ld      s5, 136(%[s])\n\t"
        "ld      s6, 144(%[s])\n\t"
        "ld      s7, 152(%[s])\n\t"
        "ld      s8, 160(%[s])\n\t"
        "ld      s9, 168(%[s])\n\t"
        "ld      s10, 176(%[s])\n\t"
        "\n"
    "L_riscv_64_block_sha3_loop_%=:\n\t"
        "sd      s0, 16(sp)\n\t"
        /* COLUMN MIX */
        "ld      s11, 184(%[s])\n\t"
        "ld      s0, 192(%[s])\n\t"
        "xor     s8, s8, t1\n\t"
        "xor     s9, s9, t2\n\t"
        "xor     s10, s10, t3\n\t"
        "xor     s11, s11, t4\n\t"
        "xor     s0, s0, t5\n\t"
        "xor     s8, s8, t6\n\t"
        "xor     s9, s9, a1\n\t"
        "xor     s10, s10, a2\n\t"
        "xor     s11, s11, a3\n\t"
        "xor     s0, s0, a4\n\t"
        "xor     s8, s8, a5\n\t"
        "xor     s9, s9, a6\n\t"
        "xor     s10, s10, a7\n\t"
        "xor     s11, s11, s1\n\t"
        "xor     s0, s0, s2\n\t"
        "xor     s8, s8, s3\n\t"
        "xor     s9, s9, s4\n\t"
        "xor     s10, s10, s5\n\t"
        "xor     s11, s11, s6\n\t"
        "xor     s0, s0, s7\n\t"
        "sd      s9, 0(sp)\n\t"
        "sd      s11, 8(sp)\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "srli    s11, s9, 63\n\t"
        "slli    s9, s9, 1\n\t"
        "or      s9, s9, s11\n\t"
#else
        /* rori s9, s9, 63 */
        ".word   0x63fcdc93\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "ld      s11, 160(%[s])\n\t"
        "xor     s9, s9, s0\n\t"
        "xor     t1, t1, s9\n\t"
        "xor     t6, t6, s9\n\t"
        "xor     s11, s11, s9\n\t"
        "xor     a5, a5, s9\n\t"
        "xor     s3, s3, s9\n\t"
        "sd      s11, 160(%[s])\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "srli    s11, s10, 63\n\t"
        "slli    s9, s10, 1\n\t"
        "or      s9, s9, s11\n\t"
#else
        /* rori s9, s10, 63 */
        ".word   0x63fd5c93\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "ld      s11, 168(%[s])\n\t"
        "xor     s9, s9, s8\n\t"
        "xor     t2, t2, s9\n\t"
        "xor     a1, a1, s9\n\t"
        "xor     s11, s11, s9\n\t"
        "xor     a6, a6, s9\n\t"
        "xor     s4, s4, s9\n\t"
        "sd      s11, 168(%[s])\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "srli    s11, s0, 63\n\t"
        "slli    s0, s0, 1\n\t"
        "or      s0, s0, s11\n\t"
#else
        /* rori s0, s0, 63 */
        ".word   0x63f45413\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "ld      s11, 184(%[s])\n\t"
        "xor     s0, s0, s10\n\t"
        "xor     t4, t4, s0\n\t"
        "xor     a3, a3, s0\n\t"
        "xor     s11, s11, s0\n\t"
        "xor     s1, s1, s0\n\t"
        "xor     s6, s6, s0\n\t"
        "sd      s11, 184(%[s])\n\t"
        "ld      s11, 8(sp)\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "srli    s10, s8, 63\n\t"
        "slli    s8, s8, 1\n\t"
        "or      s8, s8, s10\n\t"
#else
        /* rori s8, s8, 63 */
        ".word   0x63fc5c13\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "ld      s0, 192(%[s])\n\t"
        "xor     s8, s8, s11\n\t"
        "xor     t5, t5, s8\n\t"
        "xor     a4, a4, s8\n\t"
        "xor     s0, s0, s8\n\t"
        "xor     s2, s2, s8\n\t"
        "xor     s7, s7, s8\n\t"
        "ld      s9, 0(sp)\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "srli    s10, s11, 63\n\t"
        "slli    s11, s11, 1\n\t"
        "or      s11, s11, s10\n\t"
#else
        /* rori s11, s11, 63 */
        ".word   0x63fddd93\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "ld      s10, 176(%[s])\n\t"
        "xor     s11, s11, s9\n\t"
        "xor     t3, t3, s11\n\t"
        "xor     a2, a2, s11\n\t"
        "xor     s10, s10, s11\n\t"
        "xor     a7, a7, s11\n\t"
        "xor     s5, s5, s11\n\t"
        /* SWAP ROTL (rho + pi) */
        "mv      s8, a5\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "srli    s9, t2, 63\n\t"
        "slli    a5, t2, 1\n\t"
        "or      a5, a5, s9\n\t"
#else
        /* rori a5, t2, 63 */
        ".word   0x63f3d793\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "mv      s9, a2\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "srli    a2, s8, 61\n\t"
        "slli    s8, s8, 3\n\t"
        "or      a2, a2, s8\n\t"
#else
        /* rori a2, s8, 61 */
        ".word   0x63dc5613\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "mv      s8, a6\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "srli    a6, s9, 58\n\t"
        "slli    s9, s9, 6\n\t"
        "or      a6, a6, s9\n\t"
#else
        /* rori a6, s9, 58 */
        ".word   0x63acd813\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "mv      s9, s5\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "srli    s5, s8, 54\n\t"
        "slli    s8, s8, 10\n\t"
        "or      s5, s5, s8\n\t"
#else
        /* rori s5, s8, 54 */
        ".word   0x636c5a93\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "mv      s8, s6\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "srli    s6, s9, 49\n\t"
        "slli    s9, s9, 15\n\t"
        "or      s6, s6, s9\n\t"
#else
        /* rori s6, s9, 49 */
        ".word   0x631cdb13\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "mv      s9, t4\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "srli    t4, s8, 43\n\t"
        "slli    s8, s8, 21\n\t"
        "or      t4, t4, s8\n\t"
#else
        /* rori t4, s8, 43 */
        ".word   0x62bc5e93\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "mv      s8, t6\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "srli    t6, s9, 36\n\t"
        "slli    s9, s9, 28\n\t"
        "or      t6, t6, s9\n\t"
#else
        /* rori t6, s9, 36 */
        ".word   0x624cdf93\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "mv      s9, s4\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "srli    s4, s8, 28\n\t"
        "slli    s8, s8, 36\n\t"
        "or      s4, s4, s8\n\t"
#else
        /* rori s4, s8, 28 */
        ".word   0x61cc5a13\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "mv      s8, a3\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "srli    a3, s9, 19\n\t"
        "slli    s9, s9, 45\n\t"
        "or      a3, a3, s9\n\t"
#else
        /* rori a3, s9, 19 */
        ".word   0x613cd693\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "ld      s9, 168(%[s])\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "srli    s11, s8, 9\n\t"
        "slli    s8, s8, 55\n\t"
        "or      s8, s8, s11\n\t"
#else
        /* rori s8, s8, 9 */
        ".word   0x609c5c13\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "sd      s8, 168(%[s])\n\t"
        "mv      s8, s0\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "srli    s0, s9, 62\n\t"
        "slli    s9, s9, 2\n\t"
        "or      s0, s0, s9\n\t"
#else
        /* rori s0, s9, 62 */
        ".word   0x63ecd413\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "mv      s9, t5\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "srli    t5, s8, 50\n\t"
        "slli    s8, s8, 14\n\t"
        "or      t5, t5, s8\n\t"
#else
        /* rori t5, s8, 50 */
        ".word   0x632c5f13\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "mv      s8, s3\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "srli    s3, s9, 37\n\t"
        "slli    s9, s9, 27\n\t"
        "or      s3, s3, s9\n\t"
#else
        /* rori s3, s9, 37 */
        ".word   0x625cd993\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "ld      s9, 184(%[s])\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "srli    s11, s8, 23\n\t"
        "slli    s8, s8, 41\n\t"
        "or      s8, s8, s11\n\t"
#else
        /* rori s8, s8, 23 */
        ".word   0x617c5c13\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "sd      s8, 184(%[s])\n\t"
        "mv      s8, s7\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "srli    s7, s9, 8\n\t"
        "slli    s9, s9, 56\n\t"
        "or      s7, s7, s9\n\t"
#else
        /* rori s7, s9, 8 */
        ".word   0x608cdb93\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "mv      s9, s1\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "srli    s1, s8, 56\n\t"
        "slli    s8, s8, 8\n\t"
        "or      s1, s1, s8\n\t"
#else
        /* rori s1, s8, 56 */
        ".word   0x638c5493\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "mv      s8, a7\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "srli    a7, s9, 39\n\t"
        "slli    s9, s9, 25\n\t"
        "or      a7, a7, s9\n\t"
#else
        /* rori a7, s9, 39 */
        ".word   0x627cd893\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "mv      s9, t3\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "srli    t3, s8, 21\n\t"
        "slli    s8, s8, 43\n\t"
        "or      t3, t3, s8\n\t"
#else
        /* rori t3, s8, 21 */
        ".word   0x615c5e13\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "ld      s8, 160(%[s])\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "srli    s11, s9, 2\n\t"
        "slli    s9, s9, 62\n\t"
        "or      s9, s9, s11\n\t"
#else
        /* rori s9, s9, 2 */
        ".word   0x602cdc93\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "sd      s9, 160(%[s])\n\t"
        "mv      s9, s2\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "srli    s2, s8, 46\n\t"
        "slli    s8, s8, 18\n\t"
        "or      s2, s2, s8\n\t"
#else
        /* rori s2, s8, 46 */
        ".word   0x62ec5913\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "mv      s8, s10\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "srli    s10, s9, 25\n\t"
        "slli    s9, s9, 39\n\t"
        "or      s10, s10, s9\n\t"
#else
        /* rori s10, s9, 25 */
        ".word   0x619cdd13\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "mv      s9, a4\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "srli    a4, s8, 3\n\t"
        "slli    s8, s8, 61\n\t"
        "or      a4, a4, s8\n\t"
#else
        /* rori a4, s8, 3 */
        ".word   0x603c5713\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "mv      s8, a1\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "srli    a1, s9, 44\n\t"
        "slli    s9, s9, 20\n\t"
        "or      a1, a1, s9\n\t"
#else
        /* rori a1, s9, 44 */
        ".word   0x62ccd593\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "srli    t2, s8, 20\n\t"
        "slli    s8, s8, 44\n\t"
        "or      t2, t2, s8\n\t"
#else
        /* rori t2, s8, 20 */
        ".word   0x614c5393\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        /* ROW MIX (chi) */
        "mv      s8, t1\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "not     s11, t2\n\t"
        "and     s11, s11, t3\n\t"
#else
        /* andn s11, t3, t2 */
        ".word   0x407e7db3\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "xor     t1, t1, s11\n\t"
        "mv      s9, t2\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "not     s11, t3\n\t"
        "and     s11, s11, t4\n\t"
#else
        /* andn s11, t4, t3 */
        ".word   0x41cefdb3\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "xor     t2, t2, s11\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "not     s11, t4\n\t"
        "and     s11, s11, t5\n\t"
#else
        /* andn s11, t5, t4 */
        ".word   0x41df7db3\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "xor     t3, t3, s11\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "not     s11, t5\n\t"
        "and     s11, s11, s8\n\t"
#else
        /* andn s11, s8, t5 */
        ".word   0x41ec7db3\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "xor     t4, t4, s11\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "not     s11, s8\n\t"
        "and     s11, s11, s9\n\t"
#else
        /* andn s11, s9, s8 */
        ".word   0x418cfdb3\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "xor     t5, t5, s11\n\t"
        "mv      s8, t6\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "not     s11, a1\n\t"
        "and     s11, s11, a2\n\t"
#else
        /* andn s11, a2, a1 */
        ".word   0x40b67db3\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "xor     t6, t6, s11\n\t"
        "mv      s9, a1\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "not     s11, a2\n\t"
        "and     s11, s11, a3\n\t"
#else
        /* andn s11, a3, a2 */
        ".word   0x40c6fdb3\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "xor     a1, a1, s11\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "not     s11, a3\n\t"
        "and     s11, s11, a4\n\t"
#else
        /* andn s11, a4, a3 */
        ".word   0x40d77db3\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "xor     a2, a2, s11\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "not     s11, a4\n\t"
        "and     s11, s11, s8\n\t"
#else
        /* andn s11, s8, a4 */
        ".word   0x40ec7db3\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "xor     a3, a3, s11\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "not     s11, s8\n\t"
        "and     s11, s11, s9\n\t"
#else
        /* andn s11, s9, s8 */
        ".word   0x418cfdb3\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "xor     a4, a4, s11\n\t"
        "mv      s8, a5\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "not     s11, a6\n\t"
        "and     s11, s11, a7\n\t"
#else
        /* andn s11, a7, a6 */
        ".word   0x4108fdb3\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "xor     a5, a5, s11\n\t"
        "mv      s9, a6\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "not     s11, a7\n\t"
        "and     s11, s11, s1\n\t"
#else
        /* andn s11, s1, a7 */
        ".word   0x4114fdb3\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "xor     a6, a6, s11\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "not     s11, s1\n\t"
        "and     s11, s11, s2\n\t"
#else
        /* andn s11, s2, s1 */
        ".word   0x40997db3\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "xor     a7, a7, s11\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "not     s11, s2\n\t"
        "and     s11, s11, s8\n\t"
#else
        /* andn s11, s8, s2 */
        ".word   0x412c7db3\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "xor     s1, s1, s11\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "not     s11, s8\n\t"
        "and     s11, s11, s9\n\t"
#else
        /* andn s11, s9, s8 */
        ".word   0x418cfdb3\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "xor     s2, s2, s11\n\t"
        "mv      s8, s3\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "not     s11, s4\n\t"
        "and     s11, s11, s5\n\t"
#else
        /* andn s11, s5, s4 */
        ".word   0x414afdb3\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "xor     s3, s3, s11\n\t"
        "mv      s9, s4\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "not     s11, s5\n\t"
        "and     s11, s11, s6\n\t"
#else
        /* andn s11, s6, s5 */
        ".word   0x415b7db3\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "xor     s4, s4, s11\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "not     s11, s6\n\t"
        "and     s11, s11, s7\n\t"
#else
        /* andn s11, s7, s6 */
        ".word   0x416bfdb3\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "xor     s5, s5, s11\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "not     s11, s7\n\t"
        "and     s11, s11, s8\n\t"
#else
        /* andn s11, s8, s7 */
        ".word   0x417c7db3\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "xor     s6, s6, s11\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "not     s11, s8\n\t"
        "and     s11, s11, s9\n\t"
#else
        /* andn s11, s9, s8 */
        ".word   0x418cfdb3\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "xor     s7, s7, s11\n\t"
        "sd      s3, 120(%[s])\n\t"
        "sd      s4, 128(%[s])\n\t"
        "sd      s5, 136(%[s])\n\t"
        "ld      s8, 160(%[s])\n\t"
        "ld      s9, 168(%[s])\n\t"
        "ld      s11, 184(%[s])\n\t"
        "mv      s3, s8\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "not     s5, s9\n\t"
        "and     s5, s5, s10\n\t"
#else
        /* andn s5, s10, s9 */
        ".word   0x419d7ab3\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "xor     s8, s8, s5\n\t"
        "mv      s4, s9\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "not     s5, s10\n\t"
        "and     s5, s5, s11\n\t"
#else
        /* andn s5, s11, s10 */
        ".word   0x41adfab3\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "xor     s9, s9, s5\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "not     s5, s11\n\t"
        "and     s5, s5, s0\n\t"
#else
        /* andn s5, s0, s11 */
        ".word   0x41b47ab3\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "xor     s10, s10, s5\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "not     s5, s0\n\t"
        "and     s5, s5, s3\n\t"
#else
        /* andn s5, s3, s0 */
        ".word   0x4089fab3\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "xor     s11, s11, s5\n\t"
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
        "not     s5, s3\n\t"
        "and     s5, s5, s4\n\t"
#else
        /* andn s5, s4, s3 */
        ".word   0x413a7ab3\n\t"
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
        "xor     s0, s0, s5\n\t"
        "ld      s3, 120(%[s])\n\t"
        "ld      s4, 128(%[s])\n\t"
        "ld      s5, 136(%[s])\n\t"
        "sd      s8, 160(%[s])\n\t"
        "sd      s9, 168(%[s])\n\t"
        "sd      s10, 176(%[s])\n\t"
        "sd      s11, 184(%[s])\n\t"
        "sd      s0, 192(%[s])\n\t"
        /* IOTA (round constant) */
        "ld      s0, 16(sp)\n\t"
        "ld      s11, 0(%[r])\n\t"
        "addi    %[r], %[r], 8\n\t"
        "addi    s0, s0, -1\n\t"
        "xor     t1, t1, s11\n\t"
        "bnez    s0, L_riscv_64_block_sha3_loop_%=\n\t"
        "sd      t1, 0(%[s])\n\t"
        "sd      t2, 8(%[s])\n\t"
        "sd      t3, 16(%[s])\n\t"
        "sd      t4, 24(%[s])\n\t"
        "sd      t5, 32(%[s])\n\t"
        "sd      t6, 40(%[s])\n\t"
        "sd      a1, 48(%[s])\n\t"
        "sd      a2, 56(%[s])\n\t"
        "sd      a3, 64(%[s])\n\t"
        "sd      a4, 72(%[s])\n\t"
        "sd      a5, 80(%[s])\n\t"
        "sd      a6, 88(%[s])\n\t"
        "sd      a7, 96(%[s])\n\t"
        "sd      s1, 104(%[s])\n\t"
        "sd      s2, 112(%[s])\n\t"
        "sd      s3, 120(%[s])\n\t"
        "sd      s4, 128(%[s])\n\t"
        "sd      s5, 136(%[s])\n\t"
        "sd      s6, 144(%[s])\n\t"
        "sd      s7, 152(%[s])\n\t"
        "addi    sp, sp, 32\n\t"
        : [s] "+r" (s)
        : [r] "r" (r)
        : "memory", "t1", "t2", "t3", "t4", "t5", "t6", "a1", "a2", "a3", "a4",
            "a5", "a6", "a7", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8",
            "s9", "s10", "s11", "s0"
    );
}

#endif /* WOLFSSL_RISCV_VECTOR */
#endif /* WOLFSSL_SHA3 */
#endif /* WOLFSSL_RISCV_ASM_INLINE */
#endif /* WOLFSSL_RISCV_ASM */
