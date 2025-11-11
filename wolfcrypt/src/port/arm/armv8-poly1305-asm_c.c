/* armv8-poly1305-asm
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

#include <wolfssl/wolfcrypt/libwolfssl_sources_asm.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* Generated using (from wolfssl):
 *   cd ../scripts
 *   ruby ./poly1305/poly1305.rb arm64 \
 *       ../wolfssl/wolfcrypt/src/port/arm/armv8-poly1305-asm.c
 */
#ifdef WOLFSSL_ARMASM
#ifdef __aarch64__
#ifdef WOLFSSL_ARMASM_INLINE
#include <wolfssl/wolfcrypt/poly1305.h>

void poly1305_arm64_block_16(Poly1305* ctx, const byte* m)
{
    __asm__ __volatile__ (
        /* Load h */
        "ldp	w2, w3, [%x[ctx], #96]\n\t"
        "ldp	w4, w11, [%x[ctx], #104]\n\t"
        "ldr	w12, [%x[ctx], #112]\n\t"
        /* Load m */
        "ldr	x14, [%x[m]]\n\t"
        "ldr	x15, [%x[m], #8]\n\t"
        /* Load r */
        "ldp	x5, x6, [%x[ctx]]\n\t"
        /* h: Base26 -> Base 64 */
        "add	x2, x2, x3, lsl 26\n\t"
        "lsr	x3, x4, #12\n\t"
        "add	x2, x2, x4, lsl 52\n\t"
        "add	x3, x3, x11, lsl 14\n\t"
        "lsr	x4, x12, #24\n\t"
        "add	x3, x3, x12, lsl 40\n\t"
        /* Add m and !finished at bit 128 */
        "adds	x2, x2, x14\n\t"
        "adcs	x3, x3, x15\n\t"
        "adc	x4, x4, xzr\n\t"
        /* Multiply h by r */
        /* b[0] * a[0] */
        "mul	x7, x5, x2\n\t"
        "umulh	x8, x5, x2\n\t"
        /* b[0] * a[1] */
        "mul	x10, x5, x3\n\t"
        "umulh	x9, x5, x3\n\t"
        /* b[1] * a[0] */
        "mul	x11, x6, x2\n\t"
        "umulh	x12, x6, x2\n\t"
        "adds	x8, x8, x10\n\t"
        /* b[1] * a[1] */
        "mul	x13, x6, x3\n\t"
        "umulh	x10, x6, x3\n\t"
        "adc	x9, x9, x12\n\t"
        "adds	x8, x8, x11\n\t"
        /* b[0] * a[2] */
        "mul	x11, x5, x4\n\t"
        "adcs	x9, x9, x13\n\t"
        /* b[1] * a[2] */
        "mul	x12, x6, x4\n\t"
        "adc	x10, x10, xzr\n\t"
        "adds	x9, x9, x11\n\t"
        "adc	x10, x10, x12\n\t"
        /* Reduce mod 2^130 - 5 */
        /* Get high bits */
        "and	x11, x9, #-4\n\t"
        /* Get top two bits */
        "and	x9, x9, #3\n\t"
        /* Add top bits * 4 */
        "adds	x2, x7, x11\n\t"
        /* Move down 2 bits */
        "extr	x11, x10, x11, #2\n\t"
        "adcs	x3, x8, x10\n\t"
        "lsr	x10, x10, #2\n\t"
        "adc	x4, x9, xzr\n\t"
        /* Add top bits. */
        "adds	x2, x2, x11\n\t"
        "adcs	x3, x3, x10\n\t"
        "adc	x4, x4, xzr\n\t"
        "extr	x12, x4, x3, #40\n\t"
        "ubfx	x4, x2, #52, #12\n\t"
        "ubfx	x11, x3, #14, #26\n\t"
        "bfi	x4, x3, #12, #14\n\t"
        "ubfx	x3, x2, #26, #26\n\t"
        "ubfx	x2, x2, #0, #26\n\t"
        "stp	w2, w3, [%x[ctx], #96]\n\t"
        "stp	w4, w11, [%x[ctx], #104]\n\t"
        "str	w12, [%x[ctx], #112]\n\t"
        : [ctx] "+r" (ctx)
        : [m] "r" (m)
        : "memory", "cc", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
            "x11", "x12", "x13", "x14", "x15"
    );
}

void poly1305_arm64_blocks(Poly1305* ctx, const unsigned char* m, size_t bytes)
{
    __asm__ __volatile__ (
        "cmp	%x[bytes], #0x40\n\t"
        "b.lt	L_poly1305_arm64_blocks_done_%=\n\t"
        /* Set mask (0x3ffffff), hi bit and 5 into vector registers */
        "movi	v25.16b, #0xff\n\t"
        "movi	v27.4s, #1, lsl 24\n\t"
        "ushr	v25.4s, v25.4s, #6\n\t"
        "movi	v24.4s, #5\n\t"
        "uxtl	v26.2d, v25.2s\n\t"
        "add	x14, %x[ctx], #16\n\t"
        "ld4	{v15.4s, v16.4s, v17.4s, v18.4s}, [x14], #0x40\n\t"
        "ld1	{v19.4s}, [x14]\n\t"
        "add	x14, %x[ctx], #0x60\n\t"
        "movi	v0.4s, #0\n\t"
        "movi	v1.4s, #0\n\t"
        "movi	v2.4s, #0\n\t"
        "movi	v3.4s, #0\n\t"
        "movi	v4.4s, #0\n\t"
        "ld4	{v0.s, v1.s, v2.s, v3.s}[0], [x14], #16\n\t"
        "ld1	{v4.s}[0], [x14]\n\t"
        "mul	v20.4s, v16.4s, v24.4s\n\t"
        "mul	v21.4s, v17.4s, v24.4s\n\t"
        "mul	v22.4s, v18.4s, v24.4s\n\t"
        "mul	v23.4s, v19.4s, v24.4s\n\t"
        "\n"
    "L_poly1305_arm64_blocks_loop_64_%=: \n\t"
        /* Load message of 64 bytes - setting hi bit for not finished */
        "ld4	{v5.4s, v6.4s, v7.4s, v8.4s}, [%x[m]], #0x40\n\t"
        "sub	%x[bytes], %x[bytes], #0x40\n\t"
        "ushr	v9.4s, v8.4s, #8\n\t"
        "shl	v8.4s, v8.4s, #18\n\t"
        "orr	v9.16b, v9.16b, v27.16b\n\t"
        "sri	v8.4s, v7.4s, #14\n\t"
        "shl	v7.4s, v7.4s, #12\n\t"
        "and	v8.16b, v8.16b, v25.16b\n\t"
        "sri	v7.4s, v6.4s, #20\n\t"
        "shl	v6.4s, v6.4s, #6\n\t"
        "and	v7.16b, v7.16b, v25.16b\n\t"
        "sri	v6.4s, v5.4s, #26\n\t"
        "and	v5.16b, v5.16b, v25.16b\n\t"
        "and	v6.16b, v6.16b, v25.16b\n\t"
        "umull2	v10.2d, v5.4s, v15.4s\n\t"
        "umull2	v11.2d, v5.4s, v16.4s\n\t"
        "umull2	v12.2d, v5.4s, v17.4s\n\t"
        "umull2	v13.2d, v5.4s, v18.4s\n\t"
        "umull2	v14.2d, v5.4s, v19.4s\n\t"
        "umlal2	v10.2d, v6.4s, v23.4s\n\t"
        "umlal2	v11.2d, v6.4s, v15.4s\n\t"
        "umlal2	v12.2d, v6.4s, v16.4s\n\t"
        "umlal2	v13.2d, v6.4s, v17.4s\n\t"
        "umlal2	v14.2d, v6.4s, v18.4s\n\t"
        "umlal2	v10.2d, v7.4s, v22.4s\n\t"
        "umlal2	v11.2d, v7.4s, v23.4s\n\t"
        "umlal2	v12.2d, v7.4s, v15.4s\n\t"
        "umlal2	v13.2d, v7.4s, v16.4s\n\t"
        "umlal2	v14.2d, v7.4s, v17.4s\n\t"
        "umlal2	v10.2d, v8.4s, v21.4s\n\t"
        "umlal2	v11.2d, v8.4s, v22.4s\n\t"
        "umlal2	v12.2d, v8.4s, v23.4s\n\t"
        "umlal2	v13.2d, v8.4s, v15.4s\n\t"
        "umlal2	v14.2d, v8.4s, v16.4s\n\t"
        "umlal2	v10.2d, v9.4s, v20.4s\n\t"
        "umlal2	v11.2d, v9.4s, v21.4s\n\t"
        "umlal2	v12.2d, v9.4s, v22.4s\n\t"
        "umlal2	v13.2d, v9.4s, v23.4s\n\t"
        "umlal2	v14.2d, v9.4s, v15.4s\n\t"
        "add	v5.4s, v5.4s, v0.4s\n\t"
        "add	v6.4s, v6.4s, v1.4s\n\t"
        "add	v7.4s, v7.4s, v2.4s\n\t"
        "add	v8.4s, v8.4s, v3.4s\n\t"
        "add	v9.4s, v9.4s, v4.4s\n\t"
        "umlal	v10.2d, v5.2s, v15.2s\n\t"
        "umlal	v11.2d, v5.2s, v16.2s\n\t"
        "umlal	v12.2d, v5.2s, v17.2s\n\t"
        "umlal	v13.2d, v5.2s, v18.2s\n\t"
        "umlal	v14.2d, v5.2s, v19.2s\n\t"
        "umlal	v10.2d, v6.2s, v23.2s\n\t"
        "umlal	v11.2d, v6.2s, v15.2s\n\t"
        "umlal	v12.2d, v6.2s, v16.2s\n\t"
        "umlal	v13.2d, v6.2s, v17.2s\n\t"
        "umlal	v14.2d, v6.2s, v18.2s\n\t"
        "umlal	v10.2d, v7.2s, v22.2s\n\t"
        "umlal	v11.2d, v7.2s, v23.2s\n\t"
        "umlal	v12.2d, v7.2s, v15.2s\n\t"
        "umlal	v13.2d, v7.2s, v16.2s\n\t"
        "umlal	v14.2d, v7.2s, v17.2s\n\t"
        "umlal	v10.2d, v8.2s, v21.2s\n\t"
        "umlal	v11.2d, v8.2s, v22.2s\n\t"
        "umlal	v12.2d, v8.2s, v23.2s\n\t"
        "umlal	v13.2d, v8.2s, v15.2s\n\t"
        "umlal	v14.2d, v8.2s, v16.2s\n\t"
        "umlal	v10.2d, v9.2s, v20.2s\n\t"
        "umlal	v11.2d, v9.2s, v21.2s\n\t"
        "umlal	v12.2d, v9.2s, v22.2s\n\t"
        "umlal	v13.2d, v9.2s, v23.2s\n\t"
        "umlal	v14.2d, v9.2s, v15.2s\n\t"
        "addp	d10, v10.2d\n\t"
        "addp	d11, v11.2d\n\t"
        "addp	d12, v12.2d\n\t"
        "addp	d13, v13.2d\n\t"
        "addp	d14, v14.2d\n\t"
        /* Redistribute and handle overflow */
        "usra	v11.2d, v10.2d, #26\n\t"
        "and	v10.16b, v10.16b, v26.16b\n\t"
        "usra	v14.2d, v13.2d, #26\n\t"
        "and	v3.16b, v13.16b, v26.16b\n\t"
        "ushr	v2.2d, v14.2d, #26\n\t"
        "usra	v12.2d, v11.2d, #26\n\t"
        "shl	v0.2d, v2.2d, #2\n\t"
        "and	v1.16b, v11.16b, v26.16b\n\t"
        "add	v0.2d, v0.2d, v2.2d\n\t"
        "and	v4.16b, v14.16b, v26.16b\n\t"
        "add	v10.2d, v10.2d, v0.2d\n\t"
        "usra	v3.2d, v12.2d, #26\n\t"
        "and	v2.16b, v12.16b, v26.16b\n\t"
        "usra	v1.2d, v10.2d, #26\n\t"
        "and	v0.16b, v10.16b, v26.16b\n\t"
        "usra	v4.2d, v3.2d, #26\n\t"
        "and	v3.16b, v3.16b, v26.16b\n\t"
        "cmp	%x[bytes], #0x40\n\t"
        "b.ge	L_poly1305_arm64_blocks_loop_64_%=\n\t"
        "cmp	%x[bytes], #16\n\t"
        "b.le	L_poly1305_arm64_blocks_done_32_%=\n\t"
        /* Start 32 */
        "ld4	{v5.2s, v6.2s, v7.2s, v8.2s}, [%x[m]], #32\n\t"
        "sub	%x[bytes], %x[bytes], #32\n\t"
        "mov	v15.d[0], v15.d[1]\n\t"
        "mov	v16.d[0], v16.d[1]\n\t"
        "mov	v17.d[0], v17.d[1]\n\t"
        "mov	v18.d[0], v18.d[1]\n\t"
        "mov	v19.d[0], v19.d[1]\n\t"
        "mov	v20.d[0], v20.d[1]\n\t"
        "mov	v21.d[0], v21.d[1]\n\t"
        "mov	v22.d[0], v22.d[1]\n\t"
        "mov	v23.d[0], v23.d[1]\n\t"
        "ushr	v9.2s, v8.2s, #8\n\t"
        "shl	v8.2s, v8.2s, #18\n\t"
        "orr	v9.8b, v9.8b, v27.8b\n\t"
        "sri	v8.2s, v7.2s, #14\n\t"
        "shl	v7.2s, v7.2s, #12\n\t"
        "and	v8.8b, v8.8b, v25.8b\n\t"
        "sri	v7.2s, v6.2s, #20\n\t"
        "shl	v6.2s, v6.2s, #6\n\t"
        "and	v7.8b, v7.8b, v25.8b\n\t"
        "sri	v6.2s, v5.2s, #26\n\t"
        "and	v5.8b, v5.8b, v25.8b\n\t"
        "and	v6.8b, v6.8b, v25.8b\n\t"
        "add	v5.2s, v5.2s, v0.2s\n\t"
        "add	v6.2s, v6.2s, v1.2s\n\t"
        "add	v7.2s, v7.2s, v2.2s\n\t"
        "add	v8.2s, v8.2s, v3.2s\n\t"
        "add	v9.2s, v9.2s, v4.2s\n\t"
        "umull	v10.2d, v5.2s, v15.2s\n\t"
        "umull	v11.2d, v5.2s, v16.2s\n\t"
        "umull	v12.2d, v5.2s, v17.2s\n\t"
        "umull	v13.2d, v5.2s, v18.2s\n\t"
        "umull	v14.2d, v5.2s, v19.2s\n\t"
        "umlal	v10.2d, v6.2s, v23.2s\n\t"
        "umlal	v11.2d, v6.2s, v15.2s\n\t"
        "umlal	v12.2d, v6.2s, v16.2s\n\t"
        "umlal	v13.2d, v6.2s, v17.2s\n\t"
        "umlal	v14.2d, v6.2s, v18.2s\n\t"
        "umlal	v10.2d, v7.2s, v22.2s\n\t"
        "umlal	v11.2d, v7.2s, v23.2s\n\t"
        "umlal	v12.2d, v7.2s, v15.2s\n\t"
        "umlal	v13.2d, v7.2s, v16.2s\n\t"
        "umlal	v14.2d, v7.2s, v17.2s\n\t"
        "umlal	v10.2d, v8.2s, v21.2s\n\t"
        "umlal	v11.2d, v8.2s, v22.2s\n\t"
        "umlal	v12.2d, v8.2s, v23.2s\n\t"
        "umlal	v13.2d, v8.2s, v15.2s\n\t"
        "umlal	v14.2d, v8.2s, v16.2s\n\t"
        "umlal	v10.2d, v9.2s, v20.2s\n\t"
        "umlal	v11.2d, v9.2s, v21.2s\n\t"
        "umlal	v12.2d, v9.2s, v22.2s\n\t"
        "umlal	v13.2d, v9.2s, v23.2s\n\t"
        "umlal	v14.2d, v9.2s, v15.2s\n\t"
        "addp	d10, v10.2d\n\t"
        "addp	d11, v11.2d\n\t"
        "addp	d12, v12.2d\n\t"
        "addp	d13, v13.2d\n\t"
        "addp	d14, v14.2d\n\t"
        /* Redistribute and handle overflow */
        "usra	v11.2d, v10.2d, #26\n\t"
        "and	v10.16b, v10.16b, v26.16b\n\t"
        "usra	v14.2d, v13.2d, #26\n\t"
        "and	v3.16b, v13.16b, v26.16b\n\t"
        "ushr	v2.2d, v14.2d, #26\n\t"
        "usra	v12.2d, v11.2d, #26\n\t"
        "shl	v0.2d, v2.2d, #2\n\t"
        "and	v1.16b, v11.16b, v26.16b\n\t"
        "add	v0.2d, v0.2d, v2.2d\n\t"
        "and	v4.16b, v14.16b, v26.16b\n\t"
        "add	v10.2d, v10.2d, v0.2d\n\t"
        "usra	v3.2d, v12.2d, #26\n\t"
        "and	v2.16b, v12.16b, v26.16b\n\t"
        "usra	v1.2d, v10.2d, #26\n\t"
        "and	v0.16b, v10.16b, v26.16b\n\t"
        "usra	v4.2d, v3.2d, #26\n\t"
        "and	v3.16b, v3.16b, v26.16b\n\t"
        "\n"
    "L_poly1305_arm64_blocks_done_32_%=: \n\t"
        "cmp	%x[bytes], #16\n\t"
        "b.eq	L_poly1305_arm64_blocks_transfer_%=\n\t"
        "add	x14, %x[ctx], #0x60\n\t"
        "st4	{v0.s, v1.s, v2.s, v3.s}[0], [x14], #16\n\t"
        "st1	{v4.s}[0], [x14]\n\t"
        "b	L_poly1305_arm64_blocks_done_all_%=\n\t"
        "\n"
    "L_poly1305_arm64_blocks_transfer_%=: \n\t"
        "mov	w3, v0.s[0]\n\t"
        "mov	w4, v1.s[0]\n\t"
        "mov	w5, v2.s[0]\n\t"
        "mov	w6, v3.s[0]\n\t"
        "mov	w7, v4.s[0]\n\t"
        "b	L_poly1305_arm64_blocks_start_%=\n\t"
        "\n"
    "L_poly1305_arm64_blocks_done_%=: \n\t"
        "cmp	%x[bytes], #16\n\t"
        "b.lt	L_poly1305_arm64_blocks_done_all_%=\n\t"
        /* Load h */
        "ldp	w3, w4, [%x[ctx], #96]\n\t"
        "ldp	w5, w6, [%x[ctx], #104]\n\t"
        "ldr	w7, [%x[ctx], #112]\n\t"
        "\n"
    "L_poly1305_arm64_blocks_start_%=: \n\t"
        "mov	x17, #1\n\t"
        /* Load r */
        "ldp	x8, x9, [%x[ctx]]\n\t"
        /* Base26 -> Base 64 */
        "add	x3, x3, x4, lsl 26\n\t"
        "lsr	x4, x5, #12\n\t"
        "add	x3, x3, x5, lsl 52\n\t"
        "add	x4, x4, x6, lsl 14\n\t"
        "lsr	x5, x7, #24\n\t"
        "add	x4, x4, x7, lsl 40\n\t"
        "\n"
    "L_poly1305_arm64_blocks_loop_%=: \n\t"
        /* Load m */
        "ldr	x14, [%x[m]]\n\t"
        "ldr	x15, [%x[m], #8]\n\t"
        /* Add m and !finished at bit 128 */
        "adds	x3, x3, x14\n\t"
        "adcs	x4, x4, x15\n\t"
        "adc	x5, x5, x17\n\t"
        /* Multiply h by r */
        /* b[0] * a[0] */
        "mul	x10, x8, x3\n\t"
        "umulh	x11, x8, x3\n\t"
        /* b[0] * a[1] */
        "mul	x13, x8, x4\n\t"
        "umulh	x12, x8, x4\n\t"
        /* b[1] * a[0] */
        "mul	x14, x9, x3\n\t"
        "umulh	x15, x9, x3\n\t"
        "adds	x11, x11, x13\n\t"
        /* b[1] * a[1] */
        "mul	x16, x9, x4\n\t"
        "umulh	x13, x9, x4\n\t"
        "adc	x12, x12, x15\n\t"
        "adds	x11, x11, x14\n\t"
        /* b[0] * a[2] */
        "mul	x14, x8, x5\n\t"
        "adcs	x12, x12, x16\n\t"
        /* b[1] * a[2] */
        "mul	x15, x9, x5\n\t"
        "adc	x13, x13, xzr\n\t"
        "adds	x12, x12, x14\n\t"
        "adc	x13, x13, x15\n\t"
        /* Reduce mod 2^130 - 5 */
        /* Get high bits */
        "and	x14, x12, #-4\n\t"
        /* Get top two bits */
        "and	x12, x12, #3\n\t"
        /* Add top bits * 4 */
        "adds	x3, x10, x14\n\t"
        /* Move down 2 bits */
        "extr	x14, x13, x14, #2\n\t"
        "adcs	x4, x11, x13\n\t"
        "lsr	x13, x13, #2\n\t"
        "adc	x5, x12, xzr\n\t"
        /* Add top bits. */
        "adds	x3, x3, x14\n\t"
        "adcs	x4, x4, x13\n\t"
        "adc	x5, x5, xzr\n\t"
        /* Sub 16 from length. */
        "subs	%x[bytes], %x[bytes], #16\n\t"
        "add	%x[m], %x[m], #16\n\t"
        /* Loop again if more message to do. */
        "b.gt	L_poly1305_arm64_blocks_loop_%=\n\t"
        "extr	x7, x5, x4, #40\n\t"
        "ubfx	x5, x3, #52, #12\n\t"
        "ubfx	x6, x4, #14, #26\n\t"
        "bfi	x5, x4, #12, #14\n\t"
        "ubfx	x4, x3, #26, #26\n\t"
        "ubfx	x3, x3, #0, #26\n\t"
        "stp	w3, w4, [%x[ctx], #96]\n\t"
        "stp	w5, w6, [%x[ctx], #104]\n\t"
        "str	w7, [%x[ctx], #112]\n\t"
        "\n"
    "L_poly1305_arm64_blocks_done_all_%=: \n\t"
        : [ctx] "+r" (ctx), [bytes] "+r" (bytes)
        : [m] "r" (m)
        : "memory", "cc", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
            "x11", "x12", "x13", "x14", "x15", "x16", "x17", "v0", "v1", "v2",
            "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12",
            "v13", "v14", "v15", "v16", "v17", "v18", "v19", "v20", "v21",
            "v22", "v23", "v24", "v25", "v26", "v27"
    );
}

static const word32 L_poly1305_set_key_arm64_clamp[] = {
    0x0fffffff, 0x0ffffffc, 0x0ffffffc, 0x0ffffffc,
};

void poly1305_set_key(Poly1305* ctx, const byte* key)
{
    const word32* clamp = L_poly1305_set_key_arm64_clamp;
    __asm__ __volatile__ (
        /* Load key and pad. */
        "ldp	x11, x12, [%x[key]]\n\t"
        "ldp	x14, x15, [%x[key], #16]\n\t"
        /* Load mask. */
        "ldp	x16, x17, [%[clamp]]\n\t"
        /* Save pad for later */
        "stp	x14, x15, [%x[ctx], #120]\n\t"
        /* Apply clamp. */
        /* r &= 0x0ffffffc0ffffffc0ffffffc0fffffff */
        "and	x11, x11, x16\n\t"
        "and	x12, x12, x17\n\t"
        /* Store r - 64-bit version. */
        "stp	x11, x12, [%x[ctx]]\n\t"
        /* 128-bits: Base 64 -> Base 26 */
        "lsr	x7, x12, #40\n\t"
        "ubfx	x5, x11, #52, #12\n\t"
        "ubfx	x6, x12, #14, #26\n\t"
        "bfi	x5, x12, #12, #14\n\t"
        "ubfx	x4, x11, #26, #26\n\t"
        "ubfx	x3, x11, #0, #26\n\t"
        "stp	w3, w4, [%x[ctx], #64]\n\t"
        "stp	w5, w6, [%x[ctx], #72]\n\t"
        "str	w7, [%x[ctx], #92]\n\t"
        /* Compute r^2 */
        /* a[0] * a[0] */
        "mul	x3, x11, x11\n\t"
        "umulh	x4, x11, x11\n\t"
        /* 2 * a[0] * a[1] */
        "mul	x14, x11, x12\n\t"
        "umulh	x5, x11, x12\n\t"
        /* a[1] * a[1] */
        "mul	x15, x12, x12\n\t"
        "umulh	x6, x12, x12\n\t"
        "adds	x4, x4, x14, lsl 1\n\t"
        "extr	x5, x5, x14, #63\n\t"
        "adcs	x5, x5, x15\n\t"
        "adc	x6, x6, xzr\n\t"
        /* Reduce mod 2^130 - 5 */
        /* Get high bits */
        "and	x14, x5, #-4\n\t"
        /* Get top two bits */
        "and	x5, x5, #3\n\t"
        /* Add top bits * 4 */
        "adds	x8, x3, x14\n\t"
        /* Move down 2 bits */
        "extr	x14, x6, x14, #2\n\t"
        "adcs	x9, x4, x6\n\t"
        "lsr	x6, x6, #2\n\t"
        "adc	x10, x5, xzr\n\t"
        /* Add top bits. */
        "adds	x8, x8, x14\n\t"
        "adcs	x9, x9, x6\n\t"
        "adc	x10, x10, xzr\n\t"
        /* 130-bits: Base 64 -> Base 26 */
        "extr	x7, x10, x9, #40\n\t"
        "ubfx	x5, x8, #52, #12\n\t"
        "ubfx	x6, x9, #14, #26\n\t"
        "bfi	x5, x9, #12, #14\n\t"
        "ubfx	x4, x8, #26, #26\n\t"
        "ubfx	x3, x8, #0, #26\n\t"
        "stp	w3, w4, [%x[ctx], #48]\n\t"
        "stp	w5, w6, [%x[ctx], #56]\n\t"
        "str	w7, [%x[ctx], #88]\n\t"
        /* Compute r^3 */
        /* b[0] * a[0] */
        "mul	x3, x11, x8\n\t"
        "umulh	x4, x11, x8\n\t"
        /* b[0] * a[1] */
        "mul	x6, x11, x9\n\t"
        "umulh	x5, x11, x9\n\t"
        /* b[1] * a[0] */
        "mul	x14, x12, x8\n\t"
        "umulh	x15, x12, x8\n\t"
        "adds	x4, x4, x6\n\t"
        /* b[1] * a[1] */
        "mul	x16, x12, x9\n\t"
        "umulh	x6, x12, x9\n\t"
        "adc	x5, x5, x15\n\t"
        "adds	x4, x4, x14\n\t"
        /* b[0] * a[2] */
        "mul	x14, x11, x10\n\t"
        "adcs	x5, x5, x16\n\t"
        /* b[1] * a[2] */
        "mul	x15, x12, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x5, x5, x14\n\t"
        "adc	x6, x6, x15\n\t"
        /* Reduce mod 2^130 - 5 */
        /* Get high bits */
        "and	x14, x5, #-4\n\t"
        /* Get top two bits */
        "and	x5, x5, #3\n\t"
        /* Add top bits * 4 */
        "adds	x8, x3, x14\n\t"
        /* Move down 2 bits */
        "extr	x14, x6, x14, #2\n\t"
        "adcs	x9, x4, x6\n\t"
        "lsr	x6, x6, #2\n\t"
        "adc	x10, x5, xzr\n\t"
        /* Add top bits. */
        "adds	x8, x8, x14\n\t"
        "adcs	x9, x9, x6\n\t"
        "adc	x10, x10, xzr\n\t"
        /* 130-bits: Base 64 -> Base 26 */
        "extr	x7, x10, x9, #40\n\t"
        "ubfx	x5, x8, #52, #12\n\t"
        "ubfx	x6, x9, #14, #26\n\t"
        "bfi	x5, x9, #12, #14\n\t"
        "ubfx	x4, x8, #26, #26\n\t"
        "ubfx	x3, x8, #0, #26\n\t"
        "stp	w3, w4, [%x[ctx], #32]\n\t"
        "stp	w5, w6, [%x[ctx], #40]\n\t"
        "str	w7, [%x[ctx], #84]\n\t"
        /* Compute r^4 */
        /* b[0] * a[0] */
        "mul	x3, x11, x8\n\t"
        "umulh	x4, x11, x8\n\t"
        /* b[0] * a[1] */
        "mul	x6, x11, x9\n\t"
        "umulh	x5, x11, x9\n\t"
        /* b[1] * a[0] */
        "mul	x14, x12, x8\n\t"
        "umulh	x15, x12, x8\n\t"
        "adds	x4, x4, x6\n\t"
        /* b[1] * a[1] */
        "mul	x16, x12, x9\n\t"
        "umulh	x6, x12, x9\n\t"
        "adc	x5, x5, x15\n\t"
        "adds	x4, x4, x14\n\t"
        /* b[0] * a[2] */
        "mul	x14, x11, x10\n\t"
        "adcs	x5, x5, x16\n\t"
        /* b[1] * a[2] */
        "mul	x15, x12, x10\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x5, x5, x14\n\t"
        "adc	x6, x6, x15\n\t"
        /* Reduce mod 2^130 - 5 */
        /* Get high bits */
        "and	x14, x5, #-4\n\t"
        /* Get top two bits */
        "and	x5, x5, #3\n\t"
        /* Add top bits * 4 */
        "adds	x11, x3, x14\n\t"
        /* Move down 2 bits */
        "extr	x14, x6, x14, #2\n\t"
        "adcs	x12, x4, x6\n\t"
        "lsr	x6, x6, #2\n\t"
        "adc	x13, x5, xzr\n\t"
        /* Add top bits. */
        "adds	x11, x11, x14\n\t"
        "adcs	x12, x12, x6\n\t"
        "adc	x13, x13, xzr\n\t"
        /* 130-bits: Base 64 -> Base 26 */
        "extr	x7, x13, x12, #40\n\t"
        "ubfx	x5, x11, #52, #12\n\t"
        "ubfx	x6, x12, #14, #26\n\t"
        "bfi	x5, x12, #12, #14\n\t"
        "ubfx	x4, x11, #26, #26\n\t"
        "ubfx	x3, x11, #0, #26\n\t"
        "stp	w3, w4, [%x[ctx], #16]\n\t"
        "stp	w5, w6, [%x[ctx], #24]\n\t"
        "str	w7, [%x[ctx], #80]\n\t"
        /* h (accumulator) = 0 */
        "stp	xzr, xzr, [%x[ctx], #96]\n\t"
        "str	wzr, [%x[ctx], #112]\n\t"
        /* Zero leftover */
        "str	xzr, [%x[ctx], #136]\n\t"
        /* Zero finished */
        "strb	wzr, [%x[ctx], #160]\n\t"
        : [ctx] "+r" (ctx)
        : [key] "r" (key), [clamp] "r" (clamp)
        : "memory", "cc", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
            "x11", "x12", "x13", "x14", "x15", "x16", "x17"
    );
}

void poly1305_final(Poly1305* ctx, byte* mac)
{
    __asm__ __volatile__ (
        "ldp	x8, x9, [%x[ctx], #120]\n\t"
        "ldp	w2, w3, [%x[ctx], #96]\n\t"
        "ldp	w4, w5, [%x[ctx], #104]\n\t"
        "ldr	w6, [%x[ctx], #112]\n\t"
        "add	x2, x2, x3, lsl 26\n\t"
        "lsr	x3, x4, #12\n\t"
        "add	x2, x2, x4, lsl 52\n\t"
        "add	x3, x3, x5, lsl 14\n\t"
        "lsr	x4, x6, #24\n\t"
        "add	x3, x3, x6, lsl 40\n\t"
        /* Add 5 to h. */
        "adds	x5, x2, #5\n\t"
        "adcs	x6, x3, xzr\n\t"
        "adc	x7, x4, xzr\n\t"
        /* Check if h+5 s larger than p. */
        "cmp	x7, #3\n\t"
        "csel	x2, x5, x2, hi\n\t"
        "csel	x3, x6, x3, hi\n\t"
        /* Add padding */
        "adds	x2, x2, x8\n\t"
        "adc	x3, x3, x9\n\t"
        /* Store MAC */
        "stp	x2, x3, [%x[mac]]\n\t"
        /* Zero out h. */
        "stp	xzr, xzr, [%x[ctx], #96]\n\t"
        "str	wzr, [%x[ctx], #112]\n\t"
        /* Zero out r64. */
        "stp	xzr, xzr, [%x[ctx]]\n\t"
        /* Zero out r. */
        "stp	xzr, xzr, [%x[ctx], #16]\n\t"
        /* Zero out r_2. */
        "stp	xzr, xzr, [%x[ctx], #48]\n\t"
        "str	xzr, [%x[ctx], #64]\n\t"
        /* Zero out r_4. */
        "stp	xzr, xzr, [%x[ctx], #16]\n\t"
        "str	xzr, [%x[ctx], #32]\n\t"
        /* Zero out pad. */
        "stp	xzr, xzr, [%x[ctx], #120]\n\t"
        : [ctx] "+r" (ctx), [mac] "+r" (mac)
        :
        : "memory", "cc", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9"
    );
}

#endif /* __aarch64__ */
#endif /* WOLFSSL_ARMASM */
#endif /* WOLFSSL_ARMASM_INLINE */
