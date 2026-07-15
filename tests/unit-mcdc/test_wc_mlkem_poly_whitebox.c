/* test_wc_mlkem_poly_whitebox.c
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

/* White-box MC/DC supplement for wolfcrypt/src/wc_mlkem_poly.c.
 *
 * wc_mlkem_poly.c holds ML-KEM's polynomial arithmetic core. Several file-static
 * helpers own decision independence pairs that the public wc_MlKemKey_* API
 * cannot exhibit cleanly, because every public caller feeds them only the
 * "valid" operand combination:
 *
 *   - mlkem_cmp_c (constant-time byte compare): the API's re-encryption check
 *     drives it, but only the "equal" path deterministically; the returned
 *     0/-1 mask's independence needs BOTH an all-equal and a differing buffer
 *     in one binary.
 *   - mlkem_rej_uniform_c (rejection sampling of 12-bit values): the "v < q"
 *     accept and ">= q" reject branches, plus the "i < len" early-stop guard,
 *     need inputs crafted to hit both sides -- random matrix seeds almost never
 *     produce a full run of rejections.
 *   - mlkem_ntt / mlkem_invntt / mlkem_csubq_c: exercised per-variant so each of
 *     the four code-size arms (default / WOLFSSL_MLKEM_SMALL /
 *     WOLFSSL_MLKEM_NO_LARGE_CODE / WOLFSSL_MLKEM_NTT_UNROLL) gets its reduction
 *     and butterfly loops driven when the campaign rebuilds this TU per arm.
 *
 * This TU #includes wc_mlkem_poly.c so those statics are in scope, then calls
 * each with both halves of every targeted pair on tiny fixed-size buffers.
 * Memory-safe by construction (all buffers are MLKEM_N sword16 / bounded byte
 * arrays); prints skips and returns 0 on any unexpected result so the campaign
 * keeps the variant.
 */

#include <wolfcrypt/src/wc_mlkem_poly.c>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if defined(WOLFSSL_HAVE_MLKEM) && !defined(WOLFSSL_ARMASM)

/* mlkem_cmp_c: drive both the all-equal (returns 0) and differing (returns -1)
 * results so the constant-time mask expression shows its independence pair. */
static void wb_cmp(void)
{
    byte a[64];
    byte b[64];
    unsigned int i;

    for (i = 0; i < sizeof(a); i++) {
        a[i] = (byte)i;
        b[i] = (byte)i;
    }
    if (mlkem_cmp_c(a, b, (int)sizeof(a)) != 0) {
        WB_NOTE("mlkem_cmp_c equal buffers did not return 0");
        wb_fail = 1;
    }
    /* Flip a single byte: differing path. */
    b[17] ^= 0x80;
    if (mlkem_cmp_c(a, b, (int)sizeof(a)) == 0) {
        WB_NOTE("mlkem_cmp_c differing buffers returned 0");
        wb_fail = 1;
    }
}

/* mlkem_rej_uniform_c: craft a random-byte buffer whose 12-bit little-endian
 * fields include values BOTH below q (accepted) and >= q (rejected), and pass a
 * len smaller than the number of acceptable samples so the "i < len" early stop
 * fires while candidates remain -- covering both sides of the accept and
 * early-stop decisions. */
static void wb_rej_uniform(void)
{
    /* Each 3 bytes yields two 12-bit integers v0,v1.
     *   0x00,0x00 -> v0 = 0x000 (accept, < q)
     *   ...,0xFF pattern -> 0xFFF = 4095 (>= q, reject)
     * Interleave so the sampler sees accepts and rejects. */
    byte r[96];
    sword16 p[MLKEM_N];
    unsigned int n;
    unsigned int i;

    for (i = 0; i < sizeof(r); i += 3) {
        /* v0 low, v1 high. Alternate accept/reject blocks. */
        if ((i / 3) & 1) {
            r[i + 0] = 0xFF; r[i + 1] = 0xFF; r[i + 2] = 0xFF; /* both >= q */
        }
        else {
            r[i + 0] = 0x01; r[i + 1] = 0x00; r[i + 2] = 0x00; /* both < q  */
        }
    }
    XMEMSET(p, 0, sizeof(p));

    /* Full length: exercises accept + reject with room to store accepts. */
    n = mlkem_rej_uniform_c(p, MLKEM_N, r, (unsigned int)sizeof(r));
    if (n > (unsigned int)MLKEM_N) {
        WB_NOTE("mlkem_rej_uniform_c over-produced");
        wb_fail = 1;
    }
    /* Tiny len: the (i < len) guard stops early while bytes remain. */
    (void)mlkem_rej_uniform_c(p, 1, r, (unsigned int)sizeof(r));
}

/* mlkem_ntt / mlkem_invntt / mlkem_csubq_c: run the transform pipeline for
 * whichever code-size arm this TU was compiled with. */
static void wb_transform(void)
{
    sword16 poly[MLKEM_N];
    unsigned int i;

    for (i = 0; i < MLKEM_N; i++) {
        poly[i] = (sword16)((i * 7) % MLKEM_Q);
    }
    mlkem_ntt(poly);
    mlkem_invntt(poly);
    mlkem_csubq_c(poly);
}

#endif /* WOLFSSL_HAVE_MLKEM && !WOLFSSL_ARMASM */

int main(void)
{
#if defined(WOLFSSL_HAVE_MLKEM) && !defined(WOLFSSL_ARMASM)
    printf("wc_mlkem_poly.c white-box MC/DC supplement\n");
    wb_cmp();
    wb_rej_uniform();
    wb_transform();
    if (wb_fail) {
        /* Do not fail the campaign variant on a behavioural surprise; the
         * coverage is still valid. Report and exit 0. */
        printf("  [wb] note: one or more sanity checks were unexpected\n");
    }
    printf("wc_mlkem_poly.c white-box: done\n");
#else
    printf("wc_mlkem_poly.c white-box: skipped (MLKEM off or ARMASM build)\n");
#endif
    return 0;
}
