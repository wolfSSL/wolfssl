/* test_puf_gf_whitebox.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

/*
 * MC/DC white-box supplement for wolfcrypt/src/puf.c -- the GF(2^7) helper.
 *
 * Closes puf.c 123:0, the last open condition in the module:
 *
 *     static WC_INLINE byte gf_mul(byte a, byte b)
 *     {
 *         if (a == 0 || b == 0)
 *             return 0;
 *
 * `a == 0`'s independence pair needs the decision's TRUE outcome with `a` the
 * deciding operand -- i.e. a == 0 -- beside the all-false row. The BCH decoder
 * that reaches gf_mul() only multiplies syndrome/locator coefficients it has
 * already tested for zero, so every call the KAT makes arrives with both
 * operands non-zero and the decision is constant false. gf_mul() is
 * file-static, so no caller outside puf.c can supply the missing row: it takes
 * a TU that #includes puf.c.
 *
 * That is what this driver is. It rides the m33mu lane's white-box mechanism
 * (variant "lane_whitebox"; lanes/m33mu/entry.sh + harness/build-fw.sh WB_SRC
 * mode relink the firmware with puf.c's object replaced by this TU and main()
 * routed here), which is also why it could not exist before: the lane's only
 * driver used to be tests/unit-mcdc/test_puf_whitebox.c riding along as an
 * UNinstrumented lane_extra_source, and that one can only call puf.c's public
 * entry points.
 *
 * Three vectors, all in this one binary and all pure table arithmetic with no
 * state, no allocation and no I/O:
 *   (a == 0, b != 0)  -> decision true on the first operand
 *   (a != 0, b == 0)  -> decision true on the second (already covered, kept so
 *                        the pair is complete inside this binary)
 *   (a != 0, b != 0)  -> the all-false row
 * The same three are issued against gf_inv()'s single-condition guard so its
 * zero arm is exercised here too.
 */

#include <wolfssl/wolfcrypt/settings.h>

#include <wolfcrypt/src/puf.c>

#include <stdio.h>

int main(void)
{
    /* Unbuffered: on a timeout the process is killed and anything still
     * buffered is lost, which reads as an empty log. */
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("puf.c GF(2^7) white-box supplement\n");

#ifdef WOLFSSL_PUF
    {
        unsigned acc = 0;
        int i;

        /* a == 0 with b non-zero: the row the BCH decoder never produces. */
        for (i = 1; i < 8; i++) {
            acc += gf_mul(0, (byte)i);
            acc += gf_mul((byte)i, 0);
            acc += gf_mul((byte)i, (byte)(i + 1));
            acc += gf_inv((byte)i);
        }
        acc += gf_mul(0, 0);
        acc += gf_inv(0);
        printf("  [wb] gf_mul/gf_inv zero and non-zero operands issued (%u)\n",
               acc);
    }
#else
    printf("  WOLFSSL_PUF not compiled; nothing to exercise\n");
#endif

    /* Always 0: a nonzero exit discards this white-box row's coverage. */
    return 0;
}
