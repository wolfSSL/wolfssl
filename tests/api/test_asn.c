/* test_asn.c
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

#include <tests/unit.h>

#include <tests/api/test_asn.h>

#ifndef NO_ASN
static int test_SetShortInt_once(word32 val, byte* valDer, word32 valDerSz)
{
    EXPECT_DECLS;

#ifndef NO_PWDBASED
#if !defined(WOLFSSL_ASN_TEMPLATE) || defined(HAVE_PKCS8) || \
     defined(HAVE_PKCS12)

    byte outDer[MAX_SHORT_SZ];
    word32 outDerSz = 0;
    word32 inOutIdx = 0;
    word32 maxIdx = MAX_SHORT_SZ;

    ExpectIntLE(2 + valDerSz, MAX_SHORT_SZ);
    ExpectIntEQ(outDerSz = SetShortInt(outDer, &inOutIdx, val, maxIdx),
        2 + valDerSz);
    ExpectIntEQ(outDer[0], ASN_INTEGER);
    ExpectIntEQ(outDer[1], valDerSz);
    ExpectIntEQ(XMEMCMP(outDer + 2, valDer, valDerSz), 0);

#endif /* !WOLFSSL_ASN_TEMPLATE || HAVE_PKCS8 || HAVE_PKCS12 */
#endif /* !NO_PWDBASED */

    (void)val;
    (void)valDer;
    (void)valDerSz;

    return EXPECT_RESULT();
}
#endif

int test_SetShortInt(void)
{
    EXPECT_DECLS;

#ifndef NO_ASN
    byte valDer[MAX_SHORT_SZ] = {0};

    /* Corner tests for input size */
    {
        /* Input 1 byte min */
        valDer[0] = 0x00;
        EXPECT_TEST(test_SetShortInt_once(0x00, valDer, 1));

        /* Input 1 byte max */
        valDer[0] = 0x00;
        valDer[1] = 0xff;
        EXPECT_TEST(test_SetShortInt_once(0xff, valDer, 2));

        /* Input 2 bytes min */
        valDer[0] = 0x01;
        valDer[1] = 0x00;
        EXPECT_TEST(test_SetShortInt_once(0x0100, valDer, 2));

        /* Input 2 bytes max */
        valDer[0] = 0x00;
        valDer[1] = 0xff;
        valDer[2] = 0xff;
        EXPECT_TEST(test_SetShortInt_once(0xffff, valDer, 3));

        /* Input 3 bytes min */
        valDer[0] = 0x01;
        valDer[1] = 0x00;
        valDer[2] = 0x00;
        EXPECT_TEST(test_SetShortInt_once(0x010000, valDer, 3));

        /* Input 3 bytes max */
        valDer[0] = 0x00;
        valDer[1] = 0xff;
        valDer[2] = 0xff;
        valDer[3] = 0xff;
        EXPECT_TEST(test_SetShortInt_once(0xffffff, valDer, 4));

        /* Input 4 bytes min */
        valDer[0] = 0x01;
        valDer[1] = 0x00;
        valDer[2] = 0x00;
        valDer[3] = 0x00;
        EXPECT_TEST(test_SetShortInt_once(0x01000000, valDer, 4));

        /* Input 4 bytes max */
        valDer[0] = 0x00;
        valDer[1] = 0xff;
        valDer[2] = 0xff;
        valDer[3] = 0xff;
        valDer[4] = 0xff;
        EXPECT_TEST(test_SetShortInt_once(0xffffffff, valDer, 5));
    }

    /* Corner tests for output size */
    {
        /* Skip "Output 1 byte min" because of same as "Input 1 byte min" */

        /* Output 1 byte max */
        valDer[0] = 0x7f;
        EXPECT_TEST(test_SetShortInt_once(0x7f, valDer, 1));

        /* Output 2 bytes min */
        valDer[0] = 0x00;
        valDer[1] = 0x80;
        EXPECT_TEST(test_SetShortInt_once(0x80, valDer, 2));

        /* Output 2 bytes max */
        valDer[0] = 0x7f;
        valDer[1] = 0xff;
        EXPECT_TEST(test_SetShortInt_once(0x7fff, valDer, 2));

        /* Output 3 bytes min */
        valDer[0] = 0x00;
        valDer[1] = 0x80;
        valDer[2] = 0x00;
        EXPECT_TEST(test_SetShortInt_once(0x8000, valDer, 3));

        /* Output 3 bytes max */
        valDer[0] = 0x7f;
        valDer[1] = 0xff;
        valDer[2] = 0xff;
        EXPECT_TEST(test_SetShortInt_once(0x7fffff, valDer, 3));

        /* Output 4 bytes min */
        valDer[0] = 0x00;
        valDer[1] = 0x80;
        valDer[2] = 0x00;
        valDer[3] = 0x00;
        EXPECT_TEST(test_SetShortInt_once(0x800000, valDer, 4));

        /* Output 4 bytes max */
        valDer[0] = 0x7f;
        valDer[1] = 0xff;
        valDer[2] = 0xff;
        valDer[3] = 0xff;
        EXPECT_TEST(test_SetShortInt_once(0x7fffffff, valDer, 4));

        /* Output 5 bytes min */
        valDer[0] = 0x00;
        valDer[1] = 0x80;
        valDer[2] = 0x00;
        valDer[3] = 0x00;
        valDer[4] = 0x00;
        EXPECT_TEST(test_SetShortInt_once(0x80000000, valDer, 5));

        /* Skip "Output 5 bytes max" because of same as "Input 4 bytes max" */
    }

    /* Extra tests */
    {
        valDer[0] = 0x01;
        EXPECT_TEST(test_SetShortInt_once(0x01, valDer, 1));
    }
#endif

    return EXPECT_RESULT();
}
