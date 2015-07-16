/* srp.c SRP unit tests
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#include <tests/unit.h>
#include <wolfssl/wolfcrypt/srp.h>

#ifdef WOLFCRYPT_HAVE_SRP

static char user[] = "user";

static byte N[] = {
    0x00, 0xc0, 0x37, 0xc3, 0x75, 0x88, 0xb4, 0x32, 0x98, 0x87, 0xe6, 0x1c,
    0x2d, 0xa3, 0x32, 0x4b, 0x1b, 0xa4, 0xb8, 0x1a, 0x63, 0xf9, 0x74, 0x8f,
    0xed, 0x2d, 0x8a, 0x41, 0x0c, 0x2f, 0xc2, 0x1b, 0x12, 0x32, 0xf0, 0xd3,
    0xbf, 0xa0, 0x24, 0x27, 0x6c, 0xfd, 0x88, 0x44, 0x81, 0x97, 0xaa, 0xe4,
    0x86, 0xa6, 0x3b, 0xfc, 0xa7, 0xb8, 0xbf, 0x77, 0x54, 0xdf, 0xb3, 0x27,
    0xc7, 0x20, 0x1f, 0x6f, 0xd1, 0x7f, 0xd7, 0xfd, 0x74, 0x15, 0x8b, 0xd3,
    0x1c, 0xe7, 0x72, 0xc9, 0xf5, 0xf8, 0xab, 0x58, 0x45, 0x48, 0xa9, 0x9a,
    0x75, 0x9b, 0x5a, 0x2c, 0x05, 0x32, 0x16, 0x2b, 0x7b, 0x62, 0x18, 0xe8,
    0xf1, 0x42, 0xbc, 0xe2, 0xc3, 0x0d, 0x77, 0x84, 0x68, 0x9a, 0x48, 0x3e,
    0x09, 0x5e, 0x70, 0x16, 0x18, 0x43, 0x79, 0x13, 0xa8, 0xc3, 0x9c, 0x3d,
    0xd0, 0xd4, 0xca, 0x3c, 0x50, 0x0b, 0x88, 0x5f, 0xe3
};

static byte g[] = {
    0x02
};

static byte salt[] = {
    'r', 'a', 'n', 'd', 'o', 'm'
};

static void test_SrpInit(void)
{
    Srp srp;

    /* invalid params */
    AssertIntEQ(BAD_FUNC_ARG, wc_SrpInit(NULL, SRP_TYPE_SHA, SRP_CLIENT_SIDE));
    AssertIntEQ(BAD_FUNC_ARG, wc_SrpInit(&srp, 255,          SRP_CLIENT_SIDE));
    AssertIntEQ(BAD_FUNC_ARG, wc_SrpInit(&srp, SRP_TYPE_SHA, 255            ));

    /* success */
    AssertIntEQ(0, wc_SrpInit(&srp, SRP_TYPE_SHA, SRP_CLIENT_SIDE));

    wc_SrpTerm(&srp);
}

static void test_SrpSetUsername(void)
{
    Srp srp;

    AssertIntEQ(0, wc_SrpInit(&srp, SRP_TYPE_SHA, SRP_CLIENT_SIDE));

    /* invalid params */
    AssertIntEQ(BAD_FUNC_ARG, wc_SrpSetUsername(NULL, user));
    AssertIntEQ(BAD_FUNC_ARG, wc_SrpSetUsername(&srp, NULL));

    /* success */
    AssertIntEQ(0, wc_SrpSetUsername(&srp, user));
    AssertIntEQ((int) XSTRLEN(user), srp.userSz);
    AssertIntEQ(0, XMEMCMP(srp.user, user, srp.userSz));

    wc_SrpTerm(&srp);
}

static void test_SrpSetParams(void)
{
    Srp srp;

    AssertIntEQ(0, wc_SrpInit(&srp, SRP_TYPE_SHA, SRP_CLIENT_SIDE));
    AssertIntEQ(0, wc_SrpSetUsername(&srp, user));

    /* invalid params */
    AssertIntEQ(BAD_FUNC_ARG, wc_SrpSetParams(NULL, N,    sizeof(N),
                                                    g,    sizeof(g),
                                                    salt, sizeof(salt)));
    AssertIntEQ(BAD_FUNC_ARG, wc_SrpSetParams(&srp, NULL, sizeof(N),
                                                    g,    sizeof(g),
                                                    salt, sizeof(salt)));
    AssertIntEQ(BAD_FUNC_ARG, wc_SrpSetParams(&srp, N,    sizeof(N),
                                                    NULL, sizeof(g),
                                                    salt, sizeof(salt)));
    AssertIntEQ(BAD_FUNC_ARG, wc_SrpSetParams(&srp, N,    sizeof(N),
                                                    g,    sizeof(g),
                                                    NULL, sizeof(salt)));

    /* success */
    AssertIntEQ(0, wc_SrpSetParams(&srp, N,    sizeof(N),
                                         g,    sizeof(g),
                                         salt, sizeof(salt)));

    AssertIntEQ(sizeof(salt), srp.saltSz);
    AssertIntEQ(0, XMEMCMP(srp.salt, salt, srp.saltSz));

    wc_SrpTerm(&srp);
}

#endif

void SrpTest(void)
{
#ifdef WOLFCRYPT_HAVE_SRP
    test_SrpInit();
    test_SrpSetUsername();
    test_SrpSetParams();
#endif
}
