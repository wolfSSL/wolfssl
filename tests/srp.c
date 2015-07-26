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

static byte username[] = "user";
static word32 usernameSz = 4;

static byte password[] = "password";
static word32 passwordSz = 8;

static byte N[] = {
    0xD4, 0xC7, 0xF8, 0xA2, 0xB3, 0x2C, 0x11, 0xB8, 0xFB, 0xA9, 0x58, 0x1E,
    0xC4, 0xBA, 0x4F, 0x1B, 0x04, 0x21, 0x56, 0x42, 0xEF, 0x73, 0x55, 0xE3,
    0x7C, 0x0F, 0xC0, 0x44, 0x3E, 0xF7, 0x56, 0xEA, 0x2C, 0x6B, 0x8E, 0xEB,
    0x75, 0x5A, 0x1C, 0x72, 0x30, 0x27, 0x66, 0x3C, 0xAA, 0x26, 0x5E, 0xF7,
    0x85, 0xB8, 0xFF, 0x6A, 0x9B, 0x35, 0x22, 0x7A, 0x52, 0xD8, 0x66, 0x33,
    0xDB, 0xDF, 0xCA, 0x43
};

static byte g[] = {
    0x02
};

static byte salt[] = {
    0x80, 0x66, 0x61, 0x5B, 0x7D, 0x33, 0xA2, 0x2E, 0x79, 0x18
};

static byte verifier[] = {
    0x24, 0x5F, 0xA5, 0x1B, 0x2A, 0x28, 0xF8, 0xFF, 0xE2, 0xA0, 0xF8, 0x61,
    0x7B, 0x0F, 0x3C, 0x05, 0xD6, 0x4A, 0x55, 0xDF, 0x74, 0x31, 0x54, 0x47,
    0xA1, 0xFA, 0x9D, 0x25, 0x7B, 0x02, 0x88, 0x0A, 0xE8, 0x5A, 0xBA, 0x8B,
    0xA2, 0xD3, 0x8A, 0x62, 0x46, 0x8C, 0xEC, 0x52, 0xBE, 0xDE, 0xFC, 0x75,
    0xF5, 0xDB, 0x9C, 0x8C, 0x9B, 0x34, 0x7A, 0xE7, 0x4A, 0x5F, 0xBB, 0x96,
    0x38, 0x19, 0xAB, 0x24
};

static byte a[] = {
    0x37, 0x95, 0xF2, 0xA6, 0xF1, 0x6F, 0x0D, 0x58, 0xBF, 0xED, 0x44, 0x87,
    0xE0, 0xB6, 0xCC, 0x1C, 0xA0, 0x50, 0xC6, 0x61, 0xBB, 0x36, 0xE0, 0x9A,
    0xF3, 0xF7, 0x1E, 0x7A, 0x61, 0x86, 0x5A, 0xF5
};

static byte A[] = {
    0x8D, 0x28, 0xC5, 0x6A, 0x46, 0x5C, 0x82, 0xDB, 0xC7, 0xF6, 0x8B, 0x62,
    0x1A, 0xAD, 0xA1, 0x76, 0x1B, 0x55, 0xFF, 0xAB, 0x10, 0x2F, 0xFF, 0x4A,
    0xAA, 0x46, 0xAD, 0x33, 0x64, 0xDE, 0x28, 0x2E, 0x82, 0x7A, 0xBE, 0xEA,
    0x32, 0xFC, 0xD6, 0x14, 0x01, 0x71, 0xE6, 0xC8, 0xC9, 0x53, 0x69, 0x55,
    0xE1, 0xF8, 0x3D, 0xDD, 0xC7, 0xD5, 0x21, 0xCE, 0xFF, 0x17, 0xFC, 0x23,
    0xBF, 0xCF, 0x2D, 0xB0
};

static byte b[] = {
    0x2B, 0xDD, 0x30, 0x30, 0x53, 0xAF, 0xD8, 0x3A, 0xE7, 0xE0, 0x17, 0x82,
    0x39, 0x44, 0x2C, 0xDB, 0x30, 0x88, 0x0F, 0xC8, 0x88, 0xC2, 0xB2, 0xC1,
    0x78, 0x43, 0x2F, 0xD5, 0x60, 0xD4, 0xDA, 0x43
};

static byte B[] = {
    0xB5, 0x80, 0x36, 0x7F, 0x50, 0x89, 0xC1, 0x04, 0x42, 0x98, 0xD7, 0x6A,
    0x37, 0x8E, 0xF1, 0x81, 0x52, 0xC5, 0x7A, 0xA1, 0xD5, 0xB7, 0x66, 0x84,
    0xA1, 0x3E, 0x32, 0x82, 0x2B, 0x3A, 0xB5, 0xD7, 0x3D, 0x50, 0xF1, 0x58,
    0xBD, 0x89, 0x75, 0xC7, 0x51, 0xCF, 0x6C, 0x03, 0xD4, 0xCA, 0xD5, 0x6E,
    0x97, 0x4D, 0xA3, 0x1E, 0x19, 0x0B, 0xF0, 0xAA, 0x7D, 0x14, 0x90, 0x80,
    0x0E, 0xC7, 0x92, 0xAD
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
    AssertIntEQ(BAD_FUNC_ARG, wc_SrpSetUsername(NULL, username, usernameSz));
    AssertIntEQ(BAD_FUNC_ARG, wc_SrpSetUsername(&srp, NULL, usernameSz));

    /* success */
    AssertIntEQ(0, wc_SrpSetUsername(&srp, username, usernameSz));
    AssertIntEQ((int) usernameSz, srp.userSz);
    AssertIntEQ(0, XMEMCMP(srp.user, username, usernameSz));

    wc_SrpTerm(&srp);
}

static void test_SrpSetParams(void)
{
    Srp srp;

    AssertIntEQ(0, wc_SrpInit(&srp, SRP_TYPE_SHA, SRP_CLIENT_SIDE));

    /* invalid call order */
    AssertIntEQ(SRP_CALL_ORDER_E, wc_SrpSetParams(&srp, N,    sizeof(N),
                                                        g,    sizeof(g),
                                                        salt, sizeof(salt)));

    /* fix call order */
    AssertIntEQ(0, wc_SrpSetUsername(&srp, username, usernameSz));

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

static void test_SrpSetPassword(void)
{
    Srp srp;
    byte v[64];
    word32 vSz = 0;

    AssertIntEQ(0, wc_SrpInit(&srp, SRP_TYPE_SHA, SRP_CLIENT_SIDE));
    AssertIntEQ(0, wc_SrpSetUsername(&srp, username, usernameSz));

    /* invalid call order */
    AssertIntEQ(SRP_CALL_ORDER_E,
                wc_SrpSetPassword(&srp, password, passwordSz));
    AssertIntEQ(SRP_CALL_ORDER_E,
                wc_SrpGetVerifier(&srp, v, &vSz));

    /* fix call order */
    AssertIntEQ(0, wc_SrpSetParams(&srp, N,    sizeof(N),
                                         g,    sizeof(g),
                                         salt, sizeof(salt)));

    /* invalid params */
    AssertIntEQ(BAD_FUNC_ARG, wc_SrpSetPassword(NULL, password, passwordSz));
    AssertIntEQ(BAD_FUNC_ARG, wc_SrpSetPassword(&srp, NULL,     passwordSz));

    /* success */
    AssertIntEQ(0, wc_SrpSetPassword(&srp, password, passwordSz));

    /* invalid params */
    AssertIntEQ(BAD_FUNC_ARG, wc_SrpGetVerifier(NULL, v,    &vSz));
    AssertIntEQ(BAD_FUNC_ARG, wc_SrpGetVerifier(&srp, NULL, &vSz));
    AssertIntEQ(BUFFER_E,     wc_SrpGetVerifier(&srp, v,    &vSz));

    /* success */
    vSz = sizeof(v);
    AssertIntEQ(0, wc_SrpGetVerifier(&srp, v, &vSz));
    AssertIntEQ(vSz, sizeof(verifier));
    AssertIntEQ(0, XMEMCMP(verifier, v, vSz));

    /* invalid params - client side srp */
    AssertIntEQ(BAD_FUNC_ARG, wc_SrpSetVerifier(&srp, v, vSz));

    wc_SrpTerm(&srp);
    AssertIntEQ(0, wc_SrpInit(&srp, SRP_TYPE_SHA, SRP_SERVER_SIDE));

    /* invalid params */
    AssertIntEQ(BAD_FUNC_ARG, wc_SrpSetVerifier(NULL, v,    vSz));
    AssertIntEQ(BAD_FUNC_ARG, wc_SrpSetVerifier(&srp, NULL, vSz));

    /* success */
    AssertIntEQ(0, wc_SrpSetVerifier(&srp, v, vSz));

    wc_SrpTerm(&srp);
}

static void test_SrpGenPublic(void)
{
    Srp srp;
    byte public[64];
    word32 publicSz = 0;

    AssertIntEQ(0, wc_SrpInit(&srp, SRP_TYPE_SHA, SRP_CLIENT_SIDE));

    /* invalid call order */
    AssertIntEQ(SRP_CALL_ORDER_E, wc_SrpGenPublic(&srp, public, &publicSz));

    /* fix call order */
    AssertIntEQ(0, wc_SrpSetUsername(&srp, username, usernameSz));
    AssertIntEQ(0, wc_SrpSetParams(&srp, N,    sizeof(N),
                                         g,    sizeof(g),
                                         salt, sizeof(salt)));

    /* invalid params */
    AssertIntEQ(BAD_FUNC_ARG, wc_SrpGenPublic(NULL, public, &publicSz));
    AssertIntEQ(BAD_FUNC_ARG, wc_SrpGenPublic(&srp, NULL,   &publicSz));
    AssertIntEQ(BAD_FUNC_ARG, wc_SrpGenPublic(&srp, public, NULL));
    AssertIntEQ(BUFFER_E,     wc_SrpGenPublic(&srp, public, &publicSz));

    /* success */
    publicSz = sizeof(public);
    AssertIntEQ(0, wc_SrpGenPublic(&srp, NULL, NULL));

    AssertIntEQ(0, wc_SrpSetPrivate(&srp, a, sizeof(a)));
    AssertIntEQ(0, wc_SrpGenPublic(&srp, public, &publicSz));
    AssertIntEQ(publicSz, sizeof(A));
    AssertIntEQ(0, XMEMCMP(public, A, publicSz));

    wc_SrpTerm(&srp);
    AssertIntEQ(0, wc_SrpInit(&srp, SRP_TYPE_SHA, SRP_SERVER_SIDE));

    AssertIntEQ(0, wc_SrpSetUsername(&srp, username, usernameSz));
    AssertIntEQ(0, wc_SrpSetParams(&srp, N,    sizeof(N),
                                         g,    sizeof(g),
                                         salt, sizeof(salt)));

    /* invalid call order */
    AssertIntEQ(SRP_CALL_ORDER_E, wc_SrpGenPublic(&srp, public, &publicSz));

    /* fix call order */
    AssertIntEQ(0, wc_SrpSetVerifier(&srp, verifier, sizeof(verifier)));

    /* success */
    AssertIntEQ(0, wc_SrpGenPublic(&srp, NULL, NULL));

    AssertIntEQ(0, wc_SrpSetPrivate(&srp, b, sizeof(b)));
    AssertIntEQ(0, wc_SrpGenPublic(&srp, public, &publicSz));
    AssertIntEQ(publicSz, sizeof(B));
    AssertIntEQ(0, XMEMCMP(public, B, publicSz));

    wc_SrpTerm(&srp);
}

#endif

void SrpTest(void)
{
#ifdef WOLFCRYPT_HAVE_SRP
    test_SrpInit();
    test_SrpSetUsername();
    test_SrpSetParams();
    test_SrpSetPassword();
    test_SrpGenPublic();
#endif
}
