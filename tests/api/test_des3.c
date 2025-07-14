/* test_des3.c
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

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/wolfcrypt/des3.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_des3.h>

/*
 * unit test for wc_Des3_SetIV()
 */
int test_wc_Des3_SetIV(void)
{
    EXPECT_DECLS;
#ifndef NO_DES3
    Des3 des;
    const byte key[] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xde,0xba,0x98,0x76,0x54,0x32,0x10,
        0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67
    };
    const byte iv[] = {
        0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef,
        0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
        0x11,0x21,0x31,0x41,0x51,0x61,0x71,0x81
    };

    XMEMSET(&des, 0, sizeof(Des3));

    ExpectIntEQ(wc_Des3Init(&des, NULL, INVALID_DEVID), 0);

    /* DES_ENCRYPTION or DES_DECRYPTION */
    ExpectIntEQ(wc_Des3_SetKey(&des, key, iv, DES_ENCRYPTION), 0);
    ExpectIntEQ(XMEMCMP(iv, des.reg, DES_BLOCK_SIZE), 0);

#ifndef HAVE_FIPS /* no sanity checks with FIPS wrapper */
    /* Test explicitly wc_Des3_SetIV()  */
    ExpectIntEQ(wc_Des3_SetIV(NULL, iv), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Des3_SetIV(&des, NULL), 0);
#endif
    wc_Des3Free(&des);
#endif
    return EXPECT_RESULT();

} /* END test_wc_Des3_SetIV */

/*
 * unit test for wc_Des3_SetKey()
 */
int test_wc_Des3_SetKey(void)
{
    EXPECT_DECLS;
#ifndef NO_DES3
    Des3 des;
    const byte key[] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xde,0xba,0x98,0x76,0x54,0x32,0x10,
        0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67
    };
    const byte iv[] = {
        0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef,
        0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
        0x11,0x21,0x31,0x41,0x51,0x61,0x71,0x81
    };

    XMEMSET(&des, 0, sizeof(Des3));

    ExpectIntEQ(wc_Des3Init(&des, NULL, INVALID_DEVID), 0);

    /* DES_ENCRYPTION or DES_DECRYPTION */
    ExpectIntEQ(wc_Des3_SetKey(&des, key, iv, DES_ENCRYPTION), 0);
    ExpectIntEQ(XMEMCMP(iv, des.reg, DES_BLOCK_SIZE), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_Des3_SetKey(NULL, key, iv, DES_ENCRYPTION),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Des3_SetKey(&des, NULL, iv, DES_ENCRYPTION),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Des3_SetKey(&des, key, iv, -1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Default case. Should return 0. */
    ExpectIntEQ(wc_Des3_SetKey(&des, key, NULL, DES_ENCRYPTION), 0);

    wc_Des3Free(&des);
#endif
    return EXPECT_RESULT();

} /* END test_wc_Des3_SetKey */

/*
 * Test function for wc_Des3_CbcEncrypt and wc_Des3_CbcDecrypt
 */
int test_wc_Des3_CbcEncryptDecrypt(void)
{
    EXPECT_DECLS;
#ifndef NO_DES3
    Des3 des;
    byte cipher[24];
    byte plain[24];
    const byte key[] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xde,0xba,0x98,0x76,0x54,0x32,0x10,
        0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67
    };
    const byte iv[] = {
        0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef,
        0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
        0x11,0x21,0x31,0x41,0x51,0x61,0x71,0x81
    };
    const byte vector[] = { /* "Now is the time for all " w/o trailing 0 */
        0x4e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
        0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20
    };

    XMEMSET(&des, 0, sizeof(Des3));

    ExpectIntEQ(wc_Des3Init(&des, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_Des3_SetKey(&des, key, iv, DES_ENCRYPTION), 0);

    ExpectIntEQ(wc_Des3_CbcEncrypt(&des, cipher, vector, 24), 0);
    ExpectIntEQ(wc_Des3_SetKey(&des, key, iv, DES_DECRYPTION), 0);
    ExpectIntEQ(wc_Des3_CbcDecrypt(&des, plain, cipher, 24), 0);
    ExpectIntEQ(XMEMCMP(plain, vector, 24), 0);

    /* Pass in bad args. */
    ExpectIntEQ(wc_Des3_CbcEncrypt(NULL, cipher, vector, 24),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Des3_CbcEncrypt(&des, NULL, vector, 24),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Des3_CbcEncrypt(&des, cipher, NULL, sizeof(vector)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_Des3_CbcDecrypt(NULL, plain, cipher, 24),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Des3_CbcDecrypt(&des, NULL, cipher, 24),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Des3_CbcDecrypt(&des, plain, NULL, 24),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Des3Free(&des);
#endif
    return EXPECT_RESULT();

} /* END wc_Des3_CbcEncrypt */

/*
 *  Unit test for wc_Des3_EcbEncrypt
 */
int test_wc_Des3_EcbEncrypt(void)
{
    EXPECT_DECLS;
#if !defined(NO_DES3) && defined(WOLFSSL_DES_ECB)
    Des3    des;
    byte    cipher[24];
    word32  cipherSz = sizeof(cipher);
    const byte key[] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xde,0xba,0x98,0x76,0x54,0x32,0x10,
        0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67
    };
    const byte iv[] = {
        0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef,
        0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
        0x11,0x21,0x31,0x41,0x51,0x61,0x71,0x81
    };
    const byte vector[] = { /* "Now is the time for all " w/o trailing 0 */
        0x4e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
        0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20
    };

    XMEMSET(&des, 0, sizeof(Des3));

    ExpectIntEQ(wc_Des3Init(&des, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_Des3_SetKey(&des, key, iv, DES_ENCRYPTION), 0);

    /* Bad Cases */
    ExpectIntEQ(wc_Des3_EcbEncrypt(NULL, 0, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Des3_EcbEncrypt(NULL, cipher, vector, cipherSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Des3_EcbEncrypt(&des, 0, vector, cipherSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Des3_EcbEncrypt(&des, cipher, NULL, cipherSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Des3_EcbEncrypt(&des, cipher, vector, 0), 0);

    /* Good Cases */
    ExpectIntEQ(wc_Des3_EcbEncrypt(&des, cipher, vector, cipherSz), 0);

    wc_Des3Free(&des);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Des3_EcbEncrypt */

