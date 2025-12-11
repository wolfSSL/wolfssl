/* test_wc_encrypt.c
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

#include <wolfssl/wolfcrypt/wc_encrypt.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_wc_encrypt.h>

/*
 *  Unit test for wc_Des3_CbcEncryptWithKey and wc_Des3_CbcDecryptWithKey
 */
int test_wc_Des3_CbcEncryptDecryptWithKey(void)
{
    EXPECT_DECLS;
#ifndef NO_DES3
    word32 vectorSz, cipherSz;
    byte cipher[24];
    byte plain[24];
    byte vector[] = { /* Now is the time for all w/o trailing 0 */
        0x4e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
        0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20
    };
    byte key[] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xde,0xba,0x98,0x76,0x54,0x32,0x10,
        0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67
    };
    byte iv[] = {
        0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef,
        0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
        0x11,0x21,0x31,0x41,0x51,0x61,0x71,0x81
    };

    vectorSz = sizeof(byte) * 24;
    cipherSz = sizeof(byte) * 24;

    ExpectIntEQ(wc_Des3_CbcEncryptWithKey(cipher, vector, vectorSz, key, iv),
        0);
    ExpectIntEQ(wc_Des3_CbcDecryptWithKey(plain, cipher, cipherSz, key, iv), 0);
    ExpectIntEQ(XMEMCMP(plain, vector, 24), 0);

    /* pass in bad args. */
    ExpectIntEQ(wc_Des3_CbcEncryptWithKey(NULL, vector, vectorSz, key, iv),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Des3_CbcEncryptWithKey(cipher, NULL, vectorSz, key, iv),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Des3_CbcEncryptWithKey(cipher, vector, vectorSz, NULL, iv),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Des3_CbcEncryptWithKey(cipher, vector, vectorSz, key, NULL),
        0);

    ExpectIntEQ(wc_Des3_CbcDecryptWithKey(NULL, cipher, cipherSz, key, iv),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Des3_CbcDecryptWithKey(plain, NULL, cipherSz, key, iv),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Des3_CbcDecryptWithKey(plain, cipher, cipherSz, NULL, iv),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Des3_CbcDecryptWithKey(plain, cipher, cipherSz, key, NULL),
        0);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Des3_CbcEncryptDecryptWithKey */

