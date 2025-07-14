/* test_cmac.c
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

#include <wolfssl/wolfcrypt/cmac.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_cmac.h>

/*
 * Testing wc_InitCmac()
 */
int test_wc_InitCmac(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_CMAC) && !defined(NO_AES)
    Cmac        cmac1;
    Cmac        cmac2;
    Cmac        cmac3;
    /* AES 128 key. */
    byte        key1[] = "\x01\x02\x03\x04\x05\x06\x07\x08"
                         "\x09\x10\x11\x12\x13\x14\x15\x16";
    /* AES 192 key. */
    byte        key2[] = "\x01\x02\x03\x04\x05\x06\x07\x08"
                         "\x09\x01\x11\x12\x13\x14\x15\x16"
                         "\x01\x02\x03\x04\x05\x06\x07\x08";
    /* AES 256 key. */
    byte        key3[] = "\x01\x02\x03\x04\x05\x06\x07\x08"
                         "\x09\x01\x11\x12\x13\x14\x15\x16"
                         "\x01\x02\x03\x04\x05\x06\x07\x08"
                         "\x09\x01\x11\x12\x13\x14\x15\x16";
    word32      key1Sz = (word32)sizeof(key1) - 1;
    word32      key2Sz = (word32)sizeof(key2) - 1;
    word32      key3Sz = (word32)sizeof(key3) - 1;
    int         type   = WC_CMAC_AES;

    (void)key1;
    (void)key1Sz;
    (void)key2;
    (void)key2Sz;

    XMEMSET(&cmac1, 0, sizeof(Cmac));
    XMEMSET(&cmac2, 0, sizeof(Cmac));
    XMEMSET(&cmac3, 0, sizeof(Cmac));

#ifdef WOLFSSL_AES_128
    ExpectIntEQ(wc_InitCmac(&cmac1, key1, key1Sz, type, NULL), 0);
#endif
#ifdef WOLFSSL_AES_192
    wc_AesFree(&cmac1.aes);
    ExpectIntEQ(wc_InitCmac(&cmac2, key2, key2Sz, type, NULL), 0);
#endif
#ifdef WOLFSSL_AES_256
    wc_AesFree(&cmac2.aes);
    ExpectIntEQ(wc_InitCmac(&cmac3, key3, key3Sz, type, NULL), 0);
#endif

    wc_AesFree(&cmac3.aes);
    /* Test bad args. */
    ExpectIntEQ(wc_InitCmac(NULL, key3, key3Sz, type, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitCmac(&cmac3, NULL, key3Sz, type, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitCmac(&cmac3, key3, 0, type, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitCmac(&cmac3, key3, key3Sz, 0, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    return EXPECT_RESULT();
} /* END test_wc_InitCmac */

/*
 * Testing wc_CmacUpdate()
 */
int test_wc_CmacUpdate(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_CMAC) && !defined(NO_AES) && defined(WOLFSSL_AES_128)
    Cmac        cmac;
    byte        key[] = {
        0x64, 0x4c, 0xbf, 0x12, 0x85, 0x9d, 0xf0, 0x55,
        0x7e, 0xa9, 0x1f, 0x08, 0xe0, 0x51, 0xff, 0x27
    };
    byte        in[] = "\xe2\xb4\xb6\xf9\x48\x44\x02\x64"
                       "\x5c\x47\x80\x9e\xd5\xa8\x3a\x17"
                       "\xb3\x78\xcf\x85\x22\x41\x74\xd9"
                       "\xa0\x97\x39\x71\x62\xf1\x8e\x8f"
                       "\xf4";
    word32      inSz  = (word32)sizeof(in) - 1;
    word32      keySz = (word32)sizeof(key);
    int         type  = WC_CMAC_AES;

    XMEMSET(&cmac, 0, sizeof(Cmac));

    ExpectIntEQ(wc_InitCmac(&cmac, key, keySz, type, NULL), 0);
    ExpectIntEQ(wc_CmacUpdate(&cmac, in, inSz), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_CmacUpdate(NULL, in, inSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_CmacUpdate(&cmac, NULL, 30), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    wc_AesFree(&cmac.aes);
#endif
    return EXPECT_RESULT();
} /* END test_wc_CmacUpdate */

/*
 * Testing wc_CmacFinal()
 */
int test_wc_CmacFinal(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_CMAC) && !defined(NO_AES) && defined(WOLFSSL_AES_128)
    Cmac        cmac;
    byte        key[] = {
        0x64, 0x4c, 0xbf, 0x12, 0x85, 0x9d, 0xf0, 0x55,
        0x7e, 0xa9, 0x1f, 0x08, 0xe0, 0x51, 0xff, 0x27
    };
    byte        msg[] = {
        0xe2, 0xb4, 0xb6, 0xf9, 0x48, 0x44, 0x02, 0x64,
        0x5c, 0x47, 0x80, 0x9e, 0xd5, 0xa8, 0x3a, 0x17,
        0xb3, 0x78, 0xcf, 0x85, 0x22, 0x41, 0x74, 0xd9,
        0xa0, 0x97, 0x39, 0x71, 0x62, 0xf1, 0x8e, 0x8f,
        0xf4
    };
    /* Test vectors from CMACGenAES128.rsp from
     * http://csrc.nist.gov/groups/STM/cavp/block-cipher-modes.html#cmac
     * Per RFC4493 truncation of lsb is possible.
     */
    byte        expMac[] = {
        0x4e, 0x6e, 0xc5, 0x6f, 0xf9, 0x5d, 0x0e, 0xae,
        0x1c, 0xf8, 0x3e, 0xfc, 0xf4, 0x4b, 0xeb
    };
    byte        mac[WC_AES_BLOCK_SIZE];
    word32      msgSz    = (word32)sizeof(msg);
    word32      keySz    = (word32)sizeof(key);
    word32      macSz    = sizeof(mac);
    word32      badMacSz = 17;
    int         expMacSz = sizeof(expMac);
    int         type     = WC_CMAC_AES;

    XMEMSET(&cmac, 0, sizeof(Cmac));
    XMEMSET(mac, 0, macSz);

    ExpectIntEQ(wc_InitCmac(&cmac, key, keySz, type, NULL), 0);
    ExpectIntEQ(wc_CmacUpdate(&cmac, msg, msgSz), 0);

#if (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5, 3)) && !defined(HAVE_SELFTEST)
    /* Pass in bad args. */
    ExpectIntEQ(wc_CmacFinalNoFree(NULL, mac, &macSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_CmacFinalNoFree(&cmac, NULL, &macSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_CmacFinalNoFree(&cmac, mac, &badMacSz),
        WC_NO_ERR_TRACE(BUFFER_E));

    /* For the last call, use the API with implicit wc_CmacFree(). */
    ExpectIntEQ(wc_CmacFinal(&cmac, mac, &macSz), 0);
    ExpectIntEQ(XMEMCMP(mac, expMac, expMacSz), 0);
#else /* !HAVE_FIPS || FIPS>=5.3 */
    ExpectIntEQ(wc_CmacFinal(&cmac, mac, &macSz), 0);
    ExpectIntEQ(XMEMCMP(mac, expMac, expMacSz), 0);

    /* Pass in bad args. */
    ExpectIntEQ(wc_CmacFinal(NULL, mac, &macSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_CmacFinal(&cmac, NULL, &macSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_CmacFinal(&cmac, mac, &badMacSz), WC_NO_ERR_TRACE(BUFFER_E));
#endif /* !HAVE_FIPS || FIPS>=5.3 */
#endif
    return EXPECT_RESULT();
} /* END test_wc_CmacFinal */

/*
 * Testing wc_AesCmacGenerate() && wc_AesCmacVerify()
 */
int test_wc_AesCmacGenerate(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_CMAC) && !defined(NO_AES) && defined(WOLFSSL_AES_128)
    byte        key[] = {
        0x26, 0xef, 0x8b, 0x40, 0x34, 0x11, 0x7d, 0x9e,
        0xbe, 0xc0, 0xc7, 0xfc, 0x31, 0x08, 0x54, 0x69
    };
    byte        msg[]    = "\x18\x90\x49\xef\xfd\x7c\xf9\xc8"
                           "\xf3\x59\x65\xbc\xb0\x97\x8f\xd4";
    byte        expMac[] = "\x29\x5f\x2f\x71\xfc\x58\xe6\xf6"
                           "\x3d\x32\x65\x4c\x66\x23\xc5";
    byte        mac[WC_AES_BLOCK_SIZE];
    word32      keySz    = sizeof(key);
    word32      macSz    = sizeof(mac);
    word32      msgSz    = sizeof(msg) - 1;
    word32      expMacSz = sizeof(expMac) - 1;

    XMEMSET(mac, 0, macSz);

    ExpectIntEQ(wc_AesCmacGenerate(mac, &macSz, msg, msgSz, key, keySz), 0);
    ExpectIntEQ(XMEMCMP(mac, expMac, expMacSz), 0);

    /* Pass in bad args. */
    ExpectIntEQ(wc_AesCmacGenerate(NULL, &macSz, msg, msgSz, key, keySz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCmacGenerate(mac, &macSz, msg, msgSz, NULL, keySz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCmacGenerate(mac, &macSz, msg, msgSz, key, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCmacGenerate(mac, &macSz, NULL, msgSz, key, keySz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_AesCmacVerify(mac, macSz, msg, msgSz, key, keySz), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_AesCmacVerify(NULL, macSz, msg, msgSz, key, keySz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCmacVerify(mac, 0, msg, msgSz, key, keySz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCmacVerify(mac, macSz, msg, msgSz, NULL, keySz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCmacVerify(mac, macSz, msg, msgSz, key, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCmacVerify(mac, macSz, NULL, msgSz, key, keySz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    return EXPECT_RESULT();

} /* END test_wc_AesCmacGenerate */

