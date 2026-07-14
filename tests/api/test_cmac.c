/* test_cmac.c
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

#include <tests/unit.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/wolfcrypt/cmac.h>
#include <wolfssl/wolfcrypt/types.h>
#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
#endif
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
    /* in == NULL && inSz == 0: independence pair for the inSz != 0 operand
     * of (cmac == NULL) || (in == NULL && inSz != 0) -- a no-op success. */
    ExpectIntEQ(wc_CmacUpdate(&cmac, NULL, 0), 0);
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
#if (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5, 3)) && !defined(HAVE_SELFTEST)
    /* only used by the bad-arg checks in the matching #if block below */
    word32      tooSmallMacSz = WC_CMAC_TAG_MIN_SZ - 1;
#endif
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
    /* outSz == NULL: independence pair for wc_CmacFinalNoFree's third
     * operand (cmac == NULL || out == NULL || outSz == NULL). */
    ExpectIntEQ(wc_CmacFinalNoFree(&cmac, mac, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Too small: independence pair for (*outSz < MIN || *outSz > MAX)'s
     * first operand (badMacSz above already shows the second). */
    ExpectIntEQ(wc_CmacFinalNoFree(&cmac, mac, &tooSmallMacSz),
        WC_NO_ERR_TRACE(BUFFER_E));
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

    /* in == NULL && inSz == 0: independence pair for the inSz > 0 operand
     * of (out==NULL)||(in==NULL&&inSz>0)||(key==NULL)||(keySz==0) -- a
     * legitimate empty-message CMAC. */
    {
        byte emptyMac[WC_AES_BLOCK_SIZE];
        word32 emptyMacSz = sizeof(emptyMac);
        ExpectIntEQ(wc_AesCmacGenerate(emptyMac, &emptyMacSz, NULL, 0, key,
            keySz), 0);
    }

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

    /* in == NULL && inSz == 0: independence pair for the inSz > 0 operand
     * of wc_AesCmacVerify's own guard (a different physical decision than
     * wc_AesCmacGenerate's copy above). Not a matching tag, so
     * MAC_CMP_FAILED_E, not BAD_FUNC_ARG -- the point is the guard's leaf
     * evaluates false and execution proceeds past it. */
    ExpectIntNE(wc_AesCmacVerify(mac, macSz, NULL, 0, key, keySz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

#if !defined(HAVE_FIPS)
    ExpectIntEQ(wc_AesCmacVerify(mac, 1, msg, msgSz, key, keySz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCmacVerify(mac, WC_CMAC_TAG_MIN_SZ - 1, msg, msgSz,
        key, keySz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesCmacVerify(mac, WC_AES_BLOCK_SIZE + 1, msg, msgSz,
        key, keySz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Truncated tags within the supported range must verify correctly when
     * the generator was asked to produce the same length */
    {
        byte truncMac[WC_AES_BLOCK_SIZE];
        word32 truncSz;
        word32 lengths[] = { WC_CMAC_TAG_MIN_SZ, 8, WC_AES_BLOCK_SIZE - 1 };
        word32 lengthsSz = (word32)(sizeof(lengths)/sizeof(lengths[0]));
        word32 li;
        for (li = 0; li < lengthsSz; li++) {
            XMEMSET(truncMac, 0, sizeof(truncMac));
            truncSz = lengths[li];
            ExpectIntEQ(wc_AesCmacGenerate(truncMac, &truncSz, msg, msgSz,
                key, keySz), 0);
            ExpectIntEQ(truncSz, lengths[li]);
            ExpectIntEQ(wc_AesCmacVerify(truncMac, truncSz, msg, msgSz,
                key, keySz), 0);
            /* Flipping a bit in the truncated tag must yield
             * MAC_CMP_FAILED_E, not silent success from comparing a too
             * short prefix. */
            truncMac[0] ^= 0x01;
            ExpectIntEQ(wc_AesCmacVerify(truncMac, truncSz, msg, msgSz,
                key, keySz), WC_NO_ERR_TRACE(MAC_CMP_FAILED_E));
        }
    }

    /* A full-length tag that does not match must return MAC_CMP_FAILED_E. */
    {
        byte badMac[WC_AES_BLOCK_SIZE];
        XMEMCPY(badMac, mac, WC_AES_BLOCK_SIZE);
        badMac[0] ^= 0x01;
        ExpectIntEQ(wc_AesCmacVerify(badMac, WC_AES_BLOCK_SIZE, msg, msgSz,
            key, keySz), WC_NO_ERR_TRACE(MAC_CMP_FAILED_E));
    }
#endif
#endif
    return EXPECT_RESULT();

} /* END test_wc_AesCmacGenerate */

/*
 * MC/DC: wc_CMAC_Grow()'s (cmac == NULL) || (in == NULL && inSz != 0)
 * guard. Compiled out entirely unless WOLFSSL_HASH_KEEP is defined.
 */
int test_wc_CMAC_Grow(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_CMAC) && !defined(NO_AES) && defined(WOLFSSL_AES_128) && \
    defined(WOLFSSL_HASH_KEEP)
    Cmac        cmac;
    byte        key[] = {
        0x64, 0x4c, 0xbf, 0x12, 0x85, 0x9d, 0xf0, 0x55,
        0x7e, 0xa9, 0x1f, 0x08, 0xe0, 0x51, 0xff, 0x27
    };
    byte        in[] = { 0x01, 0x02, 0x03, 0x04 };

    /* cmac == NULL. */
    ExpectIntEQ(wc_CMAC_Grow(NULL, in, sizeof(in)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_InitCmac(&cmac, key, sizeof(key), WC_CMAC_AES, NULL), 0);
    /* in == NULL && inSz != 0 -- both true. */
    ExpectIntEQ(wc_CMAC_Grow(&cmac, NULL, 4), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* inSz == 0, in == NULL held true: this leaf false -- a no-op
     * success, independence pair for the inSz != 0 operand. */
    ExpectIntEQ(wc_CMAC_Grow(&cmac, NULL, 0), 0);
    /* Baseline: every leaf false, a real grow. */
    ExpectIntEQ(wc_CMAC_Grow(&cmac, in, sizeof(in)), 0);

    wc_CmacFree(&cmac); /* frees cmac->msg under WOLFSSL_HASH_KEEP */
#endif
    return EXPECT_RESULT();
} /* END test_wc_CMAC_Grow */

/*
 * MC/DC: _InitCmac_common()'s id/label pre-storage guards -- (aesInitType
 * == CMAC_AES_INIT_ID && id != NULL && idLen > 0) and the switch's own
 * (id == NULL || idLen == 0 || label != NULL) re-check. Compiled out
 * entirely unless WOLF_PRIVATE_KEY_ID is defined. The label != NULL leaf
 * of the switch's re-check is unreachable via the public API (wc_InitCmac_Id
 * always passes label == NULL) -- see tests/unit-mcdc/test_cmac_whitebox.c.
 */
int test_wc_InitCmac_Id(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_CMAC) && !defined(NO_AES) && defined(WOLFSSL_AES_128) && \
    defined(WOLF_PRIVATE_KEY_ID)
    Cmac cmac;
    byte id[16];
    byte key[] = {
        0x64, 0x4c, 0xbf, 0x12, 0x85, 0x9d, 0xf0, 0x55,
        0x7e, 0xa9, 0x1f, 0x08, 0xe0, 0x51, 0xff, 0x27
    };
    int i;

    for (i = 0; i < (int)sizeof(id); i++) {
        id[i] = (byte)i;
    }

    /* id == NULL: BAD_FUNC_ARG from the switch's re-check. */
    XMEMSET(&cmac, 0, sizeof(cmac));
    ExpectIntEQ(wc_InitCmac_Id(&cmac, key, sizeof(key), WC_CMAC_AES, NULL,
        NULL, 0, NULL, INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* idLen == 0: BAD_FUNC_ARG from the switch's re-check. */
    XMEMSET(&cmac, 0, sizeof(cmac));
    ExpectIntEQ(wc_InitCmac_Id(&cmac, key, sizeof(key), WC_CMAC_AES, NULL,
        id, 0, NULL, INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Valid id: every guard false, a real init. */
    XMEMSET(&cmac, 0, sizeof(cmac));
    ExpectIntEQ(wc_InitCmac_Id(&cmac, key, sizeof(key), WC_CMAC_AES, NULL,
        id, (int)sizeof(id), NULL, INVALID_DEVID), 0);
    ExpectIntEQ(cmac.idLen, (int)sizeof(id));
    ExpectIntEQ(XMEMCMP(cmac.id, id, sizeof(id)), 0);
    wc_AesFree(&cmac.aes);
#endif
    return EXPECT_RESULT();
} /* END test_wc_InitCmac_Id */

/*
 * MC/DC: _InitCmac_common()'s label pre-storage guards -- (aesInitType ==
 * CMAC_AES_INIT_LABEL && label != NULL), (labelLen > 0 && labelLen <
 * sizeof(cmac->label)), and the switch's own (label == NULL || id != NULL
 * || idLen != 0) re-check. Compiled out entirely unless WOLF_PRIVATE_KEY_ID
 * is defined. The id != NULL / idLen != 0 leaves of the switch's re-check
 * are unreachable via the public API (wc_InitCmac_Label always passes
 * id == NULL, idLen == 0) -- see tests/unit-mcdc/test_cmac_whitebox.c.
 */
int test_wc_InitCmac_Label(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_CMAC) && !defined(NO_AES) && defined(WOLFSSL_AES_128) && \
    defined(WOLF_PRIVATE_KEY_ID)
    Cmac cmac;
    char longLabel[48];
    byte key[] = {
        0x64, 0x4c, 0xbf, 0x12, 0x85, 0x9d, 0xf0, 0x55,
        0x7e, 0xa9, 0x1f, 0x08, 0xe0, 0x51, 0xff, 0x27
    };
    int i;

    for (i = 0; i < (int)sizeof(longLabel) - 1; i++) {
        longLabel[i] = 'a';
    }
    longLabel[sizeof(longLabel) - 1] = '\0';

    /* label == NULL: BAD_FUNC_ARG from the switch's re-check. */
    XMEMSET(&cmac, 0, sizeof(cmac));
    ExpectIntEQ(wc_InitCmac_Label(&cmac, key, sizeof(key), WC_CMAC_AES, NULL,
        NULL, NULL, INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* labelLen == 0 (empty string): pre-storage skipped (labelLen > 0
     * false), switch's own re-check sees label != NULL (empty string is a
     * non-NULL pointer) so it proceeds into wc_AesInit_Label, which
     * independently rejects the zero length. */
    XMEMSET(&cmac, 0, sizeof(cmac));
    ExpectIntEQ(wc_InitCmac_Label(&cmac, key, sizeof(key), WC_CMAC_AES, NULL,
        "", NULL, INVALID_DEVID), WC_NO_ERR_TRACE(BUFFER_E));

    /* labelLen > sizeof(cmac->label): pre-storage skipped (labelLen <
     * sizeof(...) false); wc_AesInit_Label rejects the over-length label. */
    XMEMSET(&cmac, 0, sizeof(cmac));
    ExpectIntEQ(wc_InitCmac_Label(&cmac, key, sizeof(key), WC_CMAC_AES, NULL,
        longLabel, NULL, INVALID_DEVID), WC_NO_ERR_TRACE(BUFFER_E));

    /* Valid label: every guard false, a real init. */
    XMEMSET(&cmac, 0, sizeof(cmac));
    ExpectIntEQ(wc_InitCmac_Label(&cmac, key, sizeof(key), WC_CMAC_AES, NULL,
        "test-label", NULL, INVALID_DEVID), 0);
    ExpectIntEQ(cmac.labelLen, (int)XSTRLEN("test-label"));
    wc_AesFree(&cmac.aes);
#endif
    return EXPECT_RESULT();
} /* END test_wc_InitCmac_Label */

/*
 * MC/DC: wc_AesCmacGenerate_ex()'s own front guard -- physically distinct
 * from wc_AesCmacGenerate's textually-identical-looking guard -- called
 * directly so each of its 7 leaf conditions gets an independence pair.
 * Every case below keeps out == NULL (so wc_CmacFinalNoFree's own,
 * separately-covered out == NULL guard also always fires downstream when
 * this guard's leaf is false): the return code is BAD_FUNC_ARG either way,
 * what MC/DC observes is this decision's own leaf values.
 */
int test_wc_AesCmacGenerateExDecisionCoverage(void)
{
    EXPECT_DECLS;
/* wc_AesCmacGenerate_ex is absent from the frozen FIPS cmac.h (WCv4-stable,
 * WCv5.0-RC12, ...), so exclude FIPS builds. cmac is NOT frozen under CAVP
 * self-test, so no HAVE_SELFTEST clause is needed. */
#if defined(WOLFSSL_CMAC) && !defined(NO_AES) && defined(WOLFSSL_AES_128) && \
    !defined(HAVE_FIPS)
    Cmac   cmac;
    byte   key[] = {
        0x64, 0x4c, 0xbf, 0x12, 0x85, 0x9d, 0xf0, 0x55,
        0x7e, 0xa9, 0x1f, 0x08, 0xe0, 0x51, 0xff, 0x27
    };
    byte   in[] = { 0x01, 0x02, 0x03, 0x04 };
    byte   out[WC_AES_BLOCK_SIZE];
    word32 outSz;
    word32 zeroOutSz = 0;

    /* c0=out==NULL, c1=outSz!=NULL, c2=*outSz>0: all true. */
    XMEMSET(&cmac, 0, sizeof(cmac));
    outSz = sizeof(out);
    ExpectIntEQ(wc_AesCmacGenerate_ex(&cmac, NULL, &outSz, in, sizeof(in),
        key, sizeof(key), NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* c1 false (outSz==NULL): masks c2. */
    XMEMSET(&cmac, 0, sizeof(cmac));
    ExpectIntEQ(wc_AesCmacGenerate_ex(&cmac, NULL, NULL, in, sizeof(in),
        key, sizeof(key), NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* c2 false (*outSz==0), c0/c1 held true. */
    XMEMSET(&cmac, 0, sizeof(cmac));
    ExpectIntEQ(wc_AesCmacGenerate_ex(&cmac, NULL, &zeroOutSz, in,
        sizeof(in), key, sizeof(key), NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* c3=in==NULL, c4=inSz>0: out valid (c0 false) isolates this leaf. */
    XMEMSET(&cmac, 0, sizeof(cmac));
    outSz = sizeof(out);
    ExpectIntEQ(wc_AesCmacGenerate_ex(&cmac, out, &outSz, NULL, 4,
        key, sizeof(key), NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* c4 false (inSz==0), c3 held true: legitimate empty-message CMAC. */
    XMEMSET(&cmac, 0, sizeof(cmac));
    outSz = sizeof(out);
    ExpectIntEQ(wc_AesCmacGenerate_ex(&cmac, out, &outSz, NULL, 0,
        key, sizeof(key), NULL, INVALID_DEVID), 0);

    /* c5=key==NULL, c6=keySz>0: both true. */
    XMEMSET(&cmac, 0, sizeof(cmac));
    outSz = sizeof(out);
    ExpectIntEQ(wc_AesCmacGenerate_ex(&cmac, out, &outSz, in, sizeof(in),
        NULL, 16, NULL, INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* c6 false (keySz==0), c5 held true: "Init step is optional" per the
     * comment, so this reaches wc_CmacUpdate() on a never-initialized
     * Cmac and fails from ITS OWN type check (a different, already-
     * covered decision), not from this guard. */
    XMEMSET(&cmac, 0, sizeof(cmac));
    outSz = sizeof(out);
    ExpectIntEQ(wc_AesCmacGenerate_ex(&cmac, out, &outSz, in, sizeof(in),
        NULL, 0, NULL, INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Baseline: every leaf false, a real generate. */
    XMEMSET(&cmac, 0, sizeof(cmac));
    outSz = sizeof(out);
    ExpectIntEQ(wc_AesCmacGenerate_ex(&cmac, out, &outSz, in, sizeof(in),
        key, sizeof(key), NULL, INVALID_DEVID), 0);
#endif
    return EXPECT_RESULT();
} /* END test_wc_AesCmacGenerateExDecisionCoverage */

/*
 * MC/DC: wc_AesCmacVerify_ex()'s own front guard -- physically distinct
 * from wc_AesCmacVerify's guard -- called directly so each of its 6 leaf
 * conditions gets an independence pair.
 */
int test_wc_AesCmacVerifyExDecisionCoverage(void)
{
    EXPECT_DECLS;
/* wc_AesCmacVerify_ex is absent from the frozen FIPS cmac.h; exclude FIPS
 * (cmac is not frozen under CAVP self-test). */
#if defined(WOLFSSL_CMAC) && !defined(NO_AES) && defined(WOLFSSL_AES_128) && \
    !defined(HAVE_FIPS)
    Cmac   cmac;
    byte   key[] = {
        0x64, 0x4c, 0xbf, 0x12, 0x85, 0x9d, 0xf0, 0x55,
        0x7e, 0xa9, 0x1f, 0x08, 0xe0, 0x51, 0xff, 0x27
    };
    byte   in[] = { 0x01, 0x02, 0x03, 0x04 };
    byte   check[WC_AES_BLOCK_SIZE];

    XMEMSET(check, 0, sizeof(check));

    /* c0: cmac == NULL. */
    ExpectIntEQ(wc_AesCmacVerify_ex(NULL, check, sizeof(check), in,
        sizeof(in), key, sizeof(key), NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* c1: check == NULL. */
    XMEMSET(&cmac, 0, sizeof(cmac));
    ExpectIntEQ(wc_AesCmacVerify_ex(&cmac, NULL, sizeof(check), in,
        sizeof(in), key, sizeof(key), NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* c2: checkSz < WC_CMAC_TAG_MIN_SZ. */
    XMEMSET(&cmac, 0, sizeof(cmac));
    ExpectIntEQ(wc_AesCmacVerify_ex(&cmac, check, WC_CMAC_TAG_MIN_SZ - 1,
        in, sizeof(in), key, sizeof(key), NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* c3: checkSz > WC_AES_BLOCK_SIZE. */
    XMEMSET(&cmac, 0, sizeof(cmac));
    ExpectIntEQ(wc_AesCmacVerify_ex(&cmac, check, WC_AES_BLOCK_SIZE + 1,
        in, sizeof(in), key, sizeof(key), NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* c4,c5: in == NULL && inSz != 0 -- both true. */
    XMEMSET(&cmac, 0, sizeof(cmac));
    ExpectIntEQ(wc_AesCmacVerify_ex(&cmac, check, sizeof(check), NULL, 4,
        key, sizeof(key), NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* c5 false (inSz==0), c4 held true: every leaf false overall, proceeds
     * to the real compare (empty message vs an all-zero check tag, so
     * MAC_CMP_FAILED_E, not BAD_FUNC_ARG). */
    XMEMSET(&cmac, 0, sizeof(cmac));
    ExpectIntNE(wc_AesCmacVerify_ex(&cmac, check, sizeof(check), NULL, 0,
        key, sizeof(key), NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Baseline: every leaf false, real verify of a genuine tag. */
    {
        byte genMac[WC_AES_BLOCK_SIZE];
        word32 genMacSz = sizeof(genMac);
        XMEMSET(&cmac, 0, sizeof(cmac));
        ExpectIntEQ(wc_AesCmacGenerate_ex(&cmac, genMac, &genMacSz, in,
            sizeof(in), key, sizeof(key), NULL, INVALID_DEVID), 0);
        XMEMSET(&cmac, 0, sizeof(cmac));
        ExpectIntEQ(wc_AesCmacVerify_ex(&cmac, genMac, genMacSz, in,
            sizeof(in), key, sizeof(key), NULL, INVALID_DEVID), 0);
    }
#endif
    return EXPECT_RESULT();
} /* END test_wc_AesCmacVerifyExDecisionCoverage */

/* Match test_wc_AesCmacVerify_CryptoCb_LenMismatch's guard: the callback
 * dereferences wc_CryptoInfo's cmac member (WOLFSSL_CMAC only) and uses the
 * Cmac type / wc_AesCmacGenerate_ex, so WOLF_CRYPTO_CB alone is not enough. */
#if defined(WOLF_CRYPTO_CB) && defined(WOLFSSL_CMAC) && !defined(NO_AES) && \
    defined(WOLFSSL_AES_128) && !defined(HAVE_FIPS)
#define TEST_CMAC_CRYPTOCB_DEVID 0x434d4143 /* "CMAC" */

/* Toggled by the test function below: when set, the callback fails
 * outright instead of computing a CMAC, giving the (ret == 0 && aSz !=
 * checkSz) guard's ret == 0 operand a false side to pair against the
 * length-mismatch true side (both leaves must be shown within this same
 * binary; see the whitebox file's baseline-pairing note for why). */
static int test_cmac_cryptocb_force_fail = 0;

/* Registered for the wc_AesCmacVerify_ex() (ret == 0 && aSz != checkSz)
 * demonstration below: normally computes the real (software) CMAC via a
 * devId-less Cmac so it does not recurse back into this callback, then
 * intentionally reports back a DIFFERENT outSz than requested --
 * simulating a non-conformant hardware driver, exactly the scenario
 * wc_AesCmacVerify_ex's own comment warns about ("aSz is passed by
 * reference ... forwards to a user-supplied callback that may write back
 * any value"). */
static int test_cmac_cryptocb_badlen_cb(int cbDevId, wc_CryptoInfo* info,
    void* ctx)
{
    (void)ctx;
    if (cbDevId != TEST_CMAC_CRYPTOCB_DEVID)
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    if (test_cmac_cryptocb_force_fail)
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    if (info->algo_type == WC_ALGO_TYPE_CMAC && info->cmac.out != NULL &&
            info->cmac.outSz != NULL) {
        Cmac tmp;
        word32 realSz = *info->cmac.outSz;
        int ret;

        XMEMSET(&tmp, 0, sizeof(tmp));
        ret = wc_AesCmacGenerate_ex(&tmp, info->cmac.out, &realSz,
            info->cmac.in, info->cmac.inSz, info->cmac.key,
            info->cmac.keySz, NULL, INVALID_DEVID);
        if (ret == 0 && realSz > 1) {
            /* Report back a length different from what was asked for. */
            *info->cmac.outSz = realSz - 1;
        }
        return ret;
    }
    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}
#endif /* WOLF_CRYPTO_CB && WOLFSSL_CMAC && !NO_AES && WOLFSSL_AES_128 */

/*
 * MC/DC: wc_AesCmacVerify_ex()'s (ret == 0 && aSz != checkSz) guard. In
 * every native software build aSz is set from checkSz on entry and never
 * changed by the generate call, so aSz != checkSz is unreachable without a
 * crypto callback that violates the length contract -- exactly the
 * scenario the surrounding source comment documents. Compiled out
 * entirely unless WOLF_CRYPTO_CB is defined.
 */
int test_wc_AesCmacVerify_CryptoCb_LenMismatch(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_CMAC) && !defined(NO_AES) && defined(WOLFSSL_AES_128) && \
    defined(WOLF_CRYPTO_CB) && !defined(HAVE_FIPS)
    Cmac   cmac;
    byte   key[] = {
        0x64, 0x4c, 0xbf, 0x12, 0x85, 0x9d, 0xf0, 0x55,
        0x7e, 0xa9, 0x1f, 0x08, 0xe0, 0x51, 0xff, 0x27
    };
    byte   in[] = { 0x01, 0x02, 0x03, 0x04 };
    byte   check[WC_AES_BLOCK_SIZE];

    XMEMSET(check, 0, sizeof(check));

    ExpectIntEQ(wc_CryptoCb_RegisterDevice(TEST_CMAC_CRYPTOCB_DEVID,
        test_cmac_cryptocb_badlen_cb, NULL), 0);

    /* ret == 0 && aSz != checkSz: the callback above reports back a
     * shorter length than requested. */
    test_cmac_cryptocb_force_fail = 0;
    XMEMSET(&cmac, 0, sizeof(cmac));
    ExpectIntEQ(wc_AesCmacVerify_ex(&cmac, check, sizeof(check), in,
        sizeof(in), key, sizeof(key), NULL, TEST_CMAC_CRYPTOCB_DEVID),
        WC_NO_ERR_TRACE(BAD_STATE_E));

    /* ret != 0 (cond0 false): the callback fails outright, masking the
     * aSz != checkSz operand. Independence pair for cond0, held within
     * this same binary. */
    test_cmac_cryptocb_force_fail = 1;
    XMEMSET(&cmac, 0, sizeof(cmac));
    ExpectIntEQ(wc_AesCmacVerify_ex(&cmac, check, sizeof(check), in,
        sizeof(in), key, sizeof(key), NULL, TEST_CMAC_CRYPTOCB_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    test_cmac_cryptocb_force_fail = 0;

    wc_CryptoCb_UnRegisterDevice(TEST_CMAC_CRYPTOCB_DEVID);
#endif
    return EXPECT_RESULT();
} /* END test_wc_AesCmacVerify_CryptoCb_LenMismatch */

