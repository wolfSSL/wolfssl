/* test_asn.c
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

#include <tests/api/test_asn.h>

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/rsa.h>

#if defined(WC_ENABLE_ASYM_KEY_EXPORT) && defined(HAVE_ED25519)
static int test_SetAsymKeyDer_once(byte* privKey, word32 privKeySz, byte* pubKey,
    word32 pubKeySz, byte* trueDer, word32 trueDerSz)
{
    EXPECT_DECLS;

    byte* calcDer = NULL;
    word32 calcDerSz = 0;

    ExpectIntEQ(calcDerSz = SetAsymKeyDer(privKey, privKeySz, pubKey, pubKeySz,
        NULL, 0, ED25519k), trueDerSz);
    ExpectNotNull(calcDer = (byte*)XMALLOC(calcDerSz, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    ExpectIntEQ(calcDerSz = SetAsymKeyDer(privKey, privKeySz, pubKey, pubKeySz,
        calcDer, calcDerSz, ED25519k), trueDerSz);
    ExpectIntEQ(XMEMCMP(calcDer, trueDer, trueDerSz), 0);
    XFREE(calcDer, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return EXPECT_RESULT();
}
#endif /* WC_ENABLE_ASYM_KEY_EXPORT && HAVE_ED25519 */

int test_SetAsymKeyDer(void)
{
    EXPECT_DECLS;

#if defined(WC_ENABLE_ASYM_KEY_EXPORT) && defined(HAVE_ED25519)
    /* We can't access the keyEd25519Oid variable, so declare it instead */
    byte algId[] = {43, 101, 112};
    byte version[] = {0x0};
    byte keyPat = 0xcc;

    byte* privKey = NULL;
    word32 privKeySz = 0;
    byte* pubKey = NULL;
    word32 pubKeySz = 0;
    byte trueDer[310]; /* The largest size is 310 bytes on Condition 8 */
    word32 trueDerSz = 0;

    /*
     * Condition 1:
     *     PKEY data = 34            (1 to 127)
     *     PKEY_CURVEPKEY data = 32  (1 to 127)
     *     PUBKEY data = 0           (Empty)
     *     SEQ data = 46             (1 to 127)
     */
    privKeySz = 32;
    pubKeySz = 0;
    trueDerSz = 48;

    /* SEQ */
    trueDer[0]  = ASN_SEQUENCE | ASN_CONSTRUCTED;
    trueDer[1]  = trueDerSz - 2;
    /* VER */
    trueDer[2]  = ASN_INTEGER;
    trueDer[3]  = sizeof(version);
    trueDer[4]  = version[0];
    /* PKEYALGO_SEQ */
    trueDer[5]  = ASN_SEQUENCE | ASN_CONSTRUCTED;
    trueDer[6]  = sizeof(algId) + 2;
    trueDer[7]  = ASN_OBJECT_ID;
    trueDer[8]  = sizeof(algId);
    trueDer[9]  = algId[0];
    trueDer[10] = algId[1];
    trueDer[11] = algId[2];
    /* PKEY */
    trueDer[12] = ASN_OCTET_STRING;
    trueDer[13] = privKeySz + 2;
    trueDer[14] = ASN_OCTET_STRING;
    trueDer[15] = privKeySz;
    privKey     = &trueDer[16];
    XMEMSET(privKey, keyPat, privKeySz); /* trueDer[16] to trueDer[47] */
    /* PUBKEY */
    pubKey = NULL; /* Empty */

    EXPECT_TEST(test_SetAsymKeyDer_once(privKey, privKeySz, pubKey, pubKeySz,
        trueDer, trueDerSz));

    /*
     * Condition 2:
     *     PKEY data = 129          (128 to 255)
     *     PKEY_CURVEKEY data = 127 (0 to 127)
     *     PUBKEY data = 0          (Empty)
     *     SEQ data = 142           (128 to 255)
     */
    privKeySz = 127;
    pubKeySz = 0;
    trueDerSz = 145;

    /* SEQ */
    trueDer[0]  = ASN_SEQUENCE | ASN_CONSTRUCTED;
    trueDer[1]  = 0x81;
    trueDer[2]  = trueDerSz - 3;
    /* VER */
    trueDer[3]  = ASN_INTEGER;
    trueDer[4]  = sizeof(version);
    trueDer[5]  = version[0];
    /* PKEYALGO_SEQ */
    trueDer[6]  = ASN_SEQUENCE | ASN_CONSTRUCTED;
    trueDer[7]  = sizeof(algId) + 2;
    trueDer[8]  = ASN_OBJECT_ID;
    trueDer[9]  = sizeof(algId);
    trueDer[10] = algId[0];
    trueDer[11] = algId[1];
    trueDer[12] = algId[2];
    /* PKEY */
    trueDer[13] = ASN_OCTET_STRING;
    trueDer[14] = 0x81;
    trueDer[15] = privKeySz + 2;
    trueDer[16] = ASN_OCTET_STRING;
    trueDer[17] = privKeySz;
    privKey     = &trueDer[18];
    XMEMSET(privKey, keyPat, privKeySz); /* trueDer[18] to trueDer[144] */
    /* PUBKEY */
    pubKey = NULL; /* Empty */

    EXPECT_TEST(test_SetAsymKeyDer_once(privKey, privKeySz, pubKey, pubKeySz,
        trueDer, trueDerSz));

    /*
     * Condition 3:
     *     PKEY data = 131     (128 to 255)
     *     PKEY_CURVEKEY = 128 (128 to 255)
     *     PUBKEY data = 0     (Empty)
     *     SEQ data =144       (128 to 255)
     */
    privKeySz = 128;
    pubKeySz = 0;
    trueDerSz = 147;

    /* SEQ */
    trueDer[0]  = ASN_SEQUENCE | ASN_CONSTRUCTED;
    trueDer[1]  = 0x81;
    trueDer[2]  = trueDerSz - 3;
    /* VER */
    trueDer[3]  = ASN_INTEGER;
    trueDer[4]  = sizeof(version);
    trueDer[5]  = version[0];
    /* PKEYALGO_SEQ */
    trueDer[6]  = ASN_SEQUENCE | ASN_CONSTRUCTED;
    trueDer[7]  = sizeof(algId) + 2;
    trueDer[8]  = ASN_OBJECT_ID;
    trueDer[9]  = sizeof(algId);
    trueDer[10] = algId[0];
    trueDer[11] = algId[1];
    trueDer[12] = algId[2];
    /* PKEY */
    trueDer[13] = ASN_OCTET_STRING;
    trueDer[14] = 0x81;
    trueDer[15] = privKeySz + 3;
    trueDer[16] = ASN_OCTET_STRING;
    trueDer[17] = 0x81;
    trueDer[18] = privKeySz;
    privKey     = &trueDer[19];
    XMEMSET(privKey, keyPat, privKeySz); /* trueDer[19] to trueDer[146] */
    /* PUBKEY */
    pubKey = NULL; /* Empty */

    EXPECT_TEST(test_SetAsymKeyDer_once(privKey, privKeySz, pubKey, pubKeySz,
        trueDer, trueDerSz));

    /*
     * Condition 4:
     *     PKEY data = 258           (256 to 65535)
     *     PKEY_CURVEPKEY data = 255 (128 to 255)
     *     PUBKEY data = 0           (Empty)
     *     SEQ data = 272            (256 to 65536)
     */
    privKeySz = 255;
    pubKeySz = 0;
    trueDerSz = 276;

    /* SEQ */
    trueDer[0]  = ASN_SEQUENCE | ASN_CONSTRUCTED;
    trueDer[1]  = 0x82;
    trueDer[2]  = ((trueDerSz - 4) >> 8) & 0xff;
    trueDer[3]  = (trueDerSz - 4) & 0xff;
    /* VER */
    trueDer[4]  = ASN_INTEGER;
    trueDer[5]  = sizeof(version);
    trueDer[6]  = version[0];
    /* PKEYALGO_SEQ */
    trueDer[7]  = ASN_SEQUENCE | ASN_CONSTRUCTED;
    trueDer[8]  = sizeof(algId) + 2;
    trueDer[9]  = ASN_OBJECT_ID;
    trueDer[10] = sizeof(algId);
    trueDer[11] = algId[0];
    trueDer[12] = algId[1];
    trueDer[13] = algId[2];
    /* PKEY */
    trueDer[14] = ASN_OCTET_STRING;
    trueDer[15] = 0x82;
    trueDer[16] = ((privKeySz + 3) >> 8) & 0xff;
    trueDer[17] = (privKeySz + 3) & 0xff;
    trueDer[18] = ASN_OCTET_STRING;
    trueDer[19] = 0x81;
    trueDer[20] = privKeySz;
    privKey     = &trueDer[21];
    XMEMSET(privKey, keyPat, privKeySz); /* trueDer[21] to trueDer[275] */
    /* PUBKEY */
    pubKey = NULL; /* Empty */

    EXPECT_TEST(test_SetAsymKeyDer_once(privKey, privKeySz, pubKey, pubKeySz,
        trueDer, trueDerSz));

    /*
     * Condition 5:
     *     PKEY data = 260           (256 to 65535)
     *     PKEY_CURVEPKEY data = 256 (256 to 65535)
     *     PUBKEY data = 0           (Empty)
     *     SEQ data = 274            (256 to 65535)
     */
    privKeySz = 256;
    pubKeySz = 0;
    trueDerSz = 278;

    /* SEQ */
    trueDer[0]  = ASN_SEQUENCE | ASN_CONSTRUCTED;
    trueDer[1]  = 0x82;
    trueDer[2]  = ((trueDerSz - 4) >> 8) & 0xff;
    trueDer[3]  = (trueDerSz - 4) & 0xff;
    /* VER */
    trueDer[4]  = ASN_INTEGER;
    trueDer[5]  = sizeof(version);
    trueDer[6]  = version[0];
    /* PKEYALGO_SEQ */
    trueDer[7]  = ASN_SEQUENCE | ASN_CONSTRUCTED;
    trueDer[8]  = sizeof(algId) + 2;
    trueDer[9]  = ASN_OBJECT_ID;
    trueDer[10] = sizeof(algId);
    trueDer[11] = algId[0];
    trueDer[12] = algId[1];
    trueDer[13] = algId[2];
    /* PKEY */
    trueDer[14] = ASN_OCTET_STRING;
    trueDer[15] = 0x82;
    trueDer[16] = ((privKeySz + 4) >> 8) & 0xff;
    trueDer[17] = (privKeySz + 4) & 0xff;
    trueDer[18] = ASN_OCTET_STRING;
    trueDer[19] = 0x82;
    trueDer[20] = (privKeySz >> 8) & 0xff;
    trueDer[21] = privKeySz & 0xff;
    privKey     = &trueDer[22];
    XMEMSET(privKey, keyPat, privKeySz); /* trueDer[22] to trueDer[277] */
    /* PUBKEY */
    pubKey = NULL; /* Empty */

    EXPECT_TEST(test_SetAsymKeyDer_once(privKey, privKeySz, pubKey, pubKeySz,
        trueDer, trueDerSz));

    /*
     * Condition 6:
     *     PKEY data = 34            (1 to 127)
     *     PKEY_CURVEPKEY data = 32  (1 to 127)
     *     PUBKEY data = 32          (1 to 127)
     *     SEQ data = 80             (1 to 127)
     */
    privKeySz = 32;
    pubKeySz = 32;
    trueDerSz = 82;

    /* SEQ */
    trueDer[0]  = ASN_SEQUENCE | ASN_CONSTRUCTED;
    trueDer[1]  = trueDerSz - 2;
    /* VER */
    trueDer[2]  = ASN_INTEGER;
    trueDer[3]  = sizeof(version);
    trueDer[4]  = version[0];
    /* PKEYALGO_SEQ */
    trueDer[5]  = ASN_SEQUENCE | ASN_CONSTRUCTED;
    trueDer[6]  = sizeof(algId) + 2;
    trueDer[7]  = ASN_OBJECT_ID;
    trueDer[8]  = sizeof(algId);
    trueDer[9]  = algId[0];
    trueDer[10] = algId[1];
    trueDer[11] = algId[2];
    /* PKEY */
    trueDer[12] = ASN_OCTET_STRING;
    trueDer[13] = privKeySz + 2;
    trueDer[14] = ASN_OCTET_STRING;
    trueDer[15] = privKeySz;
    privKey     = &trueDer[16];
    XMEMSET(privKey, keyPat, privKeySz); /* trueDer[16] to trueDer[47] */
    /* PUBKEY */
    trueDer[48] = ASN_CONTEXT_SPECIFIC | ASN_ASYMKEY_PUBKEY;
    trueDer[49] = pubKeySz;
    pubKey      = &trueDer[50];
    XMEMSET(pubKey, keyPat, pubKeySz); /* trueDer[50] to trueDer[81] */

    EXPECT_TEST(test_SetAsymKeyDer_once(privKey, privKeySz, pubKey, pubKeySz,
        trueDer, trueDerSz));

    /*
     * Condition 7:
     *     PKEY data = 34            (1 to 127)
     *     PKEY_CURVEPKEY data = 32  (1 to 127)
     *     PUBKEY data = 128         (128 to 255)
     *     SEQ data = 180            (128 to 255)
     */
    privKeySz = 32;
    pubKeySz = 128;
    trueDerSz = 180;

    /* SEQ */
    trueDer[0]  = ASN_SEQUENCE | ASN_CONSTRUCTED;
    trueDer[1]  = 0x81;
    trueDer[2]  = trueDerSz - 3;
    /* VER */
    trueDer[3]  = ASN_INTEGER;
    trueDer[4]  = sizeof(version);
    trueDer[5]  = version[0];
    /* PKEYALGO_SEQ */
    trueDer[6]  = ASN_SEQUENCE | ASN_CONSTRUCTED;
    trueDer[7]  = sizeof(algId) + 2;
    trueDer[8]  = ASN_OBJECT_ID;
    trueDer[9]  = sizeof(algId);
    trueDer[10] = algId[0];
    trueDer[11] = algId[1];
    trueDer[12] = algId[2];
    /* PKEY */
    trueDer[13] = ASN_OCTET_STRING;
    trueDer[14] = privKeySz + 2;
    trueDer[15] = ASN_OCTET_STRING;
    trueDer[16] = privKeySz;
    privKey     = &trueDer[17];
    XMEMSET(privKey, keyPat, privKeySz); /* trueDer[17] to trueDer[48] */
    /* PUBKEY */
    trueDer[49] = ASN_CONTEXT_SPECIFIC | ASN_ASYMKEY_PUBKEY;
    trueDer[50] = 0x81;
    trueDer[51] = pubKeySz;
    pubKey      = &trueDer[52];
    XMEMSET(pubKey, keyPat, pubKeySz); /* trueDer[52] to trueDer[179] */

    EXPECT_TEST(test_SetAsymKeyDer_once(privKey, privKeySz, pubKey, pubKeySz,
        trueDer, trueDerSz));

    /*
     * Condition 8:
     *     PKEY data = 34            (1 to 127)
     *     PKEY_CURVEPKEY data = 32  (1 to 127)
     *     PUBKEY data = 256         (256 to 65535)
     *     SEQ data = 306            (256 to 65535)
     */
    privKeySz = 32;
    pubKeySz = 256;
    trueDerSz = 310;

    /* SEQ */
    trueDer[0]  = ASN_SEQUENCE | ASN_CONSTRUCTED;
    trueDer[1]  = 0x82;
    trueDer[2]  = ((trueDerSz - 4) >> 8) & 0xff;
    trueDer[3]  = (trueDerSz - 4) & 0xff;
    /* VER */
    trueDer[4]  = ASN_INTEGER;
    trueDer[5]  = sizeof(version);
    trueDer[6]  = version[0];
    /* PKEYALGO_SEQ */
    trueDer[7]  = ASN_SEQUENCE | ASN_CONSTRUCTED;
    trueDer[8]  = sizeof(algId) + 2;
    trueDer[9]  = ASN_OBJECT_ID;
    trueDer[10] = sizeof(algId);
    trueDer[11] = algId[0];
    trueDer[12] = algId[1];
    trueDer[13] = algId[2];
    /* PKEY */
    trueDer[14] = ASN_OCTET_STRING;
    trueDer[15] = privKeySz + 2;
    trueDer[16] = ASN_OCTET_STRING;
    trueDer[17] = privKeySz;
    privKey     = &trueDer[18];
    XMEMSET(privKey, keyPat, privKeySz); /* trueDer[18] to trueDer[49] */
    /* PUBKEY */
    trueDer[50] = ASN_CONTEXT_SPECIFIC | ASN_ASYMKEY_PUBKEY;
    trueDer[51] = 0x82;
    trueDer[52] = (pubKeySz >> 8) & 0xff;
    trueDer[53] = pubKeySz & 0xff;
    pubKey      = &trueDer[54];
    XMEMSET(pubKey, keyPat, pubKeySz); /* trueDer[54] to trueDer[309] */

    EXPECT_TEST(test_SetAsymKeyDer_once(privKey, privKeySz, pubKey, pubKeySz,
        trueDer, trueDerSz));
#endif /* WC_ENABLE_ASYM_KEY_EXPORT && HAVE_ED25519 */

    return EXPECT_RESULT();

}

#ifndef NO_ASN
static int test_GetSetShortInt_once(word32 val, byte* valDer, word32 valDerSz)
{
    EXPECT_DECLS;

#ifndef NO_PWDBASED
#if !defined(WOLFSSL_ASN_TEMPLATE) || defined(HAVE_PKCS8) || \
     defined(HAVE_PKCS12)

    byte outDer[MAX_SHORT_SZ];
    word32 outDerSz = 0;
    word32 inOutIdx = 0;
    word32 maxIdx = MAX_SHORT_SZ;
    int value;

    ExpectIntLE(2 + valDerSz, MAX_SHORT_SZ);
    ExpectIntEQ(outDerSz = SetShortInt(outDer, &inOutIdx, val, maxIdx),
        2 + valDerSz);
    ExpectIntEQ(outDer[0], ASN_INTEGER);
    ExpectIntEQ(outDer[1], valDerSz);
    ExpectIntEQ(XMEMCMP(outDer + 2, valDer, valDerSz), 0);
    if (val < 0x80000000) {
        /* GetShortInt only supports positive values. */
        inOutIdx = 0;
        ExpectIntEQ(val, GetShortInt(outDer, &inOutIdx, &value, maxIdx));
    }

#endif /* !WOLFSSL_ASN_TEMPLATE || HAVE_PKCS8 || HAVE_PKCS12 */
#endif /* !NO_PWDBASED */

    (void)val;
    (void)valDer;
    (void)valDerSz;

    return EXPECT_RESULT();
}
#endif

int test_GetSetShortInt(void)
{
    EXPECT_DECLS;

#ifndef NO_ASN
    byte valDer[MAX_SHORT_SZ] = {0};

    /* Corner tests for input size */
    {
        /* Input 1 byte min */
        valDer[0] = 0x00;
        EXPECT_TEST(test_GetSetShortInt_once(0x00, valDer, 1));

        /* Input 1 byte max */
        valDer[0] = 0x00;
        valDer[1] = 0xff;
        EXPECT_TEST(test_GetSetShortInt_once(0xff, valDer, 2));

        /* Input 2 bytes min */
        valDer[0] = 0x01;
        valDer[1] = 0x00;
        EXPECT_TEST(test_GetSetShortInt_once(0x0100, valDer, 2));

        /* Input 2 bytes max */
        valDer[0] = 0x00;
        valDer[1] = 0xff;
        valDer[2] = 0xff;
        EXPECT_TEST(test_GetSetShortInt_once(0xffff, valDer, 3));

        /* Input 3 bytes min */
        valDer[0] = 0x01;
        valDer[1] = 0x00;
        valDer[2] = 0x00;
        EXPECT_TEST(test_GetSetShortInt_once(0x010000, valDer, 3));

        /* Input 3 bytes max */
        valDer[0] = 0x00;
        valDer[1] = 0xff;
        valDer[2] = 0xff;
        valDer[3] = 0xff;
        EXPECT_TEST(test_GetSetShortInt_once(0xffffff, valDer, 4));

        /* Input 4 bytes min */
        valDer[0] = 0x01;
        valDer[1] = 0x00;
        valDer[2] = 0x00;
        valDer[3] = 0x00;
        EXPECT_TEST(test_GetSetShortInt_once(0x01000000, valDer, 4));

        /* Input 4 bytes max */
        valDer[0] = 0x00;
        valDer[1] = 0xff;
        valDer[2] = 0xff;
        valDer[3] = 0xff;
        valDer[4] = 0xff;
        EXPECT_TEST(test_GetSetShortInt_once(0xffffffff, valDer, 5));
    }

    /* Corner tests for output size */
    {
        /* Skip "Output 1 byte min" because of same as "Input 1 byte min" */

        /* Output 1 byte max */
        valDer[0] = 0x7f;
        EXPECT_TEST(test_GetSetShortInt_once(0x7f, valDer, 1));

        /* Output 2 bytes min */
        valDer[0] = 0x00;
        valDer[1] = 0x80;
        EXPECT_TEST(test_GetSetShortInt_once(0x80, valDer, 2));

        /* Output 2 bytes max */
        valDer[0] = 0x7f;
        valDer[1] = 0xff;
        EXPECT_TEST(test_GetSetShortInt_once(0x7fff, valDer, 2));

        /* Output 3 bytes min */
        valDer[0] = 0x00;
        valDer[1] = 0x80;
        valDer[2] = 0x00;
        EXPECT_TEST(test_GetSetShortInt_once(0x8000, valDer, 3));

        /* Output 3 bytes max */
        valDer[0] = 0x7f;
        valDer[1] = 0xff;
        valDer[2] = 0xff;
        EXPECT_TEST(test_GetSetShortInt_once(0x7fffff, valDer, 3));

        /* Output 4 bytes min */
        valDer[0] = 0x00;
        valDer[1] = 0x80;
        valDer[2] = 0x00;
        valDer[3] = 0x00;
        EXPECT_TEST(test_GetSetShortInt_once(0x800000, valDer, 4));

        /* Output 4 bytes max */
        valDer[0] = 0x7f;
        valDer[1] = 0xff;
        valDer[2] = 0xff;
        valDer[3] = 0xff;
        EXPECT_TEST(test_GetSetShortInt_once(0x7fffffff, valDer, 4));

        /* Output 5 bytes min */
        valDer[0] = 0x00;
        valDer[1] = 0x80;
        valDer[2] = 0x00;
        valDer[3] = 0x00;
        valDer[4] = 0x00;
        EXPECT_TEST(test_GetSetShortInt_once(0x80000000, valDer, 5));

        /* Skip "Output 5 bytes max" because of same as "Input 4 bytes max" */
    }

    /* Extra tests */
    {
        valDer[0] = 0x01;
        EXPECT_TEST(test_GetSetShortInt_once(0x01, valDer, 1));
    }

#if !defined(NO_PWDBASED) || defined(WOLFSSL_ASN_EXTRA)
    /* Negative INTEGER values. */
    {
        word32 idx = 0;
        int value;

        valDer[0] = ASN_INTEGER;
        valDer[1] = 1;
        valDer[2] = 0x80;
        ExpectIntEQ(GetShortInt(valDer, &idx, &value, 3),
                WC_NO_ERR_TRACE(ASN_EXPECT_0_E));

        idx = 0;
        valDer[0] = ASN_INTEGER;
        valDer[1] = 4;
        valDer[2] = 0xFF;
        valDer[3] = 0xFF;
        valDer[4] = 0xFF;
        valDer[5] = 0xFF;
        ExpectIntEQ(GetShortInt(valDer, &idx, &value, 6),
                WC_NO_ERR_TRACE(ASN_EXPECT_0_E));
    }
#endif
#endif

    return EXPECT_RESULT();
}


int test_wc_IndexSequenceOf(void)
{
    EXPECT_DECLS;

#ifndef NO_ASN
    const byte int_seq[] = {
        0x30, 0x0A,
        0x02, 0x01, 0x0A,
        0x02, 0x02, 0x00, 0xF0,
        0x02, 0x01, 0x7F,
    };
    const byte bad_seq[] = {
        0xA0, 0x01, 0x01,
    };
    const byte empty_seq[] = {
        0x30, 0x00,
    };

    const byte * element;
    word32 elementSz;

    ExpectIntEQ(wc_IndexSequenceOf(int_seq, sizeof(int_seq), 0U, &element, &elementSz), 0);
    ExpectPtrEq(element, &int_seq[2]);
    ExpectIntEQ(elementSz, 3);

    ExpectIntEQ(wc_IndexSequenceOf(int_seq, sizeof(int_seq), 1U, &element, &elementSz), 0);
    ExpectPtrEq(element, &int_seq[5]);
    ExpectIntEQ(elementSz, 4);

    ExpectIntEQ(wc_IndexSequenceOf(int_seq, sizeof(int_seq), 2U, &element, &elementSz), 0);
    ExpectPtrEq(element, &int_seq[9]);
    ExpectIntEQ(elementSz, 3);

    ExpectIntEQ(wc_IndexSequenceOf(int_seq, sizeof(int_seq), 3U, &element, &elementSz), WC_NO_ERR_TRACE(BAD_INDEX_E));

    ExpectIntEQ(wc_IndexSequenceOf(bad_seq, sizeof(bad_seq), 0U, &element, &elementSz), WC_NO_ERR_TRACE(ASN_PARSE_E));

    ExpectIntEQ(wc_IndexSequenceOf(empty_seq, sizeof(empty_seq), 0U, &element, &elementSz), WC_NO_ERR_TRACE(BAD_INDEX_E));
#endif

    return EXPECT_RESULT();
}

int test_wolfssl_local_MatchBaseName(void)
{
    EXPECT_DECLS;

#if !defined(NO_CERTS) && !defined(NO_ASN) && !defined(IGNORE_NAME_CONSTRAINTS)
    /*
     * Tests for DNS type (ASN_DNS_TYPE = 0x02)
     */

    /* Positive tests - should match */
    /* Exact match */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "domain.com", 10, "domain.com", 10), 1);
    /* Case insensitive match */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "DOMAIN.COM", 10, "domain.com", 10), 1);
    /* Subdomain match (RFC 5280: adding labels to the left) */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "sub.domain.com", 14, "domain.com", 10), 1);
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "a.b.domain.com", 14, "domain.com", 10), 1);
    /* Leading dot constraint with subdomain (not RFC 5280 compliant for DNS,
     * but kept for backwards compatibility) */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "sub.domain.com", 14, ".domain.com", 11), 1);
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "a.b.domain.com", 14, ".domain.com", 11), 1);

    /* Negative tests - should NOT match */
    /* Bug #3: fakedomain.com should NOT match domain.com (no dot boundary) */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "fakedomain.com", 14, "domain.com", 10), 0);
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "notdomain.com", 13, "domain.com", 10), 0);
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "xexample.com", 12, "example.com", 11), 0);
    /* Bug #3: fakedomain.com should NOT match .domain.com */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "fakedomain.com", 14, ".domain.com", 11), 0);
    /* domain.com should NOT match .domain.com (leading dot requires subdomain) */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "domain.com", 10, ".domain.com", 11), 0);
    /* Different domain */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "other.com", 9, "domain.com", 10), 0);
    /* Name starting with dot */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                ".domain.com", 11, "domain.com", 10), 0);

    /*
     * Tests for email type (ASN_RFC822_TYPE = 0x01)
     */

    /* Positive tests - should match */
    /* Exact email match */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_RFC822_TYPE,
                "user@domain.com", 15, "user@domain.com", 15), 1);
    /* Email with domain constraint (leading dot) - subdomain present */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_RFC822_TYPE,
                "user@sub.domain.com", 19, ".domain.com", 11), 1);
    /* Email with domain constraint (no leading dot) - exact domain */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_RFC822_TYPE,
                "user@domain.com", 15, "domain.com", 10), 1);

    /* Negative tests - should NOT match */
    /* user@domain.com should NOT match .domain.com (subdomain required) */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_RFC822_TYPE,
                "user@domain.com", 15, ".domain.com", 11), 0);
    /* user@sub.domain.com should NOT match domain.com (exact domain only) */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_RFC822_TYPE,
                "user@sub.domain.com", 19, "domain.com", 10), 0);
    /* @ at start is invalid */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_RFC822_TYPE,
                "@domain.com", 11, ".domain.com", 11), 0);
    /* @ at end is invalid */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_RFC822_TYPE,
                "user@", 5, ".domain.com", 11), 0);
    /* double @ is invalid */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_RFC822_TYPE,
                "user@@domain.com", 16, ".domain.com", 11), 0);
    /* multiple @ is invalid */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_RFC822_TYPE,
                "user@domain@extra.com", 21, ".domain.com", 11), 0);
    /* No @ in email name */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_RFC822_TYPE,
                "userdomain.com", 14, ".domain.com", 11), 0);
    /* Email domain doesn't match constraint */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_RFC822_TYPE,
                "user@other.com", 14, ".domain.com", 11), 0);
    /* Email suffix without dot boundary (fakedomain) */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_RFC822_TYPE,
                "user@fakedomain.com", 19, ".domain.com", 11), 0);
    /* Base constraint with invalid @ position */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_RFC822_TYPE,
                "user@domain.com", 15, "@domain.com", 11), 0);
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_RFC822_TYPE,
                "user@domain.com", 15, "user@", 5), 0);

    /*
     * Tests for directory type (ASN_DIR_TYPE = 0x04)
     */

    /* Positive tests - should match */
    /* Exact match */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DIR_TYPE,
                "CN=test", 7, "CN=test", 7), 1);
    /* Prefix match (name longer than base) */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DIR_TYPE,
                "CN=test,O=org", 13, "CN=test", 7), 1);

    /* Negative tests - should NOT match */
    /* Different content */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DIR_TYPE,
                "CN=other", 8, "CN=test", 7), 0);
    /* Case sensitive for directory */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DIR_TYPE,
                "CN=TEST", 7, "CN=test", 7), 0);

    /*
     * Edge cases and error handling
     */

    /* NULL pointers */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                NULL, 10, "domain.com", 10), 0);
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "domain.com", 10, NULL, 10), 0);
    /* Empty/zero size */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "", 0, "domain.com", 10), 0);
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "domain.com", 10, "", 0), 0);
    /* Invalid type */
    ExpectIntEQ(wolfssl_local_MatchBaseName(0xFF,
                "domain.com", 10, "domain.com", 10), 0);
    /* Name starting with dot */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                ".", 1, ".", 1), 0);
    /* Name shorter than base */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "a.com", 5, "domain.com", 10), 0);

#endif /* !NO_CERTS && !NO_ASN && !IGNORE_NAME_CONSTRAINTS */

    return EXPECT_RESULT();
}

/*
 * Testing wc_DecodeRsaPssParams with known DER byte arrays.
 * Exercises both WOLFSSL_ASN_TEMPLATE and non-template paths.
 */
int test_wc_DecodeRsaPssParams(void)
{
    EXPECT_DECLS;
#if defined(WC_RSA_PSS) && !defined(NO_RSA) && !defined(NO_ASN)
    enum wc_HashType hash;
    int mgf;
    int saltLen;

    /* SHA-256 / MGF1-SHA-256 / saltLen=32 */
    static const byte pssParamsSha256[] = {
        0x30, 0x34,
          0xA0, 0x0F,
            0x30, 0x0D,
              0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                          0x04, 0x02, 0x01,
              0x05, 0x00,
          0xA1, 0x1C,
            0x30, 0x1A,
              0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
                          0x01, 0x01, 0x08,
              0x30, 0x0D,
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                            0x04, 0x02, 0x01,
                0x05, 0x00,
          0xA2, 0x03,
            0x02, 0x01, 0x20,
    };

    /* Hash-only: SHA-256 hash, defaults for MGF and salt */
    static const byte pssParamsHashOnly[] = {
        0x30, 0x11,
          0xA0, 0x0F,
            0x30, 0x0D,
              0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                          0x04, 0x02, 0x01,
              0x05, 0x00,
    };

    /* Salt-only: default hash/mgf, saltLen=48 */
    static const byte pssParamsSaltOnly[] = {
        0x30, 0x05,
          0xA2, 0x03,
            0x02, 0x01, 0x30,
    };

    /* NULL tag (05 00) means all defaults */
    static const byte pssParamsNull[] = { 0x05, 0x00 };

    /* Empty SEQUENCE means all non-default fields omitted => defaults */
    static const byte pssParamsEmptySeq[] = { 0x30, 0x00 };

    /* --- Test 1: sz=0 => all defaults --- */
    hash = WC_HASH_TYPE_NONE;
    mgf = 0;
    saltLen = 0;
    ExpectIntEQ(wc_DecodeRsaPssParams((const byte*)"", 0,
        &hash, &mgf, &saltLen), 0);
    ExpectIntEQ((int)hash, (int)WC_HASH_TYPE_SHA);
    ExpectIntEQ(mgf, WC_MGF1SHA1);
    ExpectIntEQ(saltLen, 20);

    /* --- Test 2: NULL tag => all defaults --- */
    hash = WC_HASH_TYPE_NONE;
    mgf = 0;
    saltLen = 0;
    ExpectIntEQ(wc_DecodeRsaPssParams(pssParamsNull,
        (word32)sizeof(pssParamsNull), &hash, &mgf, &saltLen), 0);
    ExpectIntEQ((int)hash, (int)WC_HASH_TYPE_SHA);
    ExpectIntEQ(mgf, WC_MGF1SHA1);
    ExpectIntEQ(saltLen, 20);

    /* --- Test 3: Empty SEQUENCE => all defaults --- */
    hash = WC_HASH_TYPE_NONE;
    mgf = 0;
    saltLen = 0;
    ExpectIntEQ(wc_DecodeRsaPssParams(pssParamsEmptySeq,
        (word32)sizeof(pssParamsEmptySeq), &hash, &mgf, &saltLen), 0);
    ExpectIntEQ((int)hash, (int)WC_HASH_TYPE_SHA);
    ExpectIntEQ(mgf, WC_MGF1SHA1);
    ExpectIntEQ(saltLen, 20);

#ifndef NO_SHA256
    /* --- Test 4: SHA-256 / MGF1-SHA-256 / salt=32 --- */
    hash = WC_HASH_TYPE_NONE;
    mgf = 0;
    saltLen = 0;
    ExpectIntEQ(wc_DecodeRsaPssParams(pssParamsSha256,
        (word32)sizeof(pssParamsSha256), &hash, &mgf, &saltLen), 0);
    ExpectIntEQ((int)hash, (int)WC_HASH_TYPE_SHA256);
    ExpectIntEQ(mgf, WC_MGF1SHA256);
    ExpectIntEQ(saltLen, 32);

    /* --- Test 5: Hash only => SHA-256, default MGF/salt --- */
    hash = WC_HASH_TYPE_NONE;
    mgf = 0;
    saltLen = 0;
    ExpectIntEQ(wc_DecodeRsaPssParams(pssParamsHashOnly,
        (word32)sizeof(pssParamsHashOnly), &hash, &mgf, &saltLen), 0);
    ExpectIntEQ((int)hash, (int)WC_HASH_TYPE_SHA256);
    ExpectIntEQ(mgf, WC_MGF1SHA1);
    ExpectIntEQ(saltLen, 20);
#endif

    /* --- Test 6: Salt only => default hash/MGF, salt=48 --- */
    hash = WC_HASH_TYPE_NONE;
    mgf = 0;
    saltLen = 0;
    ExpectIntEQ(wc_DecodeRsaPssParams(pssParamsSaltOnly,
        (word32)sizeof(pssParamsSaltOnly), &hash, &mgf, &saltLen), 0);
    ExpectIntEQ((int)hash, (int)WC_HASH_TYPE_SHA);
    ExpectIntEQ(mgf, WC_MGF1SHA1);
    ExpectIntEQ(saltLen, 48);

    /* --- Test 7: NULL pointer -> BAD_FUNC_ARG --- */
    ExpectIntEQ(wc_DecodeRsaPssParams(NULL, 10, &hash, &mgf, &saltLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* --- Test 8: Bad leading tag => ASN_PARSE_E --- */
    {
        static const byte badTag[] = { 0x01, 0x00 };
        ExpectIntEQ(wc_DecodeRsaPssParams(badTag, (word32)sizeof(badTag),
            &hash, &mgf, &saltLen), WC_NO_ERR_TRACE(ASN_PARSE_E));
    }

#endif /* WC_RSA_PSS && !NO_RSA && !NO_ASN */
    return EXPECT_RESULT();
}

/* Test that DecodeAltNames rejects a SAN entry whose length exceeds the
 * remaining SEQUENCE length (integer underflow on the length tracker). */
int test_DecodeAltNames_length_underflow(void)
{
    EXPECT_DECLS;

#if !defined(NO_CERTS) && !defined(NO_RSA) && !defined(NO_ASN)
    /* Self-signed DER certificate with a well-formed SAN extension.
     * Byte at offset 418 is the SAN SEQUENCE length (0x06).  The negative
     * test below copies this cert and shrinks that byte to 0x03 so the
     * DNS entry length exceeds the SEQUENCE bounds. */
    static const unsigned char good_san_cert[] = {
        0x30, 0x82, 0x02, 0xf9, 0x30, 0x82, 0x01, 0xe1, 0xa0, 0x03, 0x02, 0x01,
        0x02, 0x02, 0x02, 0x10, 0x21, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
        0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x0f, 0x31, 0x0d,
        0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x04, 0x61, 0x61, 0x31,
        0x31, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x36, 0x30, 0x32, 0x30, 0x37, 0x31,
        0x37, 0x32, 0x34, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x33, 0x34, 0x30, 0x32,
        0x31, 0x34, 0x30, 0x36, 0x32, 0x36, 0x35, 0x33, 0x5a, 0x30, 0x0f, 0x31,
        0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x04, 0x61, 0x61,
        0x61, 0x61, 0x30, 0x82, 0x01, 0x20, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
        0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01,
        0x0d, 0x00, 0x30, 0x82, 0x01, 0x08, 0x02, 0x82, 0x01, 0x01, 0x00, 0xa8,
        0x8a, 0x5e, 0x26, 0x23, 0x1b, 0x31, 0xd3, 0x37, 0x1a, 0x70, 0xb2, 0xec,
        0x3f, 0x74, 0xd4, 0xb4, 0x44, 0xe3, 0x7a, 0xa5, 0xc0, 0xf5, 0xaa, 0x97,
        0x26, 0x9a, 0x04, 0xff, 0xda, 0xbe, 0xe5, 0x09, 0x03, 0x98, 0x3d, 0xb5,
        0xbf, 0x01, 0x2c, 0x9a, 0x0a, 0x3a, 0xfb, 0xbc, 0x3c, 0xe7, 0xbe, 0x83,
        0x5c, 0xb3, 0x70, 0xe8, 0x5c, 0xe3, 0xd1, 0x83, 0xc3, 0x94, 0x08, 0xcd,
        0x1a, 0x87, 0xe5, 0xe0, 0x5b, 0x9c, 0x5c, 0x6e, 0xb0, 0x7d, 0xe2, 0x58,
        0x6c, 0xc3, 0xb5, 0xc8, 0x9d, 0x11, 0xf1, 0x5d, 0x96, 0x0d, 0x66, 0x1e,
        0x56, 0x7f, 0x8f, 0x59, 0xa7, 0xa5, 0xe1, 0xc5, 0xe7, 0x81, 0x4c, 0x09,
        0x9d, 0x5e, 0x96, 0xf0, 0x9a, 0xc2, 0x8b, 0x70, 0xd5, 0xab, 0x79, 0x58,
        0x5d, 0xb7, 0x58, 0xaa, 0xfd, 0x75, 0x52, 0xaa, 0x4b, 0xa7, 0x25, 0x68,
        0x76, 0x59, 0x00, 0xee, 0x78, 0x2b, 0x91, 0xc6, 0x59, 0x91, 0x99, 0x38,
        0x3e, 0xa1, 0x76, 0xc3, 0xf5, 0x23, 0x6b, 0xe6, 0x07, 0xea, 0x63, 0x1c,
        0x97, 0x49, 0xef, 0xa0, 0xfe, 0xfd, 0x13, 0xc9, 0xa9, 0x9f, 0xc2, 0x0b,
        0xe6, 0x87, 0x92, 0x5b, 0xcc, 0xf5, 0x42, 0x95, 0x4a, 0xa4, 0x6d, 0x64,
        0xba, 0x7d, 0xce, 0xcb, 0x04, 0xd0, 0xf8, 0xe7, 0xe3, 0xda, 0x75, 0x60,
        0xd3, 0x8b, 0x6a, 0x64, 0xfc, 0x78, 0x56, 0x21, 0x69, 0x5a, 0xe8, 0xa7,
        0x8f, 0xfb, 0x8f, 0x82, 0xe3, 0xae, 0x36, 0xa2, 0x93, 0x66, 0x92, 0xcb,
        0x82, 0xa3, 0xbe, 0x84, 0x00, 0x86, 0xdc, 0x7e, 0x6d, 0x53, 0x77, 0x84,
        0x17, 0xb9, 0x55, 0x43, 0x0d, 0xf1, 0x16, 0x1f, 0xd5, 0x43, 0x75, 0x99,
        0x66, 0x19, 0x52, 0xd0, 0xac, 0x5f, 0x74, 0xad, 0xb2, 0x90, 0x15, 0x50,
        0x04, 0x74, 0x43, 0xdf, 0x6c, 0x35, 0xd0, 0xfd, 0x32, 0x37, 0xb3, 0x8d,
        0xf5, 0xe5, 0x09, 0x02, 0x01, 0x03, 0xa3, 0x61, 0x30, 0x5f, 0x30, 0x0c,
        0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00,
        /* SAN extension: correct SEQUENCE length 0x06 */
        0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x08, 0x30, 0x06, 0x82,
        0x04, 0x61, 0x2a, 0x62, 0x2a, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e,
        0x04, 0x16, 0x04, 0x14, 0x92, 0x6a, 0x1e, 0x52, 0x3a, 0x1a, 0x57, 0x9f,
        0xc9, 0x82, 0x9a, 0xce, 0xc8, 0xc0, 0xa9, 0x51, 0x9d, 0x2f, 0xc7, 0x72,
        0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80,
        0x14, 0x6b, 0xf9, 0xa4, 0x2d, 0xa5, 0xe9, 0x39, 0x89, 0xa8, 0x24, 0x58,
        0x79, 0x87, 0x11, 0xfc, 0x6f, 0x07, 0x91, 0xef, 0xa6, 0x30, 0x0d, 0x06,
        0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
        0x03, 0x82, 0x01, 0x01, 0x00, 0x3f, 0xd5, 0x37, 0x2f, 0xc7, 0xf8, 0x8b,
        0x39, 0x1c, 0xe3, 0xdf, 0x77, 0xee, 0xc6, 0x4b, 0x5f, 0x84, 0xcf, 0xfa,
        0x33, 0x2c, 0xb2, 0xb5, 0x4b, 0x09, 0xee, 0x56, 0xc0, 0xf2, 0xf0, 0xeb,
        0xad, 0x1c, 0x02, 0xef, 0xae, 0x09, 0x53, 0xc0, 0x06, 0xad, 0x4e, 0xfd,
        0x3e, 0x8c, 0x13, 0xb3, 0xbf, 0x80, 0x05, 0x36, 0xb5, 0x3f, 0x2b, 0xc7,
        0x60, 0x53, 0x14, 0xbf, 0x33, 0x63, 0x47, 0xc3, 0xc6, 0x28, 0xda, 0x10,
        0x12, 0xe2, 0xc4, 0xeb, 0xc5, 0x64, 0x66, 0xc0, 0xcc, 0x6b, 0x84, 0xda,
        0x0c, 0xe9, 0xf6, 0xe3, 0xf8, 0x8e, 0x3d, 0x95, 0x5f, 0xba, 0x9f, 0xe1,
        0xc7, 0xed, 0x6e, 0x97, 0xcc, 0xbd, 0x7d, 0xe5, 0x4e, 0xab, 0xbc, 0x1b,
        0xf1, 0x3a, 0x09, 0x33, 0x09, 0xe1, 0xcc, 0xec, 0x21, 0x16, 0x8e, 0xb1,
        0x74, 0x9e, 0xc8, 0x13, 0x7c, 0xdf, 0x07, 0xaa, 0xeb, 0x70, 0xd7, 0x91,
        0x5c, 0xc4, 0xef, 0x83, 0x88, 0xc3, 0xe4, 0x97, 0xfa, 0xe4, 0xdf, 0xd7,
        0x0d, 0xff, 0xba, 0x78, 0x22, 0xfc, 0x3f, 0xdc, 0xd8, 0x02, 0x8d, 0x93,
        0x57, 0xf9, 0x9e, 0x39, 0x3a, 0x77, 0x00, 0xd9, 0x19, 0xaa, 0x68, 0xa1,
        0xe6, 0x9e, 0x13, 0xeb, 0x37, 0x16, 0xf5, 0x77, 0xa4, 0x0b, 0x40, 0x04,
        0xd3, 0xa5, 0x49, 0x78, 0x35, 0xfa, 0x3b, 0xf6, 0x02, 0xab, 0x85, 0xee,
        0xcb, 0x9b, 0x62, 0xda, 0x05, 0x00, 0x22, 0x2f, 0xf8, 0xbd, 0x0b, 0xe5,
        0x2c, 0xb2, 0x53, 0x78, 0x0a, 0xcb, 0x69, 0xc0, 0xb6, 0x9f, 0x96, 0xff,
        0x58, 0x22, 0x70, 0x9c, 0x01, 0x2e, 0x56, 0x60, 0x5d, 0x37, 0xe3, 0x40,
        0x25, 0xc9, 0x90, 0xc8, 0x0f, 0x41, 0x68, 0xb4, 0xfd, 0x10, 0xe2, 0x09,
        0x99, 0x08, 0x5d, 0x7b, 0xc9, 0xe3, 0x29, 0xd4, 0x5a, 0xcf, 0xc9, 0x34,
        0x55, 0xa1, 0x40, 0x44, 0xd6, 0x88, 0x16, 0xbb, 0xdd
    };

    /* Offset of the SAN SEQUENCE length byte inside good_san_cert. */
    #define SAN_SEQ_LEN_OFFSET 418

    DecodedCert cert;
    unsigned char bad_san_cert[sizeof(good_san_cert)];

    /* Control: the original cert with correct SAN SEQUENCE length should
     * parse successfully (signature won't verify, but NO_VERIFY skips that). */
    wc_InitDecodedCert(&cert, good_san_cert, (word32)sizeof(good_san_cert),
        NULL);
    ExpectIntEQ(wc_ParseCert(&cert, CERT_TYPE, NO_VERIFY, NULL), 0);
    wc_FreeDecodedCert(&cert);

    /* Build a malformed variant: shrink the SAN SEQUENCE length from 6 to 3
     * so the DNS entry length (4) exceeds the SEQUENCE bounds.  Without a
     * bounds check DecodeAltNames would underflow the length tracker. */
    XMEMCPY(bad_san_cert, good_san_cert, sizeof(good_san_cert));
    bad_san_cert[SAN_SEQ_LEN_OFFSET] = 0x03;

    wc_InitDecodedCert(&cert, bad_san_cert, (word32)sizeof(bad_san_cert),
        NULL);
    ExpectIntEQ(wc_ParseCert(&cert, CERT_TYPE, NO_VERIFY, NULL),
        WC_NO_ERR_TRACE(ASN_PARSE_E));
    wc_FreeDecodedCert(&cert);

    /* NUL in dNSName SAN must be rejected per RFC 5280 4.2.1.6. */
    XMEMCPY(bad_san_cert, good_san_cert, sizeof(good_san_cert));
    bad_san_cert[SAN_SEQ_LEN_OFFSET + 5] = 0x00;

    wc_InitDecodedCert(&cert, bad_san_cert, (word32)sizeof(bad_san_cert),
        NULL);
    ExpectIntEQ(wc_ParseCert(&cert, CERT_TYPE, NO_VERIFY, NULL),
        WC_NO_ERR_TRACE(ASN_PARSE_E));
    wc_FreeDecodedCert(&cert);

#endif /* !NO_CERTS && !NO_RSA && !NO_ASN */
    return EXPECT_RESULT();
}

int test_wc_DecodeObjectId(void)
{
    EXPECT_DECLS;

#if !defined(NO_ASN) && \
    (defined(HAVE_OID_DECODING) || defined(WOLFSSL_ASN_PRINT))
    {
        /* OID 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
         * DER encoding: 2a 86 48 86 f7 0d 01 01 0b
         * First byte 0x2a = 42 => arc0 = 42/40 = 1, arc1 = 42%40 = 2
         * Remaining arcs: 840, 113549, 1, 1, 11
         */
        static const byte oid_sha256rsa[] = {
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b
        };
        word16 out[MAX_OID_SZ];
        word32 outSz;

        /* Test 1: Normal decode */
        outSz = MAX_OID_SZ;
        ExpectIntEQ(DecodeObjectId(oid_sha256rsa, sizeof(oid_sha256rsa),
                                   out, &outSz), 0);
        ExpectIntEQ((int)outSz, 7);
        ExpectIntEQ(out[0], 1);
        ExpectIntEQ(out[1], 2);
        ExpectIntEQ(out[2], 840);
        ExpectIntEQ(out[3], (word16)113549); /* truncated to word16 */
        ExpectIntEQ(out[4], 1);
        ExpectIntEQ(out[5], 1);
        ExpectIntEQ(out[6], 11);

        /* Test 2: NULL args */
        outSz = MAX_OID_SZ;
        ExpectIntEQ(DecodeObjectId(NULL, sizeof(oid_sha256rsa), out, &outSz),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(DecodeObjectId(oid_sha256rsa, sizeof(oid_sha256rsa),
                                   out, NULL),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* Test 3 (Bug 1): outSz=1 must return BUFFER_E, not OOB write.
         * The first OID byte decodes into two arcs, so outSz must be >= 2. */
        outSz = 1;
        ExpectIntEQ(DecodeObjectId(oid_sha256rsa, sizeof(oid_sha256rsa),
                                   out, &outSz),
                    WC_NO_ERR_TRACE(BUFFER_E));

        /* Test 4: outSz=0 must also return BUFFER_E */
        outSz = 0;
        ExpectIntEQ(DecodeObjectId(oid_sha256rsa, sizeof(oid_sha256rsa),
                                   out, &outSz),
                    WC_NO_ERR_TRACE(BUFFER_E));

        /* Test 5: outSz=2 is enough for a single-byte OID (two arcs) */
        {
            static const byte oid_one_byte[] = { 0x2a }; /* 1.2 */
            outSz = 2;
            ExpectIntEQ(DecodeObjectId(oid_one_byte, sizeof(oid_one_byte),
                                       out, &outSz), 0);
            ExpectIntEQ((int)outSz, 2);
            ExpectIntEQ(out[0], 1);
            ExpectIntEQ(out[1], 2);
        }

        /* Test 6: Buffer too small for later arcs */
        outSz = 3; /* only room for 3 arcs, but OID has 7 */
        ExpectIntEQ(DecodeObjectId(oid_sha256rsa, sizeof(oid_sha256rsa),
                                   out, &outSz),
                    WC_NO_ERR_TRACE(BUFFER_E));
    }
#endif /* !NO_ASN && (HAVE_OID_DECODING || WOLFSSL_ASN_PRINT) */

    return EXPECT_RESULT();
}
