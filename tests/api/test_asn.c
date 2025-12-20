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

#include <wolfssl/wolfcrypt/asn.h>

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

int test_SerialNumber0_RootCA(void)
{
    EXPECT_DECLS;

#if !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && !defined(NO_RSA) && \
    defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_EXT)
    /* Test that root CA certificates with serial number 0 are accepted,
     * while non-root certificates with serial 0 are rejected (issue #8615) */

#if !defined(WOLFSSL_NO_ASN_STRICT) && !defined(WOLFSSL_PYTHON) && \
    !defined(WOLFSSL_ASN_ALLOW_0_SERIAL)
    WOLFSSL_CERT_MANAGER* cm = NULL;
    const char* rootSerial0File = "./certs/test-serial0/root_serial0.pem";
    const char* rootNormalFile = "./certs/test-serial0/root.pem";
    const char* eeSerial0File = "./certs/test-serial0/ee_serial0.pem";
    const char* eeNormalFile = "./certs/test-serial0/ee_normal.pem";
    const char* selfSignedNonCASerial0File = 
        "./certs/test-serial0/selfsigned_nonca_serial0.pem";

    /* Test 1: Root CA with serial 0 should load successfully */
    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectIntEQ(wolfSSL_CertManagerLoadCA(cm, rootSerial0File, NULL), 
                WOLFSSL_SUCCESS);
    if (cm != NULL) {
        wolfSSL_CertManagerFree(cm);
        cm = NULL;
    }

    /* Test 2: Normal root CA (serial != 0) should load successfully */
    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectIntEQ(wolfSSL_CertManagerLoadCA(cm, rootNormalFile, NULL), 
                WOLFSSL_SUCCESS);
    
    /* Test 3: End-entity cert with serial 0 should be rejected during verify */
    ExpectIntNE(wolfSSL_CertManagerVerify(cm, eeSerial0File, 
                WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    
    if (cm != NULL) {
        wolfSSL_CertManagerFree(cm);
        cm = NULL;
    }

    /* Test 4: Normal end-entity cert signed by root CA with serial 0 
     * should verify successfully */
    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectIntEQ(wolfSSL_CertManagerLoadCA(cm, rootSerial0File, NULL), 
                WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CertManagerVerify(cm, eeNormalFile, 
                WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    
    if (cm != NULL) {
        wolfSSL_CertManagerFree(cm);
        cm = NULL;
    }

    /* Test 5: Self-signed non-CA certificate with serial 0 should be rejected */
    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectIntNE(wolfSSL_CertManagerLoadCA(cm, selfSignedNonCASerial0File, NULL), 
                WOLFSSL_SUCCESS);
    
    if (cm != NULL) {
        wolfSSL_CertManagerFree(cm);
        cm = NULL;
    }
#endif /* !WOLFSSL_NO_ASN_STRICT && !WOLFSSL_PYTHON && 
          !WOLFSSL_ASN_ALLOW_0_SERIAL */
#endif /* !NO_CERTS && !NO_FILESYSTEM && !NO_RSA && WOLFSSL_CERT_GEN && 
          WOLFSSL_CERT_EXT */

    return EXPECT_RESULT();
}
