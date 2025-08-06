/* test_ossl_asn1.c
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

#include <wolfssl/openssl/asn1.h>
#include <wolfssl/openssl/x509v3.h>
#include <wolfssl/internal.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_ossl_asn1.h>

/*******************************************************************************
 * ASN.1 OpenSSL compatibility API Testing
 ******************************************************************************/

int test_wolfSSL_ASN1_BIT_STRING(void)
{
    EXPECT_DECLS;
#if !defined(NO_CERTS) && defined(OPENSSL_ALL)
    ASN1_BIT_STRING* str = NULL;
    ASN1_BIT_STRING* str2 = NULL;
    unsigned char* der = NULL;

    ExpectNotNull(str = ASN1_BIT_STRING_new());
    /* Empty data testing. */
    ExpectIntEQ(ASN1_BIT_STRING_get_bit(str, 1), 0);
    ASN1_BIT_STRING_free(str);
    str = NULL;

    ExpectNotNull(str = ASN1_BIT_STRING_new());

    /* Invalid parameter testing. */
    ExpectIntEQ(ASN1_BIT_STRING_set_bit(NULL, 42, 1), 0);
    ExpectIntEQ(ASN1_BIT_STRING_set_bit(str, -1, 1), 0);
    ExpectIntEQ(ASN1_BIT_STRING_set_bit(str, 42, 2), 0);
    ExpectIntEQ(ASN1_BIT_STRING_set_bit(str, 42, -1), 0);

    /* No bit string - bit is always 0. */
    ExpectIntEQ(ASN1_BIT_STRING_get_bit(NULL, 42), 0);
    ExpectIntEQ(ASN1_BIT_STRING_get_bit(NULL, -1), 0);
    ExpectIntEQ(ASN1_BIT_STRING_get_bit(str, -1), 0);
    ExpectIntEQ(ASN1_BIT_STRING_get_bit(str, 0), 0);

    ExpectIntEQ(ASN1_BIT_STRING_set_bit(str, 42, 1), 1);
    ExpectIntEQ(ASN1_BIT_STRING_get_bit(str, 42), 1);
    ExpectIntEQ(ASN1_BIT_STRING_get_bit(str, 41), 0);
    ExpectIntEQ(ASN1_BIT_STRING_get_bit(str, -1), 0);
    ExpectIntEQ(ASN1_BIT_STRING_set_bit(str, 84, 1), 1);
    ExpectIntEQ(ASN1_BIT_STRING_get_bit(str, 84), 1);
    ExpectIntEQ(ASN1_BIT_STRING_get_bit(str, 83), 0);
    ExpectIntEQ(ASN1_BIT_STRING_set_bit(str, 91, 0), 1);
    ExpectIntEQ(ASN1_BIT_STRING_get_bit(str, 91), 0);
    ExpectIntEQ(ASN1_BIT_STRING_set_bit(str, 89, 0), 1);
    ExpectIntEQ(ASN1_BIT_STRING_get_bit(str, 89), 0);
    ExpectIntEQ(ASN1_BIT_STRING_set_bit(str, 42, 0), 1);
    ExpectIntEQ(ASN1_BIT_STRING_get_bit(str, 42), 0);

    ExpectIntEQ(i2d_ASN1_BIT_STRING(str, NULL), 14);
    ExpectIntEQ(i2d_ASN1_BIT_STRING(str, &der), 14);
#ifdef WOLFSSL_ASN_TEMPLATE
    {
        const unsigned char* tmp = der;
        ExpectNotNull(d2i_ASN1_BIT_STRING(&str2, &tmp, 14));
    }
#endif

    ASN1_BIT_STRING_free(str);
    ASN1_BIT_STRING_free(str2);
    ASN1_BIT_STRING_free(NULL);
    XFREE(der, NULL, DYNAMIC_TYPE_ASN1);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_ASN1_INTEGER(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_ASN)
    ASN1_INTEGER* a = NULL;
    ASN1_INTEGER* dup = NULL;
    const unsigned char invalidLenDer[] = {
        0x02, 0x20, 0x00
    };
    const unsigned char longDer[] = {
        0x02, 0x20,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    };
    const unsigned char* p;

    /* Invalid parameter testing. */
    ASN1_INTEGER_free(NULL);
    ExpectNull(wolfSSL_ASN1_INTEGER_dup(NULL));

    ExpectNotNull(a = ASN1_INTEGER_new());
    ExpectNotNull(dup = wolfSSL_ASN1_INTEGER_dup(a));
    ASN1_INTEGER_free(dup);
    dup = NULL;
    ASN1_INTEGER_free(a);
    a = NULL;

    p = invalidLenDer;
    ExpectNull(d2i_ASN1_INTEGER(NULL, &p, sizeof(invalidLenDer)));

    p = longDer;
    ExpectNotNull(a = d2i_ASN1_INTEGER(NULL, &p, sizeof(longDer)));
    ExpectPtrNE(p, longDer);
    ExpectNotNull(dup = wolfSSL_ASN1_INTEGER_dup(a));
    ASN1_INTEGER_free(dup);
    ASN1_INTEGER_free(a);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_ASN1_INTEGER_cmp(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_ASN)
    ASN1_INTEGER* a = NULL;
    ASN1_INTEGER* b = NULL;

    ExpectNotNull(a = ASN1_INTEGER_new());
    ExpectNotNull(b = ASN1_INTEGER_new());
    ExpectIntEQ(ASN1_INTEGER_set(a, 1), 1);
    ExpectIntEQ(ASN1_INTEGER_set(b, 1), 1);

    /* Invalid parameter testing. */
    ExpectIntEQ(wolfSSL_ASN1_INTEGER_cmp(NULL, NULL), -1);
    ExpectIntEQ(wolfSSL_ASN1_INTEGER_cmp(a, NULL), -1);
    ExpectIntEQ(wolfSSL_ASN1_INTEGER_cmp(NULL, b), -1);

    ExpectIntEQ(wolfSSL_ASN1_INTEGER_cmp(a, b), 0);
    ExpectIntEQ(ASN1_INTEGER_set(b, -1), 1);
    ExpectIntGT(wolfSSL_ASN1_INTEGER_cmp(a, b), 0);
    ExpectIntEQ(ASN1_INTEGER_set(a, -2), 1);
    ExpectIntLT(wolfSSL_ASN1_INTEGER_cmp(a, b), 0);
    ExpectIntEQ(ASN1_INTEGER_set(b, 1), 1);
    ExpectIntLT(wolfSSL_ASN1_INTEGER_cmp(a, b), 0);
    ExpectIntEQ(ASN1_INTEGER_set(a, 0x01), 1);
    ExpectIntEQ(ASN1_INTEGER_set(b, 0x1000), 1);
    ExpectIntLT(wolfSSL_ASN1_INTEGER_cmp(a, b), 0);
    ExpectIntGT(wolfSSL_ASN1_INTEGER_cmp(b, a), 0);

    ASN1_INTEGER_free(b);
    ASN1_INTEGER_free(a);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_ASN1_INTEGER_BN(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_ASN)
    ASN1_INTEGER* ai = NULL;
    ASN1_INTEGER* ai2 = NULL;
    BIGNUM* bn = NULL;
    BIGNUM* bn2 = NULL;

    ExpectNotNull(ai = ASN1_INTEGER_new());
    ExpectNotNull(bn2 = BN_new());

    /* Invalid parameter testing. */
    ExpectNull(bn = ASN1_INTEGER_to_BN(NULL, NULL));
    ExpectNull(ai2 = BN_to_ASN1_INTEGER(NULL, NULL));

    /* at the moment hard setting since no set function */
    if (ai != NULL) {
        ai->data[0] = 0xff; /* No DER encoding. */
        ai->length = 1;
    }
#if defined(WOLFSSL_QT) || defined(WOLFSSL_HAPROXY)
    ExpectNotNull(bn = ASN1_INTEGER_to_BN(ai, NULL));
    BN_free(bn);
    bn = NULL;
#else
    ExpectNull(ASN1_INTEGER_to_BN(ai, NULL));
#endif

    if (ai != NULL) {
        ai->data[0] = 0x02; /* tag for ASN_INTEGER */
        ai->data[1] = 0x04; /* bad length of integer */
        ai->data[2] = 0x03;
        ai->length = 3;
    }
#if defined(WOLFSSL_QT) || defined(WOLFSSL_HAPROXY)
    /* Interpreted as a number 0x020403. */
    ExpectNotNull(bn = ASN1_INTEGER_to_BN(ai, NULL));
    BN_free(bn);
    bn = NULL;
#else
    ExpectNull(ASN1_INTEGER_to_BN(ai, NULL));
#endif

    if (ai != NULL) {
        ai->data[0] = 0x02; /* tag for ASN_INTEGER */
        ai->data[1] = 0x01; /* length of integer */
        ai->data[2] = 0x03;
        ai->length = 3;
    }
    ExpectNotNull(bn = ASN1_INTEGER_to_BN(ai, NULL));
    ExpectNotNull(ai2 = BN_to_ASN1_INTEGER(bn, NULL));
    ExpectIntEQ(ASN1_INTEGER_cmp(ai, ai2), 0);
    ExpectNotNull(bn2 = ASN1_INTEGER_to_BN(ai2, bn2));
    ExpectIntEQ(BN_cmp(bn, bn2), 0);

    if (ai != NULL) {
        ai->data[0] = 0x02; /* tag for ASN_INTEGER */
        ai->data[1] = 0x02; /* length of integer */
        ai->data[2] = 0x00; /* padding byte to ensure positive */
        ai->data[3] = 0xff;
        ai->length = 4;
    }
    ExpectNotNull(bn = ASN1_INTEGER_to_BN(ai, bn));
    ExpectNotNull(ai2 = BN_to_ASN1_INTEGER(bn, ai2));
    ExpectIntEQ(ASN1_INTEGER_cmp(ai, ai2), 0);
    ExpectNotNull(bn2 = ASN1_INTEGER_to_BN(ai2, bn2));
    ExpectIntEQ(BN_cmp(bn, bn2), 0);

    if (ai != NULL) {
        ai->data[0] = 0x02; /* tag for ASN_INTEGER */
        ai->data[1] = 0x01; /* length of integer */
        ai->data[2] = 0x00;
        ai->length = 3;
    }
    ExpectNotNull(bn = ASN1_INTEGER_to_BN(ai, bn));
    ExpectNotNull(ai2 = BN_to_ASN1_INTEGER(bn, ai2));
    ExpectIntEQ(ASN1_INTEGER_cmp(ai, ai2), 0);
    ExpectNotNull(bn2 = ASN1_INTEGER_to_BN(ai2, bn2));
    ExpectIntEQ(BN_cmp(bn, bn2), 0);

    if (ai != NULL) {
        ai->data[0] = 0x02; /* tag for ASN_INTEGER */
        ai->data[1] = 0x01; /* length of integer */
        ai->data[2] = 0x01;
        ai->length = 3;
        ai->negative = 1;
    }
    ExpectNotNull(bn = ASN1_INTEGER_to_BN(ai, bn));
    ExpectNotNull(ai2 = BN_to_ASN1_INTEGER(bn, ai2));
    ExpectIntEQ(ASN1_INTEGER_cmp(ai, ai2), 0);
    ExpectNotNull(bn2 = ASN1_INTEGER_to_BN(ai2, bn2));
    ExpectIntEQ(BN_cmp(bn, bn2), 0);

    BN_free(bn2);
    BN_free(bn);
    ASN1_INTEGER_free(ai2);
    ASN1_INTEGER_free(ai);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_ASN1_INTEGER_get_set(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_ASN)
    ASN1_INTEGER *a = NULL;
    long val;

    ExpectNotNull(a = ASN1_INTEGER_new());
    /* Invalid parameter testing. */
    ExpectIntEQ(ASN1_INTEGER_get(NULL), 0);
#if defined(WOLFSSL_QT) || defined(WOLFSSL_HAPROXY)
    ExpectIntEQ(ASN1_INTEGER_get(a), 0);
#else
    ExpectIntEQ(ASN1_INTEGER_get(a), -1);
#endif
    ASN1_INTEGER_free(a);
    a = NULL;

    ExpectNotNull(a = ASN1_INTEGER_new());
    val = 0;
    ExpectIntEQ(ASN1_INTEGER_set(NULL, val), 0);
    ASN1_INTEGER_free(a);
    a = NULL;

    /* 0 */
    ExpectNotNull(a = ASN1_INTEGER_new());
    val = 0;
    ExpectIntEQ(ASN1_INTEGER_set(a, val), 1);
    ExpectTrue(ASN1_INTEGER_get(a) == val);
    ASN1_INTEGER_free(a);
    a = NULL;

    /* 40 */
    ExpectNotNull(a = ASN1_INTEGER_new());
    val = 40;
    ExpectIntEQ(ASN1_INTEGER_set(a, val), 1);
    ExpectTrue(ASN1_INTEGER_get(a) == val);
    ASN1_INTEGER_free(a);
    a = NULL;

    /* -40 */
    ExpectNotNull(a = ASN1_INTEGER_new());
    val = -40;
    ExpectIntEQ(ASN1_INTEGER_set(a, val), 1);
    ExpectTrue(ASN1_INTEGER_get(a) == val);
    ASN1_INTEGER_free(a);
    a = NULL;

    /* 128 */
    ExpectNotNull(a = ASN1_INTEGER_new());
    val = 128;
    ExpectIntEQ(ASN1_INTEGER_set(a, val), 1);
    ExpectTrue(ASN1_INTEGER_get(a) == val);
    ASN1_INTEGER_free(a);
    a = NULL;

    /* -128 */
    ExpectNotNull(a = ASN1_INTEGER_new());
    val = -128;
    ExpectIntEQ(ASN1_INTEGER_set(a, val), 1);
    ExpectTrue(ASN1_INTEGER_get(a) == val);
    ASN1_INTEGER_free(a);
    a = NULL;

    /* 200 */
    ExpectNotNull(a = ASN1_INTEGER_new());
    val = 200;
    ExpectIntEQ(ASN1_INTEGER_set(a, val), 1);
    ExpectTrue(ASN1_INTEGER_get(a) == val);
    ASN1_INTEGER_free(a);
    a = NULL;

    /* int max (2147483647) */
    ExpectNotNull(a = ASN1_INTEGER_new());
    val = 2147483647;
    ExpectIntEQ(ASN1_INTEGER_set(a, val), 1);
    ExpectTrue(ASN1_INTEGER_get(a) == val);
    ASN1_INTEGER_free(a);
    a = NULL;

    /* int min (-2147483648) */
    ExpectNotNull(a = ASN1_INTEGER_new());
    val = -2147483647 - 1;
    ExpectIntEQ(ASN1_INTEGER_set(a, val), 1);
    ExpectTrue(ASN1_INTEGER_get(a) == val);
    ASN1_INTEGER_free(a);
    a = NULL;

    /* long max positive */
    ExpectNotNull(a = ASN1_INTEGER_new());
    val = (long)(((unsigned long)-1) >> 1);
    ExpectIntEQ(ASN1_INTEGER_set(a, val), 1);
    ExpectTrue(ASN1_INTEGER_get(a) == val);
    ASN1_INTEGER_free(a);
#endif
    return EXPECT_RESULT();
}

#if defined(OPENSSL_EXTRA)
typedef struct ASN1IntTestVector {
    const byte* der;
    const size_t derSz;
    const long value;
} ASN1IntTestVector;
#endif
int test_wolfSSL_d2i_ASN1_INTEGER(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA)
    size_t i;
    WOLFSSL_ASN1_INTEGER* a = NULL;
    WOLFSSL_ASN1_INTEGER* b = NULL;
    WOLFSSL_ASN1_INTEGER* c = NULL;
    const byte* p = NULL;
    byte* p2 = NULL;
    byte* reEncoded = NULL;
    int reEncodedSz = 0;

    static const byte zeroDer[] = {
        0x02, 0x01, 0x00
    };
    static const byte oneDer[] = {
        0x02, 0x01, 0x01
    };
    static const byte negativeDer[] = {
        0x02, 0x03, 0xC1, 0x16, 0x0D
    };
    static const byte positiveDer[] = {
        0x02, 0x03, 0x01, 0x00, 0x01
    };
    static const byte primeDer[] = {
        0x02, 0x82, 0x01, 0x01, 0x00, 0xc0, 0x95, 0x08, 0xe1, 0x57, 0x41,
        0xf2, 0x71, 0x6d, 0xb7, 0xd2, 0x45, 0x41, 0x27, 0x01, 0x65, 0xc6,
        0x45, 0xae, 0xf2, 0xbc, 0x24, 0x30, 0xb8, 0x95, 0xce, 0x2f, 0x4e,
        0xd6, 0xf6, 0x1c, 0x88, 0xbc, 0x7c, 0x9f, 0xfb, 0xa8, 0x67, 0x7f,
        0xfe, 0x5c, 0x9c, 0x51, 0x75, 0xf7, 0x8a, 0xca, 0x07, 0xe7, 0x35,
        0x2f, 0x8f, 0xe1, 0xbd, 0x7b, 0xc0, 0x2f, 0x7c, 0xab, 0x64, 0xa8,
        0x17, 0xfc, 0xca, 0x5d, 0x7b, 0xba, 0xe0, 0x21, 0xe5, 0x72, 0x2e,
        0x6f, 0x2e, 0x86, 0xd8, 0x95, 0x73, 0xda, 0xac, 0x1b, 0x53, 0xb9,
        0x5f, 0x3f, 0xd7, 0x19, 0x0d, 0x25, 0x4f, 0xe1, 0x63, 0x63, 0x51,
        0x8b, 0x0b, 0x64, 0x3f, 0xad, 0x43, 0xb8, 0xa5, 0x1c, 0x5c, 0x34,
        0xb3, 0xae, 0x00, 0xa0, 0x63, 0xc5, 0xf6, 0x7f, 0x0b, 0x59, 0x68,
        0x78, 0x73, 0xa6, 0x8c, 0x18, 0xa9, 0x02, 0x6d, 0xaf, 0xc3, 0x19,
        0x01, 0x2e, 0xb8, 0x10, 0xe3, 0xc6, 0xcc, 0x40, 0xb4, 0x69, 0xa3,
        0x46, 0x33, 0x69, 0x87, 0x6e, 0xc4, 0xbb, 0x17, 0xa6, 0xf3, 0xe8,
        0xdd, 0xad, 0x73, 0xbc, 0x7b, 0x2f, 0x21, 0xb5, 0xfd, 0x66, 0x51,
        0x0c, 0xbd, 0x54, 0xb3, 0xe1, 0x6d, 0x5f, 0x1c, 0xbc, 0x23, 0x73,
        0xd1, 0x09, 0x03, 0x89, 0x14, 0xd2, 0x10, 0xb9, 0x64, 0xc3, 0x2a,
        0xd0, 0xa1, 0x96, 0x4a, 0xbc, 0xe1, 0xd4, 0x1a, 0x5b, 0xc7, 0xa0,
        0xc0, 0xc1, 0x63, 0x78, 0x0f, 0x44, 0x37, 0x30, 0x32, 0x96, 0x80,
        0x32, 0x23, 0x95, 0xa1, 0x77, 0xba, 0x13, 0xd2, 0x97, 0x73, 0xe2,
        0x5d, 0x25, 0xc9, 0x6a, 0x0d, 0xc3, 0x39, 0x60, 0xa4, 0xb4, 0xb0,
        0x69, 0x42, 0x42, 0x09, 0xe9, 0xd8, 0x08, 0xbc, 0x33, 0x20, 0xb3,
        0x58, 0x22, 0xa7, 0xaa, 0xeb, 0xc4, 0xe1, 0xe6, 0x61, 0x83, 0xc5,
        0xd2, 0x96, 0xdf, 0xd9, 0xd0, 0x4f, 0xad, 0xd7
    };
    static const byte garbageDer[] = {0xDE, 0xAD, 0xBE, 0xEF};

    static const ASN1IntTestVector testVectors[] = {
        {zeroDer, sizeof(zeroDer), 0},
        {oneDer, sizeof(oneDer), 1},
        {negativeDer, sizeof(negativeDer), -4123123},
        {positiveDer, sizeof(positiveDer), 65537},
        {primeDer, sizeof(primeDer), 0}
    };
    static const size_t NUM_TEST_VECTORS =
        sizeof(testVectors)/sizeof(testVectors[0]);

    /* Check d2i error conditions */
    /* NULL pointer to input. */
    ExpectNull((a = wolfSSL_d2i_ASN1_INTEGER(&b, NULL, 1)));
    ExpectNull(b);
    /* NULL input. */
    ExpectNull((a = wolfSSL_d2i_ASN1_INTEGER(&b, &p, 1)));
    ExpectNull(b);
    /* 0 length. */
    p = testVectors[0].der;
    ExpectNull((a = wolfSSL_d2i_ASN1_INTEGER(&b, &p, 0)));
    ExpectNull(b);
    /* Negative length. */
    p = testVectors[0].der;
    ExpectNull((a = wolfSSL_d2i_ASN1_INTEGER(&b, &p, -1)));
    ExpectNull(b);
    /* Garbage DER input. */
    p = garbageDer;
    ExpectNull((a = wolfSSL_d2i_ASN1_INTEGER(&b, &p, sizeof(garbageDer))));
    ExpectNull(b);

    /* Check i2d error conditions */
    /* NULL input. */
    ExpectIntLT(wolfSSL_i2d_ASN1_INTEGER(NULL, &p2), 0);
    /* 0 length input data buffer (a->length == 0). */
    ExpectNotNull((a = wolfSSL_ASN1_INTEGER_new()));
    ExpectIntLT(wolfSSL_i2d_ASN1_INTEGER(a, &p2), 0);
    if (a != NULL)
        a->data = NULL;
    /* NULL input data buffer. */
    ExpectIntLT(wolfSSL_i2d_ASN1_INTEGER(a, &p2), 0);
    if (a != NULL) {
        /* Reset a->data. */
        a->isDynamic = 0;
        a->data = a->intData;
    }
    /* Reset p2 to NULL. */
    XFREE(p2, NULL, DYNAMIC_TYPE_ASN1);

    /* Set a to valid value. */
    ExpectIntEQ(wolfSSL_ASN1_INTEGER_set(a, 1), WOLFSSL_SUCCESS);
    /* NULL output buffer. */
    ExpectIntEQ(wolfSSL_i2d_ASN1_INTEGER(a, NULL), 3);
    wolfSSL_ASN1_INTEGER_free(a);
    a = NULL;

    for (i = 0; i < NUM_TEST_VECTORS; ++i) {
        p = testVectors[i].der;
        ExpectNotNull(a = wolfSSL_d2i_ASN1_INTEGER(&b, &p,
            testVectors[i].derSz));
        ExpectIntEQ(wolfSSL_ASN1_INTEGER_cmp(a, b), 0);

        if (testVectors[i].derSz <= sizeof(long)) {
            ExpectNotNull(c = wolfSSL_ASN1_INTEGER_new());
            ExpectIntEQ(wolfSSL_ASN1_INTEGER_set(c, testVectors[i].value), 1);
            ExpectIntEQ(wolfSSL_ASN1_INTEGER_cmp(a, c), 0);
            wolfSSL_ASN1_INTEGER_free(c);
            c = NULL;
        }

        /* Convert to DER without a pre-allocated output buffer. */
        ExpectIntGT((reEncodedSz = wolfSSL_i2d_ASN1_INTEGER(a, &reEncoded)), 0);
        ExpectIntEQ(reEncodedSz, testVectors[i].derSz);
        ExpectIntEQ(XMEMCMP(reEncoded, testVectors[i].der, reEncodedSz), 0);

        /* Convert to DER with a pre-allocated output buffer. In this case, the
         * output buffer pointer should be incremented just past the end of the
         * encoded data. */
        p2 = reEncoded;
        ExpectIntGT((reEncodedSz = wolfSSL_i2d_ASN1_INTEGER(a, &p2)), 0);
        ExpectIntEQ(reEncodedSz, testVectors[i].derSz);
        ExpectPtrEq(reEncoded, p2 - reEncodedSz);
        ExpectIntEQ(XMEMCMP(reEncoded, testVectors[i].der, reEncodedSz), 0);

        XFREE(reEncoded, NULL, DYNAMIC_TYPE_ASN1);
        reEncoded = NULL;
        wolfSSL_ASN1_INTEGER_free(a);
        a = NULL;
    }
#endif /* OPENSSL_EXTRA */
    return EXPECT_RESULT();
}

int test_wolfSSL_a2i_ASN1_INTEGER(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_BIO)
    BIO* bio = NULL;
    BIO* out = NULL;
    BIO* fixed = NULL;
    ASN1_INTEGER* ai = NULL;
    char buf[] = "123456\n12345\n1123456789123456\\\n78901234567890 \r\n\n";
    char tmp[1024];
    int  tmpSz;

    const char expected1[] = "123456";
    const char expected2[] = "112345678912345678901234567890";
    char longStr[] = "123456781234567812345678123456781234567812345678\n"
        "123456781234567812345678123456781234567812345678\\\n12345678\n";

    ExpectNotNull(out = BIO_new(BIO_s_mem()));
    ExpectNotNull(ai = ASN1_INTEGER_new());

    ExpectNotNull(bio = BIO_new_mem_buf(buf, -1));

    /* Invalid parameter testing. */
    ExpectIntEQ(a2i_ASN1_INTEGER(NULL, NULL, NULL, -1), 0);
    ExpectIntEQ(a2i_ASN1_INTEGER(bio, NULL, NULL, -1), 0);
    ExpectIntEQ(a2i_ASN1_INTEGER(NULL, ai, NULL, -1), 0);
    ExpectIntEQ(a2i_ASN1_INTEGER(NULL, NULL, tmp, -1), 0);
    ExpectIntEQ(a2i_ASN1_INTEGER(NULL, NULL, NULL, sizeof(tmp)), 0);
    ExpectIntEQ(a2i_ASN1_INTEGER(NULL, ai, tmp, sizeof(tmp)), 0);
    ExpectIntEQ(a2i_ASN1_INTEGER(bio, NULL, tmp, sizeof(tmp)), 0);
    ExpectIntEQ(a2i_ASN1_INTEGER(bio, ai, NULL, sizeof(tmp)), 0);
    ExpectIntEQ(a2i_ASN1_INTEGER(bio, ai, tmp, -1), 0);
    ExpectIntEQ(i2a_ASN1_INTEGER(NULL, NULL), 0);
    ExpectIntEQ(i2a_ASN1_INTEGER(bio, NULL), 0);
    ExpectIntEQ(i2a_ASN1_INTEGER(NULL, ai), 0);

    /* No data to read from BIO. */
    ExpectIntEQ(a2i_ASN1_INTEGER(out, ai, tmp, sizeof(tmp)), 0);

    /* read first line */
    ExpectIntEQ(a2i_ASN1_INTEGER(bio, ai, tmp, sizeof(tmp)), 1);
    ExpectIntEQ(i2a_ASN1_INTEGER(out, ai), 6);
    XMEMSET(tmp, 0, sizeof(tmp));
    tmpSz = BIO_read(out, tmp, sizeof(tmp));
    ExpectIntEQ(tmpSz, 6);
    ExpectIntEQ(XMEMCMP(tmp, expected1, tmpSz), 0);

    /* fail on second line (not % 2) */
    ExpectIntEQ(a2i_ASN1_INTEGER(bio, ai, tmp, sizeof(tmp)), 0);

    /* read 3rd long line */
    ExpectIntEQ(a2i_ASN1_INTEGER(bio, ai, tmp, sizeof(tmp)), 1);
    ExpectIntEQ(i2a_ASN1_INTEGER(out, ai), 30);
    XMEMSET(tmp, 0, sizeof(tmp));
    tmpSz = BIO_read(out, tmp, sizeof(tmp));
    ExpectIntEQ(tmpSz, 30);
    ExpectIntEQ(XMEMCMP(tmp, expected2, tmpSz), 0);

    /* fail on empty line */
    ExpectIntEQ(a2i_ASN1_INTEGER(bio, ai, tmp, sizeof(tmp)), 0);

    BIO_free(bio);
    bio = NULL;

    /* Make long integer, requiring dynamic memory, even longer. */
    ExpectNotNull(bio = BIO_new_mem_buf(longStr, -1));
    ExpectIntEQ(a2i_ASN1_INTEGER(bio, ai, tmp, sizeof(tmp)), 1);
    ExpectIntEQ(i2a_ASN1_INTEGER(out, ai), 48);
    XMEMSET(tmp, 0, sizeof(tmp));
    tmpSz = BIO_read(out, tmp, sizeof(tmp));
    ExpectIntEQ(tmpSz, 48);
    ExpectIntEQ(a2i_ASN1_INTEGER(bio, ai, tmp, sizeof(tmp)), 1);
    ExpectIntEQ(i2a_ASN1_INTEGER(out, ai), 56);
    XMEMSET(tmp, 0, sizeof(tmp));
    tmpSz = BIO_read(out, tmp, sizeof(tmp));
    ExpectIntEQ(tmpSz, 56);
    ExpectIntEQ(wolfSSL_ASN1_INTEGER_set(ai, 1), 1);
    BIO_free(bio);
    BIO_free(out);

    ExpectNotNull(fixed = BIO_new(wolfSSL_BIO_s_fixed_mem()));
    ExpectIntEQ(BIO_set_write_buf_size(fixed, 1), 1);
    /* Ensure there is 0 bytes available to write into. */
    ExpectIntEQ(BIO_write(fixed, tmp, 1), 1);
    ExpectIntEQ(i2a_ASN1_INTEGER(fixed, ai), 0);
    ExpectIntEQ(BIO_set_write_buf_size(fixed, 1), 1);
    ExpectIntEQ(i2a_ASN1_INTEGER(fixed, ai), 0);
    BIO_free(fixed);

    ASN1_INTEGER_free(ai);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_i2c_ASN1_INTEGER(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_ASN)
    ASN1_INTEGER *a = NULL;
    unsigned char *pp = NULL,*tpp = NULL;
    int ret = 0;

    ExpectNotNull(a = wolfSSL_ASN1_INTEGER_new());

    /* Invalid parameter testing. */
    /* Set pp to an invalid value. */
    pp = NULL;
    ExpectIntEQ(i2c_ASN1_INTEGER(NULL, &pp), 0);
    ExpectIntEQ(i2c_ASN1_INTEGER(a, &pp), 0);
    ExpectIntEQ(i2c_ASN1_INTEGER(NULL, NULL), 0);

    /* 40 */
    if (a != NULL) {
        a->intData[0] = ASN_INTEGER;
        a->intData[1] = 1;
        a->intData[2] = 40;
    }
    ExpectIntEQ(ret = i2c_ASN1_INTEGER(a, NULL), 1);
    ExpectNotNull(pp = (unsigned char*)XMALLOC(ret + 1, NULL,
                DYNAMIC_TYPE_TMP_BUFFER));
    tpp = pp;
    if (tpp != NULL) {
        ExpectNotNull(XMEMSET(tpp, 0, ret + 1));
        ExpectIntEQ(i2c_ASN1_INTEGER(a, &tpp), 1);
        tpp--;
        ExpectIntEQ(*tpp, 40);
    }
    XFREE(pp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    pp = NULL;

    /* 128 */
    if (a != NULL) {
        a->intData[0] = ASN_INTEGER;
        a->intData[1] = 1;
        a->intData[2] = 128;
    }
    ExpectIntEQ(ret = i2c_ASN1_INTEGER(a, NULL), 2);
    ExpectNotNull(pp = (unsigned char*)XMALLOC(ret + 1, NULL,
                DYNAMIC_TYPE_TMP_BUFFER));
    tpp = pp;
    if (tpp != NULL) {
        ExpectNotNull(XMEMSET(tpp, 0, ret + 1));
        ExpectIntEQ(i2c_ASN1_INTEGER(a, &tpp), 2);
        tpp--;
        ExpectIntEQ(*(tpp--), 128);
        ExpectIntEQ(*tpp, 0);
    }
    XFREE(pp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    pp = NULL;

    /* -40 */
    if (a != NULL) {
        a->intData[0] = ASN_INTEGER;
        a->intData[1] = 1;
        a->intData[2] = 40;
        a->negative = 1;
    }
    ExpectIntEQ(ret = i2c_ASN1_INTEGER(a, NULL), 1);
    ExpectNotNull(pp = (unsigned char*)XMALLOC(ret + 1, NULL,
                DYNAMIC_TYPE_TMP_BUFFER));
    tpp = pp;
    if (tpp != NULL) {
        ExpectNotNull(XMEMSET(tpp, 0, ret + 1));
        ExpectIntEQ(i2c_ASN1_INTEGER(a, &tpp), 1);
        tpp--;
        ExpectIntEQ(*tpp, 216);
    }
    XFREE(pp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    pp = NULL;

    /* -128 */
    if (a != NULL) {
        a->intData[0] = ASN_INTEGER;
        a->intData[1] = 1;
        a->intData[2] = 128;
        a->negative = 1;
    }
    ExpectIntEQ(ret = i2c_ASN1_INTEGER(a, NULL), 1);
    ExpectNotNull(pp = (unsigned char*)XMALLOC(ret + 1, NULL,
                DYNAMIC_TYPE_TMP_BUFFER));
    tpp = pp;
    if (tpp != NULL) {
        ExpectNotNull(XMEMSET(tpp, 0, ret + 1));
        ExpectIntEQ(i2c_ASN1_INTEGER(a, &tpp), 1);
        tpp--;
        ExpectIntEQ(*tpp, 128);
    }
    XFREE(pp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    pp = NULL;

    /* -200 */
    if (a != NULL) {
        a->intData[0] = ASN_INTEGER;
        a->intData[1] = 1;
        a->intData[2] = 200;
        a->negative = 1;
    }
    ExpectIntEQ(ret = i2c_ASN1_INTEGER(a, NULL), 2);
    ExpectNotNull(pp = (unsigned char*)XMALLOC(ret + 1, NULL,
            DYNAMIC_TYPE_TMP_BUFFER));
    tpp = pp;
    if (tpp != NULL) {
        ExpectNotNull(XMEMSET(tpp, 0, ret + 1));
        ExpectIntEQ(i2c_ASN1_INTEGER(a, &tpp), 2);
        tpp--;
        ExpectIntEQ(*(tpp--), 56);
        ExpectIntEQ(*tpp, 255);
    }
    XFREE(pp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    pp = NULL;

    /* Empty */
    if (a != NULL) {
        a->intData[0] = ASN_INTEGER;
        a->intData[1] = 0;
        a->negative = 0;
    }
    ExpectIntEQ(ret = i2c_ASN1_INTEGER(a, NULL), 1);
    ExpectNotNull(pp = (unsigned char*)XMALLOC(ret + 1, NULL,
                DYNAMIC_TYPE_TMP_BUFFER));
    tpp = pp;
    if (tpp != NULL) {
        ExpectNotNull(XMEMSET(tpp, 0, ret + 1));
        ExpectIntEQ(i2c_ASN1_INTEGER(a, &tpp), 1);
        tpp--;
        ExpectIntEQ(*tpp, 0);
    }
    XFREE(pp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    pp = NULL;

    /* 0 */
    if (a != NULL) {
        a->intData[0] = ASN_INTEGER;
        a->intData[1] = 1;
        a->intData[2] = 0;
        a->negative = 1;
    }
    ExpectIntEQ(ret = i2c_ASN1_INTEGER(a, NULL), 1);
    ExpectNotNull(pp = (unsigned char*)XMALLOC(ret + 1, NULL,
                DYNAMIC_TYPE_TMP_BUFFER));
    if (tpp != NULL) {
        tpp = pp;
        ExpectNotNull(XMEMSET(tpp, 0, ret + 1));
        ExpectIntEQ(i2c_ASN1_INTEGER(a, &tpp), 1);
        tpp--;
        ExpectIntEQ(*tpp, 0);
    }
    XFREE(pp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    pp = NULL;

    /* 0x100 */
    if (a != NULL) {
        a->intData[0] = ASN_INTEGER;
        a->intData[1] = 2;
        a->intData[2] = 0x01;
        a->intData[3] = 0x00;
        a->negative = 0;
    }
    ExpectIntEQ(ret = i2c_ASN1_INTEGER(a, NULL), 2);
    ExpectNotNull(pp = (unsigned char*)XMALLOC(ret + 1, NULL,
                DYNAMIC_TYPE_TMP_BUFFER));
    if (tpp != NULL) {
        tpp = pp;
        ExpectNotNull(XMEMSET(tpp, 0, ret + 1));
        ExpectIntEQ(i2c_ASN1_INTEGER(a, &tpp), 2);
        tpp -= 2;
        ExpectIntEQ(tpp[0], 0x01);
        ExpectIntEQ(tpp[1], 0x00);
    }
    XFREE(pp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    pp = NULL;

    /* -0x8000 => 0x8000 */
    if (a != NULL) {
        a->intData[0] = ASN_INTEGER;
        a->intData[1] = 2;
        a->intData[2] = 0x80;
        a->intData[3] = 0x00;
        a->negative = 1;
    }
    ExpectIntEQ(ret = i2c_ASN1_INTEGER(a, NULL), 2);
    ExpectNotNull(pp = (unsigned char*)XMALLOC(ret + 1, NULL,
                DYNAMIC_TYPE_TMP_BUFFER));
    tpp = pp;
    if (tpp != NULL) {
        ExpectNotNull(XMEMSET(tpp, 0, ret + 1));
        ExpectIntEQ(i2c_ASN1_INTEGER(a, &tpp), 2);
        tpp -= 2;
        ExpectIntEQ(tpp[0], 0x80);
        ExpectIntEQ(tpp[1], 0x00);
    }
    XFREE(pp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    pp = NULL;

    /* -0x8001 => 0xFF7FFF */
    if (a != NULL) {
        a->intData[0] = ASN_INTEGER;
        a->intData[1] = 2;
        a->intData[2] = 0x80;
        a->intData[3] = 0x01;
        a->negative = 1;
    }
    ExpectIntEQ(ret = i2c_ASN1_INTEGER(a, NULL), 3);
    ExpectNotNull(pp = (unsigned char*)XMALLOC(ret + 1, NULL,
                DYNAMIC_TYPE_TMP_BUFFER));
    tpp = pp;
    if (tpp != NULL) {
        ExpectNotNull(XMEMSET(tpp, 0, ret + 1));
        ExpectIntEQ(i2c_ASN1_INTEGER(a, &tpp), 3);
        tpp -= 3;
        ExpectIntEQ(tpp[0], 0xFF);
        ExpectIntEQ(tpp[1], 0x7F);
        ExpectIntEQ(tpp[2], 0xFF);
    }
    XFREE(pp, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    wolfSSL_ASN1_INTEGER_free(a);
#endif /* OPENSSL_EXTRA && !NO_ASN */
    return EXPECT_RESULT();
}

int test_wolfSSL_ASN1_OBJECT(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA)
    ASN1_OBJECT* a = NULL;
    ASN1_OBJECT s;
    const unsigned char der[] = { 0x06, 0x01, 0x00 };

    /* Invalid parameter testing. */
    ASN1_OBJECT_free(NULL);
    ExpectNull(wolfSSL_ASN1_OBJECT_dup(NULL));

    /* Test that a static ASN1_OBJECT can be freed. */
    XMEMSET(&s, 0, sizeof(ASN1_OBJECT));
    ASN1_OBJECT_free(&s);
    ExpectNotNull(a = wolfSSL_ASN1_OBJECT_dup(&s));
    ASN1_OBJECT_free(a);
    a = NULL;
    s.obj = der;
    s.objSz = sizeof(der);
    ExpectNotNull(a = wolfSSL_ASN1_OBJECT_dup(&s));
    ASN1_OBJECT_free(a);
    ASN1_OBJECT_free(&s);
#endif /* OPENSSL_EXTRA */
    return EXPECT_RESULT();
}

int test_wolfSSL_ASN1_get_object(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_ECC) && defined(USE_CERT_BUFFERS_256)
    const unsigned char* derBuf = cliecc_cert_der_256;
    const unsigned char* nullPtr = NULL;
    const unsigned char objDerInvalidLen[] = { 0x30, 0x81 };
    const unsigned char objDerBadLen[] = { 0x30, 0x04 };
    const unsigned char objDerNotObj[] = { 0x02, 0x01, 0x00 };
    const unsigned char objDerNoData[] = { 0x06, 0x00 };
    const unsigned char* p;
    unsigned char objDer[10];
    unsigned char* der;
    unsigned char* derPtr;
    int len = sizeof_cliecc_cert_der_256;
    long asnLen = 0;
    int tag = 0;
    int cls = 0;
    ASN1_OBJECT* a = NULL;
    ASN1_OBJECT s;

    XMEMSET(&s, 0, sizeof(ASN1_OBJECT));

    /* Invalid encoding at length. */
    p = objDerInvalidLen;
    ExpectIntEQ(ASN1_get_object(&p, &asnLen, &tag, &cls, sizeof(objDerBadLen)),
        0x80);
    p = objDerBadLen;
    /* Error = 0x80, Constructed = 0x20 */
    ExpectIntEQ(ASN1_get_object(&p, &asnLen, &tag, &cls, sizeof(objDerBadLen)),
        0x80 | 0x20);

    /* Read a couple TLV triplets and make sure they match the expected values
     */

    /* SEQUENCE */
    ExpectIntEQ(ASN1_get_object(&derBuf, &asnLen, &tag, &cls, len) & 0x80, 0);
    ExpectIntEQ(asnLen, 862);
    ExpectIntEQ(tag, 0x10);
    ExpectIntEQ(cls, 0);

    /* SEQUENCE */
    ExpectIntEQ(ASN1_get_object(&derBuf, &asnLen, &tag, &cls,
            len - (derBuf - cliecc_cert_der_256)) & 0x80, 0);
    ExpectIntEQ(asnLen, 772);
    ExpectIntEQ(tag, 0x10);
    ExpectIntEQ(cls, 0);

    /* [0] */
    ExpectIntEQ(ASN1_get_object(&derBuf, &asnLen, &tag, &cls,
            len - (derBuf - cliecc_cert_der_256)) & 0x80, 0);
    ExpectIntEQ(asnLen, 3);
    ExpectIntEQ(tag, 0);
    ExpectIntEQ(cls, 0x80);

    /* INTEGER */
    ExpectIntEQ(ASN1_get_object(&derBuf, &asnLen, &tag, &cls,
            len - (derBuf - cliecc_cert_der_256)) & 0x80, 0);
    ExpectIntEQ(asnLen, 1);
    ExpectIntEQ(tag, 0x2);
    ExpectIntEQ(cls, 0);
    derBuf += asnLen;

    /* INTEGER */
    ExpectIntEQ(ASN1_get_object(&derBuf, &asnLen, &tag, &cls,
            len - (derBuf - cliecc_cert_der_256)) & 0x80, 0);
    ExpectIntEQ(asnLen, 20);
    ExpectIntEQ(tag, 0x2);
    ExpectIntEQ(cls, 0);
    derBuf += asnLen;

    /* SEQUENCE */
    ExpectIntEQ(ASN1_get_object(&derBuf, &asnLen, &tag, &cls,
            len - (derBuf - cliecc_cert_der_256)) & 0x80, 0);
    ExpectIntEQ(asnLen, 10);
    ExpectIntEQ(tag, 0x10);
    ExpectIntEQ(cls, 0);

    /* Found OBJECT_ID. */

    /* Invalid parameter testing. */
    ExpectIntEQ(ASN1_get_object(NULL, NULL, NULL, NULL, 0), 0x80);
    ExpectIntEQ(ASN1_get_object(&nullPtr, NULL, NULL, NULL, 0), 0x80);
    ExpectIntEQ(ASN1_get_object(NULL, &asnLen, &tag, &cls, len), 0x80);
    ExpectIntEQ(ASN1_get_object(&nullPtr, &asnLen, &tag, &cls, len), 0x80);
    ExpectIntEQ(ASN1_get_object(&derBuf, NULL, &tag, &cls, len), 0x80);
    ExpectIntEQ(ASN1_get_object(&derBuf, &asnLen, NULL, &cls, len), 0x80);
    ExpectIntEQ(ASN1_get_object(&derBuf, &asnLen, &tag, NULL, len), 0x80);
    ExpectIntEQ(ASN1_get_object(&derBuf, &asnLen, &tag, &cls, 0), 0x80);
    ExpectIntEQ(ASN1_get_object(&derBuf, &asnLen, &tag, &cls, -1), 0x80);
    ExpectNull(d2i_ASN1_OBJECT(NULL, NULL, -1));
    ExpectNull(d2i_ASN1_OBJECT(NULL, &nullPtr, -1));
    ExpectNull(d2i_ASN1_OBJECT(NULL, &derBuf, -1));
    ExpectNull(d2i_ASN1_OBJECT(NULL, NULL, 0));
    ExpectNull(d2i_ASN1_OBJECT(&a, NULL, len));
    ExpectNull(d2i_ASN1_OBJECT(&a, &nullPtr, len));
    ExpectNull(d2i_ASN1_OBJECT(&a, &derBuf, -1));
    ExpectNull(c2i_ASN1_OBJECT(NULL, NULL, -1));
    ExpectNull(c2i_ASN1_OBJECT(NULL, &nullPtr, -1));
    ExpectNull(c2i_ASN1_OBJECT(NULL, &derBuf, -1));
    ExpectNull(c2i_ASN1_OBJECT(NULL, NULL, 1));
    ExpectNull(c2i_ASN1_OBJECT(NULL, &nullPtr, 1));

    /* Invalid encoding at length. */
    p = objDerInvalidLen;
    ExpectNull(d2i_ASN1_OBJECT(&a, &p, sizeof(objDerInvalidLen)));
    p = objDerBadLen;
    ExpectNull(d2i_ASN1_OBJECT(&a, &p, sizeof(objDerBadLen)));
    p = objDerNotObj;
    ExpectNull(d2i_ASN1_OBJECT(&a, &p, sizeof(objDerNotObj)));
    p = objDerNoData;
    ExpectNull(d2i_ASN1_OBJECT(&a, &p, sizeof(objDerNoData)));

    /* Create an ASN OBJECT from content */
    p = derBuf + 2;
    ExpectNotNull(a = c2i_ASN1_OBJECT(NULL, &p, 8));
    ASN1_OBJECT_free(a);
    a = NULL;
    /* Create an ASN OBJECT from DER */
    ExpectNotNull(d2i_ASN1_OBJECT(&a, &derBuf, len));

    /* Invalid parameter testing. */
    ExpectIntEQ(i2d_ASN1_OBJECT(NULL, NULL), 0);
    ExpectIntEQ(i2d_ASN1_OBJECT(&s, NULL), 0);

    ExpectIntEQ(i2d_ASN1_OBJECT(a, NULL), 10);
    der = NULL;
    ExpectIntEQ(i2d_ASN1_OBJECT(a, &der), 10);
    derPtr = objDer;
    ExpectIntEQ(i2d_ASN1_OBJECT(a, &derPtr), 10);
    ExpectPtrNE(derPtr, objDer);
    ExpectIntEQ(XMEMCMP(der, objDer, 10), 0);
    XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);

    ASN1_OBJECT_free(a);
#endif /* OPENSSL_EXTRA && HAVE_ECC && USE_CERT_BUFFERS_256 */
    return EXPECT_RESULT();
}

int test_wolfSSL_i2a_ASN1_OBJECT(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_ASN) && !defined(NO_BIO)
    ASN1_OBJECT* obj = NULL;
    ASN1_OBJECT* a = NULL;
    BIO *bio = NULL;
    const unsigned char notObjDer[] = { 0x04, 0x01, 0xff };
    const unsigned char* p;

    ExpectNotNull(obj = OBJ_nid2obj(NID_sha256));
    ExpectTrue((bio = BIO_new(BIO_s_mem())) != NULL);

    ExpectIntGT(wolfSSL_i2a_ASN1_OBJECT(bio, obj), 0);
    ExpectIntGT(wolfSSL_i2a_ASN1_OBJECT(bio, NULL), 0);

    ExpectIntEQ(wolfSSL_i2a_ASN1_OBJECT(NULL, obj), 0);

    /* No DER encoding in ASN1_OBJECT. */
    ExpectNotNull(a = wolfSSL_ASN1_OBJECT_new());
    ExpectIntEQ(wolfSSL_i2a_ASN1_OBJECT(bio, a), 0);
    ASN1_OBJECT_free(a);
    a = NULL;
    /* DER encoding */
    p = notObjDer;
    ExpectNotNull(a = c2i_ASN1_OBJECT(NULL, &p, 3));
    ExpectIntEQ(wolfSSL_i2a_ASN1_OBJECT(bio, a), 5);
    ASN1_OBJECT_free(a);

    BIO_free(bio);
    ASN1_OBJECT_free(obj);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_i2t_ASN1_OBJECT(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && \
    defined(WOLFSSL_CERT_EXT) && defined(WOLFSSL_CERT_GEN)
    char buf[50] = {0};
    ASN1_OBJECT* obj;
    const char* oid = "2.5.29.19";
    const char* ln  = "X509v3 Basic Constraints";

    obj = NULL;
    ExpectIntEQ(i2t_ASN1_OBJECT(NULL, sizeof(buf), obj), 0);
    ExpectIntEQ(i2t_ASN1_OBJECT(buf, sizeof(buf), NULL), 0);
    ExpectIntEQ(i2t_ASN1_OBJECT(buf, 0, NULL), 0);

    ExpectNotNull(obj = OBJ_txt2obj(oid, 0));
    XMEMSET(buf, 0, sizeof(buf));
    ExpectIntEQ(i2t_ASN1_OBJECT(buf, sizeof(buf), obj), XSTRLEN(ln));
    ExpectIntEQ(XSTRNCMP(buf, ln, XSTRLEN(ln)), 0);
    ASN1_OBJECT_free(obj);
#endif /* OPENSSL_EXTRA && WOLFSSL_CERT_EXT && WOLFSSL_CERT_GEN */
    return EXPECT_RESULT();
}

int test_wolfSSL_sk_ASN1_OBJECT(void)
{
    EXPECT_DECLS;
#if !defined(NO_ASN) && (defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL))
    WOLFSSL_STACK* sk = NULL;
    WOLFSSL_ASN1_OBJECT* obj;

    ExpectNotNull(obj = wolfSSL_ASN1_OBJECT_new());

    ExpectNotNull(sk = wolfSSL_sk_new_asn1_obj());
    wolfSSL_sk_ASN1_OBJECT_free(sk);
    sk = NULL;

    ExpectNotNull(sk = wolfSSL_sk_new_asn1_obj());
    ExpectIntEQ(wolfSSL_sk_ASN1_OBJECT_push(NULL, NULL), -1);
    ExpectIntEQ(wolfSSL_sk_ASN1_OBJECT_push(sk, NULL), 0);
    ExpectIntEQ(wolfSSL_sk_ASN1_OBJECT_push(NULL, obj), -1);
    ExpectIntEQ(wolfSSL_sk_ASN1_OBJECT_push(sk, obj), 1);
    wolfSSL_sk_ASN1_OBJECT_pop_free(sk, NULL);
    sk = NULL;
    /* obj freed in pop_free call. */

    ExpectNotNull(obj = wolfSSL_ASN1_OBJECT_new());
    ExpectNotNull(sk = wolfSSL_sk_new_asn1_obj());
    ExpectIntEQ(wolfSSL_sk_ASN1_OBJECT_push(sk, obj), 1);
    ExpectPtrEq(obj, wolfSSL_sk_ASN1_OBJECT_pop(sk));
    wolfSSL_sk_ASN1_OBJECT_free(sk);
    wolfSSL_ASN1_OBJECT_free(obj);
#endif /* !NO_ASN && (OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL) */
    return EXPECT_RESULT();
}

int test_wolfSSL_ASN1_STRING(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA)
    ASN1_STRING* str = NULL;
    ASN1_STRING* c = NULL;
    const char data[]  = "hello wolfSSL";
    const char data2[] = "Same len data";
    const char longData[] =
        "This string must be longer than CTC_NAME_SIZE that is defined as 64.";

    ExpectNotNull(str = ASN1_STRING_type_new(V_ASN1_OCTET_STRING));
    ASN1_STRING_free(str);
    str = NULL;

    ExpectNotNull(str = ASN1_STRING_type_new(V_ASN1_OCTET_STRING));
    ExpectIntEQ(ASN1_STRING_type(str), V_ASN1_OCTET_STRING);
    ExpectIntEQ(ASN1_STRING_type(NULL), 0);
    /* Check setting to NULL works. */
    ExpectIntEQ(ASN1_STRING_set(str, NULL, 0), 1);
    ExpectIntEQ(ASN1_STRING_set(str, (const void*)data, sizeof(data)), 1);
    ExpectIntEQ(ASN1_STRING_set(str, (const void*)data, -1), 1);
    ExpectIntEQ(ASN1_STRING_set(str, NULL, -1), 0);
    ExpectIntEQ(ASN1_STRING_set(NULL, NULL, 0), 0);

    ExpectIntEQ(wolfSSL_ASN1_STRING_copy(NULL, NULL), 0);
    ExpectIntEQ(wolfSSL_ASN1_STRING_copy(str, NULL), 0);
    ExpectIntEQ(wolfSSL_ASN1_STRING_copy(NULL, str), 0);
    ExpectNull(wolfSSL_ASN1_STRING_dup(NULL));

    ExpectNotNull(c = wolfSSL_ASN1_STRING_dup(str));
    ExpectIntEQ(ASN1_STRING_cmp(NULL, NULL), -1);
    ExpectIntEQ(ASN1_STRING_cmp(str, NULL), -1);
    ExpectIntEQ(ASN1_STRING_cmp(NULL, c), -1);
    ExpectIntEQ(ASN1_STRING_cmp(str, c), 0);
    ExpectIntEQ(ASN1_STRING_set(c, (const void*)data2, -1), 1);
    ExpectIntGT(ASN1_STRING_cmp(str, c), 0);
    ExpectIntEQ(ASN1_STRING_set(str, (const void*)longData, -1), 1);
    ExpectIntEQ(wolfSSL_ASN1_STRING_copy(c, str), 1);
    ExpectIntEQ(ASN1_STRING_cmp(str, c), 0);
    /* Check setting back to smaller size frees dynamic data. */
    ExpectIntEQ(ASN1_STRING_set(str, (const void*)data, -1), 1);
    ExpectIntLT(ASN1_STRING_cmp(str, c), 0);
    ExpectIntGT(ASN1_STRING_cmp(c, str), 0);

    ExpectNull(ASN1_STRING_get0_data(NULL));
    ExpectNotNull(ASN1_STRING_get0_data(str));
    ExpectNull(ASN1_STRING_data(NULL));
    ExpectNotNull(ASN1_STRING_data(str));
    ExpectIntEQ(ASN1_STRING_length(NULL), 0);
    ExpectIntGT(ASN1_STRING_length(str), 0);

    ASN1_STRING_free(c);
    ASN1_STRING_free(str);
    ASN1_STRING_free(NULL);

#ifndef NO_WOLFSSL_STUB
    ExpectNull(d2i_DISPLAYTEXT(NULL, NULL, 0));
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_ASN1_STRING_to_UTF8(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_ASN) && !defined(NO_RSA) && \
    !defined(NO_FILESYSTEM)
    WOLFSSL_X509* x509 = NULL;
    WOLFSSL_X509_NAME* subject = NULL;
    WOLFSSL_X509_NAME_ENTRY* e = NULL;
    WOLFSSL_ASN1_STRING* a = NULL;
    FILE* file = XBADFILE;
    int idx = 0;
    char targetOutput[16] = "www.wolfssl.com";
    unsigned char* actual_output = NULL;
    int len = 0;

    ExpectNotNull(file = fopen("./certs/server-cert.pem", "rb"));
    ExpectNotNull(x509 = wolfSSL_PEM_read_X509(file, NULL, NULL, NULL));
    if (file != XBADFILE)
        fclose(file);

    /* wolfSSL_ASN1_STRING_to_UTF8(): NID_commonName */
    ExpectNotNull(subject = wolfSSL_X509_get_subject_name(x509));
    ExpectIntEQ((idx = wolfSSL_X509_NAME_get_index_by_NID(subject,
                    NID_commonName, -1)), 5);
    ExpectNotNull(e = wolfSSL_X509_NAME_get_entry(subject, idx));
    ExpectNotNull(a = wolfSSL_X509_NAME_ENTRY_get_data(e));
    ExpectIntEQ((len = wolfSSL_ASN1_STRING_to_UTF8(&actual_output, a)), 15);
    ExpectIntEQ(strncmp((const char*)actual_output, targetOutput, (size_t)len), 0);
    a = NULL;

    /* wolfSSL_ASN1_STRING_to_UTF8(NULL, valid) */
    ExpectIntEQ((len = wolfSSL_ASN1_STRING_to_UTF8(NULL, a)), -1);

    /* wolfSSL_ASN1_STRING_to_UTF8(valid, NULL) */
    ExpectIntEQ((len = wolfSSL_ASN1_STRING_to_UTF8(&actual_output, NULL)), -1);

    /* wolfSSL_ASN1_STRING_to_UTF8(NULL, NULL) */
    ExpectIntEQ((len = wolfSSL_ASN1_STRING_to_UTF8(NULL, NULL)), -1);

    wolfSSL_X509_free(x509);
    XFREE(actual_output, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    ExpectNotNull(a = ASN1_STRING_new());
    ExpectIntEQ(wolfSSL_ASN1_STRING_to_UTF8(&actual_output, a), -1);
    ASN1_STRING_free(a);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_i2s_ASN1_STRING(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_ASN)
    WOLFSSL_ASN1_STRING* str = NULL;
    const char* data = "test_wolfSSL_i2s_ASN1_STRING";
    char* ret = NULL;

    ExpectNotNull(str = ASN1_STRING_new());

    ExpectNull(ret = wolfSSL_i2s_ASN1_STRING(NULL, NULL));
    XFREE(ret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ret = NULL;
    /* No data. */
    ExpectNull(ret = wolfSSL_i2s_ASN1_STRING(NULL, str));
    XFREE(ret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ret = NULL;

    ExpectIntEQ(ASN1_STRING_set(str, data, 0), 1);
    ExpectNotNull(ret = wolfSSL_i2s_ASN1_STRING(NULL, str));
    XFREE(ret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ret = NULL;

    ExpectIntEQ(ASN1_STRING_set(str, data, -1), 1);
    /* No type. */
    ExpectNotNull(ret = wolfSSL_i2s_ASN1_STRING(NULL, str));
    XFREE(ret, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    ASN1_STRING_free(str);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_ASN1_STRING_canon(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TEST_STATIC_BUILD)
#if !defined(NO_CERTS) && (defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA) || \
    defined(OPENSSL_EXTRA_X509_SMALL))
    WOLFSSL_ASN1_STRING* orig = NULL;
    WOLFSSL_ASN1_STRING* canon = NULL;
    const char* data = "test_wolfSSL_ASN1_STRING_canon";
    const char* whitespaceOnly = "\t\r\n";
    const char* modData = "  \x01\f\t\x02\r\n\v\xff\nTt \n";
    const char* canonData = "\x01 \x02 \xff tt";
    const char longData[] =
        "This string must be longer than CTC_NAME_SIZE that is defined as 64.";

    ExpectNotNull(orig = ASN1_STRING_new());
    ExpectNotNull(canon = ASN1_STRING_new());

    /* Invalid parameter testing. */
    ExpectIntEQ(wolfSSL_ASN1_STRING_canon(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_ASN1_STRING_canon(canon, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_ASN1_STRING_canon(NULL, orig), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wolfSSL_ASN1_STRING_canon(canon, orig), 1);
    ExpectIntEQ(ASN1_STRING_cmp(orig, canon), 0);

    ExpectIntEQ(ASN1_STRING_set(orig, longData, (int)XSTRLEN(data)), 1);
    ExpectIntEQ(wolfSSL_ASN1_STRING_canon(canon, orig), 1);
    ExpectIntEQ(ASN1_STRING_cmp(orig, canon), 0);

    ExpectIntEQ(ASN1_STRING_set(orig, data, (int)XSTRLEN(data)), 1);
    ExpectIntEQ(wolfSSL_ASN1_STRING_canon(canon, orig), 1);
    ExpectIntEQ(ASN1_STRING_cmp(orig, canon), 0);

    ASN1_STRING_free(orig);
    orig = NULL;

    ExpectNotNull(orig = ASN1_STRING_type_new(MBSTRING_UTF8));
    ExpectIntEQ(ASN1_STRING_set(orig, modData, 15), 1);
    ExpectIntEQ(wolfSSL_ASN1_STRING_canon(canon, orig), 1);
    ExpectIntEQ(ASN1_STRING_set(orig, canonData, 8), 1);
    ExpectIntEQ(ASN1_STRING_cmp(orig, canon), 0);
    ASN1_STRING_free(orig);
    orig = NULL;

    ExpectNotNull(orig = ASN1_STRING_type_new(V_ASN1_PRINTABLESTRING));
    ExpectIntEQ(ASN1_STRING_set(orig, whitespaceOnly, 3), 1);
    ExpectIntEQ(wolfSSL_ASN1_STRING_canon(canon, orig), 1);
    ASN1_STRING_free(orig);
    orig = NULL;
    ExpectNotNull(orig = ASN1_STRING_type_new(MBSTRING_UTF8));
    ExpectIntEQ(ASN1_STRING_cmp(orig, canon), 0);

    ASN1_STRING_free(orig);
    ASN1_STRING_free(canon);
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_ASN1_STRING_print(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_ASN) && !defined(NO_CERTS) && \
    !defined(NO_BIO)
    ASN1_STRING* asnStr = NULL;
    const char HELLO_DATA[]= \
                      {'H','e','l','l','o',' ','w','o','l','f','S','S','L','!'};
    #define MAX_UNPRINTABLE_CHAR 32
    #define MAX_BUF 255
    unsigned char unprintableData[MAX_UNPRINTABLE_CHAR + sizeof(HELLO_DATA)];
    unsigned char expected[sizeof(unprintableData)+1];
    unsigned char rbuf[MAX_BUF];
    BIO *bio = NULL;
    int p_len;
    int i;

    /* setup */

    for (i = 0; i < (int)sizeof(HELLO_DATA); i++) {
        unprintableData[i]  = (unsigned char)HELLO_DATA[i];
        expected[i]         = (unsigned char)HELLO_DATA[i];
    }

    for (i = 0; i < (int)MAX_UNPRINTABLE_CHAR; i++) {
        unprintableData[sizeof(HELLO_DATA)+i] = i;

        if (i == (int)'\n' || i == (int)'\r')
            expected[sizeof(HELLO_DATA)+i] = i;
        else
            expected[sizeof(HELLO_DATA)+i] = '.';
    }

    unprintableData[sizeof(unprintableData)-1] = '\0';
    expected[sizeof(expected)-1] = '\0';

    XMEMSET(rbuf, 0, MAX_BUF);
    ExpectNotNull(bio = BIO_new(BIO_s_mem()));
    ExpectIntEQ(BIO_set_write_buf_size(bio, MAX_BUF), 0);

    ExpectNotNull(asnStr = ASN1_STRING_type_new(V_ASN1_OCTET_STRING));
    ExpectIntEQ(ASN1_STRING_set(asnStr,(const void*)unprintableData,
            (int)sizeof(unprintableData)), 1);
    /* test */
    ExpectIntEQ(wolfSSL_ASN1_STRING_print(NULL, NULL), 0);
    ExpectIntEQ(wolfSSL_ASN1_STRING_print(bio, NULL), 0);
    ExpectIntEQ(wolfSSL_ASN1_STRING_print(NULL, asnStr), 0);
    ExpectIntEQ(p_len = wolfSSL_ASN1_STRING_print(bio, asnStr), 46);
    ExpectIntEQ(BIO_read(bio, (void*)rbuf, 46), 46);

    ExpectStrEQ((char*)rbuf, (const char*)expected);

    BIO_free(bio);
    bio = NULL;

    ExpectNotNull(bio = BIO_new(wolfSSL_BIO_s_fixed_mem()));
    ExpectIntEQ(BIO_set_write_buf_size(bio, 1), 1);
    /* Ensure there is 0 bytes available to write into. */
    ExpectIntEQ(BIO_write(bio, rbuf, 1), 1);
    ExpectIntEQ(wolfSSL_ASN1_STRING_print(bio, asnStr), 0);
    ExpectIntEQ(BIO_set_write_buf_size(bio, 1), 1);
    ExpectIntEQ(wolfSSL_ASN1_STRING_print(bio, asnStr), 0);
    ExpectIntEQ(BIO_set_write_buf_size(bio, 45), 1);
    ExpectIntEQ(wolfSSL_ASN1_STRING_print(bio, asnStr), 0);
    BIO_free(bio);

    ASN1_STRING_free(asnStr);
#endif /* OPENSSL_EXTRA && !NO_ASN && !NO_CERTS && !NO_BIO */
    return EXPECT_RESULT();
}

int test_wolfSSL_ASN1_STRING_print_ex(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_ASN) && !defined(NO_BIO)
    ASN1_STRING* asn_str = NULL;
    const char data[] = "Hello wolfSSL!";
    ASN1_STRING* esc_str = NULL;
    const char esc_data[] = "a+;<>";
    ASN1_STRING* neg_int = NULL;
    const char neg_int_data[] = "\xff";
    ASN1_STRING* neg_enum = NULL;
    const char neg_enum_data[] = "\xff";
    BIO *bio = NULL;
    BIO *fixed = NULL;
    unsigned long flags;
    int p_len;
    unsigned char rbuf[255];

    /* setup */
    XMEMSET(rbuf, 0, 255);
    ExpectNotNull(bio = BIO_new(BIO_s_mem()));
    ExpectIntEQ(BIO_set_write_buf_size(bio, 255), 0);
    ExpectNotNull(fixed = BIO_new(wolfSSL_BIO_s_fixed_mem()));

    ExpectNotNull(asn_str = ASN1_STRING_type_new(V_ASN1_OCTET_STRING));
    ExpectIntEQ(ASN1_STRING_set(asn_str, (const void*)data, sizeof(data)), 1);
    ExpectNotNull(esc_str = ASN1_STRING_type_new(V_ASN1_OCTET_STRING));
    ExpectIntEQ(ASN1_STRING_set(esc_str, (const void*)esc_data,
        sizeof(esc_data)), 1);
    ExpectNotNull(neg_int = ASN1_STRING_type_new(V_ASN1_NEG_INTEGER));
    ExpectIntEQ(ASN1_STRING_set(neg_int, (const void*)neg_int_data,
        sizeof(neg_int_data) - 1), 1);
    ExpectNotNull(neg_enum = ASN1_STRING_type_new(V_ASN1_NEG_ENUMERATED));
    ExpectIntEQ(ASN1_STRING_set(neg_enum, (const void*)neg_enum_data,
        sizeof(neg_enum_data) - 1), 1);

    /* Invalid parameter testing. */
    ExpectIntEQ(wolfSSL_ASN1_STRING_print_ex(NULL, NULL, 0), 0);
    ExpectIntEQ(wolfSSL_ASN1_STRING_print_ex(bio, NULL, 0), 0);
    ExpectIntEQ(wolfSSL_ASN1_STRING_print_ex(NULL, asn_str, 0), 0);

    /* no flags */
    XMEMSET(rbuf, 0, 255);
    flags = 0;
    ExpectIntEQ(p_len = wolfSSL_ASN1_STRING_print_ex(bio, asn_str, flags), 15);
    ExpectIntEQ(BIO_read(bio, (void*)rbuf, 15), 15);
    ExpectStrEQ((char*)rbuf, "Hello wolfSSL!");
    ExpectIntEQ(BIO_set_write_buf_size(fixed, 1), 1);
    /* Ensure there is 0 bytes available to write into. */
    ExpectIntEQ(BIO_write(fixed, rbuf, 1), 1);
    ExpectIntEQ(wolfSSL_ASN1_STRING_print_ex(fixed, asn_str, flags), 0);
    ExpectIntEQ(BIO_set_write_buf_size(fixed, 1), 1);
    ExpectIntEQ(wolfSSL_ASN1_STRING_print_ex(fixed, asn_str, flags), 0);
    ExpectIntEQ(BIO_set_write_buf_size(fixed, 14), 1);
    ExpectIntEQ(wolfSSL_ASN1_STRING_print_ex(fixed, asn_str, flags), 0);

    /* RFC2253 Escape */
    XMEMSET(rbuf, 0, 255);
    flags = ASN1_STRFLGS_ESC_2253;
    ExpectIntEQ(p_len = wolfSSL_ASN1_STRING_print_ex(bio, esc_str, flags), 9);
    ExpectIntEQ(BIO_read(bio, (void*)rbuf, 9), 9);
    ExpectStrEQ((char*)rbuf, "a\\+\\;\\<\\>");
    ExpectIntEQ(BIO_set_write_buf_size(fixed, 1), 1);
    /* Ensure there is 0 bytes available to write into. */
    ExpectIntEQ(BIO_write(fixed, rbuf, 1), 1);
    ExpectIntEQ(wolfSSL_ASN1_STRING_print_ex(fixed, esc_str, flags), 0);
    ExpectIntEQ(BIO_set_write_buf_size(fixed, 1), 1);
    ExpectIntEQ(wolfSSL_ASN1_STRING_print_ex(fixed, esc_str, flags), 0);
    ExpectIntEQ(BIO_set_write_buf_size(fixed, 8), 1);
    ExpectIntEQ(wolfSSL_ASN1_STRING_print_ex(fixed, esc_str, flags), 0);

    /* Show type */
    XMEMSET(rbuf, 0, 255);
    flags = ASN1_STRFLGS_SHOW_TYPE;
    ExpectIntEQ(p_len = wolfSSL_ASN1_STRING_print_ex(bio, asn_str, flags), 28);
    ExpectIntEQ(BIO_read(bio, (void*)rbuf, 28), 28);
    ExpectStrEQ((char*)rbuf, "OCTET STRING:Hello wolfSSL!");
    ExpectIntEQ(BIO_set_write_buf_size(fixed, 1), 1);
    /* Ensure there is 0 bytes available to write into. */
    ExpectIntEQ(BIO_write(fixed, rbuf, 1), 1);
    ExpectIntEQ(wolfSSL_ASN1_STRING_print_ex(fixed, asn_str, flags), 0);
    ExpectIntEQ(BIO_set_write_buf_size(fixed, 1), 1);
    ExpectIntEQ(wolfSSL_ASN1_STRING_print_ex(fixed, asn_str, flags), 0);
    ExpectIntEQ(BIO_set_write_buf_size(fixed, 12), 1);
    ExpectIntEQ(wolfSSL_ASN1_STRING_print_ex(fixed, asn_str, flags), 0);
    ExpectIntEQ(BIO_set_write_buf_size(fixed, 27), 1);
    ExpectIntEQ(wolfSSL_ASN1_STRING_print_ex(fixed, asn_str, flags), 0);

    /* Dump All */
    XMEMSET(rbuf, 0, 255);
    flags = ASN1_STRFLGS_DUMP_ALL;
    ExpectIntEQ(p_len = wolfSSL_ASN1_STRING_print_ex(bio, asn_str, flags), 31);
    ExpectIntEQ(BIO_read(bio, (void*)rbuf, 31), 31);
    ExpectStrEQ((char*)rbuf, "#48656C6C6F20776F6C6653534C2100");
    ExpectIntEQ(BIO_set_write_buf_size(fixed, 1), 1);
    /* Ensure there is 0 bytes available to write into. */
    ExpectIntEQ(BIO_write(fixed, rbuf, 1), 1);
    ExpectIntEQ(wolfSSL_ASN1_STRING_print_ex(fixed, asn_str, flags), 0);
    ExpectIntEQ(BIO_set_write_buf_size(fixed, 1), 1);
    ExpectIntEQ(wolfSSL_ASN1_STRING_print_ex(fixed, asn_str, flags), 0);
    ExpectIntEQ(BIO_set_write_buf_size(fixed, 30), 1);
    ExpectIntEQ(wolfSSL_ASN1_STRING_print_ex(fixed, asn_str, flags), 0);

    /* Dump Der */
    XMEMSET(rbuf, 0, 255);
    flags = ASN1_STRFLGS_DUMP_ALL | ASN1_STRFLGS_DUMP_DER;
    ExpectIntEQ(p_len = wolfSSL_ASN1_STRING_print_ex(bio, asn_str, flags), 35);
    ExpectIntEQ(BIO_read(bio, (void*)rbuf, 35), 35);
    ExpectStrEQ((char*)rbuf, "#040F48656C6C6F20776F6C6653534C2100");
    ExpectIntEQ(BIO_set_write_buf_size(fixed, 1), 1);
    /* Ensure there is 0 bytes available to write into. */
    ExpectIntEQ(BIO_write(fixed, rbuf, 1), 1);
    ExpectIntEQ(wolfSSL_ASN1_STRING_print_ex(fixed, asn_str, flags), 0);
    ExpectIntEQ(BIO_set_write_buf_size(fixed, 1), 1);
    ExpectIntEQ(wolfSSL_ASN1_STRING_print_ex(fixed, asn_str, flags), 0);
    ExpectIntEQ(BIO_set_write_buf_size(fixed, 2), 1);
    ExpectIntEQ(wolfSSL_ASN1_STRING_print_ex(fixed, asn_str, flags), 0);
    ExpectIntEQ(BIO_set_write_buf_size(fixed, 30), 1);
    ExpectIntEQ(wolfSSL_ASN1_STRING_print_ex(fixed, asn_str, flags), 0);

    /* Dump All + Show type */
    XMEMSET(rbuf, 0, 255);
    flags = ASN1_STRFLGS_DUMP_ALL | ASN1_STRFLGS_SHOW_TYPE;
    ExpectIntEQ(p_len = wolfSSL_ASN1_STRING_print_ex(bio, asn_str, flags), 44);
    ExpectIntEQ(BIO_read(bio, (void*)rbuf, 44), 44);
    ExpectStrEQ((char*)rbuf, "OCTET STRING:#48656C6C6F20776F6C6653534C2100");

    /* Dump All + Show type - Negative Integer. */
    XMEMSET(rbuf, 0, 255);
    flags = ASN1_STRFLGS_DUMP_ALL | ASN1_STRFLGS_SHOW_TYPE;
    ExpectIntEQ(p_len = wolfSSL_ASN1_STRING_print_ex(bio, neg_int, flags), 11);
    ExpectIntEQ(BIO_read(bio, (void*)rbuf, 11), 11);
    ExpectStrEQ((char*)rbuf, "INTEGER:#FF");

    /* Dump All + Show type - Negative Enumerated. */
    XMEMSET(rbuf, 0, 255);
    flags = ASN1_STRFLGS_DUMP_ALL | ASN1_STRFLGS_SHOW_TYPE;
    ExpectIntEQ(p_len = wolfSSL_ASN1_STRING_print_ex(bio, neg_enum, flags), 14);
    ExpectIntEQ(BIO_read(bio, (void*)rbuf, 14), 14);
    ExpectStrEQ((char*)rbuf, "ENUMERATED:#FF");

    BIO_free(fixed);
    BIO_free(bio);
    ASN1_STRING_free(asn_str);
    ASN1_STRING_free(esc_str);
    ASN1_STRING_free(neg_int);
    ASN1_STRING_free(neg_enum);

    ExpectStrEQ(wolfSSL_ASN1_tag2str(-1), "(unknown)");
    ExpectStrEQ(wolfSSL_ASN1_tag2str(31), "(unknown)");
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_ASN1_UNIVERSALSTRING_to_string(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_ASN)
    ASN1_STRING* asn1str_test = NULL;
    ASN1_STRING* asn1str_answer = NULL;
    /* Each character is encoded using 4 bytes */
    char input[] = {
            0, 0, 0, 'T',
            0, 0, 0, 'e',
            0, 0, 0, 's',
            0, 0, 0, 't',
    };
    char output[] = "Test";
    char badInput[] = {
            1, 0, 0, 'T',
            0, 1, 0, 'e',
            0, 0, 1, 's',
    };

    ExpectIntEQ(ASN1_UNIVERSALSTRING_to_string(NULL), 0);
    /* Test wrong type. */
    ExpectNotNull(asn1str_test = ASN1_STRING_type_new(V_ASN1_OCTET_STRING));
    ExpectIntEQ(ASN1_UNIVERSALSTRING_to_string(asn1str_test), 0);
    ASN1_STRING_free(asn1str_test);
    asn1str_test = NULL;

    ExpectNotNull(asn1str_test = ASN1_STRING_type_new(V_ASN1_UNIVERSALSTRING));

    /* Test bad length. */
    ExpectIntEQ(ASN1_STRING_set(asn1str_test, input, sizeof(input) - 1), 1);
    ExpectIntEQ(ASN1_UNIVERSALSTRING_to_string(asn1str_test), 0);
    /* Test bad input. */
    ExpectIntEQ(ASN1_STRING_set(asn1str_test, badInput + 0, 4), 1);
    ExpectIntEQ(ASN1_UNIVERSALSTRING_to_string(asn1str_test), 0);
    ExpectIntEQ(ASN1_STRING_set(asn1str_test, badInput + 4, 4), 1);
    ExpectIntEQ(ASN1_UNIVERSALSTRING_to_string(asn1str_test), 0);
    ExpectIntEQ(ASN1_STRING_set(asn1str_test, badInput + 8, 4), 1);
    ExpectIntEQ(ASN1_UNIVERSALSTRING_to_string(asn1str_test), 0);

    ExpectIntEQ(ASN1_STRING_set(asn1str_test, input, sizeof(input)), 1);
    ExpectIntEQ(ASN1_UNIVERSALSTRING_to_string(asn1str_test), 1);

    ExpectNotNull(
        asn1str_answer = ASN1_STRING_type_new(V_ASN1_PRINTABLESTRING));
    ExpectIntEQ(ASN1_STRING_set(asn1str_answer, output, sizeof(output)-1), 1);

    ExpectIntEQ(ASN1_STRING_cmp(asn1str_test, asn1str_answer), 0);

    ASN1_STRING_free(asn1str_test);
    ASN1_STRING_free(asn1str_answer);
#endif /* OPENSSL_ALL && !NO_ASN */
    return EXPECT_RESULT();
}

int test_wolfSSL_ASN1_GENERALIZEDTIME_free(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_ASN_TIME)
    WOLFSSL_ASN1_GENERALIZEDTIME* asn1_gtime = NULL;

    ExpectNotNull(asn1_gtime = ASN1_GENERALIZEDTIME_new());
    if (asn1_gtime != NULL)
        XMEMCPY(asn1_gtime->data, "20180504123500Z", ASN_GENERALIZED_TIME_SIZE);
    ASN1_GENERALIZEDTIME_free(asn1_gtime);
#endif /* OPENSSL_EXTRA && !NO_ASN_TIME */
    return EXPECT_RESULT();
}

int test_wolfSSL_ASN1_GENERALIZEDTIME_print(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_ASN_TIME) && !defined(NO_BIO)
    WOLFSSL_ASN1_GENERALIZEDTIME* gtime = NULL;
    BIO* bio = NULL;
    unsigned char buf[24];
    int i;

    ExpectNotNull(bio = BIO_new(BIO_s_mem()));
    BIO_set_write_buf_size(bio, 24);

    ExpectNotNull(gtime = ASN1_GENERALIZEDTIME_new());
    /* Type not set. */
    ExpectIntEQ(wolfSSL_ASN1_GENERALIZEDTIME_print(bio, gtime), 0);
    ExpectIntEQ(wolfSSL_ASN1_TIME_set_string(gtime, "20180504123500Z"), 1);

    /* Invalid parameters testing. */
    ExpectIntEQ(wolfSSL_ASN1_GENERALIZEDTIME_print(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_ASN1_GENERALIZEDTIME_print(bio, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_ASN1_GENERALIZEDTIME_print(NULL, gtime), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wolfSSL_ASN1_GENERALIZEDTIME_print(bio, gtime), 1);
    ExpectIntEQ(BIO_read(bio, buf, sizeof(buf)), 20);
    ExpectIntEQ(XMEMCMP(buf, "May 04 12:35:00 2018", 20), 0);

    BIO_free(bio);
    bio = NULL;

    ExpectNotNull(bio = BIO_new(wolfSSL_BIO_s_fixed_mem()));
    ExpectIntEQ(BIO_set_write_buf_size(bio, 1), 1);
    /* Ensure there is 0 bytes available to write into. */
    ExpectIntEQ(BIO_write(bio, buf, 1), 1);
    ExpectIntEQ(wolfSSL_ASN1_GENERALIZEDTIME_print(bio, gtime), 0);
    for (i = 1; i < 20; i++) {
        ExpectIntEQ(BIO_set_write_buf_size(bio, i), 1);
        ExpectIntEQ(wolfSSL_ASN1_GENERALIZEDTIME_print(bio, gtime), 0);
    }
    BIO_free(bio);

    wolfSSL_ASN1_GENERALIZEDTIME_free(gtime);
#endif /* OPENSSL_EXTRA && !NO_ASN_TIME && !NO_BIO */
    return EXPECT_RESULT();
}

int test_wolfSSL_ASN1_TIME(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_ASN_TIME)
    WOLFSSL_ASN1_TIME* asn_time = NULL;
    unsigned char *data = NULL;

    ExpectNotNull(asn_time = ASN1_TIME_new());

#ifndef NO_WOLFSSL_STUB
    ExpectNotNull(ASN1_TIME_set(asn_time, 1));
#endif
    ExpectIntEQ(ASN1_TIME_set_string(NULL, NULL), 0);
    ExpectIntEQ(ASN1_TIME_set_string(asn_time, NULL), 0);
    ExpectIntEQ(ASN1_TIME_set_string(NULL,
        "String longer than CTC_DATA_SIZE that is 32 bytes"), 0);
    ExpectIntEQ(ASN1_TIME_set_string(NULL, "101219181011Z"), 1);
    ExpectIntEQ(ASN1_TIME_set_string(asn_time, "101219181011Z"), 1);

    ExpectIntEQ(wolfSSL_ASN1_TIME_get_length(NULL), 0);
    ExpectIntEQ(wolfSSL_ASN1_TIME_get_length(asn_time), ASN_UTC_TIME_SIZE - 1);
    ExpectNull(wolfSSL_ASN1_TIME_get_data(NULL));
    ExpectNotNull(data = wolfSSL_ASN1_TIME_get_data(asn_time));
    ExpectIntEQ(XMEMCMP(data, "101219181011Z", 14), 0);

    ExpectIntEQ(ASN1_TIME_check(NULL), 0);
    ExpectIntEQ(ASN1_TIME_check(asn_time), 1);

    ExpectIntEQ(ASN1_TIME_set_string_X509(asn_time, "101219181011Z"), 1);
    ExpectIntEQ(ASN1_TIME_set_string_X509(asn_time, "101219181011Za"), 0);

    ASN1_TIME_free(asn_time);
    ASN1_TIME_free(NULL);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_ASN1_TIME_to_string(void)
{
    EXPECT_DECLS;
#ifndef NO_ASN_TIME
#if defined(WOLFSSL_MYSQL_COMPATIBLE) || defined(WOLFSSL_NGINX) || \
    defined(WOLFSSL_HAPROXY) || defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)
    WOLFSSL_ASN1_TIME* t = NULL;
    char buf[ASN_GENERALIZED_TIME_SIZE];

    ExpectNotNull((t = ASN1_TIME_new()));
    ExpectIntEQ(ASN1_TIME_set_string(t, "030222211515Z"), 1);

    /* Invalid parameter testing. */
    ExpectNull(ASN1_TIME_to_string(NULL, NULL, 4));
    ExpectNull(ASN1_TIME_to_string(t, NULL, 4));
    ExpectNull(ASN1_TIME_to_string(NULL, buf, 4));
    ExpectNull(ASN1_TIME_to_string(NULL, NULL, 5));
    ExpectNull(ASN1_TIME_to_string(NULL, buf, 5));
    ExpectNull(ASN1_TIME_to_string(t, NULL, 5));
    ExpectNull(ASN1_TIME_to_string(t, buf, 4));
    /* Buffer needs to be longer than minimum of 5 characters. */
    ExpectNull(ASN1_TIME_to_string(t, buf, 5));

    ASN1_TIME_free(t);
#endif
#endif /* NO_ASN_TIME */
    return EXPECT_RESULT();
}

int test_wolfSSL_ASN1_TIME_diff_compare(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_ASN_TIME)
    ASN1_TIME* fromTime = NULL;
    ASN1_TIME* closeToTime = NULL;
    ASN1_TIME* toTime = NULL;
    ASN1_TIME* invalidTime = NULL;
    int daysDiff = 0;
    int secsDiff = 0;

    ExpectNotNull((fromTime = ASN1_TIME_new()));
    /* Feb 22, 2003, 21:15:15 */
    ExpectIntEQ(ASN1_TIME_set_string(fromTime, "030222211515Z"), 1);
    ExpectNotNull((closeToTime = ASN1_TIME_new()));
    /* Feb 22, 2003, 21:16:15 */
    ExpectIntEQ(ASN1_TIME_set_string(closeToTime, "030222211615Z"), 1);
    ExpectNotNull((toTime = ASN1_TIME_new()));
    /* Dec 19, 2010, 18:10:11 */
    ExpectIntEQ(ASN1_TIME_set_string(toTime, "101219181011Z"), 1);
    ExpectNotNull((invalidTime = ASN1_TIME_new()));
    /* Dec 19, 2010, 18:10:11 but 'U' instead of 'Z' which is invalid. */
    ExpectIntEQ(ASN1_TIME_set_string(invalidTime, "102519181011U"), 1);

    ExpectIntEQ(ASN1_TIME_diff(&daysDiff, &secsDiff, fromTime, invalidTime), 0);
    ExpectIntEQ(ASN1_TIME_diff(&daysDiff, &secsDiff, invalidTime, toTime), 0);

    ExpectIntEQ(ASN1_TIME_diff(&daysDiff, &secsDiff, fromTime, toTime), 1);

    /* Test when secsDiff or daysDiff is NULL. */
    ExpectIntEQ(ASN1_TIME_diff(NULL, &secsDiff, fromTime, toTime), 1);
    ExpectIntEQ(ASN1_TIME_diff(&daysDiff, NULL, fromTime, toTime), 1);
    ExpectIntEQ(ASN1_TIME_diff(NULL, NULL, fromTime, toTime), 1);

    /* If both times are NULL, difference is 0. */
    ExpectIntEQ(ASN1_TIME_diff(&daysDiff, &secsDiff, NULL, NULL), 1);
    ExpectIntEQ(daysDiff, 0);
    ExpectIntEQ(secsDiff, 0);

    /* If one time is NULL, it defaults to the current time. */
    ExpectIntEQ(ASN1_TIME_diff(&daysDiff, &secsDiff, NULL, toTime), 1);
    ExpectIntEQ(ASN1_TIME_diff(&daysDiff, &secsDiff, fromTime, NULL), 1);

    /* Normal operation. Both times non-NULL. */
    ExpectIntEQ(ASN1_TIME_diff(&daysDiff, &secsDiff, fromTime, toTime), 1);
    ExpectIntEQ(daysDiff, 2856);
    ExpectIntEQ(secsDiff, 75296);
    /* Swapping the times should return negative values. */
    ExpectIntEQ(ASN1_TIME_diff(&daysDiff, &secsDiff, toTime, fromTime), 1);
    ExpectIntEQ(daysDiff, -2856);
    ExpectIntEQ(secsDiff, -75296);

    /* Compare with invalid time string. */
    ExpectIntEQ(ASN1_TIME_compare(fromTime, invalidTime), -2);
    ExpectIntEQ(ASN1_TIME_compare(invalidTime, toTime), -2);
    /* Compare with days difference of 0. */
    ExpectIntEQ(ASN1_TIME_compare(fromTime, closeToTime), -1);
    ExpectIntEQ(ASN1_TIME_compare(closeToTime, fromTime), 1);
    /* Days and seconds differences not 0. */
    ExpectIntEQ(ASN1_TIME_compare(fromTime, toTime), -1);
    ExpectIntEQ(ASN1_TIME_compare(toTime, fromTime), 1);
    /* Same time. */
    ExpectIntEQ(ASN1_TIME_compare(fromTime, fromTime), 0);

    /* Compare regression test: No seconds difference, just difference in days.
     */
    ASN1_TIME_set_string(fromTime, "19700101000000Z");
    ASN1_TIME_set_string(toTime, "19800101000000Z");
    ExpectIntEQ(ASN1_TIME_compare(fromTime, toTime), -1);
    ExpectIntEQ(ASN1_TIME_compare(toTime, fromTime), 1);
    ExpectIntEQ(ASN1_TIME_compare(fromTime, fromTime), 0);

    /* Edge case with Unix epoch. */
    ExpectNotNull(ASN1_TIME_set_string(fromTime, "19700101000000Z"));
    ExpectNotNull(ASN1_TIME_set_string(toTime, "19800101000000Z"));
    ExpectIntEQ(ASN1_TIME_diff(&daysDiff, &secsDiff, fromTime, toTime), 1);
    ExpectIntEQ(daysDiff, 3652);
    ExpectIntEQ(secsDiff, 0);

    /* Edge case with year > 2038 (year 2038 problem). */
    ExpectNotNull(ASN1_TIME_set_string(toTime, "99991231235959Z"));
    ExpectIntEQ(ASN1_TIME_diff(&daysDiff, &secsDiff, fromTime, toTime), 1);
    ExpectIntEQ(daysDiff, 2932896);
    ExpectIntEQ(secsDiff, 86399);

    ASN1_TIME_free(fromTime);
    ASN1_TIME_free(closeToTime);
    ASN1_TIME_free(toTime);
    ASN1_TIME_free(invalidTime);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_ASN1_TIME_adj(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_ASN_TIME) && \
    !defined(USER_TIME) && !defined(TIME_OVERRIDES)
    const int year = 365*24*60*60;
    const int day  = 24*60*60;
    const int hour = 60*60;
    const int mini = 60;
    const byte asn_utc_time = ASN_UTC_TIME;
#if !defined(TIME_T_NOT_64BIT) && !defined(NO_64BIT)
    const byte asn_gen_time = ASN_GENERALIZED_TIME;
#endif
    WOLFSSL_ASN1_TIME* asn_time = NULL;
    WOLFSSL_ASN1_TIME* s = NULL;
    int offset_day;
    long offset_sec;
    char date_str[CTC_DATE_SIZE + 1];
    time_t t;

    ExpectNotNull(s = wolfSSL_ASN1_TIME_new());
    /* UTC notation test */
    /* 2000/2/15 20:30:00 */
    t = (time_t)30 * year + 45 * day + 20 * hour + 30 * mini + 7 * day;
    offset_day = 7;
    offset_sec = 45 * mini;
    /* offset_sec = -45 * min;*/
    ExpectNotNull(asn_time =
            wolfSSL_ASN1_TIME_adj(s, t, offset_day, offset_sec));
    if (asn_time != NULL) {
        ExpectTrue(asn_time->type == asn_utc_time);
        ExpectNotNull(XSTRNCPY(date_str, (const char*)&asn_time->data,
            CTC_DATE_SIZE));
        date_str[CTC_DATE_SIZE] = '\0';
        ExpectIntEQ(0, XMEMCMP(date_str, "000222211500Z", 13));
        if (asn_time != s) {
            XFREE(asn_time, NULL, DYNAMIC_TYPE_OPENSSL);
        }
        asn_time = NULL;
    }

    /* negative offset */
    offset_sec = -45 * mini;
    asn_time = wolfSSL_ASN1_TIME_adj(s, t, offset_day, offset_sec);
    ExpectNotNull(asn_time);
    if (asn_time != NULL) {
        ExpectTrue(asn_time->type == asn_utc_time);
        ExpectNotNull(XSTRNCPY(date_str, (const char*)&asn_time->data,
            CTC_DATE_SIZE));
        date_str[CTC_DATE_SIZE] = '\0';
        ExpectIntEQ(0, XMEMCMP(date_str, "000222194500Z", 13));
        if (asn_time != s) {
            XFREE(asn_time, NULL, DYNAMIC_TYPE_OPENSSL);
        }
        asn_time = NULL;
    }

    XFREE(s, NULL, DYNAMIC_TYPE_OPENSSL);
    s = NULL;
    XMEMSET(date_str, 0, sizeof(date_str));

    /* Generalized time will overflow time_t if not long */
#if !defined(TIME_T_NOT_64BIT) && !defined(NO_64BIT)
    s = (WOLFSSL_ASN1_TIME*)XMALLOC(sizeof(WOLFSSL_ASN1_TIME), NULL,
                                    DYNAMIC_TYPE_OPENSSL);
    /* GeneralizedTime notation test */
    /* 2055/03/01 09:00:00 */
    t = (time_t)85 * year + 59 * day + 9 * hour + 21 * day;
        offset_day = 12;
        offset_sec = 10 * mini;
    ExpectNotNull(asn_time = wolfSSL_ASN1_TIME_adj(s, t, offset_day,
        offset_sec));
    if (asn_time != NULL) {
        ExpectTrue(asn_time->type == asn_gen_time);
        ExpectNotNull(XSTRNCPY(date_str, (const char*)&asn_time->data,
            CTC_DATE_SIZE));
        date_str[CTC_DATE_SIZE] = '\0';
        ExpectIntEQ(0, XMEMCMP(date_str, "20550313091000Z", 15));
        if (asn_time != s) {
            XFREE(asn_time, NULL, DYNAMIC_TYPE_OPENSSL);
        }
        asn_time = NULL;
    }

    XFREE(s, NULL, DYNAMIC_TYPE_OPENSSL);
    s = NULL;
    XMEMSET(date_str, 0, sizeof(date_str));
#endif /* !TIME_T_NOT_64BIT && !NO_64BIT */

    /* if WOLFSSL_ASN1_TIME struct is not allocated */
    s = NULL;

    t = (time_t)30 * year + 45 * day + 20 * hour + 30 * mini + 15 + 7 * day;
    offset_day = 7;
    offset_sec = 45 * mini;
    ExpectNotNull(asn_time = wolfSSL_ASN1_TIME_adj(s, t, offset_day,
        offset_sec));
    if (asn_time != NULL) {
        ExpectTrue(asn_time->type == asn_utc_time);
        ExpectNotNull(XSTRNCPY(date_str, (const char*)&asn_time->data,
            CTC_DATE_SIZE));
        date_str[CTC_DATE_SIZE] = '\0';
        ExpectIntEQ(0, XMEMCMP(date_str, "000222211515Z", 13));
        XFREE(asn_time, NULL, DYNAMIC_TYPE_OPENSSL);
        asn_time = NULL;
    }
    ExpectNotNull(asn_time = wolfSSL_ASN1_TIME_adj(NULL, t, offset_day,
        offset_sec));
    if (asn_time != NULL) {
        ExpectTrue(asn_time->type == asn_utc_time);
        ExpectNotNull(XSTRNCPY(date_str, (const char*)&asn_time->data,
            CTC_DATE_SIZE));
        date_str[CTC_DATE_SIZE] = '\0';
        ExpectIntEQ(0, XMEMCMP(date_str, "000222211515Z", 13));
        XFREE(asn_time, NULL, DYNAMIC_TYPE_OPENSSL);
        asn_time = NULL;
    }
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_ASN1_TIME_to_tm(void)
{
    EXPECT_DECLS;
#if (defined(WOLFSSL_MYSQL_COMPATIBLE) || defined(WOLFSSL_NGINX) || \
      defined(WOLFSSL_HAPROXY) || defined(OPENSSL_EXTRA) || \
      defined(OPENSSL_ALL)) && !defined(NO_ASN_TIME)
    ASN1_TIME asnTime;
    struct tm tm;
    time_t testTime = 1683926567; /* Fri May 12 09:22:47 PM UTC 2023 */

    XMEMSET(&tm, 0, sizeof(struct tm));

    XMEMSET(&asnTime, 0, sizeof(ASN1_TIME));
    ExpectIntEQ(ASN1_TIME_set_string(&asnTime, "000222211515Z"), 1);
    ExpectIntEQ(ASN1_TIME_to_tm(&asnTime, NULL), 1);
    ExpectIntEQ(ASN1_TIME_to_tm(&asnTime, &tm), 1);

    ExpectIntEQ(tm.tm_sec, 15);
    ExpectIntEQ(tm.tm_min, 15);
    ExpectIntEQ(tm.tm_hour, 21);
    ExpectIntEQ(tm.tm_mday, 22);
    ExpectIntEQ(tm.tm_mon, 1);
    ExpectIntEQ(tm.tm_year, 100);
    ExpectIntEQ(tm.tm_isdst, 0);
#ifdef XMKTIME
    ExpectIntEQ(tm.tm_wday, 2);
    ExpectIntEQ(tm.tm_yday, 52);
#endif

    ExpectIntEQ(ASN1_TIME_set_string(&asnTime, "500222211515Z"), 1);
    ExpectIntEQ(ASN1_TIME_to_tm(&asnTime, &tm), 1);
    ExpectIntEQ(tm.tm_year, 50);

    /* Get current time. */
    ExpectIntEQ(ASN1_TIME_to_tm(NULL, NULL), 0);
    ExpectIntEQ(ASN1_TIME_to_tm(NULL, &tm), 1);

    XMEMSET(&asnTime, 0, sizeof(ASN1_TIME));
    /* 0 length. */
    ExpectIntEQ(ASN1_TIME_to_tm(&asnTime, &tm), 0);
    /* No type. */
    asnTime.length = 1;
    ExpectIntEQ(ASN1_TIME_to_tm(&asnTime, &tm), 0);
    /* Not UTCTIME length. */
    asnTime.type = V_ASN1_UTCTIME;
    ExpectIntEQ(ASN1_TIME_to_tm(&asnTime, &tm), 0);
    /* Not GENERALIZEDTIME length. */
    asnTime.type = V_ASN1_GENERALIZEDTIME;
    ExpectIntEQ(ASN1_TIME_to_tm(&asnTime, &tm), 0);

    /* Not Zulu timezone. */
    ExpectIntEQ(ASN1_TIME_set_string(&asnTime, "000222211515U"), 1);
    ExpectIntEQ(ASN1_TIME_to_tm(&asnTime, &tm), 0);
    ExpectIntEQ(ASN1_TIME_set_string(&asnTime, "20000222211515U"), 1);
    ExpectIntEQ(ASN1_TIME_to_tm(&asnTime, &tm), 0);

#ifdef XMKTIME
    ExpectNotNull(ASN1_TIME_adj(&asnTime, testTime, 0, 0));
    ExpectIntEQ(ASN1_TIME_to_tm(&asnTime, &tm), 1);
    ExpectIntEQ(tm.tm_sec, 47);
    ExpectIntEQ(tm.tm_min, 22);
    ExpectIntEQ(tm.tm_hour, 21);
    ExpectIntEQ(tm.tm_mday, 12);
    ExpectIntEQ(tm.tm_mon, 4);
    ExpectIntEQ(tm.tm_year, 123);
    ExpectIntEQ(tm.tm_wday, 5);
    ExpectIntEQ(tm.tm_yday, 131);
    /* Confirm that when used with a tm struct from ASN1_TIME_adj, all other
       fields are zeroed out as expected. */
    ExpectIntEQ(tm.tm_isdst, 0);
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_ASN1_TIME_to_generalizedtime(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_ASN_TIME)
    WOLFSSL_ASN1_TIME *t = NULL;
    WOLFSSL_ASN1_TIME *out = NULL;
    WOLFSSL_ASN1_TIME *gtime = NULL;
    int tlen = 0;
    unsigned char *data = NULL;

    ExpectNotNull(t = wolfSSL_ASN1_TIME_new());
    ExpectNull(wolfSSL_ASN1_TIME_to_generalizedtime(NULL, &out));
    /* type not set. */
    ExpectNull(wolfSSL_ASN1_TIME_to_generalizedtime(t, &out));
    XFREE(t, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    t = NULL;

    /* UTC Time test */
    ExpectNotNull(t = wolfSSL_ASN1_TIME_new());
    if (t != NULL) {
        XMEMSET(t->data, 0, ASN_GENERALIZED_TIME_SIZE);
        t->type = ASN_UTC_TIME;
        t->length = ASN_UTC_TIME_SIZE;
        XMEMCPY(t->data, "050727123456Z", ASN_UTC_TIME_SIZE);
    }

    ExpectIntEQ(tlen = wolfSSL_ASN1_TIME_get_length(t), ASN_UTC_TIME_SIZE);
    ExpectStrEQ((char*)(data = wolfSSL_ASN1_TIME_get_data(t)), "050727123456Z");

    out = NULL;
    ExpectNotNull(gtime = wolfSSL_ASN1_TIME_to_generalizedtime(t, &out));
    wolfSSL_ASN1_TIME_free(gtime);
    gtime = NULL;
    ExpectNotNull(out = wolfSSL_ASN1_TIME_new());
    ExpectNotNull(gtime = wolfSSL_ASN1_TIME_to_generalizedtime(t, &out));
    ExpectPtrEq(gtime, out);
    ExpectIntEQ(gtime->type, ASN_GENERALIZED_TIME);
    ExpectIntEQ(gtime->length, ASN_GENERALIZED_TIME_SIZE);
    ExpectStrEQ((char*)gtime->data, "20050727123456Z");

    /* Generalized Time test */
    ExpectNotNull(XMEMSET(t, 0, ASN_GENERALIZED_TIME_SIZE));
    ExpectNotNull(XMEMSET(out, 0, ASN_GENERALIZED_TIME_SIZE));
    ExpectNotNull(XMEMSET(data, 0, ASN_GENERALIZED_TIME_SIZE));
    if (t != NULL) {
        t->type = ASN_GENERALIZED_TIME;
        t->length = ASN_GENERALIZED_TIME_SIZE;
        XMEMCPY(t->data, "20050727123456Z", ASN_GENERALIZED_TIME_SIZE);
    }

    ExpectIntEQ(tlen = wolfSSL_ASN1_TIME_get_length(t),
        ASN_GENERALIZED_TIME_SIZE);
    ExpectStrEQ((char*)(data = wolfSSL_ASN1_TIME_get_data(t)),
        "20050727123456Z");
    ExpectNotNull(gtime = wolfSSL_ASN1_TIME_to_generalizedtime(t, &out));
    ExpectIntEQ(gtime->type, ASN_GENERALIZED_TIME);
    ExpectIntEQ(gtime->length, ASN_GENERALIZED_TIME_SIZE);
    ExpectStrEQ((char*)gtime->data, "20050727123456Z");

    /* UTC Time to Generalized Time 1900's test */
    ExpectNotNull(XMEMSET(t, 0, ASN_GENERALIZED_TIME_SIZE));
    ExpectNotNull(XMEMSET(out, 0, ASN_GENERALIZED_TIME_SIZE));
    ExpectNotNull(XMEMSET(data, 0, ASN_GENERALIZED_TIME_SIZE));
    if (t != NULL) {
        t->type = ASN_UTC_TIME;
        t->length = ASN_UTC_TIME_SIZE;
        XMEMCPY(t->data, "500727123456Z", ASN_UTC_TIME_SIZE);
    }

    ExpectNotNull(gtime = wolfSSL_ASN1_TIME_to_generalizedtime(t, &out));
    ExpectIntEQ(gtime->type, ASN_GENERALIZED_TIME);
    ExpectIntEQ(gtime->length, ASN_GENERALIZED_TIME_SIZE);
    ExpectStrEQ((char*)gtime->data, "19500727123456Z");
    XFREE(out, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    /* Null parameter test */
    ExpectNotNull(XMEMSET(t, 0, ASN_GENERALIZED_TIME_SIZE));
    gtime = NULL;
    out = NULL;
    if (t != NULL) {
        t->type = ASN_UTC_TIME;
        t->length = ASN_UTC_TIME_SIZE;
        XMEMCPY(t->data, "050727123456Z", ASN_UTC_TIME_SIZE);
    }
    ExpectNotNull(gtime = wolfSSL_ASN1_TIME_to_generalizedtime(t, NULL));
    ExpectIntEQ(gtime->type, ASN_GENERALIZED_TIME);
    ExpectIntEQ(gtime->length, ASN_GENERALIZED_TIME_SIZE);
    ExpectStrEQ((char*)gtime->data, "20050727123456Z");

    XFREE(gtime, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(t, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_ASN1_TIME_print(void)
{
    EXPECT_DECLS;
#if !defined(NO_CERTS) && !defined(NO_RSA) && !defined(NO_BIO) && \
    (defined(WOLFSSL_MYSQL_COMPATIBLE) || defined(WOLFSSL_NGINX) || \
     defined(WOLFSSL_HAPROXY) || defined(OPENSSL_EXTRA) || \
     defined(OPENSSL_ALL)) && defined(USE_CERT_BUFFERS_2048) && \
    !defined(NO_ASN_TIME)
    BIO*  bio = NULL;
    BIO*  fixed = NULL;
    X509*  x509 = NULL;
    const unsigned char* der = client_cert_der_2048;
    ASN1_TIME* notAfter = NULL;
    ASN1_TIME* notBefore = NULL;
    unsigned char buf[25];

    ExpectNotNull(bio = BIO_new(BIO_s_mem()));
    ExpectNotNull(fixed = BIO_new(wolfSSL_BIO_s_fixed_mem()));
    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_buffer(der,
                sizeof_client_cert_der_2048, WOLFSSL_FILETYPE_ASN1));
    ExpectNotNull(notBefore = X509_get_notBefore(x509));

    ExpectIntEQ(ASN1_TIME_print(NULL, NULL), 0);
    ExpectIntEQ(ASN1_TIME_print(bio, NULL), 0);
    ExpectIntEQ(ASN1_TIME_print(NULL, notBefore), 0);

    ExpectIntEQ(ASN1_TIME_print(bio, notBefore), 1);
    ExpectIntEQ(BIO_read(bio, buf, sizeof(buf)), 24);
    ExpectIntEQ(XMEMCMP(buf, "Dec 18 21:25:29 2024 GMT", sizeof(buf) - 1), 0);

    /* Test BIO_write fails. */
    ExpectIntEQ(BIO_set_write_buf_size(fixed, 1), 1);
    /* Ensure there is 0 bytes available to write into. */
    ExpectIntEQ(BIO_write(fixed, buf, 1), 1);
    ExpectIntEQ(ASN1_TIME_print(fixed, notBefore), 0);
    ExpectIntEQ(BIO_set_write_buf_size(fixed, 1), 1);
    ExpectIntEQ(ASN1_TIME_print(fixed, notBefore), 0);
    ExpectIntEQ(BIO_set_write_buf_size(fixed, 23), 1);
    ExpectIntEQ(ASN1_TIME_print(fixed, notBefore), 0);

    /* create a bad time and test results */
    ExpectNotNull(notAfter = X509_get_notAfter(x509));
    ExpectIntEQ(ASN1_TIME_check(notAfter), 1);
    if (EXPECT_SUCCESS()) {
        notAfter->data[8] = 0;
        notAfter->data[3] = 0;
    }
    ExpectIntNE(ASN1_TIME_print(bio, notAfter), 1);
    ExpectIntEQ(BIO_read(bio, buf, sizeof(buf)), 14);
    ExpectIntEQ(XMEMCMP(buf, "Bad time value", 14), 0);
    ExpectIntEQ(ASN1_TIME_check(notAfter), 0);

    BIO_free(bio);
    BIO_free(fixed);
    X509_free(x509);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_ASN1_UTCTIME_print(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_ASN_TIME) && !defined(NO_BIO)
    BIO*  bio = NULL;
    ASN1_UTCTIME* utc = NULL;
    unsigned char buf[25];
    const char* validDate   = "190424111501Z";   /* UTC =   YYMMDDHHMMSSZ */
    const char* invalidDate = "190424111501X";   /* UTC =   YYMMDDHHMMSSZ */
    const char* genDate     = "20190424111501Z"; /* GEN = YYYYMMDDHHMMSSZ */

    /* Valid date */
    ExpectNotNull(bio = BIO_new(BIO_s_mem()));
    ExpectNotNull(utc = (ASN1_UTCTIME*)XMALLOC(sizeof(ASN1_UTCTIME), NULL,
                                                           DYNAMIC_TYPE_ASN1));
    if (utc != NULL) {
        utc->type = ASN_UTC_TIME;
        utc->length = ASN_UTC_TIME_SIZE;
        XMEMCPY(utc->data, (byte*)validDate, ASN_UTC_TIME_SIZE);
    }

    ExpectIntEQ(ASN1_UTCTIME_print(NULL, NULL), 0);
    ExpectIntEQ(ASN1_UTCTIME_print(bio, NULL), 0);
    ExpectIntEQ(ASN1_UTCTIME_print(NULL, utc), 0);

    ExpectIntEQ(ASN1_UTCTIME_print(bio, utc), 1);
    ExpectIntEQ(BIO_read(bio, buf, sizeof(buf)), 24);
    ExpectIntEQ(XMEMCMP(buf, "Apr 24 11:15:01 2019 GMT", sizeof(buf)-1), 0);

    XMEMSET(buf, 0, sizeof(buf));
    BIO_free(bio);
    bio = NULL;

    /* Invalid format */
    ExpectNotNull(bio = BIO_new(BIO_s_mem()));
    if (utc != NULL) {
        utc->type = ASN_UTC_TIME;
        utc->length = ASN_UTC_TIME_SIZE;
        XMEMCPY(utc->data, (byte*)invalidDate, ASN_UTC_TIME_SIZE);
    }
    ExpectIntEQ(ASN1_UTCTIME_print(bio, utc), 0);
    ExpectIntEQ(BIO_read(bio, buf, sizeof(buf)), 14);
    ExpectIntEQ(XMEMCMP(buf, "Bad time value", 14), 0);

    /* Invalid type */
    if (utc != NULL) {
        utc->type = ASN_GENERALIZED_TIME;
        utc->length = ASN_GENERALIZED_TIME_SIZE;
        XMEMCPY(utc->data, (byte*)genDate, ASN_GENERALIZED_TIME_SIZE);
    }
    ExpectIntEQ(ASN1_UTCTIME_print(bio, utc), 0);

    XFREE(utc, NULL, DYNAMIC_TYPE_ASN1);
    BIO_free(bio);
#endif /* OPENSSL_EXTRA && !NO_ASN_TIME && !NO_BIO */
    return EXPECT_RESULT();
}

int test_wolfSSL_ASN1_TYPE(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) || defined(WOLFSSL_APACHE_HTTPD) || \
    defined(WOLFSSL_HAPROXY) || defined(WOLFSSL_WPAS)
    WOLFSSL_ASN1_TYPE* t = NULL;
    WOLFSSL_ASN1_OBJECT* obj = NULL;
#ifndef NO_ASN_TIME
    WOLFSSL_ASN1_TIME* time = NULL;
#endif
    WOLFSSL_ASN1_STRING* str = NULL;
    unsigned char data[] = { 0x00 };

    ASN1_TYPE_set(NULL, V_ASN1_NULL, NULL);

    ExpectNotNull(t = wolfSSL_ASN1_TYPE_new());
    ASN1_TYPE_set(t, V_ASN1_EOC, NULL);
    wolfSSL_ASN1_TYPE_free(t);
    t = NULL;

    ExpectNotNull(t = wolfSSL_ASN1_TYPE_new());
    ASN1_TYPE_set(t, V_ASN1_NULL, NULL);
    ASN1_TYPE_set(t, V_ASN1_NULL, data);
    wolfSSL_ASN1_TYPE_free(t);
    t = NULL;

    ExpectNotNull(t = wolfSSL_ASN1_TYPE_new());
    ExpectNotNull(obj = wolfSSL_ASN1_OBJECT_new());
    ASN1_TYPE_set(t, V_ASN1_OBJECT, obj);
    wolfSSL_ASN1_TYPE_free(t);
    t = NULL;

#ifndef NO_ASN_TIME
    ExpectNotNull(t = wolfSSL_ASN1_TYPE_new());
    ExpectNotNull(time = wolfSSL_ASN1_TIME_new());
    ASN1_TYPE_set(t, V_ASN1_UTCTIME, time);
    wolfSSL_ASN1_TYPE_free(t);
    t = NULL;

    ExpectNotNull(t = wolfSSL_ASN1_TYPE_new());
    ExpectNotNull(time = wolfSSL_ASN1_TIME_new());
    ASN1_TYPE_set(t, V_ASN1_GENERALIZEDTIME, time);
    wolfSSL_ASN1_TYPE_free(t);
    t = NULL;
#endif

    ExpectNotNull(t = wolfSSL_ASN1_TYPE_new());
    ExpectNotNull(str = wolfSSL_ASN1_STRING_new());
    ASN1_TYPE_set(t, V_ASN1_UTF8STRING, str);
    wolfSSL_ASN1_TYPE_free(t);
    t = NULL;

    ExpectNotNull(t = wolfSSL_ASN1_TYPE_new());
    ExpectNotNull(str = wolfSSL_ASN1_STRING_new());
    ASN1_TYPE_set(t, V_ASN1_PRINTABLESTRING, str);
    wolfSSL_ASN1_TYPE_free(t);
    t = NULL;

    ExpectNotNull(t = wolfSSL_ASN1_TYPE_new());
    ExpectNotNull(str = wolfSSL_ASN1_STRING_new());
    ASN1_TYPE_set(t, V_ASN1_T61STRING, str);
    wolfSSL_ASN1_TYPE_free(t);
    t = NULL;

    ExpectNotNull(t = wolfSSL_ASN1_TYPE_new());
    ExpectNotNull(str = wolfSSL_ASN1_STRING_new());
    ASN1_TYPE_set(t, V_ASN1_IA5STRING, str);
    wolfSSL_ASN1_TYPE_free(t);
    t = NULL;

    ExpectNotNull(t = wolfSSL_ASN1_TYPE_new());
    ExpectNotNull(str = wolfSSL_ASN1_STRING_new());
    ASN1_TYPE_set(t, V_ASN1_UNIVERSALSTRING, str);
    wolfSSL_ASN1_TYPE_free(t);
    t = NULL;

    ExpectNotNull(t = wolfSSL_ASN1_TYPE_new());
    ExpectNotNull(str = wolfSSL_ASN1_STRING_new());
    ASN1_TYPE_set(t, V_ASN1_SEQUENCE, str);
    wolfSSL_ASN1_TYPE_free(t);
    t = NULL;
#endif
    return EXPECT_RESULT();
}

/* Testing code used in old dpp.c in hostap */
#if defined(OPENSSL_ALL) && defined(HAVE_ECC) && defined(USE_CERT_BUFFERS_256)
typedef struct {
    /* AlgorithmIdentifier ecPublicKey with optional parameters present
     * as an OID identifying the curve */
    X509_ALGOR *alg;
    /* Compressed format public key per ANSI X9.63 */
    ASN1_BIT_STRING *pub_key;
} DPP_BOOTSTRAPPING_KEY;

ASN1_SEQUENCE(DPP_BOOTSTRAPPING_KEY) = {
    ASN1_SIMPLE(DPP_BOOTSTRAPPING_KEY, alg, X509_ALGOR),
    ASN1_SIMPLE(DPP_BOOTSTRAPPING_KEY, pub_key, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(DPP_BOOTSTRAPPING_KEY)

IMPLEMENT_ASN1_FUNCTIONS(DPP_BOOTSTRAPPING_KEY)

typedef struct {
    int type;
    union {
        ASN1_BIT_STRING *str1;
        ASN1_BIT_STRING *str2;
        ASN1_BIT_STRING *str3;
    } d;
} ASN1_CHOICE_TEST;

ASN1_CHOICE(ASN1_CHOICE_TEST) = {
    ASN1_IMP(ASN1_CHOICE_TEST, d.str1, ASN1_BIT_STRING, 1),
    ASN1_IMP(ASN1_CHOICE_TEST, d.str2, ASN1_BIT_STRING, 2),
    ASN1_IMP(ASN1_CHOICE_TEST, d.str3, ASN1_BIT_STRING, 3)
} ASN1_CHOICE_END(ASN1_CHOICE_TEST)

IMPLEMENT_ASN1_FUNCTIONS(ASN1_CHOICE_TEST)

/* Test nested objects */
typedef struct {
    DPP_BOOTSTRAPPING_KEY* key;
    ASN1_INTEGER* asnNum;
    ASN1_INTEGER* expNum;
    STACK_OF(ASN1_GENERALSTRING) *strList;
    ASN1_CHOICE_TEST* str;
} TEST_ASN1_NEST1;

ASN1_SEQUENCE(TEST_ASN1_NEST1) = {
    ASN1_SIMPLE(TEST_ASN1_NEST1, key, DPP_BOOTSTRAPPING_KEY),
    ASN1_SIMPLE(TEST_ASN1_NEST1, asnNum, ASN1_INTEGER),
    ASN1_EXP(TEST_ASN1_NEST1, expNum, ASN1_INTEGER, 0),
    ASN1_EXP_SEQUENCE_OF(TEST_ASN1_NEST1, strList, ASN1_GENERALSTRING, 1),
    ASN1_SIMPLE(TEST_ASN1_NEST1, str, ASN1_CHOICE_TEST)
} ASN1_SEQUENCE_END(TEST_ASN1_NEST1)

IMPLEMENT_ASN1_FUNCTIONS(TEST_ASN1_NEST1)

typedef struct {
    ASN1_INTEGER* num;
    DPP_BOOTSTRAPPING_KEY* key;
    TEST_ASN1_NEST1* asn1_obj;
} TEST_ASN1_NEST2;

ASN1_SEQUENCE(TEST_ASN1_NEST2) = {
    ASN1_SIMPLE(TEST_ASN1_NEST2, num, ASN1_INTEGER),
    ASN1_SIMPLE(TEST_ASN1_NEST2, key, DPP_BOOTSTRAPPING_KEY),
    ASN1_SIMPLE(TEST_ASN1_NEST2, asn1_obj, TEST_ASN1_NEST1)
} ASN1_SEQUENCE_END(TEST_ASN1_NEST2)

IMPLEMENT_ASN1_FUNCTIONS(TEST_ASN1_NEST2)
/* End nested objects */

typedef struct {
    ASN1_INTEGER *integer;
} TEST_ASN1;

ASN1_SEQUENCE(TEST_ASN1) = {
    ASN1_SIMPLE(TEST_ASN1, integer, ASN1_INTEGER),
} ASN1_SEQUENCE_END(TEST_ASN1)

IMPLEMENT_ASN1_FUNCTIONS(TEST_ASN1)

typedef STACK_OF(ASN1_INTEGER) TEST_ASN1_ITEM;

ASN1_ITEM_TEMPLATE(TEST_ASN1_ITEM) =
        ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, MemName, ASN1_INTEGER)
ASN1_ITEM_TEMPLATE_END(TEST_ASN1_ITEM)

IMPLEMENT_ASN1_FUNCTIONS(TEST_ASN1_ITEM)
#endif

int test_wolfSSL_IMPLEMENT_ASN1_FUNCTIONS(void)
{
    EXPECT_DECLS;
    /* Testing code used in dpp.c in hostap */
#if defined(OPENSSL_ALL) && defined(HAVE_ECC) && defined(USE_CERT_BUFFERS_256)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
    EC_KEY *eckey = NULL;
    EVP_PKEY *key = NULL;
    size_t len = 0;
    unsigned char *der = NULL;
    unsigned char *der2 = NULL;
    const unsigned char *tmp = NULL;
    DPP_BOOTSTRAPPING_KEY *bootstrap = NULL, *bootstrap2 = NULL;
    const unsigned char *in = ecc_clikey_der_256;
    WOLFSSL_ASN1_OBJECT* ec_obj = NULL;
    WOLFSSL_ASN1_OBJECT* group_obj = NULL;
    const EC_GROUP *group = NULL;
    const EC_POINT *point = NULL;
    int nid;
    TEST_ASN1 *test_asn1 = NULL;
    TEST_ASN1 *test_asn1_2 = NULL;

    const unsigned char badObjDer[] = { 0x06, 0x00 };
    const unsigned char goodObjDer[] = {
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01
    };
    WOLFSSL_ASN1_ITEM emptyTemplate;

    XMEMSET(&emptyTemplate, 0, sizeof(WOLFSSL_ASN1_ITEM));

    ExpectNotNull(bootstrap = DPP_BOOTSTRAPPING_KEY_new());

    der = NULL;
    ExpectIntEQ(i2d_DPP_BOOTSTRAPPING_KEY(NULL, &der), -1);
    ExpectIntEQ(wolfSSL_ASN1_item_i2d(bootstrap, &der, NULL), -1);
    ExpectIntEQ(i2d_DPP_BOOTSTRAPPING_KEY(bootstrap, &der), -1);

    ExpectNotNull(key = d2i_PrivateKey(EVP_PKEY_EC, NULL, &in,
                                       (long)sizeof_ecc_clikey_der_256));
    ExpectNotNull(eckey = EVP_PKEY_get1_EC_KEY(key));
    ExpectNotNull(group = EC_KEY_get0_group(eckey));
    ExpectNotNull(point = EC_KEY_get0_public_key(eckey));
    nid = EC_GROUP_get_curve_name(group);

    ec_obj = OBJ_nid2obj(EVP_PKEY_EC);
    group_obj = OBJ_nid2obj(nid);
    if ((ec_obj != NULL) && (group_obj != NULL)) {
        ExpectIntEQ(X509_ALGOR_set0(NULL, ec_obj, V_ASN1_OBJECT,
            group_obj), 0);
        ExpectIntEQ(X509_ALGOR_set0(bootstrap->alg, NULL, V_ASN1_OBJECT,
            NULL), 1);
        ExpectIntEQ(X509_ALGOR_set0(bootstrap->alg, ec_obj, V_ASN1_OBJECT,
            group_obj), 1);
        if (EXPECT_SUCCESS()) {
            ec_obj = NULL;
            group_obj = NULL;
        }
    }
    wolfSSL_ASN1_OBJECT_free(group_obj);
    wolfSSL_ASN1_OBJECT_free(ec_obj);
    ExpectIntEQ(EC_POINT_point2oct(group, point, 0, NULL, 0, NULL), 0);
#ifdef HAVE_COMP_KEY
    ExpectIntGT((len = EC_POINT_point2oct(
                                   group, point, POINT_CONVERSION_COMPRESSED,
                                   NULL, 0, NULL)), 0);
#else
    ExpectIntGT((len = EC_POINT_point2oct(
                                   group, point, POINT_CONVERSION_UNCOMPRESSED,
                                   NULL, 0, NULL)), 0);
#endif
    ExpectNotNull(der = (unsigned char*)XMALLOC(len, NULL, DYNAMIC_TYPE_ASN1));
#ifdef HAVE_COMP_KEY
    ExpectIntEQ(EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED,
                                   der, len-1, NULL), 0);
    ExpectIntEQ(EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED,
                                   der, len, NULL), len);
#else
    ExpectIntEQ(EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                                   der, len-1, NULL), 0);
    ExpectIntEQ(EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                                   der, len, NULL), len);
#endif
    if (EXPECT_SUCCESS()) {
        bootstrap->pub_key->data = der;
        bootstrap->pub_key->length = (int)len;
        /* Not actually used */
        bootstrap->pub_key->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
        bootstrap->pub_key->flags |= ASN1_STRING_FLAG_BITS_LEFT;
    }

    ExpectIntEQ(i2d_DPP_BOOTSTRAPPING_KEY(bootstrap, NULL), 16+len);
    der = NULL;
    ExpectIntEQ(i2d_DPP_BOOTSTRAPPING_KEY(bootstrap, &der), 16+len);
    der2 = NULL;
#ifdef WOLFSSL_ASN_TEMPLATE
    tmp = der;
    ExpectNotNull(d2i_DPP_BOOTSTRAPPING_KEY(&bootstrap2, &tmp, 16+len));
    ExpectIntEQ(i2d_DPP_BOOTSTRAPPING_KEY(bootstrap2, &der2), 16+len);
    ExpectBufEQ(der, der2, 49);
#endif

    XFREE(der, NULL, DYNAMIC_TYPE_ASN1);
    XFREE(der2, NULL, DYNAMIC_TYPE_ASN1);
    EVP_PKEY_free(key);
    EC_KEY_free(eckey);
    DPP_BOOTSTRAPPING_KEY_free(bootstrap);
    DPP_BOOTSTRAPPING_KEY_free(bootstrap2);
    bootstrap = NULL;
    DPP_BOOTSTRAPPING_KEY_free(NULL);

    /* Create bootstrap key with bad OBJECT_ID DER data, parameter that is
     * a NULL and an empty BIT_STRING. */
    ExpectNotNull(bootstrap = DPP_BOOTSTRAPPING_KEY_new());
    ExpectNotNull(bootstrap->alg->algorithm = wolfSSL_ASN1_OBJECT_new());
    if (EXPECT_SUCCESS()) {
        bootstrap->alg->algorithm->obj = badObjDer;
        bootstrap->alg->algorithm->objSz = (unsigned int)sizeof(badObjDer);
    }
    ExpectNotNull(bootstrap->alg->parameter = wolfSSL_ASN1_TYPE_new());
    if (EXPECT_SUCCESS()) {
        bootstrap->alg->parameter->type = V_ASN1_NULL;
        bootstrap->alg->parameter->value.ptr = NULL;
        bootstrap->pub_key->data = NULL;
        bootstrap->pub_key->length = 0;
        /* Not actually used */
        bootstrap->pub_key->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
        bootstrap->pub_key->flags |= ASN1_STRING_FLAG_BITS_LEFT;
    }
    /* Encode with bad OBJECT_ID. */
    der = NULL;
    ExpectIntEQ(i2d_DPP_BOOTSTRAPPING_KEY(bootstrap, &der), -1);

    /* Fix OBJECT_ID and encode with empty BIT_STRING. */
    if (EXPECT_SUCCESS()) {
        bootstrap->alg->algorithm->obj = goodObjDer;
        bootstrap->alg->algorithm->objSz = (unsigned int)sizeof(goodObjDer);
        bootstrap->alg->algorithm->grp = 2;
    }
    der = NULL;
    ExpectIntEQ(i2d_DPP_BOOTSTRAPPING_KEY(bootstrap, &der), 16);
    ExpectIntEQ(wolfSSL_ASN1_item_i2d(bootstrap, &der, &emptyTemplate), -1);
    XFREE(der, NULL, DYNAMIC_TYPE_ASN1);
    DPP_BOOTSTRAPPING_KEY_free(bootstrap);

    /* Test integer */
    ExpectNotNull(test_asn1 = TEST_ASN1_new());
    der = NULL;
    ExpectIntEQ(ASN1_INTEGER_set(test_asn1->integer, 100), 1);
    ExpectIntEQ(i2d_TEST_ASN1(test_asn1, &der), 5);
    tmp = der;
    ExpectNotNull(d2i_TEST_ASN1(&test_asn1_2, &tmp, 5));
    der2 = NULL;
    ExpectIntEQ(i2d_TEST_ASN1(test_asn1_2, &der2), 5);
    ExpectBufEQ(der, der2, 5);
    XFREE(der, NULL, DYNAMIC_TYPE_ASN1);
    XFREE(der2, NULL, DYNAMIC_TYPE_ASN1);
    TEST_ASN1_free(test_asn1);
    TEST_ASN1_free(test_asn1_2);

    /* Test integer cases. */
    ExpectNull(wolfSSL_ASN1_item_new(NULL));
    TEST_ASN1_free(NULL);

    /* Test nested asn1 objects */
    {
        TEST_ASN1_NEST2 *nested_asn1 = NULL;
        TEST_ASN1_NEST2 *nested_asn1_2 = NULL;
        int i;

        ExpectNotNull(nested_asn1 = TEST_ASN1_NEST2_new());
        /* Populate nested_asn1 with some random data */
        /* nested_asn1->num */
        ExpectIntEQ(ASN1_INTEGER_set(nested_asn1->num, 30003), 1);
        /* nested_asn1->key */
        ec_obj = OBJ_nid2obj(EVP_PKEY_EC);
        group_obj = OBJ_nid2obj(NID_secp256k1);
        ExpectIntEQ(X509_ALGOR_set0(nested_asn1->key->alg, ec_obj,
                V_ASN1_OBJECT, group_obj), 1);
        if (EXPECT_SUCCESS()) {
            ec_obj = NULL;
            group_obj = NULL;
        }
        else {
            wolfSSL_ASN1_OBJECT_free(ec_obj);
            wolfSSL_ASN1_OBJECT_free(group_obj);
        }
        ExpectIntEQ(ASN1_BIT_STRING_set_bit(nested_asn1->key->pub_key, 50, 1),
                1);
        /* nested_asn1->asn1_obj->key */
        ec_obj = OBJ_nid2obj(EVP_PKEY_EC);
        group_obj = OBJ_nid2obj(NID_secp256k1);
        ExpectIntEQ(X509_ALGOR_set0(nested_asn1->asn1_obj->key->alg, ec_obj,
                V_ASN1_OBJECT, group_obj), 1);
        if (EXPECT_SUCCESS()) {
            ec_obj = NULL;
            group_obj = NULL;
        }
        else {
            wolfSSL_ASN1_OBJECT_free(ec_obj);
            wolfSSL_ASN1_OBJECT_free(group_obj);
        }
        ExpectIntEQ(ASN1_BIT_STRING_set_bit(nested_asn1->asn1_obj->key->pub_key,
                500, 1), 1);
        /* nested_asn1->asn1_obj->asnNum */
        ExpectIntEQ(ASN1_INTEGER_set(nested_asn1->asn1_obj->asnNum, 666666), 1);
        /* nested_asn1->asn1_obj->expNum */
        ExpectIntEQ(ASN1_INTEGER_set(nested_asn1->asn1_obj->expNum, 22222), 1);
        /* nested_asn1->asn1_obj->strList */
        for (i = 10; i >= 0; i--) {
            ASN1_GENERALSTRING* genStr = NULL;
            char fmtStr[20];

            ExpectIntGT(snprintf(fmtStr, sizeof(fmtStr), "Bonjour #%d", i), 0);
            ExpectNotNull(genStr = ASN1_GENERALSTRING_new());
            ExpectIntEQ(ASN1_GENERALSTRING_set(genStr, fmtStr, -1), 1);
            ExpectIntGT(
                    sk_ASN1_GENERALSTRING_push(nested_asn1->asn1_obj->strList,
                            genStr), 0);
            if (EXPECT_FAIL()) {
                ASN1_GENERALSTRING_free(genStr);
            }
        }
        /* nested_asn1->asn1_obj->str */
        ExpectNotNull(nested_asn1->asn1_obj->str->d.str2
                = ASN1_BIT_STRING_new());
        ExpectIntEQ(ASN1_BIT_STRING_set_bit(nested_asn1->asn1_obj->str->d.str2,
                150, 1), 1);
        if (nested_asn1 != NULL) {
            nested_asn1->asn1_obj->str->type = 2;
        }

        der = NULL;
        ExpectIntEQ(i2d_TEST_ASN1_NEST2(nested_asn1, &der), 285);
#ifdef WOLFSSL_ASN_TEMPLATE
        tmp = der;
        ExpectNotNull(d2i_TEST_ASN1_NEST2(&nested_asn1_2, &tmp, 285));
        der2 = NULL;
        ExpectIntEQ(i2d_TEST_ASN1_NEST2(nested_asn1_2, &der2), 285);
        ExpectBufEQ(der, der2, 285);
        XFREE(der2, NULL, DYNAMIC_TYPE_ASN1);
#endif
        XFREE(der, NULL, DYNAMIC_TYPE_ASN1);

        TEST_ASN1_NEST2_free(nested_asn1);
        TEST_ASN1_NEST2_free(nested_asn1_2);
    }

    /* Test ASN1_ITEM_TEMPLATE */
    {
        TEST_ASN1_ITEM* asn1_item = NULL;
        TEST_ASN1_ITEM* asn1_item2 = NULL;
        int i;

        ExpectNotNull(asn1_item = TEST_ASN1_ITEM_new());
        for (i = 0; i < 11; i++) {
            ASN1_INTEGER* asn1_num = NULL;

            ExpectNotNull(asn1_num = ASN1_INTEGER_new());
            ExpectIntEQ(ASN1_INTEGER_set(asn1_num, i), 1);
            ExpectIntGT(wolfSSL_sk_insert(asn1_item, asn1_num, -1), 0);
            if (EXPECT_FAIL()) {
                ASN1_INTEGER_free(asn1_num);
            }
        }

        der = NULL;
        ExpectIntEQ(i2d_TEST_ASN1_ITEM(asn1_item, &der), 35);
        tmp = der;
        ExpectNotNull(d2i_TEST_ASN1_ITEM(&asn1_item2, &tmp, 35));
        der2 = NULL;
        ExpectIntEQ(i2d_TEST_ASN1_ITEM(asn1_item2, &der2), 35);
        ExpectBufEQ(der, der2, 35);
        XFREE(der, NULL, DYNAMIC_TYPE_ASN1);
        XFREE(der2, NULL, DYNAMIC_TYPE_ASN1);

        TEST_ASN1_ITEM_free(asn1_item);
        TEST_ASN1_ITEM_free(asn1_item2);
    }

#endif /* !HAVE_FIPS || HAVE_FIPS_VERSION > 2 */
#endif /* OPENSSL_ALL && HAVE_ECC && USE_CERT_BUFFERS_256 */
    return EXPECT_RESULT();
}

int test_wolfSSL_i2d_ASN1_TYPE(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA)
    /* Taken from one of sssd's certs othernames */
    unsigned char str_bin[] = {
        0x04, 0x10, 0xa4, 0x9b, 0xc8, 0xf4, 0x85, 0x8e, 0x89, 0x4d, 0x85, 0x8d,
        0x27, 0xbd, 0x63, 0xaa, 0x93, 0x93
    };
    ASN1_TYPE* asn1type = NULL;
    unsigned char* der = NULL;

    /* Create ASN1_TYPE manually as we don't have a d2i version yet */
    {
        ASN1_STRING* str = NULL;
        ExpectNotNull(str = ASN1_STRING_type_new(V_ASN1_SEQUENCE));
        ExpectIntEQ(ASN1_STRING_set(str, str_bin, sizeof(str_bin)), 1);
        ExpectNotNull(asn1type = ASN1_TYPE_new());
        if (asn1type != NULL) {
            ASN1_TYPE_set(asn1type, V_ASN1_SEQUENCE, str);
        }
        else {
            ASN1_STRING_free(str);
        }
    }

    ExpectIntEQ(i2d_ASN1_TYPE(asn1type, NULL), sizeof(str_bin));
    ExpectIntEQ(i2d_ASN1_TYPE(asn1type, &der), sizeof(str_bin));
    ExpectBufEQ(der, str_bin, sizeof(str_bin));

    ASN1_TYPE_free(asn1type);
    XFREE(der, NULL, DYNAMIC_TYPE_ASN1);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_i2d_ASN1_SEQUENCE(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA)
    /* Taken from one of sssd's certs othernames */
    unsigned char str_bin[] = {
      0x04, 0x10, 0xa4, 0x9b, 0xc8, 0xf4, 0x85, 0x8e, 0x89, 0x4d, 0x85, 0x8d,
      0x27, 0xbd, 0x63, 0xaa, 0x93, 0x93
    };
    ASN1_STRING* str = NULL;
    unsigned char* der = NULL;

    ExpectNotNull(str = ASN1_STRING_type_new(V_ASN1_SEQUENCE));
    ExpectIntEQ(ASN1_STRING_set(str, str_bin, sizeof(str_bin)), 1);
    ExpectIntEQ(i2d_ASN1_SEQUENCE(str, NULL), sizeof(str_bin));
    ExpectIntEQ(i2d_ASN1_SEQUENCE(str, &der), sizeof(str_bin));

    ASN1_STRING_free(str);
    XFREE(der, NULL, DYNAMIC_TYPE_ASN1);
#endif
    return EXPECT_RESULT();
}

int test_ASN1_strings(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA)
    char text[] = "\0\0test string";
    unsigned char* der = NULL;
    ASN1_STRING* str = NULL;

    /* Set the length byte */
    text[1] = XSTRLEN(text + 2);

    /* GENERALSTRING */
    {
        const unsigned char* p = (const unsigned char*)text;
        text[0] = ASN_GENERALSTRING;
        ExpectNotNull(d2i_ASN1_GENERALSTRING(&str, &p, sizeof(text)));
        ExpectIntEQ(i2d_ASN1_GENERALSTRING(str, &der), 13);
        ASN1_STRING_free(str);
        str = NULL;
        XFREE(der, NULL, DYNAMIC_TYPE_ASN1);
        der = NULL;
    }

    /* OCTET_STRING */
    {
        const unsigned char* p = (const unsigned char*)text;
        text[0] = ASN_OCTET_STRING;
        ExpectNotNull(d2i_ASN1_OCTET_STRING(&str, &p, sizeof(text)));
        ExpectIntEQ(i2d_ASN1_OCTET_STRING(str, &der), 13);
        ASN1_STRING_free(str);
        str = NULL;
        XFREE(der, NULL, DYNAMIC_TYPE_ASN1);
        der = NULL;
    }

    /* UTF8STRING */
    {
        const unsigned char* p = (const unsigned char*)text;
        text[0] = ASN_UTF8STRING;
        ExpectNotNull(d2i_ASN1_UTF8STRING(&str, &p, sizeof(text)));
        ExpectIntEQ(i2d_ASN1_UTF8STRING(str, &der), 13);
        ASN1_STRING_free(str);
        str = NULL;
        XFREE(der, NULL, DYNAMIC_TYPE_ASN1);
        der = NULL;
    }

#endif
    return EXPECT_RESULT();
}

